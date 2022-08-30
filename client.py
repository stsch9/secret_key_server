from nacl.utils import random
from nacl.encoding import Base64Encoder, RawEncoder
import nacl.secret
import requests
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from resources_client.authentication import HmacAuth
from nacl.public import PrivateKey
from nacl.hash import sha512
from oblivious import sodium
import json

raw_secret_key = b'\xf4\xc4\xccp\xec\xc4o\x93L\x01j\x8c`E\xa7\x91\x0f\xf8_w\x19&\xf3\x91P{I\xb7\xcb\x8aD^'
raw_salt = b'my_\xa5W(I\x9a\xfe-\xa0\xa3\x9b\x92`\xe1\xf4T\xf7$\xcf\x07\xe4\xb5\x85\xa7p|\\\xf9\x087'
raw_private_key = PrivateKey.generate()
public_key = raw_private_key.public_key.encode(encoder=Base64Encoder).decode('utf-8')
box = nacl.secret.SecretBox(raw_secret_key)
encrypted_private_key = Base64Encoder.encode(box.encrypt(raw_private_key.encode(encoder=RawEncoder))).decode('utf-8')

new_raw_secret_key = b'\xe0\xad\x17\xc9\x8eX\x06j\x98,\x83\x04\xaeN\xa0\x05\xb1\xb4\x8f\x0cli\xc8_\xe4U\xedj\xfe\x06U\x1b'
new_raw_salt = b'\x93\xfc\x13\x04\xc4\xdf\n\xe2\xec\xc0k\x1d\xda\x1c!\xea\xa1\xe4.\x85/\xe5\x98\x82\x9b<";\x8f\xb6i\xf4'
new_raw_private_key = PrivateKey.generate()
new_public_key = raw_private_key.public_key.encode(encoder=Base64Encoder)
box = nacl.secret.SecretBox(raw_secret_key)
new_encrypted_private_key = box.encrypt(new_raw_private_key.encode(encoder=RawEncoder))

info = b"secret_key_server"
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=64,
    salt=raw_salt,
    info=info,
)

raw_key = hkdf.derive(raw_secret_key)
raw_signing_key = raw_key[:32]
raw_encryption_key = raw_key[32:]

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=64,
    salt=new_raw_salt,
    info=info,
)

new_raw_key = hkdf.derive(new_raw_secret_key)
new_raw_signing_key = new_raw_key[:32]
new_raw_encryption_key = new_raw_key[32:]


print('new encryption key: ' + Base64Encoder.encode(new_raw_encryption_key).decode('utf-8'))
print('new signing key: ' + Base64Encoder.encode(new_raw_signing_key).decode('utf-8'))

###################################################
print("----------------------")
print("add node")

headers = {"accept": "application/json",
           "Content-Type": "application/json;charset=UTF-8"}
data = {"node_id": 1,
        "derivation_salt": Base64Encoder.encode(raw_salt).decode('utf-8'),
        "signing_key": Base64Encoder.encode(raw_signing_key).decode('utf-8'),
        "encryption_key": Base64Encoder.encode(raw_encryption_key).decode('utf-8'),
        "encrypted_private_key": encrypted_private_key,
        "public_key": public_key}

response = requests.post("http://127.0.0.1:5000/api/key", data=json.dumps(data), headers=headers)
print(response.json())

####################################################
print("----------------------")
print("add user 1")

headers = {"accept": "application/json",
           "Content-Type": "application/json;charset=UTF-8"}
data = {"user_id": 1}
response = requests.post("http://127.0.0.1:5000/api/user", data=json.dumps(data), headers=headers)
print(response.json())

####################################################
print("----------------------")
print("add user 2")

headers = {"accept": "application/json",
           "Content-Type": "application/json;charset=UTF-8"}
data = {"user_id": 2}
response = requests.post("http://127.0.0.1:5000/api/user", data=json.dumps(data), headers=headers)
print(response.json())

####################################################
print("----------------------")
print("validate key")
headers = {"accept": "application/json"}
params = {"node_id": 1}
response = requests.get("http://127.0.0.1:5000/api/validate_secret_key", params=params, headers=headers)
print(response.json())
h = hmac.HMAC(key=raw_signing_key, algorithm=hashes.SHA256())
h.update(str(response.json().get('key_id')).encode())
print(Base64Encoder.encode(h.finalize()).decode('utf-8'))

####################################################
print("----------------------")
print("get challenge")

headers = {"accept": "application/json"}
params = {"node_id": 1}
response = requests.get("http://127.0.0.1:5000/api/challenge", params=params, headers=headers)
print(response.json())

#####################################################
print("----------------------")
print("add user_key")

raw_challenge = Base64Encoder.decode(response.json().get('challenge'))

headers = {"accept": "application/json",
           "Content-Type": "application/json;charset=UTF-8"}
params = {"node_id": 1}
data = {"user_id": 1,
        "secret_key": Base64Encoder.encode(random(72)).decode('utf-8')}

response = requests.post("http://127.0.0.1:5000/api/user_keys", auth=HmacAuth(1, raw_signing_key, raw_challenge),
                         data=json.dumps(data), params=params, headers=headers)
print(response.json())
print(response.request.url)
print(response.request.body)
print(response.request.headers)

####################################################
print("----------------------")
print("get challenge")

headers = {"accept": "application/json"}
params = {"node_id": 1}
response = requests.get("http://127.0.0.1:5000/api/challenge", params=params, headers=headers)
print(response.json())

#####################################################
print("----------------------")
print("change user_key")

raw_challenge = Base64Encoder.decode(response.json().get('challenge'))
plain_data = b'{"derivation_salt":"' + Base64Encoder.encode(new_raw_salt) + b'",' + \
    b'"signing_key":"' + Base64Encoder.encode(new_raw_signing_key) + b'",' + \
    b'"encryption_key":"' + Base64Encoder.encode(new_raw_encryption_key) + b'",' + \
    b'"encrypted_private_key":"' + Base64Encoder.encode(new_encrypted_private_key) + b'",' + \
    b'"public_key":"' + new_public_key + b'",' + \
    b'"users":[{"user_id": 1, "secret_key":"' + Base64Encoder.encode(random()) + b'"},' + \
             b'{"user_id": 2, "secret_key":"' + Base64Encoder.encode(random()) + b'"}]}'

box = nacl.secret.SecretBox(raw_encryption_key)
enc_data = box.encrypt(plain_data)

headers = {"accept": "application/json",
           "Content-Type": "application/json;charset=UTF-8"}
params = {"node_id": 1}
data = {"encrypted_data": Base64Encoder.encode(enc_data).decode('utf-8')}

response = requests.put("http://127.0.0.1:5000/api/user_keys", auth=HmacAuth(1, raw_signing_key, raw_challenge),
                        data=json.dumps(data), params=params, headers=headers)

print(response.json())
print(response.request.url)
print(response.request.body)
print(response.request.headers)

#####################################################
print("----------------------")
print("set encrypted mask")

headers = {"accept": "application/json",
           "Content-Type": "application/json;charset=UTF-8"}
data = {"user_id": 1}

response = requests.post("http://127.0.0.1:5000/api/private_key", data=json.dumps(data), headers=headers)
print(response.json())
enc_mask = response.json().get('enc_mask')

#####################################################
print("----------------------")
print("get private key")
user_id = 1
user_id.to_bytes(4, byteorder='big')
password = "test"
px = sodium.pnt(sha512(user_id.to_bytes(4, byteorder='big') + password.encode('utf-8'), encoder=RawEncoder))
r = sodium.rnd()
a = sodium.mul(r, px)

headers = {"accept": "application/json"}
params = {"blinded_element": Base64Encoder.encode(a).decode('utf-8'),
          "enc_mask": enc_mask}
response = requests.get("http://127.0.0.1:5000/api/private_key", params=params, headers=headers)
print(response.json())
print(response.request.url)
print(response.request.body)
print(response.request.headers)
