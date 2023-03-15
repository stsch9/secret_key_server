import requests
import gc
import json
import pyseto
import nacl.secret
import nacl.exceptions
from nacl.utils import random
from nacl.encoding import Base64Encoder, RawEncoder
from nacl.public import PrivateKey, Box, PublicKey
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from resources_client.authentication import HmacAuth
from SecureString import clearmem
from oprf.oprf_ristretto25519_sha512 import Blind, Finalize
from resources_client.dracoon_requests import create_registration_request


def signing_encryption_key_derivation(raw_secret_key, raw_salt, info = b"secret_key_server"):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=raw_salt,
        info=info,
    )

    raw_key = hkdf.derive(raw_secret_key)

    raw_signing_key = raw_key[:32]
    raw_encryption_key = raw_key[32:]
    clearmem(raw_key)

    return raw_signing_key, raw_encryption_key


def encrypt_secret_key_for_user(node_private_key, user_public_key, raw_secret_key):
    user_public_key = PublicKey(user_public_key, encoder=RawEncoder)
    node_private_key = PrivateKey(node_private_key, encoder=RawEncoder)
    try:
        box = Box(node_private_key, user_public_key)
        encrypted_secret_key = box.encrypt(raw_secret_key, encoder=Base64Encoder).decode()
    except nacl.exceptions.CryptoError:
        return "Error: Encryption Error"

    return encrypted_secret_key


def add_node(node_id, user_id, user_public_key):
    raw_secret_key = random()
    raw_salt = random()

    raw_signing_key, raw_encryption_key = signing_encryption_key_derivation(raw_secret_key, raw_salt)

    raw_private_key = PrivateKey.generate()
    public_key = raw_private_key.public_key.encode(encoder=Base64Encoder).decode('utf-8')
    box = nacl.secret.SecretBox(raw_secret_key)
    encrypted_private_key = Base64Encoder.encode(box.encrypt(raw_private_key.encode(encoder=RawEncoder))).decode(
        'utf-8')

    user_public_key = PublicKey(user_public_key, encoder=Base64Encoder)
    box = Box(raw_private_key, user_public_key)
    encrypted_secret_key = box.encrypt(raw_secret_key, encoder=Base64Encoder).decode()

    headers = {"accept": "application/json",
               "Content-Type": "application/json;charset=UTF-8"}
    data = {"node_id": node_id,
            "user_id": user_id,
            "encrypted_secret_key": encrypted_secret_key,
            "derivation_salt": Base64Encoder.encode(raw_salt).decode('utf-8'),
            "signing_key": Base64Encoder.encode(raw_signing_key).decode('utf-8'),
            "encryption_key": Base64Encoder.encode(raw_encryption_key).decode('utf-8'),
            "encrypted_private_key": encrypted_private_key,
            "public_key": public_key}

    try:
        response = requests.post("http://127.0.0.1:5000/api/key", data=json.dumps(data), headers=headers)
    except requests.exceptions.RequestException:
        return "Error: API Request failed"
    finally:
        clearmem(raw_signing_key)
        clearmem(raw_encryption_key)

    if response.status_code == 200:
        return response.json(), raw_secret_key, raw_private_key.encode(encoder=RawEncoder)
    else:
        raise Exception('Response Code: ' + str(response.status_code))


def add_user(user_id):
    headers = {"accept": "application/json",
               "Content-Type": "application/json;charset=UTF-8"}
    data = {"user_id": user_id}
    response = requests.post("http://127.0.0.1:5000/api/user", data=json.dumps(data), headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception('Response Code: ' + str(response.status_code))


def validate_key(node_id, raw_secret_key):
    headers = {"accept": "application/json"}
    params = {"node_id": node_id}
    try:
        response = requests.get("http://127.0.0.1:5000/api/validate_secret_key", params=params, headers=headers)
    except requests.exceptions.RequestException:
        clearmem(raw_secret_key)
        return "Error: API Request failed"

    if response.status_code == 200:

        raw_salt = Base64Encoder.decode(response.json().get('derivation_salt'))
        key_id = response.json().get('key_id')

        raw_signing_key, raw_encryption_key = signing_encryption_key_derivation(raw_secret_key, raw_salt)
        clearmem(raw_encryption_key)

        h = hmac.HMAC(key=raw_signing_key, algorithm=hashes.SHA256())
        h.update(str(key_id).encode())
        try:
            h.verify(Base64Encoder.decode(response.json().get('signature')))
            return key_id
        except InvalidSignature:
            print('ERROR: Invalid Signature')
        finally:
            clearmem(raw_signing_key)
    else:
        raise Exception('Response Code: ' + str(response.status_code))


def get_challenge(node_id):
    headers = {"accept": "application/json"}
    params = {"node_id": node_id}
    response = requests.get("http://127.0.0.1:5000/api/challenge", params=params, headers=headers)
    if response.status_code == 200:
        return response.json().get('challenge'), response.json().get('derivation_salt')
    else:
        raise Exception('Response Code: ' + str(response.status_code))


def add_user_key(challenge, node_id, user_id, derivation_salt, secret_key, user_public_key, node_private_key):
    raw_challenge = Base64Encoder.decode(challenge)
    raw_salt = Base64Encoder.decode(derivation_salt)
    raw_secret_key = secret_key

    encrypted_secret_key = encrypt_secret_key_for_user(node_private_key=node_private_key,
                                                       user_public_key=Base64Encoder.decode(user_public_key),
                                                       raw_secret_key=raw_secret_key)

    raw_signing_key, raw_encryption_key = signing_encryption_key_derivation(raw_secret_key, raw_salt)

    payload = {"user_id": user_id,
               "encrypted_secret_key": encrypted_secret_key}
    pyseto_key = pyseto.Key.new(version=4, purpose="local", key=raw_encryption_key)
    token = pyseto.encode(
        pyseto_key,
        payload=payload,
        serializer=json,
    )
    del pyseto_key
    gc.collect()
    clearmem(raw_encryption_key)

    headers = {"accept": "application/json",
               "Content-Type": "application/json;charset=UTF-8"}
    params = {"node_id": node_id}
    data = {"token": token.decode()}

    try:
        response = requests.post("http://127.0.0.1:5000/api/user_keys", auth=HmacAuth(node_id, raw_signing_key, raw_challenge),
                             data=json.dumps(data), params=params, headers=headers)
    except requests.exceptions.RequestException:
        return "Error: API Request failed"
    finally:
        clearmem(raw_signing_key)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception('Response Code: ' + str(response.json()))


def change_user_key(challenge, node_id, derivation_salt, secret_key, user_data):
    raw_challenge = Base64Encoder.decode(challenge)
    raw_old_salt = Base64Encoder.decode(derivation_salt)
    raw_old_secret_key = secret_key

    # derive old signing key
    raw_old_signing_key, raw_old_encryption_key = signing_encryption_key_derivation(raw_old_secret_key, raw_old_salt)
    clearmem(raw_old_secret_key)

    # derive new keys
    raw_new_secret_key = random()
    raw_new_salt = random()

    raw_new_signing_key, raw_new_encryption_key = signing_encryption_key_derivation(raw_new_secret_key, raw_new_salt)

    raw_new_private_key = PrivateKey.generate()
    new_public_key = raw_new_private_key.public_key.encode(encoder=Base64Encoder).decode('utf-8')
    box = nacl.secret.SecretBox(raw_new_secret_key)
    new_encrypted_private_key = Base64Encoder.encode(box.encrypt(raw_new_private_key.encode(encoder=RawEncoder))).decode('utf-8')

    users_list = [{"user_id": i["user_id"],
                   "encrypted_secret_key": encrypt_secret_key_for_user(raw_new_private_key.encode(encoder=RawEncoder),
                                                                       Base64Encoder.decode(i["user_public_key"]),
                                                                       raw_new_secret_key)}
                  for i in user_data]
    payload = {"derivation_salt": Base64Encoder.encode(raw_new_salt).decode('utf-8'),
               "signing_key": Base64Encoder.encode(raw_new_signing_key).decode('utf-8'),
               "encryption_key": Base64Encoder.encode(raw_new_encryption_key).decode('utf-8'),
               "encrypted_private_key": new_encrypted_private_key,
               "public_key": new_public_key,
               "users": users_list}

    # encrypt payload with old encryption key
    pyseto_key = pyseto.Key.new(version=4, purpose="local", key=raw_old_encryption_key)
    token = pyseto.encode(
        pyseto_key,
        payload=payload,
        serializer=json,
    )
    clearmem(raw_old_encryption_key)
    del pyseto_key
    gc.collect()
    clearmem(raw_new_signing_key)
    clearmem(raw_new_encryption_key)

    headers = {"accept": "application/json",
               "Content-Type": "application/json;charset=UTF-8"}
    params = {"node_id": node_id}
    data = {"token": token.decode()}

    try:
        response = requests.put("http://127.0.0.1:5000/api/user_keys",
                                auth=HmacAuth(node_id, raw_old_signing_key, raw_challenge),
                                data=json.dumps(data), params=params, headers=headers)
    except requests.exceptions.RequestException:
        return "Error: API Request failed"
    finally:
        clearmem(raw_old_signing_key)

    if response.status_code == 200:
        return response.json().get('message'), raw_new_secret_key, raw_new_private_key.encode(encoder=RawEncoder)
    else:
        raise Exception('Response Code: ' + str(response.status_code))


def set_encrypted_mask(user_id):
    headers = {"accept": "application/json",
               "Content-Type": "application/json;charset=UTF-8"}
    data = {"user_id": user_id}

    try:
        response = requests.post("http://127.0.0.1:5000/api/private_key", data=json.dumps(data), headers=headers)
    except requests.exceptions.RequestException:
        return "Error: API Request failed"

    if response.status_code == 200:
        return response.json().get('enc_mask')
    else:
        raise Exception('Response Code: ' + str(response.status_code))


def get_private_key(enc_mask, user_id, password):
    user_id.to_bytes(4, byteorder='big')
    input = user_id.to_bytes(4, byteorder='big') + password.encode('utf-8')
    blind, blindedElement = Blind(input)

    headers = {"accept": "application/json"}
    params = {"blinded_element": Base64Encoder.encode(blindedElement).decode('utf-8'),
              "enc_mask": enc_mask}
    try:
        response = requests.get("http://127.0.0.1:5000/api/private_key", params=params, headers=headers)
    except requests.exceptions.RequestException:
        return "Error: API Request failed"

    if response.status_code == 200:
        evaluated_element = response.json().get('evaluated_element')
        return Finalize(input, blind, Base64Encoder.decode(evaluated_element))
    else:
        raise Exception('Response Code: ' + str(response.status_code))

print("----------------------")
print("add user 1")
print(add_user(1))

print("----------------------")
print("add user 2")
print(add_user(2))

print("----------------------")
print("user registration 2")
print(type(create_registration_request(2, "password")))

quit()

print("----------------------")
print("add node")
user_public_key = "EPlo1/u0w072ZKfO2hS13eFTqub151aUSCzekmXzEwU="
output = add_node(1, 1, user_public_key)
print(output)
raw_secret_key = output[1]
raw_node_private_key = output[2]

print("----------------------")
print("set encrypted mask")
enc_mask = set_encrypted_mask(1)
print(enc_mask)

print("----------------------")
print("get private key")
secret = get_private_key(enc_mask, 1, "test")
print(secret)

print("----------------------")
print("validate key")
print(validate_key(1, raw_secret_key))

print("----------------------")
print("get challenge")
challenge, derivation_salt = get_challenge(1)

print("----------------------")
print("add user_key")
user_public_key = "EPlo1/u0w072ZKfO2hS13eFTqub151aUSCzekmXzEwU="
output = add_user_key(challenge, 1, 2, derivation_salt, raw_secret_key, user_public_key, raw_node_private_key)
print(output)

print("----------------------")
print("get challenge")
challenge, derivation_salt = get_challenge(1)

print("----------------------")
print("change user_key")
data = [{'user_id': 1, 'user_public_key': 'nl8CjjE1wUPg9ftz5tEWGMP5kauDKT37C9JvKu8G8U8='}, {'user_id': 2, 'user_public_key': 'nl8CjjE1wUPg9ftz5tEWGMP5kauDKT37C9JvKu8G8U8='}]
output = change_user_key(challenge, 1, derivation_salt, raw_secret_key, data)
print(output)
