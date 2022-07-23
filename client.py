from nacl.utils import random
from nacl.encoding import Base64Encoder, RawEncoder
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

raw_secret_key = b'\xf4\xc4\xccp\xec\xc4o\x93L\x01j\x8c`E\xa7\x91\x0f\xf8_w\x19&\xf3\x91P{I\xb7\xcb\x8aD^'
raw_salt = b'my_\xa5W(I\x9a\xfe-\xa0\xa3\x9b\x92`\xe1\xf4T\xf7$\xcf\x07\xe4\xb5\x85\xa7p|\\\xf9\x087'

info = b"secret_key_server"
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=64,
    salt=raw_salt,
    info=info,
)

raw_key = hkdf.derive(raw_secret_key)
#print(raw_key)
raw_signing_key = raw_key[:32]
raw_encryption_key = raw_key[32:]

###################################################

headers = {"accept": "application/json"}
data = {"node_id": 1,
        "derivation_salt": Base64Encoder.encode(raw_salt).decode('utf-8'),
        "signing_key": Base64Encoder.encode(raw_signing_key).decode('utf-8'),
        "encryption_key": Base64Encoder.encode(raw_encryption_key).decode('utf-8')}

response = requests.post("http://127.0.0.1:5000/api/key", data=data, headers=headers)
print(response.json())

####################################################

headers = {"accept": "application/json"}
params = {"node_id": 1}
response = requests.get("http://127.0.0.1:5000/api/challenge", params=params, headers=headers)
print(response.json())

#####################################################


