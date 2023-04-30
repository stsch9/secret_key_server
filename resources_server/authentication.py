import json
from typing import Union
from flask import request
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.encoding import Base64Encoder
from nacl.bindings import sodium_memcmp
from model import UserSessions, DataroomKeys


def authenticate_user(session_id: str, key_id='', challenge=b'') -> Union[UserSessions, bool]:
    session_id_db = UserSessions.query.get(session_id)
    if not session_id_db:
        return False

    if key_id:
        key_id_db = DataroomKeys.query.get(key_id)
        if not key_id_db:
            return False

        # secret = LabeledExtract(shared_secret, "secret", psk), see https://www.rfc-editor.org/rfc/rfc9180.html
        key_material = Base64Encoder.decode(session_id_db.session_key)
        salt = Base64Encoder.decode(key_id_db.signing_key)
        info = b'signing_key'
        hkdf = HKDF(algorithm=hashes.SHA256(), salt=salt, length=32, info=info)

        key = hkdf.derive(key_material)
    else:
        key = Base64Encoder.decode(session_id_db.session_key)

    if not hmac_auth(key, challenge):
        return False

    return session_id_db


def hmac_auth(secret_key, challenge=b''):
    x_auth_signature = request.headers['X-Auth-Signature']
    timestamp = request.headers['X-Auth-Timestamp']
    x_auth_version = request.headers['X-Auth-Version']

    SIGNATURE_DELIM = '\n'

    method = request.method
    path = request.full_path
    content = request.data

    print(content)
    print(path)

    message = bytearray(method, 'utf-8') + \
              bytearray(SIGNATURE_DELIM, 'utf-8') + \
              bytearray(timestamp, 'utf-8') + \
              bytearray(SIGNATURE_DELIM, 'utf-8') + \
              bytearray(path, 'utf-8')

    if challenge:
        message += bytearray(SIGNATURE_DELIM, 'utf-8') + challenge

    if content:
        message += bytearray(SIGNATURE_DELIM, 'utf-8') + content  # bytearray(content, 'utf-8')

    # https://libsodium.gitbook.io/doc/helpers#constant-time-test-for-equality
    h = hmac.HMAC(key=secret_key, algorithm=hashes.SHA256())
    h.update(message)
    return sodium_memcmp(h.finalize(), bytes.fromhex(x_auth_signature))
