import json
from typing import Union
from flask import request
from cryptography.hazmat.primitives import hashes, hmac
from nacl.bindings import sodium_memcmp
from model import UserSessions


def authenticate_user(session_id: int) -> Union[UserSessions, bool]:
    session_id_db = UserSessions.query.get(session_id)
    if not session_id_db:
        return False

    if not hmac_auth(session_id_db.session_key):
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
        message += bytearray(SIGNATURE_DELIM, 'utf-8') + content # bytearray(content, 'utf-8')

    # https://libsodium.gitbook.io/doc/helpers#constant-time-test-for-equality
    h = hmac.HMAC(key=secret_key, algorithm=hashes.SHA256())
    h.update(message)
    return sodium_memcmp(h.finalize(), bytes.fromhex(x_auth_signature))