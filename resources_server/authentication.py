from flask import request
from cryptography.hazmat.primitives import hashes, hmac
from nacl.bindings import sodium_memcmp

def hmac_auth(secret_key, challenge):
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
              bytearray(path, 'utf-8') + \
              bytearray(SIGNATURE_DELIM, 'utf-8') + \
              challenge

    if content:
        message += bytearray(SIGNATURE_DELIM, 'utf-8') + content # bytearray(content, 'utf-8')

    # https://libsodium.gitbook.io/doc/helpers#constant-time-test-for-equality
    h = hmac.HMAC(key=secret_key, algorithm=hashes.SHA256())
    h.update(message)
    return sodium_memcmp(h.finalize(), bytes.fromhex(x_auth_signature))