import hmac
from flask import request
from hashlib import sha256
from nacl.bindings import sodium_memcmp

def hmac_auth(secret_key):
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

    if content:
        message += bytearray(SIGNATURE_DELIM, 'utf-8') + content # bytearray(content, 'utf-8')

    # https://libsodium.gitbook.io/doc/helpers#constant-time-test-for-equality
    return sodium_memcmp(hmac.new(key=secret_key, msg=message, digestmod=sha256).digest(), bytes.fromhex(x_auth_signature))