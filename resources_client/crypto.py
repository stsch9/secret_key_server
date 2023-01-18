import sys
import json
from pyseto import Key, Paseto
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
from nacl.bindings import crypto_secretstream_xchacha20poly1305_state, crypto_secretstream_xchacha20poly1305_init_push, \
    crypto_secretstream_xchacha20poly1305_push, crypto_secretstream_xchacha20poly1305_TAG_FINAL, \
    crypto_secretstream_xchacha20poly1305_HEADERBYTES, crypto_secretstream_xchacha20poly1305_init_pull, \
    crypto_secretstream_xchacha20poly1305_pull, crypto_secretstream_xchacha20poly1305_ABYTES, crypto_kx_keypair,\
    crypto_scalarmult, crypto_scalarmult_base, crypto_kx_PUBLIC_KEY_BYTES, crypto_kx_SECRET_KEY_BYTES, \
    crypto_aead_chacha20poly1305_ietf_encrypt, crypto_aead_chacha20poly1305_ietf_decrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from nacl.utils import random
from nacl.exceptions import CryptoError
from nacl.encoding import Base64Encoder
from nacl import exceptions as exc
from nacl.exceptions import ensure
from SecureString import clearmem
from typing import BinaryIO
import pyseto

blocksize_msg = 64 * 1024
MASTER_KEY_BYTES = 32
PSK_BYTES = 32


def _encrypt_msg(key: bytes, msg: BinaryIO, blocksize=blocksize_msg) -> bytes:
    """Lazy function (generator) to read a file piece by piece and encrypt with xchacha20poly1305 stream.
        https://doc.libsodium.org/secret-key_cryptography/secretstream
        Default chunk size: 10k."""
    state = crypto_secretstream_xchacha20poly1305_state()
    header = crypto_secretstream_xchacha20poly1305_init_push(state, key)
    yield header
    c = False
    while True:
        data = msg.read(blocksize)
        if not data:
            break
        if c:
            enc: bytes = crypto_secretstream_xchacha20poly1305_push(state, c)
            yield enc
        c = data
    enc = crypto_secretstream_xchacha20poly1305_push(state, c, None, crypto_secretstream_xchacha20poly1305_TAG_FINAL)
    yield enc


def _decrypt_msg(key: bytes, msg: BinaryIO, blocksize=blocksize_msg) -> bytes:
    state = crypto_secretstream_xchacha20poly1305_state()
    header = msg.read(crypto_secretstream_xchacha20poly1305_HEADERBYTES)
    crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)

    data_in = msg.read(
                blocksize + crypto_secretstream_xchacha20poly1305_ABYTES)
    while data_in:
        # ciphertext = plaintext + crypto_secretstream_xchacha20poly1305_ABYTES = plaintext + 17
        data, tag = crypto_secretstream_xchacha20poly1305_pull(state, data_in)
        yield data

        data_in = msg.read(
            blocksize + crypto_secretstream_xchacha20poly1305_ABYTES)
        if len(data_in) != 0 and tag == 3:
            sys.exit('premature end')


def _encrypt_key(pkR: bytes, key: bytes) -> tuple[bytes, bytes]:
    ensure(
        isinstance(pkR, bytes)
        and len(pkR) == crypto_kx_PUBLIC_KEY_BYTES,
        "Public key recipient must be a {} bytes long bytes sequence".format(
            crypto_kx_PUBLIC_KEY_BYTES
        ),
        raising=exc.TypeError,
    )

    pkE, skE = crypto_kx_keypair()
    dh = crypto_scalarmult(skE, pkR)
    clearmem(skE)

    salt = pkE + pkR
    info = b"keyencryption"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    wrap_key = hkdf.derive(dh)

    ciphertext = crypto_aead_chacha20poly1305_ietf_encrypt(message=key, aad=None, nonce=bytes(12), key=wrap_key)
    return pkE, ciphertext


def _decrypt_key(skR: bytes, pkE: bytes, cipertext: bytes) -> bytes:
    ensure(
        isinstance(skR, bytes)
        and len(skR) == crypto_kx_SECRET_KEY_BYTES,
        "Secret key recipient key must be a {} bytes long bytes sequence".format(
            crypto_kx_SECRET_KEY_BYTES
        ),
        raising=exc.TypeError,
    )

    ensure(
        isinstance(pkE, bytes)
        and len(pkE) == crypto_kx_PUBLIC_KEY_BYTES,
        "Public key recipient key must be a {} bytes long bytes sequence".format(
            crypto_kx_PUBLIC_KEY_BYTES
        ),
        raising=exc.TypeError,
    )

    dh = crypto_scalarmult(skR, pkE)

    salt = pkE + crypto_scalarmult_base(skR)
    info = b"keyencryption"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    wrap_key = hkdf.derive(dh)

    plaintext = crypto_aead_chacha20poly1305_ietf_decrypt(ciphertext=cipertext, aad=None, nonce=bytes(12), key=wrap_key)
    return plaintext


def _encrypt_key_file(sk: bytes, key_dict: dict) -> bytes:
    ensure(
        isinstance(sk, bytes)
        and len(sk) == MASTER_KEY_BYTES,
        "Master key must be a {} bytes long bytes sequence".format(
            MASTER_KEY_BYTES
        ),
        raising=exc.TypeError,
    )

    paseto_key = Key.new(version=4, purpose="local", key=sk)
    paseto = Paseto.new(include_iat=True)  # Default values are exp=0(not specified) and including_iat=False
    token = paseto.encode(
        paseto_key,
        payload=key_dict,
        serializer=json
    )
    return token


def _decrypt_key_file(sk: bytes, token: bytes) -> bytes:
    ensure(
        isinstance(sk, bytes)
        and len(sk) == MASTER_KEY_BYTES,
        "Master key must be a {} bytes long bytes sequence".format(
            MASTER_KEY_BYTES
        ),
        raising=exc.TypeError,
    )

    paseto_key = Key.new(version=4, purpose="local", key=sk)
    decoded = pyseto.decode(paseto_key, token, deserializer=json)

    return decoded.payload


def _encrypt_hpke(pkr: bytes, sks: bytes, psk: bytes, msg: bytes) -> tuple[bytes, bytes]:
    ensure(
        isinstance(pkr, bytes)
        and len(pkr) == crypto_kx_PUBLIC_KEY_BYTES,
        "Public key recipient must be a {} bytes long bytes sequence".format(
            crypto_kx_PUBLIC_KEY_BYTES
        ),
        raising=exc.TypeError,
    )
    ensure(
        isinstance(sks, bytes)
        and len(sks) == crypto_kx_SECRET_KEY_BYTES,
        "Secret key sender must be a {} bytes long bytes sequence".format(
            crypto_kx_PUBLIC_KEY_BYTES
        ),
        raising=exc.TypeError,
    )
    ensure(
        isinstance(psk, bytes)
        and len(psk) == PSK_BYTES,
        "Secret key sender must be a {} bytes long bytes sequence".format(
            PSK_BYTES
        ),
        raising=exc.TypeError,
    )

    suite_s = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305)
    sks = KEMKey.from_pyca_cryptography_key(X25519PrivateKey.from_private_bytes(sks))
    pkr = KEMKey.from_pyca_cryptography_key(X25519PublicKey.from_public_bytes(pkr))
    enc, sender = suite_s.create_sender_context(pkr=pkr, sks=sks, psk=psk)
    return enc, sender.seal(msg)

pkR, skR = crypto_kx_keypair()
pkS, skS = crypto_kx_keypair()
psk = random()
master_key = random()

# encrypt master_key
enc, ct = _encrypt_hpke(pkR, skS, psk, master_key)


piK, siK = crypto_kx_keypair()

key_dict = {'123': Base64Encoder.encode(siK).decode('utf-8')}

token = _encrypt_key_file(master_key, key_dict)
print(_decrypt_key_file(master_key, token))
exit()

pkR, skR = crypto_kx_keypair()
pkE, ciphertext = _encrypt_key(pkR, b'sddsa')
print(_decrypt_key(skR, pkE, ciphertext))

key = random()

# https://stackoverflow.com/questions/26127889/python-read-stream
with open("./bla2", 'wb') as fw:
    with open("/Users/stefan.schaubeck/Documents/krz_migration", 'rb') as f:
        for i in _encrypt_msg(key, f):
            fw.write(i)

with open("./bla2", 'rb') as f:
    for i in _decrypt_msg(key, f):
        print(i)
