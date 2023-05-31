import sys
import json
from pyseto import Key, Paseto, Token
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
from nacl.bindings import crypto_secretstream_xchacha20poly1305_state, crypto_secretstream_xchacha20poly1305_init_push, \
    crypto_secretstream_xchacha20poly1305_push, crypto_secretstream_xchacha20poly1305_TAG_FINAL, \
    crypto_secretstream_xchacha20poly1305_HEADERBYTES, crypto_secretstream_xchacha20poly1305_init_pull, \
    crypto_secretstream_xchacha20poly1305_pull, crypto_secretstream_xchacha20poly1305_ABYTES, crypto_kx_keypair,\
    crypto_scalarmult, crypto_scalarmult_base, crypto_kx_PUBLIC_KEY_BYTES, crypto_kx_SECRET_KEY_BYTES, \
    crypto_aead_chacha20poly1305_ietf_encrypt, crypto_aead_chacha20poly1305_ietf_decrypt, crypto_sign_SECRETKEYBYTES, \
    crypto_sign_PUBLICKEYBYTES, crypto_sign_seed_keypair
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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


def _encrypt_token(sk: bytes, key_dict: dict, footer_dict: dict) -> bytes:
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
        footer=footer_dict,
        serializer=json
    )
    return token


def _decrypt_token(sk: bytes, token: bytes) -> Token:
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

    return decoded


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


def _sign_token(sk: bytes, payload: dict, footer_dict: dict) -> bytes:
    #private_key = Ed25519PrivateKey.generate()
    #public_bytes = private_key.public_key().public_bytes(
    #    encoding=serialization.Encoding.Raw,
    #    format=serialization.PublicFormat.Raw)
#
    #private_bytes = private_key.private_bytes(
    #    encoding=serialization.Encoding.Raw,
    #    format=serialization.PrivateFormat.Raw,
    #    encryption_algorithm=serialization.NoEncryption())

    ensure(
        isinstance(sk, bytes)
        and len(sk) == 32,
        "Public key recipient must be a {} bytes long bytes sequence".format(
            32
        ),
        raising=exc.TypeError,
    )
    private_key = Key.from_asymmetric_key_params(4, d=sk)

    token = pyseto.encode(
        private_key,
        payload=payload,
        footer=footer_dict,
        serializer=json
    )

    return token

def _verify_token(pk: bytes, token: bytes) -> Token:
    ensure(
        isinstance(pk, bytes)
        and len(pk) == crypto_sign_PUBLICKEYBYTES,
        "Public key recipient must be a {} bytes long bytes sequence".format(
            crypto_sign_PUBLICKEYBYTES
        ),
        raising=exc.TypeError,
    )

    public_key = Key.from_asymmetric_key_params(4, x=pk)

    decoded = pyseto.decode(public_key, token, deserializer=json)

    return decoded

class MasterKey:
    def __init__(self, x: bytes):
        if isinstance(x, bytes) and len(x) == 64:
            self.master_key = x
            self.token_key_bytes = x[0:32]
            self.signing_key_bytes = x[32:64]
        else:
            raise Exception("Invalid key")

    @property
    def token_key(self) -> bytes:
        return self.token_key_bytes

    @property
    def signing_key(self) -> bytes:
        return self.signing_key_bytes

    def encrypt_token(self, payload: dict, node_id: int, key_id: str, verify_key: str) -> bytes:
        return _encrypt_token(self.token_key, payload, {'node_id': node_id, 'key_id': key_id, 'verify_key': verify_key})

    def decrypt_token(self, token: bytes) -> Token:
        return _decrypt_token(self.token_key, token)


class MasterKeyUser:
    def __init__(self, x: bytes):
        if isinstance(x, bytes) and len(x) == 64:
            self.master_key = x
            self.token_key_bytes = x[0:32]
            self.signing_key_bytes = x[32:64]
        else:
            raise Exception("Invalid key")

    @property
    def token_key(self) -> bytes:
        return self.token_key_bytes

    @property
    def signing_key(self) -> bytes:
        return self.signing_key_bytes

    def sign_token(self, user_dict: dict, node_id: int, key_id: str) -> bytes:
        return _sign_token(self.token_key, user_dict, {'node_id': node_id, 'key_id': key_id})

    @staticmethod
    def verify_token(pk: bytes, token: bytes) -> Token:
        return _verify_token(pk, token)


class MasterKeyMeta:
    def __init__(self, x: bytes):
        if isinstance(x, bytes) and len(x) == 64:
            self.token_key_secret = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                                               info=b'token_key_secret').derive(x[0:32])
            self.token_key_recipient = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                                               info=b'token_key_recipient').derive(x[0:32])
            self.token_key_user = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                                               info=b'token_key_user').derive(x[0:32])
            self.signing_key_secret = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                                               info=b'signing_key_secret').derive(x[32:64])
            self.signing_key_recipient = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                                                 info=b'signing_key_recipient').derive(x[32:64])
            self.signing_key_user = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                                                    info=b'signing_key_user').derive(x[32:64])
        else:
            raise Exception("Invalid key")

    @property
    def master_key_user(self) -> MasterKeyUser:
        return MasterKeyUser(self.token_key_user + self.signing_key_user)

    @property
    def master_key_secret(self) -> MasterKey:
        return MasterKey(self.token_key_secret + self.signing_key_secret)

    @property
    def master_key_recipient(self) -> MasterKey:
        return MasterKey(self.token_key_recipient + self.signing_key_recipient)

    @classmethod
    def _add_new_intermediate_keys(cls, int_keys_secret: dict, int_keys_recipient: dict, node_id: int,
                                   user_permissions: dict) -> tuple["MasterKeyMeta", bytes, bytes, bytes]:
        master_key_meta_new = cls.generate()
        key_id = random(32).hex()

        pk = crypto_sign_seed_keypair(master_key_meta_new.token_key_user)[0]
        token_user = master_key_meta_new.master_key_user.sign_token(user_permissions, node_id, key_id)

        # genarate new intermediate keys + intermediate key_id
        piK, siK = crypto_kx_keypair()
        int_keys_secret.update({key_id: siK.hex()})
        token_secret_keys = master_key_meta_new.master_key_secret.encrypt_token(int_keys_secret, node_id, key_id, pk.hex())

        int_keys_recipient.update({key_id: piK.hex()})
        token_recipient_keys = master_key_meta_new.master_key_recipient.encrypt_token(int_keys_recipient, node_id, key_id, pk.hex())

        return master_key_meta_new, token_user, token_secret_keys, token_recipient_keys

    @classmethod
    def generate(cls) -> "MasterKeyMeta":
        return cls(random(64))

    @classmethod
    def initialize(cls, node_id: int, user_permissions: dict) -> tuple["MasterKeyMeta", bytes, bytes, bytes]:
        return cls._add_new_intermediate_keys({}, {}, node_id, user_permissions)

    def add_user(self, token: bytes, user_id: int, user_rights: int) -> bytes:
        pk = crypto_sign_seed_keypair(self.token_key_user)[0]
        token = MasterKeyUser.verify_token(pk, token)
        # add new user
        payload_token = token.payload
        payload_token.update({user_id: user_rights})
        new_token = self.master_key_user.sign_token(payload_token, token.footer['node_id'], token.footer['key_id'])
        return new_token

    def change_user(self, token_user: bytes, token_secret: bytes, token_recipient: bytes, user_permissions: dict) -> \
            tuple["MasterKeyMeta", bytes, bytes, bytes]:
        pk = crypto_sign_seed_keypair(self.token_key_user)[0]
        token_user_cls = MasterKeyUser.verify_token(pk, token_user)
        token_secret_cls = self.master_key_secret.decrypt_token(token_secret)
        token_recipient_cls = self.master_key_recipient.decrypt_token(token_recipient)
        node_id = token_user_cls.footer['node_id']

        int_keys_secret = token_secret_cls.payload
        int_keys_recipient = token_recipient_cls.payload

        return self._add_new_intermediate_keys(int_keys_secret, int_keys_recipient, node_id, user_permissions)


def derive_authentication_key(session_key: bytes, signing_key: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=signing_key,
        info=b'authenticationkey',
    )

    return hkdf.derive(session_key)


# # https://stackoverflow.com/questions/26127889/python-read-stream
# with open("./bla2", 'wb') as fw:
#     with open("/Users/stefan.schaubeck/Documents/krz_migration", 'rb') as f:
#         for i in _encrypt_msg(key, f):
#             fw.write(i)
#
# with open("./bla2", 'rb') as f:
#     for i in _decrypt_msg(key, f):
#         print(i)
#