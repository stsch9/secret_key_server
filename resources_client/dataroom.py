import json
import os
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
from pyseto import Key, Paseto
import pyseto
from cryptography.hazmat.primitives.asymmetric import x25519
from pysodium import crypto_sign_keypair, crypto_sign_seed_keypair, crypto_scalarmult_base, crypto_kx_keypair
from ca import CA


def encrypt_keys_token(node_id: bytes, sks: bytes, pkr: bytes, payload: dict) -> tuple[bytes, bytes]:
    suite_s = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.EXPORT_ONLY)
    sks = KEMKey.from_pyca_cryptography_key(x25519.X25519PrivateKey.from_private_bytes(sks))
    pkr = KEMKey.from_pyca_cryptography_key(x25519.X25519PublicKey.from_public_bytes(pkr))
    enc, sender = suite_s.create_sender_context(pkr=pkr, sks=sks, psk=node_id)
    sk = sender.export(exporter_context=b"encrypt_roomkeys", length=32)

    paseto_key = Key.new(version=4, purpose="local", key=sk)
    paseto = Paseto.new(include_iat=True)  # Default values are exp=0(not specified) and including_iat=False
    token = paseto.encode(
        paseto_key,
        payload=payload,
        serializer=json,
        implicit_assertion=node_id
    )
    return enc, token


def decrypt_keys_token(node_id: bytes, enc: bytes, skr: bytes, pks: bytes, token: bytes) -> dict:
    suite_s = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.EXPORT_ONLY)
    skr = KEMKey.from_pyca_cryptography_key(x25519.X25519PrivateKey.from_private_bytes(skr))
    pks = KEMKey.from_pyca_cryptography_key(x25519.X25519PublicKey.from_public_bytes(pks))
    recipient = suite_s.create_recipient_context(enc=enc, skr=skr, pks=pks, psk=node_id)
    sk = recipient.export(exporter_context=b"encrypt_roomkeys", length=32)

    paseto_key = Key.new(version=4, purpose="local", key=sk)
    decoded = pyseto.decode(paseto_key, token, implicit_assertion=node_id,  deserializer=json)

    return decoded.payload


def sign_perm_token(node_id: bytes, private_key: bytes, payload: dict) -> bytes:
    private_key = Key.from_asymmetric_key_params(4, d=private_key)

    token = pyseto.encode(
        private_key,
        payload=payload,
        serializer=json,
        implicit_assertion=node_id,
    )

    return token


def verify_perm_token(node_id: bytes, public_key: bytes, token: bytes) -> dict:
    public_key = Key.from_asymmetric_key_params(4, x=public_key)
    decoded = pyseto.decode(keys=public_key,
                            token=token,
                            deserializer=json,
                            implicit_assertion=node_id)
    return decoded.payload


class RoomKeysToken(object):
    def __init__(self, token: dict):
        # validate json schema
        self.token = token

    @property
    def payload(self):
        return self.token

    @property
    def verify_key(self):
        return self.token["VK"]

    @property
    def version(self):
        return self.token["version"]

    @property
    def public_distribution_key(self):
        return self.token["PDK"]

    @property
    def node_id(self) -> str:
        return self.token["node_id"]

    @classmethod
    def decrypt(cls, node_id: bytes, enc: bytes, skr: bytes, pks: bytes, token: bytes) -> "RoomKeysToken":
        payload = decrypt_keys_token(node_id, enc, skr, pks, token)
        return cls(payload)

    @classmethod
    def from_json(cls) -> "RoomKeysToken":
        return cls


class AdminRoomToken(object):
    def __init__(self, token: dict):
        # validate json schema
        self.token = token

    @property
    def payload(self):
        return self.token

    @property
    def version(self):
        return self.token["version"]

    @property
    def node_id(self) -> str:
        return self.token["node_id"]

    @property
    def secret_distribution_key(self) -> str:
        return self.token["SDK"]

    @property
    def secret_signing_key(self) -> str:
        return self.token["SK"]

    @classmethod
    def decrypt(cls, node_id: bytes, enc: bytes, skr: bytes, pks: bytes, token: bytes) -> "AdminRoomToken":
        payload = decrypt_keys_token(node_id, enc, skr, pks, token)
        return cls(payload)

    @classmethod
    def from_json(cls) -> "AdminRoomToken":
        return cls

    def create_recipient_keys_token(self) -> RoomKeysToken:
        payload = self.payload.copy()

        vk, sk_ = crypto_sign_seed_keypair(bytes.fromhex(self.secret_signing_key))
        vk = vk.hex()

        pdk = crypto_scalarmult_base(bytes.fromhex(self.secret_distribution_key)).hex()

        prks = {}
        for key_id, sk in payload['SRKs'].items():
            sk = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(sk)).public_key()
            sk = sk.public_bytes_raw().hex()
            prks.update({key_id: sk})

        payload.update({'VK': vk, 'PDK': pdk, 'PRKs': prks})

        del payload['SK']
        del payload['SDK']
        del payload['SRKs']

        return RoomKeysToken(payload)

    def create_secret_keys_token(self) -> RoomKeysToken:
        payload_skt = self.payload.copy()

        vk, sk_ = crypto_sign_seed_keypair(bytes.fromhex(self.secret_signing_key))
        vk = vk.hex()

        pdk = crypto_scalarmult_base(bytes.fromhex(self.secret_distribution_key)).hex()

        payload_skt.update({'VK': vk, 'PDK': pdk})
        del payload_skt['SK']
        del payload_skt['SDK']

        return RoomKeysToken(payload_skt)


class UserPermToken(object):
    def __init__(self, token: dict):
        # validate json schema
        self.token = token

    @property
    def payload(self) -> dict:
        return self.token

    @property
    def version(self):
        return self.token["version"]

    @property
    def key_token_version(self):
        return self.token["key_token_version"]

    @property
    def node_id(self):
        return self.token["node_id"]

    @property
    def perm(self):
        return self.token["perm"]

    @classmethod
    def verify(cls, node_id: bytes, public_key: bytes, token: bytes) -> "UserPermToken":
        payload = verify_perm_token(node_id, public_key, token)
        return cls(payload)

    @classmethod
    def from_json(cls) -> "UserPermToken":
        return cls


#keyset = {
#    "type": ,
#    "SDK": ,
#    "SK": ,
#    "PRK":
#    "SRK"
#}