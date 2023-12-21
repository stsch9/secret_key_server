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


class AdminUser(object):
    def __init__(self, admin_room_token: AdminRoomToken, user_perm_token: UserPermToken):
        if isinstance(admin_room_token, AdminRoomToken):
            self._admin_room_token = admin_room_token
        else:
            raise Exception("Invalid Admin Room Token")

        if isinstance(user_perm_token, UserPermToken):
            self._user_perm_token = user_perm_token
        else:
            raise Exception("Invalid User Permission Token")

    @property
    def admin_room_token(self):
        return self._admin_room_token

    @property
    def user_perm_token(self):
        return self._user_perm_token

    @classmethod
    def decrypt(cls) -> "AdminUser":
        return cls(AdminRoomToken.decrypt(), UserPermToken.verify())

    @classmethod
    def initialize_dataroom(cls, user_id: int, node_id: str) -> tuple["AdminUser", bytes]:
        sdk = x25519.X25519PrivateKey.generate().private_bytes_raw().hex()
        srk = x25519.X25519PrivateKey.generate().private_bytes_raw().hex()
        key_id = os.urandom(32).hex()
        pk, sk = crypto_sign_keypair()
        signing_key = sk[:32].hex()

        payload = {'version': 1,
                   'node_id': node_id,
                   'SDK': sdk,
                   'SK': signing_key,
                   'SRKs': {key_id: srk}}

        payload_user_perm = {'version': 1,
                             'node_id': node_id,
                             'key_token_version': 1,
                             'perm': {str(user_id): 3}}

        admin_user = cls(AdminRoomToken(payload), UserPermToken(payload_user_perm))

        signed_perm_token = admin_user.sign_token()

        return admin_user, signed_perm_token

    def encrypt_token(self, sks: bytes, pkr: bytes, payload: dict) -> tuple[bytes, bytes]:
        enc, token = encrypt_keys_token(bytes.fromhex(self._admin_room_token.node_id),
                                             sks,
                                             pkr,
                                             payload)
        return enc, token

    def sign_token(self) -> bytes:
        signed_token = sign_perm_token(bytes.fromhex(self._admin_room_token.node_id),
                                       bytes.fromhex(self._admin_room_token.secret_signing_key),
                                       self._user_perm_token.payload)
        return signed_token

    def distribute_token(self, sks: bytes, recipient_id: int, payload: dict, verify_key: bytes, cert_file: bytes) -> dict:
        user_keys = CA.verify(pk=verify_key, cert_file=cert_file)
        try:
            pkr = user_keys['users'][str(recipient_id)]
        except KeyError:
            raise Exception("recipient public key does not exists")

        # encrypt token
        enc, token = encrypt_keys_token(bytes.fromhex(self._admin_room_token.node_id),
                                        sks,
                                        bytes.fromhex(pkr),
                                        payload)
        key_dict = {recipient_id: [enc, token]}

        return key_dict

    def add_user(self, user_id: int, perm: int, sks: bytes, ca_verify_key: bytes, cert_file: bytes) -> tuple[dict,bytes]:
        if perm == 3:
            payload = self._admin_room_token.payload
        elif perm == 2:
            payload = self._admin_room_token.create_secret_keys_token().payload
            #print(payload)
            #print(self._admin_room_token.payload)
        elif perm == 1:
            payload = self._admin_room_token.create_recipient_keys_token().payload
        else:
            raise Exception("Invalid permission")

        # encrypt AdminRoomToken/RoomKeysToken
        key_dict = self.distribute_token(sks=sks,
                                         recipient_id=user_id,
                                         payload=payload,
                                         verify_key=ca_verify_key,
                                         cert_file=cert_file)

        # update UserPermToken
        self._user_perm_token.payload["version"] += 1
        self._user_perm_token.payload["perm"].update({str(user_id): perm})
        signed_perm_token = self.sign_token()

        return key_dict, signed_perm_token

    def remove_user(self, user_id: int, ca_verify_key: bytes, cert_file: bytes) -> tuple[bytes, dict]:
        # update AdminRoomToken
        self._admin_room_token.payload['version'] += 1
        prk, srk = crypto_kx_keypair()
        key_id = os.urandom(32).hex()
        self._admin_room_token.payload['SRKs'].update({key_id: srk.hex()})

        # check permissions of the user who is being removed
        perm_removed_user = self._user_perm_token.payload["perm"][str(user_id)]

        # if permission = 3 then a new SDK + SK must be created
        if perm_removed_user == 3:
            old_sdk = self._admin_room_token.secret_distribution_key
            pdk, sdk = crypto_kx_keypair()
            self._admin_room_token.payload['SDK'] = sdk.hex()
            pk, sk = crypto_sign_keypair()
            self._admin_room_token.payload['SK'] = sk[:32].hex()
        else:
            old_sdk = self._admin_room_token.secret_distribution_key

        # update UserPermToken
        self._user_perm_token.payload["version"] += 1
        self._user_perm_token.payload["key_token_version"] += 1
        del self._user_perm_token.payload["perm"][str(user_id)]

        signed_perm_token = self.sign_token()

        # encrypt AdminRoomToken/RoomKeysToken
        key_dict = {}
        for user_id, perm in self._user_perm_token.payload['perm'].items():
            if perm == 3:
                payload = self._admin_room_token.payload
            elif perm == 2:
                payload = self._admin_room_token.create_secret_keys_token().payload
            elif perm == 1:
                payload = self._admin_room_token.create_recipient_keys_token().payload
            else:
                raise Exception("Invalid permission")

            key_dict.update(self.distribute_token(sks=bytes.fromhex(old_sdk),
                                                  recipient_id=user_id,
                                                  payload=payload,
                                                  verify_key=ca_verify_key,
                                                  cert_file=cert_file))

        return signed_perm_token, key_dict

#keyset = {
#    "type": ,
#    "SDK": ,
#    "SK": ,
#    "PRK":
#    "SRK"
#}