import os
from dataroom import AdminRoomToken, RoomKeysToken, UserPermToken, encrypt_keys_token, sign_perm_token
from ca import CA
from pysodium import crypto_sign_keypair, crypto_kx_keypair

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
    def create(cls,
               node_id: bytes,
               enc: bytes,
               skr: bytes,
               pks: bytes,
               admin_token: bytes,
               verify_key: bytes,
               perm_token: bytes) -> "AdminUser":

        return cls(AdminRoomToken.decrypt(node_id, enc, skr, pks, admin_token),
                   UserPermToken.verify(node_id, verify_key, perm_token))

    @classmethod
    def initialize_dataroom(cls, user_id: int, node_id: str) -> tuple["AdminUser", bytes]:
        pdk, sdk = crypto_kx_keypair()
        prk, srk = crypto_kx_keypair()
        key_id = os.urandom(32).hex()
        pk, sk = crypto_sign_keypair()
        signing_key = sk[:32].hex()

        payload = {'version': 1,
                   'node_id': node_id,
                   'SDK': sdk.hex(),
                   'SK': signing_key,
                   'SRKs': {key_id: srk.hex()}}

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


class ReadWriteUser(object):
    def __init__(self, secret_room_keys_token: RoomKeysToken, user_perm_token: UserPermToken):
        if isinstance(secret_room_keys_token, RoomKeysToken):
            self._secret_room_keys_token = secret_room_keys_token
        else:
            raise Exception("Invalid Room Keys Token")

        if isinstance(user_perm_token, UserPermToken):
            self._user_perm_token = user_perm_token
        else:
            raise Exception("Invalid User Permission Token")

    @property
    def secret_room_keys_token(self):
        return self._secret_room_keys_token

    @property
    def user_perm_token(self):
        return self._user_perm_token

    @classmethod
    def create(cls,
               node_id: bytes,
               enc: bytes,
               skr: bytes,
               pks: bytes,
               room_key_token: bytes,
               verify_key: bytes,
               perm_token: bytes) -> "ReadWriteUser":

        return cls(RoomKeysToken.decrypt(node_id, enc, skr, pks, room_key_token),
                   UserPermToken.verify(node_id, verify_key, perm_token))

    def receive_new_room_keys_token(self, skr: bytes, enc: bytes, token: bytes):
        self._secret_room_keys_token = RoomKeysToken.decrypt(node_id=bytes.fromhex(self._secret_room_keys_token.node_id),
                                                                enc=enc,
                                                                skr=skr,
                                                                pks=bytes.fromhex(self._secret_room_keys_token.public_distribution_key),
                                                                token=token)

    def receive_new_perm_token(self, token: bytes):
        self._user_perm_token = UserPermToken.verify(node_id=bytes.fromhex(self._secret_room_keys_token.node_id),
                                                     public_key=bytes.fromhex(self._secret_room_keys_token.verify_key),
                                                     token=token)


class WriteUser(object):
    def __init__(self, recipient_room_keys_token: RoomKeysToken, user_perm_token: UserPermToken):
        if isinstance(recipient_room_keys_token, RoomKeysToken):
            self._recipient_room_keys_token = recipient_room_keys_token
        else:
            raise Exception("Invalid Room Keys Token")

        if isinstance(user_perm_token, UserPermToken):
            self._user_perm_token = user_perm_token
        else:
            raise Exception("Invalid User Permission Token")

    @property
    def recipient_room_keys_token(self):
        return self._recipient_room_keys_token

    @property
    def user_perm_token(self):
        return self._user_perm_token

    @classmethod
    def create(cls,
               node_id: bytes,
               enc: bytes,
               skr: bytes,
               pks: bytes,
               room_key_token: bytes,
               verify_key: bytes,
               perm_token: bytes) -> "WriteUser":

        return cls(RoomKeysToken.decrypt(node_id, enc, skr, pks, room_key_token),
                   UserPermToken.verify(node_id, verify_key, perm_token))

    def receive_new_room_keys_token(self, skr: bytes, enc: bytes, token: bytes):
        self._recipient_room_keys_token = RoomKeysToken.decrypt(node_id=bytes.fromhex(self._recipient_room_keys_token.node_id),
                                                                enc=enc,
                                                                skr=skr,
                                                                pks=bytes.fromhex(self._recipient_room_keys_token.public_distribution_key),
                                                                token=token)

    def receive_new_perm_token(self, token: bytes):
        self._user_perm_token = UserPermToken.verify(node_id=bytes.fromhex(self._recipient_room_keys_token.node_id),
                                                     public_key=bytes.fromhex(self._recipient_room_keys_token.verify_key),
                                                     token=token)