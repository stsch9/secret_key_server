import time
import json
from pyseto import Key
import pyseto
from pysodium import crypto_sign_keypair, crypto_sign_seed_keypair
from hmac import compare_digest


class CA(object):
    def __init__(self, sk: bytes, cert: bytes, implicit_assertion=b''):
        self._sk = sk
        self.cert = cert
        self.implicit_assertion = implicit_assertion

        self.pk, sk = crypto_sign_seed_keypair(self._sk)
        self.payload = self.verify(self.pk, cert, implicit_assertion)

    @property
    def cert_file(self) -> bytes:
        return self.cert

    @property
    def verify_key(self) -> bytes:
        return self.pk

    @staticmethod
    def verify(pk: bytes, cert_file: bytes, implicit_assertion=b'') -> dict:
        public_key = Key.from_asymmetric_key_params(4, x=pk)
        decoded = pyseto.decode(keys=public_key,
                                token=cert_file,
                                deserializer=json,
                                implicit_assertion=implicit_assertion)
        payload = decoded.payload

        if not compare_digest(pk, bytes.fromhex(payload['verify_key'])):
            raise Exception("Verification failed")
        else:
            return payload

    @staticmethod
    def new_verify_key(pk: bytes, token: bytes, implicit_assertion=b'') -> dict:
        public_key = Key.from_asymmetric_key_params(4, x=pk)
        decoded = pyseto.decode(keys=public_key,
                                token=token,
                                deserializer=json,
                                implicit_assertion=implicit_assertion)
        payload = decoded.payload

        return payload

    @classmethod
    def create_ca(cls, user_id: int, user_pk: bytes, implicit_assertion=b'') -> "CA":
        pk, sk = crypto_sign_keypair()
        sk = sk[:32]
        payload = {"version": 1,
                   "created_at": int(time.time()),
                   "created_by": user_id,
                   "verify_key": pk.hex(),
                   "verify_key_version": 1,
                   "users": {str(user_id): user_pk.hex()}}
        private_key = Key.from_asymmetric_key_params(4, d=sk)
        token = pyseto.encode(
            private_key,
            payload=payload,
            serializer=json,
            implicit_assertion=implicit_assertion,
        )

        return cls(sk, token, implicit_assertion)

    def rekey(self, signer_id: int, implicit_assertion=b'') -> tuple[bytes, bytes]:
        self.pk, new_sk = crypto_sign_keypair()
        old_pk, old_sk = crypto_sign_seed_keypair(self._sk)
        old_sk = old_sk[:32]
        self._sk = new_sk[:32]
        self.payload["version"] += 1
        self.payload['created_at'] = int(time.time())
        self.payload['created_by'] = signer_id
        self.payload['verify_key'] = self.pk.hex()
        self.payload['verify_key_version'] +=1

        private_key = Key.from_asymmetric_key_params(4, d=self._sk)
        token = pyseto.encode(
            private_key,
            payload=self.payload,
            serializer=json,
            implicit_assertion=implicit_assertion,
        )

        payload_verify_key = {self.payload['verify_key_version'] - 1 : old_pk.hex(),
                              self.payload['verify_key_version'] : self.pk.hex()}
        private_key = Key.from_asymmetric_key_params(4, d=old_sk)
        token_verify_key = pyseto.encode(
            private_key,
            payload=payload_verify_key,
            serializer=json,
            implicit_assertion=implicit_assertion,
        )

        return token, token_verify_key

    def add_user(self, signer_id: int, user_id: int, user_pk: bytes, implicit_assertion=b'') -> bytes:
        self.payload["version"] += 1
        self.payload['created_at'] = int(time.time())
        self.payload['created_by'] = signer_id
        self.payload['users'].update({str(user_id): user_pk.hex()})

        private_key = Key.from_asymmetric_key_params(4, d=self._sk)
        token = pyseto.encode(
            private_key,
            payload=self.payload,
            serializer=json,
            implicit_assertion=implicit_assertion,
        )

        return token

    def remove_user(self, signer_id: int, user_id: int, implicit_assertion=b'') -> bytes:
        self.payload["version"] += 1
        self.payload['created_at'] = int(time.time())
        self.payload['created_by'] = signer_id
        try:
            del self.payload['users'][str(user_id)]
        except KeyError:
            raise Exception("User not found")

        private_key = Key.from_asymmetric_key_params(4, d=self._sk)
        token = pyseto.encode(
            private_key,
            payload=self.payload,
            serializer=json,
            implicit_assertion=implicit_assertion,

        )

        return token
