from flask import make_response
import json
import config
import time
from flask_restful import Resource, reqparse
from model import SecretKeys, SecretKeysSchema, Challenges, ChallengesSchema
from nacl.hash import blake2b
from nacl.utils import random
from nacl.encoding import Base64Encoder, RawEncoder
from nacl.bindings.utils import sodium_memcmp
from resources_server.authentication import hmac_auth

secret_key_schema = SecretKeysSchema()
challenges_schema = ChallengesSchema()


class SecretKeyManagement(Resource):
    # register new key
    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('node_id', type=int, required=True, help='node_id must be an integer and cannot be blank')
        parser.add_argument('derivation_salt', required=True, help='derivation_salt cannot be blank')
        parser.add_argument('signing_key', required=True, help='signing_key cannot be blank')
        parser.add_argument('encryption_key', required=True, help='encryption_key cannot be blank')
        args = parser.parse_args()
        node_id = args['node_id']

        secret_key_db = SecretKeys.query.get(node_id)
        if secret_key_db:
            return make_response(json.dumps({'INFO:': f'Keys for node_id {node_id} already exists.'}), 400)
        else:
            derivation_salt = args['derivation_salt']
            signing_key = args['signing_key']
            encryption_key = args['encryption_key']
            created_at = int(time.time())
            key_id = created_at

            try:
                raw_signing_key = Base64Encoder.decode(signing_key)
                raw_encryption_key = Base64Encoder.decode(encryption_key)
            except:
                return make_response(json.dumps({'Message:': 'Not valid keys'}), 400)

            try:
                raw_derivation_salt = Base64Encoder.decode(derivation_salt)
            except:
                return make_response(json.dumps({'Message:': 'Not a valid derivation salt'}), 400)

            if len(raw_signing_key) != 32 or len(raw_encryption_key) != 32:
                return make_response(json.dumps({'Message:': 'Not valid keys'}), 400)
            elif len(raw_derivation_salt) != 32:
                return make_response(json.dumps({'Message:': 'Not a valid derivation salt'}), 400)
            else:
                secret_key_new_db = SecretKeys(node_id, key_id, derivation_salt, signing_key, encryption_key, created_at)
                db.session.add(secret_key_new_db)

                db.session.commit()
                return make_response(json.dumps({'Message:': f'Keys for node_id {node_id} added'}), 200)

    @staticmethod
    def put():
        parser = reqparse.RequestParser()
        parser.add_argument('node_id', type=int, required=True, help='node_id must be an integer and cannot be blank')
        parser.add_argument('derivation_salt', required=True, help='derivation_salt cannot be blank')
        parser.add_argument('signing_key', required=True, help='signing_key cannot be blank')
        parser.add_argument('encryption_key', required=True, help='encryption_key cannot be blank')
        parser.add_argument('X-Auth-Signature', required=True, location='headers')
        parser.add_argument('X-Auth-Timestamp', required=True, location='headers')
        args = parser.parse_args()
        node_id = args['node_id']
        derivation_salt= args['derivation_salt']
        signing_key = args['signing_key']
        encryption_key = args['encryption_key']

        try:
            raw_derivation_salt = Base64Encoder.decode(derivation_salt)
            raw_signing_key = Base64Encoder.decode(signing_key)
            raw_encryption_key = Base64Encoder.decode(encryption_key)
        except:
            return make_response(json.dumps({'Message:': 'Not valid datas'}), 400)

        if len(raw_derivation_salt) != 32 or len(raw_signing_key) !=32 or len(raw_encryption_key) != 32:
            return make_response(json.dumps({'Message:': 'Not valid datas'}), 400)

        secret_key_db = SecretKeys.query.get(node_id)
        if not secret_key_db:
            return make_response(json.dumps({'INFO:': f'Keys for node_id {node_id} does not exist.'}), 400)

        challenge_db = Challenges.query.get(secret_key_db.key_id)
        # to prevent replay attacks
        db.session.delete(challenge_db)
        db.session.commit()

        if not hmac_auth(challenge_db.signing_key):
            return make_response(json.dumps({'Message:': 'Invalid Signature'}), 400)

        new_key_id = int(time.time())
        secret_key_db.key_id = new_key_id
        secret_key_db.derivation_salt = derivation_salt
        secret_key_db.signing_key = signing_key
        secret_key_db.encryption_key = encryption_key
        secret_key_db.created_at = new_key_id
        db.session.commit()
        return make_response(json.dumps({'Message:': f'secret keys for node_id {node_id} altered'}), 200)

class ValidateKeyManagement(Resource):
    @staticmethod
    def get():
        parser = reqparse.RequestParser()
        parser.add_argument('node_id', type=int, required=True, help='node_id must be an integer and cannot be blank')
        args = parser.parse_args()
        node_id = args['node_id']

        secret_key_db = SecretKeys.query.get(node_id)
        if not secret_key_db:
            return make_response(json.dumps({'Message:': 'node_id not found'}), 400)

        raw_challenge = random()
        base64_challenge = Base64Encoder.encode(raw_challenge).decode('utf-8')
        signature = blake2b(raw_challenge, key=Base64Encoder.decode(secret_key_db.secret_key),
                            encoder=Base64Encoder).decode('utf-8')

        return make_response(json.dumps(
            {'challenge': base64_challenge, 'signature': signature, 'derivation_salt': secret_key_db.derivation_salt}))


class ChallengeResponseManagement(Resource):
    @staticmethod
    # validate if secret key is up to date
    def get():
        parser = reqparse.RequestParser()
        parser.add_argument('node_id', type=int, required=True, help='node_id must be an integer and cannot be blank')
        args = parser.parse_args()
        node_id = args['node_id']

        secret_key_db = SecretKeys.query.get(node_id)
        if not secret_key_db:
            return make_response(json.dumps({'INFO:': f'Secret Key for node_id {node_id} does not exists.'}), 400)

        challenge_db = Challenges.query.get(secret_key_db.key_id)
        created_at = int(time.time())
        if challenge_db and challenge_db.created_at + 60 > created_at:
            return make_response(json.dumps({'INFO:': f'Challenge for secret key {node_id} already exists.'}), 400)

        try:
            raw_challenge = random()
            base64_challenge = Base64Encoder.encode(raw_challenge).decode('utf-8')

            if challenge_db:
                challenge_db.challenge = base64_challenge
                challenge_db.created_at = created_at
            else:
                challenge_new = Challenges(secret_key_db.key_id, base64_challenge, created_at)
                db.session.add(challenge_new)

            db.session.commit()

            return make_response(
                json.dumps({'challenge': base64_challenge, 'derivation_salt': secret_key_db.derivation_salt}))
        except:
            return make_response(json.dumps({'Message': 'Internal Server Error'}), 500)

    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('node_id', type=int, required=True, help='node_id must be an integer and cannot be blank')
        parser.add_argument('response', required=True, help='response cannot be blank')
        parser.add_argument('secret_key')
        parser.add_argument('derivation_salt')
        args = parser.parse_args()
        node_id = args['node_id']
        response = args['response']

        try:
            raw_response = Base64Encoder.decode(response)
        except:
            return make_response(json.dumps({'Message:': 'Not a valid response'}), 400)

        secret_key_db = SecretKeys.query.get(node_id)
        if not secret_key_db:
            return make_response(json.dumps({'INFO:': f'Secret Key for node_id {node_id} does not exists.'}), 400)

        challenge_db = Challenges.query.get(node_id)
        time_response = int(time.time())
        if not challenge_db or challenge_db.created_at + 60 < time_response:
            return make_response(
                json.dumps({'INFO:': f'Challenge for Public key {node_id} does not exists or response comes too late'}),
                400)

        try:
            raw_challenge = Base64Encoder.decode(challenge_db.challenge)
            signature = blake2b(raw_challenge, key=Base64Encoder.decode(secret_key_db.signing_key), encoder=RawEncoder)
        except:
            return make_response(json.dumps({'ERROR': 'decoding base64 input failed'}), 400)

        if sodium_memcmp(signature, raw_response):
            # to prevent replay attacks
            # hier gehts weiter vielleicht challange ganz am Anfang löschen.
            db.session.delete(challenge_db)
            db.session.commit()

            try:
                secret_key = args['secret_key']
                derivation_salt = args['derivation_salt']
            except Exception as _:
                secret_key = None
                derivation_salt = None

            if not secret_key:
                db.session.delete(secret_key_db)
                db.session.commit()
                return make_response(json.dumps({'Message': f'secret key {node_id} deleted'}), 200)
            else:
                try:
                    raw_secret_key = Base64Encoder.decode(secret_key)
                except:
                    return make_response(json.dumps({'Message:': 'Not a valid public Key'}), 400)

                try:
                    raw_derivation_salt = Base64Encoder.decode(derivation_salt)
                except:
                    return make_response(json.dumps({'Message:': 'Not a valid derivation salt'}), 400)

                if len(raw_secret_key) != 32:
                    return make_response(json.dumps({'Message:': 'Not a valid public Key'}), 400)
                elif len(raw_derivation_salt) != 16:
                    return make_response(json.dumps({'Message:': 'Not a valid derivation salt'}), 400)
                else:
                    secret_key_db.secret_key = secret_key
                    secret_key_db.derivation_salt = derivation_salt
                    secret_key_db.created_at = int(time.time())
                    db.session.commit()
                    return make_response(json.dumps({'Message:': f'secret key {node_id} altered'}), 200)

        else:
            return make_response(json.dumps({'ERROR': 'invalid response'}), 400)


api = config.api
app = config.app
db = config.db

api.add_resource(SecretKeyManagement, '/api/key')
api.add_resource(ValidateKeyManagement, '/api/validate_secret_key')
api.add_resource(ChallengeResponseManagement, '/api/challenge')

if __name__ == '__main__':
    app.run(debug=True)
