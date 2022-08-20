from flask import make_response
import json
import config
import time
from flask_restful import Resource, reqparse
from model import SecretKeys, SecretKeysSchema, Challenges, ChallengesSchema, Users, UsersSchema, UserKeys, UserKeysSchema
from nacl.utils import random
from nacl.encoding import Base64Encoder
import nacl.secret
import nacl.exceptions
from resources_server.authentication import hmac_auth
from cryptography.hazmat.primitives import hashes, hmac

secret_key_schema = SecretKeysSchema()
challenges_schema = ChallengesSchema()
users_schema = UsersSchema()
user_keys_schema = UserKeysSchema()


class SecretKeyManagement(Resource):
    # register new key
    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('node_id', type=int, required=True, help='node_id must be an integer and cannot be blank')
        parser.add_argument('derivation_salt', required=True, help='derivation_salt cannot be blank')
        parser.add_argument('signing_key', required=True, help='signing_key cannot be blank')
        parser.add_argument('encryption_key', required=True, help='encryption_key cannot be blank')
        parser.add_argument('encrypted_private_key', required=True, help='encrypted_private_key cannot be blank')
        parser.add_argument('public_key', required=True, help='public_key cannot be blank')
        args = parser.parse_args()
        node_id = args['node_id']

        secret_key_db = SecretKeys.query.get(node_id)
        if secret_key_db:
            return make_response(json.dumps({'INFO:': f'Keys for node_id {node_id} already exists.'}), 400)
        else:
            derivation_salt = args['derivation_salt']
            signing_key = args['signing_key']
            encryption_key = args['encryption_key']
            encrypted_private_key = args['encrypted_private_key']
            public_key = args['public_key']
            created_at = int(time.time())
            key_id = created_at

            try:
                raw_signing_key = Base64Encoder.decode(signing_key)
                raw_encryption_key = Base64Encoder.decode(encryption_key)
                raw_encrypted_private_key = Base64Encoder.decode(encrypted_private_key)
                raw_public_key = Base64Encoder.decode(public_key)
            except:
                return make_response(json.dumps({'Message:': 'Not valid keys'}), 400)

            try:
                raw_derivation_salt = Base64Encoder.decode(derivation_salt)
            except:
                return make_response(json.dumps({'Message:': 'Not a valid derivation salt'}), 400)

            if len(raw_signing_key) != 32 or len(raw_encryption_key) != 32 or len(raw_encrypted_private_key) != 72 or len(raw_public_key) != 32:
                return make_response(json.dumps({'Message:': 'Not valid keys'}), 400)
            elif len(raw_derivation_salt) != 32:
                return make_response(json.dumps({'Message:': 'Not a valid derivation salt'}), 400)
            else:
                secret_key_new_db = SecretKeys(node_id, key_id, derivation_salt, signing_key, encryption_key, encrypted_private_key, public_key, created_at)
                db.session.add(secret_key_new_db)

                db.session.commit()
                return make_response(json.dumps({'Message:': f'Keys for node_id {node_id} added'}), 200)

    @staticmethod
    def put():
        parser = reqparse.RequestParser()
        parser.add_argument('node_id', type=int, required=True, help='node_id must be an integer and cannot be blank', location='args')
        parser.add_argument('derivation_salt', required=True, help='derivation_salt cannot be blank')
        parser.add_argument('encrypted_keys', required=True, help='encrypted_keys cannot be blank')
        parser.add_argument('encrypted_private_key', required=True, help='encrypted_private_key cannot be blank')
        parser.add_argument('public_key', required=True, help='public_key cannot be blank')
        parser.add_argument('X-Auth-Signature', required=True, location='headers')
        parser.add_argument('X-Auth-Timestamp', required=True, location='headers')
        args = parser.parse_args()
        node_id = args['node_id']
        derivation_salt= args['derivation_salt']
        encrypted_keys = args['encrypted_keys']
        encrypted_private_key = args['encrypted_private_key']
        public_key = args['public_key']

        try:
            raw_derivation_salt = Base64Encoder.decode(derivation_salt)
            raw_encrypted_keys = Base64Encoder.decode(encrypted_keys)
            raw_encrypted_private_key = Base64Encoder.decode(encrypted_private_key)
            raw_public_key = Base64Encoder.decode(public_key)
        except:
            return make_response(json.dumps({'Message:': 'Not valid datas'}), 400)

        if len(raw_derivation_salt) != 32 or len(raw_encrypted_keys) != 104 or len(raw_encrypted_private_key) != 72 or len(raw_public_key) != 32:
            return make_response(json.dumps({'Message:': 'Not valid datas'}), 400)

        secret_key_db = SecretKeys.query.get(node_id)
        if not secret_key_db:
            return make_response(json.dumps({'INFO:': f'Keys for node_id {node_id} does not exist.'}), 400)

        challenge_db = Challenges.query.get(secret_key_db.key_id)
        # to prevent replay attacks
        db.session.delete(challenge_db)
        db.session.commit()

        # decrypting of signing an encryption key
        raw_old_signing_key = Base64Encoder.decode(secret_key_db.signing_key)
        raw_old_encryption_key = Base64Encoder.decode(secret_key_db.encryption_key)

        try:
            box = nacl.secret.SecretBox(raw_old_encryption_key)
            new_raw_keys = box.decrypt(raw_encrypted_keys)
            signing_key = Base64Encoder.encode(new_raw_keys[:32]).decode('utf-8')
            encryption_key = Base64Encoder.encode(new_raw_keys[32:]).decode('utf-8')
        except nacl.exceptions.CryptoError:
            return make_response(json.dumps({'ERROR:': f'Decryption of Keys failed.'}), 500)

        if not hmac_auth(raw_old_signing_key, Base64Encoder.decode(challenge_db.challenge)):
            return make_response(json.dumps({'Message:': 'Invalid Signature'}), 400)

        new_key_id = int(time.time())
        secret_key_db.key_id = new_key_id
        secret_key_db.derivation_salt = derivation_salt
        secret_key_db.signing_key = signing_key
        secret_key_db.encryption_key = encryption_key
        secret_key_db.encrypted_private_key = encrypted_private_key
        secret_key_db.public_key = public_key
        secret_key_db.created_at = new_key_id
        db.session.commit()
        return make_response(json.dumps({'Message:': f'secret keys for node_id {node_id} altered'}), 200)


class UserKeyManagement(Resource):
    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('node_id', type=int, required=True, help='node_id must be an integer and cannot be blank', location='args')
        parser.add_argument('user_id', type=int, required=True, help='user_id must be an integer and cannot be blank')
        parser.add_argument('secret_key', required=True, help='secret_key cannot be blank')
        parser.add_argument('X-Auth-Signature', required=True, location='headers')
        parser.add_argument('X-Auth-Timestamp', required=True, location='headers')
        args = parser.parse_args()
        node_id = args['node_id']
        user_id = args['user_id']
        encrypted_secret_key = args['secret_key']

        # check input data a valid
        try:
            raw_encrypted_secret_key = Base64Encoder.decode(encrypted_secret_key)
        except:
            return make_response(json.dumps({'Message:': 'Not valid secret key'}), 400)

        if len(raw_encrypted_secret_key) != 72:
            return make_response(json.dumps({'Message:': 'Not valid key'}), 400)

        # check secret key authentication
        secret_key_db = SecretKeys.query.get(node_id)
        if not secret_key_db:
            return make_response(json.dumps({'INFO:': f'Keys for node_id {node_id} does not exist.'}), 400)

        challenge_db = Challenges.query.get(secret_key_db.key_id)
        if not challenge_db:
            return make_response(json.dumps({'INFO:': 'no challenge found'}), 400)
        # to prevent replay attacks
        db.session.delete(challenge_db)
        db.session.commit()

        raw_signing_key = Base64Encoder.decode(secret_key_db.signing_key)

        if not hmac_auth(raw_signing_key, Base64Encoder.decode(challenge_db.challenge)):
            return make_response(json.dumps({'Message:': 'Invalid Signature'}), 400)

        user_keys_db = UserKeys.query.get((node_id, user_id))
        if user_keys_db:
            return make_response(json.dumps({'INFO:': f'Key for node_id {node_id} and user {user_id} already exists.'}), 400)

        # add user secret key
        try:
            user_keys_new_db = UserKeys(node_id, user_id, encrypted_secret_key)
            db.session.add(user_keys_new_db)
            db.session.commit()
            return make_response(json.dumps({'Message:': f'Key for node_id {node_id} and user {user_id} added'}), 200)
        except:
            return make_response(json.dumps({'Message:': f'Key for node_id {node_id} or user {user_id} not found'}), 400)

    @staticmethod
    def put():
        parser = reqparse.RequestParser()
        parser.add_argument('node_id', type=int, required=True, help='node_id must be an integer and cannot be blank',
                            location='args')
        parser.add_argument('encrypted_data', required=True, help='encrypted_data cannot be blank')# , location='form')
        parser.add_argument('X-Auth-Signature', required=True, location='headers')
        parser.add_argument('X-Auth-Timestamp', required=True, location='headers')
        args = parser.parse_args()
        node_id = args['node_id']
        encrypted_data = args['encrypted_data']

        # check node_id exists
        secret_key_db = SecretKeys.query.get(node_id)
        if not secret_key_db:
            return make_response(json.dumps({'INFO:': f'Keys for node_id {node_id} does not exist.'}), 400)

        # check challenge exists and delete challenge to prevent replay attacks
        challenge_db = Challenges.query.get(secret_key_db.key_id)
        if not challenge_db:
            return make_response(json.dumps({'INFO:': 'no challenge found'}), 400)
        db.session.delete(challenge_db)
        db.session.commit()

        # decrypting signing an encryption key
        raw_old_signing_key = Base64Encoder.decode(secret_key_db.signing_key)
        raw_old_encryption_key = Base64Encoder.decode(secret_key_db.encryption_key)

        # check signature
        if not hmac_auth(raw_old_signing_key, Base64Encoder.decode(challenge_db.challenge)):
            return make_response(json.dumps({'Message:': 'Invalid Signature'}), 400)

        # decrypt body data
        try:
            box = nacl.secret.SecretBox(raw_old_encryption_key)
            new_raw_data = box.decrypt(Base64Encoder.decode(encrypted_data))
        except nacl.exceptions.CryptoError:
            return make_response(json.dumps({'ERROR:': f'Decryption of Keys failed.'}), 500)

        new_data = json.loads(new_raw_data.decode('utf-8'))

        for i in ['derivation_salt', 'signing_key', 'encryption_key', 'encrypted_private_key', 'public_key', 'users']:
            if i not in new_data:
                return make_response(json.dumps({'ERROR:': f'{i} missing'}), 400)

        try:
            raw_derivation_salt = Base64Encoder.decode(new_data['derivation_salt'])
            raw_signing_key = Base64Encoder.decode(new_data['signing_key'])
            raw_encryption_key = Base64Encoder.decode(new_data['encryption_key'])
            raw_encrypted_private_key = Base64Encoder.decode(new_data['encrypted_private_key'])
            raw_public_key = Base64Encoder.decode(new_data['public_key'])
        except:
            return make_response(json.dumps({'Message:': 'Not valid datas'}), 400)

        if len(raw_derivation_salt) != 32 or len(raw_signing_key) != 32 or len(raw_encryption_key) != 32 \
                or len(raw_encrypted_private_key) != 72 or len(raw_public_key) != 32:
            return make_response(json.dumps({'Message:': 'Not valid datas'}), 400)

        # check users
        users = new_data['users']
        for i in users:
            user_keys_db = UserKeys.query.get((node_id, i['user_id']))
            if user_keys_db:
                user_keys_db.secret_key = i['secret_key']
            else:
                new_user_key = UserKeys(i['user_id'], node_id, i['secret_key'])
                db.session.add(new_user_key)

        # change derivation_salt, etc.
        secret_key_db.derivation_salt = new_data['derivation_salt']
        secret_key_db.signing_key = new_data['signing_key']
        secret_key_db.encryption_key = new_data['encryption_key']
        secret_key_db.encrypted_private_key = new_data['encrypted_private_key']
        secret_key_db.public_key = new_data['public_key']

        db.session.commit()

        return make_response(json.dumps({'Message:': 'Successfully changed user keys.'}), 200)


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

        key_id = secret_key_db.key_id
        h = hmac.HMAC(key=Base64Encoder.decode(secret_key_db.signing_key), algorithm=hashes.SHA256())
        h.update(str(key_id).encode())
        signature = Base64Encoder.encode(h.finalize()).decode('utf-8')

        return make_response(json.dumps(
            {'key_id': key_id, 'signature': signature, 'derivation_salt': secret_key_db.derivation_salt}))


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


class UserManagement(Resource):
    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', type=int, required=True, help='user_id must be an integer and cannot be blank')
        parser.add_argument('public_key')
        args = parser.parse_args()
        user_id = args['user_id']
        public_key = args['public_key']

        user_db = Users.query.get(user_id)
        if user_db:
            return make_response(json.dumps({'INFO:': f'User {user_id} already exists.'}), 400)

        # test public key
        if not public_key:
            user = Users(user_id, None)
        else:
            user = Users(user_id, public_key)

        try:
            db.session.add(user)
            db.session.commit()
            return make_response(json.dumps({'Message:': f'User {user_id} added'}), 200)
        except:
            return make_response(json.dumps({'ERROR:': f'Adding user {user_id} failed'}),
                                 500)


api = config.api
app = config.app
db = config.db

api.add_resource(SecretKeyManagement, '/api/key')
api.add_resource(ValidateKeyManagement, '/api/validate_secret_key')
api.add_resource(ChallengeResponseManagement, '/api/challenge')
api.add_resource(UserManagement, '/api/user')
api.add_resource(UserKeyManagement, '/api/user_keys')

if __name__ == '__main__':
    app.run(debug=True)
