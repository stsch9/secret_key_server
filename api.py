from flask import make_response
import json
import config
import time
import pyseto
from flask_restful import Resource, reqparse
from model import Dataroom, Challenges, ChallengesSchema, Users, UsersSchema, UserKeys, UserKeysSchema, CA, Masks, UserSessions
from nacl.utils import random
from nacl.encoding import Base64Encoder
import nacl.secret
import nacl.exceptions
from resources_server.authentication import authenticate_user
from cryptography.hazmat.primitives import hashes, hmac, constant_time
from oblivious import sodium
from oprf.oprf_ristretto25519_sha512 import BlindEvaluate
from oprf.opaque import Nh, CreateRegistrationResponse, OPAQUE3DH
from resources_client.crypto import MasterKeyUser

#dataroom_key_schema = DataroomKeysSchema()
challenges_schema = ChallengesSchema()
users_schema = UsersSchema()
user_keys_schema = UserKeysSchema()

# ToDo:
# use uuid for mask_id + key_id
# use paseto for enc_mask token

class DataroomManagementInit(Resource):
    # register new dataroom (new master keys (secret + recipient master key)
    # 2 steps since the node_id is used in the tokens
    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('name', required=True)
        parser.add_argument('session_id', required=True, location='cookies')
        parser.add_argument('X-Auth-Signature', required=True, location='headers')
        parser.add_argument('X-Auth-Timestamp', required=True, location='headers')
        args = parser.parse_args()
        session_id = args['session_id']

        session_id_db = authenticate_user(session_id)
        if not session_id_db:
            return make_response(json.dumps({'Error': 'Unauthorized'}), 403)

        registration_code = Base64Encoder.encode(random(32)).decode('utf-8')
        node = Dataroom(name=args['name'], registration_code=registration_code, status=1, created_at=int(time.time()))
        db.session.add(node)
        db.session.commit()

        return make_response(json.dumps({'registration_code': registration_code, 'node_id': node.node_id}))

class DataroomManagementFinish(Resource):
    # register new dataroom (new master keys (secret + recipient master key)
    # 2 steps since the node_id is used in the tokens
    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('node_id', required=True)
        parser.add_argument('registration_code', required=True)
        parser.add_argument('verify_key', required=True)
        parser.add_argument('token_user', required=True)
        parser.add_argument('session_id', required=True, location='cookies')
        parser.add_argument('X-Auth-Signature', required=True, location='headers')
        parser.add_argument('X-Auth-Timestamp', required=True, location='headers')
        args = parser.parse_args()
        registration_code = args['registration_code']
        node_id = args['node_id']
        session_id = args['session_id']
        verify_key = args['verify_key']
        token_user = args['token_user']

        # user authentication
        session_id_db = authenticate_user(session_id)
        if not session_id_db:
            return make_response(json.dumps({'Error': 'Unauthorized'}), 403)

        # validate registration code
        dataroom_db = Dataroom.query.get(node_id)
        if not dataroom_db or dataroom_db.status != 1:
            return make_response(json.dumps({'INFO:': f'Registration of dataroom {node_id} not possible.'}), 400)

        if not constant_time.bytes_eq(bytes.fromhex(registration_code), bytes.fromhex(node_id.registration_code)):
            return make_response(json.dumps({'INFO:': f'Unauthorized'}), 403)

        # verify user token
        try:
            pk = bytes.fromhex(verify_key)
            token = bytes.fromhex(token_user)
            token_cls = MasterKeyUser.verify_token(pk, token)
        except:
            return make_response(json.dumps({'Error': 'Token verification error'}), 400)



        # Pre-checks
        ## check input data are valid
        #try:
        #    raw_encrypted_secret_key = Base64Encoder.decode(encrypted_secret_key)
        #except:
        #    return make_response(json.dumps({'Message:': 'Not valid data'}), 400)

        # check authentication

        # decrypt token_keys

        # validate token_keys payload

        # verify signature token_users

        # validate payload token_users

        # add dataroom

        ###


class DataroomUserManagement(Resource):
    # add a new user to a dataroom
    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('node_id', type=int, required=True, help='node_id must be an integer and cannot be blank', location='args')
        parser.add_argument('token', type=str, required=True, help='token must be an str and cannot be blank')
        parser.add_argument('X-Auth-Signature', required=True, location='headers')
        parser.add_argument('X-Auth-Timestamp', required=True, location='headers')
        args = parser.parse_args()
        node_id = args['node_id']
        token = args['token']

        # check secret key authentication
        secret_key_db = SecretKeys.query.get(node_id)
        if not secret_key_db:
            return make_response(json.dumps({'INFO:': f'Keys for node_id {node_id} does not exist.'}), 400)

        challenge_db = Challenges.query.get(secret_key_db.key_id)
        if not challenge_db:
            return make_response(json.dumps({'INFO:': 'no challenge found'}), 400)
        # to prevent replay attacks, delete challenge
        db.session.delete(challenge_db)
        db.session.commit()

        # check signature
        raw_signing_key = Base64Encoder.decode(secret_key_db.signing_key)

        if not hmac_auth(raw_signing_key, Base64Encoder.decode(challenge_db.challenge)):
            return make_response(json.dumps({'Message:': 'Invalid Signature'}), 400)

        # decrypt token
        try:
            raw_encryption_key = Base64Encoder.decode(secret_key_db.encryption_key)
            pyseto_key = pyseto.Key.new(version=4, purpose="local", key=raw_encryption_key)
            pyseto_decode = pyseto.decode(pyseto_key, token, deserializer=json)
        except pyseto.DecryptError:
            return make_response(json.dumps({'ERROR:': f'Decrypting token failed.'}), 500)

        # check payload
        for i in ["user_id", "encrypted_secret_key"]:
            if i not in pyseto_decode.payload:
                return make_response(json.dumps({'ERROR:': f'{i} missing'}), 400)

        user_id = pyseto_decode.payload["user_id"]
        encrypted_secret_key = pyseto_decode.payload["encrypted_secret_key"]

        try:
            raw_encrypted_secret_key = Base64Encoder.decode(encrypted_secret_key)
        except:
            return make_response(json.dumps({'Message:': 'Not valid data'}), 400)

        if len(raw_encrypted_secret_key) != 72:
            return make_response(json.dumps({'Message:': 'Not valid input data'}), 400)

        # check db entries
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
    # remove user from a dataroom -> renew secret + recipient master keys
    def put():
        parser = reqparse.RequestParser()
        parser.add_argument('node_id', type=int, required=True, help='node_id must be an integer and cannot be blank',
                            location='args')
        parser.add_argument('token', required=True, help='token cannot be blank')# , location='form')
        parser.add_argument('X-Auth-Signature', required=True, location='headers')
        parser.add_argument('X-Auth-Timestamp', required=True, location='headers')
        args = parser.parse_args()
        node_id = args['node_id']
        token = args['token']

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

        # decrypt token
        try:
            pyseto_key = pyseto.Key.new(version=4, purpose="local", key=raw_old_encryption_key)
            pyseto_decode = pyseto.decode(pyseto_key, token, deserializer=json)
        except pyseto.DecryptError:
            return make_response(json.dumps({'ERROR:': f'Decrypting token failed.'}), 500)

        # check payload
        for i in ['derivation_salt', 'signing_key', 'encryption_key', 'encrypted_private_key', 'public_key', 'users']:
            if i not in pyseto_decode.payload:
                return make_response(json.dumps({'ERROR:': f'{i} missing'}), 400)

        try:
            raw_derivation_salt = Base64Encoder.decode(pyseto_decode.payload['derivation_salt'])
            raw_signing_key = Base64Encoder.decode(pyseto_decode.payload['signing_key'])
            raw_encryption_key = Base64Encoder.decode(pyseto_decode.payload['encryption_key'])
            raw_encrypted_private_key = Base64Encoder.decode(pyseto_decode.payload['encrypted_private_key'])
            raw_public_key = Base64Encoder.decode(pyseto_decode.payload['public_key'])
        except:
            return make_response(json.dumps({'Message:': 'Not valid datas'}), 400)

        if len(raw_derivation_salt) != 32 or len(raw_signing_key) != 32 or len(raw_encryption_key) != 32 \
                or len(raw_encrypted_private_key) != 72 or len(raw_public_key) != 32:
            return make_response(json.dumps({'Message:': 'Not valid datas'}), 400)

        # check users
        users = pyseto_decode.payload['users']
        for i in users:
            user_keys_db = UserKeys.query.get((node_id, i['user_id']))
            if user_keys_db:
                user_keys_db.secret_key = i['encrypted_secret_key']
            else:
                new_user_key = UserKeys(i['user_id'], node_id, i['secret_key'])
                db.session.add(new_user_key)

        # andere User löschen?

        # change derivation_salt, etc.
        new_key_id = int(time.time())
        secret_key_db.key_id = new_key_id
        secret_key_db.derivation_salt = pyseto_decode.payload['derivation_salt']
        secret_key_db.signing_key = pyseto_decode.payload['signing_key']
        secret_key_db.encryption_key = pyseto_decode.payload['encryption_key']
        secret_key_db.encrypted_private_key = pyseto_decode.payload['encrypted_private_key']
        secret_key_db.public_key = pyseto_decode.payload['public_key']
        secret_key_db.created_at = new_key_id

        db.session.commit()

        return make_response(json.dumps({'message': 'Successfully changed user keys.'}), 200)


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
        args = parser.parse_args()
        user_id = args['user_id']

        user_db = Users.query.get(user_id)
        if user_db:
            return make_response(json.dumps({'INFO:': f'User {user_id} already exists.'}), 400)

        try:
            registration_code = random()
            user = Users(user_id, None, registration_code.hex(), None, None, 0)
            db.session.add(user)
            db.session.commit()
            return make_response(json.dumps({'registration_code': f'{registration_code.hex()}'}), 200)
        except:
            return make_response(json.dumps({'ERROR': f'Adding user {user_id} failed'}),
                                 500)


class OpacheRegistrationInit(Resource):
    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', type=int, required=True, help='user_id must be an integer and cannot be blank')
        parser.add_argument('request', type=str, required=True, help='request cannot be blank')
        parser.add_argument('registration_code', type=str, required=True, help='registration_code cannot be blank')
        args = parser.parse_args()
        user_id = args['user_id']
        request = args['request']
        registration_code = args['registration_code']

        user_db = Users.query.get(user_id)
        if not user_db:
            return make_response(json.dumps({'INFO:': f'User {user_id} does not exists.'}), 400)

        if not constant_time.bytes_eq(bytes.fromhex(registration_code), bytes.fromhex(user_db.registration_code)):
            return make_response(json.dumps({'INFO:': f'Unauthorized'}), 403)

        if user_db.user_status != 0:
            return make_response(json.dumps({'INFO:': f'Start registration first.'}), 400)

        if not user_db.credential_identifier:
            credential_identifier = random(Nh)
        else:
            return make_response(json.dumps({'INFO:': f'User {user_id} is already registered.'}), 400)

        server_public_key_db = CA.query.get('opache_server_public_key')
        oprf_seed_db = CA.query.get('oprf_seed')
        raw_request = bytes.fromhex(request)
        raw_server_public_key = Base64Encoder.decode(server_public_key_db.ca_value)
        raw_oprf_seed = Base64Encoder.decode(oprf_seed_db.ca_value)
        raw_evaluated_message, _ = CreateRegistrationResponse(raw_request, raw_server_public_key,
                                                              credential_identifier, raw_oprf_seed)

        user_db.credential_identifier = Base64Encoder.encode(credential_identifier).decode('utf-8')
        user_db.user_status = 1
        db.session.commit()

        evaluated_message = Base64Encoder.encode(raw_evaluated_message).decode('utf-8')
        return make_response(json.dumps({'evaluated_message': f'{evaluated_message}',
                                         'server_public_key': f'{server_public_key_db.ca_value}'}))


class OpacheRegistrationFinish(Resource):
    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', type=int, required=True, help='user_id must be an integer and cannot be blank')
        parser.add_argument('record', type=str, required=True, help='record cannot be blank')
        parser.add_argument('registration_code', type=str, required=True, help='registration_code cannot be blank')
        args = parser.parse_args()
        user_id = args['user_id']
        record = args['record']
        registration_code = args['registration_code']

        user_db = Users.query.get(user_id)
        if not user_db:
            return make_response(json.dumps({'INFO:': f'User {user_id} does not exists.'}), 400)

        if not constant_time.bytes_eq(bytes.fromhex(registration_code), bytes.fromhex(user_db.registration_code)):
            return make_response(json.dumps({'INFO:': f'Unauthorized'}), 403)

        if not user_db.credential_identifier:
            return make_response(json.dumps({'INFO:': f'credential_identifier does not exists.'}), 400)

        if user_db.user_status != 1:
            return make_response(json.dumps({'INFO:': f'User {user_id} is already registered.'}), 400)

        user_db.opache_record = record
        user_db.user_status = 2
        db.session.commit()

        return make_response(json.dumps({'INFO:': f'Registration for user {user_id} completed'}), 200)


class OpacheServerInit(Resource):
    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', type=int, required=True, help='user_id must be an integer and cannot be blank')
        parser.add_argument('ke1', type=str, required=True, help='ke1 cannot be blank')
        args = parser.parse_args()
        user_id = args['user_id']
        ke1 = args['ke1']

        user_db = Users.query.get(user_id)
        if not user_db:
            return make_response(json.dumps({'INFO:': f'User {user_id} does not exists.'}), 400)

        if user_db.user_status != 2:
            return make_response(json.dumps({'INFO:': f'User {user_id} is not registered.'}), 400)

        oprf_seed_db = CA.query.get('oprf_seed')
        server_private_key_db = CA.query.get('opache_server_private_key')
        server_public_key_db = CA.query.get('opache_server_public_key')

        opache3dh = OPAQUE3DH()
        raw_ke2 = opache3dh.ServerInit(Base64Encoder.decode(server_private_key_db.ca_value),
                                       Base64Encoder.decode(server_public_key_db.ca_value),
                                       Base64Encoder.decode(user_db.opache_record),
                                       Base64Encoder.decode(user_db.credential_identifier),
                                       Base64Encoder.decode(oprf_seed_db.ca_value), bytes.fromhex(ke1))

        ke2 = Base64Encoder.encode(raw_ke2).decode('utf-8')

        session_id = Base64Encoder.encode(random(32)).decode('utf-8')
        user_session = UserSessions(session_id, user_id, Base64Encoder.encode(opache3dh.state['session_key']).decode('utf-8'),
                                    Base64Encoder.encode(opache3dh.state['expected_client_mac']).decode('utf-8'), 1)
        db.session.add(user_session)
        db.session.commit()

        return make_response(json.dumps({'ke2': f'{ke2}', 'session_id': f'{session_id}'}), 200)


class OpacheServerFinish(Resource):
    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('session_id', required=True, location='cookies')
        parser.add_argument('ke3', type=str, required=True, help='ke3 cannot be blank')
        args = parser.parse_args()
        session_id = args['session_id']
        ke3 = args['ke3']

        user_sessions_db = UserSessions.query.get(session_id)
        if not user_sessions_db:
            return make_response(json.dumps({'INFO:': f'Session does not exists.'}), 400)

        if user_sessions_db.session_status != 1:
            return make_response(json.dumps({'INFO:': f'Invalid registration.'}), 400)

        expected_client_mac = user_sessions_db.expected_client_mac
        session_key = user_sessions_db.session_key

        opache3dh = OPAQUE3DH()
        opache3dh.state['expected_client_mac'] = Base64Encoder.decode(expected_client_mac)
        opache3dh.state['session_key'] = Base64Encoder.decode(session_key)
        raw_session_key = opache3dh.ServerFinish(bytes.fromhex(ke3))

        user_sessions_db.session_key = Base64Encoder.encode(raw_session_key).decode('utf-8')
        user_sessions_db.session_status = 2
        db.session.commit()

        return make_response(json.dumps({'authentication': 'success'}), 200)


class PrivateKeyManagement(Resource):
    @staticmethod
    def get():
        parser = reqparse.RequestParser()
        parser.add_argument('blinded_element', required=True, help='blinded_element cannot be blank',
                            location='args')
        parser.add_argument('enc_mask', required=True, help='enc_mask cannot be blank',
                            location='args')
        args = parser.parse_args()
        blinded_element = args['blinded_element']
        enc_mask = args['enc_mask']

        try:
            raw_blinded_element = Base64Encoder.decode(blinded_element)
            raw_enc_mask = Base64Encoder.decode(enc_mask)
        except:
            return make_response(json.dumps({'Message:': 'Not valid datas'}), 400)

        if len(raw_blinded_element) != 32 or len(raw_enc_mask) != 76:
            return make_response(json.dumps({'Message:': 'Not valid datas'}), 400)

        ca_db = CA.query.get('secret_mask_key')
        try:
            box = nacl.secret.SecretBox(Base64Encoder.decode(ca_db.ca_value))
            raw_mask_token = box.decrypt(raw_enc_mask)
        except nacl.exceptions.CryptoError:
            return make_response(json.dumps({'ERROR:': f'Decryption of mask failed.'}), 500)

        raw_mask_id = raw_mask_token[:4]
        raw_mask = raw_mask_token[4:]

        mask_id = int.from_bytes(raw_mask_id, "big")

        mask_db = Masks.query.get(mask_id)
        if not mask_db:
            return make_response(json.dumps({'INFO:': f'Mask {mask_id} does not exists.'}), 400)

        # Check last two tries
        if mask_db.second_last_try:
            time_diff = int(time.time()) - mask_db.second_last_try
            if time_diff < 5 * 60 * 1000:
                return make_response(json.dumps({'INFO:': f'Too many tries in last 5 min.'}), 400)

        try:
            mask_db.second_last_try = mask_db.last_try
            mask_db.last_try = int(time.time())
            db.session.commit()

            raw_evaluated_element = BlindEvaluate(raw_mask, raw_blinded_element)
            return make_response(
                json.dumps({'evaluated_element': Base64Encoder.encode(raw_evaluated_element).decode('utf-8')}))
        except:
            return make_response(json.dumps({'ERROR:': f'Calculating evaluated_element failed.'}), 500)

    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', type=int, required=True, help='user_id must be an integer and cannot be blank')
        args = parser.parse_args()
        user_id = args['user_id']

        user_db = Users.query.get(user_id)
        if not user_db:
            return make_response(json.dumps({'INFO:': f'User {user_id} does not exists.'}), 400)

        if user_db.private_key_mask:
            return make_response(json.dumps({'INFO:': f'Mask for user {user_id} already exists.'}), 400)

        raw_mask = sodium.rnd()
        mask_id = int(time.time())

        ca_db = CA.query.get('secret_mask_key')
        try:
            box = nacl.secret.SecretBox(Base64Encoder.decode(ca_db.ca_value))
            raw_enc_mask = box.encrypt(mask_id.to_bytes(4, byteorder='big') + raw_mask)
        except nacl.exceptions.CryptoError:
            return make_response(json.dumps({'ERROR:': f'Encryption of mask failed.'}), 500)

        try:
            user_db.private_key_mask = True

            mask = Masks(mask_id, None, None)
            db.session.add(mask)

            db.session.commit()
            return make_response(json.dumps({'enc_mask': Base64Encoder.encode(raw_enc_mask).decode('utf-8')}))
        except:
            return make_response(json.dumps({'ERROR:': f'Adding mask failed.'}), 500)


api = config.api
app = config.app
db = config.db

api.add_resource(OpacheRegistrationInit, '/api/user-registration-init')
api.add_resource(OpacheRegistrationFinish, '/api/user-registration-finish')
api.add_resource(OpacheServerInit, '/api/user-authentication-init')
api.add_resource(OpacheServerFinish, '/api/user-authentication-finish')
api.add_resource(DataroomManagementInit, '/api/dataroom/init')
api.add_resource(DataroomManagementFinish, '/api/dataroom/finish')
#api.add_resource(DataroomManagementUpdate, '/api/dataroom/update')
api.add_resource(DataroomUserManagement, '/api/dataroom/users-keys')
api.add_resource(ValidateKeyManagement, '/api/dataroom/validate_secret_key')
api.add_resource(ChallengeResponseManagement, '/api/dataroom/challenge')
api.add_resource(UserManagement, '/api/user')
api.add_resource(PrivateKeyManagement, '/api/private_key')

if __name__ == '__main__':
    if not CA.query.get('secret_mask_key'):
        raw_secret_mask_key = random()
        key_value = CA('secret_mask_key', Base64Encoder.encode(raw_secret_mask_key).decode('utf-8'))
        db.session.add(key_value)
        db.session.commit()
    if not CA.query.get('oprf_seed'):
        raw_oprf_seed = random(Nh)
        key_value_oprf_seed = CA('oprf_seed', Base64Encoder.encode(raw_oprf_seed).decode('utf-8'))
        db.session.add(key_value_oprf_seed)
        db.session.commit()
    if not CA.query.get('opache_server_private_key') and not CA.query.get('opache_server_public_key'):
        raw_server_private_key = sodium.rnd()
        raw_server_public_key = sodium.bas(raw_server_private_key)
        key_value_server_private_key = CA('opache_server_private_key',
                                          Base64Encoder.encode(raw_server_private_key).decode('utf-8'))
        key_value_server_public_key = CA('opache_server_public_key',
                                          Base64Encoder.encode(raw_server_public_key).decode('utf-8'))
        db.session.add(key_value_server_private_key)
        db.session.add(key_value_server_public_key)
        db.session.commit()
    elif not CA.query.get('opache_server_private_key'):
        raise Exception("Inconsistent database")
    elif not CA.query.get('opache_server_public_key'):
        raise Exception("Inconsistent database")
    app.run(debug=True)
