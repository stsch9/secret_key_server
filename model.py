from config import db, ma

class Dataroom(db.Model):
    __tablename__ = "datarooms"
    node_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    registration_code = db.Column(db.String)
    status = db.Column(db.Integer)
    created_at = db.Column(db.Integer)

    def __init__(self, name, registration_code, status, created_at):
        self.name = name
        self.registration_code = registration_code
        self.status = status  # 1 = registration first step finished, 2 = registration finished
        self.created_at = created_at


class DataroomKeys(db.Model):
    __tablename__ = "dataroom_keys"
    key_id = db.Column(db.String, primary_key=True)
    node_id = db.Column(db.Integer, db.ForeignKey('datarooms.node_id'))
    key_type = db.Column(db.Integer)  # 1 = secret key, 2 = recipient key, 3 = meta
    signing_key = db.Column(db.String(32))
    token = db.Column(db.String)
    created_at = db.Column(db.Integer)

    def __init__(self, key_id, node_id, key_type, signing_key, token, created_at):
        self.key_id = key_id
        self.node_id = node_id
        self.key_type = key_type
        self.signing_key = signing_key
        self.token = token
        self.created_at = created_at


#class FileKeys(db.Model):
#    __tablename__ = "file_keys"
#    node_id = db.Column(db.Integer, primary_key=True)
#    key_id = db.Column(db.Integer, db.ForeignKey('datarooms.key_id'))
#    pkE = db.Column(db.String())
#    file_key = db.Column(db.String())
#
#    def __init__(self, node_id, key_id, pkE, file_key):
#        self.node_id = node_id
#        self.key_id = key_id
#        self.pkE = pkE
#        self.file_key = file_key
#
#
#class FileKeysSchema(ma.Schema):
#    class Meta:
#        fields = ('node_id', 'key_id', 'pkE', 'file_key')


class Challenges(db.Model):
    __tablename__ = "challenges"
    key_id = db.Column(db.String, db.ForeignKey('dataroom_keys.key_id'), primary_key=True)
    challenge = db.Column(db.String(32))
    created_at = db.Column(db.Integer)

    def __init__(self, key_id, challenge, created_at):
        self.key_id = key_id
        self.challenge = challenge
        self.created_at = created_at


class ChallengesSchema(ma.Schema):
    class Meta:
        fields = ('key_id', 'challenge', 'created_at')


class Users(db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    public_key = db.Column(db.String(32))
    registration_code = db.Column(db.String)
    credential_identifier = db.Column(db.String(32))
    opache_record = db.Column(db.String)
    user_status = db.Column(db.Integer)  # 0 = not registrated, 1 = registration first step finished, 2 = registration finished

    def __init__(self, user_id, public_key, registration_code, credential_identifier, opache_record, user_status):
        self.user_id = user_id
        self.public_key = public_key
        self.registration_code = registration_code
        self.credential_identifier = credential_identifier
        self.opache_record = opache_record
        self.user_status = user_status


class UsersSchema(ma.Schema):
    class Meta:
        fields = ('user_id', 'public_key')


class UserKeys(db.Model):
    __tablename__ = "user_keys"
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    key_id = db.Column(db.String, db.ForeignKey('dataroom_keys.key_id'), primary_key=True)
    encrypted_master_key = db.Column(db.String(72))

    def __init__(self, user_id, key_id, encrypted_master_key):
        self.user_id = user_id
        self.key_id = key_id
        self.encrypted_master_key = encrypted_master_key


class UserKeysSchema(ma.Schema):
    class Meta:
        fields = ('user_id', 'key_id', 'encrypted_master_key')


class UserSessions(db.Model):
    __tablename__ = "user_sessions"
    session_id = db.Column(db.String, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    session_key = db.Column(db.String)
    expected_client_mac = db.Column(db.String)
    session_status = db.Column(db.Integer)  # 0 = not valid, 1 = authentication first step, 2 = authentication finished

    def __init__(self, session_id, user_id , session_key, expected_client_mac, session_status):
        self.session_id = session_id
        self.user_id = user_id
        self.session_key = session_key
        self.expected_client_mac = expected_client_mac
        self.session_status = session_status


class CA(db.Model):
    __tablename__ = "ca"
    ca_key = db.Column(db.String(32), primary_key=True)
    ca_value = db.Column(db.String(32))

    def __init__(self, ca_key, ca_value):
        self.ca_key = ca_key
        self.ca_value = ca_value


class Masks(db.Model):
    __tablename__ = "masks"
    mask_id = db.Column(db.Integer, primary_key=True)
    last_try = db.Column(db.Integer)
    second_last_try = db.Column(db.Integer)

    def __init__(self, mask_id, last_try, second_last_try):
        self.mask_id = mask_id
        self.last_try = last_try
        self.second_last_try = second_last_try