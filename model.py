from config import db, ma

class Dataroom(db.Model):
    __tablename__ = "datarooms"
    node_id = db.Column(db.Integer, primary_key=True)
    users = db.Column(db.String)
    verification_key = db.Column(db.String(32))
    created_at = db.Column(db.Integer)

    def __init__(self, node_id, users, verification_key, created_at):
        self.node_id = node_id
        self.users = users
        self.verification_key = verification_key
        self.created_at = created_at


class DataroomKeys(db.Model):
    __tablename__ = "dataroom_keys"
    node_id = db.Column(db.Integer, db.ForeignKey('datarooms.node_id'), primary_key=True)
    key_type = db.Column(db.Integer, primary_key=True)  # 1 = secret key, 2 = recipient key, 3 = both
    key_id = db.Column(db.Integer)
    signing_key = db.Column(db.String(32))
    encryption_key = db.Column(db.String(32))
    intermediate_keys = db.Column(db.String)
    created_at = db.Column(db.Integer)

    def __init__(self, node_id, key_type, key_id, signing_key, encryption_key, intermediate_keys, created_at):
        self.node_id = node_id
        self.key_type = key_type
        self.key_id = key_id
        self.signing_key = signing_key
        self.encryption_key = encryption_key
        self.intermediate_keys = intermediate_keys
        self.created_at = created_at


class DataroomKeysSchema(ma.Schema):
    class Meta:
        fields = ('node_id', 'type', 'key_id', 'signing_key', 'encryption_key', 'intermediate_keys', 'created_at')


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
    key_id = db.Column(db.Integer, db.ForeignKey('dataroom_keys.key_id'), primary_key=True)
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
    credential_identifier = db.Column(db.String(32))
    opache_record = db.Column(db.String)

    def __init__(self, user_id, public_key, credential_identifier, opache_record):
        self.user_id = user_id
        self.public_key = public_key
        self.credential_identifier = credential_identifier
        self.opache_record = opache_record


class UsersSchema(ma.Schema):
    class Meta:
        fields = ('user_id', 'public_key')


class UserKeys(db.Model):
    __tablename__ = "user_keys"
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    key_id = db.Column(db.Integer, db.ForeignKey('dataroom_keys.key_id'), primary_key=True)
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

    def __init__(self, session_id, user_id , session_key):
        self.session_id = session_id
        self.user_id = user_id
        self.session_key = session_key


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