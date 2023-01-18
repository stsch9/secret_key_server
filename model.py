from config import db, ma


class SecretKeys(db.Model):
    __tablename__ = "secret_keys"
    node_id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.Integer)
    derivation_salt = db.Column(db.String(32))
    signing_key = db.Column(db.String(32))
    encryption_key = db.Column(db.String(32))
    encrypted_intermediate_keys = db.Column(db.String)
    public_key = db.Column(db.String(32))
    created_at = db.Column(db.Integer)

    def __init__(self, node_id, key_id, derivation_salt, signing_key, encryption_key, encrypted_intermediate_keys,
                 public_key, created_at):
        self.node_id = node_id
        self.key_id = key_id
        self.derivation_salt = derivation_salt
        self.signing_key = signing_key
        self.encryption_key = encryption_key
        self.encrypted_intermediate_keys = encrypted_intermediate_keys
        self.public_key = public_key
        self.created_at = created_at


class SecretKeysSchema(ma.Schema):
    class Meta:
        fields = ('node_id', 'key_id', 'derivation_salt', 'signing_key', 'encryption_key',
                  'encrypted_intermediate_keys', 'public_key', 'created_at')


class FileKeySalts(db.Model):
    __tablename__ = "file_key_salts"
    node_id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.Integer, db.ForeignKey('secret_keys.key_id'))
    salt = db.Column(db.String())

    def __init__(self, node_id, key_id, salt):
        self.node_id = node_id
        self.key_id = key_id
        self.salt = salt


class FileKeySaltsSchema(ma.Schema):
    class Meta:
        fields = ('node_id', 'key_id', 'salt')


class Challenges(db.Model):
    __tablename__ = "challenges"
    key_id = db.Column(db.Integer, db.ForeignKey('secret_keys.key_id'), primary_key=True)
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
    private_key_mask = db.Column(db.String(32))

    def __init__(self, user_id, public_key, private_key_mask):
        self.user_id = user_id
        self.public_key = public_key
        self.private_key_mask = private_key_mask


class UsersSchema(ma.Schema):
    class Meta:
        fields = ('user_id', 'public_key')


class UserKeys(db.Model):
    __tablename__ = "user_keys"
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    node_id = db.Column(db.Integer, db.ForeignKey('secret_keys.node_id'), primary_key=True)
    encrypted_master_key = db.Column(db.String(72))

    def __init__(self, user_id, node_id, encrypted_master_key):
        self.user_id = user_id
        self.node_id = node_id
        self.encrypted_master_key = encrypted_master_key


class UserKeysSchema(ma.Schema):
    class Meta:
        fields = ('user_id', 'node_id', 'encrypted_master_key')


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