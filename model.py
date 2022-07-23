from config import db, ma


class SecretKeys(db.Model):
    __tablename__ = "secret_keys"
    node_id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.Integer)
    derivation_salt = db.Column(db.String(32))
    signing_key = db.Column(db.String(32))
    encryption_key = db.Column(db.String(32))
    created_at = db.Column(db.Integer)

    def __init__(self, node_id, key_id, derivation_salt, signing_key, encryption_key, created_at):
        self.node_id = node_id
        self.key_id = key_id
        self.derivation_salt = derivation_salt
        self.signing_key = signing_key
        self.encryption_key = encryption_key
        self.created_at = created_at


class SecretKeysSchema(ma.Schema):
    class Meta:
        fields = ('node_id', 'key_id', 'derivation_salt', 'signing_key', 'encryption_key', 'created_at')


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
