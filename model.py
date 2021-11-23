from config import db, ma


class SecretKeys(db.Model):
    __tablename__ = "secret_keys"
    node_id = db.Column(db.Integer, primary_key=True)
    secret_key = db.Column(db.String(32))
    derivation_salt = db.Column(db.String(32))
    created_at = db.Column(db.Integer)

    def __init__(self, node_id, secret_key, derivation_salt, created_at):
        self.node_id = node_id
        self.secret_key = secret_key
        self.derivation_salt = derivation_salt
        self.created_at = created_at


class SecretKeysSchema(ma.Schema):
    class Meta:
        fields = ('node_id', 'secret_key', 'derivation_salt', 'created_at')


class Challenges(db.Model):
    __tablename__ = "challenges"
    key_id = db.Column(db.Integer, db.ForeignKey('secret_keys.node_id'), primary_key=True)
    challenge = db.Column(db.String(32))
    created_at = db.Column(db.Integer)

    def __init__(self, key_id, challenge, created_at):
        self.key_id = key_id
        self.challenge = challenge
        self.created_at = created_at


class ChallengesSchema(ma.Schema):
    class Meta:
        fields = ('key_id', 'challenge', 'created_at')
