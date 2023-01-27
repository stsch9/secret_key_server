from opaque import CreateRegistrationRequest, CreateRegistrationResponse, CreateCleartextCredentials, Expand, Extract
from oprf_ristretto25519_sha512 import DeriveKeyPair, Finalize
from oblivious import sodium
from cryptography.hazmat.primitives import hashes, hmac

# adapted functions

def Store(randomized_pwd: bytes, server_public_key: bytes, server_identity=b'', client_identity=b'') -> tuple[bytes, bytes, bytes, bytes,]:
    #envelope_nonce = random(Nn)
    envelope_nonce = bytes.fromhex('ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec')
    masking_key = Expand(randomized_pwd, b"MaskingKey", Nh)
    auth_key = Expand(randomized_pwd, envelope_nonce + b"AuthKey", Nh)
    print('auth_key: ' + auth_key.hex())
    export_key = Expand(randomized_pwd, envelope_nonce + b"ExportKey", Nh)
    seed = Expand(randomized_pwd, envelope_nonce + b"PrivateKey", Nseed)
    _, client_public_key = DeriveKeyPair(seed, b"OPAQUE-DeriveAuthKeyPair")

    cleartext_creds = CreateCleartextCredentials(server_public_key, client_public_key, server_identity, client_identity)
    h = hmac.HMAC(auth_key, hashes.SHA512())
    h.update(envelope_nonce + cleartext_creds)
    auth_tag = h.finalize()

    #Create Envelope envelope with (envelope_nonce, auth_tag)
    envelope = envelope_nonce + auth_tag
    return envelope, client_public_key, masking_key, export_key


def FinalizeRegistrationRequest(password: bytes, blind: bytes, evaluated_message: bytes, server_public_key: bytes,
                                server_identity=b'', client_identity=b'') -> tuple[bytes, bytes, bytes, bytes]:
    evaluated_element = evaluated_message
    oprf_output = Finalize(password, blind, evaluated_element)
    print("oprf_output: " + oprf_output.hex())
    stretched_oprf_output = oprf_output
    randomized_pwd = Extract(b'', oprf_output + stretched_oprf_output)
    print('randomized_pwd: ' + randomized_pwd.hex())

    envelope, client_public_key, masking_key, export_key = \
        Store(randomized_pwd, server_public_key, server_identity, client_identity)
    return client_public_key, masking_key, envelope, export_key

# Input Values

Nok = 32
Nn = 32
Nh = 64
Nseed = 32

password = '436f7272656374486f72736542617474657279537461706c65'
server_private_key = '47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d'
server_public_key = sodium.bas(bytes.fromhex(server_private_key))
oprf_seed = 'f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef'
credential_identifier = '31323334'
envelope_nonce = 'ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec'
server_identity = ''
client_identity = ''


print("server_public_key: " + server_public_key.hex())

blinded_message, blind = CreateRegistrationRequest(bytes.fromhex(password))

# derive oprf_key
seed = Expand(bytes.fromhex(oprf_seed), bytes.fromhex(credential_identifier) + b"OprfKey", Nok)
oprf_key, _ = DeriveKeyPair(seed, b"OPAQUE-DeriveKeyPair")
print("oprf_key: " + oprf_key.hex())

evaluated_message, server_public_key = CreateRegistrationResponse(blinded_message, server_public_key,
                                                                  bytes.fromhex(credential_identifier),
                                                                  bytes.fromhex(oprf_seed))

client_public_key, masking_key, envelope, export_key = FinalizeRegistrationRequest(bytes.fromhex(password), blind, evaluated_message, server_public_key, server_identity=bytes.fromhex(server_identity), client_identity=bytes.fromhex(client_identity))
print('client_public_key: ' + client_public_key.hex())
print('export_key: ' + export_key.hex())
print('envelop: ' + envelope.hex())
