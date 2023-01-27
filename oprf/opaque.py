# https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque

from oprf_ristretto25519_sha512 import Blind, DeriveKeyPair, BlindEvaluate, Finalize
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from nacl.utils import random

# Global Variables

Nok = 32
Nn = 32
Nh = 64
Nseed = 32


def encode_vector_len(data: bytes, L: int) -> bytes:
    return len(data).to_bytes(L, 'big') + data


def encode_vector(data: bytes) -> bytes:
    return encode_vector_len(data, 2)

# 2.2 Key Derivation Function and Message Authentication Code

# https://www.rfc-editor.org/rfc/rfc5869
def Extract(salt: bytes, ikm: bytes) -> bytes:
    h = hmac.HMAC(salt, hashes.SHA512())
    h.update(ikm)
    signature = h.finalize()
    return signature

def Expand(key_material: bytes, info: bytes, length: int) -> bytes:
    hkdf = HKDFExpand(
        algorithm=hashes.SHA512(),
        length=length,
        info=info,
    )
    return hkdf.derive(key_material)

# 4 Client Credential Storage and Key Recovery

def CreateCleartextCredentials(server_public_key: bytes, client_public_key: bytes,
                               server_identity=b'', client_identity=b'') -> bytes:
  # Set identities as public keys if no application-layer identity is provided
    if len(server_identity) == 0:
        server_identity = server_public_key
    if len(client_identity) == 0:
        client_identity = client_public_key

  #Create CleartextCredentials cleartext_credentials with
  #  (server_public_key, server_identity, client_identity)
    #return server_public_key + server_identity + client_identity

    return server_public_key + encode_vector(server_identity) + encode_vector(client_identity)

# 4.1.2. Envelope Creation

def Store(randomized_pwd: bytes, server_public_key: bytes, server_identity=b'', client_identity=b'') -> tuple[bytes, bytes, bytes, bytes,]:
    envelope_nonce = random(Nn)
    masking_key = Expand(randomized_pwd, b"MaskingKey", Nh)
    auth_key = Expand(randomized_pwd, envelope_nonce + b"AuthKey", Nh)
    export_key = Expand(randomized_pwd, envelope_nonce + b"ExportKey", Nh)
    seed = Expand(randomized_pwd, envelope_nonce + b"PrivateKey", Nseed)
    _, client_public_key = DeriveKeyPair(seed, b"OPAQUE-DeriveAuthKeyPair")

    cleartext_creds = CreateCleartextCredentials(server_public_key, client_public_key,
                               server_identity, client_identity)
    h = hmac.HMAC(auth_key, hashes.SHA512())
    h.update(envelope_nonce + cleartext_creds)
    auth_tag = h.finalize()

    #Create Envelope envelope with (envelope_nonce, auth_tag)
    envelope = envelope_nonce + auth_tag
    return envelope, client_public_key, masking_key, export_key

#  5.2. Registration Functions

def CreateRegistrationRequest(password: bytes) -> tuple[bytes, bytes]:
    blind, blinded_element = Blind(password)
    #blinded_message = SerializeElement(blinded_element)
    blinded_message = blinded_element
    #Create RegistrationRequest request with blinded_message
    #return (request, blind)
    return blinded_message, blind

#def CreateRegistrationResponse(request, server_public_key: bytes,
#                               credential_identifier, oprf_seed):
def CreateRegistrationResponse(blinded_message: bytes, server_public_key: bytes,
                               credential_identifier: bytes, oprf_seed: bytes) -> tuple[bytes, bytes]:
    seed = Expand(oprf_seed, credential_identifier + b"OprfKey", Nok)
    oprf_key, _ = DeriveKeyPair(seed, b"OPAQUE-DeriveKeyPair")

    # blinded_element = DeserializeElement(request.blinded_message)
    blinded_element = blinded_message
    # evaluated_element = Evaluate(oprf_key, blinded_element)
    evaluated_element = BlindEvaluate(oprf_key, blinded_element)
    # evaluated_message = SerializeElement(evaluated_element)
    evaluated_message = evaluated_element

    # Create RegistrationResponse response with (evaluated_message, server_public_key)
    return evaluated_message, server_public_key


#def FinalizeRegistrationRequest(password, blind, response, server_identity, client_identity):
def FinalizeRegistrationRequest(password: bytes, blind: bytes, evaluated_message: bytes, server_public_key: bytes,
                                server_identity=b'', client_identity=b'') -> tuple[bytes, bytes, bytes, bytes]:
    # evaluated_element = DeserializeElement(response.evaluated_message)
    evaluated_element = evaluated_message
    oprf_output = Finalize(password, blind, evaluated_element)
    print("oprf_output: " + oprf_output.hex())

    # stretched_oprf_output = Stretch(oprf_output, params)
    stretched_oprf_output = oprf_output
    randomized_pwd = Extract(b'', oprf_output + stretched_oprf_output)

    envelope, client_public_key, masking_key, export_key = \
        Store(randomized_pwd, server_public_key, server_identity, client_identity)
    #Create RegistrationRecord record with (client_public_key, masking_key, envelope)
    return client_public_key, masking_key, envelope, export_key
