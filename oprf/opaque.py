# https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque

from oprf_ristretto25519_sha512 import Blind, DeriveKeyPair, BlindEvaluate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# Global Variables

Nok = 32

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
                               credential_identifier: bytes, oprf_seed: bytes) -> bytes:

    Expand = HKDFExpand(
        algorithm=hashes.SHA512(),
        length=Nok,
        info=credential_identifier + b"OprfKey"
    )
    seed = Expand.derive(oprf_seed)
    oprf_key, _ = DeriveKeyPair(seed, b"OPAQUE-DeriveKeyPair")

    # blinded_element = DeserializeElement(request.blinded_message)
    blinded_element = blinded_message
    # evaluated_element = Evaluate(oprf_key, blinded_element)
    evaluated_element = BlindEvaluate(oprf_key, blinded_element)
    # evaluated_message = SerializeElement(evaluated_element)
    evaluated_message = evaluated_element

    # Create RegistrationResponse response with (evaluated_message, server_public_key)
    return evaluated_message, server_public_key