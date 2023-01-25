from opaque import CreateRegistrationRequest, CreateRegistrationResponse
from oprf_ristretto25519_sha512 import DeriveKeyPair
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from oblivious import sodium

Nok = 32

password = '436f7272656374486f72736542617474657279537461706c65'
server_private_key = '47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d'
server_public_key = sodium.bas(bytes.fromhex(server_private_key))
oprf_seed = 'f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef'
credential_identifier = '31323334'

print("server_public_key: " + server_public_key.hex())

blinded_message, blind = CreateRegistrationRequest(bytes.fromhex(password))

# derive oprf_key
Expand = HKDFExpand(
        algorithm=hashes.SHA512(),
        length=Nok,
        info=bytes.fromhex(credential_identifier) + b"OprfKey"
)
seed = Expand.derive(bytes.fromhex(oprf_seed))
oprf_key, _ = DeriveKeyPair(seed, b"OPAQUE-DeriveKeyPair")

print("oprf_key: " + oprf_key.hex())

evaluated_message, server_public_key = CreateRegistrationResponse(blinded_message, server_public_key,
                                                                  bytes.fromhex(credential_identifier),
                                                                  bytes.fromhex(oprf_seed))


