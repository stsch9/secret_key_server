# https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-09
import hashlib
from oprf.oprf_ristretto25519_sha512 import DeriveKeyPair, BlindEvaluate, Finalize, I2OSP, contextString, identity, expand_message_xmd
from opaque import encode_vector_len, Extract, Expand, CreateCleartextCredentials, Recover, CreateRegistrationResponse, \
    RECORD, deserialize_record, KE1, deserialize_ke1, KE2, deserialize_ke2, RecoverCredentials, Preamble, DeriveKeys
from cryptography.hazmat.primitives import hashes, hmac
# from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import constant_time
from oblivious import sodium

# Global Variables

Nok = 32
Nn = 32
Nh = 64
Nseed = 32
Npk = 32
Ne = 96
Noe = 32
Nx = 64
context = bytes.fromhex('4f50415155452d504f43')


# 4.1.2. Envelope Creation
def Store(randomized_pwd: bytes, server_public_key: bytes, server_identity=b'', client_identity=b'') -> \
        tuple[bytes, bytes, bytes, bytes]:
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


#  5.2. Registration Functions
def CreateRegistrationRequest(password: bytes) -> tuple[bytes, bytes]:
    blind, blinded_element = Blind(password, bytes.fromhex(blind_registration))
    #blinded_message = SerializeElement(blinded_element)
    blinded_message = blinded_element
    #Create RegistrationRequest request with blinded_message
    #return (request, blind)
    return blinded_message, blind


def FinalizeRegistrationRequest(password: bytes, blind: bytes, evaluated_message: bytes, server_public_key: bytes,
                                server_identity=b'', client_identity=b'') -> tuple[bytes, bytes]:
    evaluated_element = evaluated_message
    oprf_output = Finalize(password, blind, evaluated_element)
    print("oprf_output: " + oprf_output.hex())
    stretched_oprf_output = oprf_output
    randomized_pwd = Extract(b'', oprf_output + stretched_oprf_output)
    print('randomized_pwd: ' + randomized_pwd.hex())

    envelope, client_public_key, masking_key, export_key = \
        Store(randomized_pwd, server_public_key, server_identity, client_identity)
    return client_public_key + masking_key + envelope, export_key


#  6. Online Authenticated Key Exchange
#  6.2.1. ClientInit
class OPAQUE3DH(object):
    def __init__(self):
        self.state = {}

    def ClientInit(self, password: bytes) -> bytes:
        credential_request, blind = CreateCredentialRequest(password)
        self.state['password'] = password
        self.state['blind'] = blind
        ke1 = self.AuthClientStart(credential_request)
        # ke1 = blinded_message, client_nonce, client_keyshare
        return ke1

    # record = client_public_key, masking_key, enevlope
    def ServerInit(self, server_private_key: bytes, server_public_key: bytes, record: bytes, credential_identifier: bytes,
                   oprf_seed: bytes, ke1: bytes, client_identity=b'', server_identity=b'') -> bytes:
        RECORD = deserialize_record(record)
        if len(server_identity) == 0:
            server_identity = server_public_key
        if len(client_identity) == 0:
            client_identity = RECORD.client_public_key
        KE1 = deserialize_ke1(ke1)
        evaluated_message, masking_nonce, masked_response = CreateCredentialResponse(KE1.blinded_message,
                                                                                     server_public_key,
                                                                                     RECORD.masking_key,
                                                                                     RECORD.envelope,
                                                                                     credential_identifier,
                                                                                     oprf_seed)
        credential_response = evaluated_message + masking_nonce + masked_response
        server_nonce, server_keyshare, server_mac = self.AuthServerRespond(server_identity, server_private_key, client_identity,
                                          RECORD.client_public_key, KE1, credential_response)
        auth_response = server_nonce + server_keyshare + server_mac
        #Create KE2 ke2 with (credential_response, auth_response)
        ke2 = credential_response + auth_response
        return ke2

    def ClientFinish(self, client_identity: bytes, server_identity: bytes, ke2: bytes) -> tuple[bytes, bytes, bytes]:
        KE2 = deserialize_ke2(ke2)
        client_private_key, server_public_key, export_key, client_public_key = RecoverCredentials(self.state['password'],
                                                                                                  self.state['blind'],
                                                                                                  KE2.evaluated_message,
                                                                                                  KE2.masking_nonce,
                                                                                                  KE2.masked_response,
                                                                                                  server_identity,
                                                                                                  client_identity)
        if len(server_identity) == 0:
            server_identity = server_public_key
        if len(client_identity) == 0:
            client_identity = client_public_key
        ke3, session_key = self.AuthClientFinalize(client_identity, client_private_key, server_identity,
                                                   server_public_key, ke2)
        return ke3, session_key, export_key

    def ServerFinish(self, ke3: bytes) -> bytes:
        return self.AuthServerFinalize(ke3)

    #  6.4.3. 3DH Client Functions
    def AuthClientStart(self, credential_request) -> bytes:
        client_nonce = bytes.fromhex('da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc')# random(Nn)
        # (client_secret, client_keyshare) = GenerateAuthKeyPair()
        client_secret, client_keyshare = bytes.fromhex(client_private_keyshare), sodium.bas(bytes.fromhex(client_private_keyshare)) # DeriveKeyPair(random(Nseed), b"OPAQUE-DeriveAuthKeyPair")
        # Create AuthRequest auth_request with (client_nonce, client_keyshare)
        auth_request = client_nonce + client_keyshare
        #Create KE1 ke1 with (credential_request, auth_request)
        ke1 = credential_request + auth_request
        self.state['client_secret'] = client_secret
        self.state['ke1'] = ke1
        # return blinded_message, client_nonce, client_keyshare
        return ke1

    def AuthClientFinalize(self, client_identity: bytes, client_private_key: bytes, server_identity: bytes,
                           server_public_key: bytes, ke2: bytes) -> tuple[bytes, bytes]:
        KE2 = deserialize_ke2(ke2)
        dh1 = sodium.mul(self.state['client_secret'], KE2.server_keyshare)
        dh2 = sodium.mul(self.state['client_secret'], server_public_key)
        dh3 = sodium.mul(client_private_key, KE2.server_keyshare)
        ikm = dh1 + dh2 + dh3

        credential_response = KE2.evaluated_message + KE2.masking_nonce + KE2.masked_response
        preamble = Preamble(client_identity, self.state['ke1'], server_identity, credential_response,
                           KE2.server_nonce, KE2.server_keyshare)
        Km2, Km3, session_key = DeriveKeys(ikm, preamble)

        digest = hashes.Hash(hashes.SHA512())
        digest.update(preamble)
        hash_preamble = digest.finalize()
        h2 = hmac.HMAC(Km2, hashes.SHA512())
        h2.update(hash_preamble)
        expected_server_mac = h2.finalize()
        if not constant_time.bytes_eq(KE2.server_mac, expected_server_mac):
            raise Exception("ServerAuthenticationError: server_mac and expected server_mac differ!")

        digest = hashes.Hash(hashes.SHA512())
        digest.update(preamble + expected_server_mac)
        hash_preamble_server_mac = digest.finalize()
        h3 = hmac.HMAC(Km3, hashes.SHA512())
        h3.update(hash_preamble_server_mac)
        client_mac = h3.finalize()
        ke3 = client_mac
        #Create KE3 ke3 with client_mac
        return ke3, session_key

    # 6.4.4. 3DH Server Functions
    def AuthServerRespond(self, server_identity: bytes, server_private_key: bytes, client_identity: bytes,
                          client_public_key: bytes, ke1: KE1, credential_response: bytes) -> tuple[bytes, bytes, bytes]:
        server_nonce = bytes.fromhex('71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1')
        # (server_private_keyshare, server_keyshare) = GenerateAuthKeyPair()
        server_private_keyshare, server_keyshare = bytes.fromhex('2e842960258a95e28bcfef489cffd19d8ec99cc1375d840f96936da7dbb0b40d'), bytes.fromhex('c8c39f573135474c51660b02425bca633e339cec4e1acc69c94dd48497fe4028')
        preamble = Preamble(client_identity, ke1.serialize(), server_identity, credential_response, server_nonce,
                            server_keyshare)

        dh1 = sodium.mul(server_private_keyshare, ke1.client_keyshare)
        dh2 = sodium.mul(server_private_key, ke1.client_keyshare)
        dh3 = sodium.mul(server_private_keyshare, client_public_key)
        ikm = dh1 + dh2 + dh3

        Km2, Km3, session_key = DeriveKeys(ikm, preamble)
        digest = hashes.Hash(hashes.SHA512())
        digest.update(preamble)
        hash_preamble = digest.finalize()
        h2 = hmac.HMAC(Km2, hashes.SHA512())
        h2.update(hash_preamble)
        server_mac = h2.finalize()

        digest = hashes.Hash(hashes.SHA512())
        digest.update(preamble + server_mac)
        hash_preamble_server_mac = digest.finalize()
        h3 = hmac.HMAC(Km3, hashes.SHA512())
        h3.update(hash_preamble_server_mac)
        expected_client_mac = h3.finalize()

        self.state['expected_client_mac'] = expected_client_mac
        self.state['session_key'] = session_key
        # Create AuthResponse auth_response with (server_nonce, server_keyshare, server_mac)
        return server_nonce, server_keyshare, server_mac

    def AuthServerFinalize(self, ke3: bytes) -> bytes:
        client_mac = ke3
        if not constant_time.bytes_eq(client_mac, self.state['expected_client_mac']):
            raise Exception('ClientAuthenticationError: client_mac and expected client_mac differ!')
        return self.state['session_key']

# 6.3.2.1. CreateCredentialRequest

def CreateCredentialRequest(password: bytes) -> tuple[bytes, bytes]:
    blind, blinded_element = Blind(password, bytes.fromhex(blind_login))
    blinded_message = blinded_element
    #Create CredentialRequest request with blinded_message
    return blinded_message, blind


#  6.3.2.2. CreateCredentialResponse
def CreateCredentialResponse(blinded_message: bytes, server_public_key: bytes, masking_key: bytes, envelope: bytes,
                             credential_identifier: bytes, oprf_seed: bytes) -> tuple[bytes, bytes, bytes]:
    seed = Expand(oprf_seed, credential_identifier + b"OprfKey", Nok)
    oprf_key, _ = DeriveKeyPair(seed, b"OPAQUE-DeriveKeyPair")

    #blinded_element = DeserializeElement
    blinded_element = blinded_message
    evaluated_element = BlindEvaluate(oprf_key, blinded_element)
    #evaluated_message = SerializeElement(evaluated_element)
    evaluated_message = evaluated_element

    masking_nonce = bytes.fromhex('38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d')
    credential_response_pad = Expand(masking_key, masking_nonce + b"CredentialResponsePad", Npk + Ne)
    masked_response = bytes(a ^ b for a, b in zip(credential_response_pad, server_public_key + envelope))
    # Create CredentialResponse response with (evaluated_message, masking_nonce, masked_response)
    return evaluated_message, masking_nonce, masked_response


def Blind(input: bytes, blind: bytes) -> tuple[bytes, bytes]:
    DST = b'HashToGroup-' + contextString
    inputElement = sodium.pnt(expand_message_xmd(input, DST, 64, hashlib.sha512))
    if inputElement == identity.to_bytes(32, 'big'):
        raise ValueError('Invalid Input')
    blindedElement = sodium.mul(blind, inputElement)
    return blind, blindedElement




##########################################


# Input Values

oprf_seed = 'f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef'
credential_identifier = '31323334'
password = '436f7272656374486f72736542617474657279537461706c65'
envelope_nonce = 'ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec'
# masking_nonce = '38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d'
server_private_key = '47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d'
server_public_key = sodium.bas(bytes.fromhex(server_private_key))
# server_nonce = '71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1'
client_nonce = 'da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc'
server_keyshare = 'c8c39f573135474c51660b02425bca633e339cec4e1acc69c94dd48497fe4028'
# client_keyshare = '0c3a00c961fead8a16f818929cc976f0475e4f723519318b96f4947a7a5f9663'
# server_private_keyshare = '2e842960258a95e28bcfef489cffd19d8ec99cc1375d840f96936da7dbb0b40d'
client_private_keyshare = '22c919134c9bdd9dc0c5ef3450f18b54820f43f646a95223bf4a85b2018c2001'
blind_registration = '76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01'
blind_login = '6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308'
server_identity = ''
client_identity = ''


print("Registration:")

print("server_public_key: " + server_public_key.hex())

blinded_message, blind = CreateRegistrationRequest(bytes.fromhex(password))

# derive oprf_key
seed = Expand(bytes.fromhex(oprf_seed), bytes.fromhex(credential_identifier) + b"OprfKey", Nok)
oprf_key, _ = DeriveKeyPair(seed, b"OPAQUE-DeriveKeyPair")
print("oprf_key: " + oprf_key.hex())

evaluated_message, server_public_key = CreateRegistrationResponse(blinded_message, server_public_key,
                                                                  bytes.fromhex(credential_identifier),
                                                                  bytes.fromhex(oprf_seed))

record, export_key = FinalizeRegistrationRequest(bytes.fromhex(password), blind, evaluated_message, server_public_key, server_identity=bytes.fromhex(server_identity), client_identity=bytes.fromhex(client_identity))
RECORD = deserialize_record(record)
print('client_public_key: ' + RECORD.client_public_key.hex())
print('export_key: ' + export_key.hex())
print('envelop: ' + RECORD.envelope.hex())


print("Online Authenticated Key Exchange:")

# 6. Online Authenticated Key Exchange

opache3dh_client = OPAQUE3DH()
ke1 = opache3dh_client.ClientInit(bytes.fromhex(password))
print('ke1: ' + ke1.hex())

opache3dh_server = OPAQUE3DH()
ke2 = opache3dh_server.ServerInit(bytes.fromhex(server_private_key), server_public_key, record,
                                  bytes.fromhex(credential_identifier), bytes.fromhex(oprf_seed), ke1)
print('ke2: ' + ke2.hex())

ke3, session_key, export_key = opache3dh_client.ClientFinish(bytes.fromhex(client_identity), bytes.fromhex(server_identity), ke2)
print('ke3: ' + ke3.hex())
print('session_key: ' + session_key.hex())
print('export_key: ' + export_key.hex())

session_key = opache3dh_server.ServerFinish(ke3)
print('session_key: ' + session_key.hex())
