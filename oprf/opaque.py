# https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque

from .oprf_ristretto25519_sha512 import Blind, DeriveKeyPair, BlindEvaluate, Finalize, I2OSP
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import constant_time
from nacl.utils import random
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
    if len(server_identity) == 0:
        server_identity = server_public_key
    if len(client_identity) == 0:
        client_identity = client_public_key
  #Create CleartextCredentials cleartext_credentials with
  #  (server_public_key, server_identity, client_identity)
    return server_public_key + encode_vector(server_identity) + encode_vector(client_identity)

# 4.1.2. Envelope Creation


def Store(randomized_pwd: bytes, server_public_key: bytes, server_identity=b'', client_identity=b'') -> \
        tuple[bytes, bytes, bytes, bytes]:
    envelope_nonce = random(Nn)
    masking_key = Expand(randomized_pwd, b"MaskingKey", Nh)
    auth_key = Expand(randomized_pwd, envelope_nonce + b"AuthKey", Nh)
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


# 4.1.3. Envelope Recovery
def Recover(randomized_pwd: bytes, server_public_key: bytes, envelope: bytes, server_identity: bytes,
            client_identity: bytes) -> tuple[bytes, bytes, bytes]:
    envelope_nonce = envelope[0:Nn]
    envelope_auth_tag = envelope[Nn:]
    auth_key = Expand(randomized_pwd, envelope_nonce + b"AuthKey", Nh)
    export_key = Expand(randomized_pwd, envelope_nonce + b"ExportKey", Nh)
    seed = Expand(randomized_pwd, envelope_nonce + b"PrivateKey", Nseed)
    client_private_key, client_public_key = DeriveKeyPair(seed, b"OPAQUE-DeriveAuthKeyPair")

    if len(server_identity) == 0:
        server_identity = server_public_key
    if len(client_identity) == 0:
        client_identity = client_public_key
    cleartext_creds = CreateCleartextCredentials(server_public_key, client_public_key, server_identity, client_identity)
    h = hmac.HMAC(auth_key, hashes.SHA512())
    h.update(envelope_nonce + cleartext_creds)
    try:
        h.verify(envelope_auth_tag)
    except InvalidSignature:
        raise Exception("InvalidSignature")
    #If !ct_equal(envelope.auth_tag, expected_tag)
    return client_private_key, export_key, client_public_key


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
                                server_identity=b'', client_identity=b'') -> tuple[bytes, bytes]:
    # evaluated_element = DeserializeElement(response.evaluated_message)
    evaluated_element = evaluated_message
    oprf_output = Finalize(password, blind, evaluated_element)

    # stretched_oprf_output = Stretch(oprf_output, params)
    stretched_oprf_output = oprf_output
    randomized_pwd = Extract(b'', oprf_output + stretched_oprf_output)

    envelope, client_public_key, masking_key, export_key = \
        Store(randomized_pwd, server_public_key, server_identity, client_identity)
    #Create RegistrationRecord record with (client_public_key, masking_key, envelope)
    return client_public_key + masking_key + envelope, export_key


class RECORD(object):
    def __init__(self, client_public_key, masking_key, envelope):
        self.client_public_key = client_public_key
        self.masking_key = masking_key
        self.envelope = envelope

    def serialize(self) -> bytes:
        return self.client_public_key + self.masking_key + self.envelope


def deserialize_record(record: bytes) -> RECORD:
    return RECORD(record[0:Npk], record[Npk:Npk + Nh], record[Npk + Nh:])


#struct {
#  CredentialRequest credential_request; (blinded_message)
#  AuthRequest auth_request; (client_nonce, client_keyshare)
#} KE1;
class KE1(object):
    def __init__(self, blinded_message, client_nonce, client_keyshare):
        self.blinded_message = blinded_message
        self.client_nonce = client_nonce
        self.client_keyshare = client_keyshare

    def serialize(self) -> bytes:
        return self.blinded_message + self.client_nonce + self.client_keyshare

def deserialize_ke1(ke1: bytes) -> KE1:
    return KE1(ke1[0:Noe], ke1[Noe:Noe + Nn], ke1[Noe + Nn:])


#struct {
#  CredentialResponse credential_response; (evaluated_message, masking_nonce, masked_response)
#  AuthResponse auth_response; (server_nonce, server_keyshare, server_mac)
#} KE2
class KE2(object):
    def __init__(self, evaluated_message, masking_nonce, masked_response, server_nonce, server_keyshare, server_mac):
        self.evaluated_message = evaluated_message
        self.masking_nonce = masking_nonce
        self.masked_response = masked_response
        self.server_nonce = server_nonce
        self.server_keyshare = server_keyshare
        self.server_mac = server_mac

    def serialize(self) -> bytes:
        return self.evaluated_message + self.masked_response + self.masked_response + self.server_nonce + \
               self.server_keyshare + self.server_mac


def deserialize_ke2(ke2: bytes) -> KE2:
    return KE2(ke2[0:Noe], ke2[Noe:Noe + Nn], ke2[Noe + Nn:Noe + Nn + Npk + Ne],
               ke2[Noe + Nn + Npk + Ne:Noe + Nn + Npk + Ne + Nn],
               ke2[Noe + Nn + Npk + Ne + Nn:Noe + Nn + Npk + Ne + Nn + Npk], ke2[Noe + Nn + Npk + Ne + Nn + Npk:])


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

    def ClientFinish(self, client_identity: bytes, server_identity:bytes, ke2: bytes) -> tuple[bytes, bytes, bytes]:
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
        client_nonce = random(Nn)
        # (client_secret, client_keyshare) = GenerateAuthKeyPair()
        client_secret, client_keyshare = DeriveKeyPair(random(Nseed), b"OPAQUE-DeriveAuthKeyPair")
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
        server_nonce = random(Nn)
        # (server_private_keyshare, server_keyshare) = GenerateAuthKeyPair()
        server_private_keyshare, server_keyshare = DeriveKeyPair(random(Nseed), b"OPAQUE-DeriveAuthKeyPair")
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
    blind, blinded_element = Blind(password)
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

    masking_nonce = random(Nn)
    credential_response_pad = Expand(masking_key, masking_nonce + b"CredentialResponsePad", Npk + Ne)
    masked_response = bytes(a ^ b for a, b in zip(credential_response_pad, server_public_key + envelope))
    # Create CredentialResponse response with (evaluated_message, masking_nonce, masked_response)
    return evaluated_message, masking_nonce, masked_response


#  6.3.2.3. RecoverCredentials
def RecoverCredentials(password: bytes, blind: bytes, evaluated_message: bytes, masking_nonce: bytes,
                       masked_response: bytes, server_identity, client_identity) -> tuple[bytes, bytes, bytes, bytes]:
    evaluated_element = evaluated_message

    oprf_output = Finalize(password, blind, evaluated_element)
    # stretched_oprf_output = Stretch(oprf_output, params)
    stretched_oprf_output = oprf_output
    randomized_pwd = Extract(b"", oprf_output + stretched_oprf_output)

    masking_key = Expand(randomized_pwd, b"MaskingKey", Nh)
    credential_response_pad = Expand(masking_key, masking_nonce + b"CredentialResponsePad", Npk + Ne)
    server_public_key_envelope = bytes(a ^ b for a, b in zip(credential_response_pad, masked_response))
    server_public_key = server_public_key_envelope[0:Npk]
    envelope = server_public_key_envelope[Npk:]
    client_private_key, export_key, client_public_key = Recover(randomized_pwd, server_public_key, envelope,
                                                                server_identity, client_identity)
    return client_private_key, server_public_key, export_key, client_public_key


# 6.4.2.1. Transcript Functions
def Preamble(client_identity: bytes, ke1: bytes, server_identity: bytes, credential_response: bytes,
             server_nonce: bytes, server_keyshare: bytes) -> bytes:
    preamble = b"RFCXXXX" + I2OSP(len(context), 2) + context + I2OSP(len(client_identity), 2) + client_identity + ke1 + \
               I2OSP(len(server_identity), 2) + server_identity + credential_response + server_nonce + server_keyshare
    return preamble


def derive_secret(secret: bytes, label: bytes, transcript_hash: bytes) -> bytes:
    def build_label(length: int, label: bytes, context_build_label: bytes):
        return I2OSP(length, 2) + encode_vector_len(b"OPAQUE-" + label, 1) + encode_vector_len(context_build_label, 1)
    hkdf_label = build_label(Nx, label, transcript_hash)
    return Expand(secret, hkdf_label, Nx)


# 6.4.2.2. Shared Secret Derivation
def DeriveKeys(ikm: bytes, preamble: bytes) -> tuple[bytes, bytes, bytes]:
    prk = Extract(b"", ikm)
    digest = hashes.Hash(hashes.SHA512())
    digest.update(preamble)
    hash_preamble = digest.finalize()
    handshake_secret = derive_secret(prk, b"HandshakeSecret", hash_preamble)
    session_key = derive_secret(prk, b"SessionKey", hash_preamble)
    Km2 = derive_secret(handshake_secret, b"ServerMAC", b"")
    Km3 = derive_secret(handshake_secret, b"ClientMAC", b"")
    return Km2, Km3, session_key
