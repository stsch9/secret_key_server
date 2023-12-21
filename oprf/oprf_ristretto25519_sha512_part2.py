# https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21
# https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16
# https://github.com/algorand/bls_sigs_ref/blob/master/sage-impl/hash_to_field.py

import struct
import sys
import hashlib
from pysodium import crypto_core_ristretto255_scalar_random, crypto_core_ristretto255_from_hash, \
    crypto_scalarmult_ristretto255, crypto_core_ristretto255_scalar_reduce, crypto_scalarmult_ristretto255_base, \
    crypto_core_ristretto255_scalar_invert


if sys.version_info[0] == 3:
    xrange = range
    strxor = lambda str1, str2: bytes( s1 ^ s2 for (s1, s2) in zip(str1, str2) )
    as_bytes = lambda x: bytes(x, "utf-8") if isinstance(x, str) else x
else:
    strxor = lambda str1, str2: ''.join( chr(ord(s1) ^ ord(s2)) for (s1, s2) in zip(str1, str2) )
    as_bytes = lambda x: x


mode = 0x00
identifier = b"ristretto255-SHA512"
# https://datatracker.ietf.org/doc/draft-irtf-cfrg-ristretto255-decaf448/
identity = 0xe2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76


def HashToScalar(input: bytes) -> bytes:
    #DST = b"HashToScalar-" + contextString
    DST = b"DeriveKeyPair" + contextString
    return crypto_core_ristretto255_scalar_reduce(expand_message_xmd(input, DST, 64, hashlib.sha512))


# https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf#section-3.2.1
def DeriveKeyPair(seed: bytes, info: bytes) -> tuple[bytes, bytes]:
    deriveInput = seed + I2OSP(len(info), 2) + info
    counter = 0
    skS = (b'\x00' * 32)
    while skS == (b'\x00' * 32):
        if counter > 255:
            raise Exception("Derive Key Pair Error")
        skS = HashToScalar(deriveInput + I2OSP(counter, 1))
        counter = counter + 1
    pkS = crypto_scalarmult_ristretto255_base(skS)
    return skS, pkS


def CreateContextString(mode: int, identifier: bytes) -> bytes:
    return b'OPRFV1-' + I2OSP(mode, 1) + b'-' + identifier


def expand_message_xmd(msg, DST, len_in_bytes, hash_fn):
    # block and output sizes in bytes
    b_in_bytes = hash_fn().digest_size
    r_in_bytes = hash_fn().block_size

    # ell: number of blocks to hash
    ell = (len_in_bytes + b_in_bytes - 1) // b_in_bytes
    if ell < 1 or ell > 255:
        raise ValueError("expand_message_xmd: ell was %d; need 0 < ell <= 255" % ell)

    # create DST_prime, Z_pad, l_i_b_str
    msg = as_bytes(msg)
    DST = as_bytes(DST)
    DST_prime = DST + I2OSP(len(DST), 1)
    Z_pad = I2OSP(0, r_in_bytes)
    l_i_b_str = I2OSP(len_in_bytes, 2)

    # main loop
    b_0 = hash_fn(Z_pad + msg + l_i_b_str + I2OSP(0, 1) + DST_prime).digest()
    b_vals = [None] * ell
    b_vals[0] = hash_fn(b_0 + I2OSP(1, 1) + DST_prime).digest()
    for idx in range(1, ell):
        b_vals[idx] = hash_fn(strxor(b_0, b_vals[idx - 1]) + I2OSP(idx + 1, 1) + DST_prime).digest()
    pseudo_random_bytes = b''.join(b_vals)
    return pseudo_random_bytes[0 : len_in_bytes]


def I2OSP(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError("bad I2OSP call: val=%d length=%d" % (val, length))
    ret = [0] * length
    val_ = val
    for idx in reversed(xrange(0, length)):
        ret[idx] = val_ & 0xff
        val_ = val_ >> 8
    ret = struct.pack("=" + "B" * length, *ret)
    assert OS2IP(ret, True) == val
    return ret


def OS2IP(octets, skip_assert=False):
    ret = 0
    for octet in struct.unpack("=" + "B" * len(octets), octets):
        ret = ret << 8
        ret += octet
    if not skip_assert:
        assert octets == I2OSP(ret, len(octets))
    return ret


contextString = CreateContextString(mode, identifier)
#DST = b'HashToGroup-' + contextString


def Blind(input: bytes) -> tuple[bytes, bytes]:
    blind = crypto_core_ristretto255_scalar_random()
    DST = b'HashToGroup-' + contextString
    inputElement = crypto_core_ristretto255_from_hash(expand_message_xmd(input, DST, 64, hashlib.sha512))
    if inputElement == identity.to_bytes(32, 'big'):
        raise ValueError('Invalid Input')
    blindedElement = crypto_scalarmult_ristretto255(blind, inputElement)
    return blind, blindedElement


def BlindEvaluate(skS: bytes, blindedElement: bytes) -> bytes:
    evaluatedElement = crypto_scalarmult_ristretto255(skS, blindedElement)
    return evaluatedElement


def Finalize(input: bytes, blind: bytes, evaluatedElement: bytes) -> bytes:
    unblindedElement = crypto_scalarmult_ristretto255(crypto_core_ristretto255_scalar_invert(blind), evaluatedElement)
    hashInput = I2OSP(len(input), 2) + input + I2OSP(len(unblindedElement), 2) + unblindedElement + b'Finalize'
    return hashlib.sha512(hashInput).digest()
