from oprf_ristretto25519_sha512 import BlindEvaluate, Finalize, expand_message_xmd, identity, DST
import hashlib
from oblivious import sodium

def Blind(input: bytes) -> tuple[bytes, bytes]:
    # no random blind
    #blind = sodium.rnd()
    blind = bytes.fromhex(r)
    inputElement = sodium.pnt(expand_message_xmd(input, DST, 64, hashlib.sha512))
    if inputElement == identity.to_bytes(32, 'big'):
        raise ValueError('Invalid Input')
    blindedElement = sodium.mul(blind, inputElement)
    return blind, blindedElement


Input = '00'
Input = '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a'
r = '64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706'
skS = 'e617ae6f2d10de61e16cab73023c5a2df74335d13f89470957214664468d2e0b'

print("Test Vectors: ")
print("skSm: " + skS)
print("Input: " + Input)
print("Blind: " + r)


blindedElement = Blind(bytes.fromhex(Input))[1]
print("Blinded Element: " + blindedElement.hex())

evaluatedElement = BlindEvaluate(bytes.fromhex(skS), blindedElement)
print("Evaluated Elemant: " + evaluatedElement.hex())

output = Finalize(bytes.fromhex(Input), bytes.fromhex(r), evaluatedElement)
print("Output: " + output.hex())