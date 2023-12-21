from oprf_ristretto25519_sha512_part2 import BlindEvaluate, Finalize, DeriveKeyPair, expand_message_xmd, identity,\
    contextString
from pysodium import crypto_core_ristretto255_from_hash, crypto_scalarmult_ristretto255
import unittest
import hashlib

def Blind(input: bytes) -> tuple[bytes, bytes]:
    #blind = crypto_core_ristretto255_scalar_random()
    DST = b'HashToGroup-' + contextString
    blind = bytes.fromhex(r)
    inputElement = crypto_core_ristretto255_from_hash(expand_message_xmd(input, DST, 64, hashlib.sha512))
    if inputElement == identity.to_bytes(32, 'big'):
        raise ValueError('Invalid Input')
    blindedElement = crypto_scalarmult_ristretto255(blind, inputElement)
    return blind, blindedElement


Seed = 'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3'
KeyInfo = '74657374206b6579'
sksm = '5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e'

Input = '00'
Input = '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a'
r = '64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706'
BlindedElement = 'da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418'
EvaluationElement = 'b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25'
Output = 'f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73'


class TestChacha20Blake2b(unittest.TestCase):
    def test_derive_key_pair(self):
        skS = DeriveKeyPair(bytes.fromhex(Seed), bytes.fromhex(KeyInfo))[0]
        self.assertEqual(skS, bytes.fromhex(sksm))

    def test_blind(self):
        blinded_element = Blind(bytes.fromhex(Input))[1]
        self.assertEqual(blinded_element, bytes.fromhex(BlindedElement))

    def test_evaluated_element(self):
        evaluated_element = BlindEvaluate(bytes.fromhex(sksm), bytes.fromhex(BlindedElement))
        self.assertEqual(evaluated_element, bytes.fromhex(EvaluationElement))

    def test_finalize(self):
        output = Finalize(bytes.fromhex(Input), bytes.fromhex(r), bytes.fromhex(EvaluationElement))
        self.assertEqual(output, bytes.fromhex(Output))


if __name__ == '__main__':
    unittest.main()