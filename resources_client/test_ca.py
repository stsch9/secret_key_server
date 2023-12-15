import unittest
from ca import CA

user_id_alice = 1
pk_alice = b'\xabk\xddr\x00"\xc1\xc9r!\xb1}\x8b\x1cCj8=\x9cx\xf2[ \xcdy;\xf4%\x9e\xf8\x04c'
sk_alice = b'\xa9FX\x03\x88\xbf\xd4\xf2D^\xff\x8e%\xfb9_\xd8\xf7\x18\xbc\x9ct\x9e\xce\xb5\xcbv9x&\x8bT'

user_id_bob = 2
pk_bob = b'\xf8\xd0X\xfb\x83[\xe0o\xa0\xceF\xbf\xa1\xa5\xc1\xb3\r\xa7\xd5\xf8\x96DB&\x9co}\xdb\x14\x8e\xf2U'
sk_bob = b'o\xad\x87\xa1=\xc3\x12\xd0\x0b\x8eZ\x00\x8dlV\xc4XG\xf8\xff_Wa\x1e\x84\xacY\xf0H\xe9t\xb9'

user_id_eve = 3
pk_eve = b'\xb1rk\x1fX\xa4-\x88\xe4\xd2\xec\xc1\xa3\x13)j\x16&\xf3j\xcd\xe3\x16\xe9\xd2j\x135i1\x13\x7f'
sk_eve = b'$\x8dx\xe5Q\x01\xcf|\x02\x1e7\xe7\x10\xc4\x95\xcb\xcf\xab\xc4O\xd4E\xd3U\x8bu\xe6\xb22\xf8@\xf7'

class TestCA(unittest.TestCase):

    def setUp(self):
        self.ca = CA.create_ca(user_id=user_id_alice, user_pk=pk_alice)

    def test_add_user(self):
        new_cert = self.ca.add_user(signer_id=user_id_alice, user_id=user_id_bob, user_pk=pk_bob)
        new_cert = self.ca.add_user(signer_id=user_id_alice, user_id=user_id_eve, user_pk=pk_eve)
        self.assertEqual(self.ca.payload['version'], 3)
        self.assertEqual(self.ca.payload['users'][2], pk_bob.hex())
        self.assertEqual(self.ca.payload['users'][3], pk_eve.hex())

    def test_remove_user(self):
        new_cert = self.ca.add_user(signer_id=user_id_alice, user_id=user_id_bob, user_pk=pk_bob)
        self.assertEqual(self.ca.payload['users'][2], pk_bob.hex())
        new_cert = self.ca.remove_user(signer_id=user_id_alice, user_id=user_id_bob)
        self.assertEqual(self.ca.payload['version'], 3)
        self.assertIsNone(self.ca.payload['users'].get('2'))

    def test_rekey(self):
        old_pk = self.ca.pk
        token, token_verify_key = self.ca.rekey(signer_id=user_id_alice)
        new_pk = self.ca.pk
        cert = self.ca.verify(self.ca.verify_key, token)
        verify_keys = self.ca.new_verify_key(old_pk, token_verify_key)
        self.assertEqual(cert['version'], 2)
        self.assertEqual(cert['verify_key'], new_pk.hex())
        self.assertEqual(cert['verify_key_version'], 2)
        self.assertEqual(verify_keys['1'], old_pk.hex())
        self.assertEqual(verify_keys['2'], new_pk.hex())

if __name__ == '__main__':
    unittest.main()