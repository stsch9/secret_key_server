import unittest
from ca import CA
from dataroom import encrypt_keys_token, decrypt_keys_token, AdminUser, verify_perm_token, sign_perm_token, AdminRoomToken, UserPermToken, RoomKeysToken
from pysodium import crypto_kx_keypair, crypto_sign_keypair, crypto_sign_seed_keypair, crypto_scalarmult_base

node_id = "a11c78ed5f0a172005f1deeaa0e36d7b3c9497bb6c02a82de3f4714fee83104c"

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
        # create ca
        self.ca = CA.create_ca(user_id=user_id_alice, user_pk=pk_alice)
        new_cert = self.ca.add_user(signer_id=user_id_alice, user_id=user_id_bob, user_pk=pk_bob)
        self.cert_file = self.ca.add_user(signer_id=user_id_alice, user_id=user_id_eve, user_pk=pk_eve)
        self.assertEqual(self.ca.payload['version'], 3)
        self.assertEqual(self.ca.payload['users']['2'], pk_bob.hex())
        self.assertEqual(self.ca.payload['users']['3'], pk_eve.hex())

        # create dataroom
        self.admin_user, self.signed_token = AdminUser.initialize_dataroom(user_id_alice, node_id)
        self.assertEqual(1, self.admin_user._admin_room_token.version)
        self.assertEqual(1, self.admin_user._user_perm_token.version)
        sk = bytes.fromhex(self.admin_user._admin_room_token.secret_signing_key)
        pk, sk_ = crypto_sign_seed_keypair(sk)
        perm_token = verify_perm_token(node_id=bytes.fromhex(node_id), public_key=pk, token=self.signed_token)
        self.assertEqual(3, perm_token['perm']['1'])

    def test_ca_remove_user(self):
        new_cert = self.ca.remove_user(signer_id=user_id_alice, user_id=user_id_bob)
        self.assertEqual(self.ca.payload['version'], 4)
        self.assertIsNone(self.ca.payload['users'].get('2'))

    def test_ca_rekey(self):
        old_pk = self.ca.pk
        token, token_verify_key = self.ca.rekey(signer_id=user_id_alice)
        new_pk = self.ca.pk
        cert = self.ca.verify(self.ca.verify_key, token)
        verify_keys = self.ca.new_verify_key(old_pk, token_verify_key)
        self.assertEqual(cert['version'], 4)
        self.assertEqual(cert['verify_key'], new_pk.hex())
        self.assertEqual(cert['verify_key_version'], 2)
        self.assertEqual(verify_keys['1'], old_pk.hex())
        self.assertEqual(verify_keys['2'], new_pk.hex())

    # test crypto2
    def test_en_de_crypt_token(self):
        token = {"test": "bla"}
        pks, sks = crypto_kx_keypair()
        pkr, skr = crypto_kx_keypair()
        enc, enc_token = encrypt_keys_token(b"1", sks, pkr, token)
        self.assertEqual(token, decrypt_keys_token(b"1", enc, skr, pks, enc_token))

    def test_sign(self):
        pk, sk = crypto_sign_keypair()
        sk = sk[:32]
        token = sign_perm_token(node_id=bytes.fromhex(node_id), private_key=sk, payload={0: 1})
        verify_perm_token(node_id=bytes.fromhex(node_id), public_key=pk, token=token)

    def test_add_remove_dataroom_admin_bob(self):
        # add new dataroom admin user bob
        key_dict, signed_token = self.admin_user.add_user(user_id_bob, 3, sk_alice, self.ca.verify_key, self.cert_file)

        # bob decrypt admin room token and verify user permission token
        admin_room_token_bob = AdminRoomToken.decrypt(bytes.fromhex(node_id), key_dict[2][0], sk_bob, pk_alice, key_dict[2][1])

        # verify permission token
        sk = bytes.fromhex(admin_room_token_bob.secret_signing_key)
        pk, sk_ = crypto_sign_seed_keypair(sk)
        user_perm_token_bob = UserPermToken.verify(node_id=bytes.fromhex(node_id), public_key=pk, token=signed_token)

        # create admin user bob
        admin_user_bob = AdminUser(admin_room_token_bob, user_perm_token_bob)

        self.assertEqual(self.admin_user.admin_room_token.payload, admin_user_bob.admin_room_token.payload)
        self.assertEqual(2, admin_user_bob.user_perm_token.version)
        self.assertEqual(3, admin_user_bob.user_perm_token.perm['2'])

        # remove admin user bob
        old_sdk = self.admin_user.admin_room_token.secret_distribution_key
        old_pdk = crypto_scalarmult_base(bytes.fromhex(old_sdk)).hex()

        user_perm_token, key_dict = self.admin_user.remove_user(2, self.ca.verify_key, self.cert_file)

        # check SDK is changed
        self.assertNotEqual(old_sdk, self.admin_user.admin_room_token.secret_distribution_key)
        # check decryption of admin token
        admin_room_token = AdminRoomToken.decrypt(node_id=bytes.fromhex(node_id), enc=key_dict[str(user_id_alice)][0], skr=sk_alice, pks=bytes.fromhex(old_pdk), token=key_dict[str(user_id_alice)][1])
        self.assertEqual(admin_room_token.payload, self.admin_user.admin_room_token.payload)
        # check signature of user_perm_token
        vk, sk = crypto_sign_seed_keypair(bytes.fromhex(admin_room_token.secret_signing_key))
        user_perm_token = UserPermToken.verify(node_id=bytes.fromhex(node_id), public_key=vk, token=user_perm_token)
        self.assertEqual(user_perm_token.payload, self.admin_user.user_perm_token.payload)
        # check user is removed in perm token
        self.assertNotIn(str(user_id_bob), user_perm_token.perm)
        self.assertIn(str(user_id_alice), user_perm_token.perm)

    def test_add_remove_perm_2(self):
        # add eve with dataroom read/write rights
        key_dict, signed_token = self.admin_user.add_user(user_id_eve, 2, sk_alice, self.ca.verify_key, self.cert_file)
        # eve decrypt secret room token
        room_keys_token_eve = RoomKeysToken.decrypt(bytes.fromhex(node_id), key_dict[user_id_eve][0], sk_eve, pk_alice, key_dict[user_id_eve][1])

        # verify permission token
        user_perm_token_eve = UserPermToken.verify(node_id=bytes.fromhex(node_id), public_key=bytes.fromhex(room_keys_token_eve.verify_key), token=signed_token)

        self.assertEqual(room_keys_token_eve.payload['version'], 1)
        self.assertEqual(user_perm_token_eve.version, 2)
        # check public distribution key
        self.assertEqual(room_keys_token_eve.public_distribution_key, crypto_scalarmult_base(bytes.fromhex(self.admin_user.admin_room_token.secret_distribution_key)).hex())
        # check SRKs
        self.assertEqual(room_keys_token_eve.payload['SRKs'],
                         self.admin_user.admin_room_token.create_secret_keys_token().payload['SRKs'])

        # remove user eve
        old_sdk = self.admin_user.admin_room_token.secret_distribution_key
        old_pdk = crypto_scalarmult_base(bytes.fromhex(old_sdk)).hex()

        user_perm_token, key_dict = self.admin_user.remove_user(3, self.ca.verify_key, self.cert_file)

        # check SDK is not changed
        self.assertEqual(old_sdk, self.admin_user.admin_room_token.secret_distribution_key)
        # check decryption of admin token
        admin_room_token_alice = AdminRoomToken.decrypt(node_id=bytes.fromhex(node_id), enc=key_dict[str(user_id_alice)][0],
                                                  skr=sk_alice, pks=bytes.fromhex(old_pdk),
                                                  token=key_dict[str(user_id_alice)][1])
        self.assertEqual(admin_room_token_alice.payload, self.admin_user.admin_room_token.payload)
        # check signature of user_perm_token
        vk, sk = crypto_sign_seed_keypair(bytes.fromhex(admin_room_token_alice.secret_signing_key))
        user_perm_token = UserPermToken.verify(node_id=bytes.fromhex(node_id), public_key=vk, token=user_perm_token)
        self.assertEqual(user_perm_token.payload, self.admin_user.user_perm_token.payload)
        # check user is removed in perm token
        self.assertNotIn(str(user_id_eve), user_perm_token.perm)
        self.assertIn(str(user_id_alice), user_perm_token.perm)

    def test_add_remove_perm_1(self):
        # add bob with dataroom write rights
        key_dict, signed_token = self.admin_user.add_user(user_id_bob, 1, sk_alice, self.ca.verify_key, self.cert_file)
        # eve decrypt secret room token
        room_keys_token_bob = RoomKeysToken.decrypt(bytes.fromhex(node_id), key_dict[user_id_bob][0], sk_bob, pk_alice,
                                                    key_dict[user_id_bob][1])

        # verify permission token
        user_perm_token_bob = UserPermToken.verify(node_id=bytes.fromhex(node_id),
                                                   public_key=bytes.fromhex(room_keys_token_bob.verify_key),
                                                   token=signed_token)

        self.assertEqual(room_keys_token_bob.payload['version'], 1)
        self.assertEqual(user_perm_token_bob.version, 2)
        # check public distribution key
        self.assertEqual(room_keys_token_bob.public_distribution_key, crypto_scalarmult_base(
            bytes.fromhex(self.admin_user.admin_room_token.secret_distribution_key)).hex())
        # check SRKs
        self.assertNotIn('SRKs', room_keys_token_bob.payload)
        self.assertIn('PRKs', room_keys_token_bob.payload)

        # remove user bob
        old_sdk = self.admin_user.admin_room_token.secret_distribution_key
        old_pdk = crypto_scalarmult_base(bytes.fromhex(old_sdk)).hex()

        user_perm_token, key_dict = self.admin_user.remove_user(2, self.ca.verify_key, self.cert_file)

        # check SDK is not changed
        self.assertEqual(old_sdk, self.admin_user.admin_room_token.secret_distribution_key)
        # check decryption of admin token
        admin_room_token_alice = AdminRoomToken.decrypt(node_id=bytes.fromhex(node_id),
                                                        enc=key_dict[str(user_id_alice)][0],
                                                        skr=sk_alice, pks=bytes.fromhex(old_pdk),
                                                        token=key_dict[str(user_id_alice)][1])
        self.assertEqual(admin_room_token_alice.payload, self.admin_user.admin_room_token.payload)
        # check signature of user_perm_token
        vk, sk = crypto_sign_seed_keypair(bytes.fromhex(admin_room_token_alice.secret_signing_key))
        user_perm_token = UserPermToken.verify(node_id=bytes.fromhex(node_id), public_key=vk, token=user_perm_token)
        self.assertEqual(user_perm_token.payload, self.admin_user.user_perm_token.payload)
        # check user is removed in perm token
        self.assertNotIn(str(user_id_bob), user_perm_token.perm)
        self.assertIn(str(user_id_alice), user_perm_token.perm)

if __name__ == '__main__':
    unittest.main()