from resources_client.crypto import MasterKeyMeta, MasterKeyUser
from nacl.bindings import crypto_sign_seed_keypair, crypto_scalarmult_base

node_id = 2
user_id = 1
user_permissions = {user_id: 7}

print("initialize Master Key Meta")
master_key_meta, token_user, token_secret_keys, token_recipient_keys = MasterKeyMeta.initialize(node_id, user_permissions)

print("##################")
print("# verify token_user:")
pk = crypto_sign_seed_keypair(master_key_meta.token_key_user)[0]
decode_token_user = MasterKeyUser.verify_token(pk, token_user)
print(" - payload: ")
print(decode_token_user.payload)
print(" - footer:")
print(decode_token_user.footer)

print("##################")
print("# decrypt token_secret_keys:")
print(" - payload:")
print(master_key_meta.master_key_secret.decrypt_token(token_secret_keys).payload)
print(" - footer:")
print(master_key_meta.master_key_secret.decrypt_token(token_secret_keys).footer)

print("##################")
print("# decrypt token_recipient_keys:")
print(" - payload:")
print(master_key_meta.master_key_recipient.decrypt_token(token_recipient_keys).payload)
print(" - footer:")
print(master_key_meta.master_key_recipient.decrypt_token(token_recipient_keys).footer)

print("##################")
print("# test intermediate keys:")
key_id = master_key_meta.master_key_recipient.decrypt_token(token_recipient_keys).footer['key_id']
int_pk = master_key_meta.master_key_recipient.decrypt_token(token_recipient_keys).payload[key_id]
int_sk = master_key_meta.master_key_secret.decrypt_token(token_secret_keys).payload[key_id]

assert crypto_scalarmult_base(bytes.fromhex(int_sk)).hex() == int_pk

print("##################")
print("# add user: ")
token_user = master_key_meta.add_user(token_user, 3, 1)
decode_token_user = MasterKeyUser.verify_token(pk, token_user)
print(" - payload:")
print(decode_token_user.payload)
print(" - footer:")
print(decode_token_user.footer)

print("##################")
print("# change user: ")
user_permissions = {2: 7, 3: 2}
master_key_meta, token_user, token_secret_keys, token_recipient_keys = \
    master_key_meta.change_user(token_user, token_secret_keys, token_recipient_keys, user_permissions)

print("##################")
print("# verify token_user:")
pk = crypto_sign_seed_keypair(master_key_meta.token_key_user)[0]
decode_token_user = MasterKeyUser.verify_token(pk, token_user)
print(" - payload: ")
print(decode_token_user.payload)
print(" - footer:")
print(decode_token_user.footer)

print("##################")
print("# decrypt token_secret_keys:")
print(" - payload:")
print(master_key_meta.master_key_secret.decrypt_token(token_secret_keys).payload)
print(" - footer:")
print(master_key_meta.master_key_secret.decrypt_token(token_secret_keys).footer)

print("##################")
print("# decrypt token_recipient_keys:")
print(" - payload:")
print(master_key_meta.master_key_recipient.decrypt_token(token_recipient_keys).payload)
print(" - footer:")
print(master_key_meta.master_key_recipient.decrypt_token(token_recipient_keys).footer)

print("##################")
print("# test intermediate keys:")
key_id = master_key_meta.master_key_recipient.decrypt_token(token_recipient_keys).footer['key_id']
int_pk = master_key_meta.master_key_recipient.decrypt_token(token_recipient_keys).payload[key_id]
int_sk = master_key_meta.master_key_secret.decrypt_token(token_secret_keys).payload[key_id]

assert crypto_scalarmult_base(bytes.fromhex(int_sk)).hex() == int_pk

print("##################")
print("# add user: ")
token_user = master_key_meta.add_user(token_user, 3, 1)
decode_token_user = MasterKeyUser.verify_token(pk, token_user)
print(" - payload:")
print(decode_token_user.payload)
print(" - footer:")
print(decode_token_user.footer)
