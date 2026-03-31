import base64
import nacl.pwhash
import nacl.secret
import sys

## TEST DATA
TEST_PASSWORD="test_password"
TEST_SALT_B64="vd0dcYMGNLKn/gpT6uTFTw=="
TEST_MEM_LIMIT="$(( 64 * 1024 * 1024 ))"
TEST_OPS_LIMIT="2"
TEST_ENCRYPTED_B64="kBXQ2PuX6y/aje5r22H0AehRPh6sQ0ULoeAO"
TEST_NONCE_B64="v7wsI+BFZsRMIjDm3rTxPhmi/CaUdkdJ"

# expected test results
TEST_EXPECTED_PLAINTEXT="plain_text"
TEST_EXPECTED_DERIVED_KEY_B64="vp8d8Nee0BbIML4ab8Cp34uYnyrN77cRwTl920flyT0="

# todo - put a def func here with args: salt_b64, nonce_b64, encrypted_b64,password, opslimit, memlimit

# turn the code into two functions (1) kdf function, (2) decrypt function

try:
    # Decode inputs
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    encrypted_payload = base64.b64decode(encrypted_b64)

    # Deriving the 32-byte key using Argon2id
    # Note: Ente uses libsodium's default Argon2id parameters
    key = nacl.pwhash.argon2id.kdf(
        32,
        password.encode(),
        salt,
        opslimit=ops_limit,
        memlimit=mem_limit / 1024 # Ente's memLimit is in bytes, but uses KB
    )


    # Decrypting data
    # Ente Auth uses XChaCha20-Poly1305 (Aead in PyNaCl)
    aead = nacl.secret.Aead(key)
    decrypted = aead.decrypt(encrypted_payload, None, nonce)

    # Output to stdout
    sys.stdout.buffer.write(decrypted)
except Exception as e:
    print(f"Decryption failed: {e}", file=sys.stderr)
    sys.exit(1)

# todo - put a __main__ gate here to check for main

# todo check for arg1 --test and call the kdf func with test data for the key
# validate the keu matches the expected key
# then call the decryption function for decrypting the test data with the derived test key
# validate the decrypted plaintext matches the expected plain_text
# print the test results and exit

# todo - if arg1 not --test, then here we check for arg1 as a json file
# todo - and then read the json file from arg1 and fill in the JSON data
# below

# read actual values from the JSON file
version=""          # .version
salt_b64=""         # .kdfParams.salt
mem_limit=0      # .kdfParams.memlimit
ops_limit=0         # .kdfParams.opslimit
nonce_b64=""        # .encryptionNonce
encrypted_b64=""    # .encryptedData


# todo  then call the kdf function and the decryption function and print the plain text
