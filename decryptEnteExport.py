import base64
import nacl.pwhash
import nacl.secret
import sys

## TEST DATA
TEST_PASSWORD = "test_password"
TEST_SALT_B64 = "vd0dcYMGNLKn/gpT6uTFTw=="
TEST_MEM_LIMIT = 64 * 1024 * 1024
TEST_OPS_LIMIT = 2
TEST_ENCRYPTED_B64 = "kBXQ2PuX6y/aje5r22H0AehRPh6sQ0ULoeAO"
TEST_NONCE_B64 = "v7wsI+BFZsRMIjDm3rTxPhmi/CaUdkdJ"

# expected test results
TEST_EXPECTED_PLAINTEXT = "plain_text"
TEST_EXPECTED_DERIVED_KEY_B64 = "vp8d8Nee0BbIML4ab8Cp34uYnyrN77cRwTl920flyT0="


def derive_key(password: str, salt: bytes, ops_limit: int, mem_limit: int) -> bytes:
    """Derive a 32-byte key using Argon2id.

    Uses libsodium's default Argon2id parameters as per Ente Auth's implementation.

    Args:
        password: The password to derive the key from.
        salt: The salt bytes (decoded from base64).
        ops_limit: Operations limit for Argon2id.
        mem_limit: Memory limit in bytes (will be converted to KB for nacl).

    Returns:
        32-byte derived key.
    """
    return nacl.pwhash.argon2id.kdf(
        32,
        password.encode(),
        salt,
        opslimit=ops_limit,
        memlimit=mem_limit // 1024,  # Ente's memLimit is in bytes, but uses KB
    )


def decrypt_data(key: bytes, encrypted_payload: bytes, nonce: bytes) -> bytes:
    """Decrypt data using XChaCha20-Poly1305.

    Args:
        key: The 32-byte derived key.
        encrypted_payload: The encrypted data bytes (decoded from base64).
        nonce: The nonce bytes (decoded from base64).

    Returns:
        Decrypted plaintext bytes.
    """
    aead = nacl.secret.Aead(key)
    return aead.decrypt(encrypted_payload, None, nonce)

# todo - put a __main__ gate here to check for main

# todo check for arg1 --test and call the kdf func with test data for the key
# validate the key matches the expected key
# then call the decryption function for decrypting the test data with the derived test key
# validate the decrypted plaintext matches the expected plain_text
# print the test results and exit

# todo - if arg1 not --test, then here we check for arg1 as a json file
# todo - and then read the json file from arg1 and fill in the JSON data
# below

# read actual values from the JSON file
version = ""  # .version
salt_b64 = ""  # .kdfParams.salt
mem_limit = 0  # .kdfParams.memlimit
ops_limit = 0  # .kdfParams.opslimit
nonce_b64 = ""  # .encryptionNonce
encrypted_b64 = ""  # .encryptedData

# todo  then call the kdf function and the decryption function and print the plain text
