import base64
import nacl.bindings
import nacl.pwhash
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
        mem_limit: Memory limit in bytes.

    Returns:
        32-byte derived key.
    """
    return nacl.pwhash.argon2id.kdf(
        32,
        password.encode(),
        salt,
        opslimit=ops_limit,
        memlimit=mem_limit,
    )


def decrypt_data(key: bytes, encrypted_payload: bytes, nonce: bytes) -> bytes:
    """Decrypt data using XChaCha20-Poly1305 secretstream.

    Args:
        key: The 32-byte derived key.
        encrypted_payload: The encrypted data bytes (decoded from base64).
        nonce: The secretstream header bytes (decoded from base64).

    Returns:
        Decrypted plaintext bytes.
    """
    state = nacl.bindings.crypto_secretstream_xchacha20poly1305_state()
    nacl.bindings.crypto_secretstream_xchacha20poly1305_init_pull(state, nonce, key)
    plaintext, _tag = nacl.bindings.crypto_secretstream_xchacha20poly1305_pull(
        state, encrypted_payload
    )
    return plaintext

def run_tests() -> None:
    """Run built-in tests for KDF and decryption functions."""
    try:
        # Test 1: Derive key
        salt = base64.b64decode(TEST_SALT_B64)
        derived_key = derive_key(TEST_PASSWORD, salt, TEST_OPS_LIMIT, TEST_MEM_LIMIT)
        derived_key_b64 = base64.b64encode(derived_key).decode()

        if derived_key_b64 != TEST_EXPECTED_DERIVED_KEY_B64:
            print(
                f"❌ KDF test failed: derived key mismatch\n"
                f"   Expected: {TEST_EXPECTED_DERIVED_KEY_B64}\n"
                f"   Got:      {derived_key_b64}",
                file=sys.stderr,
            )
            sys.exit(1)
        print("✓ KDF test passed")

        # Test 2: Decrypt data
        encrypted_payload = base64.b64decode(TEST_ENCRYPTED_B64)
        nonce = base64.b64decode(TEST_NONCE_B64)
        decrypted = decrypt_data(derived_key, encrypted_payload, nonce)
        decrypted_str = decrypted.decode()

        if decrypted_str != TEST_EXPECTED_PLAINTEXT:
            print(
                f"❌ Decryption test failed: plaintext mismatch\n"
                f"   Expected: {TEST_EXPECTED_PLAINTEXT}\n"
                f"   Got:      {decrypted_str}",
                file=sys.stderr,
            )
            sys.exit(1)
        print("✓ Decryption test passed")
        print("\n✓ All tests passed!")

    except Exception as e:
        print(f"❌ Test failed with error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_tests()
    else:
        # todo - if arg1 not --test, then here we check for arg1 as a json file
        # todo - and then read the json file from arg1 and fill in the JSON data

        # read actual values from the JSON file
        version = ""  # .version
        salt_b64 = ""  # .kdfParams.salt
        mem_limit = 0  # .kdfParams.memlimit
        ops_limit = 0  # .kdfParams.opslimit
        nonce_b64 = ""  # .encryptionNonce
        encrypted_b64 = ""  # .encryptedData

        # todo  then call the kdf function and the decryption function and print the plain text
