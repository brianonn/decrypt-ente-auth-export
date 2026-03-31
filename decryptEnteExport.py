import base64
import json
import nacl.bindings
import nacl.pwhash
import sys
from pathlib import Path

## TEST DATA
# from: https://github.com/ente-io/ente/blob/main/cli/internal/crypto/crypto_test.go#L10
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


def decrypt_from_json(
    json_file: str, password: str, output_file=None
) -> bytes:
    """Decrypt an Ente Auth export file.

    Args:
        json_file: Path to the JSON export file.
        password: Password for decryption.
        output_file: Optional file-like object to write plaintext to (default: sys.stdout.buffer).

    Returns:
        The decrypted plaintext as bytes.

    Raises:
        FileNotFoundError: If the JSON file doesn't exist.
        json.JSONDecodeError: If the JSON is invalid.
        KeyError: If required fields are missing from the JSON.
        ValueError: If decryption fails.
    """
    if output_file is None:
        output_file = sys.stdout.buffer

    try:
        # Read and parse JSON file
        file_path = Path(json_file)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {json_file}")

        with open(file_path) as f:
            data = json.load(f)

        # Extract and validate version
        version = data.get("version")
        if version != 1:
            raise ValueError(
                f"Unsupported Ente Auth Export format version: {version}. "
                "Only version 1 is supported."
            )

        # Extract required fields
        try:
            salt_b64 = data["kdfParams"]["salt"]
            mem_limit = data["kdfParams"]["memLimit"]
            ops_limit = data["kdfParams"]["opsLimit"]
            nonce_b64 = data["encryptionNonce"]
            encrypted_b64 = data["encryptedData"]
        except KeyError as e:
            raise KeyError(f"Missing required field in JSON: {e}") from e

        # Decode inputs
        salt = base64.b64decode(salt_b64)
        nonce = base64.b64decode(nonce_b64)
        encrypted_payload = base64.b64decode(encrypted_b64)

        # Derive key and decrypt
        key = derive_key(password, salt, ops_limit, mem_limit)
        plaintext = decrypt_data(key, encrypted_payload, nonce)

        # Output to file
        output_file.write(plaintext)

        return plaintext

    except FileNotFoundError as e:
        print(f"❌ File error: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, TypeError) as e:
        print(f"❌ Decryption error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_tests()
    elif len(sys.argv) > 1:
        json_file = sys.argv[1]
        # Prompt for password
        import getpass

        password = getpass.getpass("Enter password: ")
        decrypt_from_json(json_file, password)
    else:
        print("Usage: python decryptEnteExport.py [--test | <json_file>]", file=sys.stderr)
        print("  --test: Run built-in tests", file=sys.stderr)
        print("  <json_file>: Path to Ente Auth export JSON file", file=sys.stderr)
        sys.exit(1)
