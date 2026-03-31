import base64
import json
import pytest
import sys
from pathlib import Path

# Add parent directory to path to import the main module
sys.path.insert(0, str(Path(__file__).parent.parent))

from decryptEnteExport import (
    derive_key,
    decrypt_data,
    TEST_PASSWORD,
    TEST_SALT_B64,
    TEST_MEM_LIMIT,
    TEST_OPS_LIMIT,
    TEST_ENCRYPTED_B64,
    TEST_NONCE_B64,
    TEST_EXPECTED_PLAINTEXT,
    TEST_EXPECTED_DERIVED_KEY_B64,
)


class TestDeriveKey:
    """Tests for the derive_key function."""

    def test_derive_key_with_test_data(self) -> None:
        """Test KDF produces expected derived key with test data."""
        salt = base64.b64decode(TEST_SALT_B64)
        derived_key = derive_key(TEST_PASSWORD, salt, TEST_OPS_LIMIT, TEST_MEM_LIMIT)
        derived_key_b64 = base64.b64encode(derived_key).decode()

        assert derived_key_b64 == TEST_EXPECTED_DERIVED_KEY_B64

    def test_derive_key_returns_32_bytes(self) -> None:
        """Test that derive_key always returns 32 bytes."""
        salt = base64.b64decode(TEST_SALT_B64)
        derived_key = derive_key(TEST_PASSWORD, salt, TEST_OPS_LIMIT, TEST_MEM_LIMIT)

        assert len(derived_key) == 32
        assert isinstance(derived_key, bytes)

    def test_derive_key_different_passwords(self) -> None:
        """Test that different passwords produce different keys."""
        salt = base64.b64decode(TEST_SALT_B64)
        key1 = derive_key(TEST_PASSWORD, salt, TEST_OPS_LIMIT, TEST_MEM_LIMIT)
        key2 = derive_key("different_password", salt, TEST_OPS_LIMIT, TEST_MEM_LIMIT)

        assert key1 != key2


class TestDecryptData:
    """Tests for the decrypt_data function."""

    def test_decrypt_data_with_test_data(self) -> None:
        """Test decryption produces expected plaintext with test data."""
        salt = base64.b64decode(TEST_SALT_B64)
        derived_key = derive_key(TEST_PASSWORD, salt, TEST_OPS_LIMIT, TEST_MEM_LIMIT)

        encrypted_payload = base64.b64decode(TEST_ENCRYPTED_B64)
        nonce = base64.b64decode(TEST_NONCE_B64)
        decrypted = decrypt_data(derived_key, encrypted_payload, nonce)
        decrypted_str = decrypted.decode()

        assert decrypted_str == TEST_EXPECTED_PLAINTEXT

    def test_decrypt_data_returns_bytes(self) -> None:
        """Test that decrypt_data returns bytes."""
        salt = base64.b64decode(TEST_SALT_B64)
        derived_key = derive_key(TEST_PASSWORD, salt, TEST_OPS_LIMIT, TEST_MEM_LIMIT)

        encrypted_payload = base64.b64decode(TEST_ENCRYPTED_B64)
        nonce = base64.b64decode(TEST_NONCE_B64)
        decrypted = decrypt_data(derived_key, encrypted_payload, nonce)

        assert isinstance(decrypted, bytes)

    def test_decrypt_data_wrong_key_fails(self) -> None:
        """Test that decryption with wrong key fails."""
        wrong_key = b"0" * 32
        encrypted_payload = base64.b64decode(TEST_ENCRYPTED_B64)
        nonce = base64.b64decode(TEST_NONCE_B64)

        with pytest.raises(Exception):
            decrypt_data(wrong_key, encrypted_payload, nonce)

    def test_decrypt_data_wrong_nonce_fails(self) -> None:
        """Test that decryption with wrong nonce fails."""
        salt = base64.b64decode(TEST_SALT_B64)
        derived_key = derive_key(TEST_PASSWORD, salt, TEST_OPS_LIMIT, TEST_MEM_LIMIT)

        encrypted_payload = base64.b64decode(TEST_ENCRYPTED_B64)
        wrong_nonce = b"0" * 24

        with pytest.raises(Exception):
            decrypt_data(derived_key, encrypted_payload, wrong_nonce)


class TestIntegration:
    """Integration tests for full KDF + decryption workflow."""

    def test_full_workflow(self) -> None:
        """Test complete KDF and decryption workflow."""
        # Decode inputs
        salt = base64.b64decode(TEST_SALT_B64)
        nonce = base64.b64decode(TEST_NONCE_B64)
        encrypted_payload = base64.b64decode(TEST_ENCRYPTED_B64)

        # Derive key
        derived_key = derive_key(TEST_PASSWORD, salt, TEST_OPS_LIMIT, TEST_MEM_LIMIT)

        # Decrypt
        decrypted = decrypt_data(derived_key, encrypted_payload, nonce)

        # Verify
        assert decrypted.decode() == TEST_EXPECTED_PLAINTEXT


class TestJsonDecryption:
    """Tests for JSON file decryption mode."""

    def test_decrypt_from_valid_json(self, tmp_path: Path) -> None:
        """Test decryption from a valid JSON file."""
        from decryptEnteExport import decrypt_from_json
        import io

        # Create a test JSON file
        json_data = {
            "version": 1,
            "kdfParams": {
                "salt": TEST_SALT_B64,
                "memlimit": TEST_MEM_LIMIT,
                "opslimit": TEST_OPS_LIMIT,
            },
            "encryptionNonce": TEST_NONCE_B64,
            "encryptedData": TEST_ENCRYPTED_B64,
        }

        json_file = tmp_path / "test_export.json"
        json_file.write_text(json.dumps(json_data))

        # Call decrypt_from_json with a BytesIO output
        captured_output = io.BytesIO()
        result = decrypt_from_json(str(json_file), TEST_PASSWORD, captured_output)

        assert result == TEST_EXPECTED_PLAINTEXT.encode()
        assert captured_output.getvalue() == TEST_EXPECTED_PLAINTEXT.encode()

    def test_decrypt_from_missing_file(self, tmp_path: Path) -> None:
        """Test that missing JSON file raises error."""
        from decryptEnteExport import decrypt_from_json

        json_file = tmp_path / "nonexistent.json"

        with pytest.raises(SystemExit) as exc_info:
            decrypt_from_json(str(json_file), TEST_PASSWORD)
        assert exc_info.value.code == 1

    def test_decrypt_from_invalid_json(self, tmp_path: Path) -> None:
        """Test that invalid JSON raises error."""
        from decryptEnteExport import decrypt_from_json

        json_file = tmp_path / "invalid.json"
        json_file.write_text("{ invalid json }")

        with pytest.raises(SystemExit) as exc_info:
            decrypt_from_json(str(json_file), TEST_PASSWORD)
        assert exc_info.value.code == 1

    def test_decrypt_from_missing_fields(self, tmp_path: Path) -> None:
        """Test that JSON missing required fields raises error."""
        from decryptEnteExport import decrypt_from_json
        import json

        json_data = {"version": 1}  # Missing required fields

        json_file = tmp_path / "incomplete.json"
        json_file.write_text(json.dumps(json_data))

        with pytest.raises(SystemExit) as exc_info:
            decrypt_from_json(str(json_file), TEST_PASSWORD)
        assert exc_info.value.code == 1

    def test_decrypt_from_wrong_password(self, tmp_path: Path) -> None:
        """Test that wrong password causes decryption to fail."""
        from decryptEnteExport import decrypt_from_json
        import json

        json_data = {
            "version": 1,
            "kdfParams": {
                "salt": TEST_SALT_B64,
                "memlimit": TEST_MEM_LIMIT,
                "opslimit": TEST_OPS_LIMIT,
            },
            "encryptionNonce": TEST_NONCE_B64,
            "encryptedData": TEST_ENCRYPTED_B64,
        }

        json_file = tmp_path / "test_export.json"
        json_file.write_text(json.dumps(json_data))

        with pytest.raises(SystemExit) as exc_info:
            decrypt_from_json(str(json_file), "wrong_password")
        assert exc_info.value.code == 1
