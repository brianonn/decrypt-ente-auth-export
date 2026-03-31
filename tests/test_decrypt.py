import base64
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
