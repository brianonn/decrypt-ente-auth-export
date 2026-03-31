# Decrypt Ente Auth Export

A Python utility to decrypt Ente Auth (2FA authenticator) export files using Argon2id key derivation and XChaCha20-Poly1305 encryption.

## What It Does

This program decrypts encrypted authentication data exported from [Ente Auth](https://ente.io/). It:

1. **Derives a 32-byte key** from your password using Argon2id (with parameters specified in the export file)
2. **Decrypts the data** using XChaCha20-Poly1305 secretstream encryption (libsodium format)
3. **Outputs the plaintext** to stdout

## Installation

### Requirements

- Python 3.10+
- `PyNaCl` (for cryptographic operations)

### Setup

```bash
# Using uv (recommended)
uv pip install PyNaCl

# Or with pip
pip install PyNaCl
```

## Usage

### Mode 1: Test Built-in Validation

Validate that the implementation matches official Ente Auth test vectors:

```bash
python decryptEnteExport.py --test
```

Output:
```
✓ KDF test passed
✓ Decryption test passed

✓ All tests passed!
```

### Mode 2: Decrypt an Export File

Decrypt an Ente Auth export JSON file:

```bash
python decryptEnteExport.py <path-to-export.json>
```

You will be prompted for your password:
```
Enter password: 
```

The decrypted plaintext is written to stdout (binary mode).

**Example:**
```bash
python decryptEnteExport.py my-auth-export.json > decrypted.txt
```

### Mode 3: Help

Show usage information:

```bash
python decryptEnteExport.py
```

## JSON Export File Format

The input JSON file must have this structure:

```json
{
  "version": 1,
  "kdfParams": {
    "salt": "base64-encoded-salt",
    "memLimit": 67108864,
    "opsLimit": 2
  },
  "encryptionNonce": "base64-encoded-nonce",
  "encryptedData": "base64-encoded-ciphertext"
}
```

### Field Descriptions

- `version`: **Required.** Protocol version. **Only version 1 is supported.** The program will exit with an error for any other version.
- `kdfParams.salt`: 16-byte salt for Argon2id, base64-encoded
- `kdfParams.memLimit`: Memory limit in bytes for Argon2id (typically 64MB = 67108864)
- `kdfParams.opsLimit`: Operation count for Argon2id (typically 2)
- `encryptionNonce`: XChaCha20-Poly1305 secretstream header (24 bytes), base64-encoded
- `encryptedData`: Encrypted payload (ciphertext + authentication tag), base64-encoded

## Testing

### Run the Full Test Suite

```bash
# Run all 17 tests
pytest tests/test_decrypt.py -v

# Run specific test class
pytest tests/test_decrypt.py::TestDeriveKey -v

# Run a specific test
pytest tests/test_decrypt.py::TestDeriveKey::test_derive_key_with_test_data -v
```

### Test Categories

**KDF Tests (3 tests)**
- Verify key derivation produces correct output
- Verify correct key length (32 bytes)
- Verify different passwords produce different keys

**Decryption Tests (4 tests)**
- Verify decryption produces correct plaintext
- Verify decryption returns bytes
- Verify wrong key causes decryption to fail
- Verify wrong nonce causes decryption to fail

**Integration Tests (1 test)**
- Test full KDF + decryption workflow

**JSON Decryption Tests (8 tests)**
- Verify decryption from valid JSON file
- Verify error handling for missing files
- Verify error handling for invalid JSON
- Verify error handling for missing JSON fields
- Verify error handling for wrong password
- Verify error handling for unsupported version (version 2)
- Verify error handling for missing version field
- Verify error handling for null version

**CLI Tests (1 test)**
- Verify that running without arguments displays helpful usage message

## Development Tasks

This project uses [Task](https://taskfile.dev/) for common development operations. Ensure you have `task` or `go-task` installed, then run:

```bash
# List available tasks
task

# Initialize development environment (create virtual environment)
task init

# Run tests
task test

# Update dependency lock files
task freeze

# Clean build artifacts and caches
task clean
```

### Task Targets

- **init:** Create a Python virtual environment and install base dependencies
- **test:** Run the full test suite with pytest
- **freeze:** Update `requirements.txt` with current dependencies
- **clean:** Remove all build artifacts, Python caches, and virtual environment

## How It Works

### 1. Key Derivation (Argon2id)

```
password + salt + memLimit + opsLimit → 32-byte key
```

Uses libsodium's Argon2id algorithm with:
- 32-byte output
- 1 thread
- Memory and operations limits from export parameters

### 2. Decryption (XChaCha20-Poly1305)

Uses libsodium's secretstream format:
- **Cipher:** XChaCha20-Poly1305 (AEAD)
- **Mode:** Secretstream (handles nonce/counter automatically)
- **Input:** Ciphertext + authentication tag
- **Output:** Plaintext

## Error Handling

The program provides clear error messages:

```
❌ File error: File not found: nonexistent.json
❌ Invalid JSON: Expecting value: line 1 column 1 (char 0)
❌ Missing required field in JSON: 'salt'
❌ Decryption error: <description>
```

All errors exit with code 1.

## Examples

### Example 1: Export and Decrypt in One Command

```bash
python decryptEnteExport.py export.json | base64
```

### Example 2: Save Decrypted Output to File

```bash
python decryptEnteExport.py export.json > decrypted_data.bin
```

### Example 3: Verify Tests Pass

```bash
python decryptEnteExport.py --test && echo "✅ All tests passed"
```

## Security Notes

- **Password input:** Uses `getpass` module to hide password from terminal history and environment
- **Key derivation:** Uses Argon2id with memory-hard protection against brute-force attacks
- **Encryption:** XChaCha20-Poly1305 provides authenticated encryption
- **Memory:** Decrypted plaintext is kept in Python's memory (not wiped on exit)

## Implementation Details

### Libraries Used

- **PyNaCl:** Cryptographic bindings to libsodium
  - `nacl.pwhash.argon2id.kdf()` — Key derivation
  - `nacl.bindings.crypto_secretstream_xchacha20poly1305_*` — Secretstream decryption

### Compatibility

This implementation is compatible with Ente Auth's official cryptographic implementation, verified against official test vectors from the Ente CLI.

## License

See project LICENSE file.
