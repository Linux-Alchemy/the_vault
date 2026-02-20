"""Tests for vault.crypto — KDF and AES-256-GCM encrypt/decrypt.

Each test targets one specific behaviour. Fixtures provide the
test passphrase, salt, and fast KDF params (see conftest.py).
"""

import os

import pytest

from vault.crypto import decrypt, derive_key, encrypt, generate_salt
from vault.errors import VaultAuthError
from vault.models import KDFParams


# ── Key Derivation ──────────────────────────────────────────────


class TestDeriveKey:
    """Tests for the Argon2id key derivation function."""

    def test_derive_key_produces_32_bytes(self, sample_passphrase, sample_salt, fast_kdf_params):
        """The derived key must be exactly 32 bytes (256 bits) for AES-256."""
        key = derive_key(sample_passphrase, sample_salt, fast_kdf_params)
        assert len(key) == 32


    def test_derive_key_deterministic(self, sample_passphrase, sample_salt, fast_kdf_params):
        """Same passphrase + salt + params must always produce the same key."""
        key1 = derive_key(sample_passphrase, sample_salt, fast_kdf_params)
        key2 = derive_key(sample_passphrase, sample_salt, fast_kdf_params)
        assert key1 == key2


    def test_derive_key_different_salt(self, sample_passphrase, fast_kdf_params):
        """Different salts must produce different keys (even with same passphrase)."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        key1 = derive_key(sample_passphrase, salt1, fast_kdf_params)
        key2 = derive_key(sample_passphrase, salt2, fast_kdf_params)
        assert key1 != key2


    def test_derive_key_different_passphrase(self, sample_salt, fast_kdf_params):
        """Different passphrases must produce different keys."""
        passphrase1 = "sample_pass1"
        passphrase2 = "sample_pass2"
        key1 = derive_key(passphrase1, sample_salt, fast_kdf_params)
        key2 = derive_key(passphrase2, sample_salt, fast_kdf_params)
        assert key1 != key2



# ── Encrypt / Decrypt ───────────────────────────────────────────


class TestEncryptDecrypt:
    """Tests for AES-256-GCM encryption and decryption."""

    def test_encrypt_decrypt_roundtrip(self, derived_key):
        """Encrypting then decrypting must return the original data."""
        # TODO: Pick some plaintext bytes (e.g. b"hello vault")
        # TODO: Encrypt it
        # TODO: Decrypt the result using the same key and returned nonce
        # TODO: Assert decrypted == original plaintext
        pass

    def test_encrypt_produces_different_output_each_time(self, derived_key):
        """Two encryptions of the same data must differ (because nonces differ)."""
        # TODO: Encrypt the same data twice
        # TODO: Assert the ciphertexts are NOT equal
        # (This proves fresh nonces are being generated)
        pass

    def test_decrypt_wrong_key_raises_auth_error(self, derived_key):
        """Decrypting with the wrong key must raise VaultAuthError."""
        # TODO: Encrypt some data with derived_key
        # TODO: Create a different key (derive from a different passphrase, or just random 32 bytes)
        # TODO: Try to decrypt with the wrong key
        # TODO: Assert VaultAuthError is raised (use pytest.raises)
        pass

    def test_decrypt_tampered_ciphertext_raises_auth_error(self, derived_key):
        """Flipping a bit in the ciphertext must be detected (AEAD integrity)."""
        # TODO: Encrypt some data
        # TODO: Tamper with the ciphertext (e.g. flip one byte: bytearray trick)
        #       tampered = bytearray(ciphertext)
        #       tampered[0] ^= 0xFF
        #       tampered = bytes(tampered)
        # TODO: Try to decrypt the tampered ciphertext
        # TODO: Assert VaultAuthError is raised
        pass

    def test_decrypt_wrong_nonce_raises_auth_error(self, derived_key):
        """Using the wrong nonce for decryption must fail."""
        # TODO: Encrypt some data (returns nonce, ciphertext)
        # TODO: Create a different nonce (e.g. os.urandom(12))
        # TODO: Try to decrypt with the wrong nonce
        # TODO: Assert VaultAuthError is raised
        pass


# ── Salt Generation ─────────────────────────────────────────────


class TestGenerateSalt:
    """Tests for the random salt generator."""

    def test_generate_salt_length(self):
        """Salt must be exactly 16 bytes."""
        # TODO: Call generate_salt() and assert length is 16
        pass

    def test_generate_salt_unique(self):
        """Two calls must produce different salts (astronomically likely)."""
        # TODO: Call generate_salt() twice
        # TODO: Assert the results are different
        pass
