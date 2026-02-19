"""crypto.py — Cryptographic operations for The Vault.

Handles password-based key derivation (Argon2id) and authenticated
encryption/decryption (AES-256-GCM). All other modules call into
this one for cryptographic operations — crypto logic never leaks
into other layers.
"""

import os

# Docs: https://argon2-cffi.readthedocs.io/en/stable/lowlevel.html
import argon2.low_level

# Docs: https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault.constants import KEY_LENGTH, NONCE_LENGTH, SALT_LENGTH
from vault.errors import VaultAuthError
from vault.models import KDFParams


def generate_salt() -> bytes:
    """Generate a cryptographically random salt for key derivation."""
    salt = os.urandom(SALT_LENGTH)
    return salt



def derive_key(passphrase: str, salt: bytes, params: KDFParams) -> bytes:
    """Derive a 256-bit encryption key from a passphrase using Argon2id.

    Args:
        passphrase: The user's passphrase (UTF-8 string).
        salt: Random salt bytes (16 bytes, generated at vault creation).
        params: KDF parameters (time_cost, memory_cost, parallelism).

    Returns:
        32 bytes of derived key material suitable for AES-256-GCM.
    """
    key = argon2.low_level.hash_secret_raw(
        secret = passphrase.encode("UTF-8"),
        salt = salt, 
        time_cost = KDFParams.time_cost,
        memory_cost = KDFParams.memory_cost,
        parallelism = KDFParams.parallelism,
        hash_len = KEY_LENGTH,
        type = argon2.low_level.Type.ID,
    )
    
    return key



def encrypt(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt data using AES-256-GCM.

    Args:
        data: Plaintext bytes to encrypt.
        key: 32-byte encryption key.

    Returns:
        Tuple of (nonce, ciphertext). Both are needed for decryption.
        The nonce is 12 bytes. The ciphertext includes the GCM auth tag.
    """


    # TODO: Generate a random 12-byte nonce (NONCE_LENGTH) with os.urandom
    # TODO: Create an AESGCM instance with the key
    # TODO: Encrypt: aesgcm.encrypt(nonce, data, None)
    #       The None means no additional authenticated data (AAD)
    # TODO: Return (nonce, ciphertext)
    pass


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt data using AES-256-GCM.

    Args:
        ciphertext: Encrypted bytes (includes GCM auth tag).
        key: 32-byte encryption key (must match the key used to encrypt).
        nonce: 12-byte nonce that was used during encryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        VaultAuthError: If the key is wrong or the ciphertext has been
            tampered with (AEAD tag verification failure).
    """
    # TODO: Create an AESGCM instance with the key
    # TODO: Try to decrypt: aesgcm.decrypt(nonce, ciphertext, None)
    # TODO: Catch cryptography.exceptions.InvalidTag and raise VaultAuthError instead
    #       Import: from cryptography.exceptions import InvalidTag
    # TODO: Return the decrypted plaintext bytes
    pass
