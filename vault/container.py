"""container.py — Binary file I/O for the .vlt vault format.

Handles reading and writing the vault's binary structure:
- Fixed 42-byte plaintext header (magic, version, KDF params, salt, metadata pointer)
- Encrypted metadata blocks (JSON index of all entries)
- Encrypted blobs (the actual secret data)

All writes are append-only (except the metadata offset pointer in the header).
This makes the format crash-safe — a failed write can't corrupt existing data.

Docs: https://docs.python.org/3/library/struct.html
"""

import json
import struct
from datetime import datetime, timezone

from vault.constants import (
    FORMAT_VERSION,
    HEADER_FORMAT,
    HEADER_SIZE,
    MAGIC_BYTES,
    METADATA_OFFSET_POSITION,
    NONCE_LENGTH,
)
from vault.crypto import derive_key, encrypt, decrypt, generate_salt
from vault.errors import VaultCorruptError
from vault.models import KDFParams, VaultHeader, VaultMetadata


def write_header(filepath: str, header: VaultHeader) -> None:
    """Write the 42-byte header to the start of the vault file."""

    packed = struct.pack(HEADER_FORMAT, header.magic, header.version, header.kdf_params.time_cost, header.kdf_params.memory_cost, header.kdf_params.parallelism, header.salt, header.metadata_offset)

    with open(filepath, 'wb') as f:
        f.write(packed)


def read_header(filepath: str) -> VaultHeader:
    """Read and validate the 42-byte header from a vault file."""
    with open(filepath, 'rb') as f:
        raw_bytes = f.read(HEADER_SIZE)

    magic, version, time_cost, memory_cost, parallelism, salt, metadata_offset = struct.unpack(HEADER_FORMAT, raw_bytes)
    if magic != MAGIC_BYTES:
        raise VaultCorruptError("Invalid magic bytes")

    if version > FORMAT_VERSION:
        raise VaultCorruptError("Invalid version")

    kdf = KDFParams(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism)
    header = VaultHeader(magic=magic, version=version, kdf_params=kdf, salt=salt, metadata_offset=metadata_offset)
    return header

    
def update_metadata_offset(filepath: str, offset: int) -> None:
    """Update the metadata offset pointer in the header."""

    with open(filepath, 'r+b') as f:
        f.seek(METADATA_OFFSET_POSITION)
        f.write(struct.pack('>Q', offset))



def write_metadata(filepath: str, metadata: VaultMetadata, key: bytes) -> int:
    """Encrypt and append a metadata block to the vault file.

    On-disk format: [12-byte nonce][4-byte ciphertext length][ciphertext]

    Args:
        filepath: Path to the vault file.
        metadata: The metadata to write.
        key: Encryption key.

    Returns:
        The byte offset where this metadata block was written.
    """
    # TODO: Serialise metadata to JSON bytes — metadata.to_dict() then json.dumps().encode()
    # TODO: Encrypt the JSON bytes using crypto.encrypt() → (nonce, ciphertext)
    # TODO: Open file in 'ab' mode (append binary)
    # TODO: Record the current position with f.tell() — this is your offset
    # TODO: Write: nonce + struct.pack('>I', len(ciphertext)) + ciphertext
    # TODO: Call update_metadata_offset() with the offset you recorded
    # TODO: Return the offset
    pass


def read_metadata(filepath: str, key: bytes) -> VaultMetadata:
    """Read and decrypt the latest metadata block from the vault.

    Args:
        filepath: Path to the vault file.
        key: Decryption key.

    Returns:
        VaultMetadata with all entries.

    Raises:
        VaultAuthError: If key is wrong (AEAD tag failure).
    """
    # TODO: Read the header to get metadata_offset
    # TODO: Open in 'rb', seek to metadata_offset
    # TODO: Read 12 bytes (nonce), then 4 bytes and unpack as '>I' (ciphertext length)
    # TODO: Read that many bytes (ciphertext)
    # TODO: Decrypt using crypto.decrypt(ciphertext, key, nonce)
    # TODO: json.loads() the plaintext, then VaultMetadata.from_dict()
    # TODO: Return the metadata
    pass


def append_blob(filepath: str, data: bytes, key: bytes) -> tuple[int, int, bytes]:
    """Encrypt and append a data blob to the vault file.

    On-disk format: [ciphertext] (nonce stored in metadata, not on disk with blob)

    Args:
        filepath: Path to the vault file.
        data: Plaintext bytes to encrypt and store.
        key: Encryption key.

    Returns:
        Tuple of (offset, length, nonce) for storing in metadata.
        offset: byte position where ciphertext starts in the file.
        length: number of ciphertext bytes written.
        nonce: the 12-byte nonce needed for decryption.
    """
    # TODO: Encrypt data using crypto.encrypt() → (nonce, ciphertext)
    # TODO: Open file in 'ab' mode
    # TODO: Record position with f.tell() — this is offset
    # TODO: Write just the ciphertext (nonce goes in metadata, not on disk)
    # TODO: Return (offset, len(ciphertext), nonce)
    pass


def read_blob(filepath: str, offset: int, length: int, nonce: bytes, key: bytes) -> bytes:
    """Read and decrypt a data blob from the vault file.

    Args:
        filepath: Path to the vault file.
        offset: Byte offset where the ciphertext starts.
        length: Number of bytes of ciphertext to read.
        nonce: 12-byte nonce for decryption (from metadata).
        key: Decryption key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        VaultAuthError: If key is wrong or data is tampered.
    """
    # TODO: Open in 'rb', seek to offset, read length bytes
    # TODO: Decrypt using crypto.decrypt(ciphertext, key, nonce)
    # TODO: Return the plaintext
    pass


def create_vault(filepath: str, passphrase: str, kdf_params: KDFParams | None = None) -> None:
    """Create a new vault file from scratch.

    This orchestrates the full vault creation:
    1. Generate a random salt
    2. Derive the encryption key from passphrase + salt
    3. Build the header
    4. Write the header (creates the file)
    5. Create empty metadata
    6. Write encrypted metadata
    (metadata offset gets updated inside write_metadata)

    Args:
        filepath: Path for the new vault file.
        passphrase: User's passphrase.
        kdf_params: Optional KDF parameters (uses defaults if None).
    """
    # TODO: Use kdf_params or create default KDFParams()
    # TODO: Generate salt with crypto.generate_salt()
    # TODO: Derive key with crypto.derive_key(passphrase, salt, params)
    # TODO: Create a VaultHeader with the params, salt, and metadata_offset=0
    # TODO: Open file in 'wb' mode and write the packed header (creates the file)
    # TODO: Create empty VaultMetadata with vault_created as ISO timestamp, version, empty entries
    # TODO: Call write_metadata() to encrypt and append it (this also updates the header offset)
    pass
