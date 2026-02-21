"""models.py — Data classes for The Vault.

Defines the core data structures used across the vault system:
- KDFParams: Argon2id key derivation parameters
- VaultHeader: The 42-byte plaintext file header
- VaultEntry: A single secret record (password, key, or file)
- VaultMetadata: The encrypted index of all entries
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from vault.constants import (
    DEFAULT_MEMORY_COST,
    DEFAULT_PARALLELISM,
    DEFAULT_TIME_COST,
    FORMAT_VERSION,
    MAGIC_BYTES,
)


@dataclass
class KDFParams:
    """Parameters for the Argon2id key derivation function."""

    time_cost: int = DEFAULT_TIME_COST
    memory_cost: int = DEFAULT_MEMORY_COST
    parallelism: int = DEFAULT_PARALLELISM


@dataclass
class VaultHeader:
    """The 42-byte plaintext header at the start of every .vlt file.

    Layout (big-endian):
        Offset  Size  Field
        0       4     Magic bytes ("TVLT")
        4       2     Format version (uint16)
        6       4     Argon2 time_cost (uint32)
        10      4     Argon2 memory_cost (uint32)
        14      4     Argon2 parallelism (uint32)
        18      16    Salt
        34      8     Metadata offset (uint64)
    """

    magic: bytes = MAGIC_BYTES
    version: int = FORMAT_VERSION
    kdf_params: KDFParams = field(default_factory=KDFParams)
    salt: bytes = b""
    metadata_offset: int = 0


@dataclass
class VaultEntry:
    """A single entry in the vault (password, key, or file).

    The actual secret data lives in an encrypted blob in the vault file.
    This entry stores the metadata needed to find and decrypt that blob.
    """

    id: str = ""
    entry_type: str = ""  # "password", "key", or "file"
    name: str = ""
    fields: dict = field(default_factory=dict)  # non-secret metadata (username, email, etc.)
    blob_offset: int = 0
    blob_length: int = 0
    nonce: bytes = b""  # 12-byte nonce for blob decryption
    created_at: str = ""
    deleted: bool = False

    def to_dict(self) -> dict:
        """Serialise to a JSON-safe dictionary.

        Nonce is stored as hex since JSON can't handle raw bytes.
        """
        return {
            "id": self.id,
            "entry_type": self.entry_type,
            "name": self.name,
            "fields": self.fields,
            "blob_offset": self.blob_offset,
            "blob_length": self.blob_length,
            "nonce": self.nonce.hex(),
            "created_at": self.created_at,
            "deleted": self.deleted,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VaultEntry":
        """Deserialise from a dictionary (as read from JSON)."""
        return cls(
            id=data["id"],
            entry_type=data["entry_type"],
            name=data["name"],
            fields=data.get("fields", {}),
            blob_offset=data["blob_offset"],
            blob_length=data["blob_length"],
            nonce=bytes.fromhex(data["nonce"]),
            created_at=data["created_at"],
            deleted=data.get("deleted", False),
        )


@dataclass
class VaultMetadata:
    """The encrypted index that tracks all entries in the vault.

    This gets serialised to JSON, encrypted, and appended to the vault file.
    The header's metadata_offset points to the latest version.
    """

    vault_created: str = ""
    vault_version: int = FORMAT_VERSION
    entries: list[VaultEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialise to a JSON-safe dictionary."""
        return {
            "vault_created": self.vault_created,
            "vault_version": self.vault_version,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VaultMetadata":
        """Deserialise from a dictionary (as read from JSON)."""
        return cls(
            vault_created=data["vault_created"],
            vault_version=data["vault_version"],
            entries=[VaultEntry.from_dict(e) for e in data.get("entries", [])],
        )
