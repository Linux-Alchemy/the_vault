"""Tests for vault/container.py — Binary .vlt file format I/O.

12 tests covering header, metadata, blob, and vault creation operations.
"""

import os
import struct
from datetime import datetime, timezone
import pytest

from vault.constants import FORMAT_VERSION, HEADER_FORMAT, HEADER_SIZE, MAGIC_BYTES
from vault.container import (
    append_blob,
    create_vault,
    read_blob,
    read_header,
    read_metadata,
    write_header,
    write_metadata,
)
from vault.errors import VaultAuthError, VaultCorruptError
from vault.models import KDFParams, VaultEntry, VaultHeader, VaultMetadata


class TestHeader:
    """Tests for header read/write operations."""

    def test_create_vault_produces_file(self, tmp_vault):
        """Vault file should exist after creation."""
        assert os.path.exists(tmp_vault)
        assert os.path.getsize(tmp_vault) > 0

        
    def test_header_roundtrip(self, tmp_vault):
        """Write a header, read it back — all fields should match."""
        header = read_header(tmp_vault)
        assert header.magic == MAGIC_BYTES
        assert header.version == FORMAT_VERSION
        assert len(header.salt) == 16
        assert header.metadata_offset > 0


    def test_header_magic_bytes_correct(self, tmp_vault):
        """First 4 bytes of the file should be b'TVLT'."""
        with open(tmp_vault, 'rb') as f:
            assert f.read(4) == MAGIC_BYTES


    def test_header_invalid_magic_raises_corrupt(self, tmp_vault):
        """Corrupted magic bytes should raise VaultCorruptError."""
        with open(tmp_vault, 'r+b') as f:
            f.write(b'XXXX')

        with pytest.raises(VaultCorruptError):
            read_header(tmp_vault)


    def test_header_unsupported_version_raises_corrupt(self, tmp_vault):
        """A version number we don't support should raise VaultCorruptError."""
        with open(tmp_vault, 'r+b') as f:
            # Version field starts at byte offset 4 (after 4-byte magic).
            f.seek(4)
            f.write(struct.pack('>H', 99))

        with pytest.raises(VaultCorruptError):
            read_header(tmp_vault)


class TestMetadata:
    """Tests for encrypted metadata read/write."""

    def test_metadata_roundtrip(self, tmp_vault, vault_key):
        """Empty metadata should survive write→read."""
        metadata = read_metadata(tmp_vault, vault_key)
        assert isinstance(metadata, VaultMetadata)
        assert metadata.vault_version == FORMAT_VERSION


    def test_metadata_with_entries_roundtrip(self, tmp_vault, vault_key):
        """Metadata with entries should survive write→read."""
        metadata = read_metadata(tmp_vault, vault_key)
        entry = VaultEntry(id="test_1", name="smith", entry_type="password")
        metadata.entries.append(entry)
        write_metadata(tmp_vault, metadata, vault_key)
        result = read_metadata(tmp_vault, vault_key)
        assert len(result.entries) == 1
        assert result.entries[0].name == "smith"
        assert result.entries[0].entry_type == "password"

    def test_metadata_wrong_key_raises_auth_error(self, tmp_vault):
        """Decrypting metadata with the wrong key should raise VaultAuthError."""
        wrong_key = os.urandom(32)
        with pytest.raises(VaultAuthError):
            read_metadata(tmp_vault, wrong_key)


class TestBlob:
    """Tests for encrypted blob read/write."""

    def test_blob_roundtrip(self, tmp_vault, vault_key):
        """Data should survive encrypt→append→read→decrypt."""
        plaintext = b"secret_password"
        offset, length, nonce = append_blob(tmp_vault, plaintext, vault_key)
        decrypted = read_blob(tmp_vault, offset, length, nonce, vault_key)
        assert plaintext == decrypted

    def test_blob_wrong_key_raises_auth_error(self, tmp_vault, vault_key):
        """Decrypting a blob with the wrong key should raise VaultAuthError."""
        data = b"heart of gold"
        bad_key = os.urandom(32)
        offset, length, nonce = append_blob(tmp_vault, data, vault_key)
        with pytest.raises(VaultAuthError):
            read_blob(tmp_vault, offset, length, nonce, bad_key)


    def test_append_preserves_existing_data(self, tmp_vault, vault_key):
        """Appending new blobs shouldn't corrupt earlier ones."""
        data1 = b"pippen was kind of a doosh"
        data2 = b"seriously though, what's with pippen?"
        offset1, length1, nonce1 = append_blob(tmp_vault, data1, vault_key)
        offset2, length2, nonce2 = append_blob(tmp_vault, data2, vault_key)
        decrypt1 = read_blob(tmp_vault, offset1, length1, nonce1, vault_key)
        decrypt2 = read_blob(tmp_vault, offset2, length2, nonce2, vault_key)
        assert decrypt1 == data1
        assert decrypt2 == data2


class TestCreateVault:
    """Tests for the create_vault orchestration function."""

    def test_create_vault_empty_metadata_decryptable(self, tmp_vault, vault_key):
        """A freshly created vault's metadata should decrypt successfully."""
        metadata = read_metadata(tmp_vault, vault_key)
        assert metadata.entries == []
        assert isinstance(metadata.vault_created, str)
        parsed = datetime.fromisoformat(metadata.vault_created)
        assert parsed.tzinfo is not None


