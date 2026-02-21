"""Shared test fixtures for The Vault test suite."""

import os

import pytest

from vault.models import KDFParams


@pytest.fixture
def sample_passphrase():
    """A deterministic test passphrase."""
    return "dont-panic-42"


@pytest.fixture
def sample_salt():
    """A random salt for testing. Fresh per test."""
    return os.urandom(16)


@pytest.fixture
def fast_kdf_params():
    """Reduced KDF params so tests don't take forever.

    Production defaults are time_cost=3, memory_cost=65536.
    We dial these way down for testing — the crypto is the same,
    just faster to compute.
    """
    return KDFParams(time_cost=1, memory_cost=8192, parallelism=1)


@pytest.fixture
def derived_key(sample_passphrase, sample_salt, fast_kdf_params):
    """A derived key from the test passphrase + salt.

    Imported lazily so this fixture works even before crypto.py
    is implemented — it'll just fail with a clear error.
    """
    from vault.crypto import derive_key

    return derive_key(sample_passphrase, sample_salt, fast_kdf_params)


# --- Phase 2 fixtures ---


@pytest.fixture
def tmp_vault(tmp_path, sample_passphrase, fast_kdf_params):
    """Creates a fresh vault file for testing.

    Uses fast KDF params so tests aren't glacial.
    """
    from vault.container import create_vault

    vault_path = tmp_path / "test.vlt"
    create_vault(str(vault_path), sample_passphrase, fast_kdf_params)
    return vault_path


@pytest.fixture
def vault_key(sample_passphrase, tmp_vault, fast_kdf_params):
    """Returns the derived key for the test vault."""
    from vault.container import read_header
    from vault.crypto import derive_key

    header = read_header(str(tmp_vault))
    return derive_key(sample_passphrase, header.salt, fast_kdf_params)
