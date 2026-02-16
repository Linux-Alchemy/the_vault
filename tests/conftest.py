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
