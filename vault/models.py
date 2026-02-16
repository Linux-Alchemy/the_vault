"""models.py — Data classes for The Vault.

Starts with KDFParams for Phase 1. Additional models (VaultHeader, VaultEntry,
VaultMetadata) will be added in Phase 2.
"""

from dataclasses import dataclass

from vault.constants import DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM, DEFAULT_TIME_COST


@dataclass
class KDFParams:
    """Parameters for the Argon2id key derivation function."""

    time_cost: int = DEFAULT_TIME_COST
    memory_cost: int = DEFAULT_MEMORY_COST
    parallelism: int = DEFAULT_PARALLELISM
