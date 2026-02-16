"""errors.py — Custom exception hierarchy for The Vault.

Each exception maps to a specific exit code so the CLI layer can translate
exceptions into user-friendly messages without knowing the internals.
"""

from vault.constants import (
    EXIT_BAD_PASSPHRASE,
    EXIT_CORRUPT,
    EXIT_GENERAL_ERROR,
    EXIT_LOCKED,
    EXIT_NOT_FOUND,
)


class VaultError(Exception):
    """Base exception for all vault-specific errors."""

    exit_code = EXIT_GENERAL_ERROR

    def __init__(self, message: str = "An error occurred"):
        self.message = message
        super().__init__(self.message)


class VaultCorruptError(VaultError):
    """Raised when the vault file is malformed or has bad magic bytes."""

    exit_code = EXIT_CORRUPT

    def __init__(self, message: str = "Vault file is corrupt or unsupported version"):
        super().__init__(message)


class VaultLockedError(VaultError):
    """Raised when an operation requires an active session but none exists."""

    exit_code = EXIT_LOCKED

    def __init__(self, message: str = "Vault is locked. Run `vault open <path>`"):
        super().__init__(message)


class VaultAuthError(VaultError):
    """Raised on wrong passphrase or AEAD tag verification failure."""

    exit_code = EXIT_BAD_PASSPHRASE

    def __init__(self, message: str = "Invalid passphrase"):
        super().__init__(message)


class VaultEntryNotFoundError(VaultError):
    """Raised when a requested entry doesn't exist in the vault."""

    exit_code = EXIT_NOT_FOUND

    def __init__(self, name: str = ""):
        message = f"No such entry: {name}" if name else "Entry not found"
        super().__init__(message)
