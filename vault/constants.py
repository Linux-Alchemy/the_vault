"""constants.py — Central registry of magic values and defaults for The Vault."""

# File format identifiers
MAGIC_BYTES = b"TVLT"
FORMAT_VERSION = 1

# Argon2id KDF defaults
# Docs: https://argon2-cffi.readthedocs.io/en/stable/api.html#low-level
DEFAULT_TIME_COST = 3
DEFAULT_MEMORY_COST = 65536  # 64 MB
DEFAULT_PARALLELISM = 4

# Crypto sizes (bytes)
SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32

# Binary header format
# >  = big-endian
# 4s = 4-byte magic string ("TVLT")
# H  = uint16 (version)
# I  = uint32 (time_cost, memory_cost, parallelism)
# 16s = 16-byte salt
# Q  = uint64 (metadata offset)
# Docs: https://docs.python.org/3/library/struct.html#format-characters
HEADER_FORMAT = ">4sHIII16sQ"
HEADER_SIZE = 42  # struct.calcsize(HEADER_FORMAT)
METADATA_OFFSET_POSITION = 34  # byte offset where metadata_offset lives in header

# Session defaults
DEFAULT_TIMEOUT = 300  # 5 minutes

# Exit codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_NOT_FOUND = 2
EXIT_LOCKED = 3
EXIT_CORRUPT = 4
EXIT_BAD_PASSPHRASE = 5
