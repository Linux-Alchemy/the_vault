# The Vault — OUTLINE.md

## Build Plan for Claude Code (Plan Mode)

> **What this document is:** A highly detailed, phase-by-phase build plan for "The Vault" — a
> session-based, single-file encrypted vault CLI tool. Each phase produces a working, testable
> increment. Hand this to Claude Code in plan mode and it will know exactly what to build and when.

> **Predecessor project:** [The Locksmith](./locksmith.py) — a simple file encryption CLI using
> Fernet symmetric encryption. The Vault evolves every concept from Locksmith: proper KDF-based
> key derivation replaces raw key files, AEAD encryption replaces Fernet, a binary container
> format replaces loose files, and session management replaces per-command key entry.

---

## 1. Project Overview

### What We're Building

A Python CLI tool called `vault` that manages an encrypted single-file container (`.vlt`).
Everything — metadata index, secret records, and stored files — lives inside one portable
binary file, encrypted at rest. The CLI presents a "folder-like" view (Passwords / Keys / Files)
purely as presentation over the encrypted data.

Think of it as a miniature, CLI-driven password vault. One file you can chuck on a USB stick or
back up to cloud storage, knowing that without your passphrase, it's just noise.

### Primary Use Case

A security-conscious developer who wants a local, portable, offline vault for credentials,
API keys, SSH keys, and sensitive files — without trusting a third-party cloud service.

### Core Functionality (V1)

- **Vault lifecycle:** `init`, `open`, `close`, `status`
- **Session management:** unlock once with passphrase, work until timeout or explicit close
- **Secrets management:** add/get/remove passwords and keys (clipboard-only output)
- **File storage:** encrypt and store arbitrary files inside the vault
- **Search:** find entries by name or field values
- **List/browse:** grouped view of vault contents by type

### Success Criteria (What "Done" Looks Like)

- [ ] `vault init` creates a valid `.vlt` file with proper header and encrypted empty metadata
- [ ] `vault open` derives the master key, decrypts metadata, creates a session
- [ ] Subsequent commands work without re-entering the passphrase (until timeout)
- [ ] Secrets are **never** printed to stdout — clipboard only
- [ ] Files survive a full cycle: add → close → open → get
- [ ] Wrong passphrase fails cleanly with no partial output
- [ ] Tampered ciphertext is detected (AEAD integrity)
- [ ] All commands have proper exit codes and help text
- [ ] pytest test suite covers all major behaviours

### Why This Matters

This project is a significant step up from Locksmith in several dimensions:

- **Cryptography:** From Fernet (a convenience wrapper) to raw Argon2id KDF + AES-256-GCM AEAD.
  You'll understand *why* password-based encryption needs a KDF, what salts and nonces do, and
  how authenticated encryption prevents tampering.
- **Architecture:** From flat functions to a proper multi-module OOP design with clear separation
  of concerns. Classes with real responsibilities, not just wrappers.
- **File formats:** From "encrypt a file, get a file" to designing and implementing a binary
  container format with headers, offsets, and append-only writes.
- **Session management:** State that persists across CLI invocations — a real-world pattern
  used by tools like `ssh-agent`, `gpg-agent`, and `docker login`.
- **Testing:** From zero tests to a proper pytest suite with fixtures, mocks, and coverage of
  happy paths, error paths, and security properties.

---

## 2. Smart Design Decisions

### Architecture Approach

The project uses a **layered architecture** with four clear layers:

```
┌─────────────────────────────────┐
│         CLI Layer (cli.py)       │  ← argparse, user interaction, exit codes
├─────────────────────────────────┤
│      Session Layer (session.py)  │  ← session tokens, timeout, authentication
├─────────────────────────────────┤
│       Vault Layer (vault.py)     │  ← business logic: add/get/rm/list/search
├─────────────────────────────────┤
│      Crypto Layer (crypto.py)    │  ← KDF, encrypt, decrypt, key management
├─────────────────────────────────┤
│     Container Layer (container.py)│  ← binary file format, read/write/append
└─────────────────────────────────┘
```

**Why this structure:** Each layer has one job. The CLI layer never touches raw bytes. The crypto
layer never knows about argparse. The container layer doesn't care what's in the encrypted blobs.
This means you can test each layer independently, and changes to one layer don't ripple through
the others. It's the same principle as Locksmith's function separation, just taken to module level.

### Technology Choices

| Component | Choice | Why |
|-----------|--------|-----|
| Language | Python 3.10+ | Your learning language; match types for clarity |
| KDF | Argon2id via `argon2-cffi` | Industry-standard password hashing; resistant to GPU/ASIC attacks |
| AEAD cipher | AES-256-GCM via `cryptography` | Authenticated encryption; you already know the `cryptography` lib from Locksmith |
| Serialisation | JSON (stdlib) | Human-debuggable during development; adequate for V1 metadata |
| CLI framework | `argparse` (stdlib) | You know it from Locksmith; subcommands work well for this |
| Clipboard | `subprocess` calling `wl-copy`/`xclip`/`pbcopy` | Cross-platform without heavy deps |
| Testing | `pytest` + `pytest-tmp-files` | Industry standard; fixtures make crypto testing clean |
| Session storage | JSON file in `/tmp` with 0600 perms | Simple, inspectable, secure enough for V1 |

### File Structure

```
the_vault/
├── vault/                    # Main package
│   ├── __init__.py
│   ├── cli.py                # argparse setup, command routing, exit codes
│   ├── crypto.py             # KDF (Argon2id), AES-256-GCM encrypt/decrypt
│   ├── container.py          # Binary file format: header, metadata, blobs
│   ├── vault_core.py         # Business logic: add/get/rm/list/search
│   ├── session.py            # Session token management, timeout
│   ├── clipboard.py          # Cross-platform clipboard abstraction
│   ├── models.py             # Data classes: VaultEntry, VaultMetadata, etc.
│   ├── errors.py             # Custom exceptions + exit code mapping
│   └── constants.py          # Magic bytes, version, defaults, exit codes
├── tests/
│   ├── conftest.py           # Shared fixtures (temp vaults, test passphrases)
│   ├── test_crypto.py        # KDF + encryption unit tests
│   ├── test_container.py     # File format read/write tests
│   ├── test_vault_core.py    # Business logic tests
│   ├── test_session.py       # Session creation/timeout/cleanup tests
│   ├── test_clipboard.py     # Clipboard detection + mock tests
│   ├── test_cli.py           # Integration tests via subprocess
│   └── test_security.py      # Tamper detection, wrong passphrase, etc.
├── main.py                   # Entry point: `python main.py` or `vault` command
├── requirements.txt          # cryptography, argon2-cffi, pytest
├── README.md                 # Usage, installation, examples
└── OUTLINE.md                # This file
```

### Design Principles Applied

**Single Responsibility:** Each module handles one concern. `crypto.py` doesn't know about
CLI arguments. `cli.py` doesn't know how AES-GCM works. This is the same principle you used
in Locksmith with separate validation functions, just at module scale.

**Data flows down, errors flow up:** Commands enter at the CLI layer, flow down through
vault logic to crypto/container, and results (or exceptions) bubble back up. Custom
exceptions in `errors.py` get translated to user-friendly messages and exit codes in `cli.py`.

**Explicit over implicit:** No global state. The session file is the only shared state between
CLI invocations, and it's explicitly loaded and validated each time.

**Append-only writes:** The vault file is never rewritten in place (V1). New data is appended,
new metadata is written, and the header pointer is updated. This is resilient — a crash mid-write
can't corrupt existing data.

---

## 3. Security Considerations

### Threat Model (Practical, Not Paranoid)

This is a **local-first** tool. The primary threats are:

1. **Attacker gets the `.vlt` file** (e.g., stolen USB, cloud backup breach)
   - Mitigation: Argon2id KDF makes brute-force expensive; AES-256-GCM is computationally secure
2. **Attacker reads clipboard**
   - Mitigation: Auto-clear after configurable timeout (default 20s)
3. **Attacker reads session token from /tmp**
   - Mitigation: File permissions 0600; timeout expiry; explicit close
4. **User provides wrong passphrase**
   - Mitigation: AEAD tag verification fails cleanly; no partial decryption
5. **File tampering (bit-flip attack)**
   - Mitigation: AES-GCM authentication tag detects any modification

### Input Validation

| Input | Validation | Risk if skipped |
|-------|-----------|-----------------|
| Vault file path | Exists, is file (not dir), readable | Crash or confusing error |
| Passphrase | Non-empty, prompted securely (no echo) | Empty passphrase = no security |
| Entry name | Non-empty string, unique within type | Collisions, confusing lookups |
| `--timeout` value | Valid duration string, sane range | Infinite session or instant expiry |
| `--out` path for file export | Directory exists, writable | Write failure, data loss |
| `--field` argument | Must be valid field for entry type | KeyError or wrong data |

### Error Handling Strategy

**Principle:** Fail loudly with helpful messages. Never expose internal state.

| Scenario | User sees | Exit code |
|----------|-----------|-----------|
| Success | Operation-specific message | 0 |
| Entry not found | "No such entry: <name>" | 2 |
| Vault is locked | "Vault is locked. Run `vault open <path>`" | 3 |
| Corrupt vault / bad decrypt | "Vault file is corrupt or unsupported version" | 4 |
| Invalid passphrase | "Invalid passphrase" | 5 |
| General error | "Error: <brief description>" | 1 |

**What we NEVER show:** stack traces, file paths to session tokens, raw crypto errors,
memory addresses, or partial decrypted data.

### Data Protection

- **Passphrase:** Never stored. Used to derive key, then discarded from scope.
- **Derived key:** Stored in session token file (0600 perms). Cleared on close/timeout.
- **Decrypted metadata:** Held in memory only during active session operations.
- **Clipboard:** Cleared after N seconds via background thread/subprocess.
- **Secrets in memory:** Python doesn't guarantee memory zeroing (GC limitation).
  This is a known V1 limitation. Noted, not solved — honest about the boundary.

### Security Checklist

- [ ] All user input validated before use
- [ ] Passphrase prompted with `getpass` (no echo)
- [ ] Passphrase confirmed on `init` (entered twice)
- [ ] Error messages don't leak internal state
- [ ] Session token file has 0600 permissions
- [ ] Session expires after idle timeout
- [ ] Clipboard auto-clears after configurable delay
- [ ] AEAD tag verified on every decrypt (tamper detection)
- [ ] Unique nonce per encryption operation (never reused)
- [ ] Salt is random per vault (generated at init)

---

## 4. Implementation Phases

---

### Phase 1: Project Skeleton + Crypto Foundation

**Goal:** Get the project structure in place with working Argon2id key derivation and
AES-256-GCM encrypt/decrypt. This is the bedrock everything else builds on.

**What to Build:**

**`constants.py`** — Central place for all magic values:
- `MAGIC_BYTES = b"TVLT"` — identifies vault files
- `FORMAT_VERSION = 1` — for future compatibility
- Default Argon2 parameters (time_cost, memory_cost, parallelism)
- Default timeout duration
- Exit code constants (SUCCESS=0, NOT_FOUND=2, LOCKED=3, CORRUPT=4, BAD_PASSPHRASE=5)

**`errors.py`** — Custom exception hierarchy:
- `VaultError` (base) — all vault-specific errors inherit from this
- `VaultCorruptError` — file format issues, bad magic bytes
- `VaultLockedError` — no active session
- `VaultAuthError` — wrong passphrase / AEAD tag failure
- `VaultEntryNotFoundError` — entry doesn't exist
- Each exception class maps to an exit code via a `.exit_code` attribute

**`crypto.py`** — The cryptographic engine:
- `derive_key(passphrase: str, salt: bytes, params: dict) -> bytes`
  - Uses `argon2.low_level.hash_secret_raw()` with Argon2id
  - Returns 32 bytes (256-bit key for AES-256-GCM)
  - Parameters (time_cost, memory_cost, parallelism) passed in, not hardcoded
- `encrypt(data: bytes, key: bytes) -> tuple[bytes, bytes]`
  - Generates random 12-byte nonce via `os.urandom(12)`
  - Encrypts with AES-256-GCM using `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
  - Returns `(nonce, ciphertext)` — nonce is needed for decryption
- `decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes`
  - Decrypts with AES-256-GCM
  - Raises `VaultAuthError` if AEAD tag verification fails (tamper or wrong key)
- `generate_salt() -> bytes`
  - Returns 16 bytes from `os.urandom(16)`

**`models.py`** — Data classes (using `@dataclass`):
- `KDFParams` — time_cost, memory_cost, parallelism, salt
- Start with just this; other models added in later phases

**`requirements.txt`:**
```
cryptography>=42.0.0
argon2-cffi>=23.1.0
pytest>=8.0.0
```

**Project setup:**
- `main.py` — placeholder entry point (just prints "The Vault v0.1")
- `vault/__init__.py` — empty
- `tests/` directory with `conftest.py` containing basic fixtures
- `.gitignore` — `__pycache__/`, `*.vlt`, `.pytest_cache/`, `venv/`

**Implementation Notes:**
- The `cryptography` library's `AESGCM` class is straightforward: create instance with key,
  call `.encrypt(nonce, data, None)` and `.decrypt(nonce, data, None)`. The `None` is for
  "associated data" (AAD) which we don't need in V1.
- Argon2id is the recommended variant (combines Argon2i's side-channel resistance with
  Argon2d's GPU resistance). The `argon2-cffi` library wraps the reference C implementation.
- **Critical:** Never reuse a nonce with the same key. AES-GCM's security completely breaks
  if you do. Our `encrypt()` generates a fresh random nonce every time — this is correct.
- Default Argon2 params: `time_cost=3, memory_cost=65536 (64MB), parallelism=4`.
  These are reasonable for a local tool. Can be tuned later.

**Testing This Phase (`tests/test_crypto.py`):**

- `test_derive_key_produces_32_bytes` — Verify output length is 32 bytes
- `test_derive_key_deterministic` — Same passphrase + salt + params = same key
- `test_derive_key_different_salt` — Different salt = different key
- `test_derive_key_different_passphrase` — Different passphrase = different key
- `test_encrypt_decrypt_roundtrip` — Encrypt then decrypt returns original data
- `test_encrypt_produces_different_output_each_time` — Two encryptions of same data differ
  (because nonces differ)
- `test_decrypt_wrong_key_raises_auth_error` — VaultAuthError raised
- `test_decrypt_tampered_ciphertext_raises_auth_error` — Flip a bit, verify detection
- `test_decrypt_wrong_nonce_raises_auth_error` — Wrong nonce fails
- `test_generate_salt_length` — Salt is 16 bytes
- `test_generate_salt_unique` — Two calls produce different salts

**`tests/conftest.py` fixtures:**
```python
@pytest.fixture
def sample_passphrase():
    return "dont-panic-42"

@pytest.fixture
def sample_salt():
    return os.urandom(16)

@pytest.fixture
def derived_key(sample_passphrase, sample_salt):
    return derive_key(sample_passphrase, sample_salt, DEFAULT_KDF_PARAMS)
```

**Success Criteria:**
- [ ] `pytest tests/test_crypto.py` — all tests pass
- [ ] Encrypt/decrypt roundtrip works for various data sizes (empty, small, 1MB)
- [ ] Wrong key, wrong nonce, tampered data all raise `VaultAuthError`
- [ ] `derive_key` is deterministic with same inputs
- [ ] Project structure matches the file layout above

**Advanced Approach (Future Enhancement):**
In a production vault, you'd use a *two-tier key system*: the passphrase derives a
"master key" which then unwraps a randomly-generated "data encryption key" (DEK). This lets
you change your passphrase without re-encrypting all data. For V1, single-tier is fine.

---

### Phase 2: Binary Container Format

**Goal:** Implement the `.vlt` file format — reading and writing the plaintext header,
encrypted metadata blocks, and encrypted blobs. After this phase, you can create a vault
file and read it back.

**What to Build:**

**`models.py`** — Expand with container-related models:
- `VaultHeader` dataclass:
  - `magic: bytes` (4 bytes, "TVLT")
  - `version: int` (2 bytes, unsigned short)
  - `kdf_params: KDFParams` (serialised as fixed-size fields)
  - `salt: bytes` (16 bytes)
  - `metadata_offset: int` (8 bytes, unsigned long long — points to latest metadata block)
- `VaultEntry` dataclass:
  - `id: str` (UUID4 as string)
  - `entry_type: str` ("password", "key", "file")
  - `name: str`
  - `fields: dict` (username, email, etc. — varies by type)
  - `blob_offset: int`
  - `blob_length: int`
  - `nonce: bytes` (12 bytes for AES-GCM)
  - `created_at: str` (ISO 8601 timestamp)
  - `deleted: bool` (tombstone flag, default False)
- `VaultMetadata` dataclass:
  - `vault_created: str` (ISO 8601)
  - `vault_version: int`
  - `entries: list[VaultEntry]`

**`container.py`** — Binary file I/O:

*Header operations:*
- `write_header(filepath: str, header: VaultHeader) -> None`
  - Writes the fixed-size plaintext header at the start of the file
  - Uses `struct.pack` for binary encoding
  - Header layout (exact byte positions):
    ```
    Offset  Size  Field
    0       4     Magic bytes ("TVLT")
    4       2     Format version (uint16)
    6       4     Argon2 time_cost (uint32)
    10      4     Argon2 memory_cost (uint32)
    14      4     Argon2 parallelism (uint32)
    18      16    Salt
    34      8     Metadata offset (uint64)
    ─────────────────────────────
    Total: 42 bytes (fixed)
    ```
- `read_header(filepath: str) -> VaultHeader`
  - Reads and validates header: checks magic bytes, version compatibility
  - Raises `VaultCorruptError` if magic bytes don't match or version unsupported
- `update_metadata_offset(filepath: str, offset: int) -> None`
  - Seeks to byte 34, writes new uint64 offset
  - This is the only in-place write in the entire system

*Metadata operations:*
- `write_metadata(filepath: str, metadata: VaultMetadata, key: bytes) -> int`
  - Serialises metadata to JSON bytes
  - Encrypts with `crypto.encrypt()`
  - Appends to end of file: `[nonce (12 bytes)][length (4 bytes)][ciphertext]`
  - Returns the offset where this metadata block was written
  - Updates header's metadata_offset pointer
- `read_metadata(filepath: str, key: bytes) -> VaultMetadata`
  - Reads metadata_offset from header
  - Seeks to that offset, reads nonce + length + ciphertext
  - Decrypts and deserialises JSON back to `VaultMetadata`
  - Raises `VaultAuthError` on bad passphrase (AEAD failure)

*Blob operations:*
- `append_blob(filepath: str, data: bytes, key: bytes) -> tuple[int, int, bytes]`
  - Encrypts data with `crypto.encrypt()`
  - Appends to end of file: raw `[nonce][ciphertext]`
  - Returns `(offset, length, nonce)` for metadata tracking
- `read_blob(filepath: str, offset: int, length: int, nonce: bytes, key: bytes) -> bytes`
  - Seeks to offset, reads length bytes of ciphertext
  - Decrypts with provided nonce and key
  - Returns plaintext bytes

*Vault creation:*
- `create_vault(filepath: str, passphrase: str) -> None`
  - Generates random salt
  - Derives key from passphrase + salt
  - Creates header with default KDF params
  - Writes header
  - Creates empty metadata (no entries)
  - Writes encrypted empty metadata
  - Updates header metadata offset
  - Result: a valid `.vlt` file ready for use

**Implementation Notes:**
- `struct` module is your friend here. `struct.pack('>4sHIII16sQ', ...)` for the header.
  The `>` means big-endian (network byte order — conventional for binary formats).
- The metadata block format on disk is: `[12-byte nonce][4-byte length of ciphertext][ciphertext]`.
  The length prefix lets us know exactly how many bytes to read.
- Blob format on disk is simpler: `[12-byte nonce][ciphertext]`. We store the nonce and
  ciphertext length in the metadata entry, so we know how much to read.
- **Why append-only?** It's crash-safe. If the program dies mid-write, the old metadata
  pointer is still valid. The worst case is orphaned bytes at the end of the file.
- File operations should use `'ab'` for appending and `'r+b'` only for the header offset update.

**Testing This Phase (`tests/test_container.py`):**

- `test_create_vault_produces_file` — File exists after creation
- `test_header_roundtrip` — Write header, read it back, all fields match
- `test_header_magic_bytes_correct` — First 4 bytes are "TVLT"
- `test_header_invalid_magic_raises_corrupt` — Modify magic bytes, verify error
- `test_header_unsupported_version_raises_corrupt` — Version 99 raises error
- `test_metadata_roundtrip` — Write empty metadata, read back, matches
- `test_metadata_with_entries_roundtrip` — Add entries, write, read, verify
- `test_metadata_wrong_key_raises_auth_error` — Decrypt with wrong key fails
- `test_blob_roundtrip` — Write blob, read back, data matches
- `test_blob_wrong_key_raises_auth_error` — Decrypt blob with wrong key fails
- `test_append_preserves_existing_data` — Multiple appends don't corrupt earlier data
- `test_create_vault_empty_metadata_decryptable` — Fresh vault's metadata decrypts OK

**Fixtures to add to `conftest.py`:**
```python
@pytest.fixture
def tmp_vault(tmp_path, sample_passphrase):
    """Creates a fresh vault file for testing."""
    vault_path = tmp_path / "test.vlt"
    create_vault(str(vault_path), sample_passphrase)
    return vault_path

@pytest.fixture
def vault_key(sample_passphrase, tmp_vault):
    """Returns the derived key for the test vault."""
    header = read_header(str(tmp_vault))
    return derive_key(sample_passphrase, header.salt, header.kdf_params)
```

**Success Criteria:**
- [ ] `pytest tests/test_container.py` — all tests pass
- [ ] Can create a `.vlt` file from scratch
- [ ] Can read back header, metadata, and blobs
- [ ] Wrong passphrase fails at metadata decryption
- [ ] File survives multiple append operations without corruption
- [ ] Binary format is exactly as specified (verifiable with hex editor)

**Advanced Approach (Future Enhancement):**
Production vaults often use a *write-ahead log* (WAL) pattern for atomic updates, and
a `compact` command to reclaim space from deleted entries. V1's append-only approach is
the correct foundation — compaction is a natural V2 feature.

---

### Phase 3: Vault Core Logic (CRUD Operations)

**Goal:** Implement the business logic layer — adding, retrieving, listing, searching, and
deleting entries. After this phase, the vault is fully functional (minus CLI and sessions).

**What to Build:**

**`vault_core.py`** — The brain of the operation:

*Constructor / state:*
- `VaultManager` class:
  - `__init__(self, filepath: str, key: bytes)` — stores path and derived key
  - Loads metadata from container on instantiation
  - Holds metadata in memory as `VaultMetadata` object
  - All mutations update in-memory metadata AND write to disk

*Adding entries:*
- `add_password(self, name: str, username: str, password: str, email: str = None) -> VaultEntry`
  - Validates: name not empty, no duplicate name within type "password"
  - Creates `VaultEntry` with UUID, type="password", fields dict
  - Encrypts the secret fields as a JSON blob → appends to vault file
  - Updates metadata with new entry (including blob offset/length/nonce)
  - Writes new encrypted metadata block, updates header pointer
  - Returns the created entry

- `add_key(self, name: str, username: str, key_value: str) -> VaultEntry`
  - Same pattern as add_password but type="key", fields={username, key}

- `add_file(self, name: str, source_path: str) -> VaultEntry`
  - Validates source file exists and is readable
  - Reads file bytes
  - Encrypts raw bytes → appends blob
  - Stores original filename in metadata fields
  - Updates metadata
  - Returns entry

*Retrieving entries:*
- `get_entry(self, entry_type: str, name: str) -> VaultEntry`
  - Searches metadata for matching type + name (case-insensitive)
  - Skips tombstoned entries
  - Raises `VaultEntryNotFoundError` if not found

- `get_secret_field(self, entry_type: str, name: str, field: str) -> str`
  - Gets entry via `get_entry`
  - Reads and decrypts the blob
  - Deserialises JSON, extracts the requested field
  - Returns the field value as string (caller puts it on clipboard)
  - Validates that the requested field exists; raises error if not

- `get_file(self, name: str, output_path: str) -> None`
  - Gets entry via `get_entry` (type="file")
  - Reads and decrypts blob
  - Writes decrypted bytes to output_path
  - Validates output directory exists and is writable

*Listing and searching:*
- `list_entries(self, entry_type: str = None) -> list[VaultEntry]`
  - Returns all non-tombstoned entries
  - Optionally filtered by type
  - Sorted by name within each type

- `search(self, query: str, entry_type: str = None) -> list[VaultEntry]`
  - Case-insensitive substring search across:
    - Entry name
    - All values in entry fields dict
  - Optionally filtered by type
  - Returns matching non-tombstoned entries

*Deleting entries:*
- `remove_entry(self, entry_type: str, name: str) -> None`
  - Finds entry by type + name
  - Sets `deleted = True` (tombstone)
  - Writes new metadata block (blob data remains in file — reclaimed by V2 compact)
  - Raises `VaultEntryNotFoundError` if not found

**Implementation Notes:**
- The `VaultManager` is the central class that everything routes through. The CLI will
  create one when a session is active and delegate all operations to it.
- **Duplicate name handling:** Within a type, names must be unique. Across types, the same
  name is fine (you could have a password called "github" and a key called "github").
- **Search is simple substring matching** for V1. No fuzzy matching, no regex. Just
  `query.lower() in value.lower()` across names and field values. Good enough, and dead simple.
- All write operations follow the same pattern: mutate in memory → append blob (if needed) →
  write new metadata → update pointer. This is the append-only contract.
- Secret fields are stored as a JSON dict in the blob. For passwords:
  `{"username": "...", "email": "...", "password": "..."}`. For keys:
  `{"username": "...", "key": "..."}`.

**Testing This Phase (`tests/test_vault_core.py`):**

*Add operations:*
- `test_add_password_creates_entry` — Entry appears in list
- `test_add_password_fields_stored` — Username/email/password retrievable
- `test_add_password_duplicate_name_raises_error` — Can't add same name twice
- `test_add_key_creates_entry` — Key entry works same as password
- `test_add_file_stores_bytes` — File content survives add→get roundtrip
- `test_add_file_nonexistent_source_raises_error` — Bad path caught

*Get operations:*
- `test_get_secret_field_returns_correct_value` — Password field matches what was stored
- `test_get_secret_field_invalid_field_raises_error` — Asking for nonexistent field fails
- `test_get_entry_not_found_raises_error` — Missing entry produces correct error
- `test_get_file_writes_to_output` — Decrypted file matches original content
- `test_get_file_bad_output_path_raises_error` — Invalid output directory caught

*List and search:*
- `test_list_all_entries` — Returns all non-deleted entries
- `test_list_filtered_by_type` — Type filter works
- `test_list_excludes_tombstoned` — Deleted entries hidden
- `test_search_by_name` — Finds entry by name substring
- `test_search_by_field_value` — Finds entry by username/email match
- `test_search_case_insensitive` — "AWS" matches "aws"
- `test_search_no_results` — Non-matching query returns empty list
- `test_search_filtered_by_type` — Type filter + search combined

*Delete operations:*
- `test_remove_entry_tombstones` — Entry no longer in list/search after removal
- `test_remove_entry_not_found_raises_error` — Can't delete what doesn't exist
- `test_remove_then_get_raises_error` — Can't retrieve deleted entry

*Persistence:*
- `test_entries_persist_across_reopen` — Add entry, create new VaultManager from same file, entry exists
- `test_multiple_entries_persist` — Add several entries, reopen, all present

**Fixtures to add:**
```python
@pytest.fixture
def vault_manager(tmp_vault, vault_key):
    """Returns a VaultManager instance for the test vault."""
    return VaultManager(str(tmp_vault), vault_key)
```

**Success Criteria:**
- [ ] `pytest tests/test_vault_core.py` — all tests pass
- [ ] Full CRUD lifecycle works: add → list → get → search → remove
- [ ] Entries persist across VaultManager instances (simulating close/reopen)
- [ ] Tombstoned entries excluded from all queries
- [ ] Duplicate names rejected within same type
- [ ] All error cases produce correct custom exceptions

**Advanced Approach (Future Enhancement):**
A more sophisticated search could use an encrypted search index (like encrypted bloom
filters) for O(1) lookups instead of scanning all entries. For V1 with dozens or even
hundreds of entries, linear scan is perfectly fine.

---

### Phase 4: Session Management

**Goal:** Implement the session system — creating, validating, expiring, and destroying
sessions. After this phase, a user can `open` a vault once and run multiple commands
without re-entering their passphrase.

**What to Build:**

**`session.py`** — Session lifecycle:

*Session file format (JSON in `/tmp`):**
```json
{
    "vault_path": "/absolute/path/to/myvault.vlt",
    "key_material": "<hex-encoded derived key>",
    "timeout_seconds": 300,
    "last_activity": "2025-01-15T10:30:00Z",
    "created_at": "2025-01-15T10:25:00Z"
}
```

*Session file naming:*
- Path: `/tmp/vault_session_<hash>.json`
- The `<hash>` is derived from the vault file's absolute path (SHA-256 truncated to 16 hex chars)
- This means each vault has exactly one session file, and opening the same vault twice
  just overwrites the session

*Functions:*

- `create_session(vault_path: str, key: bytes, timeout_seconds: int) -> None`
  - Resolves vault_path to absolute path
  - Creates session JSON with current timestamp
  - Writes to `/tmp/vault_session_<hash>.json`
  - Sets file permissions to 0600 (`os.chmod`)
  - If session file already exists, overwrites it (re-opening refreshes session)

- `load_session(vault_path: str = None) -> dict`
  - If vault_path provided: look for that vault's session file
  - If not provided: look for *any* active session in /tmp (convenience for single-vault users)
  - Reads session JSON
  - Checks timeout: if `now - last_activity > timeout_seconds`, session is expired
    - Delete the expired session file
    - Raise `VaultLockedError`
  - If valid: update `last_activity` to now (resets idle timer), rewrite file
  - Return session data (including key material)

- `destroy_session(vault_path: str = None) -> None`
  - Finds session file
  - Deletes it
  - Best-effort: overwrite file content with zeros before deletion

- `get_session_path(vault_path: str) -> str`
  - Computes the session file path for a given vault
  - Pure function, no side effects

- `is_session_active(vault_path: str = None) -> bool`
  - Quick check: does a valid (non-expired) session exist?
  - Returns True/False without raising exceptions

**Implementation Notes:**
- **Why `/tmp`?** It's world-writable, cleared on reboot, and every Unix system has it.
  The 0600 permissions mean only your user can read the session file.
- **Key material in the session file:** Yes, the derived key is stored as hex in the JSON.
  This is the same trade-off `ssh-agent` makes — the key lives in memory/temp storage so
  you don't have to re-enter your passphrase for every operation. The timeout limits exposure.
- **Idle timeout logic:** Every successful `load_session()` call updates `last_activity`.
  This means any vault command that loads the session resets the timer. If you walk away
  for N minutes, the next command finds an expired session and forces re-auth.
- **Single-vault convenience:** When no vault path is given, `load_session()` scans `/tmp`
  for `vault_session_*.json` files. If exactly one exists and is valid, use it. If multiple
  exist, raise an error asking the user to specify which vault. This is a UX nicety.
- `os.chmod(path, 0o600)` — note the `0o` prefix for octal in Python 3.

**Testing This Phase (`tests/test_session.py`):**

- `test_create_session_writes_file` — Session file exists in /tmp after creation
- `test_create_session_permissions` — File has 0600 permissions (Unix only)
- `test_load_session_returns_key` — Can retrieve key material from session
- `test_load_session_updates_activity` — last_activity advances on each load
- `test_load_session_expired_raises_locked` — Session past timeout raises VaultLockedError
- `test_load_session_expired_deletes_file` — Expired session file is cleaned up
- `test_destroy_session_removes_file` — File gone after destroy
- `test_destroy_session_nonexistent_no_error` — Destroying nothing doesn't crash
- `test_session_path_deterministic` — Same vault path always gives same session path
- `test_session_different_vaults_different_paths` — Two vaults get distinct session files
- `test_is_session_active_true` — Fresh session reports active
- `test_is_session_active_false_expired` — Old session reports inactive
- `test_is_session_active_false_no_session` — No session file reports inactive
- `test_create_session_overwrites_existing` — Re-opening vault refreshes session

**Testing note:** For timeout tests, you'll want to either:
- Set a very short timeout (1 second) and `time.sleep(2)`, or
- Mock `datetime.now()` / `time.time()` to simulate time passing (cleaner, faster)

**Fixtures:**
```python
@pytest.fixture
def active_session(tmp_vault, vault_key):
    """Creates an active session for the test vault."""
    create_session(str(tmp_vault), vault_key, timeout_seconds=300)
    yield
    # Cleanup
    try:
        destroy_session(str(tmp_vault))
    except FileNotFoundError:
        pass
```

**Success Criteria:**
- [ ] `pytest tests/test_session.py` — all tests pass
- [ ] Session file created with correct permissions
- [ ] Session loads successfully within timeout window
- [ ] Session expires correctly after idle period
- [ ] Session destroy cleans up completely
- [ ] Multiple vaults get independent sessions

**Advanced Approach (Future Enhancement):**
A more secure session could use a Unix domain socket with a background daemon process
(like `ssh-agent`), keeping the key in a separate process's memory rather than a file.
The temp file approach is the standard "good enough" for V1 and is how many CLI tools work.

---

### Phase 5: Clipboard Abstraction

**Goal:** Build a cross-platform clipboard module that copies secrets and auto-clears them.
After this phase, the security-critical "clipboard only" requirement is satisfied.

**What to Build:**

**`clipboard.py`** — Platform-aware clipboard operations:

*Detection:*
- `detect_clipboard_backend() -> str`
  - Check platform (`sys.platform`) and environment variables
  - **Wayland (Linux):** Check for `WAYLAND_DISPLAY` env var → use `wl-copy` / `wl-paste`
  - **X11 (Linux):** Check for `DISPLAY` env var → use `xclip -selection clipboard`
  - **macOS:** `sys.platform == "darwin"` → use `pbcopy` / `pbpaste`
  - **Fallback:** Raise descriptive error with install instructions
  - Uses `shutil.which()` to verify the binary actually exists in PATH

*Operations:*
- `copy_to_clipboard(text: str) -> None`
  - Detects backend
  - Runs appropriate command via `subprocess.run()` with `input=text.encode()`
  - Raises clear error if command fails or binary not found
  - **Never** prints the secret — it goes straight to subprocess stdin

- `clear_clipboard() -> None`
  - Copies empty string to clipboard
  - Same backend detection

- `copy_with_clear(text: str, clear_after: int = 20) -> None`
  - Copies text to clipboard
  - Spawns a daemon thread (`threading.Timer`) that sleeps for `clear_after` seconds,
    then calls `clear_clipboard()`
  - The thread is daemonic so it won't prevent program exit
  - Prints: "Copied to clipboard (clears in {clear_after}s)."
  - **Edge case:** If the user has copied something else to clipboard in the meantime,
    we still clear it. This is the standard behaviour for password managers — security
    over convenience.

**Implementation Notes:**
- `subprocess.run(["wl-copy"], input=text.encode(), check=True)` — the `input` parameter
  feeds data to stdin, so the secret never appears in process arguments (visible in `ps`).
- For `xclip`, the command is `xclip -selection clipboard` (the `-selection clipboard` part
  is important — without it, xclip uses the PRIMARY selection, not the one Ctrl+V accesses).
- The daemon thread approach for auto-clear is simple but effective. The main process
  continues immediately; the thread sleeps in the background.
- `shutil.which("wl-copy")` returns the full path if found, `None` if not. Better than
  catching exceptions from subprocess.

**Testing This Phase (`tests/test_clipboard.py`):**

Clipboard testing is inherently environment-dependent. Strategy:

*Unit tests (always run, use mocks):*
- `test_detect_wayland` — Mock `WAYLAND_DISPLAY` env + `shutil.which`, verify "wl-copy" selected
- `test_detect_x11` — Mock `DISPLAY` env + `shutil.which`, verify "xclip" selected
- `test_detect_macos` — Mock `sys.platform` as "darwin" + `shutil.which`, verify "pbcopy"
- `test_detect_no_backend_raises_error` — No env vars, no binaries → clear error message
- `test_copy_calls_correct_command` — Mock subprocess.run, verify correct args and stdin
- `test_clear_calls_copy_empty` — Verify clear sends empty string

*Integration tests (marked, skip if no clipboard available):*
- `test_copy_paste_roundtrip` — Copy a string, paste it back, verify match
- `test_copy_with_clear_clears` — Copy, wait, verify clipboard is empty

```python
import pytest
import shutil

has_clipboard = shutil.which("wl-copy") or shutil.which("xclip") or shutil.which("pbcopy")

@pytest.mark.skipif(not has_clipboard, reason="No clipboard tool available")
class TestClipboardIntegration:
    ...
```

**Success Criteria:**
- [ ] `pytest tests/test_clipboard.py` — unit tests pass everywhere
- [ ] Integration tests pass on your Omarchy system
- [ ] Backend detection correctly identifies Wayland/X11/macOS
- [ ] Secrets never appear in process arguments
- [ ] Auto-clear works after specified delay
- [ ] Missing clipboard tool gives helpful error message

**Advanced Approach (Future Enhancement):**
Some password managers use platform-specific APIs (like macOS's `NSPasteboard` with
concealed type, or Wayland's `wl-copy --type text/plain --paste-once`) to make clipboard
contents invisible to other apps or auto-expire at the OS level. Worth exploring in V2.

---

### Phase 6: CLI Layer + Full Integration

**Goal:** Wire everything together with a polished argparse CLI. After this phase, the
tool is fully usable from the command line, end to end.

**What to Build:**

**`cli.py`** — Command routing and user interaction:

*Top-level parser:*
```
vault <command> [options]

commands:
  init      Create a new vault
  open      Unlock a vault (start session)
  close     Lock the vault (end session)
  status    Show session status
  list      List vault entries
  search    Search vault entries
  add       Add a new entry
  get       Retrieve an entry
  rm        Remove an entry
```

*Command implementations (each is a function called by the router):*

- `cmd_init(args)`:
  - Validate: path doesn't already exist (or prompt to overwrite)
  - Prompt passphrase with `getpass.getpass("Passphrase: ")`
  - Prompt confirmation: `getpass.getpass("Confirm passphrase: ")`
  - Validate they match
  - Call `container.create_vault()`
  - Print: "Vault created: {path}"

- `cmd_open(args)`:
  - Validate vault file exists
  - Read header
  - Prompt passphrase
  - Derive key, attempt to decrypt metadata (this validates the passphrase)
  - If success: create session with timeout
  - Print: "Vault unlocked. Session timeout: {timeout}."

- `cmd_close(args)`:
  - Destroy session
  - Print: "Vault locked."

- `cmd_status(args)`:
  - Check if session active
  - If yes: print vault path, time remaining, entry count
  - If no: print "No active session."

- `cmd_list(args)`:
  - Load session (raises VaultLockedError if expired)
  - Create VaultManager
  - Get entries (filtered by `--type` if provided)
  - Display grouped by type:
    ```
    Passwords
      github (user: matt@example.com)
      aws-root (user: admin)

    Keys
      deploy-key (user: deploy)

    Files
      id_ed25519
    ```
  - If `--json`: output as JSON array

- `cmd_search(args)`:
  - Load session
  - Search with query (and optional `--type` filter)
  - Display results in same format as list
  - If `--json`: JSON output

- `cmd_add(args)`:
  - Subcommands: `add password`, `add key`, `add file`
  - **add password:** parse name, --user, --email, prompt for password with getpass
  - **add key:** parse name, --user, prompt for key value with getpass
  - **add file:** parse source path, --name (optional, defaults to filename)
  - Load session, create VaultManager, call appropriate method
  - Print: "Added {type}: {name}"

- `cmd_get(args)`:
  - Subcommands: `get password`, `get key`, `get file`
  - **get password/key:** `--field` selects which field (default: password/key respectively)
    - `--clip` flag (default behaviour, but explicit is good)
    - `--clear` timeout in seconds (default: 20)
    - Call `clipboard.copy_with_clear()` with the field value
  - **get file:** `--out` required, specifies output path
    - Call `vault_core.get_file()`
    - Print warning: "⚠ File exported in plaintext: {path}"

- `cmd_rm(args)`:
  - Subcommands: `rm password`, `rm key`, `rm file`
  - Load session, remove entry
  - Print: "Removed: {name}"

*Error handling wrapper:*
- Main entry point wraps all commands in try/except
- Catches `VaultError` subclasses → prints message → exits with mapped code
- Catches `KeyboardInterrupt` → prints nothing, exits cleanly
- Catches unexpected exceptions → prints "Unexpected error" (no traceback), exits 1

**`main.py`** — Entry point:
```python
from vault.cli import main

if __name__ == "__main__":
    main()
```

**Implementation Notes:**
- argparse with nested subparsers: `vault add password` needs a subparser within a subparser.
  This is done by adding subparsers to the `add` subparser. It looks like:
  ```python
  add_parser = subparsers.add_parser("add")
  add_sub = add_parser.add_subparsers(dest="add_type")
  add_password = add_sub.add_parser("password")
  add_password.add_argument("name")
  add_password.add_argument("--user", required=True)
  # etc.
  ```
- `getpass.getpass()` suppresses terminal echo — critical for passphrase entry.
- The `--clear` argument: parse duration strings like "20s", "1m", "90" (default seconds).
  Keep it simple — just accept an integer for seconds in V1.
- Exit codes should be consistent. Map them in `errors.py` and use them in the CLI wrapper.
- **No `--verbose` flag in V1.** Keep output clean and minimal. Debug logging is a V2 feature.

**Testing This Phase (`tests/test_cli.py`):**

These are **integration tests** that invoke the CLI as a subprocess, simulating real usage:

```python
import subprocess

def run_vault(*args, input_text=None):
    """Helper to run vault commands and capture output."""
    result = subprocess.run(
        ["python", "main.py"] + list(args),
        capture_output=True, text=True, input=input_text
    )
    return result
```

*Init tests:*
- `test_cli_init_creates_vault` — `vault init test.vlt` → file exists, exit code 0
- `test_cli_init_existing_path_warns` — Existing file produces appropriate response
- `test_cli_init_mismatched_passphrase` — Different confirmations rejected

*Session tests:*
- `test_cli_open_close_cycle` — open → status shows active → close → status shows inactive
- `test_cli_command_without_session_fails` — `vault list` without open → exit code 3
- `test_cli_wrong_passphrase` — Bad passphrase → exit code 5

*CRUD tests:*
- `test_cli_add_list_cycle` — Add password, list shows it
- `test_cli_add_get_password` — Add password, get it (verify clipboard via mock or paste)
- `test_cli_add_get_file` — Add file, export it, compare contents
- `test_cli_rm_removes_entry` — Add, remove, list no longer shows it
- `test_cli_search_finds_entry` — Add entries, search finds correct ones

*Error handling tests:*
- `test_cli_get_nonexistent_entry` — Exit code 2
- `test_cli_help_text` — `vault --help` produces useful output
- `test_cli_invalid_command` — Nonsense command produces error

*JSON output tests:*
- `test_cli_list_json_output` — `--json` flag produces valid JSON
- `test_cli_search_json_output` — JSON output from search

**Success Criteria:**
- [ ] `pytest tests/test_cli.py` — all integration tests pass
- [ ] Full user workflow works end-to-end:
  `init → open → add password → add file → list → search → get → rm → close`
- [ ] All error cases produce correct exit codes
- [ ] Help text is clear and complete for all commands
- [ ] `--json` output is valid, parseable JSON
- [ ] Passphrase entry uses getpass (no echo)
- [ ] Secrets never appear in stdout (clipboard only)

**Advanced Approach (Future Enhancement):**
For a more polished CLI, consider `click` or `typer` libraries — they handle nested commands,
type validation, and help generation more elegantly than argparse. Sticking with argparse
for V1 keeps dependencies minimal and reinforces your stdlib knowledge from Locksmith.

---

### Phase 7: Security Hardening + Edge Cases

**Goal:** Harden the tool against real-world edge cases and adversarial conditions. This is
the "make it robust" phase — after this, the tool handles the ugly stuff gracefully.

**What to Build:**

**Security hardening:**

- **Passphrase strength feedback** (non-blocking, informational only):
  - After passphrase entry on `init`, display a simple strength indicator
  - Check: length ≥ 12, has mixed case, has numbers, has symbols
  - Output like: "Passphrase strength: moderate (consider adding symbols)"
  - **Never reject** a passphrase — user knows best, we just inform

- **Session file hardening:**
  - Verify permissions on load (warn if not 0600)
  - Validate JSON structure on load (handle corrupt session files gracefully)
  - Atomic write: write to temp file, set perms, rename into place

- **Vault file integrity:**
  - Validate header checksum (add a simple CRC32 of the header fields)
  - Handle truncated files gracefully
  - Handle zero-length files
  - Handle files that start with TVLT but are otherwise garbage

- **Memory cleanup (best-effort):**
  - After operations complete, `del` sensitive variables and call `gc.collect()`
  - Document that Python doesn't guarantee memory zeroing (honest limitation)

- **Race condition protection:**
  - File locking via `fcntl.flock()` on the vault file during writes
  - Prevents corruption if two sessions somehow operate on the same vault
  - Handle `OSError` from flock gracefully

**Edge case handling:**

- Empty vault (no entries): `list` and `search` should work, not crash
- Entry name with special characters (spaces, unicode, quotes)
- Very long entry names (truncate display, not storage)
- Large files (>10MB): warn on add, but allow it
- Vault file on read-only filesystem: clear error on write operations
- Disk full during write: handle `OSError`, don't corrupt vault
- `KeyboardInterrupt` during any operation: clean exit, no partial state

**Testing This Phase (`tests/test_security.py`):**

- `test_tampered_header_detected` — Modify header bytes, verify detection
- `test_tampered_metadata_detected` — Modify encrypted metadata, verify AEAD failure
- `test_tampered_blob_detected` — Modify encrypted blob, verify AEAD failure
- `test_corrupt_session_file_handled` — Garbage in session file → clean error
- `test_session_wrong_permissions_warns` — Session file with 0644 produces warning
- `test_empty_vault_list_search` — No crash on empty vault
- `test_special_chars_in_name` — Unicode, spaces, quotes all work
- `test_large_file_handling` — 10MB file encrypts and decrypts correctly
- `test_concurrent_write_protection` — File lock prevents dual-write corruption
- `test_keyboard_interrupt_clean` — Ctrl+C during operation doesn't corrupt vault
- `test_disk_full_simulation` — Write failure doesn't corrupt existing data
- `test_passphrase_strength_feedback` — Strength check returns appropriate levels

**Success Criteria:**
- [ ] `pytest tests/test_security.py` — all tests pass
- [ ] Full test suite still passes (`pytest` across all test files)
- [ ] Tool handles every edge case without crashing
- [ ] Tamper detection works for header, metadata, and blobs
- [ ] File locking prevents concurrent corruption
- [ ] Clean shutdown on Ctrl+C at any point

**Advanced Approach (Future Enhancement):**
Production tools use memory-locked pages (`mlock`) to prevent sensitive data from being
swapped to disk, and `madvise(MADV_DONTDUMP)` to exclude it from core dumps. Python
can access these via `ctypes`, but it's fiddly. For V1, best-effort cleanup is honest and
appropriate.

---

### Phase 8: Documentation + Polish

**Goal:** Professional-grade documentation and final UX polish. After this phase, the
project is GitHub-ready.

**What to Build:**

**`README.md`** — Complete project documentation:

- Project title, one-line description, and a brief "what is this?"
- **Security notice:** "This is a learning project. For production credential management,
  use established tools like Bitwarden, 1Password, or KeePassXC."
- **Features list** (what V1 does)
- **Installation:**
  - Clone repo
  - `pip install -r requirements.txt`
  - Platform-specific clipboard tool (`wl-copy`, `xclip`, or `pbcopy`)
- **Quick start:** init → open → add → get → close (with actual commands)
- **Full command reference** (every command with flags and examples)
- **File format documentation** (brief description of .vlt structure)
- **Security model** (what's protected, what's not, honest limitations)
- **Architecture overview** (brief module descriptions)
- **Testing:** how to run the test suite
- **Comparison with Locksmith** (what changed and why — great for portfolio)
- **Future enhancements** (V2 ideas)
- **License** (pick one — MIT is fine for a learning project)

**Code documentation:**
- Docstrings for every public function and class (Google style)
- Module-level docstrings explaining each file's purpose
- Inline comments for non-obvious logic (especially crypto operations)
- Type hints on all function signatures

**CLI polish:**
- Consistent message formatting across all commands
- Colour output (optional, use `\033[` ANSI codes or keep plain for simplicity)
- `--version` flag
- Helpful error messages that suggest the correct command

**Final test sweep:**
- Run full suite: `pytest -v`
- Check coverage: `pytest --cov=vault --cov-report=term-missing`
- Aim for >80% coverage (realistic for a V1)
- Fix any failing or flaky tests

**Success Criteria:**
- [ ] README.md is comprehensive and well-formatted
- [ ] All public functions have docstrings
- [ ] All functions have type hints
- [ ] `pytest -v` passes all tests
- [ ] Coverage >80%
- [ ] Tool feels polished and professional from the user's perspective
- [ ] `.gitignore` covers all generated files
- [ ] `requirements.txt` is accurate and pinned

---

## 5. Testing Strategy Summary

### Framework: pytest

**Why pytest over unittest:** Less boilerplate, better fixtures, better output, more
Pythonic. Industry standard for Python testing.

### Test Categories

| Category | Location | What it covers | Run with |
|----------|----------|---------------|----------|
| Crypto unit | `test_crypto.py` | KDF, encrypt/decrypt | `pytest tests/test_crypto.py` |
| Container unit | `test_container.py` | File format I/O | `pytest tests/test_container.py` |
| Vault logic | `test_vault_core.py` | CRUD operations | `pytest tests/test_vault_core.py` |
| Session unit | `test_session.py` | Session lifecycle | `pytest tests/test_session.py` |
| Clipboard unit | `test_clipboard.py` | Backend detection | `pytest tests/test_clipboard.py` |
| CLI integration | `test_cli.py` | End-to-end commands | `pytest tests/test_cli.py` |
| Security | `test_security.py` | Hardening, tamper | `pytest tests/test_security.py` |

### Shared Fixtures (`conftest.py`)

Key fixtures that most tests will use:
- `sample_passphrase` — deterministic test passphrase
- `sample_salt` — random test salt
- `derived_key` — key derived from above
- `tmp_vault` — fresh vault file in temp directory
- `vault_key` — derived key for the test vault
- `vault_manager` — VaultManager instance ready to use
- `active_session` — session created for test vault

### Running Tests

```bash
# All tests
pytest -v

# Single module
pytest tests/test_crypto.py -v

# With coverage
pytest --cov=vault --cov-report=term-missing

# Just the fast unit tests (skip clipboard integration)
pytest -v -m "not integration"
```

### Test Principles

- **Each test tests one thing.** Name says what it verifies.
- **Tests don't depend on each other.** Each gets fresh fixtures.
- **Crypto tests are deterministic.** Fixed salts + passphrases = reproducible keys.
- **Integration tests use subprocess.** They test the actual CLI, not internal functions.
- **Mock external dependencies.** Clipboard commands, time functions — mock them in unit tests.

---

## 6. Documentation Requirements

### README.md (Detailed in Phase 8)

The README is part of the deliverable. Key sections:
- What it is and why it exists
- Honest security disclaimer
- Installation and platform requirements
- Complete command reference with examples
- Architecture overview
- How to run tests
- What's different from Locksmith (portfolio value)

### Code Documentation Standards

**Every module:** Top-level docstring explaining its role:
```python
"""
crypto.py — Cryptographic operations for The Vault.

Handles password-based key derivation (Argon2id) and authenticated
encryption/decryption (AES-256-GCM). All other modules call into
this one for cryptographic operations — crypto logic never leaks
into other layers.
"""
```

**Every public function:** Google-style docstring:
```python
def derive_key(passphrase: str, salt: bytes, params: KDFParams) -> bytes:
    """Derive a 256-bit encryption key from a passphrase using Argon2id.

    Args:
        passphrase: The user's passphrase (UTF-8 string).
        salt: Random salt bytes (16 bytes, generated at vault creation).
        params: KDF parameters (time_cost, memory_cost, parallelism).

    Returns:
        32 bytes of derived key material suitable for AES-256-GCM.

    Raises:
        VaultAuthError: If key derivation fails unexpectedly.
    """
```

**Type hints everywhere:**
```python
def search(self, query: str, entry_type: str | None = None) -> list[VaultEntry]:
```

---

## 7. Future Enhancements (V2+)

These are documented but **explicitly out of scope** for V1:

- **`vault compact`** — Rewrite vault file, removing tombstoned entries and orphaned blobs
- **Two-tier key system** — Master key wraps a data encryption key; change passphrase without re-encrypting data
- **Keyfile support** — Optional second factor (passphrase + keyfile)
- **`vault rename`** — Rename entries
- **`vault edit`** — Modify existing entries (update password, etc.)
- **Tags and notes** — Categorise and annotate entries
- **`vault export/import`** — Bulk operations (encrypted export format)
- **Fuzzy search** — Approximate matching for search queries
- **`vault generate`** — Built-in secure password generator
- **Logging** — Optional verbose/debug mode
- **Shell completion** — Tab completion for bash/zsh/fish
- **Config file** — Per-vault or global settings (default timeout, etc.)
- **Memory locking** — `mlock()` for sensitive data pages
- **Backup/versioning** — Keep N previous metadata snapshots

### Learning Opportunities

Each V2 feature teaches something valuable:
- **Compact** → understanding file defragmentation and rewriting binary formats
- **Two-tier keys** → key wrapping, a pattern used in disk encryption and cloud KMS
- **Keyfile** → multi-factor authentication design
- **Password generator** → CSPRNG usage and entropy calculation
- **Shell completion** → how CLI tools integrate with shell environments
- **Memory locking** → OS-level security primitives via ctypes/cffi

---

## Build Order Summary

| Phase | Module(s) | Tests | Key Milestone |
|-------|-----------|-------|---------------|
| 1 | `crypto.py`, `models.py`, `errors.py`, `constants.py` | `test_crypto.py` | Encrypt/decrypt works |
| 2 | `container.py`, expand `models.py` | `test_container.py` | Can create and read `.vlt` files |
| 3 | `vault_core.py` | `test_vault_core.py` | Full CRUD on entries |
| 4 | `session.py` | `test_session.py` | Open/close/timeout sessions |
| 5 | `clipboard.py` | `test_clipboard.py` | Cross-platform clipboard |
| 6 | `cli.py`, `main.py` | `test_cli.py` | Fully usable CLI tool |
| 7 | Hardening across all modules | `test_security.py` | Handles edge cases + tamper |
| 8 | `README.md`, docstrings, polish | Coverage check | GitHub-ready |

**Critical rule:** Each phase MUST have its tests passing before moving to the next.
No building on shaky foundations.
