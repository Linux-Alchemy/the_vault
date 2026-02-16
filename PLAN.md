# The Vault — Build Plan

## Context

This plan covers the full build of "The Vault" — a CLI-based encrypted vault tool that manages a single-file encrypted container (`.vlt`). It evolves every concept from the predecessor project "The Locksmith": proper KDF-based key derivation replaces raw key files, AEAD encryption replaces Fernet, a binary container format replaces loose files, and session management replaces per-command key entry.

The plan is structured for **pair-programming** between the learner (Driver) and Obie-Wan (Navigator). The Driver writes security-critical and core logic code. Obie-Wan scaffolds boilerplate, creates test skeletons, and guides architectural decisions.

**Legend:**
- **DRIVER** — The learner writes this code (learning moments)
- **NAVIGATOR** — Obie-Wan scaffolds this (boilerplate, structure)
- **DISCUSS** — Concept to understand before coding

---

## Phase 0: Project Setup & Dependencies

**Goal:** Wire up dependencies and package structure. Zero logic.

### Tasks

1. **Update `pyproject.toml`** (NAVIGATOR) — Add runtime deps:
   ```toml
   dependencies = [
       "cryptography>=42.0.0",
       "argon2-cffi>=23.1.0",
   ]
   ```
   Then `uv sync`.

2. **Create directory structure** (NAVIGATOR):
   ```
   vault/__init__.py     (empty)
   tests/__init__.py     (empty)
   main.py               (prints "The Vault v0.1")
   ```

3. **Update `.gitignore`** (NAVIGATOR) — Add `*.vlt`

### Checkpoint
```bash
uv run python main.py                    # prints version
uv run pytest                             # 0 tests, clean exit
uv run python -c "import argon2; print(argon2.__version__)"
uv run python -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('OK')"
```

---

## Phase 1: Crypto Foundation

**Goal:** Working Argon2id key derivation and AES-256-GCM encrypt/decrypt.

### DISCUSS before coding
- Why Argon2id over PBKDF2/bcrypt (memory-hard, GPU/ASIC resistant)
- What salts and nonces do, why nonce reuse breaks AES-GCM
- AEAD: confidentiality AND integrity in one operation

### Files to Create

| File | Who | What |
|------|-----|------|
| `vault/constants.py` | NAVIGATOR | Magic values: `MAGIC_BYTES`, `FORMAT_VERSION`, KDF defaults, exit codes |
| `vault/errors.py` | NAVIGATOR | Exception hierarchy: `VaultError` -> `VaultCorruptError`, `VaultLockedError`, `VaultAuthError`, `VaultEntryNotFoundError` (each with `.exit_code`) |
| `vault/models.py` | NAVIGATOR | `KDFParams` dataclass (time_cost, memory_cost, parallelism) |
| `vault/crypto.py` | **DRIVER** | `generate_salt()`, `derive_key()`, `encrypt()`, `decrypt()` |
| `tests/conftest.py` | NAVIGATOR | Fixtures: `sample_passphrase`, `sample_salt`, `fast_kdf_params`, `derived_key` |
| `tests/test_crypto.py` | NAVIGATOR scaffolds, **DRIVER** fills assertions | 11 tests |

### Key implementation details for `crypto.py`
- `derive_key(passphrase, salt, params)` -> uses `argon2.low_level.hash_secret_raw()` with `Type.ID`, returns 32 bytes
- `encrypt(data, key)` -> `AESGCM(key)`, random 12-byte nonce, returns `(nonce, ciphertext)`
- `decrypt(ciphertext, key, nonce)` -> `AESGCM(key)`, wraps `InvalidTag` into `VaultAuthError`
- Use reduced KDF params in tests (`time_cost=1, memory_cost=8192`) for speed

### Tests (11)
`test_derive_key_produces_32_bytes`, `test_derive_key_deterministic`, `test_derive_key_different_salt`, `test_derive_key_different_passphrase`, `test_encrypt_decrypt_roundtrip`, `test_encrypt_produces_different_output_each_time`, `test_decrypt_wrong_key_raises_auth_error`, `test_decrypt_tampered_ciphertext_raises_auth_error`, `test_decrypt_wrong_nonce_raises_auth_error`, `test_generate_salt_length`, `test_generate_salt_unique`

### Checkpoint
```bash
uv run pytest tests/test_crypto.py -v    # all 11 green
```

---

## Phase 2: Binary Container Format

**Goal:** Implement the `.vlt` file format — headers, encrypted metadata, encrypted blobs.

### DISCUSS before coding
- `struct` module for binary packing/unpacking (try in REPL first)
- Big-endian (`>`) convention for binary formats
- Append-only pattern: crash-safe, old pointer always valid

### Files to Create/Modify

| File | Who | What |
|------|-----|------|
| `vault/models.py` (expand) | NAVIGATOR | Add `VaultHeader`, `VaultEntry`, `VaultMetadata` dataclasses with `to_dict()`/`from_dict()` |
| `vault/container.py` | **DRIVER** (NAVIGATOR provides format string + signatures) | All I/O functions |
| `tests/conftest.py` (expand) | NAVIGATOR | Add `tmp_vault`, `vault_key` fixtures |
| `tests/test_container.py` | NAVIGATOR scaffolds, **DRIVER** fills | 12 tests |

### Header format (42 bytes, big-endian)
```
Offset  Size  Field              struct format
0       4     Magic "TVLT"       4s
4       2     Version            H
6       4     time_cost          I
10      4     memory_cost        I
14      4     parallelism        I
18      16    Salt               16s
34      8     metadata_offset    Q
```
Format string: `'>4sHIII16sQ'`

### container.py functions (DRIVER writes all)
- `write_header(filepath, header)` — `struct.pack`, write at offset 0
- `read_header(filepath)` — `struct.unpack`, validate magic + version
- `update_metadata_offset(filepath, offset)` — seek to byte 34, write uint64
- `write_metadata(filepath, metadata, key)` — JSON -> encrypt -> append `[nonce][length][ciphertext]`
- `read_metadata(filepath, key)` — read from offset, decrypt, deserialise
- `append_blob(filepath, data, key)` — encrypt -> append `[nonce][ciphertext]`, return `(offset, length, nonce)`
- `read_blob(filepath, offset, length, nonce, key)` — seek, read, decrypt
- `create_vault(filepath, passphrase, kdf_params=None)` — orchestrates full vault creation

### Tests (12)
`test_create_vault_produces_file`, `test_header_roundtrip`, `test_header_magic_bytes_correct`, `test_header_invalid_magic_raises_corrupt`, `test_header_unsupported_version_raises_corrupt`, `test_metadata_roundtrip`, `test_metadata_with_entries_roundtrip`, `test_metadata_wrong_key_raises_auth_error`, `test_blob_roundtrip`, `test_blob_wrong_key_raises_auth_error`, `test_append_preserves_existing_data`, `test_create_vault_empty_metadata_decryptable`

### Checkpoint
```bash
uv run pytest tests/test_crypto.py tests/test_container.py -v    # all green
```

---

## Phase 3: Vault Core Logic (CRUD)

**Goal:** `VaultManager` class with full add/get/list/search/remove.

### DISCUSS before coding
- Separation: container.py knows bytes, VaultManager knows passwords/keys/files
- Tombstone deletion: mark deleted, data stays in file (future `compact` command)
- Write pattern: mutate memory -> append blob -> write metadata -> update pointer

### Files to Create

| File | Who | What |
|------|-----|------|
| `vault/vault_core.py` | **DRIVER** | Full `VaultManager` class |
| `tests/conftest.py` (expand) | NAVIGATOR | Add `vault_manager` fixture |
| `tests/test_vault_core.py` | NAVIGATOR scaffolds, **DRIVER** fills | 22 tests |

### VaultManager methods (all DRIVER)
- `__init__(filepath, key)` — load metadata
- `add_password(name, username, password, email=None)` -> encrypt fields as JSON blob, append, update metadata
- `add_key(name, username, key_value)` -> same pattern
- `add_file(name, source_path)` -> read file bytes, encrypt, store original filename
- `get_entry(entry_type, name)` -> linear scan, case-insensitive, skip tombstoned
- `get_secret_field(entry_type, name, field)` -> decrypt blob, parse JSON, extract field
- `get_file(name, output_path)` -> decrypt blob, write to file
- `list_entries(entry_type=None)` -> filter, sort by name
- `search(query, entry_type=None)` -> substring match on name + field values
- `remove_entry(entry_type, name)` -> set `deleted=True`, write new metadata

### Tests (22): Add(6), Get(5), List/Search(7), Delete(3), Persistence(2)

### Checkpoint
```bash
uv run pytest tests/test_crypto.py tests/test_container.py tests/test_vault_core.py -v
```

---

## Phase 4: Session Management

**Goal:** Unlock once, work until timeout. Key cached in `/tmp` with 0600 permissions.

### DISCUSS before coding
- The ssh-agent trade-off: key on disk vs re-entering passphrase every time
- Idle timeout: timer resets on each operation

### Files to Create

| File | Who | What |
|------|-----|------|
| `vault/session.py` | **DRIVER** | All session functions (security-critical) |
| `tests/conftest.py` (expand) | NAVIGATOR | Add `active_session` fixture |
| `tests/test_session.py` | NAVIGATOR scaffolds, **DRIVER** fills | 14 tests |

### session.py functions (all DRIVER)
- `get_session_path(vault_path)` -> SHA-256 hash of absolute path, `/tmp/vault_session_{hash[:16]}.json`
- `create_session(vault_path, key, timeout_seconds)` -> write JSON, `os.chmod(0o600)`
- `load_session(vault_path=None)` -> read, check timeout, update activity, return data
- `destroy_session(vault_path=None)` -> overwrite with zeros, delete
- `is_session_active(vault_path=None)` -> try load, return bool

### Tests (14)
Includes permission checks, timeout expiry, deterministic paths, overwrite on re-open.

### Checkpoint
```bash
uv run pytest tests/test_crypto.py tests/test_container.py tests/test_vault_core.py tests/test_session.py -v
```

---

## Phase 5: Clipboard Abstraction

**Goal:** Cross-platform clipboard copy with auto-clear. Secrets never touch stdout.

### Files to Create

| File | Who | What |
|------|-----|------|
| `vault/clipboard.py` | **DRIVER** | Detection, copy, clear, timed clear |
| `tests/test_clipboard.py` | NAVIGATOR scaffolds, **DRIVER** fills | 6 unit + 2 integration tests |

### clipboard.py functions (all DRIVER)
- `detect_clipboard_backend()` -> check `WAYLAND_DISPLAY`/`DISPLAY`/`sys.platform`, verify with `shutil.which()`
- `copy_to_clipboard(text)` -> `subprocess.run(cmd, input=text.encode(), check=True)` (secret in stdin, not argv)
- `clear_clipboard()` -> copy empty string
- `copy_with_clear(text, clear_after=20)` -> copy + `threading.Timer` daemon thread

### Checkpoint
```bash
uv run pytest tests/test_clipboard.py -v
```

---

## Phase 6: CLI Layer + Full Integration

**Goal:** Wire everything with argparse. Fully usable end-to-end.

### Files to Create/Modify

| File | Who | What |
|------|-----|------|
| `vault/cli.py` argparse setup | NAVIGATOR | All subparser boilerplate |
| `vault/cli.py` command handlers | **DRIVER** | `cmd_init`, `cmd_open`, `cmd_close`, `cmd_status`, `cmd_list`, `cmd_search`, `cmd_add`, `cmd_get`, `cmd_rm` |
| `main.py` (update) | NAVIGATOR | Import and call `main()` |
| `tests/test_cli.py` | NAVIGATOR scaffolds, **DRIVER** fills | 14 tests |

### CLI commands
```
vault init <path>
vault open <path> [--timeout N]
vault close [path]
vault status [path]
vault list [--type TYPE] [--json]
vault search <query> [--type TYPE] [--json]
vault add password <name> --user USER [--email EMAIL]
vault add key <name> --user USER
vault add file <path> [--name NAME]
vault get password <name> [--field FIELD] [--clear N]
vault get key <name> [--field FIELD] [--clear N]
vault get file <name> --out PATH
vault rm password|key|file <name>
```

### Error boundary in `main()`
- Catch `VaultError` -> print message -> exit with mapped code
- Catch `KeyboardInterrupt` -> silent clean exit
- Catch `Exception` -> "Unexpected error" (no traceback) -> exit 1

### Checkpoint
```bash
uv run pytest -v                         # ALL tests across ALL files green
# Manual end-to-end:
uv run python main.py init test.vlt
uv run python main.py open test.vlt
uv run python main.py add password github --user octocat
uv run python main.py list
uv run python main.py get password github
uv run python main.py rm password github
uv run python main.py close
```

---

## Phase 7: Security Hardening + Edge Cases

**Goal:** Handle tamper detection, corrupt files, concurrent access, edge-case inputs.

### Changes across the codebase (all DRIVER)

1. **Passphrase strength feedback** — informational check on `init` (length, mixed case, numbers, symbols). Never reject.
2. **Session hardening** — verify permissions on load, validate JSON structure, atomic writes (temp file -> chmod -> rename)
3. **Vault file integrity** — handle truncated files, zero-length files, garbage after magic bytes
4. **File locking** — `fcntl.flock()` during writes, context manager pattern
5. **Edge cases** — empty vault list/search, unicode names, large files (>10MB warn), read-only FS, `KeyboardInterrupt` cleanup

### Tests (12 in `tests/test_security.py`)
`test_tampered_header_detected`, `test_tampered_metadata_detected`, `test_tampered_blob_detected`, `test_corrupt_session_file_handled`, `test_session_wrong_permissions_warns`, `test_empty_vault_list_search`, `test_special_chars_in_name`, `test_large_file_handling`, `test_concurrent_write_protection`, `test_keyboard_interrupt_clean`, `test_disk_full_simulation`, `test_passphrase_strength_feedback`

### Checkpoint
```bash
uv run pytest -v                         # full suite green
```

---

## Phase 8: Documentation + Polish

**Goal:** GitHub-ready. Professional documentation, full test coverage.

### Tasks

1. **`README.md`** (DRIVER writes) — project description, security disclaimer, install, quick start, command reference, security model, architecture, testing, comparison with Locksmith, V2 ideas
2. **Docstrings** (BOTH) — module-level docstrings, Google-style function docstrings, type hints everywhere
3. **CLI polish** (NAVIGATOR) — `--version` flag, consistent formatting, complete help text
4. **Test coverage** (BOTH) — add `pytest-cov` to dev deps, target >80%
5. **Lint** (BOTH) — `uv run ruff check vault/` clean

### Checkpoint
```bash
uv run pytest -v                                        # all green
uv run pytest --cov=vault --cov-report=term-missing     # >80%
uv run ruff check vault/                                # clean
```

---

## Driver vs Navigator Summary

| Task | Who | Why |
|------|-----|-----|
| Project structure, deps, `.gitignore` | Navigator | Pure boilerplate |
| `constants.py`, `errors.py`, `models.py` | Navigator | Definitions, discuss serialisation |
| `crypto.py` (all functions) | **Driver** | Core cryptographic learning |
| `container.py` (all I/O) | **Driver** | Binary format + file I/O |
| `vault_core.py` (VaultManager) | **Driver** | Business logic + design patterns |
| `session.py` (all functions) | **Driver** | Security-critical session mgmt |
| `clipboard.py` (all functions) | **Driver** | Platform detection, subprocess, threads |
| `cli.py` argparse boilerplate | Navigator | Verbose, no learning value |
| `cli.py` command handlers | **Driver** | Wiring layers together |
| Test scaffolding (signatures) | Navigator | Structure boilerplate |
| Test assertions + logic | **Driver** | Understanding what to verify |
| `README.md` | **Driver** | Technical writing practice |

---

## Critical Files

- `vault/crypto.py` — Argon2id KDF + AES-256-GCM (security foundation)
- `vault/container.py` — Binary .vlt format I/O (data persistence)
- `vault/vault_core.py` — VaultManager CRUD (central orchestration)
- `vault/session.py` — Session lifecycle (key caching with timeout)
- `vault/cli.py` — argparse CLI (user-facing surface)
- `vault/models.py` — All dataclasses (VaultHeader, VaultEntry, VaultMetadata, KDFParams)
- `vault/errors.py` — Exception hierarchy with exit codes
- `vault/constants.py` — Magic values and defaults

## Verification

After each phase, run `uv run pytest -v` on all test files completed so far. After Phase 8, the full verification is:

```bash
uv run pytest -v                                        # all tests pass
uv run pytest --cov=vault --cov-report=term-missing     # >80% coverage
uv run ruff check vault/                                # lint clean
# Manual end-to-end workflow test
uv run python main.py init myvault.vlt
uv run python main.py open myvault.vlt
uv run python main.py add password github --user octocat
uv run python main.py add file ~/.ssh/id_ed25519 --name my-ssh-key
uv run python main.py list
uv run python main.py search github
uv run python main.py get password github
uv run python main.py get file my-ssh-key --out /tmp/exported_key
uv run python main.py rm password github
uv run python main.py close
uv run python main.py status                             # "No active session"
```
