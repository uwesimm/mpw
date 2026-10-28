# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-10-28
- **Breaking:** length/counter prefixes are now written as raw big-endian bytes,
  matching the reference implementations. Previously `String::from_utf8_lossy`
  corrupted any byte ≥ 0x80, so passwords for counters ≥ 128 and for
  names/contexts of ≥ 128 UTF-8 bytes did not match official Master Password
  clients.
- **Breaking:** `generate_password` rejects empty master password, user or
  site name, and a counter below 1, per the algorithm specification.
- `PasswordBuilder` now defaults to counter 1, usage `a`, template `x`
  (previously counter 0, which is invalid).
- Added `is_valid_usage` / `is_valid_template` helpers for request validation.
- scrypt errors are propagated instead of silently ignored.
- Added reference test vectors pinned against an independent implementation,
  including the official self-test vector (`ZedaFaxcZaso9*`).

## [0.1.0] - 2026-03-29
- Initial release of **masterpassword‑rs**.
- Implemented deterministic Master Password algorithm.
- Added `PasswordBuilder` ergonomic API.
- Refactored static data into `templates.rs`.
- Added extensive test suite (13 tests).
- Removed debug logging of secret material.
- Added README with usage example and security notes.
