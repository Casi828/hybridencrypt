# Changelog & Development History

A consolidated record of the project's security hardening, architectural decisions,
and resolved audit findings. The system reached its **Level 4 maturity milestone —
a hardened research prototype (616 tests passing)** on 2026-04-28. It has not undergone
a formal external security review; see "Level 5 Architecture Gaps" below.

> Consolidated from the project's original two-part working log. Entries are kept
> where they document a meaningful technical decision, milestone, security fix, or
> research change; routine planning notes have been omitted.

---

## Maturity Timeline

| Date | Milestone | Tests |
|------|-----------|-------|
| 2026-04-16 | Project 1 complete — 9 original issues resolved | 76 |
| 2026-04-18 | Container V4 + body signature; key_id gates; error sanitization | 256 |
| 2026-04-21 | Sign/verify exit codes, key_id identity, audit coverage | 256 |
| 2026-04-23 | Audit rotation chain continuity; independent KeyRegistry removed | 256 |
| 2026-04-24 | User authentication system (Argon2id, HMAC user store) | 282 |
| 2026-04-25 | Unified exec path; full user lifecycle; classification binding (V4) | 414 |
| 2026-04-26 | Safe workspace; classified output paths; auditor read-only tools | 502 |
| 2026-04-27 | Security Audit #1 — blockers A1–A7 resolved (Batches 1–4) | 512 |
| 2026-04-27 | Adversarial Audit #2 — findings resolved (Batches 5–6) | 585 |
| 2026-04-28 | **Level 4 reached** — relocation-attack tests, audit-integrity fixes | 591 |
| 2026-04-28 | Batch P0 — forward audit-chain verification; auth-bypass aliases removed | 593 |
| 2026-04-28 | Batch P1 — failed-login auditing; encryption-key fingerprints | 601 |
| 2026-04-28 | Batch P2 — pipeline decrypt made internal/admin-only; dead params removed | 605 |
| 2026-04-28 | Batch P3 — documentation corrections | 605 |
| 2026-04-28 | Batch P4 — audit-repair admin gating; HMAC-key entropy validation | 616 |

---

## Foundational Work — The 9 Original Issues (Resolved)

| # | Issue | Resolution |
|---|-------|------------|
| 1 | Provider bypass in governance pipeline | `run()` → instance method; provider injected via constructor |
| 2 | Unencrypted PEM at rest / empty passphrases | `_encryption_algorithm()` hard-errors on `None` passphrase |
| 3 | Incomplete signing key lifecycle | `sign_with_key_id` / `verify_with_key_id` added |
| 4 | Private key loaded during encryption | `stream_encrypt_file` uses the public key only |
| 5 | Error leakage | Sanitized messages only; no exception interpolation |
| 6 | Registry path boundary not enforced | `is_relative_to(KEY_DIR.resolve())` enforced |
| 7 | Signing not streamed | `sign_stream` / `verify_stream` at all entry points |
| 8 | Audit log not tamper-resistant | SHA-256 hash chain written; forward verification added in Batch P0 |
| 9 | Sensitive files in project root | `.gitignore` hardened |

---

## Core Architecture Milestones

### Container V4 + Body Signature (2026-04-18)
- Incremental SHA-256 body digest with trailer `[body_sig][sig_len 4BE]`.
- Decrypt order enforced: header signature → body signature → DEK unwrap → chunk decrypt.
- `verify_body_signature()` seeks EOF-4 and verifies **before** chunk iteration.

### User Authentication (P1, 2026-04-24)
- Argon2id password hashing; HMAC-SHA256 user store; bootstrap rule for first admin.
- Identity flow: `username/password → authenticate() → User(authenticated=True) → pipeline`.
- Pipeline rejects unauthenticated users: `"Authentication required"`.

### Classification Binding (P5–P6, 2026-04-25/26)
- Classification is bound to the signed SVST V4 container header and is **system-assigned**,
  never caller-supplied. Decrypt authorization reads the classification from the container,
  making relocation attacks ineffective (verified by dedicated tests).

### Safe Workspace & Classified Output (P7 / P4.8, 2026-04-26)
- All file I/O bounded to `workspace/`; dotfiles, blocked names, and symlink escapes hidden.
- Engine routes output to `encrypted/` and `decrypted/<classification>/` subdirectories.

### Auditor Read-Only Tools (P4.11, 2026-04-26)
- Auditor role limited to view / verify / export with SHA-256 sidecars.

### Standardized Audit Schema
- Actions: `ENCRYPT, DECRYPT, KEY_ROTATE, ACCESS_DENIED, SIGN, VERIFY`.
- Fields: `timestamp, action, role, classification, key_id, result`.
- Result values: `SUCCESS, DENIED, ERROR`.

---

## Security Audit #1 — A1–A7 (Batches 1–4, 2026-04-27)

| ID | Severity | Fix |
|----|----------|-----|
| A1 | HIGH | `_require_admin(user)` added to CLI rotate/rewrap/sign/verify |
| A2 | HIGH | `rewrap_dek(user=None)` — authorization gate + KEY_ROTATE audit |
| A3 | MEDIUM | Engine-layer `_check_access()` replaced by `AuthorizationEngine.authorize()` |
| A4 | MEDIUM | Overwrite check moved inside the audit try-block |
| A5 | MEDIUM | `AUDIT_LOG_PATH` must be absolute — relative paths rejected |
| A6 | MEDIUM | `DASHBOARD_SECRET` gate added; audit schema fields corrected |
| A7 | MEDIUM | Hardcoded-user `__main__` block removed from `orchestrator.py` |

---

## Adversarial Audit #2 (Batches 5–6, 2026-04-27)

| ID | Severity | Resolution |
|----|----------|------------|
| N-C1 | MEDIUM | Public `get_key_entry(key_id)`; removed direct `_registry` access |
| N-C2 | MEDIUM | `StreamingHeader.version` preserved across rewrap |
| N-C3 | MEDIUM | `validate_user_record()` — load-boundary schema validation |
| N-C4 | MEDIUM | `KeyRegistry.register()` guards key_id format, algorithm allowlist, key reference |
| N-C5 | MEDIUM | Agents delegate to `GovernancePipeline` / `stream_decrypt_file` (no direct crypto) |
| N-D1 | LOW | Audit sort tolerates null/missing timestamps |

Also in this window: relocation-attack test coverage added, and a duplicate
system-attributed `DECRYPT` audit event was removed so that exactly one DECRYPT event
is emitted per operation, always attributed to the real user (closes N-B3, A10).

---

## Post-Level-4 Hardening Batches (2026-04-28)

### Batch P0 — Audit Integrity & Auth-Bypass Removal
- `check_chain()` rewritten to perform full forward hash-chain verification; `export_logs()`
  now refuses to export a tampered log.
- Removed `encrypt_file()` / `decrypt_file()` compatibility aliases that called the streaming
  functions with `user=None`, bypassing authorization entirely.

### Batch P1 — Failed-Login Auditing & Encryption-Key Fingerprints
- All four `authenticate()` failure paths emit an `ACCESS_DENIED` audit event (best-effort;
  narrowed exception handling so genuine audit failures still propagate).
- RSA/ECC encryption-key rotation writes a `.fp` fingerprint sidecar (SHA-256 of the DER
  SubjectPublicKeyInfo); `get_rsa_public_key()` / `get_ecc_public_key()` verify the fingerprint
  on load and raise on mismatch or a missing sidecar.

### Batch P2 — Pipeline Decrypt Restricted
- `GovernancePipeline.decrypt()` documented and enforced as **internal/admin-only**; two gates
  fire in sequence (unauthenticated → "Authentication required"; non-admin → "Internal decrypt
  not permitted"). `stream_decrypt_file()` is the sole production decrypt path.
- Removed the unused `data_classification` parameter from `stream_decrypt_file()` and its call
  sites — classification is authoritative from the signed container.

### Batch P3 — Documentation Corrections
- Removed a stale CLI comment that misdescribed the authorization engine's command coverage.
- Clarified in the history that the audit chain was written from the start but not
  forward-verified until Batch P0.

### Batch P4 — Audit-Repair Gating & HMAC-Key Entropy
- `audit-repair` now requires an authenticated admin and emits `ACCESS_DENIED` on refusal;
  removed it from the unauthenticated CLI bypass block.
- `USERS_HMAC_KEY` must decode as valid hex and be ≥ 32 bytes; the key is validated **before**
  any user-store file I/O.

---

## Open Items (Non-Blocking)

| ID | Location | Issue |
|----|----------|-------|
| A8 | `spy/auth.py` | Bootstrap TOCTOU race on `store_path.exists()` |
| H-4 | `spy/auth.py` | No rate limiting / lockout on failed logins |
| S7 | `spy/file_crypto_engine.py` | `_rewrap_write_header` duplicates the container header format |
| S11 | `spy/policy_engine.py` | `strict` compliance hardcodes an RSA score bonus (P-256 ECC is equivalent per NIST) |

---

## Level 5 Architecture Gaps (Future Work)

| Gap | Requirement |
|-----|-------------|
| Keys on disk (encrypted PEMs) | HSM / KMS backend |
| No key escrow | Recovery mechanism |
| No multi-party authorization | Threshold signing |
| No formal pentest | External review + threat model |
| No MFA | Multi-factor authentication for admin operations |
| No TLS | Data-in-transit protection |
