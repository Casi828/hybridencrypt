# Changelog & Development History

A consolidated record of the project's security hardening, architectural decisions,
and resolved audit findings. The system reached its **Level 4 maturity milestone —
a hardened research prototype (616 tests passing)** on 2026-04-28, and closed its last
open code-level findings in Batches P5–P6 on 2026-07-27 (761 tests passing). It has not
undergone a formal external security review; see "Level 5 Architecture Gaps" below.

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
| 2026-07-27 | Batch P5 — open items A8, H-4, S7, S11 closed | 753 |
| 2026-07-27 | Batch P6 — audit chain verification made rotation-aware | 761 |

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

### Batch P5 — Open Items A8, H-4, S7, S11 Closed (2026-07-27)

The four remaining non-blocking findings are resolved. No open code-level items remain;
what is left is the Level 5 architecture work below.

**A8 — bootstrap TOCTOU (`spy/auth.py`).** The check-then-create gap is closed by a
transaction lock covering the *full* read-modify-write cycle, not just bootstrap — two
admins mutating concurrently could previously both load, mutate, and save, silently
discarding one update. `_store_transaction()` now wraps `create_user`, `disable_user`,
`enable_user`, `change_role`, `change_clearance`, `reset_password`, `delete_user`, and
`authenticate()`'s commit step. The lock file is opened defensively:
`O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW` → `fstat` regular-file check → unconditional
`fchmod(fd, 0o600)` → `flock`, with a symlinked runtime directory rejected and every
failure raising `AuthError`. Authorization under the lock is now **store-backed**:
`_require_current_admin(admin_user, store)` requires the caller's record to still exist,
be `active`, and still be `admin` in the freshly reloaded store — the pre-existing
`_require_admin()` only inspected the cached `User` object, so a disabled, deleted, or
demoted admin's stale object kept working indefinitely. Argon2 ordering is
authorize (preliminary) → hash → lock → re-authorize (authoritative) → apply, so hashing
never runs inside the lock nor before an authorization check.

**H-4 — login rate limiting (`spy/auth.py`).** `failed_attempts` and `locked_until` are
tracked per record with `LOCKOUT_THRESHOLD = 5` and escalating
`LOCKOUT_SCHEDULE_SECONDS = (30, 60, 300, 900)`. A correct password during an active lock
is still denied; success resets both fields; admin `reset_password()` clears them.
`_lockout_state()` is the single fail-closed parser: a malformed counter or timestamp
(including `bool`, which subclasses `int`) locks the account indefinitely and is never
normalized to zero — recovery is an admin action, by design. Argon2 verification runs
outside the lock against a snapshot, and the result is committed only if the record still
matches that snapshot under the lock, otherwise the attempt restarts (bounded retry);
this closes a stale-password race where a concurrent reset could be overtaken by a login
verified against the old hash. Disabled accounts run the timing-resistant verification but
are always denied and never have their lockout state mutated.

**S7 — container header duplication (`spy/container_writer.py`, `spy/file_crypto_engine.py`).**
`_rewrap_write_header()` is deleted. A new pure, stateless, keyword-only
`build_signed_region()` in `container_writer.py` is the single authority for the SVST
signed-region layout, shared by `write_header()` and the rewrap path. It owns *all* header
validation — including the checks the writer constructor used to provide, since rewrap no
longer constructs a writer at all — plus per-version required-and-forbidden field
invariants for V1–V4. `sender_pubkey_raw` is now `bytes | None` end to end with no `b""`
sentinel (RSA requires `None`, ECC non-empty bytes). The rewrap path holds zero references
to writer-private state. This also closed a latent bug: the old helper appended
`sign_key_id` whenever the writer had one while forcing the input's version byte, so a V2
input could have produced a `version=2` container with a V3-shaped payload that the reader
cannot parse — unreachable in practice only because of an upstream authorization gate, and
now structurally impossible.

**S11 — policy engine RSA bias (`spy/policy_engine.py`).** The unconditional
`strict`/`moderate` RSA score bonus is removed; RSA-3072+ and P-256 ECC are equivalent at
~128-bit classical strength per NIST SP 800-57 Part 1 Rev. 5. `compliance_level` is now
documented for what it actually does — validated as a recognized policy-context value,
contributing nothing to RSA-versus-ECC ranking, and *not* validating or enforcing algorithm
eligibility. Ties (including "no other signal fires") resolve to ECC; this is a stated
decision, not an accident of the comparison operator.

Tests: 608 → 753 (all passing, plus 71 subtests). New coverage includes process-level
concurrency tests using real separate OS processes, revoked-admin authorization tests,
lock-file symlink and permission tests, a test proving unauthorized calls never reach
Argon2, the full lockout state machine under an injected clock, and a V1–V4 × RSA/ECC
container wire-format matrix with byte-exact reader re-parse.

**Two trade-offs are documented rather than hidden.** The transaction lock is POSIX-only
(`flock`); non-POSIX platforms raise `AuthError` at lock time rather than failing at import.
And persistent per-account lockout state introduces a disk-write timing difference between
known and unknown usernames — Argon2 timing remains normalized, but full timing
indistinguishability is no longer claimed. A future networked service should key
rate-limit state independently of user records.

---

### Batch P6 — Audit Chain Verification Made Rotation-Aware (2026-07-27)

Found by running the CLI after Batch P5: `verify-chain` reported
`Chain broken at line 1: expected previous_hash='GENESIS'` on a log whose chain was
in fact fully intact. Two defects, one of them security-relevant.

**`check_chain()` was rotation-blind.** It read only the current log file and
unconditionally required `previous_hash == "GENESIS"` at line 1. But
`_AuditRotatingFileHandler` deliberately writes an `AUDIT_ROTATION` sentinel as the first
entry of each new file, linking it to the file it replaced — so after *every* rotation the
verifier reported a break that did not exist, and rotated history was never verified at
all. Tamper detection covered only the newest file. Replaced by `verify_chain()`, which
discovers `audit_log.json.N … .1` plus the current file, walks them oldest-first, and
carries the running hash across rotation boundaries. `check_chain()` is retained as a
fail-closed wrapper so `export_logs()` keeps its refuse-to-export-a-tampered-log contract
(that path was also blocked by the false positive). Two conditions are now *reported*
rather than misread as tampering: an **epoch restart** (a later file beginning at GENESIS,
which is what quarantine-and-recover leaves behind) and **truncated history** (the oldest
surviving file not beginning at GENESIS, because rotation pruned earlier backups). An
epoch restart is excused only for a literal GENESIS — an arbitrary unknown hash is still a
hard failure, so a forged sentinel cannot launder a break.

**The CLI conflated two different events.** `_startup_validate()` caught any
`AuditLogError` and printed *"audit log has corrupt entries — auto-recovery active"*. A
genuine linkage break — the signature of tampering — produced that same routine-sounding
message and startup continued. Corrupt-tail auto-recovery and chain verification failure
are now reported separately: a verification failure prints an explicit
`*** AUDIT CHAIN VERIFICATION FAILED ***` block stating that this is consistent with
tampering and is not the same as an interrupted write, and points at `audit-repair`.
Startup still continues so the operator can investigate. `verify-chain` now prints a
per-file entry count, any epoch restarts, and the total verified across all files.

Tests: 753 → 761. New coverage for end-to-end verification across rotation, multi-backup
chronological ordering, detection of tampering **inside a rotated file** (previously
invisible), epoch restarts being reported but not fatal, a forged non-GENESIS first entry
still failing, pruned history flagged as truncated, and an absent log as a clean chain.

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
