# Roadmap & Working Status

Tracking document for where the project stands and what comes next.
Technical detail for completed work lives in [`CHANGELOG.md`](CHANGELOG.md); this file
is the forward-looking view and the running status log.

**Last updated:** 2026-07-27

---

## Current status

| | |
|---|---|
| Maturity | Level 4 — hardened research prototype |
| Tests | 761 passing (+71 subtests) |
| Open code-level findings | **None** |
| Next milestone | Phase 2 — key-management abstraction (not started) |
| External security review | Not performed |

All four previously-tracked open items (A8, H-4, S7, S11) were closed on 2026-07-27.
What remains between here and Level 5 is architectural, not defect-fixing.

---

## Session log — 2026-07-27

### Phase 1 complete: A8, H-4, S7, S11 closed

Recorded in detail as **Batch P5** in `CHANGELOG.md`. Summary:

- **A8 — bootstrap TOCTOU** (`spy/auth.py`). Closed with a transaction lock covering the
  full read-modify-write cycle of *all* user-store mutations, not just bootstrap — the
  original finding understated the problem, since two concurrent admins could already lose
  each other's writes. Lock file is symlink-hardened (`O_NOFOLLOW` + `fstat` regular-file
  check + unconditional `fchmod`).
- **H-4 — login rate limiting** (`spy/auth.py`). Per-account lockout with escalating
  backoff, fail-closed parsing of malformed state, and a snapshot/retry flow so Argon2
  never runs under the lock while still refusing to honour a verification computed against
  a since-changed record.
- **S7 — container header duplication** (`spy/container_writer.py`,
  `spy/file_crypto_engine.py`). `_rewrap_write_header()` deleted; a pure
  `build_signed_region()` is now the single authority for the SVST byte layout.
- **S11 — policy engine RSA bias** (`spy/policy_engine.py`). Unconditional RSA compliance
  bonus removed; tie-break to ECC documented as a decision rather than left implicit.

Also found and fixed during this work:

- **A store-backed authorization gap.** `_require_admin()` only inspected the cached `User`
  object, so an admin who was disabled, deleted, or demoted after authenticating kept full
  privileges indefinitely. Now re-validated against the freshly loaded store under the lock.
- **A latent container bug.** The old rewrap helper could emit a `version=2` header with a
  V3-shaped payload — unparseable, and unreachable only by accident of an upstream
  authorization gate. Structurally impossible now.

### Phase 1 follow-on: audit chain verification fixed

Recorded as **Batch P6** in `CHANGELOG.md`. Found by actually running the CLI afterwards.

- `check_chain()` was rotation-blind — it read only the newest log file and demanded
  `previous_hash == "GENESIS"` at line 1, so it reported a false break after *every*
  rotation and never verified rotated history at all. Replaced with a cross-file,
  epoch-aware `verify_chain()`.
- The CLI reported a genuine linkage break with the same reassuring "corrupt entries —
  auto-recovery active" message used for routine interrupted writes. Now separated, with an
  explicit failure block for suspected tampering.

The live audit log was verified intact end to end (9,888 entries across 4 files) — the
original failure was a verifier bug, not tampering.

---

## Corrections to `analaysis.md`

The untracked `analaysis.md` (ChatGPT-authored) was the original source for this roadmap.
Its Phase 1 items were all accurate. Two later-phase claims were not, and this file carries
the corrected version:

1. **Phase 2 is a refactor, not a green-field build.** `analaysis.md` says to *create* a
   `KeyProvider` abstraction. One already exists (`spy/key_provider.py`) and is used
   throughout. See "Phase 2" below for what the actual blocker is.
2. **Level 5 gaps are real and correctly identified** — that part of the document checks out
   against `CHANGELOG.md`.

Recommendation: treat this file as authoritative and let `analaysis.md` go (it is untracked
and superseded).

---

## Future plans

Phases are sequenced deliberately. The ordering matters: each one assumes the previous is
in place, and jumping ahead means rework.

### Phase 2 — Key-management abstraction ← **next**

**The real blocker, stated precisely:** `KeyProvider` exists, but it *exports raw private
key objects*. `get_rsa_private_key()`, `get_ecc_private_key()`, and the signing-key
equivalents all return live `cryptography` key objects that callers then operate on
directly. AWS KMS, Azure Key Vault, and PKCS#11 HSMs **never export private keys** — they
only perform operations on your behalf. So the interface as shaped today cannot back onto
any of them.

Required work:

- Refactor `KeyProvider` from a **key-export** model to an **operation-delegation** model:
  `wrap_dek()`, `unwrap_dek()`, `sign_digest()`, `verify_signature()`, `rotate_key()`,
  `get_public_key()`, `get_key_metadata()`.
- Update every caller (`cli.py`, `file_crypto_engine.py`, `governance_pipeline.py`,
  `gui.py`, `demo.py`) so no engine holds private key material.
- Keep `LocalPemKeyProvider` working throughout as the reference implementation.

**Decide the interface shape before writing any backend** — adding a KMS first would mean
rewriting it.

### Phase 3 — KMS backend

One real backend (AWS KMS, Azure Key Vault, or HashiCorp Vault). Private wrapping and
signing keys stay outside the process; the application receives only wrapped DEKs,
signatures, public keys, and metadata. Key IDs, versions, aliases, and provider identifiers
become part of the signed container metadata.

Note: this environment has no cloud credentials, so initial development would need a mock
(e.g. `moto` for AWS).

### Phase 4 — MFA and step-up authentication

TOTP or WebAuthn/passkeys for administrators; session expiration; re-authentication for
sensitive actions (key rotation, DEK rewrapping, privilege changes, audit repair,
recovery-key access, policy modification). Enterprise IdP integration with role and
clearance mapped from trusted claims. Break-glass accounts with stronger auditing.

Account lockout and rate limiting — listed here in the original roadmap — is **already done**
(H-4, Batch P5).

### Phase 5 — TLS-secured service boundary

Turn the local tool into a dedicated always-on service (the Mac mini) behind a narrow API
over the governance pipeline. Never expose the file crypto engine directly. Mutual TLS for
managed clients, streamed uploads/downloads, bounded worker queues, restricted OS account,
`launchd` management, and fail-closed behaviour when auth, policy, KMS, audit, or config are
unavailable.

### Phase 6 — Key recovery and multi-party control

Optional second wrap of each DEK under a separately controlled recovery key, with recovery
identity and version in the signed header, a distinct authorization policy, and separate
auditing. Recovery must not bypass classification or clearance checks, and the recovery key
must not sit beside the operational private key.

Threshold / M-of-N authorization for master-key rotation, recovery-key use, audit-chain
repair, destructive user administration, policy changes, and emergency recovery.

### Phase 7 — Externalized audit storage

Append-only external destination, cryptographically anchored checkpoints outside the host,
retention and rotation rules, correlation IDs across auth/policy/crypto/key-provider events,
and policy version plus decision rationale recorded per operation.

Local forward hash-chain verification now covers rotated history (Batch P6); external
anchoring extends that trust beyond this machine, so that a local administrator cannot
silently replace both the data and its audit trail.

### Phase 8 — Concurrency, failure, and fuzz testing

Multi-gigabyte files, concurrent workloads, memory ceilings, backpressure, interrupted-
operation recovery, disk-full behaviour, partial-write cleanup, atomic output publication,
container-format fuzzing, property-based crypto tests, and KMS/HSM outage simulation.
Benchmarks: RSA vs ECC wrapping, local PEM vs KMS/HSM, policy and audit overhead. Chunked
streaming must never regress to full-file memory loading.

### Phase 9 — Formal security validation

Threat model document, trust-boundary diagrams, asset and attacker-capability definitions,
abuse-case analysis, independent code review, external penetration test, remediation report.

### Phase 10 — Packaging, operations, compliance

Signed reproducible releases, dependency locking, SBOM, vulnerability scanning, a secure
update mechanism that verifies signed release metadata and fails closed, config schema
validation, migration support for container and key versions, runbooks, CI security gates.

Compliance alignment (NIST key-management guidance, CSF, SOC 2, documented access control
and key custody, separation of duties, evidence collection) — designed so certification
*could* be pursued, without claiming it.

---

## Open questions

- **`AUDIT_LOG_PATH` cross-pointing.** `.env` points the audit log and key directory at
  `~/projects/ClaudeProject_SPY_v3.4/runtime/`, not this repo's `runtime/`. This repo's own
  `runtime/` holds stale files. Confirm whether this is intentional.
- **Disposition of `analaysis.md`.** Untracked and superseded by this file.

## Known trade-offs (accepted and documented)

- The user-store transaction lock is **POSIX-only** (`flock`). Non-POSIX platforms raise
  `AuthError` at lock time rather than failing at import. Porting is a one-function change.
- Persistent per-account lockout state introduces a **disk-write timing difference between
  known and unknown usernames**. Argon2 verification timing remains normalized, but full
  timing indistinguishability is no longer claimed. A future networked service should key
  rate-limit state independently of user records.
- **Rotated-history verification is bounded by `_BACKUP_COUNT`** (currently 3). Once
  rotation prunes a backup, verification can no longer reach past it; `verify_chain()`
  reports this as truncated history rather than silently narrowing the guarantee.
