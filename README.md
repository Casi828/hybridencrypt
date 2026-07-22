# Policy-Driven Hybrid Encryption System

A research-grade hybrid file-encryption system that combines **AES-256-GCM** for bulk
data encryption with **RSA-OAEP / ECC** key wrapping, wrapped in a governance layer that
enforces authentication, role- and clearance-based authorization, system-assigned data
classification, and a tamper-evident audit trail.

This repository accompanies a research thesis on the design of secure, policy-driven
hybrid cryptosystems and is provided as supporting material for a fellowship application.

---

## Research Motivation

Symmetric ciphers are fast but require a shared secret; asymmetric ciphers solve key
distribution but are too slow for bulk data. **Hybrid encryption** resolves this tension:
a random data-encryption key (DEK) protects the payload with AES-256-GCM, and that DEK is
wrapped under a recipient's RSA or ECC public key. The research question this project
explores is how to wrap that primitive in a **policy engine** that makes correct, auditable
authorization decisions — binding data classification to the ciphertext itself so that
access control cannot be subverted by relocating or renaming a file.

---

## Features

- **Hybrid encryption** — AES-256-GCM data encryption with RSA-OAEP or ECC (ECDH + HKDF) key wrapping.
- **Signed container format (SVST V4)** — header signature + streamed body signature, verified before any DEK unwrap.
- **Governance pipeline** — authentication (Argon2id), role + clearance RBAC, and system-assigned classification bound to the signed container header.
- **Tamper-evident audit log** — hash-chained JSONL with forward-chain verification; exports refuse a tampered log.
- **Key lifecycle** — key rotation, DEK rewrapping, and public-key fingerprint (`.fp`) verification on load.
- **Streaming I/O** — large files are processed in chunks; no full-file memory loading.
- **Bounded workspace** — all file I/O is confined to a safe workspace with symlink-escape protection.

---

## Repository Structure

```
.
├── spy/                    # Core package: crypto engines, governance pipeline, CLI, GUI, auth
│   └── agents/             # Encrypt/decrypt agents (delegate to the pipeline — no direct crypto)
├── tests/                  # Test suite (616 tests)
│   └── fixtures/           # Sample plaintext input for round-trip tests
├── benchmarks/             # Performance benchmark suite + results (benchmark_results.{json,csv})
├── scripts/
│   └── generate_thesis.py  # Regenerates thesis.pdf from benchmark data (reproducibility)
├── docs/
│   └── dev/ai-workflow/     # AI-assisted development methodology (not required to run the project)
├── thesis.pdf              # Research thesis
├── pyproject.toml          # Package + entry-point definitions
├── requirements.txt        # Core runtime dependencies
├── requirements-dashboard.txt
├── .env.example            # Configuration template (copy to .env)
├── CHANGELOG.md            # Development history & resolved security findings
└── README.md
```

> Runtime-generated directories (`keys/`, `runtime/`, `workspace/`) and secret files
> (`.env`, `*.pem`, `*.fp`, audit logs, user store) are intentionally excluded from version
> control via `.gitignore` and are created locally during setup.

---

## Requirements

- Python **3.11+**
- Dependencies (see `requirements.txt` / `pyproject.toml`): `cryptography`, `python-dotenv`, `argon2-cffi`
- Optional: `streamlit` for the dashboard (`requirements-dashboard.txt`)

---

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

---

## Configuration

Copy the template and fill in every required value:

```bash
cp .env.example .env
```

| Variable | Required | Purpose |
|----------|----------|---------|
| `CRYPTO_KEY_DIR` | ✅ | Absolute path to the key storage directory |
| `AUDIT_LOG_PATH` | ✅ | Absolute path for the audit log (relative paths are rejected) |
| `USERS_HMAC_KEY` | ✅ | User-store integrity key — generate with `openssl rand -hex 32` |
| `RSA_KEY_PASSPHRASE` | ✅ | Passphrase for the RSA encryption private key |
| `RSA_SIGN_KEY_PASSPHRASE` | ✅ | Passphrase for the RSA signing private key |
| `ECC_KEY_PASSPHRASE` | ✅ | Passphrase for the ECC encryption private key |
| `ECC_SIGN_KEY_PASSPHRASE` | ✅ | Passphrase for the ECC signing private key |
| `DASHBOARD_SECRET` | ✅ (dashboard) | Access gate for the Streamlit dashboard |
| `SAFE_FILE_ROOT` | optional | Override for the workspace root (defaults to `workspace/`) |
| `USERS_STORE_PATH` | optional | Override for the user store (defaults to `runtime/users.json`) |

Then bootstrap the key material:

```bash
spy-setup-keys           # or: python3 -m spy.setup_keys
```

### First run — create your admin account

Every command except the first `add-user` requires an authenticated login, so a fresh install
starts with no accounts. Create the initial account with the **bootstrap** command:

```bash
spy-cli add-user         # or: python3 -m spy.cli add-user
```

Because no user store exists yet, this one command runs without authentication and creates the
**first user as an admin with `high` clearance** (any `--role`/`--clearance` are ignored on this
first run). You'll be prompted for a username and password. From then on the store exists, so every
command — including creating more users — requires logging in, and only an authenticated admin can
add further accounts.

---

## Usage

The primary interface is the `spy-cli` command. It can be launched either as the installed
`spy-cli` script or, when running from a clone, as `python3 -m spy.cli` — both invoke the same
entry point and behave identically. The module form requires the dependencies to be installed and
the `spy` package to be importable (run from the repo root, or after `pip install -e .`). Every
example below also works as `python3 -m spy.cli <subcommand>`:

```bash
# File operations
spy-cli encrypt        # encrypt a file from the workspace
spy-cli decrypt        # decrypt a container
spy-cli sign           # detached signature
spy-cli verify         # verify a signature

# Key management (admin)
spy-cli rotate-keys    # rotate signing keys
spy-cli rotate-enc-keys
spy-cli rewrap         # re-wrap a DEK under a new key

# Audit (auditor/admin)
spy-cli view-logs
spy-cli verify-chain   # verify the audit hash chain
spy-cli export-logs
spy-cli audit-repair   # admin-only: repair audit-log continuity metadata

# User management (admin)
spy-cli users add | list | disable | enable | change-role | change-clearance | reset-password | delete
```

The user-management verbs are also available as top-level commands (`add-user`, `disable-user`,
`enable-user`, `list-users`, `change-role`, `change-clearance`, `reset-password`, `delete-user`),
which behave identically to their `users` subcommand equivalents.

A Tkinter GUI and an optional Streamlit dashboard are also provided. Launch the GUI with `spy-gui`
or `python3 -m spy.gui`, and the dashboard with `streamlit run spy/dashboard.py`. (Key setup can
likewise be run as `spy-setup-keys` or `python3 -m spy.setup_keys`.)

---

## Running the Tests

The test suite is **not** clean-checkout reproducible without configuration: many tests exercise
the real streaming file engine, which loads passphrase-encrypted key material from the directory
named by `CRYPTO_KEY_DIR`. Before running the tests, complete the **Configuration** steps above —
copy `.env.example` to `.env`, set the four PEM passphrases and `USERS_HMAC_KEY`, and run
`spy-setup-keys` to generate a local key set. Then:

```bash
python -m pytest
```

---

## Reproducibility & Benchmarks

Performance benchmarks live in `benchmarks/` and produce `benchmark_results.json` / `.csv`:

```bash
python -m pytest benchmarks/ -q
```

The thesis figures and `thesis.pdf` are fully reproducible from that benchmark data:

```bash
python scripts/generate_thesis.py
```

---

## Thesis

`thesis.pdf` — *Design and Implementation of a Policy-Driven Hybrid Encryption System* —
documents the architecture, threat model, and evaluation. It is authored by
**Geneve Casimir** and represents the author's own research; the benchmark data and figures
it presents are reproducible from this repository (see above).

---

## Known Limitations

This is a **research prototype**, not an externally audited production system. It has a mature,
well-tested feature set at its current maturity level, but it has **not** undergone a formal
external security review or penetration test. Planned future work includes an HSM/KMS
key backend, key escrow, multi-party (threshold) authorization, multi-factor authentication for
admin operations, TLS for data in transit, and a formal external penetration test. See
`CHANGELOG.md` for the full status of open items.

---

## Development Transparency

This project was developed with the assistance of AI coding tools. The author directed the
work and personally reviewed, tested, and documented every change. 

---

## License

Licensed under the **Apache License, Version 2.0** — see [`LICENSE`](LICENSE).
Copyright © 2026 Geneve Casimir.
