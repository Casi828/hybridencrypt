"""
setup_keys.py — One-time key initialization for the hybrid encryption system.

Generates all four required cryptographic keypairs and registers all keys
in the key registry. Run once before first use of the system.

Keys generated:
  - RSA-3072 encryption keypair  (registry-tracked, active, key_id rsa-enc-...)
  - ECC-P256 encryption keypair  (registry-tracked, active, key_id ecc-enc-...)
  - RSA-3072 signing keypair     (registry-tracked, active, key_id rsa-sign-v1)
  - ECC-P256  signing keypair    (registry-tracked, active, key_id ecc-sign-v1)

DO NOT integrate this script into application runtime.
DO NOT auto-run from any engine, pipeline, or test fixture.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .key_registry import get_key_dir, KeyRegistry, KeyRegistryError
from .rsa_engine import (
    rotate_rsa_encryption_keys,
    rotate_rsa_signing_keys,
)
from .ecc_engine import (
    rotate_ecc_encryption_keys,
    rotate_ecc_signing_keys,
)

# Signing-key filenames. These mirror the fixed names the engines write in
# rotate_rsa_signing_keys() / rotate_ecc_signing_keys() (rsa_engine.py,
# ecc_engine.py). They are derived here from get_key_dir() rather than imported,
# because the engines build the paths inline and do not export them as constants.
_SIGNING_KEY_FILENAMES = (
    "rsa_sign_private.pem",
    "rsa_sign_public.pem",
    "ecc_sign_private.pem",
    "ecc_sign_public.pem",
)


def _signing_key_files() -> tuple[Path, ...]:
    """Return the absolute paths of the four signing-key PEM files.

    Resolved against the active key directory (CRYPTO_KEY_DIR via get_key_dir())
    so this matches wherever the engines will actually write the keys.
    """
    key_dir = get_key_dir()
    return tuple(key_dir / name for name in _SIGNING_KEY_FILENAMES)


def _abort(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def _check_no_existing_keys(registry: KeyRegistry) -> None:
    """Fail if any keys are already registered or signing key files exist.

    Prevents accidental overwrite of live key material on a running system.
    """
    for key_type in ("rsa_enc", "ecc_enc", "rsa_sign", "ecc_sign"):
        try:
            existing_id = registry.get_active_key_id(key_type)
            _abort(
                f"Active {key_type} key already registered: {existing_id}. "
                "Remove all key files and the registry before re-initializing."
            )
        except KeyRegistryError:
            pass  # Expected — no active key yet.

    for path in _signing_key_files():
        if path.exists():
            _abort(
                f"Signing key file already exists: {path.name}. "
                "Remove all key files before re-initializing."
            )


_REQUIRED_PASSPHRASES = (
    "RSA_KEY_PASSPHRASE",
    "RSA_SIGN_KEY_PASSPHRASE",
    "ECC_KEY_PASSPHRASE",
    "ECC_SIGN_KEY_PASSPHRASE",
)


def _check_passphrases() -> None:
    """Abort if any required passphrase environment variable is missing or empty.

    Generating private keys without a passphrase produces unencrypted PEM files
    on disk — a key-custody violation. Fail closed before any key material is created.
    """
    missing = [v for v in _REQUIRED_PASSPHRASES if not os.environ.get(v, "").strip()]
    if missing:
        _abort(
            "The following passphrase environment variables are missing or empty:\n"
            + "\n".join(f"  {v}" for v in missing)
            + "\n\nSet all four passphrases in your .env file before running setup_keys.py."
        )


def main() -> None:
    # Fail closed if any passphrase is missing — must be first check.
    _check_passphrases()

    # Ensure key directory exists.
    get_key_dir().mkdir(parents=True, exist_ok=True)

    # Load registry — empty in-memory if no registry file exists yet.
    registry = KeyRegistry()
    registry.load()

    # Hard stop if any key material is already present.
    _check_no_existing_keys(registry)

    print("Initializing cryptographic keys...\n")

    rsa_sign_private_file, rsa_sign_public_file, \
        ecc_sign_private_file, ecc_sign_public_file = _signing_key_files()

    # ------------------------------------------------------------------
    # RSA encryption keypair — registered as active in key registry
    # ------------------------------------------------------------------
    _, _, rsa_enc_id = rotate_rsa_encryption_keys(registry)
    print(f"  RSA encryption key  key_id={rsa_enc_id}")
    print(f"                      private=rsa_enc_{rsa_enc_id}_private.pem  (0o600)")
    print(f"                      public =rsa_enc_{rsa_enc_id}_public.pem   (0o644)")

    # ------------------------------------------------------------------
    # ECC encryption keypair — registered as active in key registry
    # ------------------------------------------------------------------
    _, _, ecc_enc_id = rotate_ecc_encryption_keys(registry)
    print(f"  ECC encryption key  key_id={ecc_enc_id}")
    print(f"                      private=ecc_enc_{ecc_enc_id}_private.pem  (0o600)")
    print(f"                      public =ecc_enc_{ecc_enc_id}_public.pem   (0o644)")

    # ------------------------------------------------------------------
    # RSA signing keypair — registry-tracked as rsa-sign-v1
    # ------------------------------------------------------------------
    _, _, rsa_sign_id = rotate_rsa_signing_keys(registry)
    print(f"  RSA signing key     key_id={rsa_sign_id}")
    print(f"                      private={rsa_sign_private_file.name}  (0o600)")
    print(f"                      public ={rsa_sign_public_file.name}   (0o644)")

    # ------------------------------------------------------------------
    # ECC signing keypair — registry-tracked as ecc-sign-v1
    # ------------------------------------------------------------------
    _, _, ecc_sign_id = rotate_ecc_signing_keys(registry)
    print(f"  ECC signing key     key_id={ecc_sign_id}")
    print(f"                      private={ecc_sign_private_file.name}  (0o600)")
    print(f"                      public ={ecc_sign_public_file.name}   (0o644)")

    print(f"\nRegistry written to: {get_key_dir() / 'key_registry.json'}")
    print("Key initialization complete.")


if __name__ == "__main__":
    main()
