import os
from pathlib import Path
from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

# Provide test-safe defaults for required env vars not present in .env.
# Production code still fails closed — these defaults only apply to the test harness.
# Always ensure AUDIT_LOG_PATH is absolute — .env may set a relative path which the
# new strict enforcement rejects at runtime.
_audit_path = os.environ.get("AUDIT_LOG_PATH", "")
if not _audit_path or not Path(_audit_path).is_absolute():
    os.environ["AUDIT_LOG_PATH"] = str(_PROJECT_ROOT / "audit_log.json")

# Test-only auth defaults — only applied when .env does not define these.
_TEST_HMAC_KEY = "aa" * 32  # 32-byte hex key for test suite
_TEST_CLI_USER = "testuser"
_TEST_CLI_PASS = "testpass"

if not os.environ.get("USERS_HMAC_KEY"):
    os.environ["USERS_HMAC_KEY"] = _TEST_HMAC_KEY

# Dedicated test CLI store — always separate from the production users.json.
# CLI subprocess tests inherit USERS_STORE_PATH via os.environ.copy(); pointing
# them at this path guarantees testuser exists regardless of production store state.
# unit tests (test_auth.py, test_user_management.py) override USERS_STORE_PATH via
# patch.dict in their own setUp, so they are unaffected by this assignment.
_TEST_CLI_STORE = str(_PROJECT_ROOT / "runtime" / ".users_test_cli.json")
os.environ["USERS_STORE_PATH"] = _TEST_CLI_STORE

# Always recreate the test CLI store so testuser is present and the HMAC key matches.
_cli_store_path = Path(_TEST_CLI_STORE)
if _cli_store_path.exists():
    _cli_store_path.unlink()
try:
    from spy.auth import create_user as _create_user
    _create_user(_TEST_CLI_USER, _TEST_CLI_PASS, "admin", "high")
except Exception:
    pass  # Best-effort; tests that require auth will surface the failure naturally.


def _migrate_signing_keys_to_registry() -> None:
    """Register existing fixed-path signing keys as v1 in the registry if not yet present.

    The runtime/keys/ directory was created before signing keys were registry-tracked.
    This migration runs once per test session to bring the registry up to date so that
    provider.get_active_rsa_signing_key_id() and get_active_ecc_signing_key_id() work.

    Idempotent — safe to call when v1 entries are already registered.
    """
    _key_dir = os.environ.get("CRYPTO_KEY_DIR", "")
    if not _key_dir:
        return
    key_dir = Path(_key_dir)

    # Defer imports until after env vars are set.
    try:
        from spy.key_registry import (
            KeyRegistry, KeyEntry, KeyRegistryError,
            make_sign_key_id, algorithm_for_type, now_iso,
        )
    except Exception:
        return

    registry = KeyRegistry()
    try:
        registry.load()
    except Exception:
        return

    changed = False
    for key_type, priv_ref, pub_ref in (
        ("rsa_sign", "rsa_sign_private.pem", "rsa_sign_public.pem"),
        ("ecc_sign", "ecc_sign_private.pem", "ecc_sign_public.pem"),
    ):
        # Skip if any signing key of this type is already in the registry.
        if registry.list_by_type(key_type):
            continue
        # Skip if the key files do not exist yet (setup_keys not run).
        if not (key_dir / priv_ref).exists():
            continue
        key_id = make_sign_key_id(key_type, 1)
        ts = now_iso()
        entry = KeyEntry(
            key_id=key_id,
            key_type=key_type,
            status="active",
            created_at=ts,
            activate_at=ts,
            retire_at=None,
            algorithm=algorithm_for_type(key_type),
            key_reference=priv_ref,
        )
        try:
            registry.register(entry)
            changed = True
        except KeyRegistryError:
            pass

    if changed:
        try:
            registry.save()
        except Exception:
            pass


_migrate_signing_keys_to_registry()


def _generate_enc_key_fingerprints() -> None:
    """Write .fp sidecar files for any encryption public keys that lack them.

    One-time migration for keys created before fingerprint enforcement was added.
    New keys get .fp written automatically by rotate_rsa/ecc_encryption_keys().
    Idempotent — skips keys whose .fp already exists.
    """
    key_dir_str = os.environ.get("CRYPTO_KEY_DIR", "")
    if not key_dir_str:
        return
    key_dir = Path(key_dir_str)
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from spy.rsa_engine import _write_fingerprint
    except ImportError:
        return
    for pattern in ("rsa_enc_*_public.pem", "ecc_enc_*_public.pem"):
        for pub_pem in key_dir.glob(pattern):
            fp_path = pub_pem.with_suffix(".fp")
            if fp_path.exists():
                continue
            try:
                key = load_pem_public_key(pub_pem.read_bytes())
                _write_fingerprint(key, fp_path)
            except Exception:
                pass


_generate_enc_key_fingerprints()


# ---------------------------------------------------------------------------
# Workspace test helpers — import in any test that calls stream_encrypt_file or
# stream_decrypt_file.  Redirects the workspace module globals so the engine
# routes output to a temp directory instead of the real workspace/.
# ---------------------------------------------------------------------------

import spy.workspace as _ws_mod

_WS_ATTRS = (
    "SAFE_FILE_ROOT",
    "SAFE_INPUT_DIR", "SAFE_ENCRYPT_INPUT_DIR", "SAFE_DECRYPT_INPUT_DIR",
    "SAFE_OUTPUT_DIR", "SAFE_ENCRYPTED_OUTPUT_DIR", "SAFE_DECRYPTED_OUTPUT_DIR",
    "SAFE_SIG_DIR", "SAFE_AUDIT_OUTPUT_DIR",
)


def ws_snap() -> dict:
    """Return a snapshot of current workspace module constants."""
    return {k: getattr(_ws_mod, k) for k in _WS_ATTRS}


def ws_patch(tmp_root: "Path") -> dict:
    """Redirect workspace to *tmp_root*, create classified subdirs, return snapshot."""
    snap = ws_snap()
    root = tmp_root.resolve()
    _ws_mod.SAFE_FILE_ROOT            = root
    _ws_mod.SAFE_INPUT_DIR            = root / "input"
    _ws_mod.SAFE_ENCRYPT_INPUT_DIR    = root / "input" / "encrypt"
    _ws_mod.SAFE_DECRYPT_INPUT_DIR    = root / "input" / "decrypt"
    _ws_mod.SAFE_OUTPUT_DIR           = root / "output"
    _ws_mod.SAFE_ENCRYPTED_OUTPUT_DIR = root / "output" / "encrypted"
    _ws_mod.SAFE_DECRYPTED_OUTPUT_DIR = root / "output" / "decrypted"
    _ws_mod.SAFE_SIG_DIR              = root / "sig"
    _ws_mod.SAFE_AUDIT_OUTPUT_DIR     = root / "output" / "audit"
    _ws_mod.ensure_safe_workspace()
    return snap


def ws_restore(snap: dict) -> None:
    """Restore workspace module constants from a snapshot produced by ws_patch."""
    for k, v in snap.items():
        setattr(_ws_mod, k, v)
