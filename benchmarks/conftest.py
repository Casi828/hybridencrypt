import csv
import json
import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

import spy.workspace as _ws_mod

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

# --- env setup ---
_audit_path = os.environ.get("AUDIT_LOG_PATH", "")
if not _audit_path or not Path(_audit_path).is_absolute():
    os.environ["AUDIT_LOG_PATH"] = str(_PROJECT_ROOT / "audit_log.json")

if not os.environ.get("USERS_HMAC_KEY"):
    os.environ["USERS_HMAC_KEY"] = "aa" * 32

_BENCH_STORE = str(_PROJECT_ROOT / "runtime" / ".users_bench.json")
os.environ["USERS_STORE_PATH"] = _BENCH_STORE

_bench_store_path = Path(_BENCH_STORE)
if _bench_store_path.exists():
    _bench_store_path.unlink()
_bench_store_path.parent.mkdir(parents=True, exist_ok=True)

try:
    from spy.auth import authenticate as _authenticate
    from spy.auth import create_user as _create_user

    _create_user("bench_admin", "benchpass_admin", "admin", "high")
    _admin = _authenticate("bench_admin", "benchpass_admin")
    _create_user("bench_analyst_low", "benchpass_low", "analyst", "low", admin_user=_admin)
    _create_user("bench_analyst_med", "benchpass_med", "analyst", "medium", admin_user=_admin)
except Exception:
    pass


def _migrate_signing_keys_to_registry() -> None:
    _key_dir = os.environ.get("CRYPTO_KEY_DIR", "")
    if not _key_dir:
        return
    key_dir = Path(_key_dir)
    try:
        from spy.key_registry import (
            KeyEntry,
            KeyRegistry,
            KeyRegistryError,
            algorithm_for_type,
            make_sign_key_id,
            now_iso,
        )
    except Exception:
        return
    registry = KeyRegistry()
    try:
        registry.load()
    except Exception:
        return
    changed = False
    for key_type, priv_ref, _pub_ref in (
        ("rsa_sign", "rsa_sign_private.pem", "rsa_sign_public.pem"),
        ("ecc_sign", "ecc_sign_private.pem", "ecc_sign_public.pem"),
    ):
        if registry.list_by_type(key_type):
            continue
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

# --- workspace helpers ---
_WS_ATTRS = (
    "SAFE_FILE_ROOT",
    "SAFE_INPUT_DIR",
    "SAFE_ENCRYPT_INPUT_DIR",
    "SAFE_DECRYPT_INPUT_DIR",
    "SAFE_OUTPUT_DIR",
    "SAFE_ENCRYPTED_OUTPUT_DIR",
    "SAFE_DECRYPTED_OUTPUT_DIR",
    "SAFE_SIG_DIR",
    "SAFE_AUDIT_OUTPUT_DIR",
)


def ws_snap() -> dict:
    return {k: getattr(_ws_mod, k) for k in _WS_ATTRS}


def ws_patch(tmp_root: Path) -> dict:
    snap = ws_snap()
    root = tmp_root.resolve()
    _ws_mod.SAFE_FILE_ROOT = root
    _ws_mod.SAFE_INPUT_DIR = root / "input"
    _ws_mod.SAFE_ENCRYPT_INPUT_DIR = root / "input" / "encrypt"
    _ws_mod.SAFE_DECRYPT_INPUT_DIR = root / "input" / "decrypt"
    _ws_mod.SAFE_OUTPUT_DIR = root / "output"
    _ws_mod.SAFE_ENCRYPTED_OUTPUT_DIR = root / "output" / "encrypted"
    _ws_mod.SAFE_DECRYPTED_OUTPUT_DIR = root / "output" / "decrypted"
    _ws_mod.SAFE_SIG_DIR = root / "sig"
    _ws_mod.SAFE_AUDIT_OUTPUT_DIR = root / "output" / "audit"
    _ws_mod.ensure_safe_workspace()
    return snap


def ws_restore(snap: dict) -> None:
    for k, v in snap.items():
        setattr(_ws_mod, k, v)


# --- session fixtures ---

@pytest.fixture(scope="session")
def bench_workspace(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("bench")
    snap = ws_patch(tmp)
    yield tmp
    ws_restore(snap)


@pytest.fixture(scope="session")
def bench_users():
    from spy.auth import authenticate as _auth

    return {
        "admin": _auth("bench_admin", "benchpass_admin"),
        "analyst_low": _auth("bench_analyst_low", "benchpass_low"),
        "analyst_med": _auth("bench_analyst_med", "benchpass_med"),
    }


# --- results collector and CSV/JSON exporter ---

_BENCH_DIR = Path(__file__).resolve().parent
_CSV_PATH = _BENCH_DIR / "benchmark_results.csv"
_JSON_PATH = _BENCH_DIR / "benchmark_results.json"

_CSV_FIELDS = [
    "test_name",
    "file_size_label",
    "file_size_bytes",
    "method",
    "classification",
    "metric",
    "mean",
    "median",
    "min",
    "max",
    "stdev",
    "unit",
    "iterations",
]


def _export_results(records: list[dict]) -> None:
    if not records:
        return
    with _CSV_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    with _JSON_PATH.open("w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


@pytest.fixture(scope="session")
def bench_results():
    """Accumulate benchmark records; export to CSV and JSON on session teardown."""
    records: list[dict] = []
    yield records
    _export_results(records)
