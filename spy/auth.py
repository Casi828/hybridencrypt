"""
auth.py — User authentication, password hashing, and HMAC-protected user store.

Trust boundary: only User objects returned by authenticate() carry authenticated=True.
Externally constructed User objects are untrusted and will be rejected by governance_pipeline.

HMAC key source: USERS_HMAC_KEY environment variable (required; missing → AuthError).
User store: USERS_STORE_PATH environment variable (default: <project_root>/runtime/users.json).
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import tempfile
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .audit_logger import AuditLogger
from .user_model import User

_PH = PasswordHasher()  # Argon2id with argon2-cffi defaults

_BASE_DIR = Path(__file__).resolve().parent.parent

_VALID_ROLES = frozenset({"admin", "analyst", "auditor"})
_VALID_CLEARANCES = frozenset({"low", "medium", "high"})

# Lazily computed to avoid Argon2id hash cost at import time.
_DUMMY_HASH: str | None = None


class AuthError(Exception):
    pass


def _log_auth_denied(username: str) -> None:
    """Emit ACCESS_DENIED audit event for a failed authentication attempt.

    Swallows RuntimeError/OSError (AUDIT_LOG_PATH not configured or filesystem error).
    Propagates AuditLogError — a write failure to a configured audit system is a hard error.
    No password or secret is logged; only the attempted username.
    """
    class _Stub:
        role = "unknown"
    stub = _Stub()
    stub.username = username
    try:
        AuditLogger.log_event(stub, "ACCESS_DENIED", outcome="denied")
    except (RuntimeError, OSError):
        pass


def _require_admin(admin_user: User | None) -> None:
    """Fail closed unless ``admin_user`` is an authenticated admin.

    Every user-management mutation calls this first, so an unauthenticated or
    non-admin caller is rejected before any store read or write occurs.

    Raises:
        AuthError: if ``admin_user`` is None, not authenticated, or not an admin.
    """
    if not (
        admin_user is not None
        and getattr(admin_user, "authenticated", False)
        and admin_user.role == "admin"
    ):
        raise AuthError("Admin authentication required")


def _count_active_admins(store: dict) -> int:
    return sum(
        1 for u in store["users"]
        if u.get("role") == "admin" and u.get("status") == "active"
    )


def user_store_exists() -> bool:
    """Return True if the user store file exists on disk."""
    return _get_store_path().exists()


def _get_store_path() -> Path:
    env = os.environ.get("USERS_STORE_PATH", "").strip()
    return Path(env) if env else _BASE_DIR / "runtime" / "users.json"


def _get_hmac_key() -> bytes:
    raw = os.environ.get("USERS_HMAC_KEY", "").strip()
    if not raw:
        raise AuthError("USERS_HMAC_KEY is not set")
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise AuthError("USERS_HMAC_KEY must be a valid hex string")
    if len(key) < 32:
        raise AuthError("USERS_HMAC_KEY must be at least 32 bytes (64 hex characters)")
    return key


def _compute_hmac(content: str) -> str:
    key = _get_hmac_key()
    mac = _hmac.new(key, content.encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = _PH.hash("__timing_resistance__")
    return _DUMMY_HASH


def hash_password(password: str) -> str:
    """Hash a password with Argon2id for storage.

    Returns the encoded Argon2 hash string (embeds algorithm, parameters, and a
    per-hash random salt). The plaintext password is never stored or logged.
    """
    return _PH.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password against a stored Argon2id hash, failing closed.

    Argon2's verify performs the comparison in constant time relative to the
    secret. Any malformed-hash or mismatch error is caught and reported as a
    plain ``False`` so no distinguishing detail leaks to the caller.
    """
    try:
        return _PH.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def load_user_store() -> dict:
    """Load and HMAC-verify the user store. Fails closed on any error."""
    _get_hmac_key()  # validate before any I/O
    path = _get_store_path()
    if not path.exists():
        raise AuthError("User store does not exist")

    try:
        raw = path.read_text(encoding="utf-8")
        store = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthError("User store is invalid") from exc

    signature = store.pop("signature", None)
    if signature is None:
        raise AuthError("User store integrity check failed")

    canonical = json.dumps(store, sort_keys=True, separators=(",", ":"))
    expected = _compute_hmac(canonical)

    if not _hmac.compare_digest(expected, signature):
        raise AuthError("User store integrity check failed")

    return store


def save_user_store(store: dict) -> None:
    """Compute HMAC and atomically write the user store with chmod 600."""
    _get_hmac_key()  # validate before any I/O
    path = _get_store_path()
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)

    data = {k: v for k, v in store.items() if k != "signature"}
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    signature = _compute_hmac(canonical)

    full_store = dict(data)
    full_store["signature"] = signature
    content = json.dumps(full_store, indent=2)

    fd, tmp_path = tempfile.mkstemp(dir=str(parent), prefix=".users_tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def authenticate(username: str, password: str) -> User | None:
    """Return User(authenticated=True) on success; None on any failure.

    Wrong password and unknown user produce identical outcomes (timing safe).
    Disabled users fail authentication.
    """
    try:
        store = load_user_store()
    except AuthError:
        verify_password(_dummy_hash(), password)  # timing resistance
        _log_auth_denied(username)
        return None

    users = store.get("users", [])
    record = next((u for u in users if u.get("username") == username), None)

    if record is None:
        verify_password(_dummy_hash(), password)  # timing resistance
        _log_auth_denied(username)
        return None

    stored_hash = record.get("password_hash", _dummy_hash())
    if not verify_password(stored_hash, password):
        _log_auth_denied(username)
        return None

    if record.get("status") != "active":
        _log_auth_denied(username)
        return None

    return User(
        username=record["username"],
        role=record["role"],
        clearance=record["clearance"],
        authenticated=True,
    )


def create_user(
    username: str,
    password: str,
    role: str,
    clearance: str,
    *,
    admin_user: User | None = None,
) -> None:
    """Create a user in the store.

    Bootstrap rule: admin_user=None is allowed only when no user store exists.
    Bootstrap forces role=admin and clearance=high.
    After bootstrap: admin_user must be authenticated with role='admin'.
    """
    store_path = _get_store_path()
    is_bootstrap = not store_path.exists()

    if is_bootstrap:
        role = "admin"
        clearance = "high"
        store: dict = {"version": 1, "users": []}
    else:
        _require_admin(admin_user)
        if role not in _VALID_ROLES:
            raise AuthError(f"Invalid role: {role}")
        if clearance not in _VALID_CLEARANCES:
            raise AuthError(f"Invalid clearance: {clearance}")
        store = load_user_store()

    if any(u["username"] == username for u in store["users"]):
        raise AuthError(f"User already exists: {username}")

    store["users"].append({
        "username": username,
        "role": role,
        "clearance": clearance,
        "status": "active",
        "password_hash": hash_password(password),
    })

    save_user_store(store)


def disable_user(username: str, *, admin_user: User | None = None) -> None:
    """Mark a user as disabled (admin only), preventing future authentication.

    Guards against lockout/self-harm: an admin cannot disable their own account,
    and the last remaining active admin cannot be disabled.

    Raises:
        AuthError: if the caller is not an admin, the user does not exist, the
            target is the caller, or the target is the last active admin.
    """
    _require_admin(admin_user)
    store = load_user_store()
    record = next((u for u in store["users"] if u["username"] == username), None)
    if record is None:
        raise AuthError("User not found")
    if username == admin_user.username:
        raise AuthError("Cannot disable your own account")
    if record.get("role") == "admin" and _count_active_admins(store) <= 1:
        raise AuthError("Cannot disable the last active admin")
    record["status"] = "disabled"
    save_user_store(store)


def enable_user(username: str, *, admin_user: User | None = None) -> None:
    """Re-activate a disabled user (admin only).

    Raises:
        AuthError: if the caller is not an admin or the user does not exist.
    """
    _require_admin(admin_user)
    store = load_user_store()
    record = next((u for u in store["users"] if u["username"] == username), None)
    if record is None:
        raise AuthError("User not found")
    record["status"] = "active"
    save_user_store(store)


def list_users(*, admin_user: User | None = None) -> list[dict]:
    """Return user records with password_hash stripped. Requires authenticated admin."""
    _require_admin(admin_user)
    store = load_user_store()
    return [
        {k: v for k, v in u.items() if k != "password_hash"}
        for u in store["users"]
    ]


def change_role(username: str, new_role: str, *, admin_user: User | None = None) -> None:
    """Change a user's RBAC role (admin only), validating against known roles.

    Guards against privilege lockout: an admin cannot change their own role, and
    the role cannot be removed from the last active admin. ``new_role`` must be a
    member of the allowed role set.

    Raises:
        AuthError: if the caller is not an admin, the target is the caller, the
            role is invalid, the user does not exist, or the change would strip
            the last active admin of the admin role.
    """
    _require_admin(admin_user)
    if username == admin_user.username:
        raise AuthError("Cannot change your own role")
    if new_role not in _VALID_ROLES:
        raise AuthError("Invalid role")
    store = load_user_store()
    record = next((u for u in store["users"] if u["username"] == username), None)
    if record is None:
        raise AuthError("User not found")
    if record.get("role") == "admin" and new_role != "admin":
        if _count_active_admins(store) <= 1:
            raise AuthError("Cannot remove admin role from last active admin")
    record["role"] = new_role
    save_user_store(store)


def change_clearance(username: str, new_clearance: str, *, admin_user: User | None = None) -> None:
    """Change a user's clearance level (admin only), validating the value.

    Clearance gates which data classifications a user may decrypt, so an admin
    cannot change their own clearance, and ``new_clearance`` must be one of the
    allowed levels.

    Raises:
        AuthError: if the caller is not an admin, the target is the caller, the
            clearance is invalid, or the user does not exist.
    """
    _require_admin(admin_user)
    if username == admin_user.username:
        raise AuthError("Cannot change your own clearance")
    if new_clearance not in _VALID_CLEARANCES:
        raise AuthError("Invalid clearance")
    store = load_user_store()
    record = next((u for u in store["users"] if u["username"] == username), None)
    if record is None:
        raise AuthError("User not found")
    record["clearance"] = new_clearance
    save_user_store(store)


def reset_password(username: str, new_password: str, *, admin_user: User | None = None) -> None:
    """Set a new Argon2id password hash for a user (admin only).

    The new password is hashed before storage and never written in plaintext.

    Raises:
        AuthError: if the caller is not an admin, the password is empty, or the
            user does not exist.
    """
    _require_admin(admin_user)
    if not new_password:
        raise AuthError("Password cannot be empty")
    store = load_user_store()
    record = next((u for u in store["users"] if u["username"] == username), None)
    if record is None:
        raise AuthError("User not found")
    record["password_hash"] = hash_password(new_password)
    save_user_store(store)


def delete_user(username: str, *, admin_user: User | None = None) -> None:
    """Permanently remove a user from the store (admin only).

    Guards against lockout: an admin cannot delete their own account, and the
    last remaining active admin cannot be deleted.

    Raises:
        AuthError: if the caller is not an admin, the user does not exist, the
            target is the caller, or the target is the last active admin.
    """
    _require_admin(admin_user)
    store = load_user_store()
    record = next((u for u in store["users"] if u["username"] == username), None)
    if record is None:
        raise AuthError("User not found")
    if username == admin_user.username:
        raise AuthError("Cannot delete your own account")
    if record.get("role") == "admin" and _count_active_admins(store) <= 1:
        raise AuthError("Cannot delete the last active admin")
    store["users"] = [u for u in store["users"] if u["username"] != username]
    save_user_store(store)
