"""
auth.py — User authentication, password hashing, and HMAC-protected user store.

Trust boundary: only User objects returned by authenticate() carry authenticated=True.
Externally constructed User objects are untrusted and will be rejected by governance_pipeline.

HMAC key source: USERS_HMAC_KEY environment variable (required; missing → AuthError).
User store: USERS_STORE_PATH environment variable (default: <project_root>/runtime/users.json).

Transaction lock: every read-modify-write cycle against the user store is serialized
by an exclusive ``flock`` on a dedicated lock file kept next to the store. This is
POSIX-only by design for now (``fcntl`` is unavailable on native Windows); the import
is guarded so the module still imports there, and any locked operation raises
``AuthError`` instead. Porting to a cross-platform lock is a change to
``_acquire_lock``/``_release_lock`` only, not a rewrite.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, NamedTuple

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .audit_logger import AuditLogger
from .user_model import User

try:  # POSIX only — guarded so the module still imports on other platforms.
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised only on non-POSIX platforms
    _fcntl = None  # type: ignore[assignment]

_PH = PasswordHasher()  # Argon2id with argon2-cffi defaults

_BASE_DIR = Path(__file__).resolve().parent.parent

_VALID_ROLES = frozenset({"admin", "analyst", "auditor"})
_VALID_CLEARANCES = frozenset({"low", "medium", "high"})

# Lazily computed to avoid Argon2id hash cost at import time.
_DUMMY_HASH: str | None = None

# --- Rate limiting (H-4) ---------------------------------------------------
LOCKOUT_THRESHOLD = 5
LOCKOUT_SCHEDULE_SECONDS = (30, 60, 300, 900)  # 30s, 1m, 5m, 15m cap

# Upper sanity bound for a stored failed-attempt counter. Anything outside
# [0, _MAX_FAILED_ATTEMPTS] is treated as a malformed record (fail closed).
_MAX_FAILED_ATTEMPTS = 1000

# Bounded retry budget for authenticate()'s stale-snapshot restart loop.
_MAX_AUTH_RETRIES = 3

# Sentinel for "key absent from record" in snapshot comparison. Distinct from
# any JSON-representable value, so a missing field never compares equal to None.
_MISSING = object()

# Sentinel returned by the locked commit step when the record changed underneath
# an unlocked verification and the whole attempt must be restarted.
_STALE = object()


class AuthError(Exception):
    pass


class _LockoutState(NamedTuple):
    """Parsed lockout fields for one user record.

    Attributes:
        failed_attempts: Consecutive failed logins recorded for the account.
        locked_until: Timezone-aware UTC expiry of an active lock, or None.
        malformed: True when the stored lockout fields could not be trusted. A
            malformed record is unauthenticatable until an admin repairs it —
            it never expires on its own.
    """

    failed_attempts: int
    locked_until: datetime | None
    malformed: bool


def _now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime.

    Single indirection point for the wall clock so lockout expiry can be tested
    with an injected clock instead of real sleeps.
    """
    return datetime.now(timezone.utc)


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

    This is a **preliminary** check only: it inspects the in-memory ``User``
    object and never consults the store, so it cannot detect an account that was
    disabled, deleted, or demoted after it authenticated. It runs first purely to
    reject obviously unauthorized callers before any disk I/O or Argon2 work.
    ``_require_current_admin`` is the authoritative check.

    Raises:
        AuthError: if ``admin_user`` is None, not authenticated, or not an admin.
    """
    if not (
        admin_user is not None
        and getattr(admin_user, "authenticated", False)
        and admin_user.role == "admin"
    ):
        raise AuthError("Admin authentication required")


def _require_current_admin(admin_user: User | None, store: dict) -> None:
    """Authoritatively authorize ``admin_user`` against a freshly loaded store.

    A ``User`` object obtained from a successful ``authenticate()`` keeps passing
    ``_require_admin`` forever, even after the account behind it is revoked. This
    check re-validates the caller against the store record loaded under the
    transaction lock, so an admin who was disabled, deleted, or demoted since
    authenticating can no longer mutate the store.

    Args:
        admin_user: The caller's identity, as returned by ``authenticate()``.
        store: A user store dict loaded inside the current transaction lock.

    Raises:
        AuthError: if the preliminary check fails, or the caller's record is
            absent, not ``status="active"``, or no longer ``role="admin"``. The
            message is identical in every case so it never reveals whether the
            account was deleted, disabled, or demoted.
    """
    _require_admin(admin_user)
    record = next(
        (u for u in store.get("users", []) if u.get("username") == admin_user.username),
        None,
    )
    if record is None:
        raise AuthError("Admin authentication required")
    if record.get("status") != "active" or record.get("role") != "admin":
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


def _get_lock_path() -> Path:
    """Return the path of the transaction lock file for the current store.

    The lock file lives next to the store, is created once, and is deliberately
    never unlinked: removing it would reopen a check-then-create race on the lock
    file itself, which is exactly what the lock exists to prevent.

    Raises:
        AuthError: if the configured store path has no derivable lock path.
    """
    try:
        return _get_store_path().with_suffix(".lock")
    except ValueError as exc:
        raise AuthError("User store path is invalid") from exc


def _open_lock_file(lock_path: Path) -> int:
    """Open the transaction lock file defensively and return its file descriptor.

    Permissions alone are not enough: an attacker who pre-creates the lock path as
    a symlink would have the open follow it, so ``O_NOFOLLOW`` plus a regular-file
    ``fstat`` check runs before any ``fchmod``. ``fchmod`` is applied
    unconditionally on the fd because the restrictive mode passed to ``os.open``
    only takes effect when the file is newly created — it does nothing about a
    lock file left behind with broader permissions.

    Args:
        lock_path: Path of the lock file, from ``_get_lock_path()``.

    Returns:
        An open file descriptor with mode 0600 enforced, ready for ``flock``.

    Raises:
        AuthError: on any failure — unusable or symlinked runtime directory,
            symlinked lock path, non-regular file at the lock path, or a failed
            open, fstat, or fchmod. Fails closed; never returns a descriptor
            whose target or permissions could not be verified.
    """
    parent = lock_path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AuthError("User store lock directory is unavailable") from exc
    if parent.is_symlink():
        raise AuthError("User store lock directory is not a regular directory")
    if not parent.is_dir():
        raise AuthError("User store lock directory is not a regular directory")

    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)  # do not leak the lock fd into children
    flags |= getattr(os, "O_NOFOLLOW", 0)  # a symlinked lock path fails outright
    try:
        fd = os.open(str(lock_path), flags, 0o600)
    except OSError as exc:
        raise AuthError("User store lock file could not be opened") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AuthError("User store lock file is not a regular file")
        os.fchmod(fd, 0o600)
    except AuthError:
        os.close(fd)
        raise
    except OSError as exc:
        os.close(fd)
        raise AuthError("User store lock file could not be secured") from exc
    return fd


def _acquire_lock(fd: int) -> None:
    """Take an exclusive advisory lock on ``fd``, blocking until it is granted.

    Isolates the only POSIX-specific call in this module.

    Raises:
        AuthError: if file locking is unavailable on this platform, or the lock
            could not be acquired.
    """
    if _fcntl is None:
        raise AuthError("File locking is not supported on this platform")
    try:
        _fcntl.flock(fd, _fcntl.LOCK_EX)
    except OSError as exc:
        raise AuthError("User store lock could not be acquired") from exc


def _release_lock(fd: int) -> None:
    """Release the advisory lock held on ``fd``.

    Errors are swallowed: closing the descriptor releases the lock regardless, so
    a failed explicit unlock cannot leave the store wedged.
    """
    if _fcntl is None:  # pragma: no cover - unreachable once _acquire_lock succeeded
        return
    try:
        _fcntl.flock(fd, _fcntl.LOCK_UN)
    except OSError:
        pass


@contextmanager
def _store_transaction() -> Iterator[None]:
    """Serialize a full read-modify-write cycle against the user store.

    Callers reload the store, mutate it, and save it *inside* the block, so the
    load and the save are one atomic transaction with respect to other processes.
    Concurrent admins can no longer both read, mutate, and write, silently
    discarding each other's update.

    Yields:
        None — the lock is held for the duration of the ``with`` body.

    Raises:
        AuthError: if the lock file cannot be safely opened or the lock cannot be
            acquired. The mutation never runs in that case (fail closed).
    """
    fd = _open_lock_file(_get_lock_path())
    try:
        _acquire_lock(fd)
        try:
            yield
        finally:
            _release_lock(fd)
    finally:
        os.close(fd)


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


# ---------------------------------------------------------------------------
# Lockout state (H-4)
# ---------------------------------------------------------------------------

def _lockout_state(record: dict) -> _LockoutState:
    """Interpret a record's lockout fields, failing closed on anything suspect.

    One shared parser for every call site so the fail-closed rule cannot drift.

    Rules:
        - Both fields absent → ``failed_attempts=0, locked_until=None``. This is
          the only case that gets a zero default: it is a legacy record that
          predates the feature, a known-good state.
        - Only one field present → malformed (a partially written record is not
          trustworthy; every write path in this module emits both fields).
        - ``failed_attempts`` that is a bool (``bool`` subclasses ``int``, so
          ``True``/``False`` must never be accepted as ``1``/``0``), non-integer,
          negative, or above ``_MAX_FAILED_ATTEMPTS`` → malformed.
        - ``locked_until`` that is neither None nor a parseable ISO-8601 string
          carrying a UTC offset → malformed.

    A malformed record is treated as locked indefinitely: it is never normalized
    to zero and never self-expires, because there is no trustworthy attempt count
    to compute an expiry from. Recovery is an admin ``reset_password()`` (or a
    direct record repair), by design.

    Args:
        record: A raw user record dict from a verified store.

    Returns:
        The parsed ``_LockoutState``.
    """
    has_attempts = "failed_attempts" in record
    has_until = "locked_until" in record

    if not has_attempts and not has_until:
        return _LockoutState(0, None, False)
    if not (has_attempts and has_until):
        return _LockoutState(0, None, True)

    attempts = record["failed_attempts"]
    if isinstance(attempts, bool) or not isinstance(attempts, int):
        return _LockoutState(0, None, True)
    if attempts < 0 or attempts > _MAX_FAILED_ATTEMPTS:
        return _LockoutState(0, None, True)

    raw_until = record["locked_until"]
    if raw_until is None:
        return _LockoutState(attempts, None, False)
    if not isinstance(raw_until, str):
        return _LockoutState(attempts, None, True)

    text = raw_until.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return _LockoutState(attempts, None, True)
    if parsed.tzinfo is None:
        return _LockoutState(attempts, None, True)
    return _LockoutState(attempts, parsed.astimezone(timezone.utc), False)


def _is_locked_out(state: _LockoutState, now: datetime) -> bool:
    """Return True if ``state`` forbids authentication at ``now``.

    A malformed state is always locked and has no expiry.
    """
    if state.malformed:
        return True
    if state.locked_until is None:
        return False
    return now < state.locked_until


def _apply_failed_attempt(record: dict, state: _LockoutState) -> None:
    """Increment a record's failure counter and set the next lockout window.

    Attempts below ``LOCKOUT_THRESHOLD`` only increment. At and beyond the
    threshold the account is locked for ``LOCKOUT_SCHEDULE_SECONDS[min(N, last)]``
    where ``N`` is the number of lockouts already triggered for the account, so
    consecutive lockouts escalate 30s → 1m → 5m → 15m and then stay capped.

    Args:
        record: The user record being updated, held under the transaction lock.
        state: The parsed lockout state the increment is applied to.
    """
    attempts = min(state.failed_attempts + 1, _MAX_FAILED_ATTEMPTS)
    record["failed_attempts"] = attempts
    if attempts >= LOCKOUT_THRESHOLD:
        index = min(attempts - LOCKOUT_THRESHOLD, len(LOCKOUT_SCHEDULE_SECONDS) - 1)
        expiry = _now() + timedelta(seconds=LOCKOUT_SCHEDULE_SECONDS[index])
        record["locked_until"] = expiry.isoformat()
    else:
        record["locked_until"] = None


def _clear_lockout(record: dict) -> None:
    """Reset a record's lockout fields to their defaults."""
    record["failed_attempts"] = 0
    record["locked_until"] = None


def _record_snapshot(record: dict) -> tuple:
    """Capture the authentication-relevant fields of a record for comparison.

    Each value is tagged with its type name so a type change (for example ``0``
    becoming ``False``, which compare equal in Python) still registers as a
    difference, and an absent field never compares equal to ``None``.
    """
    def _tag(value: object) -> tuple:
        return (type(value).__name__, value)

    return (
        _tag(record.get("password_hash", _MISSING)),
        _tag(record.get("status", _MISSING)),
        _tag(record.get("failed_attempts", _MISSING)),
        _tag(record.get("locked_until", _MISSING)),
    )


def _authenticate_snapshot_hook() -> None:
    """No-op extension point invoked after the pre-lock snapshot is captured.

    Exists solely so tests can deterministically interleave a concurrent store
    mutation between the unlocked snapshot and the locked re-read, instead of
    relying on timing. It is called once per attempt, including retries.
    """
    return None


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


def _commit_auth_attempt(
    username: str,
    snapshot: tuple,
    state: _LockoutState,
    password_ok: bool,
) -> object:
    """Apply an authentication outcome to the store under the transaction lock.

    The Argon2 verification behind ``password_ok`` ran *without* the lock held,
    against ``snapshot``. This step reloads the record and refuses to act on a
    verification computed against data that has since changed.

    Args:
        username: The account being authenticated.
        snapshot: The pre-lock ``_record_snapshot`` the verification used.
        state: The pre-lock lockout state the increment is applied to.
        password_ok: Result of verifying against the snapshot's password hash.

    Returns:
        ``_STALE`` if the record changed since the snapshot and the caller must
        restart, an authenticated ``User`` on success, or None on denial.

    Raises:
        AuthError: if the lock could not be taken or the store could not be read.
        OSError: if the store could not be written back.
    """
    with _store_transaction():
        store = load_user_store()
        record = next(
            (u for u in store.get("users", []) if u.get("username") == username),
            None,
        )
        if record is None:
            return None
        if _record_snapshot(record) != snapshot:
            return _STALE
        # Re-checked explicitly under the lock: a disabled account must never
        # receive authenticated=True, and must never have its lockout state
        # mutated by a login attempt.
        if record.get("status") != "active":
            return None

        if password_ok:
            _clear_lockout(record)
            save_user_store(store)
            return User(
                username=record["username"],
                role=record["role"],
                clearance=record["clearance"],
                authenticated=True,
            )

        _apply_failed_attempt(record, state)
        save_user_store(store)
        return None


def authenticate(username: str, password: str) -> User | None:
    """Return User(authenticated=True) on success; None on any failure.

    Wrong password and unknown user produce identical outcomes. Disabled users
    always fail authentication, even with a correct password, and a failed or
    successful attempt against a disabled account never touches its lockout
    state. Repeated failures lock the account per ``LOCKOUT_THRESHOLD`` and
    ``LOCKOUT_SCHEDULE_SECONDS``; a correct password during an active lock is
    still denied.

    Argon2 verification deliberately runs *outside* the transaction lock, so a
    login cannot serialize every other store operation behind an expensive hash.
    That means the verification uses a snapshot taken before the lock; the result
    is only committed if the record still matches that snapshot under the lock,
    otherwise the whole attempt restarts (bounded by ``_MAX_AUTH_RETRIES``).
    Exhausting the retry budget under contention is treated as a failed
    authentication.

    Timing note — do not overclaim: Argon2 verification timing is normalized
    between known and unknown users. Persistent per-account lockout state
    introduces an inherent disk-write difference between known and unknown
    usernames, so full timing indistinguishability is no longer claimed. A future
    networked service should key rate-limit state independently of user records
    (e.g. by source plus attempted identifier) rather than only on existing
    accounts.

    Args:
        username: The account name being authenticated.
        password: The candidate plaintext password; never stored or logged.

    Returns:
        An authenticated ``User`` on success, otherwise None.
    """
    for _attempt in range(_MAX_AUTH_RETRIES):
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

        snapshot = _record_snapshot(record)
        state = _lockout_state(record)
        _authenticate_snapshot_hook()

        if _is_locked_out(state, _now()):
            verify_password(_dummy_hash(), password)  # timing resistance
            _log_auth_denied(username)
            return None

        stored_hash = record.get("password_hash") or _dummy_hash()
        password_ok = verify_password(stored_hash, password)

        if record.get("status") != "active":
            # Timing-resistant verification already ran above; the account is
            # denied regardless of the result and its counters are left alone.
            _log_auth_denied(username)
            return None

        try:
            result = _commit_auth_attempt(username, snapshot, state, password_ok)
        except (AuthError, OSError):
            # An unusable lock or an unwritable store denies the login rather
            # than propagating — authenticate() returns None on any failure.
            _log_auth_denied(username)
            return None

        if result is _STALE:
            continue
        if result is None:
            _log_auth_denied(username)
            return None
        return result  # type: ignore[return-value]

    _log_auth_denied(username)
    return None


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

    Ordering is deliberate — authorize (preliminary) → hash → lock → re-authorize
    (authoritative) → apply. Argon2 never runs inside the transaction lock, where
    it would serialize every concurrent store mutation, and never before an
    authorization check, where an unauthorized caller could burn CPU on hashes for
    calls that were always going to be rejected. The bootstrap decision is made
    under the lock against freshly reloaded state, so two concurrent bootstrap
    attempts cannot both succeed.

    Args:
        username: New account name; must be non-empty.
        password: New account password; must be non-empty and is hashed before storage.
        role: RBAC role; validated except on the bootstrap path, which forces admin.
        clearance: Clearance level; validated except on bootstrap, which forces high.
        admin_user: Authenticated admin performing the creation, or None for bootstrap.

    Raises:
        AuthError: if the inputs are invalid, the caller is not a currently active
            admin, the username already exists, or the store lock is unavailable.
    """
    if not isinstance(username, str) or not username.strip():
        raise AuthError("Username cannot be empty")
    if not password:
        raise AuthError("Password cannot be empty")

    store_path = _get_store_path()

    # Pre-lock early rejection only — never a substitute for the authoritative
    # check below. Skipped when the store is absent, since a candidate bootstrap
    # has no admin to check yet and the decision is made under the lock.
    if store_path.exists():
        _require_admin(admin_user)
        if role not in _VALID_ROLES:
            raise AuthError(f"Invalid role: {role}")
        if clearance not in _VALID_CLEARANCES:
            raise AuthError(f"Invalid clearance: {clearance}")

    password_hash = hash_password(password)

    with _store_transaction():
        # Re-evaluated under the lock: another process may have completed
        # bootstrap in the gap, in which case this is no longer a bootstrap.
        if not store_path.exists():
            role = "admin"
            clearance = "high"
            store: dict = {"version": 1, "users": []}
        else:
            store = load_user_store()
            _require_current_admin(admin_user, store)
            if role not in _VALID_ROLES:
                raise AuthError(f"Invalid role: {role}")
            if clearance not in _VALID_CLEARANCES:
                raise AuthError(f"Invalid clearance: {clearance}")

        if any(u["username"] == username for u in store["users"]):
            raise AuthError(f"User already exists: {username}")

        store["users"].append({
            "username": username,
            "role": role,
            "clearance": clearance,
            "status": "active",
            "password_hash": password_hash,
            "failed_attempts": 0,
            "locked_until": None,
        })

        save_user_store(store)


def disable_user(username: str, *, admin_user: User | None = None) -> None:
    """Mark a user as disabled (admin only), preventing future authentication.

    Guards against lockout/self-harm: an admin cannot disable their own account,
    and the last remaining active admin cannot be disabled. The load, the check,
    and the write all happen inside one transaction lock.

    Raises:
        AuthError: if the caller is not a currently active admin, the user does
            not exist, the target is the caller, the target is the last active
            admin, or the store lock is unavailable.
    """
    _require_admin(admin_user)
    with _store_transaction():
        store = load_user_store()
        _require_current_admin(admin_user, store)
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
        AuthError: if the caller is not a currently active admin, the user does
            not exist, or the store lock is unavailable.
    """
    _require_admin(admin_user)
    with _store_transaction():
        store = load_user_store()
        _require_current_admin(admin_user, store)
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
        AuthError: if the caller is not a currently active admin, the target is
            the caller, the role is invalid, the user does not exist, the change
            would strip the last active admin of the admin role, or the store
            lock is unavailable.
    """
    _require_admin(admin_user)
    if username == admin_user.username:
        raise AuthError("Cannot change your own role")
    if new_role not in _VALID_ROLES:
        raise AuthError("Invalid role")
    with _store_transaction():
        store = load_user_store()
        _require_current_admin(admin_user, store)
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
        AuthError: if the caller is not a currently active admin, the target is
            the caller, the clearance is invalid, the user does not exist, or the
            store lock is unavailable.
    """
    _require_admin(admin_user)
    if username == admin_user.username:
        raise AuthError("Cannot change your own clearance")
    if new_clearance not in _VALID_CLEARANCES:
        raise AuthError("Invalid clearance")
    with _store_transaction():
        store = load_user_store()
        _require_current_admin(admin_user, store)
        record = next((u for u in store["users"] if u["username"] == username), None)
        if record is None:
            raise AuthError("User not found")
        record["clearance"] = new_clearance
        save_user_store(store)


def reset_password(username: str, new_password: str, *, admin_user: User | None = None) -> None:
    """Set a new Argon2id password hash for a user (admin only).

    The new password is hashed before storage and never written in plaintext.
    Resetting also clears the account's lockout state, so a reset user is not
    left administratively locked out — this is the only recovery path for a
    record whose lockout fields are malformed.

    Ordering is deliberate — authorize (preliminary) → hash → lock → re-authorize
    (authoritative) → apply — so Argon2 never runs inside the lock and never runs
    for a caller who was going to be rejected anyway.

    Raises:
        AuthError: if the caller is not a currently active admin, the password is
            empty, the user does not exist, or the store lock is unavailable.
    """
    if not new_password:
        raise AuthError("Password cannot be empty")
    _require_admin(admin_user)

    password_hash = hash_password(new_password)

    with _store_transaction():
        store = load_user_store()
        _require_current_admin(admin_user, store)
        record = next((u for u in store["users"] if u["username"] == username), None)
        if record is None:
            raise AuthError("User not found")
        record["password_hash"] = password_hash
        _clear_lockout(record)
        save_user_store(store)


def delete_user(username: str, *, admin_user: User | None = None) -> None:
    """Permanently remove a user from the store (admin only).

    Guards against lockout: an admin cannot delete their own account, and the
    last remaining active admin cannot be deleted.

    Raises:
        AuthError: if the caller is not a currently active admin, the user does
            not exist, the target is the caller, the target is the last active
            admin, or the store lock is unavailable.
    """
    _require_admin(admin_user)
    with _store_transaction():
        store = load_user_store()
        _require_current_admin(admin_user, store)
        record = next((u for u in store["users"] if u["username"] == username), None)
        if record is None:
            raise AuthError("User not found")
        if username == admin_user.username:
            raise AuthError("Cannot delete your own account")
        if record.get("role") == "admin" and _count_active_admins(store) <= 1:
            raise AuthError("Cannot delete the last active admin")
        store["users"] = [u for u in store["users"] if u["username"] != username]
        save_user_store(store)
