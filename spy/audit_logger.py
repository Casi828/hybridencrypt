"""
audit_logger.py — Structured JSON audit trail for all governance operations.

Logs are written to a rotating file (audit_log.json). Each entry is a single
JSON object on one line. Sensitive fields (keys, plaintext, tokens) must never
be passed to this module.

Hash chaining:
  Each entry carries a previous_hash (the current_hash of the preceding entry,
  or "GENESIS" for the first entry) and a current_hash computed as:

      SHA256(previous_hash || JSON(entry_without_current_hash))

  where || is byte concatenation and JSON uses sort_keys=True for determinism.

Corruption recovery:
  If the last entry in the log is corrupt (truncated write, disk-full crash),
  _read_last_hash() scans backward to find the last valid entry and returns
  that hash along with a recovery flag. log_event() then writes an
  AUDIT_RECOVERY event before the normal event to document the chain break.
  A single corrupt tail entry no longer blocks all crypto operations.

  check_chain() performs a strict scan and raises AuditLogError if any
  corruption is detected — intended for use by spy-audit-repair, not for
  blocking normal operations.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import workspace as _workspace_mod

def _get_audit_log_path() -> Path:
    p = os.environ.get("AUDIT_LOG_PATH", "")
    if not p:
        raise RuntimeError(
            "AUDIT_LOG_PATH environment variable is not set. "
            "Set it to the path of your audit log file before running "
            "(e.g. AUDIT_LOG_PATH=audit_log.json)."
        )
    resolved = Path(p)
    if not resolved.is_absolute():
        raise RuntimeError(
            f"AUDIT_LOG_PATH must be an absolute path, got: {p!r}. "
            "Relative paths cause split audit chains when the process is "
            "launched from different working directories."
        )
    return resolved


def __getattr__(name: str):
    if name == "AUDIT_LOG_FILE":
        return _get_audit_log_path()
    raise AttributeError(name)


# Patchable module-level names — tests override these; production code uses
# _get_audit_log_path() as fallback when these are None.
_LOG_PATH: "Path | None" = None
_LOG_FILE: "str | None" = None
_MAX_BYTES = 1_000_000
_BACKUP_COUNT = 3
_LOGGER_NAME = "audit"
_GENESIS = "GENESIS"


class _SystemUser:
    """Sentinel for audit events emitted by internal system operations."""
    username = "system"
    role = "system"
    clearance = "system"


_SYSTEM_USER = _SystemUser()

# Allowed action values — any other value fails closed.
VALID_ACTIONS: frozenset[str] = frozenset({
    "ENCRYPT", "DECRYPT", "KEY_ROTATE", "ACCESS_DENIED", "SIGN", "VERIFY",
})

# Crypto operations: events with these actions must carry a resolved key_id.
_CRYPTO_ACTIONS: frozenset[str] = frozenset({"ENCRYPT", "DECRYPT"})


class AuditLogError(Exception):
    """Raised when the audit log is corrupt or the hash chain cannot be established."""


def _read_last_hash() -> tuple[str, bool]:
    """Return (last_valid_hash, was_recovered).

    Scans the log backward to find the most recent valid JSON entry that
    carries a current_hash field. If the last entry is corrupt (truncated
    write, disk-full crash), the scan continues until a valid entry is found.

    was_recovered=True means at least one corrupt tail entry was skipped.
    was_recovered=False means the last entry was valid (or the log was empty).

    Raises AuditLogError only on OS-level read failure — not on JSON corruption.
    """
    log_path = _LOG_PATH if _LOG_PATH is not None else _get_audit_log_path()
    if not log_path.exists() or log_path.stat().st_size == 0:
        return _GENESIS, False
    try:
        raw = log_path.read_bytes()
    except OSError as exc:
        raise AuditLogError("Cannot read audit log: hash chain cannot be established") from exc

    lines = [line.strip() for line in reversed(raw.splitlines()) if line.strip()]
    if not lines:
        return _GENESIS, False

    # Try the most recent (last) entry first — the common, fast path.
    try:
        entry = json.loads(lines[0])
        if "current_hash" in entry:
            return entry["current_hash"], False
    except (json.JSONDecodeError, ValueError):
        pass

    # Last entry is corrupt. Scan backward to find the most recent valid entry.
    for line in lines[1:]:
        try:
            entry = json.loads(line)
            if "current_hash" in entry:
                return entry["current_hash"], True  # recovered from corruption
        except (json.JSONDecodeError, ValueError):
            continue

    # No valid entry found in the entire log — start a fresh chain from GENESIS.
    return _GENESIS, True


def check_chain() -> None:
    """Forward chain verification — raises AuditLogError on any linkage or hash violation.

    Iterates entries in write order. For each entry:
      - Verifies entry["previous_hash"] == expected (prior current_hash, or GENESIS).
      - Recomputes SHA256(previous_hash || JSON(entry_without_current_hash)) and
        verifies it matches entry["current_hash"].

    Raises AuditLogError on OS failure, corrupt JSON, broken linkage, or hash mismatch.
    Intended for spy-audit-repair and the verify-chain CLI command. Does not auto-recover.
    """
    log_path = _LOG_PATH if _LOG_PATH is not None else _get_audit_log_path()
    if not log_path.exists() or log_path.stat().st_size == 0:
        return
    try:
        raw = log_path.read_bytes()
    except OSError as exc:
        raise AuditLogError("Cannot read audit log") from exc

    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    expected = _GENESIS
    for i, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            raise AuditLogError(f"Corrupt entry at line {i + 1}: not valid JSON")

        if "previous_hash" not in entry or "current_hash" not in entry:
            raise AuditLogError(f"Entry at line {i + 1} missing hash fields")

        if entry["previous_hash"] != expected:
            raise AuditLogError(
                f"Chain broken at line {i + 1}: "
                f"expected previous_hash={expected!r}, got {entry['previous_hash']!r}"
            )

        without_hash = {k: v for k, v in entry.items() if k != "current_hash"}
        recomputed = _compute_hash(entry["previous_hash"], without_hash)
        if entry["current_hash"] != recomputed:
            raise AuditLogError(
                f"Hash mismatch at line {i + 1}: "
                f"stored={entry['current_hash']!r}, computed={recomputed!r}"
            )

        expected = entry["current_hash"]


def scan_audit_chain() -> tuple[str, int]:
    """Scan the full audit log and report corruption.

    Returns:
        (last_valid_hash, corrupt_entry_count) — the hash to chain from and
        the number of entries that could not be parsed.

    Raises AuditLogError on OS read failure.
    """
    log_path = _LOG_PATH if _LOG_PATH is not None else _get_audit_log_path()
    if not log_path.exists() or log_path.stat().st_size == 0:
        return _GENESIS, 0
    try:
        raw = log_path.read_bytes()
    except OSError as exc:
        raise AuditLogError("Cannot read audit log") from exc

    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    corrupt_count = 0
    last_valid_hash = _GENESIS

    for line in lines:
        try:
            entry = json.loads(line)
            if "current_hash" in entry:
                last_valid_hash = entry["current_hash"]
            else:
                corrupt_count += 1
        except (json.JSONDecodeError, ValueError):
            corrupt_count += 1

    return last_valid_hash, corrupt_count


def read_logs(filters: dict | None = None) -> list[dict]:
    """Read all audit log entries, optionally filtered by exact schema field values.

    Filter keys must match actual log field names: 'username', 'role', 'action', 'result'.
    Matching is case-insensitive substring. A missing key means no filter on that field.

    Returns entries sorted newest-first (by timestamp descending). Corrupt entries
    (no parseable timestamp) are appended after all clean entries.

    Corrupt lines are returned as entries with '_corrupt': True and '_raw': <line>
    so callers can surface the corruption count to users.

    Raises AuditLogError on OS read failure.
    """
    log_path = _LOG_PATH if _LOG_PATH is not None else _get_audit_log_path()
    if not log_path.exists() or log_path.stat().st_size == 0:
        return []
    try:
        raw = log_path.read_bytes()
    except OSError as exc:
        raise AuditLogError("Cannot read audit log") from exc

    clean: list[dict] = []
    corrupt: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            corrupt.append({"_corrupt": True, "_raw": line.decode("utf-8", errors="replace")})
            continue

        if filters:
            match = True
            for key, value in filters.items():
                if not value:
                    continue
                field_val = str(entry.get(key, "")).lower()
                if str(value).lower() not in field_val:
                    match = False
                    break
            if not match:
                continue

        clean.append(entry)

    clean.sort(key=lambda e: str(e.get("timestamp") or ""), reverse=True)
    return clean + corrupt


def export_logs(dest_path: str) -> str:
    """Copy the active audit log to dest_path directory with a timestamped filename.

    Also writes a SHA-256 sidecar file (<filename>.sha256) for export integrity.

    Args:
        dest_path: Destination directory (caller must ensure it's SAFE_AUDIT_OUTPUT_DIR).

    Returns:
        str path of the exported log file.

    Raises AuditLogError if: source log missing, destination outside safe root, or OS error.
    """
    log_path = _LOG_PATH if _LOG_PATH is not None else _get_audit_log_path()
    if not log_path.exists():
        raise AuditLogError("Audit log does not exist — nothing to export")

    if Path(dest_path).resolve() != _workspace_mod.SAFE_AUDIT_OUTPUT_DIR.resolve():
        raise AuditLogError("Export destination must be SAFE_AUDIT_OUTPUT_DIR")

    try:
        check_chain()
    except AuditLogError as exc:
        raise AuditLogError(f"Cannot export: audit chain verification failed — {exc}") from exc

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = Path(dest_path) / f"audit_export_{ts}.json"

    try:
        shutil.copy2(str(log_path), str(out_file))
    except OSError as exc:
        raise AuditLogError("Failed to export audit log") from exc

    # SHA-256 sidecar for integrity verification of the export artifact.
    try:
        digest = hashlib.sha256(out_file.read_bytes()).hexdigest()
        out_file.with_suffix(".json.sha256").write_text(f"{digest}  {out_file.name}\n", encoding="utf-8")
    except OSError as exc:
        raise AuditLogError("Failed to write export sidecar") from exc

    return str(out_file)


def _compute_hash(previous_hash: str, entry_without_current_hash: dict) -> str:
    """Compute SHA-256(previous_hash || JSON(entry)) with sort_keys for determinism."""
    serialized = json.dumps(entry_without_current_hash, sort_keys=True, separators=(",", ":"))
    payload = (previous_hash + serialized).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _get_logger() -> logging.Logger:
    """Return the audit logger, initializing its handler on first call."""
    logger = logging.getLogger(_LOGGER_NAME)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    logger.propagate = False
    log_file = _LOG_FILE if _LOG_FILE is not None else str(_get_audit_log_path())
    handler = _AuditRotatingFileHandler(log_file, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


def _write_recovery_event(previous_hash: str) -> str:
    """Write an AUDIT_RECOVERY sentinel entry. Returns the new current_hash.

    Written inline by log_event() when _read_last_hash() detects a corrupt tail.
    Not subject to VALID_ACTIONS validation — it is an internal chain-repair marker.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "AUDIT_RECOVERY",
        "role": None,
        "classification": "",
        "key_id": None,
        "result": "ERROR",
        "previous_hash": previous_hash,
    }
    current_hash = _compute_hash(previous_hash, event)
    event["current_hash"] = current_hash
    _get_logger().info(json.dumps(event, separators=(",", ":")))
    return current_hash


class _AuditRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler that preserves hash chain continuity across log rotation.

    Overrides emit() to intercept the record that triggers rotation, write an
    AUDIT_ROTATION sentinel as the first entry of the new file, then re-chain
    the triggering record so its previous_hash follows the sentinel rather than
    the pre-rotation last hash — preventing a chain fork.

    All writes to the new file go directly to self.stream to avoid re-entrant
    lock acquisition (emit() is called while the handler lock is held).
    Fails closed if the pre-rotation hash cannot be determined.
    """

    def emit(self, record: logging.LogRecord) -> None:
        if not self.shouldRollover(record):
            super().emit(record)
            return
        try:
            last_hash, _ = _read_last_hash()
        except AuditLogError as exc:
            raise AuditLogError(
                "Audit rotation failed: cannot determine previous hash"
            ) from exc
        self.doRollover()
        # Write AUDIT_ROTATION as first entry in the new file.
        rotation_event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "AUDIT_ROTATION",
            "role": None,
            "classification": "",
            "key_id": None,
            "result": "SUCCESS",
            "previous_hash": last_hash,
        }
        rotation_hash = _compute_hash(last_hash, rotation_event)
        rotation_event["current_hash"] = rotation_hash
        self.stream.write(json.dumps(rotation_event, separators=(",", ":")) + "\n")
        self.stream.flush()
        # Re-chain the triggering record to follow AUDIT_ROTATION.
        try:
            original = json.loads(record.getMessage())
            without_hash = {k: v for k, v in original.items() if k != "current_hash"}
            without_hash["previous_hash"] = rotation_hash
            new_hash = _compute_hash(rotation_hash, without_hash)
            without_hash["current_hash"] = new_hash
            new_record = logging.makeLogRecord(record.__dict__)
            new_record.msg = json.dumps(without_hash, separators=(",", ":"))
            new_record.args = None
            record = new_record
        except (json.JSONDecodeError, KeyError, ValueError):
            pass
        logging.FileHandler.emit(self, record)


class AuditLogger:
    """Append-only, hash-chained audit log writer.

    Each entry stores the previous entry's hash and its own hash over
    ``SHA256(previous_hash || canonical_entry)``, forming a tamper-evident chain
    that ``check_chain()`` verifies forward from GENESIS. Logging is a security
    control, not a side effect: callers treat a failure to append as a hard error
    and abort the audited operation (fail-closed), so an attacker cannot suppress
    the record of an action by breaking the log.
    """

    @staticmethod
    def log_event(
        user,
        action: str,
        classification: str = "",   # written to log
        outcome: str = "success",   # mapped: "success"→SUCCESS, "denied"→DENIED, else→ERROR
        *,
        key_id: str | None = None,
        reason: str | None = None,  # kept for caller compat; not written to log
    ) -> None:
        """Write a structured audit event to the rotating JSON log file.

        If the log tail was corrupt, an AUDIT_RECOVERY event is written first
        to document the chain break, then the normal event follows.

        Schema written to disk:
            timestamp, username, action, role, classification, key_id, result,
            previous_hash, current_hash

        Args:
            user: Source of username and role fields; None yields both as None.
            action: Must be one of VALID_ACTIONS; uppercase-normalized before validation.
            classification: Data classification level written to the log.
            outcome: 'success'→SUCCESS, 'denied'→DENIED, anything else→ERROR.
            key_id: Required for ENCRYPT and DECRYPT actions.
            reason: Kept for caller compatibility; not written to the log.

        Raises:
            AuditLogError: On OS read failure, invalid action, or missing key_id
                           for a crypto action. Corrupt tail entries are recovered
                           automatically — they do not raise.
        """
        previous_hash, was_recovered = _read_last_hash()

        # If the tail was corrupt, document the recovery before the normal event.
        if was_recovered:
            previous_hash = _write_recovery_event(previous_hash)

        # Normalize action to uppercase and validate against locked enum.
        action = action.upper() if isinstance(action, str) else action
        if action not in VALID_ACTIONS:
            raise AuditLogError(f"Invalid audit action: {action!r}")

        # Successful crypto operations must carry a resolved key_id — fail closed.
        # Failure paths may not yet have a key_id; they are permitted to omit it.
        if action in _CRYPTO_ACTIONS and key_id is None and outcome == "success":
            raise AuditLogError(f"Audit event for {action!r} requires a resolved key_id")

        # Map outcome to locked RESULT enum.
        if outcome == "success":
            result = "SUCCESS"
        elif outcome == "denied":
            result = "DENIED"
        else:
            result = "ERROR"

        username = getattr(user, "username", None)
        role = getattr(user, "role", None)

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "username": username,
            "action": action,
            "role": role,
            "classification": classification,
            "key_id": key_id,
            "result": result,
            "previous_hash": previous_hash,
        }

        current_hash = _compute_hash(previous_hash, event)
        event["current_hash"] = current_hash

        _get_logger().info(json.dumps(event, separators=(",", ":")))
