"""
test_audit_logger.py — Unit tests for audit_logger P1-B recovery behavior.

Tests the backward-scan recovery path, AUDIT_RECOVERY sentinel event,
check_chain() diagnostic, and scan_audit_chain() corpus scan.

Each test that exercises the logger creates a unique logger name so the
Python logging module never shares cached handlers between tests.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_raw_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _read_entries(path: Path) -> list[dict]:
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            pass
    return entries


def _make_valid_entry(previous_hash: str = "GENESIS") -> dict:
    """Build a minimal valid entry with a real current_hash."""
    import hashlib
    entry = {
        "timestamp": "2026-04-19T00:00:00+00:00",
        "action": "ENCRYPT",
        "role": "admin",
        "classification": "CONFIDENTIAL",
        "key_id": "rsa-enc-v1",
        "result": "SUCCESS",
        "previous_hash": previous_hash,
    }
    serialized = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    payload = (previous_hash + serialized).encode("utf-8")
    entry["current_hash"] = hashlib.sha256(payload).hexdigest()
    return entry


# ---------------------------------------------------------------------------
# Test: _read_last_hash()
# ---------------------------------------------------------------------------

class TestReadLastHash(unittest.TestCase):
    """_read_last_hash() returns correct (hash, was_recovered) tuples."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._log = Path(self._tmpdir.name) / "audit.json"

    def tearDown(self):
        self._tmpdir.cleanup()

    def _patch(self):
        return patch.multiple(
            "spy.audit_logger",
            _LOG_PATH=self._log,
            _LOG_FILE=str(self._log),
        )

    def test_empty_log_returns_genesis(self):
        with self._patch():
            from spy.audit_logger import _read_last_hash
            result, recovered = _read_last_hash()
        self.assertEqual(result, "GENESIS")
        self.assertFalse(recovered)

    def test_missing_file_returns_genesis(self):
        # Log file does not exist at all.
        with self._patch():
            from spy.audit_logger import _read_last_hash
            result, recovered = _read_last_hash()
        self.assertEqual(result, "GENESIS")
        self.assertFalse(recovered)

    def test_single_valid_entry_no_recovery(self):
        entry = _make_valid_entry("GENESIS")
        _write_raw_lines(self._log, [json.dumps(entry)])
        with self._patch():
            from spy.audit_logger import _read_last_hash
            result, recovered = _read_last_hash()
        self.assertEqual(result, entry["current_hash"])
        self.assertFalse(recovered)

    def test_multiple_valid_entries_returns_last(self):
        e1 = _make_valid_entry("GENESIS")
        e2 = _make_valid_entry(e1["current_hash"])
        e3 = _make_valid_entry(e2["current_hash"])
        _write_raw_lines(self._log, [json.dumps(e) for e in (e1, e2, e3)])
        with self._patch():
            from spy.audit_logger import _read_last_hash
            result, recovered = _read_last_hash()
        self.assertEqual(result, e3["current_hash"])
        self.assertFalse(recovered)

    def test_corrupt_last_entry_recovers_to_previous(self):
        e1 = _make_valid_entry("GENESIS")
        e2 = _make_valid_entry(e1["current_hash"])
        _write_raw_lines(self._log, [json.dumps(e1), json.dumps(e2), "NOT_JSON{{{"])
        with self._patch():
            from spy.audit_logger import _read_last_hash
            result, recovered = _read_last_hash()
        self.assertEqual(result, e2["current_hash"])
        self.assertTrue(recovered)

    def test_all_corrupt_entries_returns_genesis_recovered(self):
        _write_raw_lines(self._log, ["BADJSON{", "{{broken", "also bad"])
        with self._patch():
            from spy.audit_logger import _read_last_hash
            result, recovered = _read_last_hash()
        self.assertEqual(result, "GENESIS")
        self.assertTrue(recovered)

    def test_valid_entry_missing_current_hash_field_triggers_recovery(self):
        # Valid JSON but no current_hash — treated as corrupt for chaining purposes.
        no_hash = {"timestamp": "x", "action": "ENCRYPT"}
        e1 = _make_valid_entry("GENESIS")
        _write_raw_lines(self._log, [json.dumps(e1), json.dumps(no_hash)])
        with self._patch():
            from spy.audit_logger import _read_last_hash
            result, recovered = _read_last_hash()
        # Falls back to e1's hash.
        self.assertEqual(result, e1["current_hash"])
        self.assertTrue(recovered)


# ---------------------------------------------------------------------------
# Test: check_chain()
# ---------------------------------------------------------------------------

class TestCheckChain(unittest.TestCase):
    """check_chain() is diagnostic-only — raises on corruption, passes on clean log."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._log = Path(self._tmpdir.name) / "audit.json"

    def tearDown(self):
        self._tmpdir.cleanup()

    def _patch(self):
        return patch.multiple(
            "spy.audit_logger",
            _LOG_PATH=self._log,
            _LOG_FILE=str(self._log),
        )

    def test_clean_log_does_not_raise(self):
        e1 = _make_valid_entry("GENESIS")
        _write_raw_lines(self._log, [json.dumps(e1)])
        with self._patch():
            from spy.audit_logger import check_chain, AuditLogError
            check_chain()  # Must not raise.

    def test_empty_log_does_not_raise(self):
        with self._patch():
            from spy.audit_logger import check_chain
            check_chain()  # Empty log is clean.

    def test_corrupt_tail_raises_audit_log_error(self):
        e1 = _make_valid_entry("GENESIS")
        _write_raw_lines(self._log, [json.dumps(e1), "CORRUPT{{{"])
        with self._patch():
            from spy.audit_logger import check_chain, AuditLogError
            with self.assertRaises(AuditLogError):
                check_chain()

    def test_tampered_middle_entry_raises(self):
        """An entry whose previous_hash breaks linkage from the prior entry must raise."""
        e1 = _make_valid_entry("GENESIS")
        e2 = _make_valid_entry(e1["current_hash"])
        e3 = _make_valid_entry(e2["current_hash"])
        # Break e2: set previous_hash to a wrong value, recompute current_hash so
        # e2 is internally self-consistent but its linkage from e1 is broken.
        e2_tampered = dict(e2)
        e2_tampered["previous_hash"] = "deadbeef" * 8
        without = {k: v for k, v in e2_tampered.items() if k != "current_hash"}
        import hashlib as _hl
        serialized = json.dumps(without, sort_keys=True, separators=(",", ":"))
        e2_tampered["current_hash"] = _hl.sha256(
            (e2_tampered["previous_hash"] + serialized).encode("utf-8")
        ).hexdigest()
        _write_raw_lines(self._log, [json.dumps(e1), json.dumps(e2_tampered), json.dumps(e3)])
        with self._patch():
            from spy.audit_logger import check_chain, AuditLogError
            with self.assertRaises(AuditLogError):
                check_chain()

    def test_hash_mismatch_raises(self):
        """An entry whose current_hash doesn't match the recomputed value must raise."""
        e1 = _make_valid_entry("GENESIS")
        e1_bad = dict(e1)
        e1_bad["current_hash"] = "0" * 64
        _write_raw_lines(self._log, [json.dumps(e1_bad)])
        with self._patch():
            from spy.audit_logger import check_chain, AuditLogError
            with self.assertRaises(AuditLogError):
                check_chain()


# ---------------------------------------------------------------------------
# Test: scan_audit_chain()
# ---------------------------------------------------------------------------

class TestScanAuditChain(unittest.TestCase):
    """scan_audit_chain() reports the correct corrupt entry count."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._log = Path(self._tmpdir.name) / "audit.json"

    def tearDown(self):
        self._tmpdir.cleanup()

    def _patch(self):
        return patch.multiple(
            "spy.audit_logger",
            _LOG_PATH=self._log,
            _LOG_FILE=str(self._log),
        )

    def test_empty_log_zero_corrupt(self):
        with self._patch():
            from spy.audit_logger import scan_audit_chain
            last_hash, count = scan_audit_chain()
        self.assertEqual(last_hash, "GENESIS")
        self.assertEqual(count, 0)

    def test_all_valid_zero_corrupt(self):
        e1 = _make_valid_entry("GENESIS")
        e2 = _make_valid_entry(e1["current_hash"])
        _write_raw_lines(self._log, [json.dumps(e1), json.dumps(e2)])
        with self._patch():
            from spy.audit_logger import scan_audit_chain
            last_hash, count = scan_audit_chain()
        self.assertEqual(last_hash, e2["current_hash"])
        self.assertEqual(count, 0)

    def test_two_corrupt_entries_counted(self):
        e1 = _make_valid_entry("GENESIS")
        _write_raw_lines(self._log, [json.dumps(e1), "BAD1", "BAD2"])
        with self._patch():
            from spy.audit_logger import scan_audit_chain
            last_hash, count = scan_audit_chain()
        self.assertEqual(last_hash, e1["current_hash"])
        self.assertEqual(count, 2)


# ---------------------------------------------------------------------------
# Test: log_event() with AUDIT_RECOVERY
# ---------------------------------------------------------------------------

class TestLogEventRecovery(unittest.TestCase):
    """log_event() writes AUDIT_RECOVERY sentinel before the normal event when
    the log tail is corrupt, and chains correctly on a clean log.

    Each test uses a unique logger name to prevent RotatingFileHandler sharing.
    """

    _test_counter = 0

    def setUp(self):
        TestLogEventRecovery._test_counter += 1
        self._tmpdir = tempfile.TemporaryDirectory()
        self._log = Path(self._tmpdir.name) / "audit.json"
        # Unique logger name isolates handler registration per test.
        self._logger_name = f"audit_test_{TestLogEventRecovery._test_counter}"

    def tearDown(self):
        # Remove the test logger so its handler is not reused.
        lg = logging.getLogger(self._logger_name)
        for h in lg.handlers[:]:
            h.close()
            lg.removeHandler(h)
        logging.Logger.manager.loggerDict.pop(self._logger_name, None)
        self._tmpdir.cleanup()

    def _patch(self):
        return patch.multiple(
            "spy.audit_logger",
            _LOG_PATH=self._log,
            _LOG_FILE=str(self._log),
            _LOGGER_NAME=self._logger_name,
        )

    class _FakeUser:
        role = "admin"

    def test_clean_log_writes_single_event_no_recovery(self):
        with self._patch():
            from spy.audit_logger import AuditLogger
            AuditLogger.log_event(
                self._FakeUser(), action="ENCRYPT", key_id="rsa-enc-v1"
            )

        entries = _read_entries(self._log)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["action"], "ENCRYPT")
        self.assertEqual(entries[0]["result"], "SUCCESS")
        self.assertEqual(entries[0]["previous_hash"], "GENESIS")

    def test_corrupt_tail_triggers_recovery_event_then_normal_event(self):
        # Write two valid entries then a corrupt tail.
        e1 = _make_valid_entry("GENESIS")
        e2 = _make_valid_entry(e1["current_hash"])
        _write_raw_lines(self._log, [json.dumps(e1), json.dumps(e2), "CORRUPT{{{"])

        with self._patch():
            from spy.audit_logger import AuditLogger
            AuditLogger.log_event(
                self._FakeUser(), action="ENCRYPT", key_id="rsa-enc-v1"
            )

        entries = _read_entries(self._log)
        # Original 2 valid entries + AUDIT_RECOVERY + new ENCRYPT event.
        self.assertEqual(len(entries), 4, f"Expected 4 entries, got {len(entries)}: {entries}")
        actions = [e["action"] for e in entries]
        self.assertIn("AUDIT_RECOVERY", actions, f"AUDIT_RECOVERY not in {actions}")
        recovery_idx = actions.index("AUDIT_RECOVERY")
        self.assertEqual(actions[recovery_idx + 1], "ENCRYPT")

        # Recovery event chains from e2's hash.
        recovery_entry = entries[recovery_idx]
        self.assertEqual(recovery_entry["previous_hash"], e2["current_hash"])
        self.assertEqual(recovery_entry["result"], "ERROR")

        # Normal event chains from recovery's hash.
        normal_entry = entries[recovery_idx + 1]
        self.assertEqual(normal_entry["previous_hash"], recovery_entry["current_hash"])

    def test_corrupt_tail_does_not_raise(self):
        _write_raw_lines(self._log, ["TOTALLY_NOT_JSON"])
        with self._patch():
            from spy.audit_logger import AuditLogger
            # Must not raise — corruption auto-recovered.
            AuditLogger.log_event(
                self._FakeUser(), action="KEY_ROTATE"
            )

    def test_hash_chain_is_continuous_across_two_events(self):
        with self._patch():
            from spy.audit_logger import AuditLogger
            AuditLogger.log_event(
                self._FakeUser(), action="ENCRYPT", key_id="rsa-enc-v1"
            )
            AuditLogger.log_event(
                self._FakeUser(), action="DECRYPT", key_id="rsa-enc-v1"
            )

        entries = _read_entries(self._log)
        self.assertEqual(len(entries), 2)
        # Second entry's previous_hash must equal first entry's current_hash.
        self.assertEqual(entries[1]["previous_hash"], entries[0]["current_hash"])

    def test_denied_outcome_writes_denied_result(self):
        with self._patch():
            from spy.audit_logger import AuditLogger
            AuditLogger.log_event(
                self._FakeUser(), action="ACCESS_DENIED", outcome="denied"
            )

        entries = _read_entries(self._log)
        self.assertEqual(entries[0]["result"], "DENIED")

    def test_invalid_action_raises_audit_log_error(self):
        with self._patch():
            from spy.audit_logger import AuditLogger, AuditLogError
            with self.assertRaises(AuditLogError):
                AuditLogger.log_event(
                    self._FakeUser(), action="SIGN_UNKNOWN", key_id="rsa-sign-v1"
                )

    def test_crypto_action_without_key_id_raises(self):
        with self._patch():
            from spy.audit_logger import AuditLogger, AuditLogError
            with self.assertRaises(AuditLogError):
                AuditLogger.log_event(
                    self._FakeUser(), action="ENCRYPT"
                    # Missing key_id — must raise.
                )

    def test_all_corrupt_log_recovers_from_genesis(self):
        _write_raw_lines(self._log, ["BAD1", "BAD2", "BAD3"])
        with self._patch():
            from spy.audit_logger import AuditLogger
            AuditLogger.log_event(
                self._FakeUser(), action="KEY_ROTATE"
            )

        entries = _read_entries(self._log)
        # AUDIT_RECOVERY (chained from GENESIS) + KEY_ROTATE
        actions = [e["action"] for e in entries]
        self.assertIn("AUDIT_RECOVERY", actions)
        recovery = next(e for e in entries if e["action"] == "AUDIT_RECOVERY")
        self.assertEqual(recovery["previous_hash"], "GENESIS")


# ---------------------------------------------------------------------------
# Test: read_logs() robustness against corrupt entries (N-D1)
# ---------------------------------------------------------------------------

class TestReadLogsRobustness(unittest.TestCase):
    """read_logs() must not crash on null/missing timestamp or corrupt lines."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._log = Path(self._tmpdir.name) / "audit.json"

    def tearDown(self):
        self._tmpdir.cleanup()

    def _patch(self):
        return patch.multiple(
            "spy.audit_logger",
            _LOG_PATH=self._log,
            _LOG_FILE=str(self._log),
        )

    def test_read_logs_null_timestamp_does_not_crash(self):
        """Valid-JSON entry with "timestamp": null must not raise TypeError during sort."""
        entry = _make_valid_entry("GENESIS")
        null_entry = dict(entry)
        null_entry["timestamp"] = None
        _write_raw_lines(self._log, [json.dumps(entry), json.dumps(null_entry)])
        with self._patch():
            from spy.audit_logger import read_logs
            result = read_logs()
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        # Neither entry should be marked corrupt.
        self.assertFalse(any(e.get("_corrupt") for e in result))

    def test_read_logs_corrupt_entry_preserved(self):
        """Unparseable lines must appear as _corrupt entries, not be silently dropped."""
        entry = _make_valid_entry("GENESIS")
        _write_raw_lines(self._log, [json.dumps(entry), "NOT_VALID_JSON{{{"])
        with self._patch():
            from spy.audit_logger import read_logs
            result = read_logs()
        corrupt = [e for e in result if e.get("_corrupt")]
        self.assertEqual(len(corrupt), 1)
        self.assertIn("_raw", corrupt[0])

    def test_read_logs_valid_sort_unaffected(self):
        """Multiple clean entries with valid timestamps sort newest-first."""
        e1 = dict(_make_valid_entry("GENESIS"))
        e2 = dict(_make_valid_entry(e1.get("current_hash", "GENESIS")))
        e1["timestamp"] = "2026-01-01T00:00:00+00:00"
        e2["timestamp"] = "2026-06-01T00:00:00+00:00"
        _write_raw_lines(self._log, [json.dumps(e1), json.dumps(e2)])
        with self._patch():
            from spy.audit_logger import read_logs
            result = read_logs()
        clean = [e for e in result if not e.get("_corrupt")]
        self.assertEqual(len(clean), 2)
        self.assertEqual(clean[0]["timestamp"], "2026-06-01T00:00:00+00:00")
        self.assertEqual(clean[1]["timestamp"], "2026-01-01T00:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
