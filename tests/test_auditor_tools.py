"""
test_auditor_tools.py — P4.11 auditor read-only tools validation.

Tests:
  - read_logs: basic behavior, filtering (exact schema keys), corrupt line surfacing
  - export_logs: creates file + SHA-256 sidecar, raises on missing log / bad path
  - Permissions: auditor has view_logs/verify_audit/export_logs; cannot encrypt/decrypt
  - _cmd_view_logs / _cmd_verify_chain / _cmd_export_logs: access control + behavior
  - SAFE_AUDIT_OUTPUT_DIR: export always routed to workspace audit dir
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from spy.audit_logger import AuditLogError, export_logs, read_logs
from spy.auth_engine import _ROLE_PERMISSIONS, AuthorizationEngine
from spy.user_model import User
from tests.conftest import ws_patch, ws_restore


def _auditor(clearance: str = "low") -> User:
    return User(username="auditor1", role="auditor", clearance=clearance, authenticated=True)


def _analyst() -> User:
    return User(username="analyst1", role="analyst", clearance="medium", authenticated=True)


def _log_entry(action: str = "ENCRYPT", role: str = "analyst",
               result: str = "SUCCESS", key_id: str = "rsa-enc-v1",
               classification: str = "low", username: str = "analyst1") -> str:
    entry = {
        "timestamp": "2026-04-26T12:00:00Z",
        "username": username,
        "action": action,
        "role": role,
        "classification": classification,
        "key_id": key_id,
        "result": result,
        "previous_hash": "GENESIS",
        "current_hash": "abc123",
    }
    return json.dumps(entry)


def _valid_log_entry(previous_hash: str = "GENESIS", **overrides) -> str:
    """Build a log entry with a correctly computed current_hash for chain verification."""
    entry = {
        "timestamp": "2026-04-26T12:00:00Z",
        "username": "analyst1",
        "action": "ENCRYPT",
        "role": "analyst",
        "classification": "low",
        "key_id": "rsa-enc-v1",
        "result": "SUCCESS",
        "previous_hash": previous_hash,
        **overrides,
    }
    serialized = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    payload = (previous_hash + serialized).encode("utf-8")
    entry["current_hash"] = hashlib.sha256(payload).hexdigest()
    return json.dumps(entry)


# ---------------------------------------------------------------------------
# TestReadLogs
# ---------------------------------------------------------------------------

class TestReadLogs(unittest.TestCase):

    def _write_log(self, lines: list[str]) -> Path:
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return Path(path)

    def test_empty_log_returns_empty_list(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        Path(path).write_bytes(b"")
        try:
            with patch("spy.audit_logger._LOG_PATH", Path(path)):
                self.assertEqual(read_logs(), [])
        finally:
            Path(path).unlink(missing_ok=True)

    def test_missing_log_returns_empty_list(self):
        with patch("spy.audit_logger._LOG_PATH", Path("/nonexistent/audit_log.json")):
            self.assertEqual(read_logs(), [])

    def test_reads_all_entries(self):
        log = self._write_log([
            _log_entry("ENCRYPT"), _log_entry("DECRYPT"), _log_entry("KEY_ROTATE"),
        ])
        try:
            with patch("spy.audit_logger._LOG_PATH", log):
                entries = read_logs()
            self.assertEqual(len(entries), 3)
        finally:
            log.unlink(missing_ok=True)

    def test_filter_by_action_exact_key(self):
        log = self._write_log([
            _log_entry("ENCRYPT"), _log_entry("DECRYPT"), _log_entry("ENCRYPT"),
        ])
        try:
            with patch("spy.audit_logger._LOG_PATH", log):
                entries = read_logs({"action": "DECRYPT"})
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["action"], "DECRYPT")
        finally:
            log.unlink(missing_ok=True)

    def test_filter_by_result_exact_key(self):
        log = self._write_log([
            _log_entry(result="SUCCESS"), _log_entry(result="DENIED"),
            _log_entry(result="SUCCESS"),
        ])
        try:
            with patch("spy.audit_logger._LOG_PATH", log):
                entries = read_logs({"result": "DENIED"})
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["result"], "DENIED")
        finally:
            log.unlink(missing_ok=True)

    def test_filter_by_role_exact_key(self):
        log = self._write_log([
            _log_entry(role="admin"), _log_entry(role="analyst"), _log_entry(role="admin"),
        ])
        try:
            with patch("spy.audit_logger._LOG_PATH", log):
                entries = read_logs({"role": "admin"})
            self.assertEqual(len(entries), 2)
        finally:
            log.unlink(missing_ok=True)

    def test_corrupt_lines_surfaced_not_skipped(self):
        log = self._write_log([
            _log_entry("ENCRYPT"),
            "NOT VALID JSON {{{{",
            _log_entry("DECRYPT"),
        ])
        try:
            with patch("spy.audit_logger._LOG_PATH", log):
                entries = read_logs()
            corrupt = [e for e in entries if e.get("_corrupt")]
            clean = [e for e in entries if not e.get("_corrupt")]
            self.assertEqual(len(corrupt), 1)
            self.assertEqual(len(clean), 2)
            self.assertIn("_raw", corrupt[0])
        finally:
            log.unlink(missing_ok=True)

    def test_raises_audit_log_error_on_os_error(self):
        with patch("spy.audit_logger._LOG_PATH", Path("/nonexistent/path/audit.json")) as p:
            # Force the file to "exist" but fail on read
            with patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.stat") as mock_stat, \
                 patch("pathlib.Path.read_bytes", side_effect=OSError("disk error")):
                mock_stat.return_value.st_size = 100
                with self.assertRaises(AuditLogError):
                    read_logs()


# ---------------------------------------------------------------------------
# TestExportLogs
# ---------------------------------------------------------------------------

class TestExportLogs(unittest.TestCase):

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        # Write a log file with a properly hashed entry so check_chain() passes.
        fd, lp = tempfile.mkstemp(suffix=".json")
        os.write(fd, (_valid_log_entry() + "\n").encode())
        os.close(fd)
        self._log_path = Path(lp)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        self._log_path.unlink(missing_ok=True)

    def test_creates_export_file_in_dest_dir(self):
        dest = str(self._ws_root / "output" / "audit")
        with patch("spy.audit_logger._LOG_PATH", self._log_path):
            result = export_logs(dest)
        self.assertTrue(Path(result).exists())

    def test_export_filename_pattern(self):
        dest = str(self._ws_root / "output" / "audit")
        with patch("spy.audit_logger._LOG_PATH", self._log_path):
            result = export_logs(dest)
        name = Path(result).name
        self.assertTrue(name.startswith("audit_export_"))
        self.assertTrue(name.endswith(".json"))

    def test_export_creates_sha256_sidecar(self):
        dest = str(self._ws_root / "output" / "audit")
        with patch("spy.audit_logger._LOG_PATH", self._log_path):
            result = export_logs(dest)
        sidecar = Path(result).with_suffix(".json.sha256")
        self.assertTrue(sidecar.exists())
        content = sidecar.read_text()
        expected_hash = hashlib.sha256(Path(result).read_bytes()).hexdigest()
        self.assertIn(expected_hash, content)

    def test_export_content_matches_source(self):
        dest = str(self._ws_root / "output" / "audit")
        with patch("spy.audit_logger._LOG_PATH", self._log_path):
            result = export_logs(dest)
        self.assertEqual(Path(result).read_bytes(), self._log_path.read_bytes())

    def test_export_raises_if_log_missing(self):
        dest = str(self._ws_root / "output" / "audit")
        with patch("spy.audit_logger._LOG_PATH", Path("/nonexistent/audit.json")):
            with self.assertRaises(AuditLogError):
                export_logs(dest)

    def test_export_raises_if_outside_safe_root(self):
        with patch("spy.audit_logger._LOG_PATH", self._log_path):
            with self.assertRaises(AuditLogError):
                export_logs("/tmp/evil_export_dir")


# ---------------------------------------------------------------------------
# TestAuditorPermissions
# ---------------------------------------------------------------------------

class TestAuditorPermissions(unittest.TestCase):

    def test_auditor_has_view_logs(self):
        self.assertIn("view_logs", _ROLE_PERMISSIONS["auditor"])

    def test_auditor_has_verify_audit(self):
        self.assertIn("verify_audit", _ROLE_PERMISSIONS["auditor"])

    def test_auditor_has_export_logs(self):
        self.assertIn("export_logs", _ROLE_PERMISSIONS["auditor"])

    def test_auditor_cannot_encrypt(self):
        self.assertNotIn("encrypt", _ROLE_PERMISSIONS["auditor"])

    def test_auditor_cannot_decrypt(self):
        self.assertNotIn("decrypt", _ROLE_PERMISSIONS["auditor"])

    def test_admin_analyst_roles_unchanged(self):
        for role in ("admin", "analyst"):
            self.assertIn("encrypt", _ROLE_PERMISSIONS[role])
            self.assertIn("decrypt", _ROLE_PERMISSIONS[role])

    def test_authorize_auditor_view_logs(self):
        ok, _ = AuthorizationEngine.authorize(_auditor(), "view_logs", "low")
        self.assertTrue(ok)

    def test_authorize_analyst_view_logs_denied(self):
        ok, _ = AuthorizationEngine.authorize(_analyst(), "view_logs", "low")
        self.assertFalse(ok)

    def test_log_event_records_username_and_role(self):
        """log_event() must write username and role as separate fields."""
        from spy.audit_logger import AuditLogger
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            with patch("spy.audit_logger._LOG_PATH", Path(path)), \
                 patch("spy.audit_logger._LOG_FILE", path):
                logging.getLogger("audit").handlers.clear()
                AuditLogger.log_event(
                    _analyst(), "ACCESS_DENIED", classification="medium", outcome="denied",
                )
                entries = read_logs()
            self.assertEqual(len(entries), 1)
            e = entries[0]
            self.assertEqual(e.get("username"), "analyst1")
            self.assertEqual(e.get("role"), "analyst")
            self.assertEqual(e.get("classification"), "medium")
        finally:
            Path(path).unlink(missing_ok=True)
            logging.getLogger("audit").handlers.clear()


# ---------------------------------------------------------------------------
# TestCmdFunctions
# ---------------------------------------------------------------------------

class TestCmdFunctions(unittest.TestCase):

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        fd, lp = tempfile.mkstemp(suffix=".json")
        os.write(fd, (_valid_log_entry() + "\n").encode())
        os.close(fd)
        self._log_path = Path(lp)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        self._log_path.unlink(missing_ok=True)

    def test_view_logs_non_auditor_denied(self):
        from spy.cli import _cmd_view_logs
        rc = _cmd_view_logs(argparse.Namespace(role="", action="", result=""), _analyst())
        self.assertEqual(rc, 1)

    def test_view_logs_auditor_succeeds(self):
        from spy.cli import _cmd_view_logs
        with patch("spy.audit_logger._LOG_PATH", self._log_path), \
             patch("sys.stdout", new_callable=StringIO):
            rc = _cmd_view_logs(argparse.Namespace(role="", action="", result=""), _auditor())
        self.assertEqual(rc, 0)

    def test_verify_chain_non_auditor_denied(self):
        from spy.cli import _cmd_verify_chain
        rc = _cmd_verify_chain(argparse.Namespace(), _analyst())
        self.assertEqual(rc, 1)

    def test_verify_chain_clean_returns_0(self):
        from spy.cli import _cmd_verify_chain
        with patch("spy.audit_logger._LOG_PATH", self._log_path), \
             patch("sys.stdout", new_callable=StringIO):
            rc = _cmd_verify_chain(argparse.Namespace(), _auditor())
        self.assertEqual(rc, 0)

    def test_export_logs_non_auditor_denied(self):
        from spy.cli import _cmd_export_logs
        rc = _cmd_export_logs(argparse.Namespace(), _analyst())
        self.assertEqual(rc, 1)

    def test_export_logs_auditor_success(self):
        from spy.cli import _cmd_export_logs
        with patch("spy.audit_logger._LOG_PATH", self._log_path), \
             patch("sys.stdout", new_callable=StringIO):
            rc = _cmd_export_logs(argparse.Namespace(), _auditor())
        self.assertEqual(rc, 0)

    def test_export_uses_safe_audit_output_dir(self):
        from spy.cli import _cmd_export_logs
        import spy.workspace as ws_mod
        captured_dest = []

        def fake_export(dest: str) -> str:
            captured_dest.append(dest)
            return dest + "/audit_export_fake.json"

        with patch("spy.cli.export_logs", fake_export), \
             patch("sys.stdout", new_callable=StringIO):
            _cmd_export_logs(argparse.Namespace(), _auditor())

        expected = str(ws_mod.SAFE_AUDIT_OUTPUT_DIR)
        self.assertEqual(captured_dest[0], expected)


def _admin() -> User:
    return User(username="admin1", role="admin", clearance="high", authenticated=True)


def _unauthenticated() -> User:
    return User(username="nobody", role="admin", clearance="high")  # authenticated=False


# ---------------------------------------------------------------------------
# TestAuditRepairAuth
# ---------------------------------------------------------------------------

class TestAuditRepairAuth(unittest.TestCase):
    """audit-repair must require authenticated admin; denied attempts must be audited."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        fd, lp = tempfile.mkstemp(suffix=".json")
        os.write(fd, (_valid_log_entry() + "\n").encode())
        os.close(fd)
        self._log_path = Path(lp)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        self._log_path.unlink(missing_ok=True)

    def _repair(self, user):
        from spy.cli import _cmd_audit_repair
        with patch("sys.stderr", new_callable=StringIO), \
             patch("sys.stdout", new_callable=StringIO):
            return _cmd_audit_repair(argparse.Namespace(), user)

    def test_unauthenticated_user_blocked(self):
        self.assertEqual(self._repair(_unauthenticated()), 1)

    def test_analyst_blocked(self):
        self.assertEqual(self._repair(_analyst()), 1)

    def test_auditor_blocked(self):
        self.assertEqual(self._repair(_auditor()), 1)

    def test_admin_allowed(self):
        with patch("spy.audit_logger._LOG_PATH", self._log_path):
            rc = self._repair(_admin())
        self.assertEqual(rc, 0)

    def test_denied_attempt_emits_access_denied_audit(self):
        from unittest.mock import patch as mpatch
        from spy.audit_logger import AuditLogger
        with mpatch.object(AuditLogger, "log_event") as mock_log:
            self._repair(_analyst())
        calls = [c for c in mock_log.call_args_list
                 if c.kwargs.get("action") == "ACCESS_DENIED"]
        self.assertTrue(len(calls) >= 1, "Expected at least one ACCESS_DENIED audit event")


if __name__ == "__main__":
    unittest.main(verbosity=2)
