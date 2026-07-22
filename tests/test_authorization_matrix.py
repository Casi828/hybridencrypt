"""
test_authorization_matrix.py — Full role × clearance × classification matrix tests.

Covers:
  - _check_access() unit tests for all combinations
  - stream_encrypt_file / stream_decrypt_file integration tests verifying
    fail-closed behavior (no output file created on denial)
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spy.file_crypto_engine import FileCryptoError, _check_access
from spy.user_model import User

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _user(role: str, clearance: str, authenticated: bool = True) -> User:
    return User(username="testuser", role=role, clearance=clearance,
                authenticated=authenticated)


# ---------------------------------------------------------------------------
# Unit tests — _check_access directly
# ---------------------------------------------------------------------------

class TestCheckAccessNoneUser(unittest.TestCase):
    """user=None (system/internal call) must always pass."""

    def test_none_user_encrypt_passes(self):
        _check_access(None, "high", "encrypt")  # must not raise

    def test_none_user_decrypt_passes(self):
        _check_access(None, "high", "decrypt")


class TestCheckAccessUnauthenticated(unittest.TestCase):
    """Unauthenticated users are always denied."""

    def _assert_denied(self, role, clearance, classification, action):
        with self.assertRaises(FileCryptoError):
            _check_access(_user(role, clearance, authenticated=False), classification, action)

    def test_unauthenticated_admin_encrypt(self):
        self._assert_denied("admin", "high", "low", "encrypt")

    def test_unauthenticated_analyst_decrypt(self):
        self._assert_denied("analyst", "high", "low", "decrypt")


class TestCheckAccessAuditor(unittest.TestCase):
    """Auditor is denied for all actions and classifications."""

    def _assert_denied(self, clearance, classification, action):
        with self.assertRaises(FileCryptoError):
            _check_access(_user("auditor", clearance), classification, action)

    def test_auditor_high_encrypt_high(self):
        self._assert_denied("high", "high", "encrypt")

    def test_auditor_high_encrypt_medium(self):
        self._assert_denied("high", "medium", "encrypt")

    def test_auditor_high_encrypt_low(self):
        self._assert_denied("high", "low", "encrypt")

    def test_auditor_high_decrypt_high(self):
        self._assert_denied("high", "high", "decrypt")

    def test_auditor_high_decrypt_medium(self):
        self._assert_denied("high", "medium", "decrypt")

    def test_auditor_high_decrypt_low(self):
        self._assert_denied("high", "low", "decrypt")

    def test_auditor_low_decrypt_low(self):
        self._assert_denied("low", "low", "decrypt")


class TestCheckAccessAdminMatrix(unittest.TestCase):
    """Admin: encrypt/decrypt allowed when clearance >= classification."""

    def _ok(self, clearance, classification, action):
        _check_access(_user("admin", clearance), classification, action)  # no raise

    def _denied(self, clearance, classification, action):
        with self.assertRaises(FileCryptoError):
            _check_access(_user("admin", clearance), classification, action)

    # admin/high — all pass
    def test_admin_high_encrypt_high(self):   self._ok("high", "high", "encrypt")
    def test_admin_high_encrypt_medium(self): self._ok("high", "medium", "encrypt")
    def test_admin_high_encrypt_low(self):    self._ok("high", "low", "encrypt")
    def test_admin_high_decrypt_high(self):   self._ok("high", "high", "decrypt")
    def test_admin_high_decrypt_medium(self): self._ok("high", "medium", "decrypt")
    def test_admin_high_decrypt_low(self):    self._ok("high", "low", "decrypt")

    # admin/medium — high denied
    def test_admin_medium_encrypt_medium(self): self._ok("medium", "medium", "encrypt")
    def test_admin_medium_encrypt_low(self):    self._ok("medium", "low", "encrypt")
    def test_admin_medium_encrypt_high(self):   self._denied("medium", "high", "encrypt")
    def test_admin_medium_decrypt_medium(self): self._ok("medium", "medium", "decrypt")
    def test_admin_medium_decrypt_low(self):    self._ok("medium", "low", "decrypt")
    def test_admin_medium_decrypt_high(self):   self._denied("medium", "high", "decrypt")

    # admin/low — only low passes
    def test_admin_low_encrypt_low(self):    self._ok("low", "low", "encrypt")
    def test_admin_low_encrypt_medium(self): self._denied("low", "medium", "encrypt")
    def test_admin_low_encrypt_high(self):   self._denied("low", "high", "encrypt")
    def test_admin_low_decrypt_low(self):    self._ok("low", "low", "decrypt")
    def test_admin_low_decrypt_medium(self): self._denied("low", "medium", "decrypt")
    def test_admin_low_decrypt_high(self):   self._denied("low", "high", "decrypt")


class TestCheckAccessAnalystMatrix(unittest.TestCase):
    """Analyst: encrypt and decrypt both allowed when clearance >= classification."""

    def _ok(self, clearance, classification, action):
        _check_access(_user("analyst", clearance), classification, action)

    def _denied(self, clearance, classification, action):
        with self.assertRaises(FileCryptoError):
            _check_access(_user("analyst", clearance), classification, action)

    # analyst/high — all pass
    def test_analyst_high_encrypt_high(self):   self._ok("high", "high", "encrypt")
    def test_analyst_high_encrypt_medium(self): self._ok("high", "medium", "encrypt")
    def test_analyst_high_encrypt_low(self):    self._ok("high", "low", "encrypt")
    def test_analyst_high_decrypt_high(self):   self._ok("high", "high", "decrypt")
    def test_analyst_high_decrypt_medium(self): self._ok("high", "medium", "decrypt")
    def test_analyst_high_decrypt_low(self):    self._ok("high", "low", "decrypt")

    # analyst/medium
    def test_analyst_medium_decrypt_low(self):    self._ok("medium", "low", "decrypt")
    def test_analyst_medium_decrypt_medium(self): self._ok("medium", "medium", "decrypt")
    def test_analyst_medium_decrypt_high(self):   self._denied("medium", "high", "decrypt")
    def test_analyst_medium_encrypt_low(self):    self._ok("medium", "low", "encrypt")
    def test_analyst_medium_encrypt_medium(self): self._ok("medium", "medium", "encrypt")
    def test_analyst_medium_encrypt_high(self):   self._denied("medium", "high", "encrypt")

    # analyst/low
    def test_analyst_low_decrypt_low(self):    self._ok("low", "low", "decrypt")
    def test_analyst_low_decrypt_medium(self): self._denied("low", "medium", "decrypt")
    def test_analyst_low_decrypt_high(self):   self._denied("low", "high", "decrypt")
    def test_analyst_low_encrypt_low(self):    self._ok("low", "low", "encrypt")
    def test_analyst_low_encrypt_medium(self): self._denied("low", "medium", "encrypt")
    def test_analyst_low_encrypt_high(self):   self._denied("low", "high", "encrypt")


# ---------------------------------------------------------------------------
# Integration tests — through stream_encrypt_file / stream_decrypt_file
# verifying fail-closed: no output file created on denial
# ---------------------------------------------------------------------------

class TestFailClosedEncrypt(unittest.TestCase):
    """Denied encrypt must raise FileCryptoError and produce no output file."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _src(self, content: bytes = b"test plaintext") -> str:
        p = Path(self._tmpdir) / "plain.txt"
        p.write_bytes(content)
        return str(p)

    def _enc_path(self, src: str) -> str:
        return src + ".enc"

    def test_auditor_encrypt_denied_no_output(self):
        from spy.file_crypto_engine import stream_encrypt_file
        src = self._src()
        enc = self._enc_path(src)
        user = _user("auditor", "high")
        with self.assertRaises(FileCryptoError):
            stream_encrypt_file(src, output_path=enc, user=user, context={})
        self.assertFalse(Path(enc).exists(), "Output file must not be created on denial")

    def test_insufficient_clearance_encrypt_denied_no_output(self):
        # low-clearance user + sensitive context → policy=high, floor=low → high classification
        # _check_access(low, "high", "encrypt") → denied
        from spy.file_crypto_engine import stream_encrypt_file
        src = self._src()
        enc = self._enc_path(src)
        user = _user("analyst", "low")
        with self.assertRaises(FileCryptoError):
            stream_encrypt_file(src, output_path=enc, user=user, context={"sensitive": True})
        self.assertFalse(Path(enc).exists(), "Output file must not be created on denial")

    def test_unauthenticated_encrypt_denied_no_output(self):
        from spy.file_crypto_engine import stream_encrypt_file
        src = self._src()
        enc = self._enc_path(src)
        user = _user("admin", "high", authenticated=False)
        with self.assertRaises(FileCryptoError):
            stream_encrypt_file(src, output_path=enc, user=user, context={})
        self.assertFalse(Path(enc).exists(), "Output file must not be created on denial")


class TestFailClosedDecrypt(unittest.TestCase):
    """Denied decrypt must raise FileCryptoError and produce no output file."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        # Stub .enc file: SVST magic + padding (enough to pass magic check)
        self._enc = Path(self._tmpdir) / "stub.enc"
        self._enc.write_bytes(b"SVST" + b"\x00" * 64)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _out_path(self) -> str:
        return str(Path(self._tmpdir) / "stub")

    def test_auditor_decrypt_denied_no_output(self):
        from spy.file_crypto_engine import stream_decrypt_file
        out = self._out_path()
        user = _user("auditor", "high")
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(str(self._enc), output_path=out,
                                user=user)
        self.assertFalse(Path(out).exists(), "Output file must not be created on denial")

    def test_insufficient_clearance_decrypt_denied_no_output(self):
        from spy.file_crypto_engine import stream_decrypt_file
        out = self._out_path()
        user = _user("analyst", "low")
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(str(self._enc), output_path=out,
                                user=user)
        self.assertFalse(Path(out).exists(), "Output file must not be created on denial")

    def test_unauthenticated_decrypt_denied_no_output(self):
        from spy.file_crypto_engine import stream_decrypt_file
        out = self._out_path()
        user = _user("admin", "high", authenticated=False)
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(str(self._enc), output_path=out,
                                user=user)
        self.assertFalse(Path(out).exists(), "Output file must not be created on denial")


class TestInfrastructureActions(unittest.TestCase):
    """AuthorizationEngine correctly gates admin-only infrastructure actions."""

    def test_admin_allowed_rewrap(self):
        from spy.auth_engine import AuthorizationEngine
        user = _user("admin", "high")
        allowed, _ = AuthorizationEngine.authorize(user, "rewrap", "low")
        self.assertTrue(allowed)

    def test_analyst_denied_rewrap(self):
        from spy.auth_engine import AuthorizationEngine
        user = _user("analyst", "high")
        allowed, _ = AuthorizationEngine.authorize(user, "rewrap", "low")
        self.assertFalse(allowed)

    def test_auditor_denied_rewrap(self):
        from spy.auth_engine import AuthorizationEngine
        user = _user("auditor", "high")
        allowed, _ = AuthorizationEngine.authorize(user, "rewrap", "low")
        self.assertFalse(allowed)

    def test_admin_allowed_rotate_keys(self):
        from spy.auth_engine import AuthorizationEngine
        user = _user("admin", "high")
        allowed, _ = AuthorizationEngine.authorize(user, "rotate_keys", "low")
        self.assertTrue(allowed)


# ---------------------------------------------------------------------------
# N-A1 — AuthorizationEngine must reject unauthenticated users
# ---------------------------------------------------------------------------

class TestAuthorizationEngineUnauthenticated(unittest.TestCase):
    """AuthorizationEngine.authorize() must be self-defending: authenticated=False
    always returns (False, 'Not authenticated') regardless of role or clearance."""

    def setUp(self):
        from spy.auth_engine import AuthorizationEngine
        self.engine = AuthorizationEngine

    def test_unauthenticated_admin_denied(self):
        user = _user("admin", "high", authenticated=False)
        allowed, reason = self.engine.authorize(user, "encrypt", "low")
        self.assertFalse(allowed)
        self.assertEqual(reason, "Not authenticated")

    def test_unauthenticated_analyst_denied(self):
        user = _user("analyst", "high", authenticated=False)
        allowed, reason = self.engine.authorize(user, "decrypt", "low")
        self.assertFalse(allowed)
        self.assertEqual(reason, "Not authenticated")

    def test_missing_authenticated_field_denied(self):
        """Object without authenticated attribute must be treated as unauthenticated."""
        class _Bare:
            role = "admin"
            clearance = "high"
        allowed, reason = self.engine.authorize(_Bare(), "encrypt", "low")
        self.assertFalse(allowed)
        self.assertEqual(reason, "Not authenticated")

    def test_authenticated_admin_still_passes(self):
        """Regression: authenticated admin must not be broken by the new check."""
        user = _user("admin", "high", authenticated=True)
        allowed, _ = self.engine.authorize(user, "encrypt", "low")
        self.assertTrue(allowed)

    def test_authenticated_analyst_still_passes(self):
        user = _user("analyst", "high", authenticated=True)
        allowed, _ = self.engine.authorize(user, "encrypt", "low")
        self.assertTrue(allowed)


# ---------------------------------------------------------------------------
# N-A2 — _require_admin must reject unauthenticated users
# ---------------------------------------------------------------------------

class TestRequireAdmin(unittest.TestCase):
    """_require_admin() must check authentication before role."""

    def setUp(self):
        from spy.cli import _require_admin
        self._require_admin = _require_admin

    def test_unauthenticated_admin_denied(self):
        user = _user("admin", "high", authenticated=False)
        result = self._require_admin(user)
        self.assertEqual(result, 1)

    def test_unauthenticated_analyst_denied(self):
        user = _user("analyst", "high", authenticated=False)
        result = self._require_admin(user)
        self.assertEqual(result, 1)

    def test_authenticated_admin_passes(self):
        user = _user("admin", "high", authenticated=True)
        result = self._require_admin(user)
        self.assertIsNone(result)

    def test_authenticated_non_admin_denied(self):
        user = _user("analyst", "high", authenticated=True)
        result = self._require_admin(user)
        self.assertEqual(result, 1)

    def test_none_user_denied(self):
        result = self._require_admin(None)
        self.assertEqual(result, 1)


# ---------------------------------------------------------------------------
# Batch 2 — Audit tool authorization: verify_audit and export_logs
# ---------------------------------------------------------------------------

class TestAuditToolAuthorization(unittest.TestCase):
    """verify_audit and export_logs are accessible to admin and auditor; denied for analyst."""

    def setUp(self):
        from spy.auth_engine import AuthorizationEngine
        self.engine = AuthorizationEngine

    def test_admin_can_verify_audit(self):
        user = _user("admin", "high")
        allowed, _ = self.engine.authorize(user, "verify_audit", "low")
        self.assertTrue(allowed)

    def test_admin_can_export_logs(self):
        user = _user("admin", "high")
        allowed, _ = self.engine.authorize(user, "export_logs", "low")
        self.assertTrue(allowed)

    def test_auditor_can_verify_audit(self):
        user = _user("auditor", "high")
        allowed, _ = self.engine.authorize(user, "verify_audit", "low")
        self.assertTrue(allowed)

    def test_auditor_can_export_logs(self):
        user = _user("auditor", "high")
        allowed, _ = self.engine.authorize(user, "export_logs", "low")
        self.assertTrue(allowed)

    def test_analyst_denied_verify_audit(self):
        user = _user("analyst", "high")
        allowed, _ = self.engine.authorize(user, "verify_audit", "low")
        self.assertFalse(allowed)

    def test_analyst_denied_export_logs(self):
        user = _user("analyst", "high")
        allowed, _ = self.engine.authorize(user, "export_logs", "low")
        self.assertFalse(allowed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
