"""
test_sign_verify_audit.py — Batch 2: SIGN and VERIFY audit accountability.

Verifies:
  - _cmd_sign() emits SIGN audit event with authenticated user on success
  - _cmd_verify() emits VERIFY audit event with authenticated user on success
  - SIGN/VERIFY fail closed when AuditLogger.log_event raises AuditLogError
  - Error paths emit appropriate audit events
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

from spy.user_model import User


def _admin(username: str = "testadmin") -> User:
    return User(username=username, role="admin", clearance="high", authenticated=True)


def _make_args(**kwargs):
    """Build a minimal argparse.Namespace for sign/verify tests."""
    import argparse
    defaults = {"file": "", "output": None, "sig": "", "method": "rsa"}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestSignAudit(unittest.TestCase):
    """_cmd_sign() must emit a SIGN audit event and fail closed on audit failure."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._input = Path(self._tmp) / "plain.txt"
        self._input.write_bytes(b"hello")
        self._sig = Path(self._tmp) / "plain.txt.sig"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run_sign(self, user, extra_patches=None):
        from spy.cli import _cmd_sign
        args = _make_args(file=str(self._input), output=str(self._sig), method="rsa")
        mock_provider = MagicMock()
        mock_provider.get_active_rsa_signing_key_id.return_value = "rsa-sign-v1"
        mock_provider.get_rsa_signing_private_key.return_value = MagicMock()
        patches = {
            "spy.cli.LocalPemKeyProvider": MagicMock(return_value=mock_provider),
            "spy.cli.sign_stream": MagicMock(return_value=b"sig-bytes"),
            "spy.cli.encode_sig_file": MagicMock(return_value=b"encoded"),
        }
        if extra_patches:
            patches.update(extra_patches)
        with patch.multiple("spy.cli", **{k.replace("spy.cli.", ""): v for k, v in patches.items()}):
            with patch("spy.cli.LocalPemKeyProvider", patches["spy.cli.LocalPemKeyProvider"]):
                with patch("spy.cli.sign_stream", patches["spy.cli.sign_stream"]):
                    with patch("spy.cli.encode_sig_file", patches["spy.cli.encode_sig_file"]):
                        return _cmd_sign(args, user=user)

    def test_sign_success_emits_audit_with_user(self):
        from spy.cli import _cmd_sign
        from spy.audit_logger import AuditLogError
        args = _make_args(file=str(self._input), output=str(self._sig), method="rsa")
        user = _admin()
        mock_provider = MagicMock()
        mock_provider.get_active_rsa_signing_key_id.return_value = "rsa-sign-v1"
        mock_provider.get_rsa_signing_private_key.return_value = MagicMock()

        captured_calls = []

        def capture_log(u, **kwargs):
            captured_calls.append((u, kwargs))

        with patch("spy.cli.LocalPemKeyProvider", return_value=mock_provider):
            with patch("spy.cli.sign_stream", return_value=b"sig"):
                with patch("spy.cli.encode_sig_file", return_value=b"enc"):
                    with patch("spy.cli.AuditLogger") as mock_audit:
                        mock_audit.log_event.side_effect = capture_log
                        result = _cmd_sign(args, user=user)

        self.assertEqual(result, 0)
        self.assertEqual(len(captured_calls), 1)
        logged_user, logged_kwargs = captured_calls[0]
        self.assertIs(logged_user, user)
        self.assertEqual(logged_kwargs["action"], "SIGN")
        self.assertEqual(logged_kwargs["outcome"], "success")
        self.assertEqual(logged_kwargs["key_id"], "rsa-sign-v1")

    def test_sign_audit_failure_fails_closed(self):
        from spy.cli import _cmd_sign
        from spy.audit_logger import AuditLogError
        args = _make_args(file=str(self._input), output=str(self._sig), method="rsa")
        user = _admin()
        mock_provider = MagicMock()
        mock_provider.get_active_rsa_signing_key_id.return_value = "rsa-sign-v1"
        mock_provider.get_rsa_signing_private_key.return_value = MagicMock()

        with patch("spy.cli.LocalPemKeyProvider", return_value=mock_provider):
            with patch("spy.cli.sign_stream", return_value=b"sig"):
                with patch("spy.cli.encode_sig_file", return_value=b"enc"):
                    with patch("spy.cli.AuditLogger") as mock_audit:
                        mock_audit.log_event.side_effect = AuditLogError("disk full")
                        result = _cmd_sign(args, user=user)

        self.assertEqual(result, 1)

    def test_sign_error_emits_audit(self):
        from spy.cli import _cmd_sign
        from spy.signature_engine import SignatureError
        args = _make_args(file=str(self._input), output=str(self._sig), method="rsa")
        user = _admin()
        mock_provider = MagicMock()
        mock_provider.get_active_rsa_signing_key_id.return_value = "rsa-sign-v1"
        mock_provider.get_rsa_signing_private_key.return_value = MagicMock()

        captured_calls = []

        def capture_log(u, **kwargs):
            captured_calls.append((u, kwargs))

        with patch("spy.cli.LocalPemKeyProvider", return_value=mock_provider):
            with patch("spy.cli.sign_stream", side_effect=SignatureError("bad")):
                with patch("spy.cli.AuditLogger") as mock_audit:
                    mock_audit.log_event.side_effect = capture_log
                    result = _cmd_sign(args, user=user)

        self.assertEqual(result, 1)
        self.assertEqual(len(captured_calls), 1)
        _, logged_kwargs = captured_calls[0]
        self.assertEqual(logged_kwargs["action"], "SIGN")
        self.assertEqual(logged_kwargs["outcome"], "error")


class TestVerifyAudit(unittest.TestCase):
    """_cmd_verify() must emit a VERIFY audit event and fail closed on audit failure."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._input = Path(self._tmp) / "plain.txt"
        self._input.write_bytes(b"hello")
        self._sig = Path(self._tmp) / "plain.txt.sig"
        self._sig.write_bytes(b"dummy-sig-content")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_verify_success_emits_audit_with_user(self):
        from spy.cli import _cmd_verify
        import argparse
        args = argparse.Namespace(file=str(self._input), sig=str(self._sig))
        user = _admin()
        mock_provider = MagicMock()
        mock_provider.get_signing_public_key.return_value = MagicMock()

        captured_calls = []

        def capture_log(u, **kwargs):
            captured_calls.append((u, kwargs))

        with patch("spy.cli.decode_sig_file_full", return_value=("rsa", b"sig", "rsa-sign-v1")):
            with patch("spy.cli.LocalPemKeyProvider", return_value=mock_provider):
                with patch("spy.cli.verify_stream", return_value=None):
                    with patch("spy.cli.AuditLogger") as mock_audit:
                        mock_audit.log_event.side_effect = capture_log
                        result = _cmd_verify(args, user=user)

        self.assertEqual(result, 0)
        self.assertEqual(len(captured_calls), 1)
        logged_user, logged_kwargs = captured_calls[0]
        self.assertIs(logged_user, user)
        self.assertEqual(logged_kwargs["action"], "VERIFY")
        self.assertEqual(logged_kwargs["outcome"], "success")
        self.assertEqual(logged_kwargs["key_id"], "rsa-sign-v1")

    def test_verify_audit_failure_fails_closed(self):
        from spy.cli import _cmd_verify
        from spy.audit_logger import AuditLogError
        import argparse
        args = argparse.Namespace(file=str(self._input), sig=str(self._sig))
        user = _admin()
        mock_provider = MagicMock()
        mock_provider.get_signing_public_key.return_value = MagicMock()

        with patch("spy.cli.decode_sig_file_full", return_value=("rsa", b"sig", "rsa-sign-v1")):
            with patch("spy.cli.LocalPemKeyProvider", return_value=mock_provider):
                with patch("spy.cli.verify_stream", return_value=None):
                    with patch("spy.cli.AuditLogger") as mock_audit:
                        mock_audit.log_event.side_effect = AuditLogError("disk full")
                        result = _cmd_verify(args, user=user)

        self.assertEqual(result, 1)

    def test_verify_invalid_signature_emits_denied_audit(self):
        from spy.cli import _cmd_verify
        from spy.signature_engine import SignatureError
        import argparse
        args = argparse.Namespace(file=str(self._input), sig=str(self._sig))
        user = _admin()
        mock_provider = MagicMock()
        mock_provider.get_signing_public_key.return_value = MagicMock()

        captured_calls = []

        def capture_log(u, **kwargs):
            captured_calls.append((u, kwargs))

        with patch("spy.cli.decode_sig_file_full", return_value=("rsa", b"sig", "rsa-sign-v1")):
            with patch("spy.cli.LocalPemKeyProvider", return_value=mock_provider):
                with patch("spy.cli.verify_stream", side_effect=SignatureError("tampered")):
                    with patch("spy.cli.AuditLogger") as mock_audit:
                        mock_audit.log_event.side_effect = capture_log
                        result = _cmd_verify(args, user=user)

        self.assertEqual(result, 2)
        self.assertEqual(len(captured_calls), 1)
        _, logged_kwargs = captured_calls[0]
        self.assertEqual(logged_kwargs["action"], "VERIFY")
        self.assertEqual(logged_kwargs["outcome"], "denied")

    def test_verify_corrupt_sig_file_emits_error_audit(self):
        from spy.cli import _cmd_verify
        from spy.signature_engine import SignatureError
        import argparse
        args = argparse.Namespace(file=str(self._input), sig=str(self._sig))
        user = _admin()

        captured_calls = []

        def capture_log(u, **kwargs):
            captured_calls.append((u, kwargs))

        with patch("spy.cli.decode_sig_file_full", side_effect=SignatureError("corrupt")):
            with patch("spy.cli.AuditLogger") as mock_audit:
                mock_audit.log_event.side_effect = capture_log
                result = _cmd_verify(args, user=user)

        self.assertEqual(result, 1)
        self.assertEqual(len(captured_calls), 1)
        _, logged_kwargs = captured_calls[0]
        self.assertEqual(logged_kwargs["action"], "VERIFY")
        self.assertEqual(logged_kwargs["outcome"], "error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
