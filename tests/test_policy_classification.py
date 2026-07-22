"""
test_policy_classification.py — Policy engine classification and clearance-minimum floor.

Verifies:
  - determine_classification maps context signals to classification deterministically
  - stream_encrypt_file always uses policy classification, never caller-supplied
  - Clearance minimum (no-write-down): user cannot produce a container classified below their clearance
  - user=None (system call) uses policy result directly, no clearance floor applied
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from spy.policy_engine import PolicyError, determine_classification
from spy.user_model import User
from tests.conftest import ws_patch, ws_restore


def _user(role: str, clearance: str, authenticated: bool = True) -> User:
    return User(username="testuser", role=role, clearance=clearance,
                authenticated=authenticated)


# ---------------------------------------------------------------------------
# TestDetermineClassification — pure policy function
# ---------------------------------------------------------------------------

class TestDetermineClassification(unittest.TestCase):

    def test_sensitive_returns_high(self):
        self.assertEqual(determine_classification({"sensitive": True}), "high")

    def test_sensitive_truthy_string(self):
        self.assertEqual(determine_classification({"sensitive": "yes"}), "high")

    def test_internal_returns_medium(self):
        self.assertEqual(determine_classification({"internal": True}), "medium")

    def test_empty_context_returns_low(self):
        self.assertEqual(determine_classification({}), "low")

    def test_unrecognized_keys_return_low(self):
        self.assertEqual(determine_classification({"public": True, "open": True}), "low")

    def test_sensitive_takes_priority_over_internal(self):
        self.assertEqual(determine_classification({"sensitive": True, "internal": True}), "high")

    def test_false_sensitive_with_internal_returns_medium(self):
        self.assertEqual(determine_classification({"sensitive": False, "internal": True}), "medium")

    def test_non_dict_raises_policy_error(self):
        with self.assertRaises(PolicyError):
            determine_classification("high")

    def test_non_dict_integer_raises_policy_error(self):
        with self.assertRaises(PolicyError):
            determine_classification(42)

    def test_non_dict_list_raises_policy_error(self):
        with self.assertRaises(PolicyError):
            determine_classification(["sensitive"])

    def test_result_always_in_valid_set(self):
        valid = {"low", "medium", "high"}
        for ctx in [{}, {"sensitive": True}, {"internal": True},
                    {"sensitive": False}, {"other": "value"}]:
            self.assertIn(determine_classification(ctx), valid)


# ---------------------------------------------------------------------------
# TestClearanceMinimumFloor — through stream_encrypt_file
# ---------------------------------------------------------------------------

class TestClearanceMinimumFloor(unittest.TestCase):
    """User clearance sets the minimum classification — high user cannot write low."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)

    def _src(self, content: bytes = b"data") -> str:
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
        return path

    def _read_container_classification(self, enc_path: str) -> str | None:
        from spy.container_reader import StreamingContainerReader
        from spy.file_crypto_engine import _make_svst_sign_key_resolver
        from spy.key_provider import LocalPemKeyProvider
        provider = LocalPemKeyProvider()
        with open(enc_path, "rb") as f:
            reader = StreamingContainerReader(f)
            header = reader.read_and_verify_header(_make_svst_sign_key_resolver(provider))
        return header.classification

    def test_high_clearance_user_empty_context_produces_high_container(self):
        """High-clearance user + no signals → clearance floor raises to 'high'."""
        from spy.file_crypto_engine import stream_encrypt_file
        src = self._src()
        user = _user("admin", "high")
        enc = stream_encrypt_file(src, output_path=None, user=user, context={})
        self.assertEqual(self._read_container_classification(enc), "high")

    def test_medium_clearance_user_empty_context_produces_medium_container(self):
        """Medium-clearance user + no signals → clearance floor raises to 'medium'."""
        from spy.file_crypto_engine import stream_encrypt_file
        src = self._src()
        user = _user("analyst", "medium")
        enc = stream_encrypt_file(src, output_path=None, user=user, context={})
        self.assertEqual(self._read_container_classification(enc), "medium")

    def test_low_clearance_user_empty_context_produces_low_container(self):
        from spy.file_crypto_engine import stream_encrypt_file
        src = self._src()
        user = _user("analyst", "low")
        enc = stream_encrypt_file(src, output_path=None, user=user, context={})
        self.assertEqual(self._read_container_classification(enc), "low")

    def test_system_call_no_user_empty_context_produces_high_container(self):
        """No user (system call) → SYSTEM_CLEARANCE='high' floor; 'low' policy result raised to 'high'."""
        from spy.file_crypto_engine import stream_encrypt_file
        src = self._src()
        enc = stream_encrypt_file(src, output_path=None, context={})
        self.assertEqual(self._read_container_classification(enc), "high")

    def test_system_call_no_user_internal_context_produces_high_container(self):
        """No user + internal signal → policy='medium', SYSTEM_CLEARANCE floor raises to 'high'."""
        from spy.file_crypto_engine import stream_encrypt_file
        src = self._src()
        enc = stream_encrypt_file(src, output_path=None, context={"internal": True})
        self.assertEqual(self._read_container_classification(enc), "high")

    def test_system_call_no_user_sensitive_context_produces_high_container(self):
        from spy.file_crypto_engine import stream_encrypt_file
        src = self._src()
        enc = stream_encrypt_file(src, output_path=None, context={"sensitive": True})
        self.assertEqual(self._read_container_classification(enc), "high")

    def test_high_clearance_user_sensitive_context_produces_high_container(self):
        from spy.file_crypto_engine import stream_encrypt_file
        src = self._src()
        user = _user("admin", "high")
        enc = stream_encrypt_file(src, output_path=None, user=user, context={"sensitive": True})
        self.assertEqual(self._read_container_classification(enc), "high")


# ---------------------------------------------------------------------------
# TestUserCannotDowngrade — Bell-LaPadula no-write-down invariant
# ---------------------------------------------------------------------------

class TestUserCannotDowngrade(unittest.TestCase):
    """A user cannot produce a container classified below their clearance level."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)

    def _src(self, content: bytes = b"data") -> str:
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
        return path

    def _read_container_classification(self, enc_path: str) -> str | None:
        from spy.container_reader import StreamingContainerReader
        from spy.file_crypto_engine import _make_svst_sign_key_resolver
        from spy.key_provider import LocalPemKeyProvider
        provider = LocalPemKeyProvider()
        with open(enc_path, "rb") as f:
            reader = StreamingContainerReader(f)
            header = reader.read_and_verify_header(_make_svst_sign_key_resolver(provider))
        return header.classification

    def test_high_user_cannot_produce_low_container(self):
        """High-clearance user omitting sensitive flag still produces 'high' container."""
        from spy.file_crypto_engine import stream_encrypt_file
        src = self._src(b"this is sensitive data but no flag passed")
        user = _user("admin", "high")
        enc = stream_encrypt_file(src, output_path=None, user=user, context={})
        cls = self._read_container_classification(enc)
        self.assertEqual(cls, "high",
                         "High-clearance user must not produce a container below their clearance")

    def test_medium_user_cannot_produce_low_container(self):
        """Medium-clearance user omitting internal flag still produces 'medium' container."""
        from spy.file_crypto_engine import stream_encrypt_file
        src = self._src(b"internal report, no flag passed")
        user = _user("analyst", "medium")
        enc = stream_encrypt_file(src, output_path=None, user=user, context={})
        cls = self._read_container_classification(enc)
        self.assertEqual(cls, "medium",
                         "Medium-clearance user must not produce a container below their clearance")


if __name__ == "__main__":
    unittest.main(verbosity=2)
