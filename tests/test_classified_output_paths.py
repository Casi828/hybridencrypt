"""
test_classified_output_paths.py — Classification-routed output directory tests.

Verifies:
  - Encrypt output lands in workspace/output/encrypted/<cls>/
  - Decrypt output lands in workspace/output/decrypted/<cls>/
  - Engine rejects explicit paths in the wrong classification folder
  - Engine rejects paths outside the workspace root
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from spy.file_crypto_engine import FileCryptoError, stream_decrypt_file, stream_encrypt_file
from spy.user_model import User
from tests.conftest import ws_patch, ws_restore


def _user(role: str, clearance: str) -> User:
    return User(username="testuser", role=role, clearance=clearance, authenticated=True)


def _make_src(content: bytes = b"classified routing test") -> str:
    fd, path = tempfile.mkstemp(suffix=".txt")
    try:
        os.write(fd, content)
    finally:
        os.close(fd)
    return path


class TestEncryptRoutingByUser(unittest.TestCase):
    """Encrypt output is routed to encrypted/<clearance>/ via clearance-minimum floor."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)

    def test_low_user_encrypt_routes_to_encrypted_low(self):
        src = _make_src()
        try:
            enc = stream_encrypt_file(src, output_path=None, user=_user("analyst", "low"), context={})
        finally:
            Path(src).unlink(missing_ok=True)
        self.assertIn(
            Path("output") / "encrypted" / "low",
            Path(enc).parts[-4:-1] and [Path(*Path(enc).parts[-4:-1])],
        )
        expected_dir = self._ws_root / "output" / "encrypted" / "low"
        self.assertEqual(Path(enc).parent.resolve(), expected_dir.resolve())

    def test_medium_user_encrypt_routes_to_encrypted_medium(self):
        src = _make_src()
        try:
            enc = stream_encrypt_file(src, output_path=None, user=_user("analyst", "medium"), context={})
        finally:
            Path(src).unlink(missing_ok=True)
        expected_dir = self._ws_root / "output" / "encrypted" / "medium"
        self.assertEqual(Path(enc).parent.resolve(), expected_dir.resolve())

    def test_high_user_encrypt_routes_to_encrypted_high(self):
        src = _make_src()
        try:
            enc = stream_encrypt_file(src, output_path=None, user=_user("admin", "high"), context={})
        finally:
            Path(src).unlink(missing_ok=True)
        expected_dir = self._ws_root / "output" / "encrypted" / "high"
        self.assertEqual(Path(enc).parent.resolve(), expected_dir.resolve())

    def test_system_encrypt_routes_to_encrypted_high(self):
        """user=None (system call) uses SYSTEM_CLEARANCE='high' floor."""
        src = _make_src()
        try:
            enc = stream_encrypt_file(src, output_path=None, context={})
        finally:
            Path(src).unlink(missing_ok=True)
        expected_dir = self._ws_root / "output" / "encrypted" / "high"
        self.assertEqual(Path(enc).parent.resolve(), expected_dir.resolve())


class TestDecryptRoutingByContainerClassification(unittest.TestCase):
    """Decrypt output is routed to decrypted/<container-classification>/."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)

    def _encrypt_with_classification(self, context: dict, user=None) -> str:
        src = _make_src()
        try:
            enc = stream_encrypt_file(src, output_path=None, user=user, context=context)
        finally:
            Path(src).unlink(missing_ok=True)
        return enc

    def test_low_container_decrypt_routes_to_decrypted_low(self):
        enc = self._encrypt_with_classification({}, user=_user("analyst", "low"))
        dec = stream_decrypt_file(enc, output_path=None)
        expected_dir = self._ws_root / "output" / "decrypted" / "low"
        self.assertEqual(Path(dec).parent.resolve(), expected_dir.resolve())

    def test_medium_container_decrypt_routes_to_decrypted_medium(self):
        enc = self._encrypt_with_classification({"internal": True}, user=_user("analyst", "medium"))
        dec = stream_decrypt_file(enc, output_path=None)
        expected_dir = self._ws_root / "output" / "decrypted" / "medium"
        self.assertEqual(Path(dec).parent.resolve(), expected_dir.resolve())

    def test_high_container_decrypt_routes_to_decrypted_high(self):
        enc = self._encrypt_with_classification({"sensitive": True}, user=_user("admin", "high"))
        dec = stream_decrypt_file(enc, output_path=None)
        expected_dir = self._ws_root / "output" / "decrypted" / "high"
        self.assertEqual(Path(dec).parent.resolve(), expected_dir.resolve())


class TestClassificationFolderEnforcement(unittest.TestCase):
    """Engine must reject explicit output paths in the wrong classification folder."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)

    def test_high_file_cannot_write_to_encrypted_low_folder(self):
        """High-clearance encrypt with explicit path in encrypted/low/ must fail."""
        src = _make_src()
        try:
            wrong_dir = self._ws_root / "output" / "encrypted" / "low"
            wrong_dir.mkdir(parents=True, exist_ok=True)
            wrong_path = str(wrong_dir / "test.enc")
            with self.assertRaises(FileCryptoError):
                stream_encrypt_file(
                    src, output_path=wrong_path,
                    user=_user("admin", "high"), context={},
                )
        finally:
            Path(src).unlink(missing_ok=True)

    def test_high_container_cannot_decrypt_to_decrypted_low(self):
        """Decrypting a high container into decrypted/low/ must fail."""
        src = _make_src()
        try:
            enc = stream_encrypt_file(src, output_path=None, user=_user("admin", "high"), context={})
        finally:
            Path(src).unlink(missing_ok=True)
        wrong_dir = self._ws_root / "output" / "decrypted" / "low"
        wrong_dir.mkdir(parents=True, exist_ok=True)
        wrong_path = str(wrong_dir / "test.txt")
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(enc, output_path=wrong_path)

    def test_output_outside_workspace_rejected(self):
        """Explicit output_path outside SAFE_FILE_ROOT is unconditionally rejected."""
        src = _make_src()
        try:
            with self.assertRaises(FileCryptoError):
                stream_encrypt_file(src, output_path="/tmp/evil_output.enc", context={})
        finally:
            Path(src).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
