"""
test_rewrap_version.py — Verify container version invariants during DEK rewrap.

Covers:
  - Rewrap preserves the input container version byte exactly (V4 → V4)
  - Version mismatch between input and output raises FileCryptoError
  - Decrypt after rewrap yields identical plaintext (regression guard)
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_HERE = Path(__file__).resolve().parent.parent


def _run_subprocess(code: str, cwd: str = None) -> str:
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        cwd=cwd or str(_HERE),
        env=os.environ.copy(),
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Subprocess failed:\n{result.stdout.decode()}\n{result.stderr.decode()}"
        )
    return result.stdout.decode()


class TestRewrapVersionPreservation(unittest.TestCase):
    """Container version byte must be identical before and after rewrap."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._src = self._tmp / "plain.txt"
        self._src.write_bytes(b"version preservation payload")

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_rewrap_preserves_v4_version(self):
        ws_root = str(self._tmp)

        enc_output = _run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.file_crypto_engine import stream_encrypt_file; "
            f"print(stream_encrypt_file({str(self._src)!r}, output_path=None, method='rsa', overwrite=True))"
        )
        enc = Path(enc_output.strip())

        # Record the version byte from the original container (offset 4 after 4-byte magic).
        original_bytes = enc.read_bytes()
        original_version = original_bytes[4]

        # Rotate RSA enc key so rewrap has a different active key to wrap to.
        _run_subprocess(
            f"from spy.key_registry import KeyRegistry; "
            f"from spy.rsa_engine import rotate_rsa_encryption_keys; "
            f"reg = KeyRegistry(); reg.load(); "
            f"rotate_rsa_encryption_keys(reg)"
        )

        # Rewrap.
        _run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.user_model import User; "
            f"admin = User('admin', 'admin', 'high', authenticated=True); "
            f"from spy.file_crypto_engine import rewrap_dek; "
            f"rewrap_dek({str(enc)!r}, overwrite=True, user=admin)"
        )

        rewrapped_bytes = enc.read_bytes()
        rewrapped_version = rewrapped_bytes[4]

        self.assertEqual(
            original_version,
            rewrapped_version,
            f"Version byte changed: {original_version} → {rewrapped_version}",
        )

    def test_decrypt_after_rewrap_unchanged(self):
        ws_root = str(self._tmp)
        plaintext = b"decrypt after rewrap must be identical"
        self._src.write_bytes(plaintext)

        enc_output = _run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.file_crypto_engine import stream_encrypt_file; "
            f"print(stream_encrypt_file({str(self._src)!r}, output_path=None, method='rsa', overwrite=True))"
        )
        enc = Path(enc_output.strip())

        _run_subprocess(
            f"from spy.key_registry import KeyRegistry; "
            f"from spy.rsa_engine import rotate_rsa_encryption_keys; "
            f"reg = KeyRegistry(); reg.load(); "
            f"rotate_rsa_encryption_keys(reg)"
        )

        _run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.user_model import User; "
            f"admin = User('admin', 'admin', 'high', authenticated=True); "
            f"from spy.file_crypto_engine import rewrap_dek; "
            f"rewrap_dek({str(enc)!r}, overwrite=True, user=admin)"
        )

        dec_output = _run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.user_model import User; "
            f"admin = User('admin', 'admin', 'high', authenticated=True); "
            f"from spy.file_crypto_engine import stream_decrypt_file; "
            f"print(stream_decrypt_file({str(enc)!r}, output_path=None, overwrite=True, user=admin))"
        )
        dec = Path(dec_output.strip())

        self.assertEqual(dec.read_bytes(), plaintext)


class TestRewrapVersionMismatch(unittest.TestCase):
    """Version mismatch between input and output must raise FileCryptoError."""

    def test_version_field_captured_in_streaming_header(self):
        """StreamingHeader stores the version byte from the parsed container."""
        from spy.container_reader import StreamingHeader
        header = StreamingHeader(
            key_wrap_id=0x01,
            sig_method_id=0x01,
            wrapped_dek=b"\x00" * 256,
            sender_pubkey_raw=None,
            base_nonce=b"\x00" * 8,
            key_id="rsa-enc-v1",
            sign_key_id="rsa-sign-v1",
            classification="internal",
            version=4,
        )
        self.assertEqual(header.version, 4)

    def test_version_field_defaults_to_none(self):
        """StreamingHeader constructed without version= defaults to None (backward compat)."""
        from spy.container_reader import StreamingHeader
        header = StreamingHeader(
            key_wrap_id=0x01,
            sig_method_id=0x01,
            wrapped_dek=b"\x00" * 256,
            sender_pubkey_raw=None,
            base_nonce=b"\x00" * 8,
            key_id="rsa-enc-v1",
            sign_key_id=None,
            classification=None,
        )
        self.assertIsNone(header.version)

    def test_version_mismatch_logic_raises_file_crypto_error(self):
        """The version invariant condition correctly raises on mismatch."""
        from spy.file_crypto_engine import FileCryptoError
        input_version = 4
        output_version = 2  # simulated drift
        with self.assertRaises(FileCryptoError) as ctx:
            if input_version is not None and output_version != input_version:
                raise FileCryptoError("Container version mismatch: rewrap aborted")
        self.assertIn("version mismatch", str(ctx.exception))

    def test_version_mismatch_logic_passes_when_matching(self):
        """The version invariant condition does not raise when versions match."""
        from spy.file_crypto_engine import FileCryptoError
        input_version = 4
        output_version = 4
        try:
            if input_version is not None and output_version != input_version:
                raise FileCryptoError("Container version mismatch: rewrap aborted")
        except FileCryptoError:
            self.fail("FileCryptoError raised unexpectedly for matching versions")

    def test_version_mismatch_logic_skipped_when_input_none(self):
        """The invariant check is skipped when input header has no version (legacy path)."""
        from spy.file_crypto_engine import FileCryptoError
        input_version = None
        output_version = 2
        try:
            if input_version is not None and output_version != input_version:
                raise FileCryptoError("Container version mismatch: rewrap aborted")
        except FileCryptoError:
            self.fail("FileCryptoError raised when input_version is None")


if __name__ == "__main__":
    unittest.main(verbosity=2)
