"""
test_stream_encryption.py — Tests for the SVST streaming container format.

Coverage:
  TestStreamRoundTrip          — encrypt/decrypt round-trips for various sizes
  TestStreamContainerFormat    — binary header field validation
  TestStreamFailClosed         — every tamper / truncation scenario raises FileCryptoError
  TestStreamBackwardCompatibility — SENV auto-detection and format isolation
  TestStreamFileSafety         — temp file cleanup, atomic rename, overwrite guard
  TestStreamCLIDispatch        — CLI 'encrypt' / 'decrypt' produce and accept SVST
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from spy.crypto_container import (
    STREAMING_MAGIC,
    STREAMING_CONTAINER_VERSION,
    STREAMING_CONTAINER_VERSION_V2,
    STREAMING_CONTAINER_VERSION_V3,
    KEY_WRAP_ID_RSA,
    KEY_WRAP_ID_ECC,
    SIG_METHOD_ID_RSA,
    SIG_METHOD_ID_ECC,
    is_signed_envelope,
    is_streaming_container,
)
from spy.file_crypto_engine import (
    FileCryptoError,
    stream_decrypt_file,
    stream_encrypt_file,
)
from tests.conftest import ws_patch, ws_restore


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _write_tmp(data: bytes) -> Path:
    """Write *data* to a named temp file (outside workspace) and return its Path."""
    fd, path = tempfile.mkstemp()
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return Path(path)


def _round_trip(plaintext: bytes, method: str = "rsa") -> bytes:
    """Encrypt then decrypt *plaintext* in a temp workspace and return the recovered bytes."""
    ws_root = Path(tempfile.mkdtemp()).resolve()
    snap = ws_patch(ws_root)
    src = _write_tmp(plaintext)
    try:
        enc = stream_encrypt_file(str(src), method=method)
        dec = stream_decrypt_file(enc)
        return Path(dec).read_bytes()
    finally:
        ws_restore(snap)
        shutil.rmtree(str(ws_root), ignore_errors=True)
        src.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# TestStreamRoundTrip
# ---------------------------------------------------------------------------

class TestStreamRoundTrip(unittest.TestCase):

    def test_rsa_round_trip_empty(self):
        self.assertEqual(_round_trip(b"", method="rsa"), b"")

    def test_ecc_round_trip_empty(self):
        self.assertEqual(_round_trip(b"", method="ecc"), b"")

    def test_rsa_round_trip_one_byte(self):
        self.assertEqual(_round_trip(b"\xff", method="rsa"), b"\xff")

    def test_ecc_round_trip_one_byte(self):
        self.assertEqual(_round_trip(b"\xaa", method="ecc"), b"\xaa")

    def test_rsa_round_trip_small(self):
        data = b"Hello, streaming world!"
        self.assertEqual(_round_trip(data, method="rsa"), data)

    def test_ecc_round_trip_small(self):
        data = b"Hello, streaming world!"
        self.assertEqual(_round_trip(data, method="ecc"), data)

    def test_rsa_round_trip_exact_one_chunk(self):
        data = os.urandom(1 * 1024 * 1024)
        self.assertEqual(_round_trip(data, method="rsa"), data)

    def test_rsa_round_trip_multi_chunk(self):
        data = os.urandom(int(2.5 * 1024 * 1024))
        self.assertEqual(_round_trip(data, method="rsa"), data)

    def test_ecc_round_trip_multi_chunk(self):
        data = os.urandom(int(2.5 * 1024 * 1024))
        self.assertEqual(_round_trip(data, method="ecc"), data)

    def test_rsa_round_trip_binary(self):
        data = os.urandom(128 * 1024)
        self.assertEqual(_round_trip(data, method="rsa"), data)

    def test_rsa_round_trip_null_bytes(self):
        data = b"\x00" * (64 * 1024)
        self.assertEqual(_round_trip(data, method="rsa"), data)

    def test_rsa_round_trip_10mb(self):
        data = os.urandom(10 * 1024 * 1024)
        self.assertEqual(_round_trip(data, method="rsa"), data)


# ---------------------------------------------------------------------------
# TestStreamContainerFormat
# ---------------------------------------------------------------------------

class TestStreamContainerFormat(unittest.TestCase):

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        plaintext = b"format test data"
        self._src = _write_tmp(plaintext)
        self._enc_rsa = stream_encrypt_file(str(self._src), method="rsa")
        self._enc_ecc = stream_encrypt_file(
            str(self._src), method="ecc",
            output_path=str(
                self._ws_root / "output" / "encrypted" / "high" /
                (self._src.name + ".ecc.enc")
            ),
        )

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        self._src.unlink(missing_ok=True)

    def test_magic_bytes_rsa(self):
        data = Path(self._enc_rsa).read_bytes()
        self.assertEqual(data[:4], STREAMING_MAGIC)

    def test_magic_bytes_ecc(self):
        data = Path(self._enc_ecc).read_bytes()
        self.assertEqual(data[:4], STREAMING_MAGIC)

    def test_version_byte_rsa(self):
        from spy.crypto_container import STREAMING_CONTAINER_VERSION_V4
        data = Path(self._enc_rsa).read_bytes()
        self.assertEqual(data[4], STREAMING_CONTAINER_VERSION_V4)

    def test_key_wrap_id_rsa(self):
        data = Path(self._enc_rsa).read_bytes()
        self.assertEqual(data[5], KEY_WRAP_ID_RSA)

    def test_key_wrap_id_ecc(self):
        data = Path(self._enc_ecc).read_bytes()
        self.assertEqual(data[5], KEY_WRAP_ID_ECC)

    def test_sig_method_id_rsa(self):
        data = Path(self._enc_rsa).read_bytes()
        self.assertEqual(data[6], SIG_METHOD_ID_RSA)

    def test_flags_byte_is_zero(self):
        data = Path(self._enc_rsa).read_bytes()
        self.assertEqual(data[7], 0x00)

    def test_is_streaming_container_true(self):
        data = Path(self._enc_rsa).read_bytes()
        self.assertTrue(is_streaming_container(data))

    def test_is_streaming_container_false_for_senv(self):
        senv_data = b"SENV" + b"\x00" * 20
        self.assertFalse(is_streaming_container(senv_data))
        self.assertTrue(is_signed_envelope(senv_data))

    def test_is_signed_envelope_false_for_svst(self):
        data = Path(self._enc_rsa).read_bytes()
        self.assertFalse(is_signed_envelope(data))


# ---------------------------------------------------------------------------
# TestStreamFailClosed
# ---------------------------------------------------------------------------

class TestStreamFailClosed(unittest.TestCase):

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        self._plaintext = os.urandom(int(2.5 * 1024 * 1024))
        self._src = _write_tmp(self._plaintext)
        self._enc = Path(stream_encrypt_file(str(self._src), method="rsa"))
        self._enc_bytes = self._enc.read_bytes()

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        self._src.unlink(missing_ok=True)

    def _decrypt_tampered(self, data: bytes) -> None:
        """Write *data* to a .enc file inside workspace and attempt decryption; expect FileCryptoError."""
        t = self._enc.parent / (self._enc.name + ".tampered.enc")
        try:
            t.write_bytes(data)
            with self.assertRaises(FileCryptoError):
                stream_decrypt_file(str(t))
        finally:
            t.unlink(missing_ok=True)

    def test_bad_magic_rejected(self):
        tampered = b"XXXX" + self._enc_bytes[4:]
        self._decrypt_tampered(tampered)

    def test_wrong_version_rejected(self):
        tampered = self._enc_bytes[:4] + b"\x99" + self._enc_bytes[5:]
        self._decrypt_tampered(tampered)

    def test_unknown_key_wrap_id_rejected(self):
        tampered = self._enc_bytes[:5] + b"\xff" + self._enc_bytes[6:]
        self._decrypt_tampered(tampered)

    def test_unknown_sig_method_id_rejected(self):
        tampered = self._enc_bytes[:6] + b"\xff" + self._enc_bytes[7:]
        self._decrypt_tampered(tampered)

    def test_nonzero_flags_rejected(self):
        tampered = self._enc_bytes[:7] + b"\x01" + self._enc_bytes[8:]
        self._decrypt_tampered(tampered)

    def test_truncated_header_rejected(self):
        self._decrypt_tampered(self._enc_bytes[:20])

    def test_header_signature_tampered(self):
        tampered = bytearray(self._enc_bytes)
        tampered[12] ^= 0xFF
        self._decrypt_tampered(bytes(tampered))

    def test_chunk_ciphertext_tampered(self):
        data = self._enc_bytes
        wrapped_dek_len = struct.unpack(">H", data[8:10])[0]
        offset = 10 + wrapped_dek_len
        offset += 8
        if data[4] >= STREAMING_CONTAINER_VERSION_V2:
            key_id_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2 + key_id_len
        if data[4] >= STREAMING_CONTAINER_VERSION_V3:
            sign_key_id_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2 + sign_key_id_len
        from spy.crypto_container import STREAMING_CONTAINER_VERSION_V4
        if data[4] >= STREAMING_CONTAINER_VERSION_V4:
            cls_len = data[offset]
            offset += 1 + cls_len
        sig_len = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4 + sig_len
        chunk_len = struct.unpack(">I", data[offset:offset + 4])[0]
        target = offset + 4 + 20
        tampered = bytearray(data)
        tampered[target] ^= 0xFF
        self._decrypt_tampered(bytes(tampered))

    def test_truncated_file_after_header(self):
        data = self._enc_bytes
        wrapped_dek_len = struct.unpack(">H", data[8:10])[0]
        offset = 10 + wrapped_dek_len + 8
        if data[4] >= STREAMING_CONTAINER_VERSION_V2:
            key_id_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2 + key_id_len
        if data[4] >= STREAMING_CONTAINER_VERSION_V3:
            sign_key_id_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2 + sign_key_id_len
        from spy.crypto_container import STREAMING_CONTAINER_VERSION_V4
        if data[4] >= STREAMING_CONTAINER_VERSION_V4:
            cls_len = data[offset]
            offset += 1 + cls_len
        sig_len = struct.unpack(">I", data[offset:offset + 4])[0]
        header_end = offset + 4 + sig_len
        self._decrypt_tampered(data[:header_end])

    def test_truncated_chunk_data(self):
        data = self._enc_bytes
        wrapped_dek_len = struct.unpack(">H", data[8:10])[0]
        offset = 10 + wrapped_dek_len + 8
        if data[4] >= STREAMING_CONTAINER_VERSION_V2:
            key_id_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2 + key_id_len
        if data[4] >= STREAMING_CONTAINER_VERSION_V3:
            sign_key_id_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2 + sign_key_id_len
        from spy.crypto_container import STREAMING_CONTAINER_VERSION_V4
        if data[4] >= STREAMING_CONTAINER_VERSION_V4:
            cls_len = data[offset]
            offset += 1 + cls_len
        sig_len = struct.unpack(">I", data[offset:offset + 4])[0]
        header_end = offset + 4 + sig_len
        chunk_len = struct.unpack(">I", data[header_end:header_end + 4])[0]
        cutoff = header_end + 4 + chunk_len // 2
        self._decrypt_tampered(data[:cutoff])

    def test_partial_output_not_written_on_failure(self):
        tampered = bytearray(self._enc_bytes)
        tampered[12] ^= 0xFF
        t = self._enc.parent / (self._enc.name + ".partial_test.enc")
        t.write_bytes(bytes(tampered))
        try:
            with self.assertRaises(FileCryptoError):
                stream_decrypt_file(str(t))
            # Decrypted output must not exist
            import spy.workspace as _ws
            for cls in ("low", "medium", "high"):
                out_dir = _ws.SAFE_DECRYPTED_OUTPUT_DIR / cls
                self.assertFalse(any(out_dir.iterdir()) if out_dir.exists() else False)
        finally:
            t.unlink(missing_ok=True)

    def test_temp_file_cleaned_up_on_failure(self):
        tampered = bytearray(self._enc_bytes)
        tampered[12] ^= 0xFF
        t = self._enc.parent / (self._enc.name + ".tmpclean_test.enc")
        t.write_bytes(bytes(tampered))
        try:
            with self.assertRaises(FileCryptoError):
                stream_decrypt_file(str(t))
            # No .svst_decrypt_tmp files should remain anywhere in workspace
            import spy.workspace as _ws
            for tmp_file in _ws.SAFE_FILE_ROOT.rglob("*.svst_decrypt_tmp"):
                self.fail(f"Temp file not cleaned up: {tmp_file}")
        finally:
            t.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# TestStreamBackwardCompatibility
# ---------------------------------------------------------------------------

class TestStreamBackwardCompatibility(unittest.TestCase):

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        self._plaintext = b"backward compat test data"
        self._src = _write_tmp(self._plaintext)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        self._src.unlink(missing_ok=True)

    def test_stream_decrypt_rejects_senv_file(self):
        """stream_decrypt_file must reject legacy SENV files."""
        senv = _write_tmp(b"SENV" + b"\x01\x00" + b"\x00" * 50)
        senv = senv.rename(senv.with_suffix(".enc"))
        try:
            with self.assertRaises(FileCryptoError):
                stream_decrypt_file(str(senv))
        finally:
            senv.unlink(missing_ok=True)

    def test_format_detection_streaming(self):
        enc = stream_encrypt_file(str(self._src), method="rsa")
        data = Path(enc).read_bytes()
        self.assertTrue(is_streaming_container(data))
        self.assertFalse(is_signed_envelope(data))

    def test_format_detection_senv_magic(self):
        senv_bytes = b"SENV" + b"\x01\x00" + b"\x00" * 50
        self.assertFalse(is_streaming_container(senv_bytes))
        self.assertTrue(is_signed_envelope(senv_bytes))

    def test_unknown_magic_rejected(self):
        bad = _write_tmp(b"XXXX" + b"\x00" * 100)
        bad = bad.rename(bad.with_suffix(".enc"))
        try:
            with self.assertRaises(FileCryptoError):
                stream_decrypt_file(str(bad))
        finally:
            bad.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# TestStreamFileSafety
# ---------------------------------------------------------------------------

class TestStreamFileSafety(unittest.TestCase):

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        self._plaintext = b"file safety test"
        self._src = _write_tmp(self._plaintext)
        self._enc = Path(stream_encrypt_file(str(self._src), method="rsa"))
        # user=None → system → high classification → decrypted/high/
        import spy.workspace as _ws
        self._dec_dir = _ws.SAFE_DECRYPTED_OUTPUT_DIR / "high"

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        self._src.unlink(missing_ok=True)

    def test_atomic_rename_on_success(self):
        dec = stream_decrypt_file(str(self._enc))
        self.assertTrue(Path(dec).exists())
        tmp = Path(dec).parent / (Path(dec).name + ".svst_decrypt_tmp")
        self.assertFalse(tmp.exists(), "Temp file must be gone after success")

    def test_no_overwrite_by_default(self):
        # First decrypt creates the output file
        dec = stream_decrypt_file(str(self._enc))
        # Second decrypt of same input → same output path → must refuse without overwrite
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(str(self._enc))

    def test_overwrite_flag_replaces_output(self):
        dec = stream_decrypt_file(str(self._enc))
        dec2 = stream_decrypt_file(str(self._enc), overwrite=True)
        self.assertEqual(Path(dec2).read_bytes(), self._plaintext)

    def test_no_encrypt_overwrite_by_default(self):
        # Encrypt again without overwrite — same classified output path must already exist.
        with self.assertRaises(FileCryptoError):
            stream_encrypt_file(str(self._src), method="rsa")

    def test_refuses_double_encrypt(self):
        with self.assertRaises(FileCryptoError):
            stream_encrypt_file(str(self._enc), method="rsa")

    def test_no_output_file_on_decrypt_failure(self):
        data = bytearray(self._enc.read_bytes())
        data[12] ^= 0xFF
        t = self._enc.parent / (self._enc.name + ".nosave.enc")
        t.write_bytes(bytes(data))
        try:
            with self.assertRaises(FileCryptoError):
                stream_decrypt_file(str(t))
            # No output file should exist in any decrypted dir
            for cls in ("low", "medium", "high"):
                d = self._dec_dir.parent / cls
                if d.exists():
                    self.assertFalse(list(d.iterdir()), f"Unexpected output in {d}")
        finally:
            t.unlink(missing_ok=True)

    def test_output_outside_workspace_rejected(self):
        """Engine must reject any explicit output_path outside SAFE_FILE_ROOT."""
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(str(self._enc), output_path="/tmp/evil_output.txt")

    def test_encrypt_output_outside_workspace_rejected(self):
        """Engine must reject any explicit output_path outside SAFE_FILE_ROOT for encrypt."""
        with self.assertRaises(FileCryptoError):
            stream_encrypt_file(str(self._src), output_path="/tmp/evil.enc")


# ---------------------------------------------------------------------------
# TestStreamCLIDispatch
# ---------------------------------------------------------------------------

class TestStreamCLIDispatch(unittest.TestCase):

    def _run(self, *args: str) -> tuple[int, str]:
        env = os.environ.copy()
        env["SAFE_FILE_ROOT"] = str(self._ws_root)
        result = subprocess.run(
            [sys.executable, "-m", "spy.cli", *args],
            input="testuser\ntestpass\n",
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
            env=env,
        )
        return result.returncode, result.stdout + result.stderr

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        self._plaintext = b"CLI dispatch test"
        self._src = _write_tmp(self._plaintext)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        self._src.unlink(missing_ok=True)

    def test_cli_encrypt_produces_svst_magic(self):
        rc, out = self._run("encrypt", str(self._src), "--method", "rsa", "--overwrite")
        self.assertEqual(rc, 0, f"CLI encrypt failed: {out}")
        # Find the produced .enc file in the workspace
        enc_files = list((self._ws_root / "output" / "encrypted").rglob("*.enc"))
        self.assertTrue(enc_files, "No .enc file produced in workspace")
        self.assertEqual(enc_files[0].read_bytes()[:4], STREAMING_MAGIC)

    def test_cli_decrypt_svst_file(self):
        rc, _ = self._run("encrypt", str(self._src), "--method", "rsa", "--overwrite")
        self.assertEqual(rc, 0)
        enc_files = list((self._ws_root / "output" / "encrypted").rglob("*.enc"))
        self.assertTrue(enc_files)
        enc = enc_files[0]
        rc, cli_out = self._run("decrypt", str(enc), "--overwrite")
        self.assertEqual(rc, 0, f"CLI decrypt failed: {cli_out}")
        dec_files = list((self._ws_root / "output" / "decrypted").rglob("*"))
        dec_files = [f for f in dec_files if f.is_file()]
        self.assertTrue(dec_files)
        self.assertEqual(dec_files[0].read_bytes(), self._plaintext)

    def test_cli_decrypt_rejects_senv_file(self):
        senv = _write_tmp(b"SENV" + b"\x01\x00" + b"\x00" * 50)
        senv = senv.rename(senv.with_suffix(".enc"))
        try:
            rc, cli_out = self._run("decrypt", str(senv))
            self.assertNotEqual(rc, 0, "CLI decrypt of SENV should have failed")
        finally:
            senv.unlink(missing_ok=True)

    def test_cli_ecc_encrypt_produces_svst_magic(self):
        rc, out = self._run("encrypt", str(self._src), "--method", "ecc", "--overwrite")
        self.assertEqual(rc, 0, f"CLI ECC encrypt failed: {out}")
        enc_files = list((self._ws_root / "output" / "encrypted").rglob("*.enc"))
        self.assertTrue(enc_files)
        self.assertEqual(enc_files[0].read_bytes()[:4], STREAMING_MAGIC)


if __name__ == "__main__":
    unittest.main(verbosity=2)
