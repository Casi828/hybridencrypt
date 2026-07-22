"""
test_file_encryption.py — File round-trip regression tests.

All tests use the streaming (SVST) path, which is the only supported
encryption/decryption path as of Phase 3.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from spy.file_crypto_engine import FileCryptoError, stream_decrypt_file, stream_encrypt_file
from tests.conftest import ws_patch, ws_restore


def _make_src(content: bytes, suffix: str = ".txt") -> Path:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return Path(path)


class TestFileEncryptionRoundTrip(unittest.TestCase):

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        self._src_files: list[Path] = []

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        for p in self._src_files:
            p.unlink(missing_ok=True)

    def _round_trip(self, method: str, content: bytes = b"round trip validation") -> None:
        src = _make_src(content)
        self._src_files.append(src)
        enc = stream_encrypt_file(str(src), method=method)
        dec = stream_decrypt_file(enc)
        self.assertEqual(Path(dec).read_bytes(), content,
                         f"{method.upper()} round-trip content mismatch")

    def test_rsa_round_trip(self):
        self._round_trip("rsa")

    def test_ecc_round_trip(self):
        self._round_trip("ecc")

    def test_rsa_binary_content(self):
        self._round_trip("rsa", bytes(range(256)) * 16)

    def test_ecc_binary_content(self):
        self._round_trip("ecc", bytes(range(256)) * 16)


class TestSecurityGuards(unittest.TestCase):

    def test_encrypt_rejects_enc_file(self):
        """stream_encrypt_file must refuse to encrypt an already-encrypted .enc file."""
        src = _make_src(b"fake encrypted content", ".enc")
        try:
            with self.assertRaises(FileCryptoError) as ctx:
                stream_encrypt_file(str(src))
            self.assertEqual(str(ctx.exception), "Encryption failed")
        finally:
            src.unlink(missing_ok=True)

    def test_decrypt_rejects_non_enc_file(self):
        """stream_decrypt_file must refuse to decrypt a file that is not .enc."""
        src = _make_src(b"this is plaintext", ".txt")
        try:
            with self.assertRaises(FileCryptoError) as ctx:
                stream_decrypt_file(str(src))
            self.assertEqual(str(ctx.exception), "Decryption denied")
        finally:
            src.unlink(missing_ok=True)


class TestSignedRoundTrip(unittest.TestCase):
    """Verify that streaming encrypt produces signed SVST containers."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        self._src_files: list[Path] = []

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        for p in self._src_files:
            p.unlink(missing_ok=True)

    def _signed_round_trip(self, method: str) -> None:
        from spy.crypto_container import is_streaming_container
        src = _make_src(b"signed round trip test")
        self._src_files.append(src)
        enc = stream_encrypt_file(str(src), method=method)
        raw = Path(enc).read_bytes()
        self.assertTrue(is_streaming_container(raw),
                        f"{method.upper()} encrypt must produce an SVST container")
        dec = stream_decrypt_file(enc)
        self.assertEqual(Path(dec).read_bytes(), b"signed round trip test")

    def test_rsa_signed_round_trip(self):
        self._signed_round_trip("rsa")

    def test_ecc_signed_round_trip(self):
        self._signed_round_trip("ecc")


class TestTamperRejection(unittest.TestCase):
    """Verify that tampered containers are rejected before decryption."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        self._src_files: list[Path] = []

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        for p in self._src_files:
            p.unlink(missing_ok=True)

    def _make_enc(self, method: str) -> str:
        src = _make_src(b"tamper test data")
        self._src_files.append(src)
        return stream_encrypt_file(str(src), method=method)

    def _tamper_test(self, method: str) -> None:
        enc = self._make_enc(method)
        raw = bytearray(Path(enc).read_bytes())
        raw[12] ^= 0xFF
        # write tampered file inside workspace so output_path validation doesn't interfere
        tampered_path = Path(enc).parent / (Path(enc).name + ".tampered.enc")
        tampered_path.write_bytes(bytes(raw))
        try:
            with self.assertRaises(FileCryptoError):
                stream_decrypt_file(str(tampered_path))
        finally:
            tampered_path.unlink(missing_ok=True)

    def test_rsa_tampered_container_rejected(self):
        self._tamper_test("rsa")

    def test_ecc_tampered_container_rejected(self):
        self._tamper_test("ecc")

    def test_unknown_magic_rejected(self):
        """stream_decrypt_file must refuse files with unknown magic."""
        fake = _make_src(b"XXXX" + b"\x00" * 100, ".enc")
        try:
            with self.assertRaises(FileCryptoError):
                stream_decrypt_file(str(fake))
        finally:
            fake.unlink(missing_ok=True)


class TestFileTypeEncryption(unittest.TestCase):
    """Verify common file formats survive the encrypt/decrypt pipeline intact."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        self._src_files: list[Path] = []

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        for p in self._src_files:
            p.unlink(missing_ok=True)

    def _round_trip(self, method: str, content: bytes, suffix: str) -> None:
        src = _make_src(content, suffix)
        self._src_files.append(src)
        enc = stream_encrypt_file(str(src), method=method)
        dec = stream_decrypt_file(enc)
        self.assertEqual(Path(dec).read_bytes(), content,
                         f"{method.upper()} {suffix} round-trip content mismatch")

    def test_pdf_round_trip(self):
        content = b"%PDF-1.4\n" + os.urandom(1024)
        self._round_trip("rsa", content, ".pdf")
        self._round_trip("ecc", content, ".pdf")

    def test_png_round_trip(self):
        content = b"\x89PNG\r\n\x1a\n" + os.urandom(1024)
        self._round_trip("rsa", content, ".png")
        self._round_trip("ecc", content, ".png")

    def test_jpeg_round_trip(self):
        content = b"\xff\xd8\xff\xe0" + os.urandom(1024)
        self._round_trip("rsa", content, ".jpg")
        self._round_trip("ecc", content, ".jpg")

    def test_zip_round_trip(self):
        content = b"PK\x03\x04" + os.urandom(1024)
        self._round_trip("rsa", content, ".zip")
        self._round_trip("ecc", content, ".zip")

    def test_null_bytes_round_trip(self):
        content = b"\x00" * 2048
        self._round_trip("rsa", content, ".bin")
        self._round_trip("ecc", content, ".bin")

    def test_high_entropy_binary_round_trip(self):
        content = os.urandom(128 * 1024)
        self._round_trip("rsa", content, ".bin")
        self._round_trip("ecc", content, ".bin")


if __name__ == "__main__":
    unittest.main(verbosity=2)
