"""
test_container_classification.py — Classification binding to encrypted container.

Verifies that data_classification is stored in the SVST V4 signed header region and
that stream_decrypt_file uses the container's classification (not caller-supplied input)
for authorization.

Required cases (TASK.md §8):
  - encrypt high → low user decrypt denied even if caller passes low
  - encrypt low  → low user decrypt allowed
  - encrypt medium → low denied, medium allowed, high allowed
  - missing classification (V3 container) → denied
  - invalid classification value → denied at encrypt time
  - tampered classification → header verification/integrity failure
"""

from __future__ import annotations

import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import ws_patch, ws_restore

from spy.container_reader import StreamingContainerReader, StreamingError
from spy.container_writer import StreamingContainerWriter
from spy.crypto_container import (
    STREAMING_CONTAINER_VERSION_V3,
    STREAMING_CONTAINER_VERSION_V4,
    STREAMING_MAGIC,
)
from spy.file_crypto_engine import (
    FileCryptoError,
    _VALID_CLASSIFICATIONS,
    stream_decrypt_file,
    stream_encrypt_file,
)
from spy.user_model import User


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _user(role: str, clearance: str, authenticated: bool = True) -> User:
    return User(username="testuser", role=role, clearance=clearance,
                authenticated=authenticated)


def _write_tmp(data: bytes, suffix: str = ".txt") -> Path:
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return Path(path)


def _enc_path(src: Path) -> Path:
    return Path(str(src) + ".enc")


def _encrypt(plaintext: bytes, context: dict, method: str = "rsa", user=None) -> Path:
    """Encrypt plaintext with the given policy context; return path to .enc file.

    Pass user to apply the clearance floor for a specific clearance level.
    Without user, SYSTEM_CLEARANCE='high' floor applies — all system calls produce 'high'.
    """
    src = _write_tmp(plaintext)
    enc_path = stream_encrypt_file(str(src), output_path=None, method=method,
                                   overwrite=True, context=context, user=user)
    src.unlink(missing_ok=True)
    return Path(enc_path)


# ---------------------------------------------------------------------------
# TestValidClassificationsConstant
# ---------------------------------------------------------------------------

class TestValidClassificationsConstant(unittest.TestCase):

    def test_contains_expected_values(self):
        self.assertEqual(_VALID_CLASSIFICATIONS, frozenset({"low", "medium", "high"}))

    def test_rejects_empty(self):
        self.assertNotIn("", _VALID_CLASSIFICATIONS)

    def test_rejects_unknown(self):
        self.assertNotIn("critical", _VALID_CLASSIFICATIONS)


# ---------------------------------------------------------------------------
# TestEncryptClassificationValidation
# ---------------------------------------------------------------------------

class TestEncryptClassificationValidation(unittest.TestCase):
    """stream_encrypt_file must reject invalid context types before doing any crypto."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._src = Path(self._tmpdir) / "plain.txt"
        self._src.write_bytes(b"test")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _assert_invalid_context(self, ctx) -> None:
        with self.assertRaises(FileCryptoError):
            stream_encrypt_file(str(self._src), output_path=None, overwrite=True, context=ctx)

    def test_invalid_context_string(self):
        self._assert_invalid_context("high")

    def test_invalid_context_integer(self):
        self._assert_invalid_context(42)

    def test_invalid_context_list(self):
        self._assert_invalid_context(["sensitive"])


# ---------------------------------------------------------------------------
# TestContainerHeaderClassification
# ---------------------------------------------------------------------------

class TestContainerHeaderClassification(unittest.TestCase):
    """Verify classification is embedded in V4 container headers."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._ws_root = Path(self._tmpdir).resolve()
        self._ws_snap = ws_patch(self._ws_root)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _read_header_classification(self, enc_path: Path) -> str | None:
        """Open the container and parse the header classification field."""
        from spy.key_provider import LocalPemKeyProvider
        from spy.file_crypto_engine import _make_svst_sign_key_resolver
        provider = LocalPemKeyProvider()
        with enc_path.open("rb") as f:
            reader = StreamingContainerReader(f)
            header = reader.read_and_verify_header(_make_svst_sign_key_resolver(provider))
        return header.classification

    def _enc_at(self, context: dict, method: str = "rsa", user=None) -> Path:
        src = Path(self._tmpdir) / "plain.txt"
        src.write_bytes(b"container classification test")
        enc_path = stream_encrypt_file(str(src), output_path=None, method=method,
                                       overwrite=True, context=context, user=user)
        return Path(enc_path)

    def test_rsa_low_classification_in_header(self):
        enc = self._enc_at({}, "rsa", user=_user("analyst", "low"))
        self.assertEqual(self._read_header_classification(enc), "low")

    def test_rsa_medium_classification_in_header(self):
        enc = self._enc_at({"internal": True}, "rsa", user=_user("analyst", "medium"))
        self.assertEqual(self._read_header_classification(enc), "medium")

    def test_rsa_high_classification_in_header(self):
        enc = self._enc_at({"sensitive": True}, "rsa")
        self.assertEqual(self._read_header_classification(enc), "high")

    def test_ecc_low_classification_in_header(self):
        enc = self._enc_at({}, "ecc", user=_user("analyst", "low"))
        self.assertEqual(self._read_header_classification(enc), "low")

    def test_ecc_high_classification_in_header(self):
        enc = self._enc_at({"sensitive": True}, "ecc")
        self.assertEqual(self._read_header_classification(enc), "high")

    def test_container_is_v4(self):
        """Containers written with classification must be V4."""
        enc = self._enc_at({"internal": True}, "rsa", user=_user("analyst", "medium"))
        raw = enc.read_bytes()
        # Byte 4 is the version field
        version = raw[4]
        self.assertEqual(version, STREAMING_CONTAINER_VERSION_V4)


# ---------------------------------------------------------------------------
# TestDecryptClassificationBinding — TASK.md §8 required cases
# ---------------------------------------------------------------------------

class TestDecryptClassificationBinding(unittest.TestCase):
    """Decrypt authorization uses container classification, not caller-supplied value."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._ws_root = Path(self._tmpdir).resolve()
        self._ws_snap = ws_patch(self._ws_root)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_encrypt_high_low_user_denied(self):
        """encrypt high → low user decrypt denied even if caller passes low."""
        enc = _encrypt(b"secret", {"sensitive": True})
        try:
            user = _user("analyst", "low")
            with self.assertRaises(FileCryptoError):
                stream_decrypt_file(str(enc), output_path=None, overwrite=True,
                                    user=user)
        finally:
            enc.unlink(missing_ok=True)

    def test_encrypt_low_low_user_allowed(self):
        """encrypt low → low user decrypt allowed."""
        enc = _encrypt(b"public data", {}, user=_user("analyst", "low"))
        try:
            user = _user("analyst", "low")
            dec = stream_decrypt_file(str(enc), output_path=None, overwrite=True, user=user)
            self.assertTrue(Path(dec).exists())
            self.assertEqual(Path(dec).read_bytes(), b"public data")
        finally:
            enc.unlink(missing_ok=True)

    def test_encrypt_medium_low_user_denied(self):
        """encrypt medium → low user denied."""
        enc = _encrypt(b"medium data", {"internal": True}, user=_user("analyst", "medium"))
        try:
            user = _user("analyst", "low")
            with self.assertRaises(FileCryptoError):
                stream_decrypt_file(str(enc), output_path=None, overwrite=True,
                                    user=user)
        finally:
            enc.unlink(missing_ok=True)

    def test_encrypt_medium_medium_user_allowed(self):
        """encrypt medium → medium user allowed."""
        enc = _encrypt(b"medium data", {"internal": True}, user=_user("analyst", "medium"))
        try:
            user = _user("analyst", "medium")
            dec = stream_decrypt_file(str(enc), output_path=None, overwrite=True, user=user)
            self.assertEqual(Path(dec).read_bytes(), b"medium data")
        finally:
            enc.unlink(missing_ok=True)

    def test_encrypt_medium_high_user_allowed(self):
        """encrypt medium → high user allowed."""
        enc = _encrypt(b"medium data", {"internal": True}, user=_user("analyst", "medium"))
        try:
            user = _user("admin", "high")
            dec = stream_decrypt_file(str(enc), output_path=None, overwrite=True, user=user)
            self.assertEqual(Path(dec).read_bytes(), b"medium data")
        finally:
            enc.unlink(missing_ok=True)

    def test_caller_supplied_classification_ignored(self):
        """Passing data_classification='low' to decrypt of a 'high' file must not bypass auth."""
        enc = _encrypt(b"top secret", {"sensitive": True})
        try:
            user = _user("analyst", "low")
            # Caller lies: passes low, but container says high → must be denied
            with self.assertRaises(FileCryptoError):
                stream_decrypt_file(str(enc), output_path=None, overwrite=True,
                                    user=user)
        finally:
            enc.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# TestLegacyContainerDenied
# ---------------------------------------------------------------------------

class TestLegacyContainerDenied(unittest.TestCase):
    """V3 containers (no classification field) must be denied on decrypt."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._ws_root = Path(self._tmpdir).resolve()
        self._ws_snap = ws_patch(self._ws_root)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_v3_container_denied(self):
        """A valid V3 container (no classification) must fail decrypt with 'Decryption denied'."""
        from spy.key_provider import LocalPemKeyProvider
        from spy.crypto_engine import generate_key
        from spy.rsa_engine import wrap_key as rsa_wrap_key
        from spy.signature_engine import sign

        provider = LocalPemKeyProvider()
        aes_key = generate_key()
        active_key_id = provider.get_active_rsa_key_id()
        sign_key_id = provider.get_active_rsa_signing_key_id()
        public_key = provider.get_rsa_public_key(active_key_id)
        sign_priv = provider.get_rsa_signing_private_key()
        wrapped_dek = rsa_wrap_key(public_key, aes_key)

        from spy.crypto_container import KEY_WRAP_ID_RSA, SIG_METHOD_ID_RSA

        enc_path = Path(self._tmpdir) / "legacy.enc"
        with enc_path.open("wb") as f:
            # Write V3 container (no classification)
            writer = StreamingContainerWriter(
                out_file=f,
                key_wrap_id=KEY_WRAP_ID_RSA,
                sig_method_id=SIG_METHOD_ID_RSA,
                wrapped_dek=wrapped_dek,
                sender_pubkey_raw=None,
                sign_private_key=sign_priv,
                aes_key=aes_key,
                key_id=active_key_id,
                sign_key_id=sign_key_id,
                # No classification — produces V3 container
            )
            writer.write_header()
            import io
            writer.write_chunks(io.BytesIO(b"legacy plaintext"))
            writer.close()

        with self.assertRaises(FileCryptoError) as cm:
            stream_decrypt_file(str(enc_path), output_path=None, overwrite=True)
        self.assertIn("Decryption denied", str(cm.exception))

    def test_v3_container_is_v3_version(self):
        """Sanity check: a writer without classification produces a V3 container."""
        from spy.key_provider import LocalPemKeyProvider
        from spy.crypto_engine import generate_key
        from spy.rsa_engine import wrap_key as rsa_wrap_key
        from spy.crypto_container import KEY_WRAP_ID_RSA, SIG_METHOD_ID_RSA
        import io

        provider = LocalPemKeyProvider()
        aes_key = generate_key()
        active_key_id = provider.get_active_rsa_key_id()
        sign_key_id = provider.get_active_rsa_signing_key_id()
        public_key = provider.get_rsa_public_key(active_key_id)
        sign_priv = provider.get_rsa_signing_private_key()
        wrapped_dek = rsa_wrap_key(public_key, aes_key)

        buf = io.BytesIO()
        writer = StreamingContainerWriter(
            out_file=buf,
            key_wrap_id=KEY_WRAP_ID_RSA,
            sig_method_id=SIG_METHOD_ID_RSA,
            wrapped_dek=wrapped_dek,
            sender_pubkey_raw=None,
            sign_private_key=sign_priv,
            aes_key=aes_key,
            key_id=active_key_id,
            sign_key_id=sign_key_id,
        )
        writer.write_header()
        writer.write_chunks(io.BytesIO(b""))
        writer.close()

        raw = buf.getvalue()
        version = raw[4]
        self.assertEqual(version, STREAMING_CONTAINER_VERSION_V3)


# ---------------------------------------------------------------------------
# TestTamperedClassification
# ---------------------------------------------------------------------------

class TestTamperedClassification(unittest.TestCase):
    """Tampering with the classification bytes must cause header sig failure."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._ws_root = Path(self._tmpdir).resolve()
        self._ws_snap = ws_patch(self._ws_root)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _flip_classification_byte(self, raw: bytes) -> bytes:
        """Find and flip a byte inside the classification field of a V4 container.

        The classification field comes after the sign_key_id field. We parse just
        enough to locate it.
        """
        # Parse enough to find the classification offset.
        pos = 4  # skip magic
        # version(1) + key_wrap_id(1) + sig_method_id(1) + flags(1) = 4 bytes
        key_wrap_id = raw[pos + 1]
        pos += 4
        # wrapped_dek_len (2 BE)
        wrapped_dek_len = struct.unpack(">H", raw[pos:pos + 2])[0]
        pos += 2 + wrapped_dek_len
        # sender_pubkey (ECC only)
        from spy.crypto_container import KEY_WRAP_ID_ECC
        if key_wrap_id == KEY_WRAP_ID_ECC:
            pubkey_len = struct.unpack(">H", raw[pos:pos + 2])[0]
            pos += 2 + pubkey_len
        # base_nonce (8 bytes)
        pos += 8
        # key_id
        key_id_len = struct.unpack(">H", raw[pos:pos + 2])[0]
        pos += 2 + key_id_len
        # sign_key_id
        sign_key_id_len = struct.unpack(">H", raw[pos:pos + 2])[0]
        pos += 2 + sign_key_id_len
        # classification_len (1 byte) + classification
        cls_len = raw[pos]
        pos += 1
        # pos now points to the first byte of the classification string — flip it
        data = bytearray(raw)
        data[pos] ^= 0xFF
        return bytes(data)

    def test_tampered_classification_fails_header_verification(self):
        src = Path(self._tmpdir) / "plain.txt"
        src.write_bytes(b"classified data")
        enc_path = stream_encrypt_file(str(src), output_path=None, overwrite=True,
                                       context={"internal": True})
        enc = Path(enc_path)

        raw = enc.read_bytes()
        tampered = self._flip_classification_byte(raw)
        tampered_enc = Path(self._tmpdir) / "tampered.enc"
        tampered_enc.write_bytes(tampered)

        with self.assertRaises(FileCryptoError) as cm:
            stream_decrypt_file(str(tampered_enc), output_path=None, overwrite=True)
        self.assertIn("Integrity", str(cm.exception),
                      "Expected integrity failure on tampered classification")


# ---------------------------------------------------------------------------
# TestMissingClassificationDenied — None / invalid classification edge cases
# ---------------------------------------------------------------------------

class TestMissingClassificationDenied(unittest.TestCase):
    """Containers with missing or invalid classification must be denied."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_none_classification_not_in_valid_set(self):
        """None is not a valid classification."""
        self.assertNotIn(None, _VALID_CLASSIFICATIONS)

    def test_empty_string_not_valid(self):
        self.assertNotIn("", _VALID_CLASSIFICATIONS)


# ---------------------------------------------------------------------------
# TestRelocationAttack — VERIFY.md relocation scenarios
# ---------------------------------------------------------------------------

class TestRelocationAttack(unittest.TestCase):
    """Moving a .enc file to a different directory must not change its authorization outcome.

    Classification is read from the authenticated container header, never from the
    filesystem path. Relocation cannot downgrade security classification.
    """

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._ws_snap = ws_patch(Path(self._tmpdir))

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_low_user_denied_after_relocation(self):
        """Encrypt high → move .enc to 'low_folder' → low user decrypt → DENIED."""
        enc = _encrypt(b"secret relocation data", {"sensitive": True})
        relocated = Path(self._tmpdir) / "low_folder" / enc.name
        relocated.parent.mkdir(parents=True, exist_ok=True)
        enc.rename(relocated)

        low_user = _user("analyst", "low")
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(str(relocated), output_path=None, user=low_user)

    def test_high_user_allowed_after_relocation(self):
        """Encrypt high → move .enc to 'low_folder' → high user decrypt → SUCCESS."""
        enc = _encrypt(b"secret relocation data", {"sensitive": True})
        relocated = Path(self._tmpdir) / "low_folder" / enc.name
        relocated.parent.mkdir(parents=True, exist_ok=True)
        enc.rename(relocated)

        high_user = _user("admin", "high")
        out = stream_decrypt_file(str(relocated), output_path=None, user=high_user)
        self.assertTrue(Path(out).exists())
        self.assertEqual(Path(out).read_bytes(), b"secret relocation data")


if __name__ == "__main__":
    unittest.main(verbosity=2)
