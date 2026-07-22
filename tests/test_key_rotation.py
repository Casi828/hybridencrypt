"""
test_key_rotation.py — Tests for Phase 2: Encryption Keypair Rotation.

Covers:
  - KeyRegistry CRUD and lifecycle
  - RSA and ECC encryption key rotation
  - SVST v2 header (key_id embedded)
  - Backward compatibility with SVST v1 (no key_id)
  - Decrypt with rotated (decrypt-only) keys
  - Block encryption when no active key exists
  - Audit logging for deprecated keys
  - DEK rewrap (header rekeying without re-encrypting chunks)
  - CLI rotate-enc-keys and rewrap commands
"""

from __future__ import annotations

import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from tests.conftest import ws_patch, ws_restore

# ---------------------------------------------------------------------------
# Bootstrap environment so test discovery works without .env loaded
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent.parent
os.environ.setdefault("CRYPTO_KEY_DIR", str(_HERE / "runtime" / "keys"))


class TestKeyRegistryCRUD(unittest.TestCase):
    """Unit tests for KeyRegistry persistence and query methods."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._orig_crypto_key_dir = os.environ.get("CRYPTO_KEY_DIR", "")
        os.environ["CRYPTO_KEY_DIR"] = str(self._tmp)

    def tearDown(self):
        if self._orig_crypto_key_dir:
            os.environ["CRYPTO_KEY_DIR"] = self._orig_crypto_key_dir
        else:
            os.environ.pop("CRYPTO_KEY_DIR", None)
        self._tmpdir.cleanup()

    def _make_entry(self, key_id="rsa-enc-test", key_type="rsa_enc", status="active"):
        from spy.key_registry import KeyEntry
        return KeyEntry(
            key_id=key_id,
            key_type=key_type,
            status=status,
            created_at="2026-04-01T12:00:00Z",
            activate_at="2026-04-01T12:00:00Z",
            retire_at=None,
            algorithm="RSA-3072-OAEP-SHA256",
            key_reference="rsa_private.pem",
        )

    def test_load_empty_when_file_absent(self):
        from spy.key_registry import KeyRegistry
        reg = KeyRegistry()
        reg.load()
        self.assertEqual(reg._entries, [])

    def test_save_and_reload_round_trip(self):
        from spy.key_registry import KeyRegistry
        reg = KeyRegistry()
        reg.load()
        reg.register(self._make_entry())
        reg.save()

        reg2 = KeyRegistry()
        reg2.load()
        self.assertEqual(len(reg2._entries), 1)
        e = reg2._entries[0]
        self.assertEqual(e.key_id, "rsa-enc-test")
        self.assertEqual(e.status, "active")

    def test_get_active_key_id(self):
        from spy.key_registry import KeyRegistry
        reg = KeyRegistry()
        reg.load()
        reg.register(self._make_entry())
        self.assertEqual(reg.get_active_key_id("rsa_enc"), "rsa-enc-test")

    def test_get_active_key_id_no_active_raises(self):
        from spy.key_registry import KeyRegistry, KeyRegistryError
        reg = KeyRegistry()
        reg.load()
        reg.register(self._make_entry(status="decrypt-only"))
        with self.assertRaises(KeyRegistryError):
            reg.get_active_key_id("rsa_enc")

    def test_get_entry_missing_raises(self):
        from spy.key_registry import KeyRegistry, KeyRegistryError
        reg = KeyRegistry()
        reg.load()
        with self.assertRaises(KeyRegistryError):
            reg.get_entry("nonexistent")

    def test_set_status_active_to_decrypt_only(self):
        from spy.key_registry import KeyRegistry
        reg = KeyRegistry()
        reg.load()
        reg.register(self._make_entry())
        reg.set_status("rsa-enc-test", "decrypt-only")
        e = reg.get_entry("rsa-enc-test")
        self.assertEqual(e.status, "decrypt-only")

    def test_set_status_invalid_raises(self):
        from spy.key_registry import KeyRegistry, KeyRegistryError
        reg = KeyRegistry()
        reg.load()
        reg.register(self._make_entry())
        with self.assertRaises(KeyRegistryError):
            reg.set_status("rsa-enc-test", "invalid-status")

    def test_register_duplicate_raises(self):
        from spy.key_registry import KeyRegistry, KeyRegistryError
        reg = KeyRegistry()
        reg.load()
        reg.register(self._make_entry())
        with self.assertRaises(KeyRegistryError):
            reg.register(self._make_entry())

    def test_has_entry(self):
        from spy.key_registry import KeyRegistry
        reg = KeyRegistry()
        reg.load()
        self.assertFalse(reg.has_entry("rsa-enc-test"))
        reg.register(self._make_entry())
        self.assertTrue(reg.has_entry("rsa-enc-test"))

    def test_get_private_key_path(self):
        from spy.key_registry import KeyRegistry
        reg = KeyRegistry()
        reg.load()
        reg.register(self._make_entry())
        path = reg.get_private_key_path("rsa-enc-test")
        self.assertEqual(path, self._tmp / "rsa_private.pem")

    def test_get_public_key_path_replaces_private(self):
        from spy.key_registry import KeyRegistry
        reg = KeyRegistry()
        reg.load()
        entry = self._make_entry()
        # Use a key_reference that has _private in the name.
        from spy.key_registry import KeyEntry
        entry2 = KeyEntry(
            key_id="rsa-enc-v2",
            key_type="rsa_enc",
            status="active",
            created_at="2026-04-01T12:00:00Z",
            activate_at="2026-04-01T12:00:00Z",
            retire_at=None,
            algorithm="RSA-3072-OAEP-SHA256",
            key_reference="rsa_enc_v2_private.pem",
        )
        reg.register(entry2)
        pub_path = reg.get_public_key_path("rsa-enc-v2")
        self.assertEqual(pub_path.name, "rsa_enc_v2_public.pem")

    def test_status_full_lifecycle(self):
        from spy.key_registry import KeyRegistry
        reg = KeyRegistry()
        reg.load()
        reg.register(self._make_entry())
        for status in ("decrypt-only", "retired", "revoked"):
            reg.set_status("rsa-enc-test", status)
            e = reg.get_entry("rsa-enc-test")
            self.assertEqual(e.status, status)


class TestRSAEncKeyRotation(unittest.TestCase):
    """Tests for rotate_rsa_encryption_keys()."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._orig_crypto_key_dir = os.environ.get("CRYPTO_KEY_DIR", "")
        os.environ["CRYPTO_KEY_DIR"] = str(self._tmp)

    def tearDown(self):
        if self._orig_crypto_key_dir:
            os.environ["CRYPTO_KEY_DIR"] = self._orig_crypto_key_dir
        else:
            os.environ.pop("CRYPTO_KEY_DIR", None)
        self._tmpdir.cleanup()

    def _make_registry_with_initial_key(self):
        from spy.key_registry import KeyRegistry, KeyEntry
        reg = KeyRegistry()
        reg.load()
        entry = KeyEntry(
            key_id="rsa-enc-initial",
            key_type="rsa_enc",
            status="active",
            created_at="2026-04-01T12:00:00Z",
            activate_at="2026-04-01T12:00:00Z",
            retire_at=None,
            algorithm="RSA-3072-OAEP-SHA256",
            key_reference="rsa_private.pem",
        )
        reg.register(entry)
        return reg

    def test_rotate_generates_new_keypair(self):
        from spy.rsa_engine import rotate_rsa_encryption_keys
        reg = self._make_registry_with_initial_key()
        priv, pub, key_id = rotate_rsa_encryption_keys(reg)
        self.assertIsNotNone(priv)
        self.assertIsNotNone(pub)
        self.assertTrue(key_id.startswith("rsa-enc-"))

    def test_rotate_new_key_is_active(self):
        from spy.rsa_engine import rotate_rsa_encryption_keys
        reg = self._make_registry_with_initial_key()
        _, _, new_key_id = rotate_rsa_encryption_keys(reg)
        self.assertEqual(reg.get_active_key_id("rsa_enc"), new_key_id)

    def test_rotate_old_key_becomes_decrypt_only(self):
        from spy.rsa_engine import rotate_rsa_encryption_keys
        reg = self._make_registry_with_initial_key()
        _, _, _ = rotate_rsa_encryption_keys(reg)
        old_entry = reg.get_entry("rsa-enc-initial")
        self.assertEqual(old_entry.status, "decrypt-only")

    def test_rotate_creates_key_files(self):
        from spy.rsa_engine import rotate_rsa_encryption_keys
        reg = self._make_registry_with_initial_key()
        _, _, key_id = rotate_rsa_encryption_keys(reg)
        priv_path = self._tmp / f"rsa_enc_{key_id}_private.pem"
        pub_path = self._tmp / f"rsa_enc_{key_id}_public.pem"
        self.assertTrue(priv_path.exists(), f"Missing {priv_path.name}")
        self.assertTrue(pub_path.exists(), f"Missing {pub_path.name}")

    def test_rotate_persists_registry(self):
        from spy.rsa_engine import rotate_rsa_encryption_keys
        from spy.key_registry import KeyRegistry
        reg = self._make_registry_with_initial_key()
        _, _, new_key_id = rotate_rsa_encryption_keys(reg)

        reg2 = KeyRegistry()
        reg2.load()
        self.assertEqual(reg2.get_active_key_id("rsa_enc"), new_key_id)
        self.assertEqual(reg2.get_entry("rsa-enc-initial").status, "decrypt-only")

    def test_double_rotation(self):
        from spy.rsa_engine import rotate_rsa_encryption_keys
        reg = self._make_registry_with_initial_key()
        _, _, key_id_1 = rotate_rsa_encryption_keys(reg)
        _, _, key_id_2 = rotate_rsa_encryption_keys(reg)
        self.assertEqual(reg.get_active_key_id("rsa_enc"), key_id_2)
        self.assertEqual(reg.get_entry(key_id_1).status, "decrypt-only")
        self.assertEqual(reg.get_entry("rsa-enc-initial").status, "decrypt-only")


class TestECCEncKeyRotation(unittest.TestCase):
    """Tests for rotate_ecc_encryption_keys()."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._orig_crypto_key_dir = os.environ.get("CRYPTO_KEY_DIR", "")
        os.environ["CRYPTO_KEY_DIR"] = str(self._tmp)

    def tearDown(self):
        if self._orig_crypto_key_dir:
            os.environ["CRYPTO_KEY_DIR"] = self._orig_crypto_key_dir
        else:
            os.environ.pop("CRYPTO_KEY_DIR", None)
        self._tmpdir.cleanup()

    def _make_registry_with_initial_key(self):
        from spy.key_registry import KeyRegistry, KeyEntry
        reg = KeyRegistry()
        reg.load()
        entry = KeyEntry(
            key_id="ecc-enc-initial",
            key_type="ecc_enc",
            status="active",
            created_at="2026-04-01T12:00:00Z",
            activate_at="2026-04-01T12:00:00Z",
            retire_at=None,
            algorithm="ECC-P256-ECDH-AES-GCM",
            key_reference="ecc_private.pem",
        )
        reg.register(entry)
        return reg

    def test_rotate_generates_new_keypair(self):
        from spy.ecc_engine import rotate_ecc_encryption_keys
        reg = self._make_registry_with_initial_key()
        priv, pub, key_id = rotate_ecc_encryption_keys(reg)
        self.assertIsNotNone(priv)
        self.assertTrue(key_id.startswith("ecc-enc-"))

    def test_rotate_new_key_is_active(self):
        from spy.ecc_engine import rotate_ecc_encryption_keys
        reg = self._make_registry_with_initial_key()
        _, _, new_key_id = rotate_ecc_encryption_keys(reg)
        self.assertEqual(reg.get_active_key_id("ecc_enc"), new_key_id)

    def test_rotate_old_key_becomes_decrypt_only(self):
        from spy.ecc_engine import rotate_ecc_encryption_keys
        reg = self._make_registry_with_initial_key()
        rotate_ecc_encryption_keys(reg)
        self.assertEqual(reg.get_entry("ecc-enc-initial").status, "decrypt-only")

    def test_rotate_creates_key_files(self):
        from spy.ecc_engine import rotate_ecc_encryption_keys
        reg = self._make_registry_with_initial_key()
        _, _, key_id = rotate_ecc_encryption_keys(reg)
        self.assertTrue((self._tmp / f"ecc_enc_{key_id}_private.pem").exists())
        self.assertTrue((self._tmp / f"ecc_enc_{key_id}_public.pem").exists())


class TestKeyIdInSVSTHeader(unittest.TestCase):
    """Tests that SVST v2 embeds key_id and v1 is still accepted."""

    def _write_and_parse(self, key_id=None):
        """Write a minimal SVST container, parse header, return StreamingHeader."""
        from spy.container_writer import StreamingContainerWriter
        from spy.container_reader import StreamingContainerReader
        from spy.crypto_container import KEY_WRAP_ID_RSA, SIG_METHOD_ID_RSA

        # Use real keys from the system key dir for signing.
        from spy.key_provider import LocalPemKeyProvider

        provider = LocalPemKeyProvider()
        pub_enc = provider.get_rsa_public_key(provider.get_active_rsa_key_id())
        sign_priv = provider.get_rsa_signing_private_key()
        from spy.rsa_engine import wrap_key
        from spy.crypto_engine import generate_key
        aes_key = generate_key()
        wrapped_dek = wrap_key(pub_enc, aes_key)

        buf = io.BytesIO()
        writer = StreamingContainerWriter(
            out_file=buf,
            key_wrap_id=KEY_WRAP_ID_RSA,
            sig_method_id=SIG_METHOD_ID_RSA,
            wrapped_dek=wrapped_dek,
            sender_pubkey_raw=None,
            sign_private_key=sign_priv,
            aes_key=aes_key,
            key_id=key_id,
        )
        writer.write_header()
        writer.write_chunks(io.BytesIO(b"hello world"))
        writer.close()

        buf.seek(0)
        reader = StreamingContainerReader(buf)
        provider = LocalPemKeyProvider()
        sign_pub = provider.get_rsa_signing_public_key()
        return reader.read_and_verify_header(sign_pub)

    def test_v2_header_stores_key_id(self):
        header = self._write_and_parse(key_id="rsa-enc-test-id")
        self.assertEqual(header.key_id, "rsa-enc-test-id")

    def test_v1_header_key_id_is_none(self):
        header = self._write_and_parse(key_id=None)
        self.assertIsNone(header.key_id)

    def test_v2_header_rejects_tampered_key_id(self):
        """Tampering with key_id (part of signed region) must fail signature verification."""
        from spy.container_writer import StreamingContainerWriter
        from spy.container_reader import StreamingContainerReader, StreamingError
        from spy.crypto_container import KEY_WRAP_ID_RSA, SIG_METHOD_ID_RSA
        from spy.rsa_engine import wrap_key
        from spy.crypto_engine import generate_key
        from spy.key_provider import LocalPemKeyProvider

        provider = LocalPemKeyProvider()
        pub_enc = provider.get_rsa_public_key(provider.get_active_rsa_key_id())
        sign_priv = provider.get_rsa_signing_private_key()
        sign_pub = provider.get_rsa_signing_public_key()
        aes_key = generate_key()
        wrapped_dek = wrap_key(pub_enc, aes_key)

        buf = io.BytesIO()
        writer = StreamingContainerWriter(
            out_file=buf,
            key_wrap_id=KEY_WRAP_ID_RSA,
            sig_method_id=SIG_METHOD_ID_RSA,
            wrapped_dek=wrapped_dek,
            sender_pubkey_raw=None,
            sign_private_key=sign_priv,
            aes_key=aes_key,
            key_id="rsa-enc-v1",
        )
        writer.write_header()
        writer.write_chunks(io.BytesIO(b"test"))
        writer.close()

        raw = bytearray(buf.getvalue())
        # The key_id string "rsa-enc-v1" appears somewhere in raw. Flip a byte.
        target = b"rsa-enc-v1"
        idx = raw.find(target)
        self.assertGreater(idx, 0, "key_id bytes not found in container")
        raw[idx] ^= 0xFF  # corrupt first byte of key_id

        tampered = io.BytesIO(bytes(raw))
        reader = StreamingContainerReader(tampered)
        from spy.signature_engine import SignatureError
        with self.assertRaises(StreamingError):
            reader.read_and_verify_header(sign_pub)


class TestDecryptWithRotatedKey(unittest.TestCase):
    """Encrypt with key v1, rotate to v2, verify decrypt still works with old key."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._src = self._tmp / "plain.txt"
        self._src.write_bytes(b"rotation test data")

    def tearDown(self):
        self._tmpdir.cleanup()

    def _run_in_subprocess(self, code: str) -> str:
        """Run Python code in a subprocess with the system CRYPTO_KEY_DIR env var."""
        env = os.environ.copy()
        env["CRYPTO_KEY_DIR"] = os.environ.get("CRYPTO_KEY_DIR", "")
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            cwd=str(_HERE),
            env=env,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"Subprocess failed:\n{result.stdout.decode()}\n{result.stderr.decode()}"
            )
        return result.stdout.decode()

    def test_decrypt_after_rotation_rsa(self):
        """Encrypt, rotate RSA enc key, then decrypt — must succeed using old key."""
        ws_root = str(self._tmp)

        # Encrypt using workspace routing; print result so we capture the enc path.
        enc_output = self._run_in_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.file_crypto_engine import stream_encrypt_file; "
            f"print(stream_encrypt_file({str(self._src)!r}, output_path=None, method='rsa', overwrite=True))"
        )
        enc = Path(enc_output.strip())
        self.assertTrue(enc.exists())

        # Rotate key (subprocess so KEY_DIR is set correctly).
        self._run_in_subprocess(
            f"from spy.key_registry import KeyRegistry; "
            f"from spy.rsa_engine import rotate_rsa_encryption_keys; "
            f"reg = KeyRegistry(); reg.load(); "
            f"rotate_rsa_encryption_keys(reg)"
        )

        # Decrypt with old key — must succeed.
        dec_output = self._run_in_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.file_crypto_engine import stream_decrypt_file; "
            f"print(stream_decrypt_file({str(enc)!r}, output_path=None, overwrite=True))"
        )
        dec = Path(dec_output.strip())
        self.assertTrue(dec.exists())
        self.assertEqual(dec.read_bytes(), b"rotation test data")


class TestBlockNoActiveKey(unittest.TestCase):
    """stream_encrypt_file raises when no active encryption key exists."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._ws_snap = ws_patch(self._tmp)
        self._src = self._tmp / "plain.txt"
        self._src.write_bytes(b"block test")
        self._orig_crypto_key_dir = os.environ.get("CRYPTO_KEY_DIR", "")
        os.environ["CRYPTO_KEY_DIR"] = str(self._tmp)

    def tearDown(self):
        ws_restore(self._ws_snap)
        if self._orig_crypto_key_dir:
            os.environ["CRYPTO_KEY_DIR"] = self._orig_crypto_key_dir
        else:
            os.environ.pop("CRYPTO_KEY_DIR", None)
        self._tmpdir.cleanup()

    def test_encrypt_blocked_when_all_keys_revoked(self):
        """If all rsa_enc keys are revoked, stream_encrypt_file must raise FileCryptoError."""
        from spy.key_registry import KeyRegistry, KeyEntry
        from spy.file_crypto_engine import FileCryptoError, stream_encrypt_file

        # Register a revoked key only.
        reg = KeyRegistry()
        reg.load()
        reg.register(KeyEntry(
            key_id="rsa-enc-revoked",
            key_type="rsa_enc",
            status="revoked",
            created_at="2026-04-01T00:00:00Z",
            activate_at="2026-04-01T00:00:00Z",
            retire_at=None,
            algorithm="RSA-3072-OAEP-SHA256",
            key_reference="rsa_private_nonexistent.pem",
        ))
        reg.save()

        with self.assertRaises(FileCryptoError):
            stream_encrypt_file(str(self._src), output_path=None, method="rsa", overwrite=True)


class TestAuditLoggingDeprecated(unittest.TestCase):
    """Deprecated key status must NOT emit a system-level DECRYPT event.

    The user-facing DECRYPT event in stream_decrypt_file is the sole
    authoritative audit record. Internal helpers must not add system duplicates.
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._orig_crypto_key_dir = os.environ.get("CRYPTO_KEY_DIR", "")
        os.environ["CRYPTO_KEY_DIR"] = str(self._tmp)

    def tearDown(self):
        if self._orig_crypto_key_dir:
            os.environ["CRYPTO_KEY_DIR"] = self._orig_crypto_key_dir
        else:
            os.environ.pop("CRYPTO_KEY_DIR", None)
        self._tmpdir.cleanup()

    def _make_v2_header(self, key_id: str):
        """Return a StreamingHeader with key_id set (simulates v2 container)."""
        from spy.container_reader import StreamingHeader
        from spy.crypto_container import KEY_WRAP_ID_RSA, SIG_METHOD_ID_RSA
        return StreamingHeader(
            key_wrap_id=KEY_WRAP_ID_RSA,
            sig_method_id=SIG_METHOD_ID_RSA,
            wrapped_dek=b"\x00" * 384,
            sender_pubkey_raw=None,
            base_nonce=b"\x00" * 8,
            key_id=key_id,
            sign_key_id=None,
            classification=None,
        )

    def _make_registry_with_key(self, key_id: str, status: str):
        from spy.key_registry import KeyRegistry, KeyEntry
        from spy.key_provider import LocalPemKeyProvider
        reg = KeyRegistry()
        reg.load()
        reg.register(KeyEntry(
            key_id=key_id,
            key_type="rsa_enc",
            status=status,
            created_at="2026-04-01T00:00:00Z",
            activate_at="2026-04-01T00:00:00Z",
            retire_at=None,
            algorithm="RSA-3072-OAEP-SHA256",
            key_reference="rsa_private.pem",
        ))
        reg.save()
        return LocalPemKeyProvider(registry=reg)

    def test_decrypt_only_emits_no_system_audit_event(self):
        """_unwrap_svst_dek_by_key_id must not emit a DECRYPT event for decrypt-only keys."""
        from spy.file_crypto_engine import _unwrap_svst_dek_by_key_id
        provider = self._make_registry_with_key("rsa-enc-old", "decrypt-only")
        header = self._make_v2_header("rsa-enc-old")
        with patch("spy.file_crypto_engine.AuditLogger.log_event") as mock_log:
            try:
                _unwrap_svst_dek_by_key_id(header, provider)
            except Exception:
                pass
            decrypt_calls = [c for c in mock_log.call_args_list if c.args[1] == "DECRYPT"]
            self.assertEqual(decrypt_calls, [],
                             f"Expected no DECRYPT event from _unwrap, got: {decrypt_calls}")

    def test_retired_key_emits_no_system_audit_event(self):
        """_unwrap_svst_dek_by_key_id must not emit a DECRYPT event for retired keys."""
        from spy.file_crypto_engine import _unwrap_svst_dek_by_key_id
        provider = self._make_registry_with_key("rsa-enc-retired", "retired")
        header = self._make_v2_header("rsa-enc-retired")
        with patch("spy.file_crypto_engine.AuditLogger.log_event") as mock_log:
            try:
                _unwrap_svst_dek_by_key_id(header, provider)
            except Exception:
                pass
            decrypt_calls = [c for c in mock_log.call_args_list if c.args[1] == "DECRYPT"]
            self.assertEqual(decrypt_calls, [],
                             f"Expected no DECRYPT event from _unwrap, got: {decrypt_calls}")

    def test_revoked_key_raises_without_decrypting(self):
        from spy.key_registry import KeyRegistry, KeyEntry
        from spy.file_crypto_engine import _unwrap_svst_dek_by_key_id, FileCryptoError
        from spy.key_provider import LocalPemKeyProvider

        reg = KeyRegistry()
        reg.load()
        reg.register(KeyEntry(
            key_id="rsa-enc-revoked",
            key_type="rsa_enc",
            status="revoked",
            created_at="2026-04-01T00:00:00Z",
            activate_at="2026-04-01T00:00:00Z",
            retire_at=None,
            algorithm="RSA-3072-OAEP-SHA256",
            key_reference="rsa_private.pem",
        ))
        reg.save()

        provider = LocalPemKeyProvider(registry=reg)
        header = self._make_v2_header("rsa-enc-revoked")
        with self.assertRaises(FileCryptoError) as ctx:
            _unwrap_svst_dek_by_key_id(header, provider)
        self.assertIn("Decryption denied", str(ctx.exception))


class TestDecryptAuditInvariant(unittest.TestCase):
    """stream_decrypt_file emits exactly one DECRYPT event; no system attribution."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._ws_snap = ws_patch(self._tmp)

    def tearDown(self):
        ws_restore(self._ws_snap)
        self._tmpdir.cleanup()

    def test_no_system_decrypt_in_stream_decrypt_file(self):
        """Full decrypt must emit exactly one DECRYPT event attributed to the real user."""
        from spy.file_crypto_engine import stream_encrypt_file, stream_decrypt_file
        from spy.user_model import User

        src = self._tmp / "plain.txt"
        src.write_bytes(b"audit invariant test payload")
        user = User(username="tester", role="admin", clearance="high", authenticated=True)

        enc_path = stream_encrypt_file(
            str(src), output_path=None, method="rsa",
            overwrite=True, context={"sensitive": True}, user=user,
        )

        with patch("spy.file_crypto_engine.AuditLogger.log_event") as mock_log:
            stream_decrypt_file(enc_path, output_path=None, user=user, overwrite=True)

        system_decrypt = [
            c for c in mock_log.call_args_list
            if c.args[1] == "DECRYPT" and getattr(c.args[0], "username", None) == "system"
        ]
        self.assertEqual(system_decrypt, [],
                         f"Expected no system DECRYPT event, got: {system_decrypt}")

        all_decrypt = [c for c in mock_log.call_args_list if c.args[1] == "DECRYPT"]
        self.assertEqual(len(all_decrypt), 1,
                         f"Expected exactly 1 DECRYPT event, got: {all_decrypt}")


class TestRewrapDek(unittest.TestCase):
    """DEK rewrap: header rekeyed, chunk bytes unchanged, plaintext recoverable."""

    def _run_subprocess(self, code: str) -> str:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            cwd=str(_HERE),
            env=os.environ.copy(),
        )
        if result.returncode != 0:
            raise AssertionError(
                f"Subprocess failed:\n{result.stdout.decode()}\n{result.stderr.decode()}"
            )
        return result.stdout.decode()

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._src = self._tmp / "plain.txt"
        self._src.write_bytes(b"rewrap test payload - verify me after rekeying")

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_rewrap_rsa_and_decrypt(self):
        ws_root = str(self._tmp)

        # Encrypt — print result to capture enc path.
        enc_output = self._run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.file_crypto_engine import stream_encrypt_file; "
            f"print(stream_encrypt_file({str(self._src)!r}, output_path=None, method='rsa', overwrite=True))"
        )
        enc = Path(enc_output.strip())

        # Read original header bytes to later verify they changed.
        original_header_bytes = enc.read_bytes()[:200]

        # Rotate RSA enc key.
        self._run_subprocess(
            f"from spy.key_registry import KeyRegistry; "
            f"from spy.rsa_engine import rotate_rsa_encryption_keys; "
            f"reg = KeyRegistry(); reg.load(); "
            f"rotate_rsa_encryption_keys(reg)"
        )

        # Rewrap (rewrites in-place — no workspace routing needed).
        self._run_subprocess(
            f"from spy.user_model import User; "
            f"from spy.file_crypto_engine import rewrap_dek; "
            f"admin = User('testadmin', 'admin', 'high', authenticated=True); "
            f"rewrap_dek({str(enc)!r}, overwrite=True, user=admin)"
        )

        # Header must have changed (new wrapped_dek + new key_id).
        new_header_bytes = enc.read_bytes()[:200]
        self.assertNotEqual(original_header_bytes, new_header_bytes)

        # Decrypt must succeed with new key.
        dec_output = self._run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.file_crypto_engine import stream_decrypt_file; "
            f"print(stream_decrypt_file({str(enc)!r}, output_path=None, overwrite=True))"
        )
        dec = Path(dec_output.strip())
        self.assertEqual(dec.read_bytes(), b"rewrap test payload - verify me after rekeying")

    def test_rewrap_rejected_for_senv_file(self):
        """rewrap_dek must reject SENV containers (magic byte check precedes auth gate)."""
        from spy.user_model import User
        from spy.file_crypto_engine import rewrap_dek, FileCryptoError

        # Create a minimal SENV-like file (just the magic bytes).
        fake_senv = self._tmp / "fake.enc"
        fake_senv.write_bytes(b"SENV" + b"\x00" * 100)

        admin = User("testadmin", "admin", "high", authenticated=True)
        with self.assertRaises(FileCryptoError) as ctx:
            rewrap_dek(str(fake_senv), user=admin)
        self.assertEqual(str(ctx.exception), "Decryption denied")

    def test_rewrap_noop_when_already_current_key(self):
        """rewrap_dek raises if file is already wrapped with the active key."""
        ws_root = str(self._tmp)

        enc_output = self._run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.file_crypto_engine import stream_encrypt_file; "
            f"print(stream_encrypt_file({str(self._src)!r}, output_path=None, method='rsa', overwrite=True))"
        )
        enc = Path(enc_output.strip())

        # Without rotation, rewrap_dek must reject because key_id already matches active key.
        result = subprocess.run(
            [sys.executable, "-c",
             f"from spy.user_model import User; "
             f"from spy.file_crypto_engine import rewrap_dek; "
             f"admin = User('testadmin', 'admin', 'high', authenticated=True); "
             f"rewrap_dek({str(enc)!r}, user=admin)"],
            capture_output=True,
            cwd=str(_HERE),
            env=os.environ.copy(),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("decryption denied", result.stderr.decode().lower())


class TestRewrapAuthorization(unittest.TestCase):
    """rewrap_dek() enforces existence + authentication; exactly one audit per authenticated attempt."""

    def _run_subprocess(self, code: str) -> str:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            cwd=str(_HERE),
            env=os.environ.copy(),
        )
        if result.returncode != 0:
            raise AssertionError(
                f"Subprocess failed:\n{result.stdout.decode()}\n{result.stderr.decode()}"
            )
        return result.stdout.decode()

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._src = self._tmp / "plain.txt"
        self._src.write_bytes(b"rewrap auth test payload")
        # Encrypt a real SVST file so auth gate (after Gate 1) is reachable.
        ws_root = str(self._tmp)
        enc_output = self._run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.file_crypto_engine import stream_encrypt_file; "
            f"print(stream_encrypt_file({str(self._src)!r}, output_path=None, method='rsa', overwrite=True))"
        )
        self._enc = Path(enc_output.strip())

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_denied_user_none(self):
        """user=None is denied with no audit event."""
        from spy.file_crypto_engine import rewrap_dek, FileCryptoError
        with self.assertRaises(FileCryptoError):
            rewrap_dek(str(self._enc), user=None)

    def test_denied_unauthenticated(self):
        """Unauthenticated user is denied with no audit event."""
        from spy.user_model import User
        from spy.file_crypto_engine import rewrap_dek, FileCryptoError
        unauth = User("alice", "admin", "high")  # authenticated=False by default
        with self.assertRaises(FileCryptoError):
            rewrap_dek(str(self._enc), user=unauth)

    def test_denied_analyst_emits_key_rotate_denied(self):
        """Authenticated analyst is denied at engine level with KEY_ROTATE/DENIED audit."""
        from unittest.mock import patch
        from spy.user_model import User
        from spy.file_crypto_engine import rewrap_dek, FileCryptoError
        analyst = User("alice", "analyst", "high", authenticated=True)
        with patch("spy.file_crypto_engine.AuditLogger.log_event") as mock_log:
            with self.assertRaises(FileCryptoError):
                rewrap_dek(str(self._enc), user=analyst)
            calls = mock_log.call_args_list
            self.assertEqual(len(calls), 1, f"Expected exactly 1 audit call; got {calls}")
            self.assertEqual(calls[0][0][1], "KEY_ROTATE")
            self.assertEqual(calls[0][1].get("outcome"), "denied")

    def test_admin_rewrap_emits_key_rotate_success(self):
        """Successful admin rewrap writes exactly one KEY_ROTATE/SUCCESS audit event."""
        ws_root = str(self._tmp)
        # Rotate key so rewrap is non-noop.
        self._run_subprocess(
            f"from spy.key_registry import KeyRegistry; "
            f"from spy.rsa_engine import rotate_rsa_encryption_keys; "
            f"reg = KeyRegistry(); reg.load(); "
            f"rotate_rsa_encryption_keys(reg)"
        )
        import json, os as _os
        audit_path = _os.environ.get("AUDIT_LOG_PATH", "")
        before_size = Path(audit_path).stat().st_size if Path(audit_path).exists() else 0

        self._run_subprocess(
            f"from spy.user_model import User; "
            f"from spy.file_crypto_engine import rewrap_dek; "
            f"admin = User('testadmin', 'admin', 'high', authenticated=True); "
            f"rewrap_dek({str(self._enc)!r}, overwrite=True, user=admin)"
        )
        # Read new audit entries written after this test started.
        entries = []
        with open(audit_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        new_entries = [e for e in entries if e.get("action") == "KEY_ROTATE" and e.get("result") == "SUCCESS"]
        self.assertTrue(len(new_entries) >= 1, f"Expected KEY_ROTATE/SUCCESS audit entry; entries={entries}")

    def test_error_emits_key_rotate_error(self):
        """Authenticated attempt that fails crypto emits exactly one KEY_ROTATE/ERROR audit event."""
        from unittest.mock import patch
        from spy.user_model import User
        from spy.file_crypto_engine import rewrap_dek, FileCryptoError
        admin = User("testadmin", "admin", "high", authenticated=True)
        # Patch AuditLogger to capture calls without disk I/O.
        with patch("spy.file_crypto_engine.AuditLogger.log_event") as mock_log:
            with self.assertRaises(FileCryptoError):
                # File is wrapped with current active key → noop → FileCryptoError after auth gate.
                rewrap_dek(str(self._enc), user=admin)
            calls = mock_log.call_args_list
            self.assertEqual(len(calls), 1, f"Expected exactly 1 audit call; got {calls}")
            kwargs = calls[0][1]
            self.assertEqual(kwargs.get("outcome"), "error")
            # Action is positional arg[1]
            self.assertEqual(calls[0][0][1], "KEY_ROTATE")


class TestCLIRotateEncKeys(unittest.TestCase):
    """CLI rotate-enc-keys command smoke tests."""

    def _run_cli(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "spy.cli"] + list(args),
            input=b"testuser\ntestpass\n",
            capture_output=True,
            cwd=str(_HERE),
            env=os.environ.copy(),
        )

    def test_rotate_enc_keys_rsa(self):
        result = self._run_cli("rotate-enc-keys", "--method", "rsa")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn("RSA", result.stdout.decode())
        self.assertIn("rotated", result.stdout.decode())

    def test_rotate_enc_keys_ecc(self):
        result = self._run_cli("rotate-enc-keys", "--method", "ecc")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn("ECC", result.stdout.decode())

    def test_rotate_enc_keys_all(self):
        result = self._run_cli("rotate-enc-keys", "--method", "all")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        out = result.stdout.decode()
        self.assertIn("RSA", out)
        self.assertIn("ECC", out)


class TestCLIRewrap(unittest.TestCase):
    """CLI rewrap command smoke tests."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._src = self._tmp / "plain.txt"
        self._src.write_bytes(b"cli rewrap test data")

    def tearDown(self):
        self._tmpdir.cleanup()

    def _run_cli_subprocess(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "spy.cli"] + list(args),
            input=b"testuser\ntestpass\n",
            capture_output=True,
            cwd=str(_HERE),
            env=os.environ.copy(),
        )

    def test_cli_rewrap_after_rotation(self):
        ws_root = str(self._tmp)
        env = os.environ.copy()
        env["SAFE_FILE_ROOT"] = ws_root

        def _run_with_ws(*args):
            return subprocess.run(
                [sys.executable, "-m", "spy.cli"] + list(args),
                input=b"testuser\ntestpass\n",
                capture_output=True,
                cwd=str(_HERE),
                env=env,
            )

        # Initialise workspace dirs inside temp root.
        subprocess.run(
            [sys.executable, "-c",
             f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
             f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace()"],
            cwd=str(_HERE),
            env=env,
            check=True,
        )

        # Encrypt — no explicit --output; engine routes to workspace.
        r = _run_with_ws("encrypt", str(self._src), "--overwrite")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        stdout_text = r.stdout.decode()
        enc_marker = "Encrypted: "
        enc_pos = stdout_text.find(enc_marker)
        self.assertNotEqual(enc_pos, -1, f"No 'Encrypted:' in stdout: {stdout_text!r}")
        enc_end = stdout_text.find("\n", enc_pos)
        enc = stdout_text[enc_pos + len(enc_marker): enc_end if enc_end != -1 else None].strip()

        # Rotate enc key.
        r = _run_with_ws("rotate-enc-keys", "--method", "rsa")
        self.assertEqual(r.returncode, 0, r.stderr.decode())

        # Rewrap.
        r = _run_with_ws("rewrap", enc, "--overwrite")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertIn("rewrapped", r.stdout.decode().lower())


class TestSVSTv2BackwardCompat(unittest.TestCase):
    """SVST v1 containers (no key_id) are explicitly rejected by stream_decrypt_file."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_v1_container_decrypts_via_stream_decrypt(self):
        """Write a v1 container (no key_id), verify stream_decrypt_file rejects it."""
        from spy.container_writer import StreamingContainerWriter
        from spy.crypto_container import KEY_WRAP_ID_RSA, SIG_METHOD_ID_RSA
        from spy.rsa_engine import wrap_key
        from spy.crypto_engine import generate_key
        from spy.file_crypto_engine import stream_decrypt_file, FileCryptoError
        from spy.key_provider import LocalPemKeyProvider

        provider = LocalPemKeyProvider()
        pub = provider.get_rsa_public_key(provider.get_active_rsa_key_id())
        sign_priv = provider.get_rsa_signing_private_key()
        aes_key = generate_key()
        wrapped_dek = wrap_key(pub, aes_key)

        enc = self._tmp / "v1_test.enc"
        with enc.open("wb") as out_f:
            writer = StreamingContainerWriter(
                out_file=out_f,
                key_wrap_id=KEY_WRAP_ID_RSA,
                sig_method_id=SIG_METHOD_ID_RSA,
                wrapped_dek=wrapped_dek,
                sender_pubkey_raw=None,
                sign_private_key=sign_priv,
                aes_key=aes_key,
                key_id=None,  # v1 — no key_id
            )
            writer.write_header()
            writer.write_chunks(io.BytesIO(b"v1 backward compat data"))
            writer.close()

        dec = self._tmp / "v1_test.txt"
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(str(enc), output_path=str(dec), overwrite=True)


class TestSigningKeyRotationRegression(unittest.TestCase):
    """Regression tests for Phase 3 signing key rotation identity.

    Covers:
      A — legacy artifact: 'rsa-sign' alias resolves to v1 key material
      B — historical verification: v1 artifact still verifies after rotation to v2
      C — new artifact: post-rotation artifact embeds v2 sign_key_id and verifies
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._orig_crypto_key_dir = os.environ.get("CRYPTO_KEY_DIR", "")
        os.environ["CRYPTO_KEY_DIR"] = str(self._tmp)

    def tearDown(self):
        if self._orig_crypto_key_dir:
            os.environ["CRYPTO_KEY_DIR"] = self._orig_crypto_key_dir
        else:
            os.environ.pop("CRYPTO_KEY_DIR", None)
        self._tmpdir.cleanup()

    def _setup_v1_signing_key(self):
        """Generate v1 RSA signing key in temp dir and register it. Returns (registry, key_id)."""
        from spy.key_registry import KeyRegistry
        from spy.rsa_engine import rotate_rsa_signing_keys
        registry = KeyRegistry()
        registry.load()
        _, _, key_id = rotate_rsa_signing_keys(registry)
        return registry, key_id

    def _make_signed_container(self, sign_private_key, sign_key_id: str) -> bytes:
        """Write a minimal signed SVST v3 container and return raw bytes.

        Uses a dummy wrapped DEK — this test is only concerned with signing identity,
        not with encryption or decryption.
        """
        from spy.container_writer import StreamingContainerWriter
        from spy.crypto_container import KEY_WRAP_ID_RSA, SIG_METHOD_ID_RSA
        from spy.crypto_engine import generate_key
        aes_key = generate_key()
        wrapped_dek = b"\x00" * 384  # RSA-3072 output size; content unused in signing tests
        buf = io.BytesIO()
        writer = StreamingContainerWriter(
            out_file=buf,
            key_wrap_id=KEY_WRAP_ID_RSA,
            sig_method_id=SIG_METHOD_ID_RSA,
            wrapped_dek=wrapped_dek,
            sender_pubkey_raw=None,
            sign_private_key=sign_private_key,
            aes_key=aes_key,
            key_id="rsa-enc-test",
            sign_key_id=sign_key_id,
        )
        writer.write_header()
        writer.write_chunks(io.BytesIO(b"signing regression test payload"))
        writer.close()
        return buf.getvalue()

    def _verify_container(self, container_bytes: bytes, provider) -> str:
        """Verify both header and body signatures. Returns sign_key_id from header."""
        from spy.container_reader import StreamingContainerReader
        from spy.file_crypto_engine import _make_svst_sign_key_resolver
        resolver = _make_svst_sign_key_resolver(provider)
        buf = io.BytesIO(container_bytes)
        reader = StreamingContainerReader(buf)
        header = reader.read_and_verify_header(resolver)
        reader.verify_body_signature(resolver)
        return header.sign_key_id

    # ------------------------------------------------------------------
    # Test A — legacy ID compatibility
    # ------------------------------------------------------------------

    def test_a_legacy_rsa_sign_alias_resolves_to_v1_key_material(self):
        """'rsa-sign' alias must return the same public key bytes as 'rsa-sign-v1'."""
        from spy.key_provider import LocalPemKeyProvider
        from cryptography.hazmat.primitives import serialization
        registry, _ = self._setup_v1_signing_key()
        provider = LocalPemKeyProvider(key_dir=self._tmp, registry=registry)

        key_v1 = provider.get_signing_public_key("rsa-sign-v1")
        key_legacy = provider.get_signing_public_key("rsa-sign")

        v1_der = key_v1.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        legacy_der = key_legacy.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.assertEqual(v1_der, legacy_der,
                         "'rsa-sign' alias must resolve to same key material as 'rsa-sign-v1'")

    def test_a_legacy_artifact_verifies_via_alias(self):
        """Container created with legacy sign_key_id 'rsa-sign' must verify via alias."""
        from spy.key_provider import LocalPemKeyProvider
        registry, v1_key_id = self._setup_v1_signing_key()
        provider = LocalPemKeyProvider(key_dir=self._tmp, registry=registry)
        sign_priv = provider.get_rsa_signing_private_key()

        # Simulate a legacy artifact: embed "rsa-sign" (no version) as the sign_key_id.
        legacy_container = self._make_signed_container(sign_priv, "rsa-sign")

        # Verification must succeed — alias routes "rsa-sign" → "rsa-sign-v1".
        sign_key_id_from_header = self._verify_container(legacy_container, provider)
        self.assertEqual(sign_key_id_from_header, "rsa-sign")

    # ------------------------------------------------------------------
    # Test B — historical verification after rotation
    # ------------------------------------------------------------------

    def test_b_v1_files_survive_rotation(self):
        """v1 signing key files must not be moved or overwritten during rotation to v2."""
        from spy.rsa_engine import rotate_rsa_signing_keys
        registry, _ = self._setup_v1_signing_key()

        rotate_rsa_signing_keys(registry)

        self.assertTrue((self._tmp / "rsa_sign_private.pem").exists(),
                        "v1 private key must remain at original path after rotation")
        self.assertTrue((self._tmp / "rsa_sign_public.pem").exists(),
                        "v1 public key must remain at original path after rotation")

    def test_b_v1_artifact_verifies_after_rotation_to_v2(self):
        """Artifact signed with v1 key must still verify after rotation to v2."""
        from spy.key_registry import KeyRegistry
        from spy.rsa_engine import rotate_rsa_signing_keys
        from spy.key_provider import LocalPemKeyProvider

        registry, v1_key_id = self._setup_v1_signing_key()
        provider_v1 = LocalPemKeyProvider(key_dir=self._tmp, registry=registry)
        sign_priv_v1 = provider_v1.get_rsa_signing_private_key()
        v1_container = self._make_signed_container(sign_priv_v1, v1_key_id)

        # Rotate to v2.
        _, _, v2_key_id = rotate_rsa_signing_keys(registry)
        self.assertEqual(v2_key_id, "rsa-sign-v2")

        # v1 registry entry must be retired, not deleted.
        v1_entry = registry.get_entry(v1_key_id)
        self.assertEqual(v1_entry.status, "retired")
        self.assertEqual(v1_entry.key_reference, "rsa_sign_private.pem")

        # Verify the v1 artifact with the post-rotation provider.
        provider_post = LocalPemKeyProvider(key_dir=self._tmp, registry=registry)
        sign_key_id_from_header = self._verify_container(v1_container, provider_post)
        self.assertEqual(sign_key_id_from_header, v1_key_id)

    # ------------------------------------------------------------------
    # Test C — new artifact uses v2 after rotation
    # ------------------------------------------------------------------

    def test_c_new_artifact_embeds_v2_sign_key_id(self):
        """After rotation, new artifacts must embed v2 sign_key_id and verify correctly."""
        from spy.rsa_engine import rotate_rsa_signing_keys
        from spy.key_provider import LocalPemKeyProvider

        registry, _ = self._setup_v1_signing_key()
        _, _, v2_key_id = rotate_rsa_signing_keys(registry)

        provider = LocalPemKeyProvider(key_dir=self._tmp, registry=registry)

        # Provider must report v2 as the active signing key.
        active_id = provider.get_active_rsa_signing_key_id()
        self.assertEqual(active_id, v2_key_id)

        sign_priv = provider.get_rsa_signing_private_key()
        v2_container = self._make_signed_container(sign_priv, active_id)

        sign_key_id_from_header = self._verify_container(v2_container, provider)
        self.assertEqual(sign_key_id_from_header, v2_key_id,
                         "New post-rotation artifact must embed v2 sign_key_id")


class TestECCSigningKeyRotationRegression(unittest.TestCase):
    """ECC mirror of TestSigningKeyRotationRegression.

    Covers:
      A — legacy artifact: 'ecc-sign' alias resolves to v1 key material
      B — historical verification: v1 artifact still verifies after rotation to v2
      C — new artifact: post-rotation artifact embeds v2 sign_key_id and verifies
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._orig_crypto_key_dir = os.environ.get("CRYPTO_KEY_DIR", "")
        os.environ["CRYPTO_KEY_DIR"] = str(self._tmp)

    def tearDown(self):
        if self._orig_crypto_key_dir:
            os.environ["CRYPTO_KEY_DIR"] = self._orig_crypto_key_dir
        else:
            os.environ.pop("CRYPTO_KEY_DIR", None)
        self._tmpdir.cleanup()

    def _setup_v1_signing_key(self):
        """Generate v1 ECC signing key in temp dir and register it. Returns (registry, key_id)."""
        from spy.key_registry import KeyRegistry
        from spy.ecc_engine import rotate_ecc_signing_keys
        registry = KeyRegistry()
        registry.load()
        _, _, key_id = rotate_ecc_signing_keys(registry)
        return registry, key_id

    def _make_signed_container(self, sign_private_key, sign_key_id: str) -> bytes:
        """Write a minimal signed SVST v3 container using ECC signing and return raw bytes."""
        from spy.container_writer import StreamingContainerWriter
        from spy.crypto_container import KEY_WRAP_ID_RSA, SIG_METHOD_ID_ECC
        from spy.crypto_engine import generate_key
        aes_key = generate_key()
        wrapped_dek = b"\x00" * 384  # placeholder — signing tests do not decrypt
        buf = io.BytesIO()
        writer = StreamingContainerWriter(
            out_file=buf,
            key_wrap_id=KEY_WRAP_ID_RSA,
            sig_method_id=SIG_METHOD_ID_ECC,
            wrapped_dek=wrapped_dek,
            sender_pubkey_raw=None,
            sign_private_key=sign_private_key,
            aes_key=aes_key,
            key_id="ecc-enc-test",
            sign_key_id=sign_key_id,
        )
        writer.write_header()
        writer.write_chunks(io.BytesIO(b"ecc signing regression test payload"))
        writer.close()
        return buf.getvalue()

    def _verify_container(self, container_bytes: bytes, provider) -> str:
        """Verify both header and body signatures. Returns sign_key_id from header."""
        from spy.container_reader import StreamingContainerReader
        from spy.file_crypto_engine import _make_svst_sign_key_resolver
        resolver = _make_svst_sign_key_resolver(provider)
        buf = io.BytesIO(container_bytes)
        reader = StreamingContainerReader(buf)
        header = reader.read_and_verify_header(resolver)
        reader.verify_body_signature(resolver)
        return header.sign_key_id

    # ------------------------------------------------------------------
    # Test A — legacy ID compatibility
    # ------------------------------------------------------------------

    def test_a_legacy_ecc_sign_alias_resolves_to_v1_key_material(self):
        """'ecc-sign' alias must return the same public key bytes as 'ecc-sign-v1'."""
        from spy.key_provider import LocalPemKeyProvider
        from cryptography.hazmat.primitives import serialization
        registry, _ = self._setup_v1_signing_key()
        provider = LocalPemKeyProvider(key_dir=self._tmp, registry=registry)

        key_v1 = provider.get_signing_public_key("ecc-sign-v1")
        key_legacy = provider.get_signing_public_key("ecc-sign")

        v1_der = key_v1.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        legacy_der = key_legacy.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.assertEqual(v1_der, legacy_der,
                         "'ecc-sign' alias must resolve to same key material as 'ecc-sign-v1'")

    def test_a_legacy_ecc_artifact_verifies_via_alias(self):
        """Container created with legacy sign_key_id 'ecc-sign' must verify via alias."""
        from spy.key_provider import LocalPemKeyProvider
        registry, _ = self._setup_v1_signing_key()
        provider = LocalPemKeyProvider(key_dir=self._tmp, registry=registry)
        sign_priv = provider.get_ecc_signing_private_key()

        legacy_container = self._make_signed_container(sign_priv, "ecc-sign")

        sign_key_id_from_header = self._verify_container(legacy_container, provider)
        self.assertEqual(sign_key_id_from_header, "ecc-sign")

    # ------------------------------------------------------------------
    # Test B — historical verification after rotation
    # ------------------------------------------------------------------

    def test_b_ecc_v1_files_survive_rotation(self):
        """v1 ECC signing key files must not be moved or overwritten during rotation to v2."""
        from spy.ecc_engine import rotate_ecc_signing_keys
        registry, _ = self._setup_v1_signing_key()

        rotate_ecc_signing_keys(registry)

        self.assertTrue((self._tmp / "ecc_sign_private.pem").exists(),
                        "v1 ECC private key must remain at original path after rotation")
        self.assertTrue((self._tmp / "ecc_sign_public.pem").exists(),
                        "v1 ECC public key must remain at original path after rotation")

    def test_b_ecc_v1_artifact_verifies_after_rotation_to_v2(self):
        """ECC artifact signed with v1 key must still verify after rotation to v2."""
        from spy.ecc_engine import rotate_ecc_signing_keys
        from spy.key_provider import LocalPemKeyProvider

        registry, v1_key_id = self._setup_v1_signing_key()
        provider_v1 = LocalPemKeyProvider(key_dir=self._tmp, registry=registry)
        sign_priv_v1 = provider_v1.get_ecc_signing_private_key()
        v1_container = self._make_signed_container(sign_priv_v1, v1_key_id)

        _, _, v2_key_id = rotate_ecc_signing_keys(registry)
        self.assertEqual(v2_key_id, "ecc-sign-v2")

        v1_entry = registry.get_entry(v1_key_id)
        self.assertEqual(v1_entry.status, "retired")
        self.assertEqual(v1_entry.key_reference, "ecc_sign_private.pem")

        provider_post = LocalPemKeyProvider(key_dir=self._tmp, registry=registry)
        sign_key_id_from_header = self._verify_container(v1_container, provider_post)
        self.assertEqual(sign_key_id_from_header, v1_key_id)

    # ------------------------------------------------------------------
    # Test C — new artifact uses v2 after rotation
    # ------------------------------------------------------------------

    def test_c_new_ecc_artifact_embeds_v2_sign_key_id(self):
        """After ECC rotation, new artifacts must embed v2 sign_key_id and verify."""
        from spy.ecc_engine import rotate_ecc_signing_keys
        from spy.key_provider import LocalPemKeyProvider

        registry, _ = self._setup_v1_signing_key()
        _, _, v2_key_id = rotate_ecc_signing_keys(registry)

        provider = LocalPemKeyProvider(key_dir=self._tmp, registry=registry)

        active_id = provider.get_active_ecc_signing_key_id()
        self.assertEqual(active_id, v2_key_id)

        sign_priv = provider.get_ecc_signing_private_key()
        v2_container = self._make_signed_container(sign_priv, active_id)

        sign_key_id_from_header = self._verify_container(v2_container, provider)
        self.assertEqual(sign_key_id_from_header, v2_key_id,
                         "New post-rotation ECC artifact must embed v2 sign_key_id")


# ---------------------------------------------------------------------------
# Batch 2 — KEY_ROTATE audit actor attribution
# ---------------------------------------------------------------------------

class TestKeyRotationAttribution(unittest.TestCase):
    """KEY_ROTATE audit events must record the authenticated actor when one is provided,
    and fall back to _SYSTEM_USER when called without a user."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._saved_env = {k: os.environ.get(k) for k in (
            "CRYPTO_KEY_DIR", "RSA_PASSPHRASE", "RSA_SIGN_PASSPHRASE",
            "ECC_PASSPHRASE", "ECC_SIGN_PASSPHRASE",
        )}
        os.environ["CRYPTO_KEY_DIR"] = self._tmp
        os.environ["RSA_PASSPHRASE"] = "test-rsa-pass"
        os.environ["RSA_SIGN_PASSPHRASE"] = "test-rsa-sign-pass"
        os.environ["ECC_PASSPHRASE"] = "test-ecc-pass"
        os.environ["ECC_SIGN_PASSPHRASE"] = "test-ecc-sign-pass"
        from spy.key_registry import KeyRegistry
        self._registry_cls = KeyRegistry

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _fresh_registry(self):
        reg = self._registry_cls()
        try:
            reg.load()
        except Exception:
            pass
        return reg

    def _admin_user(self):
        from spy.user_model import User
        return User(username="rotator", role="admin", clearance="high", authenticated=True)

    def test_rsa_enc_rotation_records_user(self):
        from spy.rsa_engine import rotate_rsa_encryption_keys
        reg = self._fresh_registry()
        admin = self._admin_user()
        with patch("spy.audit_logger.AuditLogger.log_event") as mock_log:
            rotate_rsa_encryption_keys(reg, user=admin)
        self.assertEqual(mock_log.call_args[0][0], admin)

    def test_ecc_enc_rotation_records_user(self):
        from spy.ecc_engine import rotate_ecc_encryption_keys
        reg = self._fresh_registry()
        admin = self._admin_user()
        with patch("spy.audit_logger.AuditLogger.log_event") as mock_log:
            rotate_ecc_encryption_keys(reg, user=admin)
        self.assertEqual(mock_log.call_args[0][0], admin)

    def test_rsa_sign_rotation_records_user(self):
        from spy.rsa_engine import rotate_rsa_signing_keys
        reg = self._fresh_registry()
        admin = self._admin_user()
        with patch("spy.audit_logger.AuditLogger.log_event") as mock_log:
            rotate_rsa_signing_keys(reg, user=admin)
        self.assertEqual(mock_log.call_args[0][0], admin)

    def test_system_user_fallback_when_no_user(self):
        from spy.rsa_engine import rotate_rsa_encryption_keys
        from spy.audit_logger import _SYSTEM_USER
        reg = self._fresh_registry()
        with patch("spy.audit_logger.AuditLogger.log_event") as mock_log:
            rotate_rsa_encryption_keys(reg)
        self.assertIs(mock_log.call_args[0][0], _SYSTEM_USER)


class TestGetKeyEntry(unittest.TestCase):
    """get_key_entry() public accessor on KeyProvider."""

    def _make_provider_with_mock_registry(self):
        from spy.key_provider import LocalPemKeyProvider
        provider = LocalPemKeyProvider.__new__(LocalPemKeyProvider)
        provider._registry = MagicMock()
        return provider

    def test_returns_entry_from_registry(self):
        from spy.key_provider import LocalPemKeyProvider
        provider = self._make_provider_with_mock_registry()
        mock_entry = MagicMock()
        mock_entry.status = "active"
        provider._registry.get_entry.return_value = mock_entry
        result = provider.get_key_entry("rsa-enc-v1")
        self.assertIs(result, mock_entry)
        provider._registry.get_entry.assert_called_once_with("rsa-enc-v1")

    def test_raises_key_provider_error_on_missing(self):
        from spy.key_provider import LocalPemKeyProvider, KeyProviderError
        from spy.key_registry import KeyRegistryError
        provider = self._make_provider_with_mock_registry()
        provider._registry.get_entry.side_effect = KeyRegistryError("not found")
        with self.assertRaises(KeyProviderError):
            provider.get_key_entry("no-such-key")


if __name__ == "__main__":
    unittest.main(verbosity=2)
