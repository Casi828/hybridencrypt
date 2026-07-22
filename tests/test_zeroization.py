"""
test_zeroization.py — P2-A best-effort DEK and passphrase zeroization tests.

Scope: caller-controlled mutable buffers only. We capture the bytearray reference
via mocked constructors/methods, then verify it is zeroed after the function
returns (success path) or raises (exception path).

Not in scope: zeroization of copies made by the cryptography library internals
(e.g., bytes(aes_key) passed to RSA OAEP binding). That is the documented limitation.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import ws_patch, ws_restore


# ---------------------------------------------------------------------------
# DEK zeroization — stream_encrypt_file
# ---------------------------------------------------------------------------

class TestEncryptDEKZeroization(unittest.TestCase):
    """DEK bytearray is zeroed in the finally block of stream_encrypt_file."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        self._src = self._ws_root / "plain.txt"
        self._src.write_text("encrypt zeroization test")

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)

    def _capture_writer(self):
        """Return (captured_list, CapturingWriter class).

        CapturingWriter stores a reference to the aes_key bytearray so the
        test can inspect it after the function returns.
        """
        from spy.container_writer import StreamingContainerWriter

        captured = []

        class CapturingWriter(StreamingContainerWriter):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                captured.append(self._aes_key)

        return captured, CapturingWriter

    def test_dek_zeroed_on_success_rsa(self):
        from spy.file_crypto_engine import stream_encrypt_file

        captured, CapturingWriter = self._capture_writer()

        with patch("spy.file_crypto_engine.StreamingContainerWriter", CapturingWriter):
            stream_encrypt_file(str(self._src), output_path=None, method="rsa")

        self.assertTrue(captured, "DEK bytearray was not captured")
        dek = captured[0]
        self.assertEqual(len(dek), 32)
        self.assertTrue(
            all(b == 0 for b in dek),
            f"DEK not zeroed after successful encrypt (first 8 bytes: {bytes(dek[:8]).hex()})",
        )

    def test_dek_zeroed_on_success_ecc(self):
        from spy.file_crypto_engine import stream_encrypt_file

        captured, CapturingWriter = self._capture_writer()

        with patch("spy.file_crypto_engine.StreamingContainerWriter", CapturingWriter):
            stream_encrypt_file(str(self._src), output_path=None, method="ecc")

        self.assertTrue(captured, "DEK bytearray was not captured")
        dek = captured[0]
        self.assertEqual(len(dek), 32)
        self.assertTrue(
            all(b == 0 for b in dek),
            f"DEK not zeroed after successful ECC encrypt",
        )

    def test_dek_zeroed_on_writer_exception(self):
        """DEK bytearray is zeroed even when the container writer raises."""
        from spy.container_writer import ContainerWriterError, StreamingContainerWriter
        from spy.file_crypto_engine import FileCryptoError, stream_encrypt_file

        captured = []

        class FailingWriter(StreamingContainerWriter):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                captured.append(self._aes_key)
                raise ContainerWriterError("simulated writer failure")

        with patch("spy.file_crypto_engine.StreamingContainerWriter", FailingWriter):
            with self.assertRaises(FileCryptoError):
                stream_encrypt_file(str(self._src), output_path=None, method="rsa")

        self.assertTrue(captured, "DEK bytearray was not captured before failure")
        dek = captured[0]
        self.assertTrue(
            all(b == 0 for b in dek),
            f"DEK not zeroed after exception (first 8 bytes: {bytes(dek[:8]).hex()})",
        )


# ---------------------------------------------------------------------------
# DEK zeroization — stream_decrypt_file
# ---------------------------------------------------------------------------

class TestDecryptDEKZeroization(unittest.TestCase):
    """DEK bytearray is zeroed in the finally block of stream_decrypt_file."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)

        src = self._ws_root / "plain.txt"
        src.write_text("decrypt zeroization test")
        try:
            from spy.file_crypto_engine import stream_encrypt_file
            enc_path = stream_encrypt_file(str(src), output_path=None, method="rsa")
            self._enc = Path(enc_path)
            self._ready = True
        except Exception:
            self._ready = False

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)

    def _capture_iter(self):
        """Return (captured_list, patched iter method).

        The patched method stores a reference to the aes_key bytearray and
        still delegates to the real implementation.
        """
        from spy.container_reader import StreamingContainerReader

        captured = []
        original_iter = StreamingContainerReader.iter_plaintext_chunks

        def capturing_iter(self_reader, aes_key):
            captured.append(aes_key)
            yield from original_iter(self_reader, aes_key)

        return captured, capturing_iter

    def test_dek_zeroed_on_success(self):
        if not self._ready:
            self.skipTest("No encrypted file — key infrastructure not available")

        from spy.container_reader import StreamingContainerReader
        from spy.file_crypto_engine import stream_decrypt_file

        captured, capturing_iter = self._capture_iter()

        with patch.object(StreamingContainerReader, "iter_plaintext_chunks", capturing_iter):
            stream_decrypt_file(str(self._enc), output_path=None, overwrite=True)

        self.assertTrue(captured, "DEK bytearray was not captured")
        dek = captured[0]
        self.assertEqual(len(dek), 32)
        self.assertTrue(
            all(b == 0 for b in dek),
            f"DEK not zeroed after successful decrypt",
        )

    def test_dek_zeroed_on_chunk_exception(self):
        """DEK bytearray is zeroed even when chunk decryption raises."""
        if not self._ready:
            self.skipTest("No encrypted file — key infrastructure not available")

        from spy.container_reader import StreamingContainerReader
        from spy.file_crypto_engine import FileCryptoError, stream_decrypt_file

        captured = []
        original_iter = StreamingContainerReader.iter_plaintext_chunks

        def failing_iter(self_reader, aes_key):
            captured.append(aes_key)
            # Exhaust one real chunk, then raise to simulate a mid-stream failure.
            it = original_iter(self_reader, aes_key)
            try:
                yield next(it)
            except StopIteration:
                pass
            from spy.container_reader import StreamingError
            raise StreamingError("simulated chunk failure")

        with patch.object(StreamingContainerReader, "iter_plaintext_chunks", failing_iter):
            with self.assertRaises(FileCryptoError):
                stream_decrypt_file(str(self._enc), output_path=None, overwrite=True)

        self.assertTrue(captured, "DEK bytearray was not captured before failure")
        dek = captured[0]
        self.assertTrue(
            all(b == 0 for b in dek),
            f"DEK not zeroed after chunk exception",
        )


# ---------------------------------------------------------------------------
# Passphrase zeroization — LocalPemKeyProvider
# ---------------------------------------------------------------------------

class TestPassphraseZeroization(unittest.TestCase):
    """Passphrase bytearrays are zeroed in finally blocks of private key getters.

    For each getter, two cases: successful PEM load and failed PEM load (wrong
    passphrase). In both cases the bytearray must be zeroed before the method
    returns or raises.
    """

    def _real_passphrase_as_bytearray(self, env_var: str) -> bytearray:
        """Return the real passphrase as a fresh bytearray (or a dummy if not set)."""
        val = os.environ.get(env_var, "").strip()
        return bytearray(val.encode("utf-8")) if val else bytearray(b"placeholder")

    def _provider_and_key_id(self, key_type: str):
        from spy.key_provider import LocalPemKeyProvider
        provider = LocalPemKeyProvider()
        from spy.key_registry import KeyRegistry
        registry = KeyRegistry()
        registry.load()
        ids = registry.list_by_type(key_type)
        if not ids:
            return None, None
        active = [e for e in ids if e.status == "active"]
        if not active:
            return None, None
        return provider, active[0].key_id

    # --- RSA encryption key ---

    def test_rsa_passphrase_zeroed_on_success(self):
        from spy.key_provider import LocalPemKeyProvider

        provider, key_id = self._provider_and_key_id("rsa_enc")
        if key_id is None:
            self.skipTest("No active rsa_enc key")

        passphrase_buf = self._real_passphrase_as_bytearray("RSA_KEY_PASSPHRASE")

        with patch.object(provider, "_rsa_passphrase", return_value=passphrase_buf):
            key = provider.get_rsa_private_key(key_id)

        self.assertIsNotNone(key)
        self.assertTrue(
            all(b == 0 for b in passphrase_buf),
            "RSA passphrase not zeroed after successful key load",
        )

    def test_rsa_passphrase_zeroed_on_failure(self):
        from spy.key_provider import KeyProviderError, LocalPemKeyProvider

        provider, key_id = self._provider_and_key_id("rsa_enc")
        if key_id is None:
            self.skipTest("No active rsa_enc key")

        passphrase_buf = bytearray(b"definitely_wrong_passphrase")

        with patch.object(provider, "_rsa_passphrase", return_value=passphrase_buf):
            with self.assertRaises(KeyProviderError):
                provider.get_rsa_private_key(key_id)

        self.assertTrue(
            all(b == 0 for b in passphrase_buf),
            "RSA passphrase not zeroed after failed key load",
        )

    # --- ECC encryption key ---

    def test_ecc_passphrase_zeroed_on_success(self):
        from spy.key_provider import LocalPemKeyProvider

        provider, key_id = self._provider_and_key_id("ecc_enc")
        if key_id is None:
            self.skipTest("No active ecc_enc key")

        passphrase_buf = self._real_passphrase_as_bytearray("ECC_KEY_PASSPHRASE")

        with patch.object(provider, "_ecc_passphrase", return_value=passphrase_buf):
            key = provider.get_ecc_private_key(key_id)

        self.assertIsNotNone(key)
        self.assertTrue(
            all(b == 0 for b in passphrase_buf),
            "ECC passphrase not zeroed after successful key load",
        )

    def test_ecc_passphrase_zeroed_on_failure(self):
        from spy.key_provider import KeyProviderError, LocalPemKeyProvider

        provider, key_id = self._provider_and_key_id("ecc_enc")
        if key_id is None:
            self.skipTest("No active ecc_enc key")

        passphrase_buf = bytearray(b"wrong_ecc_passphrase")

        with patch.object(provider, "_ecc_passphrase", return_value=passphrase_buf):
            with self.assertRaises(KeyProviderError):
                provider.get_ecc_private_key(key_id)

        self.assertTrue(
            all(b == 0 for b in passphrase_buf),
            "ECC passphrase not zeroed after failed key load",
        )

    # --- RSA signing key ---

    def test_rsa_sign_passphrase_zeroed_on_success(self):
        from spy.key_provider import LocalPemKeyProvider

        provider = LocalPemKeyProvider()
        passphrase_buf = self._real_passphrase_as_bytearray("RSA_SIGN_KEY_PASSPHRASE")

        try:
            provider.get_active_rsa_signing_key_id()
        except Exception:
            self.skipTest("No active RSA signing key")

        with patch.object(provider, "_rsa_sign_passphrase", return_value=passphrase_buf):
            key = provider.get_rsa_signing_private_key()

        self.assertIsNotNone(key)
        self.assertTrue(
            all(b == 0 for b in passphrase_buf),
            "RSA signing passphrase not zeroed after successful load",
        )

    def test_rsa_sign_passphrase_zeroed_on_failure(self):
        from spy.key_provider import KeyProviderError, LocalPemKeyProvider

        provider = LocalPemKeyProvider()

        try:
            provider.get_active_rsa_signing_key_id()
        except Exception:
            self.skipTest("No active RSA signing key")

        passphrase_buf = bytearray(b"wrong_sign_passphrase")

        with patch.object(provider, "_rsa_sign_passphrase", return_value=passphrase_buf):
            with self.assertRaises(KeyProviderError):
                provider.get_rsa_signing_private_key()

        self.assertTrue(
            all(b == 0 for b in passphrase_buf),
            "RSA signing passphrase not zeroed after failed load",
        )

    # --- ECC signing key ---

    def test_ecc_sign_passphrase_zeroed_on_success(self):
        from spy.key_provider import LocalPemKeyProvider

        provider = LocalPemKeyProvider()
        passphrase_buf = self._real_passphrase_as_bytearray("ECC_SIGN_KEY_PASSPHRASE")

        try:
            provider.get_active_ecc_signing_key_id()
        except Exception:
            self.skipTest("No active ECC signing key")

        with patch.object(provider, "_ecc_sign_passphrase", return_value=passphrase_buf):
            key = provider.get_ecc_signing_private_key()

        self.assertIsNotNone(key)
        self.assertTrue(
            all(b == 0 for b in passphrase_buf),
            "ECC signing passphrase not zeroed after successful load",
        )

    def test_ecc_sign_passphrase_zeroed_on_failure(self):
        from spy.key_provider import KeyProviderError, LocalPemKeyProvider

        provider = LocalPemKeyProvider()

        try:
            provider.get_active_ecc_signing_key_id()
        except Exception:
            self.skipTest("No active ECC signing key")

        passphrase_buf = bytearray(b"wrong_ecc_sign_passphrase")

        with patch.object(provider, "_ecc_sign_passphrase", return_value=passphrase_buf):
            with self.assertRaises(KeyProviderError):
                provider.get_ecc_signing_private_key()

        self.assertTrue(
            all(b == 0 for b in passphrase_buf),
            "ECC signing passphrase not zeroed after failed load",
        )


if __name__ == "__main__":
    unittest.main()
