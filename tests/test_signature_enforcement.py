"""
test_signature_enforcement.py — Validates authenticity guarantees at system boundary.

Tests sign-then-encrypt / verify-before-decrypt enforcement entirely through
stream_encrypt_file and stream_decrypt_file public interfaces only.
No internal APIs, container structures, or private helpers are used.
"""

from __future__ import annotations

import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from spy.file_crypto_engine import FileCryptoError, stream_decrypt_file, stream_encrypt_file
from spy.key_provider import KeyProviderError, LocalPemKeyProvider
from spy.rsa_engine import generate_rsa_keypair
from tests.conftest import ws_patch, ws_restore


# ---------------------------------------------------------------------------
# Provider stubs — injected via provider= to test key-resolution failure paths
# ---------------------------------------------------------------------------

class _WrongKeyProvider(LocalPemKeyProvider):
    """Returns a freshly generated RSA public key instead of the real signing key."""

    def get_signing_public_key(self, key_id: str):
        _, wrong_pub = generate_rsa_keypair()
        return wrong_pub

    def get_rsa_signing_public_key(self):
        _, wrong_pub = generate_rsa_keypair()
        return wrong_pub

    def get_ecc_signing_public_key(self):
        from spy.ecc_engine import generate_ecc_keypair
        _, wrong_pub = generate_ecc_keypair()
        return wrong_pub


class _UnknownKeyProvider(LocalPemKeyProvider):
    """Raises KeyProviderError for all signing key resolution."""

    def get_signing_public_key(self, key_id: str):
        raise KeyProviderError(f"Key not found: {key_id!r}")

    def get_rsa_signing_public_key(self):
        raise KeyProviderError("Key not found")

    def get_ecc_signing_public_key(self):
        raise KeyProviderError("Key not found")


# ---------------------------------------------------------------------------
# Binary tamper helpers — file-level byte manipulation, no Python internal APIs
# ---------------------------------------------------------------------------

def _tamper_chunk(enc_path: str) -> None:
    """Flip one byte at the start of the first encrypted chunk payload."""
    data = Path(enc_path).read_bytes()
    raw = bytearray(data)

    version = data[4]
    key_wrap_id = data[5]
    wrapped_dek_len = struct.unpack(">H", data[8:10])[0]
    offset = 10 + wrapped_dek_len

    if key_wrap_id == 0x02:  # ECC: skip sender pubkey
        pubkey_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2 + pubkey_len

    offset += 8  # base_nonce

    if version >= 0x02:  # key_id field
        key_id_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2 + key_id_len
    if version >= 0x03:  # sign_key_id field
        sign_key_id_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2 + sign_key_id_len
    if version >= 0x04:  # classification field (1-byte length prefix)
        cls_len = data[offset]
        offset += 1 + cls_len

    sig_len = struct.unpack(">I", data[offset:offset + 4])[0]
    payload_start = offset + 4 + sig_len

    raw[payload_start] ^= 0xFF
    Path(enc_path).write_bytes(bytes(raw))


def _zero_sig_len(enc_path: str) -> None:
    """Zero the body signature length trailer — simulates a missing signature."""
    data = bytearray(Path(enc_path).read_bytes())
    data[-4:] = b'\x00\x00\x00\x00'
    Path(enc_path).write_bytes(bytes(data))


def _tamper_body_sig(enc_path: str) -> None:
    """Flip the first byte of the body signature — corrupts the signature itself."""
    data = Path(enc_path).read_bytes()
    raw = bytearray(data)
    sig_len = struct.unpack(">I", data[-4:])[0]
    sig_start = len(data) - 4 - sig_len
    raw[sig_start] ^= 0xFF
    Path(enc_path).write_bytes(bytes(raw))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSignatureEnforcement(unittest.TestCase):
    """Authenticity guarantees validated entirely through the public encrypt/decrypt API."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        self._plaintext = b"signature enforcement test payload"

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)

    def _encrypt(self) -> str:
        fd, src = tempfile.mkstemp(suffix=".txt")
        try:
            os.write(fd, self._plaintext)
        finally:
            os.close(fd)
        try:
            return stream_encrypt_file(src, output_path=None, method="rsa")
        finally:
            Path(src).unlink(missing_ok=True)

    def test_valid_roundtrip(self):
        """Encrypt then decrypt succeeds — proves signature is created and verified."""
        enc = self._encrypt()
        dec = stream_decrypt_file(enc, output_path=None)
        self.assertEqual(Path(dec).read_bytes(), self._plaintext)

    def test_tampered_ciphertext_fails(self):
        """Flipping a byte in the encrypted payload must be detected and rejected."""
        enc = self._encrypt()
        _tamper_chunk(enc)
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(enc, output_path=None)

    def test_wrong_signing_key_fails(self):
        """A provider returning the wrong public key must cause decryption to fail."""
        enc = self._encrypt()
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(enc, output_path=None, provider=_WrongKeyProvider())

    def test_missing_body_signature_fails(self):
        """Zeroing the signature length trailer must cause decryption to fail."""
        enc = self._encrypt()
        _zero_sig_len(enc)
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(enc, output_path=None)

    def test_unknown_sign_key_id_fails(self):
        """A provider that cannot resolve the signing key must cause decryption to fail."""
        enc = self._encrypt()
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(enc, output_path=None, provider=_UnknownKeyProvider())

    def test_tampered_body_signature_fails(self):
        """Corrupting the signature bytes themselves must cause decryption to fail."""
        enc = self._encrypt()
        _tamper_body_sig(enc)
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(enc, output_path=None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
