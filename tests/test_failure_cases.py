"""
test_failure_cases.py — Failure and fault-tolerance tests.

Covers:
  - Wrong key decryption
  - Tampered ciphertext detection
  - Corrupted metadata / bad container
  - Unsupported container version
  - Empty file encryption
  - Large file encryption round-trip
  - Governance rule violations
  - Signature tamper detection

Run with: python3 -m unittest test_failure_cases -v
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from spy.crypto_container import ContainerError, decode_container, encode_container
from spy.ecc_engine import generate_ecc_keypair, serialize_public_key
from spy.file_crypto_engine import (
    FileCryptoError,
    stream_decrypt_file, stream_encrypt_file,
)
from spy.governance_rules import GovernanceViolation, enforce_aes_key_size, enforce_ecc_curve, enforce_rsa_key_size
from spy.hybrid_engine import HybridEngineError, decrypt_hybrid, encrypt_hybrid
from spy.rsa_engine import generate_rsa_keypair
from spy.signature_engine import SignatureError, sign, verify
from tests.conftest import ws_patch, ws_restore


class TestWrongKeyDecryption(unittest.TestCase):
    """Decryption with the wrong key must fail, not silently return garbage."""

    def test_rsa_wrong_private_key(self):
        priv1, pub1 = generate_rsa_keypair()
        priv2, _ = generate_rsa_keypair()
        pkg = encrypt_hybrid(b"secret", method="rsa", public_key=pub1)
        with self.assertRaises(HybridEngineError):
            decrypt_hybrid("rsa", priv2, pkg.encrypted_aes_key, pkg.encrypted_message)

    def test_ecc_wrong_receiver_key(self):
        recv_priv1, recv_pub1 = generate_ecc_keypair()
        recv_priv2, _ = generate_ecc_keypair()
        send_priv, send_pub = generate_ecc_keypair()
        sender_bytes = serialize_public_key(send_pub)
        aad = b"test|ecc|" + sender_bytes
        pkg = encrypt_hybrid(
            b"secret", method="ecc",
            public_key=recv_pub1, sender_private_key=send_priv, associated_data=aad,
        )
        with self.assertRaises(HybridEngineError):
            decrypt_hybrid(
                "ecc", recv_priv2, pkg.encrypted_aes_key, pkg.encrypted_message,
                sender_public_key=send_pub, associated_data=aad,
            )


class TestTamperedCiphertext(unittest.TestCase):
    """Mutating any byte of the ciphertext must cause authentication failure."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)

    def _make_enc_file(self, method: str) -> str:
        fd, src = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "wb") as f:
            f.write(b"tamper test payload")
        try:
            enc = stream_encrypt_file(src, method=method, overwrite=True)
        finally:
            Path(src).unlink(missing_ok=True)
        return enc

    def _tamper_senv(self, enc_path: str) -> None:
        """Flip a byte in the SVST container payload to trigger signature failure.

        Navigates the variable-length SVST header to find the first chunk, then
        flips a byte so the GCM tag mismatch is detected on decrypt.

        SVST header layout (RSA v2):
          magic(4) + version(1) + key_wrap_id(1) + sig_method_id(1) + flags(1) +
          wrapped_dek_len(2BE) + wrapped_dek(N) +
          [ECC: pubkey_len(2BE) + pubkey_raw(M)] +
          base_nonce(8) +
          [v2: key_id_len(2BE) + key_id(K)] +
          sig_len(4BE) + sig(S) + chunks...
        """
        data = Path(enc_path).read_bytes()
        raw = bytearray(data)

        key_wrap_id = data[5]
        version = data[4]
        wrapped_dek_len = struct.unpack(">H", data[8:10])[0]
        offset = 10 + wrapped_dek_len  # end of wrapped_dek

        # ECC: skip sender pubkey field
        if key_wrap_id == 0x02:  # KEY_WRAP_ID_ECC
            pubkey_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2 + pubkey_len

        offset += 8  # base_nonce

        # v2/v3/v4: skip key_id field
        if version >= 0x02:  # STREAMING_CONTAINER_VERSION_V2 or higher
            key_id_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2 + key_id_len
        # v3/v4: also skip sign_key_id field
        if version >= 0x03:  # STREAMING_CONTAINER_VERSION_V3 or higher
            sign_key_id_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2 + sign_key_id_len
        # v4: also skip classification field (1-byte length + bytes)
        if version >= 0x04:  # STREAMING_CONTAINER_VERSION_V4
            cls_len = data[offset]
            offset += 1 + cls_len

        sig_len = struct.unpack(">I", data[offset:offset + 4])[0]
        payload_start = offset + 4 + sig_len  # first chunk starts here

        if payload_start >= len(raw):
            raise ValueError(f"Container too short to tamper: payload_start={payload_start}, len={len(raw)}")
        raw[payload_start] ^= 0xFF
        Path(enc_path).write_bytes(bytes(raw))

    def test_rsa_tamper_detected(self):
        enc = self._make_enc_file("rsa")
        self._tamper_senv(enc)
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(enc)

    def test_ecc_tamper_detected(self):
        enc = self._make_enc_file("ecc")
        self._tamper_senv(enc)
        with self.assertRaises(FileCryptoError):
            stream_decrypt_file(enc)


class TestCorruptedMetadata(unittest.TestCase):
    """Corrupted JSON container must raise ContainerError."""

    def test_garbage_bytes(self):
        with self.assertRaises(ContainerError):
            decode_container(b"\x00\x01\x02garbage data that is not valid")

    def test_wrong_version(self):
        container = json.loads(encode_container("rsa", b"A" * 384, b"\x00" * 12 + b"\x01" * 1 + b"\x00" * 16))
        container["version"] = 99
        with self.assertRaises(ContainerError):
            decode_container(json.dumps(container).encode())

    def test_invalid_cipher_field(self):
        container = json.loads(encode_container("rsa", b"A" * 384, b"\x00" * 12 + b"\x01" * 1 + b"\x00" * 16))
        container["cipher"] = "AES-128-CBC"
        with self.assertRaises(ContainerError):
            decode_container(json.dumps(container).encode())

    def test_missing_nonce_field(self):
        container = json.loads(encode_container("rsa", b"A" * 384, b"\x00" * 12 + b"\x01" * 1 + b"\x00" * 16))
        del container["nonce"]
        with self.assertRaises(ContainerError):
            decode_container(json.dumps(container).encode())

    def test_truncated_json(self):
        raw = encode_container("rsa", b"A" * 384, b"\x00" * 12 + b"\x01" * 1 + b"\x00" * 16)
        with self.assertRaises(ContainerError):
            decode_container(raw[:20])


class TestEmptyFileEncryption(unittest.TestCase):
    """An empty file should encrypt and decrypt successfully (zero-byte plaintext)."""

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)

    def test_rsa_empty_file(self):
        fd, src = tempfile.mkstemp()
        os.close(fd)  # creates a 0-byte file
        try:
            enc = stream_encrypt_file(src, method="rsa", overwrite=True)
            dec = stream_decrypt_file(enc)
            self.assertEqual(Path(dec).read_bytes(), b"")
        finally:
            Path(src).unlink(missing_ok=True)

    def test_ecc_empty_file(self):
        fd, src = tempfile.mkstemp()
        os.close(fd)
        try:
            enc = stream_encrypt_file(src, method="ecc", overwrite=True)
            dec = stream_decrypt_file(enc)
            self.assertEqual(Path(dec).read_bytes(), b"")
        finally:
            Path(src).unlink(missing_ok=True)


class TestLargeFileEncryption(unittest.TestCase):
    """A 10 MB file should encrypt and decrypt with content integrity preserved."""

    _SIZE = 10 * 1024 * 1024  # 10 MB

    def setUp(self):
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)

    def test_rsa_large_file(self):
        data = os.urandom(self._SIZE)
        fd, src = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        try:
            enc = stream_encrypt_file(src, method="rsa", overwrite=True)
            dec = stream_decrypt_file(enc)
            self.assertEqual(Path(dec).read_bytes(), data)
        finally:
            Path(src).unlink(missing_ok=True)

    def test_ecc_large_file(self):
        data = os.urandom(self._SIZE)
        fd, src = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        try:
            enc = stream_encrypt_file(src, method="ecc", overwrite=True)
            dec = stream_decrypt_file(enc)
            self.assertEqual(Path(dec).read_bytes(), data)
        finally:
            Path(src).unlink(missing_ok=True)


class TestGovernanceRuleEnforcement(unittest.TestCase):
    """Governance rules must reject insecure configurations."""

    def test_aes_128_rejected(self):
        with self.assertRaises(GovernanceViolation):
            enforce_aes_key_size(os.urandom(16))  # 128 bits

    def test_aes_192_rejected(self):
        with self.assertRaises(GovernanceViolation):
            enforce_aes_key_size(os.urandom(24))  # 192 bits

    def test_aes_256_accepted(self):
        enforce_aes_key_size(os.urandom(32))  # Should not raise

    def test_rsa_2048_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        small_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(GovernanceViolation):
            enforce_rsa_key_size(small_key)

    def test_rsa_3072_accepted(self):
        priv, _ = generate_rsa_keypair()
        enforce_rsa_key_size(priv)  # Should not raise


class TestSignatureTamperDetection(unittest.TestCase):
    """Signature verification must reject modified data."""

    def test_rsa_pss_tamper_detected(self):
        priv, pub = generate_rsa_keypair()
        data = b"original ciphertext"
        sig = sign("rsa", priv, data)
        with self.assertRaises(SignatureError):
            verify("rsa", pub, sig, b"tampered ciphertext")

    def test_ecdsa_tamper_detected(self):
        priv, pub = generate_ecc_keypair()
        data = b"original ciphertext"
        sig = sign("ecc", priv, data)
        with self.assertRaises(SignatureError):
            verify("ecc", pub, sig, b"tampered ciphertext")

    def test_rsa_wrong_key_rejected(self):
        priv1, _ = generate_rsa_keypair()
        _, pub2 = generate_rsa_keypair()
        sig = sign("rsa", priv1, b"data")
        with self.assertRaises(SignatureError):
            verify("rsa", pub2, sig, b"data")

    def test_ecdsa_wrong_key_rejected(self):
        priv1, _ = generate_ecc_keypair()
        _, pub2 = generate_ecc_keypair()
        sig = sign("ecc", priv1, b"data")
        with self.assertRaises(SignatureError):
            verify("ecc", pub2, sig, b"data")


if __name__ == "__main__":
    unittest.main(verbosity=2)
