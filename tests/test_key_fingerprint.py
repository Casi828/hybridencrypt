"""
test_key_fingerprint.py — Encryption public key fingerprint enforcement (H-1).

Verifies:
  - get_rsa_public_key() / get_ecc_public_key() load successfully when .fp is present and matches
  - Tampered public key (content replaced, .fp unchanged) raises KeyProviderError
  - Missing .fp file raises KeyProviderError
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class TestEncryptionKeyFingerprint(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._key_dir = Path(self._tmpdir.name)
        # Patch env so LocalPemKeyProvider and key engines use the temp dir.
        self._env_patch = patch.dict(os.environ, {
            "CRYPTO_KEY_DIR": str(self._key_dir),
            "RSA_ENC_PASSPHRASE": "test-rsa-enc-pass",
            "ECC_ENC_PASSPHRASE": "test-ecc-enc-pass",
        })
        self._env_patch.start()

    def tearDown(self):
        self._env_patch.stop()
        self._tmpdir.cleanup()

    # ------------------------------------------------------------------
    # RSA
    # ------------------------------------------------------------------

    def _make_rsa_enc_key(self):
        """Generate an RSA encryption keypair in the temp key dir, return (pub_path, fp_path, key_id)."""
        from spy.key_registry import KeyRegistry
        from spy.rsa_engine import rotate_rsa_encryption_keys
        registry = KeyRegistry()
        try:
            registry.load()
        except Exception:
            pass
        _, pub_key, key_id = rotate_rsa_encryption_keys(registry)
        pub_ref = f"rsa_enc_{key_id}_public.pem"
        pub_path = self._key_dir / pub_ref
        fp_path = pub_path.with_suffix(".fp")
        return pub_path, fp_path, key_id

    def test_rsa_valid_fingerprint_loads_successfully(self):
        """get_rsa_public_key() must succeed when .fp matches the public key."""
        _, _, key_id = self._make_rsa_enc_key()
        from spy.key_provider import LocalPemKeyProvider
        provider = LocalPemKeyProvider()
        key = provider.get_rsa_public_key(key_id)
        self.assertIsNotNone(key)

    def test_rsa_tampered_key_raises(self):
        """get_rsa_public_key() must raise KeyProviderError when PEM content is replaced."""
        pub_path, _, key_id = self._make_rsa_enc_key()
        # Generate a second RSA key and overwrite the first key's PEM with the second's bytes.
        from spy.rsa_engine import generate_rsa_keypair
        from cryptography.hazmat.primitives import serialization
        _, impostor_pub = generate_rsa_keypair()
        pub_path.write_bytes(impostor_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        from spy.key_provider import LocalPemKeyProvider, KeyProviderError
        provider = LocalPemKeyProvider()
        with self.assertRaises(KeyProviderError):
            provider.get_rsa_public_key(key_id)

    def test_rsa_missing_fp_raises(self):
        """get_rsa_public_key() must raise KeyProviderError when .fp file is absent."""
        pub_path, fp_path, key_id = self._make_rsa_enc_key()
        fp_path.unlink()
        from spy.key_provider import LocalPemKeyProvider, KeyProviderError
        provider = LocalPemKeyProvider()
        with self.assertRaises(KeyProviderError):
            provider.get_rsa_public_key(key_id)

    # ------------------------------------------------------------------
    # ECC
    # ------------------------------------------------------------------

    def _make_ecc_enc_key(self):
        """Generate an ECC encryption keypair in the temp key dir, return (pub_path, fp_path, key_id)."""
        from spy.key_registry import KeyRegistry
        from spy.ecc_engine import rotate_ecc_encryption_keys
        registry = KeyRegistry()
        try:
            registry.load()
        except Exception:
            pass
        _, pub_key, key_id = rotate_ecc_encryption_keys(registry)
        pub_ref = f"ecc_enc_{key_id}_public.pem"
        pub_path = self._key_dir / pub_ref
        fp_path = pub_path.with_suffix(".fp")
        return pub_path, fp_path, key_id

    def test_ecc_valid_fingerprint_loads_successfully(self):
        """get_ecc_public_key() must succeed when .fp matches the public key."""
        _, _, key_id = self._make_ecc_enc_key()
        from spy.key_provider import LocalPemKeyProvider
        provider = LocalPemKeyProvider()
        key = provider.get_ecc_public_key(key_id)
        self.assertIsNotNone(key)

    def test_ecc_tampered_key_raises(self):
        """get_ecc_public_key() must raise KeyProviderError when PEM content is replaced."""
        pub_path, _, key_id = self._make_ecc_enc_key()
        from spy.ecc_engine import generate_ecc_keypair, serialize_public_key
        from cryptography.hazmat.primitives import serialization
        _, impostor_pub = generate_ecc_keypair()
        pub_path.write_bytes(impostor_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        from spy.key_provider import LocalPemKeyProvider, KeyProviderError
        provider = LocalPemKeyProvider()
        with self.assertRaises(KeyProviderError):
            provider.get_ecc_public_key(key_id)

    def test_ecc_missing_fp_raises(self):
        """get_ecc_public_key() must raise KeyProviderError when .fp file is absent."""
        pub_path, fp_path, key_id = self._make_ecc_enc_key()
        fp_path.unlink()
        from spy.key_provider import LocalPemKeyProvider, KeyProviderError
        provider = LocalPemKeyProvider()
        with self.assertRaises(KeyProviderError):
            provider.get_ecc_public_key(key_id)
