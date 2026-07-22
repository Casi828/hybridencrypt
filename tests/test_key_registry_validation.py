"""
test_key_registry_validation.py — Tests for N-C4: key entry validation at registration.

Covers KeyRegistry.register() rejection of entries with unapproved algorithms,
invalid key_id formats, and empty key_reference values.
"""

import unittest
from spy.key_registry import KeyRegistry, KeyEntry, KeyRegistryError, VALID_ALGORITHMS


def _valid_entry(**overrides) -> KeyEntry:
    base = dict(
        key_id="rsa-enc-v1",
        key_type="rsa_enc",
        status="active",
        created_at="2026-04-27T00:00:00+00:00",
        activate_at="2026-04-27T00:00:00+00:00",
        retire_at=None,
        algorithm="RSA-3072-OAEP-SHA256",
        key_reference="rsa_enc_rsa-enc-v1_private.pem",
    )
    base.update(overrides)
    return KeyEntry(**base)


class TestKeyRegistryValidation(unittest.TestCase):

    def _fresh_registry(self) -> KeyRegistry:
        reg = KeyRegistry.__new__(KeyRegistry)
        reg._entries = []
        return reg

    def test_valid_entry_registers_ok(self):
        reg = self._fresh_registry()
        reg.register(_valid_entry())  # must not raise

    def test_all_approved_algorithms_accepted(self):
        for i, algorithm in enumerate(sorted(VALID_ALGORITHMS)):
            key_type = {
                "RSA-3072-OAEP-SHA256": "rsa_enc",
                "ECC-P256-ECDH-AES-GCM": "ecc_enc",
                "RSA-3072-PSS-SHA256": "rsa_sign",
                "ECC-P256-ECDSA-SHA256": "ecc_sign",
            }[algorithm]
            reg = self._fresh_registry()
            entry = _valid_entry(key_id=f"test-key-{i}", key_type=key_type, algorithm=algorithm)
            reg.register(entry)  # must not raise

    def test_invalid_algorithm_rejected(self):
        reg = self._fresh_registry()
        with self.assertRaises(KeyRegistryError) as ctx:
            reg.register(_valid_entry(algorithm="MD5-BROKEN"))
        self.assertIn("Algorithm", str(ctx.exception))

    def test_empty_algorithm_rejected(self):
        reg = self._fresh_registry()
        with self.assertRaises(KeyRegistryError):
            reg.register(_valid_entry(algorithm=""))

    def test_empty_key_reference_rejected(self):
        reg = self._fresh_registry()
        with self.assertRaises(KeyRegistryError) as ctx:
            reg.register(_valid_entry(key_reference=""))
        self.assertIn("key_reference", str(ctx.exception))

    def test_whitespace_key_reference_rejected(self):
        reg = self._fresh_registry()
        with self.assertRaises(KeyRegistryError):
            reg.register(_valid_entry(key_reference="   "))

    def test_invalid_key_id_path_traversal_rejected(self):
        reg = self._fresh_registry()
        with self.assertRaises(KeyRegistryError) as ctx:
            reg.register(_valid_entry(key_id="../etc/passwd"))
        self.assertIn("key_id", str(ctx.exception))

    def test_invalid_key_id_with_slash_rejected(self):
        reg = self._fresh_registry()
        with self.assertRaises(KeyRegistryError):
            reg.register(_valid_entry(key_id="some/path"))

    def test_invalid_key_id_with_space_rejected(self):
        reg = self._fresh_registry()
        with self.assertRaises(KeyRegistryError):
            reg.register(_valid_entry(key_id="bad key"))

    def test_empty_key_id_rejected(self):
        reg = self._fresh_registry()
        with self.assertRaises(KeyRegistryError):
            reg.register(_valid_entry(key_id=""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
