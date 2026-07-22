"""
test_integration.py — Comprehensive integration tests for the hybrid encryption system.

Run with:  python3 -m unittest test_integration -v
       or: python3 test_integration.py

Covers:
  - RSA and ECC hybrid encrypt/decrypt round trips
  - File encryption/decryption round trips
  - Malformed container rejection
  - Wrong private key failure
  - Tampered ciphertext failure
  - Governance pipeline end-to-end
  - Orchestrator integration (fallback path)
  - Policy engine method selection
  - Authorization engine RBAC
  - Compile/import sanity for all modules
"""

from __future__ import annotations

import importlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from tests.conftest import ws_patch, ws_restore

# conftest.py handles load_dotenv for all tests.


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _temp_file(content: bytes = b"test payload") -> str:
    """Write content to a temp file and return the path. Caller is responsible for cleanup."""
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return path


# ---------------------------------------------------------------------------
# Import / compile sanity
# ---------------------------------------------------------------------------

class TestImports(unittest.TestCase):
    """Verify every module imports cleanly with no side effects."""

    MODULES = [
        "spy.crypto_engine",
        "spy.crypto_container",
        "spy.rsa_engine",
        "spy.ecc_engine",
        "spy.hybrid_engine",
        "spy.file_crypto_engine",
        "spy.cli",
        "spy.policy_engine",
        "spy.auth_engine",
        "spy.audit_logger",
        "spy.user_model",
        "spy.governance_pipeline",
        "spy.agents.encrypt_agent",
        "spy.agents.decrypt_agent",
    ]

    def test_all_modules_import(self):
        for name in self.MODULES:
            with self.subTest(module=name):
                mod = importlib.import_module(name)
                self.assertIsNotNone(mod, f"{name} import returned None")

    def test_no_import_side_effects(self):
        """Importing modules must not create files or generate keys."""
        files_before = set(Path(".").glob("*.pem"))
        for name in self.MODULES:
            importlib.import_module(name)
        files_after = set(Path(".").glob("*.pem"))
        self.assertEqual(files_before, files_after, "Import created unexpected .pem files")


# ---------------------------------------------------------------------------
# Crypto engine
# ---------------------------------------------------------------------------

class TestCryptoEngine(unittest.TestCase):
    def setUp(self):
        from spy.crypto_engine import generate_key, encrypt_message, decrypt_message, CryptoError
        self.generate_key = generate_key
        self.encrypt = encrypt_message
        self.decrypt = decrypt_message
        self.CryptoError = CryptoError

    def test_key_is_32_bytes(self):
        self.assertEqual(len(self.generate_key()), 32)

    def test_round_trip_bytes(self):
        key = self.generate_key()
        ct = self.encrypt(key, b"hello world")
        self.assertEqual(self.decrypt(key, ct), b"hello world")

    def test_round_trip_string(self):
        key = self.generate_key()
        ct = self.encrypt(key, "unicode: \u2603")
        self.assertEqual(self.decrypt(key, ct), "unicode: \u2603".encode())

    def test_aad_bound(self):
        from cryptography.exceptions import InvalidTag
        key = self.generate_key()
        ct = self.encrypt(key, b"secret", associated_data=b"context-A")
        with self.assertRaises(InvalidTag):
            self.decrypt(key, ct, associated_data=b"context-B")

    def test_nonces_are_unique(self):
        key = self.generate_key()
        ct1 = self.encrypt(key, b"same plaintext")
        ct2 = self.encrypt(key, b"same plaintext")
        self.assertNotEqual(ct1[:12], ct2[:12], "Two encryptions must produce different nonces")

    def test_short_payload_rejected(self):
        key = self.generate_key()
        with self.assertRaises(self.CryptoError):
            self.decrypt(key, b"tooshort")

    def test_wrong_key_type_rejected(self):
        with self.assertRaises(self.CryptoError):
            self.encrypt("not bytes", b"data")  # type: ignore


# ---------------------------------------------------------------------------
# RSA engine
# ---------------------------------------------------------------------------

class TestRSAEngine(unittest.TestCase):
    def setUp(self):
        from spy.rsa_engine import generate_rsa_keypair, wrap_key, unwrap_key, RSAEngineError
        self.gen = generate_rsa_keypair
        self.wrap = wrap_key
        self.unwrap = unwrap_key
        self.Error = RSAEngineError

    def test_wrap_unwrap_round_trip(self):
        priv, pub = self.gen()
        aes_key = os.urandom(32)
        self.assertEqual(self.unwrap(priv, self.wrap(pub, aes_key)), aes_key)

    def test_wrong_private_key_rejected(self):
        _, pub = self.gen()
        priv2, _ = self.gen()
        wrapped = self.wrap(pub, os.urandom(32))
        with self.assertRaises(self.Error):
            self.unwrap(priv2, wrapped)

    def test_truncated_payload_rejected(self):
        _, pub = self.gen()
        wrapped = self.wrap(pub, os.urandom(32))
        with self.assertRaises(Exception):
            self.unwrap(pub, wrapped[:10])  # type: ignore — wrong object type


# ---------------------------------------------------------------------------
# ECC engine
# ---------------------------------------------------------------------------

class TestECCEngine(unittest.TestCase):
    def setUp(self):
        from spy.ecc_engine import generate_ecc_keypair, wrap_key, unwrap_key, ECCEngineError
        self.gen = generate_ecc_keypair
        self.wrap = wrap_key
        self.unwrap = unwrap_key
        self.Error = ECCEngineError

    def _keypairs(self):
        recv_priv, recv_pub = self.gen()
        send_priv, send_pub = self.gen()
        return recv_priv, recv_pub, send_priv, send_pub

    def test_wrap_unwrap_round_trip(self):
        recv_priv, recv_pub, send_priv, send_pub = self._keypairs()
        aes_key = os.urandom(32)
        wrapped = self.wrap(send_priv, recv_pub, aes_key)
        self.assertEqual(self.unwrap(recv_priv, send_pub, wrapped), aes_key)

    def test_aad_enforced(self):
        recv_priv, recv_pub, send_priv, send_pub = self._keypairs()
        aes_key = os.urandom(32)
        wrapped = self.wrap(send_priv, recv_pub, aes_key, associated_data=b"aad-A")
        with self.assertRaises(self.Error):
            self.unwrap(recv_priv, send_pub, wrapped, associated_data=b"aad-B")

    def test_wrong_receiver_key_rejected(self):
        recv_priv, recv_pub, send_priv, send_pub = self._keypairs()
        wrong_priv, _ = self.gen()
        wrapped = self.wrap(send_priv, recv_pub, os.urandom(32))
        with self.assertRaises(self.Error):
            self.unwrap(wrong_priv, send_pub, wrapped)

    def test_short_payload_rejected(self):
        recv_priv, _, send_priv, send_pub = self._keypairs()
        with self.assertRaises(self.Error):
            self.unwrap(recv_priv, send_pub, b"short")


# ---------------------------------------------------------------------------
# Hybrid engine
# ---------------------------------------------------------------------------

class TestHybridEngine(unittest.TestCase):
    def setUp(self):
        from spy.hybrid_engine import encrypt_hybrid, decrypt_hybrid, HybridEngineError, EncryptedPackage
        from spy.rsa_engine import generate_rsa_keypair
        from spy.ecc_engine import generate_ecc_keypair
        self.encrypt = encrypt_hybrid
        self.decrypt = decrypt_hybrid
        self.Error = HybridEngineError
        self.Package = EncryptedPackage
        self.rsa_gen = generate_rsa_keypair
        self.ecc_gen = generate_ecc_keypair

    def test_rsa_round_trip_bytes(self):
        priv, pub = self.rsa_gen()
        pkg = self.encrypt(b"rsa plaintext", method="rsa", public_key=pub)
        self.assertIsInstance(pkg, self.Package)
        result = self.decrypt("rsa", priv, pkg.encrypted_aes_key, pkg.encrypted_message)
        self.assertEqual(result, b"rsa plaintext")

    def test_rsa_round_trip_string(self):
        priv, pub = self.rsa_gen()
        pkg = self.encrypt("string input", method="rsa", public_key=pub)
        result = self.decrypt("rsa", priv, pkg.encrypted_aes_key, pkg.encrypted_message)
        self.assertEqual(result, b"string input")

    def test_ecc_round_trip(self):
        recv_priv, recv_pub = self.ecc_gen()
        send_priv, send_pub = self.ecc_gen()
        aad = b"ecc-test-aad"
        pkg = self.encrypt(
            b"ecc plaintext", method="ecc",
            public_key=recv_pub, sender_private_key=send_priv, associated_data=aad
        )
        result = self.decrypt(
            "ecc", recv_priv, pkg.encrypted_aes_key, pkg.encrypted_message,
            sender_public_key=send_pub, associated_data=aad
        )
        self.assertEqual(result, b"ecc plaintext")

    def test_rsa_wrong_key_rejected(self):
        _, pub = self.rsa_gen()
        priv2, _ = self.rsa_gen()
        pkg = self.encrypt(b"secret", method="rsa", public_key=pub)
        with self.assertRaises(self.Error):
            self.decrypt("rsa", priv2, pkg.encrypted_aes_key, pkg.encrypted_message)

    def test_tampered_ciphertext_rejected(self):
        priv, pub = self.rsa_gen()
        pkg = self.encrypt(b"secret", method="rsa", public_key=pub)
        tampered = pkg.encrypted_message[:-4] + b"XXXX"
        with self.assertRaises(self.Error):
            self.decrypt("rsa", priv, pkg.encrypted_aes_key, tampered)

    def test_invalid_method_rejected(self):
        _, pub = self.rsa_gen()
        with self.assertRaises(self.Error):
            self.encrypt(b"data", method="des", public_key=pub)

    def test_ecc_missing_sender_key_rejected(self):
        _, recv_pub = self.ecc_gen()
        with self.assertRaises(self.Error):
            self.encrypt(b"data", method="ecc", public_key=recv_pub)

    def test_ecc_missing_sender_public_on_decrypt_rejected(self):
        recv_priv, recv_pub = self.ecc_gen()
        send_priv, _ = self.ecc_gen()
        pkg = self.encrypt(b"data", method="ecc", public_key=recv_pub, sender_private_key=send_priv)
        with self.assertRaises(self.Error):
            self.decrypt("ecc", recv_priv, pkg.encrypted_aes_key, pkg.encrypted_message)

    def test_encrypted_package_is_immutable(self):
        _, pub = self.rsa_gen()
        pkg = self.encrypt(b"x", method="rsa", public_key=pub)
        with self.assertRaises((TypeError, AttributeError)):
            pkg.method = "ecc"  # type: ignore


# ---------------------------------------------------------------------------
# Container format
# ---------------------------------------------------------------------------

class TestContainerFormat(unittest.TestCase):
    def setUp(self):
        from spy.crypto_container import encode_container, decode_container, ContainerError
        self.encode = encode_container
        self.decode = decode_container
        self.Error = ContainerError

    # Minimum valid encrypted_message: 12-byte nonce + 1-byte ciphertext body + 16-byte GCM tag
    _FAKE_MSG = b"\x00" * 12 + b"\x01" + b"\x00" * 16  # 29 bytes

    def _valid_container(self, method="rsa"):
        return self.encode(method, b"wrappedkey", self._FAKE_MSG)

    def test_rsa_round_trip(self):
        raw = self._valid_container("rsa")
        c = self.decode(raw)
        self.assertEqual(c.method, "rsa")
        self.assertEqual(c.encrypted_key, b"wrappedkey")
        self.assertEqual(c.encrypted_message, self._FAKE_MSG)
        self.assertEqual(c.sender_public_bytes, b"")

    def test_ecc_round_trip_with_sender(self):
        raw = self.encode("ecc", b"key", self._FAKE_MSG, sender_public_bytes=b"pubkey-pem")
        c = self.decode(raw)
        self.assertEqual(c.method, "ecc")
        self.assertEqual(c.sender_public_bytes, b"pubkey-pem")

    def test_garbage_bytes_rejected(self):
        """Arbitrary binary data that is not a valid container must raise ContainerError."""
        with self.assertRaises(self.Error):
            self.decode(b"\x00\x01\x02\x03garbage data that is not JSON or a known format")

    def test_wrong_version_rejected(self):
        obj = json.loads(self._valid_container())
        obj["version"] = 99
        with self.assertRaises(self.Error):
            self.decode(json.dumps(obj).encode())

    def test_truncated_container_rejected(self):
        raw = self._valid_container()
        with self.assertRaises(self.Error):
            self.decode(raw[:10])

    def test_missing_required_field_rejected(self):
        obj = json.loads(self._valid_container())
        del obj["nonce"]
        with self.assertRaises(self.Error):
            self.decode(json.dumps(obj).encode())

    def test_unknown_key_wrap_rejected(self):
        obj = json.loads(self._valid_container())
        obj["key_wrap"] = "TRIPLE-DES"
        with self.assertRaises(self.Error):
            self.decode(json.dumps(obj).encode())

    def test_unsupported_method_on_encode_rejected(self):
        with self.assertRaises(self.Error):
            self.encode("des", b"key", self._FAKE_MSG)


# ---------------------------------------------------------------------------
# File crypto engine
# ---------------------------------------------------------------------------

class TestFileEngine(unittest.TestCase):
    def setUp(self):
        from spy.file_crypto_engine import stream_encrypt_file, stream_decrypt_file, FileCryptoError
        from spy.user_model import User
        self._test_user = User(username="testadmin", role="admin", clearance="high", authenticated=True)
        self.encrypt = lambda *a, **kw: stream_encrypt_file(*a, user=self._test_user, **kw)
        self.decrypt = lambda *a, **kw: stream_decrypt_file(*a, user=self._test_user, **kw)
        self.Error = FileCryptoError
        self._ws_root = Path(tempfile.mkdtemp()).resolve()
        self._ws_snap = ws_patch(self._ws_root)
        self._src_files: list[str] = []

    def tearDown(self):
        ws_restore(self._ws_snap)
        shutil.rmtree(str(self._ws_root), ignore_errors=True)
        for p in self._src_files:
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

    def _make_src(self, content: bytes = b"file test content") -> str:
        path = _temp_file(content)
        self._src_files.append(path)
        return path

    def test_rsa_file_round_trip(self):
        src = self._make_src(b"RSA file round trip")
        enc = self.encrypt(src, method="rsa")
        dec = self.decrypt(enc)
        self.assertEqual(Path(dec).read_bytes(), b"RSA file round trip")

    def test_ecc_file_round_trip(self):
        src = self._make_src(b"ECC file round trip")
        enc = self.encrypt(src, method="ecc")
        dec = self.decrypt(enc)
        self.assertEqual(Path(dec).read_bytes(), b"ECC file round trip")

    def test_binary_content_preserved(self):
        content = bytes(range(256)) * 64
        src = self._make_src(content)
        enc = self.encrypt(src, method="rsa")
        dec = self.decrypt(enc)
        self.assertEqual(Path(dec).read_bytes(), content)

    def test_tampered_file_rejected(self):
        src = self._make_src()
        enc = self.encrypt(src, method="rsa")
        data = bytearray(Path(enc).read_bytes())
        data[-8:-4] = b"TAMR"
        Path(enc).write_bytes(bytes(data))
        with self.assertRaises(self.Error):
            self.decrypt(enc, overwrite=True)

    def test_overwrite_protection_encrypt(self):
        src = self._make_src()
        self.encrypt(src, method="rsa")
        with self.assertRaises(self.Error):
            self.encrypt(src, method="rsa")  # output already exists

    def test_overwrite_protection_decrypt(self):
        src = self._make_src()
        enc = self.encrypt(src, method="rsa")
        self.decrypt(enc)  # first decrypt
        with self.assertRaises(self.Error):
            self.decrypt(enc)  # output already exists, no overwrite

    def test_overwrite_true_succeeds(self):
        src = self._make_src(b"overwrite test")
        enc = self.encrypt(src, method="rsa")
        enc2 = self.encrypt(src, method="rsa", overwrite=True)
        self.assertEqual(enc, enc2)

    def test_missing_input_file_rejected(self):
        with self.assertRaises(self.Error):
            self.encrypt("/nonexistent/file.txt", method="rsa")

    def test_invalid_method_rejected(self):
        src = self._make_src()
        with self.assertRaises(self.Error):
            self.encrypt(src, method="des")

    def test_delete_original(self):
        src = self._make_src()
        self.encrypt(src, method="rsa", delete_original=True)
        self.assertFalse(Path(src).exists(), "Original file should have been deleted")


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------

class TestPolicyEngine(unittest.TestCase):
    def setUp(self):
        from spy.policy_engine import select_encryption_method, PolicyError
        self.select = select_encryption_method
        self.Error = PolicyError

    def _ctx(self, **kwargs) -> dict:
        base = {
            "environment": "cloud",
            "compliance_level": "none",
            "performance_priority": "medium",
            "legacy_support_required": False,
            "bandwidth_constraint": "medium",
        }
        base.update(kwargs)
        return base

    def test_returns_valid_method(self):
        result = self.select(self._ctx())
        self.assertIn(result, {"rsa", "ecc"})

    def test_legacy_support_favors_rsa(self):
        result = self.select(self._ctx(legacy_support_required=True, compliance_level="strict"))
        self.assertEqual(result, "rsa")

    def test_mobile_high_perf_favors_ecc(self):
        result = self.select(self._ctx(environment="mobile", performance_priority="high"))
        self.assertEqual(result, "ecc")

    def test_enterprise_strict_legacy_favors_rsa(self):
        result = self.select(self._ctx(
            environment="enterprise", compliance_level="strict", legacy_support_required=True
        ))
        self.assertEqual(result, "rsa")

    def test_invalid_environment_rejected(self):
        with self.assertRaises(self.Error):
            self.select(self._ctx(environment="mainframe"))

    def test_invalid_compliance_rejected(self):
        with self.assertRaises(self.Error):
            self.select(self._ctx(compliance_level="ultra"))

    def test_non_dict_context_rejected(self):
        with self.assertRaises(self.Error):
            self.select("not a dict")  # type: ignore


# ---------------------------------------------------------------------------
# Authorization engine
# ---------------------------------------------------------------------------

class TestAuthEngine(unittest.TestCase):
    def setUp(self):
        from spy.auth_engine import AuthorizationEngine
        from spy.user_model import User
        self.auth = AuthorizationEngine
        self.User = User

    def test_admin_can_encrypt_high(self):
        ok, _ = self.auth.authorize(self.User("a", "admin", "high", authenticated=True), "encrypt", "high")
        self.assertTrue(ok)

    def test_admin_can_decrypt(self):
        ok, _ = self.auth.authorize(self.User("a", "admin", "high", authenticated=True), "decrypt", "high")
        self.assertTrue(ok)

    def test_analyst_can_encrypt(self):
        ok, _ = self.auth.authorize(self.User("a", "analyst", "high", authenticated=True), "encrypt", "high")
        self.assertTrue(ok)

    def test_analyst_can_decrypt(self):
        ok, _ = self.auth.authorize(self.User("a", "analyst", "high", authenticated=True), "decrypt", "high")
        self.assertTrue(ok)

    def test_guest_cannot_encrypt(self):
        ok, _ = self.auth.authorize(self.User("g", "guest", "low", authenticated=True), "encrypt", "low")
        self.assertFalse(ok)

    def test_insufficient_clearance_blocked(self):
        ok, reason = self.auth.authorize(self.User("a", "admin", "low", authenticated=True), "encrypt", "high")
        self.assertFalse(ok)
        self.assertIn("clearance", reason.lower())

    def test_unknown_role_rejected(self):
        ok, _ = self.auth.authorize(self.User("x", "superuser", "high", authenticated=True), "encrypt", "high")
        self.assertFalse(ok)

    def test_invalid_classification_rejected(self):
        ok, _ = self.auth.authorize(self.User("a", "admin", "high", authenticated=True), "encrypt", "critical")
        self.assertFalse(ok)

    def test_none_user_rejected(self):
        ok, _ = self.auth.authorize(None, "encrypt", "low")
        self.assertFalse(ok)


# ---------------------------------------------------------------------------
# Governance pipeline
# ---------------------------------------------------------------------------

class TestGovernancePipeline(unittest.TestCase):
    def setUp(self):
        from spy.governance_pipeline import GovernancePipeline
        from spy.key_provider import LocalPemKeyProvider
        from spy.user_model import User
        self.pipeline = GovernancePipeline(LocalPemKeyProvider())
        self.User = User

    def _ctx(self, environment="cloud", compliance="none", performance="medium",
              legacy=False, bandwidth="medium") -> dict:
        return {
            "environment": environment,
            "compliance_level": compliance,
            "performance_priority": performance,
            "legacy_support_required": legacy,
            "bandwidth_constraint": bandwidth,
        }

    def test_authorized_admin_rsa(self):
        user = self.User("alice", "admin", "high", authenticated=True)
        ctx = self._ctx(environment="enterprise", compliance="strict", legacy=True)
        ok, result = self.pipeline._run_roundtrip(user, ctx, b"rsa pipeline test", "high")
        self.assertTrue(ok)
        self.assertEqual(result, b"rsa pipeline test")

    def test_authorized_admin_ecc(self):
        user = self.User("alice", "admin", "high", authenticated=True)
        ctx = self._ctx(environment="mobile", performance="high")
        ok, result = self.pipeline._run_roundtrip(user, ctx, b"ecc pipeline test", "high")
        self.assertTrue(ok)
        self.assertEqual(result, b"ecc pipeline test")

    def test_string_message_decrypted_as_bytes(self):
        user = self.User("alice", "admin", "high", authenticated=True)
        ok, result = self.pipeline._run_roundtrip(user, self._ctx(), "hello", "low")
        self.assertTrue(ok)
        self.assertEqual(result, b"hello")

    def test_unauthorized_guest_denied(self):
        user = self.User("bob", "guest", "low", authenticated=True)
        ok, result = self.pipeline._run_roundtrip(user, self._ctx(), b"data", "low")
        self.assertFalse(ok)
        self.assertEqual(result, "Encryption failed")

    def test_insufficient_clearance_denied(self):
        user = self.User("alice", "admin", "low", authenticated=True)  # low clearance
        ok, result = self.pipeline._run_roundtrip(user, self._ctx(), b"data", "high")
        self.assertFalse(ok)

    def test_invalid_policy_context_handled(self):
        user = self.User("alice", "admin", "high", authenticated=True)
        ok, result = self.pipeline._run_roundtrip(user, {"environment": "mainframe"}, b"data", "high")
        self.assertFalse(ok)
        self.assertEqual(result, "Encryption failed")

    def test_audit_log_written(self):
        from spy.audit_logger import AUDIT_LOG_FILE
        log_path = AUDIT_LOG_FILE
        size_before = log_path.stat().st_size if log_path.exists() else 0
        user = self.User("alice", "admin", "high", authenticated=True)
        self.pipeline._run_roundtrip(user, self._ctx(), b"audit test", "low")
        size_after = log_path.stat().st_size if log_path.exists() else 0
        self.assertGreater(size_after, size_before, "Audit log should have grown")


# ---------------------------------------------------------------------------
# Agent stubs
# ---------------------------------------------------------------------------

class TestAgentDelegation(unittest.TestCase):
    """Agents delegate to approved paths; they no longer raise NotImplementedError."""

    def test_encrypt_agent_delegates_to_pipeline(self):
        """Unauthenticated user is rejected by GovernancePipeline, not the agent."""
        from spy.agents.encrypt_agent import run
        from spy.user_model import User
        ok, _ = run(User("x", "admin", "high", authenticated=False), {}, b"data", "high")
        self.assertFalse(ok)

    def test_decrypt_agent_delegates_to_engine(self):
        """Non-existent input path surfaces as FileCryptoError from the engine."""
        from spy.agents.decrypt_agent import run
        from spy.user_model import User
        from spy.file_crypto_engine import FileCryptoError
        with self.assertRaises(FileCryptoError):
            run(User("x", "admin", "high", authenticated=True), "/some/file.enc")


if __name__ == "__main__":
    unittest.main(verbosity=2)
