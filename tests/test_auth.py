"""
test_auth.py — Tests for spy/auth.py (P1 user authentication system).

Acceptance criteria verified:
  - Unauthenticated User is rejected by governance pipeline
  - Authenticated admin succeeds at governance layer
  - Wrong password fails
  - Disabled user fails
  - Tampered users.json fails closed
  - First user bootstrap works only when user store does not exist
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _env_patches(store_path: str) -> dict:
    return {
        "USERS_HMAC_KEY": "bb" * 32,
        "USERS_STORE_PATH": store_path,
    }


class TestPasswordHashing(unittest.TestCase):
    def test_hash_produces_argon2id(self):
        from spy.auth import hash_password
        h = hash_password("test-password")
        self.assertTrue(h.startswith("$argon2id$"), f"Expected Argon2id hash, got: {h[:20]}")

    def test_verify_correct_password(self):
        from spy.auth import hash_password, verify_password
        h = hash_password("correct")
        self.assertTrue(verify_password(h, "correct"))

    def test_verify_wrong_password(self):
        from spy.auth import hash_password, verify_password
        h = hash_password("correct")
        self.assertFalse(verify_password(h, "wrong"))

    def test_verify_invalid_hash(self):
        from spy.auth import verify_password
        self.assertFalse(verify_password("not-a-hash", "password"))

    def test_hashes_are_unique(self):
        from spy.auth import hash_password
        h1 = hash_password("same")
        h2 = hash_password("same")
        self.assertNotEqual(h1, h2, "Argon2id must use a random salt per hash")


class TestUserStoreIntegrity(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._store_path = str(Path(self._tmpdir) / "users.json")
        self._patcher = patch.dict(os.environ, _env_patches(self._store_path))
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _bootstrap(self, username: str = "alice", password: str = "correct-pw") -> None:
        from spy.auth import create_user
        create_user(username, password, "admin", "high")

    def test_save_and_load_roundtrip(self):
        from spy.auth import load_user_store, save_user_store
        store = {"version": 1, "users": [{"username": "x", "role": "admin",
                                           "clearance": "high", "status": "active",
                                           "password_hash": "h"}]}
        save_user_store(store)
        loaded = load_user_store()
        self.assertEqual(loaded["users"][0]["username"], "x")

    def test_store_gets_chmod_600(self):
        from spy.auth import save_user_store
        save_user_store({"version": 1, "users": []})
        mode = oct(Path(self._store_path).stat().st_mode)
        self.assertTrue(mode.endswith("600"), f"Expected 600 permissions, got {mode}")

    def test_tampered_store_fails_closed(self):
        from spy.auth import AuthError, load_user_store
        self._bootstrap()
        # Modify the store without updating the HMAC
        raw = json.loads(Path(self._store_path).read_text())
        raw["users"][0]["role"] = "superadmin"
        Path(self._store_path).write_text(json.dumps(raw))
        with self.assertRaises(AuthError):
            load_user_store()

    def test_missing_signature_fails_closed(self):
        from spy.auth import AuthError, load_user_store
        self._bootstrap()
        raw = json.loads(Path(self._store_path).read_text())
        del raw["signature"]
        Path(self._store_path).write_text(json.dumps(raw))
        with self.assertRaises(AuthError):
            load_user_store()

    def test_missing_store_fails_closed(self):
        from spy.auth import AuthError, load_user_store
        with self.assertRaises(AuthError):
            load_user_store()

    def test_invalid_json_fails_closed(self):
        from spy.auth import AuthError, load_user_store
        Path(self._store_path).write_text("not json {{{")
        with self.assertRaises(AuthError):
            load_user_store()

    def test_missing_hmac_key_fails_closed(self):
        from spy.auth import AuthError, load_user_store, save_user_store
        save_user_store({"version": 1, "users": []})
        with patch.dict(os.environ, {"USERS_HMAC_KEY": ""}):
            with self.assertRaises(AuthError):
                load_user_store()


class TestBootstrap(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._store_path = str(Path(self._tmpdir) / "users.json")
        self._patcher = patch.dict(os.environ, _env_patches(self._store_path))
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_first_user_bootstrap_forces_admin_high(self):
        from spy.auth import create_user, load_user_store
        create_user("alice", "pw", "analyst", "low")  # role/clearance overridden
        store = load_user_store()
        u = store["users"][0]
        self.assertEqual(u["role"], "admin")
        self.assertEqual(u["clearance"], "high")
        self.assertEqual(u["status"], "active")

    def test_bootstrap_only_when_no_store_exists(self):
        from spy.auth import AuthError, create_user
        create_user("alice", "pw", "admin", "high")  # bootstrap
        with self.assertRaises(AuthError):
            create_user("bob", "pw", "analyst", "low")  # no admin_user → rejected

    def test_post_bootstrap_requires_admin(self):
        from spy.auth import AuthError, authenticate, create_user
        create_user("alice", "pw", "admin", "high")
        admin = authenticate("alice", "pw")
        self.assertIsNotNone(admin)
        create_user("bob", "pw", "analyst", "low", admin_user=admin)
        store_data = __import__("spy.auth", fromlist=["load_user_store"]).load_user_store()
        usernames = [u["username"] for u in store_data["users"]]
        self.assertIn("bob", usernames)

    def test_duplicate_username_rejected(self):
        from spy.auth import AuthError, authenticate, create_user
        create_user("alice", "pw", "admin", "high")
        admin = authenticate("alice", "pw")
        with self.assertRaises(AuthError):
            create_user("alice", "pw2", "analyst", "low", admin_user=admin)


class TestAuthenticate(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._store_path = str(Path(self._tmpdir) / "users.json")
        self._patcher = patch.dict(os.environ, _env_patches(self._store_path))
        self._patcher.start()
        from spy.auth import create_user
        create_user("alice", "correct-password", "admin", "high")

    def tearDown(self):
        self._patcher.stop()
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_correct_password_returns_authenticated_user(self):
        from spy.auth import authenticate
        user = authenticate("alice", "correct-password")
        self.assertIsNotNone(user)
        self.assertTrue(user.authenticated)
        self.assertEqual(user.username, "alice")
        self.assertEqual(user.role, "admin")
        self.assertEqual(user.clearance, "high")

    def test_wrong_password_returns_none(self):
        from spy.auth import authenticate
        user = authenticate("alice", "wrong-password")
        self.assertIsNone(user)

    def test_unknown_user_returns_none(self):
        from spy.auth import authenticate
        user = authenticate("nobody", "password")
        self.assertIsNone(user)

    def test_disabled_user_returns_none(self):
        from spy.auth import authenticate, load_user_store, save_user_store
        store = load_user_store()
        store["users"][0]["status"] = "disabled"
        save_user_store(store)
        user = authenticate("alice", "correct-password")
        self.assertIsNone(user)

    def test_wrong_and_unknown_indistinguishable(self):
        # Both return None — no enumeration via error type
        from spy.auth import authenticate
        result_wrong = authenticate("alice", "wrong")
        result_unknown = authenticate("nobody", "wrong")
        self.assertIsNone(result_wrong)
        self.assertIsNone(result_unknown)

    def test_failed_login_emits_access_denied(self):
        """Failed authentication must emit an ACCESS_DENIED audit event."""
        from spy.auth import authenticate
        from unittest.mock import patch
        with patch("spy.auth.AuditLogger.log_event") as mock_log:
            authenticate("alice", "wrong-password")
        denied = [c for c in mock_log.call_args_list if c.args[1] == "ACCESS_DENIED"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0].kwargs.get("outcome"), "denied")

    def test_successful_login_no_access_denied(self):
        """Successful authentication must not emit ACCESS_DENIED."""
        from spy.auth import authenticate
        from unittest.mock import patch
        with patch("spy.auth.AuditLogger.log_event") as mock_log:
            authenticate("alice", "correct-password")
        denied = [c for c in mock_log.call_args_list if c.args[1] == "ACCESS_DENIED"]
        self.assertEqual(denied, [])


class TestGovernancePipelineAuthGate(unittest.TestCase):
    """Verify governance pipeline rejects unauthenticated users regardless of role."""

    def _ctx(self) -> dict:
        return {
            "environment": "cloud",
            "compliance_level": "none",
            "performance_priority": "medium",
            "legacy_support_required": False,
            "bandwidth_constraint": "medium",
        }

    def test_unauthenticated_admin_rejected_by_governance(self):
        from spy.governance_pipeline import GovernancePipeline
        from spy.key_provider import LocalPemKeyProvider
        from spy.user_model import User
        user = User("admin", "admin", "high")  # no authenticated=True
        pipeline = GovernancePipeline(LocalPemKeyProvider())
        ok, msg = pipeline.encrypt(user, self._ctx(), b"bypass", "high")
        self.assertFalse(ok)
        self.assertEqual(msg, "Authentication required")

    def test_unauthenticated_admin_rejected_on_decrypt(self):
        from spy.governance_pipeline import GovernancePipeline
        from spy.key_provider import LocalPemKeyProvider
        from spy.user_model import User
        user = User("admin", "admin", "high")  # no authenticated=True
        pipeline = GovernancePipeline(LocalPemKeyProvider())
        ok, msg = pipeline.decrypt(user, "rsa", "some-key-id", b"x", b"x", "high")
        self.assertFalse(ok)
        self.assertEqual(msg, "Authentication required")

    def test_authenticated_admin_passes_auth_gate(self):
        from spy.governance_pipeline import GovernancePipeline
        from spy.key_provider import LocalPemKeyProvider
        from spy.user_model import User
        user = User("alice", "admin", "high", authenticated=True)
        pipeline = GovernancePipeline(LocalPemKeyProvider())
        ok, result = pipeline._run_roundtrip(user, self._ctx(), b"auth gate test", "high")
        self.assertTrue(ok)
        self.assertEqual(result, b"auth gate test")


class TestHmacKeyValidation(unittest.TestCase):
    """_get_hmac_key() must enforce hex encoding and 32-byte minimum."""

    def setUp(self):
        fd, p = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self._store_path = p

    def tearDown(self):
        Path(self._store_path).unlink(missing_ok=True)

    def _load_with_key(self, key_value):
        """Attempt load_user_store with the given key (store written with same key)."""
        from spy.auth import load_user_store, save_user_store
        env = {"USERS_HMAC_KEY": key_value, "USERS_STORE_PATH": self._store_path}
        # Write the store with the same key so HMAC matches on load.
        with patch.dict(os.environ, {"USERS_HMAC_KEY": "bb" * 32,
                                     "USERS_STORE_PATH": self._store_path}):
            save_user_store({"version": 1, "users": []})
        with patch.dict(os.environ, env):
            load_user_store()

    def _load(self, key_value):
        """Attempt load_user_store with the given invalid key (store irrelevant — should fail early)."""
        from spy.auth import load_user_store, save_user_store
        with patch.dict(os.environ, {"USERS_HMAC_KEY": "bb" * 32,
                                     "USERS_STORE_PATH": self._store_path}):
            save_user_store({"version": 1, "users": []})
        with patch.dict(os.environ, {"USERS_HMAC_KEY": key_value,
                                     "USERS_STORE_PATH": self._store_path}):
            load_user_store()

    def test_missing_key_raises(self):
        from spy.auth import AuthError
        with self.assertRaises(AuthError):
            self._load("")

    def test_non_hex_key_raises(self):
        from spy.auth import AuthError
        with self.assertRaises(AuthError):
            self._load("notvalidhex!")

    def test_one_byte_key_raises(self):
        from spy.auth import AuthError
        with self.assertRaises(AuthError):
            self._load("00")

    def test_31_byte_key_raises(self):
        from spy.auth import AuthError
        with self.assertRaises(AuthError):
            self._load("00" * 31)

    def test_32_byte_key_accepted(self):
        self._load_with_key("bb" * 32)  # same key used to write — must not raise

    def test_invalid_key_blocks_before_file_io(self):
        """Invalid key must raise AuthError before Path.read_text is ever called."""
        from spy.auth import AuthError, load_user_store
        from unittest.mock import MagicMock
        mock_read = MagicMock(side_effect=AssertionError("file I/O occurred before key validation"))
        with patch.dict(os.environ, {"USERS_HMAC_KEY": "tooshort",
                                     "USERS_STORE_PATH": self._store_path}), \
             patch("pathlib.Path.read_text", mock_read):
            with self.assertRaises(AuthError):
                load_user_store()
        mock_read.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
