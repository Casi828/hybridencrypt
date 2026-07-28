"""
test_auth.py — Tests for spy/auth.py (P1 user authentication system).

Acceptance criteria verified:
  - Unauthenticated User is rejected by governance pipeline
  - Authenticated admin succeeds at governance layer
  - Wrong password fails
  - Disabled user fails
  - Tampered users.json fails closed
  - First user bootstrap works only when user store does not exist
  - Failed-login lockout state machine (H-4), fail closed on malformed state
  - Bootstrap TOCTOU closed by a process-level transaction lock (A8)
  - Lock file is a non-symlinked regular file forced to mode 0600
"""

from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

_HMAC_KEY = "bb" * 32


def _env_patches(store_path: str) -> dict:
    return {
        "USERS_HMAC_KEY": _HMAC_KEY,
        "USERS_STORE_PATH": store_path,
    }


class _FakeClock:
    """Injectable replacement for spy.auth._now — advances only when told to."""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def _bootstrap_race_worker(store_path, hmac_key, audit_path, username, barrier, queue):
    """Child-process entry point for the bootstrap race test.

    Must stay module level so it is importable under the ``spawn`` start method.
    Reports either ``("ok", username)`` or ``(exception_class_name, message)``.
    """
    os.environ["USERS_STORE_PATH"] = store_path
    os.environ["USERS_HMAC_KEY"] = hmac_key
    if audit_path:
        os.environ["AUDIT_LOG_PATH"] = audit_path
    try:
        from spy.auth import create_user
        barrier.wait(timeout=60)
        create_user(username, "race-pw", "admin", "high")
    except Exception as exc:  # reported back to the parent for assertion
        queue.put((type(exc).__name__, str(exc)))
        return
    queue.put(("ok", username))


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


# ---------------------------------------------------------------------------
# H-4 — failed-login lockout state machine
# ---------------------------------------------------------------------------

class _LockoutBase(unittest.TestCase):
    """Bootstrap an admin plus an ordinary target user under a controlled clock."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._store_path = str(Path(self._tmpdir) / "users.json")
        self._patcher = patch.dict(os.environ, _env_patches(self._store_path))
        self._patcher.start()
        from spy.auth import authenticate, create_user
        create_user("alice", "admin_pw", "admin", "high")
        self.admin = authenticate("alice", "admin_pw")
        create_user("bob", "bob_pw", "analyst", "low", admin_user=self.admin)
        self.clock = _FakeClock()
        self._clock_patcher = patch("spy.auth._now", self.clock)
        self._clock_patcher.start()

    def tearDown(self):
        self._clock_patcher.stop()
        self._patcher.stop()
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _record(self, username: str = "bob") -> dict:
        from spy.auth import load_user_store
        return next(u for u in load_user_store()["users"] if u["username"] == username)

    def _patch_record(self, username: str = "bob", *, remove=(), **fields) -> None:
        from spy.auth import load_user_store, save_user_store
        store = load_user_store()
        record = next(u for u in store["users"] if u["username"] == username)
        for name in remove:
            record.pop(name, None)
        record.update(fields)
        save_user_store(store)

    def _fail(self, times: int = 1, username: str = "bob") -> None:
        from spy.auth import authenticate
        for _ in range(times):
            self.assertIsNone(authenticate(username, "wrong-pw"))


class TestLockoutStateMachine(_LockoutBase):
    def test_new_user_starts_with_zero_lockout_state(self):
        record = self._record()
        self.assertEqual(record["failed_attempts"], 0)
        self.assertIsNone(record["locked_until"])

    def test_attempts_one_to_four_increment_without_locking(self):
        from spy.auth import authenticate
        for expected in (1, 2, 3, 4):
            self._fail()
            record = self._record()
            self.assertEqual(record["failed_attempts"], expected)
            self.assertIsNone(record["locked_until"])
        # Still authenticatable below the threshold.
        self.assertIsNotNone(authenticate("bob", "bob_pw"))

    def test_fifth_failure_locks_for_thirty_seconds(self):
        from spy.auth import LOCKOUT_SCHEDULE_SECONDS
        self._fail(5)
        record = self._record()
        self.assertEqual(record["failed_attempts"], 5)
        expected = (self.clock.now + timedelta(seconds=LOCKOUT_SCHEDULE_SECONDS[0])).isoformat()
        self.assertEqual(record["locked_until"], expected)

    def test_correct_password_denied_during_active_lock(self):
        from spy.auth import authenticate
        self._fail(5)
        self.clock.advance(29)
        self.assertIsNone(authenticate("bob", "bob_pw"))

    def test_lock_does_not_mutate_state_while_active(self):
        from spy.auth import authenticate
        self._fail(5)
        before = self._record()
        self.clock.advance(10)
        self.assertIsNone(authenticate("bob", "bob_pw"))
        self.assertIsNone(authenticate("bob", "wrong-pw"))
        self.assertEqual(self._record(), before)

    def test_correct_password_after_expiry_succeeds_and_resets(self):
        from spy.auth import authenticate
        self._fail(5)
        self.clock.advance(31)
        user = authenticate("bob", "bob_pw")
        self.assertIsNotNone(user)
        self.assertTrue(user.authenticated)
        record = self._record()
        self.assertEqual(record["failed_attempts"], 0)
        self.assertIsNone(record["locked_until"])

    def test_successful_login_mid_sequence_resets_counters(self):
        from spy.auth import authenticate
        self._fail(3)
        self.assertEqual(self._record()["failed_attempts"], 3)
        self.assertIsNotNone(authenticate("bob", "bob_pw"))
        record = self._record()
        self.assertEqual(record["failed_attempts"], 0)
        self.assertIsNone(record["locked_until"])

    def test_lockout_schedule_escalates_and_caps(self):
        from spy.auth import LOCKOUT_SCHEDULE_SECONDS
        expected_delays = list(LOCKOUT_SCHEDULE_SECONDS) + [LOCKOUT_SCHEDULE_SECONDS[-1]]
        self._fail(4)  # 4 failures, no lock yet
        for delay in expected_delays:
            self._fail(1)
            record = self._record()
            self.assertEqual(
                record["locked_until"],
                (self.clock.now + timedelta(seconds=delay)).isoformat(),
                f"expected a {delay}s lock at attempt {record['failed_attempts']}",
            )
            self.clock.advance(delay + 1)  # let the lock expire before the next failure

    def test_reset_password_clears_lockout_state(self):
        from spy.auth import authenticate, reset_password
        self._fail(5)
        self.assertIsNone(authenticate("bob", "bob_pw"))
        reset_password("bob", "fresh_pw", admin_user=self.admin)
        record = self._record()
        self.assertEqual(record["failed_attempts"], 0)
        self.assertIsNone(record["locked_until"])
        self.assertIsNotNone(authenticate("bob", "fresh_pw"))

    def test_legacy_record_without_lockout_fields_behaves_as_attempt_one(self):
        from spy.auth import authenticate
        self._patch_record(remove=("failed_attempts", "locked_until"))
        self.assertNotIn("failed_attempts", self._record())
        self._fail(1)
        self.assertEqual(self._record()["failed_attempts"], 1)
        self.assertIsNone(self._record()["locked_until"])
        self.assertIsNotNone(authenticate("bob", "bob_pw"))

    def test_lockout_is_per_account(self):
        from spy.auth import authenticate
        self._fail(5)
        self.assertIsNone(authenticate("bob", "bob_pw"))
        self.assertIsNotNone(authenticate("alice", "admin_pw"))

    def test_failed_login_during_lock_emits_access_denied(self):
        from spy.auth import authenticate
        self._fail(5)
        with patch("spy.auth.AuditLogger.log_event") as mock_log:
            authenticate("bob", "bob_pw")
        denied = [c for c in mock_log.call_args_list if c.args[1] == "ACCESS_DENIED"]
        self.assertEqual(len(denied), 1)


class TestMalformedLockoutStateFailsClosed(_LockoutBase):
    """Malformed lockout fields lock the account until an admin repairs it."""

    def test_malformed_locked_until_denies_login(self):
        from spy.auth import authenticate
        self._patch_record(locked_until="not-a-timestamp")
        self.assertIsNone(authenticate("bob", "bob_pw"))

    def test_malformed_locked_until_never_self_expires(self):
        from spy.auth import authenticate
        self._patch_record(locked_until="not-a-timestamp")
        self.clock.advance(365 * 24 * 3600)
        self.assertIsNone(authenticate("bob", "bob_pw"))
        # And the malformed value was not silently normalized away.
        self.assertEqual(self._record()["locked_until"], "not-a-timestamp")
        self.assertEqual(self._record()["failed_attempts"], 0)

    def test_naive_locked_until_is_malformed(self):
        from spy.auth import authenticate
        self._patch_record(locked_until="2026-01-01T12:00:00")  # no UTC offset
        self.assertIsNone(authenticate("bob", "bob_pw"))

    def test_non_string_locked_until_is_malformed(self):
        from spy.auth import authenticate
        self._patch_record(locked_until=1735732800)
        self.assertIsNone(authenticate("bob", "bob_pw"))

    def test_malformed_failed_attempts_denies_login(self):
        from spy.auth import authenticate
        for bad in (-1, True, False, "3", 3.5, 10 ** 9):
            with self.subTest(failed_attempts=bad):
                self._patch_record(failed_attempts=bad, locked_until=None)
                self.assertIsNone(authenticate("bob", "bob_pw"))

    def test_malformed_failed_attempts_never_self_expires(self):
        from spy.auth import authenticate
        self._patch_record(failed_attempts=-1, locked_until=None)
        self.clock.advance(365 * 24 * 3600)
        self.assertIsNone(authenticate("bob", "bob_pw"))
        self.assertEqual(self._record()["failed_attempts"], -1)

    def test_partially_present_lockout_fields_are_malformed(self):
        from spy.auth import authenticate
        self._patch_record(remove=("locked_until",), failed_attempts=2)
        self.assertIsNone(authenticate("bob", "bob_pw"))

    def test_malformed_locked_until_recovers_after_reset_password(self):
        from spy.auth import authenticate, reset_password
        self._patch_record(locked_until="not-a-timestamp")
        self.assertIsNone(authenticate("bob", "bob_pw"))
        reset_password("bob", "fresh_pw", admin_user=self.admin)
        self.assertIsNotNone(authenticate("bob", "fresh_pw"))

    def test_malformed_failed_attempts_recovers_after_reset_password(self):
        from spy.auth import authenticate, reset_password
        self._patch_record(failed_attempts=True, locked_until=None)
        self.assertIsNone(authenticate("bob", "bob_pw"))
        reset_password("bob", "fresh_pw", admin_user=self.admin)
        record = self._record()
        self.assertEqual(record["failed_attempts"], 0)
        self.assertIsNone(record["locked_until"])
        self.assertIsNotNone(authenticate("bob", "fresh_pw"))


# ---------------------------------------------------------------------------
# Disabled accounts — authoritative, and never interacting with lockout state
# ---------------------------------------------------------------------------

class TestDisabledAccountInvariants(_LockoutBase):
    def test_correct_password_for_disabled_user_denied(self):
        from spy.auth import authenticate
        self._patch_record(status="disabled")
        self.assertIsNone(authenticate("bob", "bob_pw"))

    def test_disabled_user_never_authenticated_for_any_password(self):
        from spy.auth import authenticate
        self._patch_record(status="disabled")
        for candidate in ("bob_pw", "wrong-pw", "", "another"):
            with self.subTest(password=candidate):
                self.assertIsNone(authenticate("bob", candidate))

    def test_disabled_user_emits_access_denied(self):
        from spy.auth import authenticate
        self._patch_record(status="disabled")
        with patch("spy.auth.AuditLogger.log_event") as mock_log:
            authenticate("bob", "bob_pw")
        denied = [c for c in mock_log.call_args_list if c.args[1] == "ACCESS_DENIED"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0].kwargs.get("outcome"), "denied")

    def test_correct_password_for_disabled_user_does_not_reset_counters(self):
        from spy.auth import authenticate
        self._patch_record(status="disabled", failed_attempts=3, locked_until=None)
        before = self._record()
        self.assertIsNone(authenticate("bob", "bob_pw"))
        self.assertEqual(self._record(), before)

    def test_wrong_password_for_disabled_user_does_not_increment_counters(self):
        from spy.auth import authenticate
        self._patch_record(status="disabled", failed_attempts=3, locked_until=None)
        before = self._record()
        self.assertIsNone(authenticate("bob", "wrong-pw"))
        self.assertEqual(self._record(), before)

    def test_status_flip_between_snapshot_and_lock_aborts_login(self):
        """A disable landing after the snapshot must abort a would-be success."""
        from spy import auth
        invocations = []

        def hook():
            invocations.append(1)
            if len(invocations) == 1:
                auth.disable_user("bob", admin_user=self.admin)

        with patch("spy.auth._authenticate_snapshot_hook", hook):
            result = auth.authenticate("bob", "bob_pw")

        self.assertIsNone(result)
        self.assertEqual(len(invocations), 2, "expected exactly one stale-snapshot retry")
        record = self._record()
        self.assertEqual(record["status"], "disabled")
        self.assertEqual(record["failed_attempts"], 0)
        self.assertIsNone(record["locked_until"])


# ---------------------------------------------------------------------------
# Stale-password race between the unlocked snapshot and the locked commit
# ---------------------------------------------------------------------------

class TestStaleSnapshotRace(_LockoutBase):
    def test_old_password_not_honored_after_concurrent_reset(self):
        from spy import auth
        invocations = []

        def hook():
            invocations.append(1)
            if len(invocations) == 1:
                auth.reset_password("bob", "rotated_pw", admin_user=self.admin)

        with patch("spy.auth._authenticate_snapshot_hook", hook):
            result = auth.authenticate("bob", "bob_pw")

        self.assertIsNone(result, "verification against a stale hash must not authenticate")
        self.assertEqual(len(invocations), 2, "expected exactly one stale-snapshot retry")
        self.assertIsNotNone(auth.authenticate("bob", "rotated_pw"))

    def test_retry_authenticates_against_the_new_state(self):
        from spy import auth
        invocations = []

        def hook():
            invocations.append(1)
            if len(invocations) == 1:
                auth.reset_password("bob", "rotated_pw", admin_user=self.admin)

        with patch("spy.auth._authenticate_snapshot_hook", hook):
            result = auth.authenticate("bob", "rotated_pw")

        self.assertIsNotNone(result)
        self.assertTrue(result.authenticated)
        self.assertEqual(len(invocations), 2)

    def test_retry_budget_is_bounded(self):
        """Endless contention is a denied login, not an infinite loop."""
        from spy import auth
        invocations = []

        def hook():
            invocations.append(1)
            auth.reset_password("bob", f"rotated_{len(invocations)}", admin_user=self.admin)

        with patch("spy.auth._authenticate_snapshot_hook", hook):
            result = auth.authenticate("bob", "bob_pw")

        self.assertIsNone(result)
        self.assertEqual(len(invocations), auth._MAX_AUTH_RETRIES)


class TestAuthenticateFailsClosed(_LockoutBase):
    """authenticate() denies rather than propagating when the store is unusable."""

    def test_unavailable_lock_denies_login(self):
        from spy import auth
        with patch("spy.auth._fcntl", None):
            self.assertIsNone(auth.authenticate("bob", "bob_pw"))

    def test_unwritable_store_denies_login(self):
        from spy import auth
        with patch("spy.auth.save_user_store", side_effect=OSError("read-only")):
            self.assertIsNone(auth.authenticate("bob", "bob_pw"))

    def test_record_deleted_between_snapshot_and_lock_denies_login(self):
        from spy import auth
        invocations = []

        def hook():
            invocations.append(1)
            if len(invocations) == 1:
                auth.delete_user("bob", admin_user=self.admin)

        with patch("spy.auth._authenticate_snapshot_hook", hook):
            self.assertIsNone(auth.authenticate("bob", "bob_pw"))


# ---------------------------------------------------------------------------
# Transaction lock file hardening
# ---------------------------------------------------------------------------

class TestStoreLockFile(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._store_path = str(Path(self._tmpdir) / "users.json")
        self._lock_path = Path(self._tmpdir) / "users.lock"
        self._patcher = patch.dict(os.environ, _env_patches(self._store_path))
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _locked_operation(self) -> None:
        from spy.auth import create_user
        create_user("alice", "pw", "admin", "high")

    def test_lock_path_sits_next_to_the_store(self):
        from spy.auth import _get_lock_path
        self.assertEqual(_get_lock_path(), self._lock_path)

    def test_lock_file_created_with_600(self):
        self._locked_operation()
        self.assertTrue(self._lock_path.exists())
        self.assertEqual(stat.S_IMODE(self._lock_path.stat().st_mode), 0o600)

    def test_lock_file_survives_release(self):
        """The lock file is never unlinked — removing it would reopen a race."""
        self._locked_operation()
        self.assertTrue(self._lock_path.exists())

    def test_preexisting_broad_permissions_are_tightened(self):
        self._lock_path.touch()
        os.chmod(self._lock_path, 0o644)
        self._locked_operation()
        self.assertEqual(stat.S_IMODE(self._lock_path.stat().st_mode), 0o600)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires O_NOFOLLOW")
    def test_symlinked_lock_path_rejected(self):
        from spy.auth import AuthError
        decoy = Path(self._tmpdir) / "decoy.txt"
        decoy.write_text("decoy contents", encoding="utf-8")
        os.chmod(decoy, 0o644)
        os.symlink(decoy, self._lock_path)

        with self.assertRaises(AuthError):
            self._locked_operation()

        self.assertEqual(decoy.read_text(encoding="utf-8"), "decoy contents")
        self.assertEqual(stat.S_IMODE(decoy.stat().st_mode), 0o644)
        self.assertFalse(Path(self._store_path).exists(), "store must not be written")

    def test_directory_at_lock_path_rejected(self):
        from spy.auth import AuthError
        os.mkdir(self._lock_path)
        with self.assertRaises(AuthError):
            self._locked_operation()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires mkfifo")
    def test_fifo_at_lock_path_rejected(self):
        from spy.auth import AuthError
        os.mkfifo(self._lock_path)
        with self.assertRaises(AuthError):
            self._locked_operation()

    @unittest.skipUnless(hasattr(os, "symlink"), "requires symlink support")
    def test_symlinked_runtime_directory_rejected(self):
        from spy.auth import AuthError
        real_dir = Path(self._tmpdir) / "real_runtime"
        real_dir.mkdir()
        linked_dir = Path(self._tmpdir) / "linked_runtime"
        os.symlink(real_dir, linked_dir)
        with patch.dict(os.environ, _env_patches(str(linked_dir / "users.json"))):
            with self.assertRaises(AuthError):
                self._locked_operation()

    def test_missing_fcntl_fails_closed(self):
        """Non-POSIX platforms must raise AuthError, not crash at import time."""
        from spy.auth import AuthError
        with patch("spy.auth._fcntl", None):
            with self.assertRaises(AuthError) as ctx:
                self._locked_operation()
        self.assertEqual(str(ctx.exception), "File locking is not supported on this platform")

    def test_lock_failure_prevents_the_mutation(self):
        from spy.auth import AuthError
        with patch("spy.auth._acquire_lock", side_effect=AuthError("nope")):
            with self.assertRaises(AuthError):
                self._locked_operation()
        self.assertFalse(Path(self._store_path).exists())


# ---------------------------------------------------------------------------
# A8 — bootstrap TOCTOU, exercised across real OS processes
# ---------------------------------------------------------------------------

class TestBootstrapConcurrency(unittest.TestCase):
    """Process-level (not thread-level) evidence that the inter-process flock works."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._store_path = str(Path(self._tmpdir) / "users.json")
        self._patcher = patch.dict(os.environ, _env_patches(self._store_path))
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_concurrent_bootstrap_creates_exactly_one_admin(self):
        from spy.auth import load_user_store
        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(2)
        queue = ctx.Queue()
        audit_path = os.environ.get("AUDIT_LOG_PATH", "")

        procs = [
            ctx.Process(
                target=_bootstrap_race_worker,
                args=(self._store_path, _HMAC_KEY, audit_path, name, barrier, queue),
            )
            for name in ("racer_one", "racer_two")
        ]
        for proc in procs:
            proc.start()
        results = [queue.get(timeout=120) for _ in procs]
        for proc in procs:
            proc.join(timeout=60)
            self.assertFalse(proc.is_alive(), "worker process did not exit")

        successes = [r for r in results if r[0] == "ok"]
        failures = [r for r in results if r[0] != "ok"]
        self.assertEqual(len(successes), 1, f"expected exactly one bootstrap, got {results}")
        self.assertEqual(len(failures), 1, f"expected exactly one rejection, got {results}")
        self.assertEqual(failures[0][0], "AuthError")
        self.assertEqual(failures[0][1], "Admin authentication required")

        # load_user_store() re-verifies the HMAC — proves the race left the store intact.
        store = load_user_store()
        self.assertEqual(len(store["users"]), 1)
        self.assertEqual(store["users"][0]["username"], successes[0][1])
        self.assertEqual(store["users"][0]["role"], "admin")


if __name__ == "__main__":
    unittest.main(verbosity=2)
