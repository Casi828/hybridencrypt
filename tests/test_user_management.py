"""
test_user_management.py — Tests for P4 user lifecycle management functions.

Covers: disable_user, enable_user, list_users, change_role, change_clearance,
        reset_password, delete_user — all in spy/auth.py.

Also covers the transaction-lock hardening applied to those mutations:
  - store-backed authorization (a revoked admin's cached User object is rejected)
  - Argon2 never runs before the preliminary authorization check
  - concurrent mutations from separate OS processes do not lose updates
"""

from __future__ import annotations

import multiprocessing
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_HMAC_KEY = "cc" * 32


def _env_patches(store_path: str) -> dict:
    return {
        "USERS_HMAC_KEY": _HMAC_KEY,
        "USERS_STORE_PATH": store_path,
    }


def _concurrent_create_worker(store_path, hmac_key, audit_path, admin_name, admin_pw,
                              new_username, barrier, queue):
    """Child-process entry point for the lost-update test.

    Must stay module level so it is importable under the ``spawn`` start method.
    Authenticates before the barrier so only ``create_user`` races.
    """
    os.environ["USERS_STORE_PATH"] = store_path
    os.environ["USERS_HMAC_KEY"] = hmac_key
    if audit_path:
        os.environ["AUDIT_LOG_PATH"] = audit_path
    try:
        from spy.auth import authenticate, create_user
        admin = authenticate(admin_name, admin_pw)
        if admin is None:
            queue.put(("AdminAuthFailed", new_username))
            return
        barrier.wait(timeout=60)
        create_user(new_username, "worker-pw", "analyst", "low", admin_user=admin)
    except Exception as exc:  # reported back to the parent for assertion
        queue.put((type(exc).__name__, str(exc)))
        return
    queue.put(("ok", new_username))


class _BaseUserTest(unittest.TestCase):
    """Common setUp/tearDown + helpers shared by all test classes."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._store_path = str(Path(self._tmpdir) / "users.json")
        self._patcher = patch.dict(os.environ, _env_patches(self._store_path))
        self._patcher.start()
        self._bootstrap()

    def tearDown(self):
        self._patcher.stop()
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _bootstrap(self) -> None:
        from spy.auth import authenticate, create_user
        create_user("admin_user", "admin_pw", "admin", "high")
        self.admin = authenticate("admin_user", "admin_pw")

    def _create_target(self, username="target", role="analyst", clearance="medium",
                       password="target_pw") -> None:
        from spy.auth import create_user
        create_user(username, password, role, clearance, admin_user=self.admin)

    def _make_non_admin(self) -> object:
        from spy.auth import authenticate, create_user
        create_user("analyst_user", "analyst_pw", "analyst", "low", admin_user=self.admin)
        return authenticate("analyst_user", "analyst_pw")


# ---------------------------------------------------------------------------
# disable_user
# ---------------------------------------------------------------------------

class TestDisableUser(_BaseUserTest):
    def test_disable_prevents_login(self):
        from spy.auth import authenticate, disable_user
        self._create_target()
        disable_user("target", admin_user=self.admin)
        result = authenticate("target", "target_pw")
        self.assertIsNone(result)

    def test_disable_last_admin_blocked(self):
        from spy.auth import AuthError, disable_user
        with self.assertRaises(AuthError):
            disable_user("admin_user", admin_user=self.admin)

    def test_disable_self_blocked(self):
        from spy.auth import AuthError, disable_user
        with self.assertRaises(AuthError):
            disable_user("admin_user", admin_user=self.admin)

    def test_disable_nonexistent_raises(self):
        from spy.auth import AuthError, disable_user
        with self.assertRaises(AuthError):
            disable_user("no_such_user", admin_user=self.admin)

    def test_non_admin_cannot_disable(self):
        from spy.auth import AuthError, disable_user
        self._create_target()
        non_admin = self._make_non_admin()
        with self.assertRaises(AuthError):
            disable_user("target", admin_user=non_admin)

    def test_disable_non_admin_user_allowed(self):
        from spy.auth import authenticate, create_user, disable_user
        create_user("second_admin", "pw2", "admin", "high", admin_user=self.admin)
        self._create_target()
        disable_user("target", admin_user=self.admin)
        self.assertIsNone(authenticate("target", "target_pw"))


# ---------------------------------------------------------------------------
# enable_user
# ---------------------------------------------------------------------------

class TestEnableUser(_BaseUserTest):
    def test_enable_restores_login(self):
        from spy.auth import authenticate, disable_user, enable_user
        self._create_target()
        disable_user("target", admin_user=self.admin)
        self.assertIsNone(authenticate("target", "target_pw"))
        enable_user("target", admin_user=self.admin)
        result = authenticate("target", "target_pw")
        self.assertIsNotNone(result)
        self.assertTrue(result.authenticated)

    def test_enable_nonexistent_raises(self):
        from spy.auth import AuthError, enable_user
        with self.assertRaises(AuthError):
            enable_user("no_such_user", admin_user=self.admin)

    def test_non_admin_cannot_enable(self):
        from spy.auth import AuthError, disable_user, enable_user
        self._create_target()
        disable_user("target", admin_user=self.admin)
        non_admin = self._make_non_admin()
        with self.assertRaises(AuthError):
            enable_user("target", admin_user=non_admin)


# ---------------------------------------------------------------------------
# list_users
# ---------------------------------------------------------------------------

class TestListUsers(_BaseUserTest):
    def test_list_returns_all_users(self):
        from spy.auth import list_users
        self._create_target(username="user1")
        self._create_target(username="user2")
        users = list_users(admin_user=self.admin)
        usernames = [u["username"] for u in users]
        self.assertIn("admin_user", usernames)
        self.assertIn("user1", usernames)
        self.assertIn("user2", usernames)

    def test_list_excludes_password_hash(self):
        from spy.auth import list_users
        self._create_target()
        users = list_users(admin_user=self.admin)
        for u in users:
            self.assertNotIn("password_hash", u)

    def test_list_includes_expected_fields(self):
        from spy.auth import list_users
        self._create_target()
        users = list_users(admin_user=self.admin)
        for u in users:
            self.assertIn("username", u)
            self.assertIn("role", u)
            self.assertIn("clearance", u)
            self.assertIn("status", u)

    def test_non_admin_cannot_list(self):
        from spy.auth import AuthError, list_users
        non_admin = self._make_non_admin()
        with self.assertRaises(AuthError):
            list_users(admin_user=non_admin)


# ---------------------------------------------------------------------------
# change_role
# ---------------------------------------------------------------------------

class TestChangeRole(_BaseUserTest):
    def test_change_role_analyst_to_auditor(self):
        from spy.auth import authenticate, change_role, create_user
        self._create_target(role="analyst")
        change_role("target", "auditor", admin_user=self.admin)
        store = __import__("spy.auth", fromlist=["load_user_store"]).load_user_store()
        record = next(u for u in store["users"] if u["username"] == "target")
        self.assertEqual(record["role"], "auditor")

    def test_change_role_last_admin_blocked(self):
        from spy.auth import AuthError, change_role
        with self.assertRaises(AuthError):
            change_role("admin_user", "analyst", admin_user=self.admin)

    def test_change_role_last_admin_allowed_when_another_exists(self):
        from spy.auth import authenticate, change_role, create_user
        create_user("second_admin", "pw2", "admin", "high", admin_user=self.admin)
        second_admin = authenticate("second_admin", "pw2")
        change_role("admin_user", "analyst", admin_user=second_admin)
        store = __import__("spy.auth", fromlist=["load_user_store"]).load_user_store()
        record = next(u for u in store["users"] if u["username"] == "admin_user")
        self.assertEqual(record["role"], "analyst")

    def test_change_role_self_blocked(self):
        from spy.auth import AuthError, change_role
        with self.assertRaises(AuthError):
            change_role("admin_user", "analyst", admin_user=self.admin)

    def test_change_role_invalid_role(self):
        from spy.auth import AuthError, change_role
        self._create_target()
        with self.assertRaises(AuthError):
            change_role("target", "superuser", admin_user=self.admin)

    def test_change_role_nonexistent_raises(self):
        from spy.auth import AuthError, change_role
        with self.assertRaises(AuthError):
            change_role("no_such_user", "analyst", admin_user=self.admin)

    def test_non_admin_cannot_change_role(self):
        from spy.auth import AuthError, change_role
        self._create_target()
        non_admin = self._make_non_admin()
        with self.assertRaises(AuthError):
            change_role("target", "auditor", admin_user=non_admin)


# ---------------------------------------------------------------------------
# change_clearance
# ---------------------------------------------------------------------------

class TestChangeClearance(_BaseUserTest):
    def test_change_clearance_high_to_low(self):
        from spy.auth import change_clearance
        self._create_target(clearance="high")
        change_clearance("target", "low", admin_user=self.admin)
        store = __import__("spy.auth", fromlist=["load_user_store"]).load_user_store()
        record = next(u for u in store["users"] if u["username"] == "target")
        self.assertEqual(record["clearance"], "low")

    def test_change_clearance_invalid(self):
        from spy.auth import AuthError, change_clearance
        self._create_target()
        with self.assertRaises(AuthError):
            change_clearance("target", "top_secret", admin_user=self.admin)

    def test_change_clearance_nonexistent_raises(self):
        from spy.auth import AuthError, change_clearance
        with self.assertRaises(AuthError):
            change_clearance("no_such_user", "low", admin_user=self.admin)

    def test_change_clearance_self_blocked(self):
        from spy.auth import AuthError, change_clearance
        with self.assertRaises(AuthError):
            change_clearance("admin_user", "low", admin_user=self.admin)

    def test_non_admin_cannot_change_clearance(self):
        from spy.auth import AuthError, change_clearance
        self._create_target()
        non_admin = self._make_non_admin()
        with self.assertRaises(AuthError):
            change_clearance("target", "low", admin_user=non_admin)


# ---------------------------------------------------------------------------
# reset_password
# ---------------------------------------------------------------------------

class TestResetPassword(_BaseUserTest):
    def test_reset_password_allows_new_login(self):
        from spy.auth import authenticate, reset_password
        self._create_target()
        reset_password("target", "new_secure_pw", admin_user=self.admin)
        self.assertIsNone(authenticate("target", "target_pw"))
        result = authenticate("target", "new_secure_pw")
        self.assertIsNotNone(result)
        self.assertTrue(result.authenticated)

    def test_reset_password_empty_blocked(self):
        from spy.auth import AuthError, reset_password
        self._create_target()
        with self.assertRaises(AuthError):
            reset_password("target", "", admin_user=self.admin)

    def test_reset_password_nonexistent_raises(self):
        from spy.auth import AuthError, reset_password
        with self.assertRaises(AuthError):
            reset_password("no_such_user", "newpw", admin_user=self.admin)

    def test_non_admin_cannot_reset_password(self):
        from spy.auth import AuthError, reset_password
        self._create_target()
        non_admin = self._make_non_admin()
        with self.assertRaises(AuthError):
            reset_password("target", "newpw", admin_user=non_admin)

    def test_reset_own_password_allowed(self):
        from spy.auth import authenticate, reset_password
        reset_password("admin_user", "new_admin_pw", admin_user=self.admin)
        result = authenticate("admin_user", "new_admin_pw")
        self.assertIsNotNone(result)
        self.assertTrue(result.authenticated)

    def test_reset_password_clears_lockout_state(self):
        from spy.auth import load_user_store, reset_password, save_user_store
        self._create_target()
        store = load_user_store()
        record = next(u for u in store["users"] if u["username"] == "target")
        record["failed_attempts"] = 5
        record["locked_until"] = "2099-01-01T00:00:00+00:00"
        save_user_store(store)

        reset_password("target", "newpw", admin_user=self.admin)

        record = next(u for u in load_user_store()["users"] if u["username"] == "target")
        self.assertEqual(record["failed_attempts"], 0)
        self.assertIsNone(record["locked_until"])

    def test_reset_password_unlocks_a_locked_out_user(self):
        from spy.auth import authenticate, load_user_store, reset_password, save_user_store
        self._create_target()
        store = load_user_store()
        record = next(u for u in store["users"] if u["username"] == "target")
        record["failed_attempts"] = 5
        record["locked_until"] = "2099-01-01T00:00:00+00:00"
        save_user_store(store)
        self.assertIsNone(authenticate("target", "target_pw"))

        reset_password("target", "newpw", admin_user=self.admin)

        result = authenticate("target", "newpw")
        self.assertIsNotNone(result)
        self.assertTrue(result.authenticated)

    def test_reset_password_repairs_a_malformed_record(self):
        from spy.auth import authenticate, load_user_store, reset_password, save_user_store
        self._create_target()
        store = load_user_store()
        record = next(u for u in store["users"] if u["username"] == "target")
        record["failed_attempts"] = True  # bool must never be accepted as 1
        record["locked_until"] = "garbage"
        save_user_store(store)
        self.assertIsNone(authenticate("target", "target_pw"))

        reset_password("target", "newpw", admin_user=self.admin)

        self.assertIsNotNone(authenticate("target", "newpw"))


# ---------------------------------------------------------------------------
# delete_user
# ---------------------------------------------------------------------------

class TestDeleteUser(_BaseUserTest):
    def test_delete_removes_user(self):
        from spy.auth import authenticate, delete_user
        self._create_target()
        delete_user("target", admin_user=self.admin)
        self.assertIsNone(authenticate("target", "target_pw"))
        store = __import__("spy.auth", fromlist=["load_user_store"]).load_user_store()
        usernames = [u["username"] for u in store["users"]]
        self.assertNotIn("target", usernames)

    def test_delete_last_admin_blocked(self):
        from spy.auth import AuthError, delete_user
        with self.assertRaises(AuthError):
            delete_user("admin_user", admin_user=self.admin)

    def test_delete_self_blocked(self):
        from spy.auth import AuthError, delete_user
        with self.assertRaises(AuthError):
            delete_user("admin_user", admin_user=self.admin)

    def test_delete_nonexistent_raises(self):
        from spy.auth import AuthError, delete_user
        with self.assertRaises(AuthError):
            delete_user("no_such_user", admin_user=self.admin)

    def test_non_admin_cannot_delete(self):
        from spy.auth import AuthError, delete_user
        self._create_target()
        non_admin = self._make_non_admin()
        with self.assertRaises(AuthError):
            delete_user("target", admin_user=non_admin)

    def test_delete_non_admin_when_multiple_admins(self):
        from spy.auth import authenticate, create_user, delete_user
        create_user("second_admin", "pw2", "admin", "high", admin_user=self.admin)
        self._create_target()
        delete_user("target", admin_user=self.admin)
        self.assertIsNone(authenticate("target", "target_pw"))

    def test_delete_admin_allowed_when_another_exists(self):
        from spy.auth import authenticate, create_user, delete_user
        create_user("second_admin", "pw2", "admin", "high", admin_user=self.admin)
        second_admin = authenticate("second_admin", "pw2")
        delete_user("admin_user", admin_user=second_admin)
        store = __import__("spy.auth", fromlist=["load_user_store"]).load_user_store()
        usernames = [u["username"] for u in store["users"]]
        self.assertNotIn("admin_user", usernames)


# ---------------------------------------------------------------------------
# create_user — lockout field defaults
# ---------------------------------------------------------------------------

class TestCreateUserLockoutDefaults(_BaseUserTest):
    def test_new_records_carry_default_lockout_fields(self):
        from spy.auth import load_user_store
        self._create_target()
        for record in load_user_store()["users"]:
            with self.subTest(username=record["username"]):
                self.assertEqual(record["failed_attempts"], 0)
                self.assertIsNone(record["locked_until"])

    def test_create_user_rejects_empty_password(self):
        from spy.auth import AuthError, create_user
        with self.assertRaises(AuthError):
            create_user("blank", "", "analyst", "low", admin_user=self.admin)

    def test_create_user_rejects_empty_username(self):
        from spy.auth import AuthError, create_user
        with self.assertRaises(AuthError):
            create_user("   ", "pw", "analyst", "low", admin_user=self.admin)


# ---------------------------------------------------------------------------
# Authorization must precede Argon2 hashing
# ---------------------------------------------------------------------------

class TestNoArgon2BeforeAuthorization(_BaseUserTest):
    """An unauthorized caller must not be able to make the server burn CPU on Argon2."""

    def _unauthorized_callers(self) -> list:
        return [None, self._make_non_admin()]

    def test_create_user_never_hashes_for_unauthorized_caller(self):
        from spy.auth import AuthError, create_user
        for caller in self._unauthorized_callers():
            with self.subTest(caller=getattr(caller, "role", None)):
                with patch("spy.auth.hash_password",
                           side_effect=AssertionError("Argon2 ran before authorization")) as mock_hash:
                    with self.assertRaises(AuthError) as ctx:
                        create_user("newbie", "pw", "analyst", "low", admin_user=caller)
                self.assertEqual(str(ctx.exception), "Admin authentication required")
                mock_hash.assert_not_called()

    def test_reset_password_never_hashes_for_unauthorized_caller(self):
        from spy.auth import AuthError, reset_password
        self._create_target()
        for caller in self._unauthorized_callers():
            with self.subTest(caller=getattr(caller, "role", None)):
                with patch("spy.auth.hash_password",
                           side_effect=AssertionError("Argon2 ran before authorization")) as mock_hash:
                    with self.assertRaises(AuthError) as ctx:
                        reset_password("target", "newpw", admin_user=caller)
                self.assertEqual(str(ctx.exception), "Admin authentication required")
                mock_hash.assert_not_called()

    def test_authorized_create_user_still_hashes(self):
        """Sanity check that the patch above would have caught a real call."""
        from spy import auth
        with patch("spy.auth.hash_password", wraps=auth.hash_password) as mock_hash:
            auth.create_user("newbie", "pw", "analyst", "low", admin_user=self.admin)
        mock_hash.assert_called_once()

    def test_authorized_reset_password_still_hashes(self):
        from spy import auth
        self._create_target()
        with patch("spy.auth.hash_password", wraps=auth.hash_password) as mock_hash:
            auth.reset_password("target", "newpw", admin_user=self.admin)
        mock_hash.assert_called_once()


# ---------------------------------------------------------------------------
# Store-backed authorization — a revoked admin's cached User object is worthless
# ---------------------------------------------------------------------------

class TestRevokedAdminAuthorization(_BaseUserTest):
    """_require_current_admin must consult the store, not the cached User object."""

    def setUp(self):
        super().setUp()
        from spy.auth import authenticate, create_user
        create_user("second_admin", "second_pw", "admin", "high", admin_user=self.admin)
        self.second_admin = authenticate("second_admin", "second_pw")
        self._create_target()

    def _assert_every_mutation_rejected(self, stale_admin) -> None:
        from spy.auth import (
            AuthError, change_clearance, change_role, create_user, delete_user,
            disable_user, enable_user, load_user_store, reset_password,
        )
        mutations = (
            ("create_user", lambda: create_user("newbie", "pw", "analyst", "low",
                                                admin_user=stale_admin)),
            ("reset_password", lambda: reset_password("target", "newpw", admin_user=stale_admin)),
            ("change_role", lambda: change_role("target", "auditor", admin_user=stale_admin)),
            ("change_clearance", lambda: change_clearance("target", "low", admin_user=stale_admin)),
            ("disable_user", lambda: disable_user("target", admin_user=stale_admin)),
            ("enable_user", lambda: enable_user("target", admin_user=stale_admin)),
            ("delete_user", lambda: delete_user("target", admin_user=stale_admin)),
        )
        for name, call in mutations:
            with self.subTest(mutation=name):
                with self.assertRaises(AuthError) as ctx:
                    call()
                self.assertEqual(str(ctx.exception), "Admin authentication required")

        store = load_user_store()
        usernames = [u["username"] for u in store["users"]]
        self.assertNotIn("newbie", usernames)
        target = next(u for u in store["users"] if u["username"] == "target")
        self.assertEqual(target["role"], "analyst")
        self.assertEqual(target["clearance"], "medium")
        self.assertEqual(target["status"], "active")

    def test_cached_user_object_still_passes_the_preliminary_check(self):
        """Documents why the store-backed check is required at all."""
        from spy.auth import _require_admin, disable_user
        disable_user("admin_user", admin_user=self.second_admin)
        self.assertTrue(self.admin.authenticated)
        self.assertEqual(self.admin.role, "admin")
        _require_admin(self.admin)  # must not raise — only the store knows better

    def test_disabled_admin_cannot_mutate_store(self):
        from spy.auth import disable_user
        disable_user("admin_user", admin_user=self.second_admin)
        self._assert_every_mutation_rejected(self.admin)

    def test_deleted_admin_cannot_mutate_store(self):
        from spy.auth import delete_user
        delete_user("admin_user", admin_user=self.second_admin)
        self._assert_every_mutation_rejected(self.admin)

    def test_demoted_admin_cannot_mutate_store(self):
        from spy.auth import change_role
        change_role("admin_user", "analyst", admin_user=self.second_admin)
        self._assert_every_mutation_rejected(self.admin)

    def test_still_active_admin_is_unaffected(self):
        """The store-backed check must not reject a genuinely current admin."""
        from spy.auth import create_user, load_user_store
        create_user("newbie", "pw", "analyst", "low", admin_user=self.second_admin)
        usernames = [u["username"] for u in load_user_store()["users"]]
        self.assertIn("newbie", usernames)


# ---------------------------------------------------------------------------
# Transaction lock — no lost updates across separate OS processes
# ---------------------------------------------------------------------------

class TestTransactionLockConcurrency(_BaseUserTest):
    """Process-level evidence that the general mutation lock prevents lost updates."""

    def test_concurrent_create_user_keeps_both_users(self):
        from spy.auth import load_user_store
        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(2)
        queue = ctx.Queue()
        audit_path = os.environ.get("AUDIT_LOG_PATH", "")

        procs = [
            ctx.Process(
                target=_concurrent_create_worker,
                args=(self._store_path, _HMAC_KEY, audit_path,
                      "admin_user", "admin_pw", name, barrier, queue),
            )
            for name in ("worker_one", "worker_two")
        ]
        for proc in procs:
            proc.start()
        results = [queue.get(timeout=120) for _ in procs]
        for proc in procs:
            proc.join(timeout=60)
            self.assertFalse(proc.is_alive(), "worker process did not exit")

        self.assertEqual(
            sorted(results), [("ok", "worker_one"), ("ok", "worker_two")],
            f"both concurrent create_user calls must succeed, got {results}",
        )

        # load_user_store() re-verifies the HMAC — proves nothing was half-written.
        usernames = sorted(u["username"] for u in load_user_store()["users"])
        self.assertEqual(usernames, ["admin_user", "worker_one", "worker_two"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
