"""
test_user_management.py — Tests for P4 user lifecycle management functions.

Covers: disable_user, enable_user, list_users, change_role, change_clearance,
        reset_password, delete_user — all in spy/auth.py.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _env_patches(store_path: str) -> dict:
    return {
        "USERS_HMAC_KEY": "cc" * 32,
        "USERS_STORE_PATH": store_path,
    }


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
