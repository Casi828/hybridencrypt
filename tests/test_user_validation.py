"""
test_user_validation.py — Tests for N-C3: user record schema validation.

Covers validate_user_record() rejection of malformed user store records
and auth_engine.py explicit clearance rejection.
"""

import unittest
from spy.user_model import validate_user_record, UserRecordError, VALID_ROLES, VALID_CLEARANCES


def _valid_record(**overrides) -> dict:
    base = {
        "username": "alice",
        "role": "admin",
        "clearance": "high",
        "status": "active",
        "password_hash": "$argon2id$v=19$...",
    }
    base.update(overrides)
    return base


class TestValidateUserRecord(unittest.TestCase):

    def test_valid_record_passes(self):
        validate_user_record(_valid_record())  # must not raise

    def test_valid_record_all_roles(self):
        for role in VALID_ROLES:
            validate_user_record(_valid_record(role=role))

    def test_valid_record_all_clearances(self):
        for clearance in VALID_CLEARANCES:
            validate_user_record(_valid_record(clearance=clearance))

    def test_missing_username_rejected(self):
        record = _valid_record()
        del record["username"]
        with self.assertRaises(UserRecordError) as ctx:
            validate_user_record(record)
        self.assertIn("username", str(ctx.exception))

    def test_missing_role_rejected(self):
        record = _valid_record()
        del record["role"]
        with self.assertRaises(UserRecordError):
            validate_user_record(record)

    def test_missing_clearance_rejected(self):
        record = _valid_record()
        del record["clearance"]
        with self.assertRaises(UserRecordError):
            validate_user_record(record)

    def test_missing_status_rejected(self):
        record = _valid_record()
        del record["status"]
        with self.assertRaises(UserRecordError):
            validate_user_record(record)

    def test_missing_password_hash_rejected(self):
        record = _valid_record()
        del record["password_hash"]
        with self.assertRaises(UserRecordError):
            validate_user_record(record)

    def test_empty_username_rejected(self):
        with self.assertRaises(UserRecordError) as ctx:
            validate_user_record(_valid_record(username=""))
        self.assertIn("username", str(ctx.exception))

    def test_whitespace_username_rejected(self):
        with self.assertRaises(UserRecordError):
            validate_user_record(_valid_record(username="   "))

    def test_invalid_role_rejected(self):
        with self.assertRaises(UserRecordError) as ctx:
            validate_user_record(_valid_record(role="superadmin"))
        self.assertIn("role", str(ctx.exception))

    def test_invalid_clearance_rejected(self):
        with self.assertRaises(UserRecordError) as ctx:
            validate_user_record(_valid_record(clearance="ultra"))
        self.assertIn("clearance", str(ctx.exception))

    def test_invalid_status_rejected(self):
        with self.assertRaises(UserRecordError) as ctx:
            validate_user_record(_valid_record(status="suspended"))
        self.assertIn("status", str(ctx.exception))

    def test_non_string_username_rejected(self):
        with self.assertRaises(UserRecordError):
            validate_user_record(_valid_record(username=42))


class TestAuthEngineExplicitClearanceRejection(unittest.TestCase):
    """auth_engine.py must explicitly reject unknown clearance strings."""

    def test_invalid_clearance_returns_false(self):
        from spy.auth_engine import AuthorizationEngine
        from spy.user_model import User

        class _DuckUser:
            role = "admin"
            clearance = "ultra"
            authenticated = True

        ok, reason = AuthorizationEngine.authorize(_DuckUser(), "encrypt", "high")
        self.assertFalse(ok)
        self.assertIn("clearance", reason.lower())

    def test_valid_clearance_not_rejected(self):
        from spy.auth_engine import AuthorizationEngine
        from spy.user_model import User
        user = User("alice", "admin", "high", authenticated=True)
        ok, _ = AuthorizationEngine.authorize(user, "encrypt", "high")
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
