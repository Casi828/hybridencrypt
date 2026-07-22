"""
test_governance_pipeline.py — Governance pipeline, auth, and policy integration tests.

Run with: python3 -m unittest test_governance_pipeline -v
"""

from __future__ import annotations

import unittest

from spy.auth_engine import AuthorizationEngine
from spy.governance_pipeline import GovernancePipeline
from spy.key_provider import LocalPemKeyProvider
from spy.policy_engine import select_encryption_method
from spy.user_model import User


class TestGovernancePipelineIntegration(unittest.TestCase):
    def _ctx(self, environment="cloud", compliance="none", performance="medium",
              legacy=False, bandwidth="medium") -> dict:
        return {
            "environment": environment,
            "compliance_level": compliance,
            "performance_priority": performance,
            "legacy_support_required": legacy,
            "bandwidth_constraint": bandwidth,
        }

    def test_authorized_encryption_succeeds(self):
        user = User("alice", "admin", "high", authenticated=True)
        pipeline = GovernancePipeline(LocalPemKeyProvider())
        ok, result = pipeline._run_roundtrip(user, self._ctx(), b"authorized test", "high")
        self.assertTrue(ok, f"Expected success, got: {result}")
        self.assertEqual(result, b"authorized test")

    def test_unauthorized_user_blocked(self):
        user = User("bob", "guest", "low", authenticated=True)
        pipeline = GovernancePipeline(LocalPemKeyProvider())
        ok, result = pipeline._run_roundtrip(user, self._ctx(), b"secret", "low")
        self.assertFalse(ok)
        self.assertIn("Encryption failed", result)

    def test_unauthenticated_user_rejected(self):
        user = User("admin", "admin", "high")  # no authenticated=True
        pipeline = GovernancePipeline(LocalPemKeyProvider())
        ok, result = pipeline._run_roundtrip(user, self._ctx(), b"bypass attempt", "high")
        self.assertFalse(ok)
        self.assertIn("Authentication required", result)

    def test_policy_engine_selects_valid_algorithm(self):
        ctx = self._ctx(environment="enterprise", compliance="strict",
                        performance="low", legacy=True, bandwidth="high")
        method = select_encryption_method(ctx)
        self.assertIn(method, {"rsa", "ecc"})

    def test_rsa_path_end_to_end(self):
        user = User("alice", "admin", "high", authenticated=True)
        ctx = self._ctx(environment="enterprise", compliance="strict", legacy=True)
        pipeline = GovernancePipeline(LocalPemKeyProvider())
        ok, result = pipeline._run_roundtrip(user, ctx, b"rsa e2e", "high")
        self.assertTrue(ok)
        self.assertEqual(result, b"rsa e2e")

    def test_ecc_path_end_to_end(self):
        user = User("alice", "admin", "high", authenticated=True)
        ctx = self._ctx(environment="mobile", performance="high")
        pipeline = GovernancePipeline(LocalPemKeyProvider())
        ok, result = pipeline._run_roundtrip(user, ctx, b"ecc e2e", "high")
        self.assertTrue(ok)
        self.assertEqual(result, b"ecc e2e")


class TestAuthorizationEngine(unittest.TestCase):
    def test_admin_high_clearance_authorized(self):
        user = User("a", "admin", "high", authenticated=True)
        ok, _ = AuthorizationEngine.authorize(user, "encrypt", "high")
        self.assertTrue(ok)

    def test_guest_unauthorized(self):
        user = User("g", "guest", "low", authenticated=True)
        ok, _ = AuthorizationEngine.authorize(user, "encrypt", "low")
        self.assertFalse(ok)

    def test_insufficient_clearance_blocked(self):
        user = User("a", "admin", "low", authenticated=True)
        ok, reason = AuthorizationEngine.authorize(user, "encrypt", "high")
        self.assertFalse(ok)
        self.assertIn("clearance", reason.lower())

    def test_decrypt_is_not_called_in_production_code(self):
        """GovernancePipeline.decrypt() must not be called in any production spy/ module."""
        import ast
        import pathlib
        spy_dir = pathlib.Path(__file__).resolve().parent.parent / "spy"
        for py_file in spy_dir.rglob("*.py"):
            if "test" in py_file.name or "governance_pipeline" in py_file.name:
                continue
            source = py_file.read_text(encoding="utf-8")
            self.assertNotIn(
                "pipeline.decrypt(",
                source,
                f"Production file {py_file.name} calls GovernancePipeline.decrypt()",
            )


class TestGovernancePipelineDecryptEnforcement(unittest.TestCase):
    """GovernancePipeline.decrypt() must be restricted to admin users only."""

    def setUp(self):
        self._pipeline = GovernancePipeline(LocalPemKeyProvider())
        # Dummy values — enforcement gates fire before any crypto.
        self._kwargs = dict(
            method="rsa",
            key_id="rsa_enc_key",
            encrypted_aes_key=b"\x00" * 32,
            encrypted_message=b"\x00" * 32,
            data_classification="high",
        )

    def test_unauthenticated_user_rejected(self):
        user = User("eve", "analyst", "high")  # authenticated=False
        ok, msg = self._pipeline.decrypt(user, **self._kwargs)
        self.assertFalse(ok)
        self.assertEqual(msg, "Authentication required")

    def test_non_admin_authenticated_user_rejected(self):
        user = User("eve", "analyst", "high", authenticated=True)
        ok, msg = self._pipeline.decrypt(user, **self._kwargs)
        self.assertFalse(ok)
        self.assertEqual(msg, "Internal decrypt not permitted")

    def test_admin_user_passes_enforcement_gates(self):
        """Admin user clears both gates (crypto will then run — result is irrelevant here)."""
        user = User("alice", "admin", "high", authenticated=True)
        ok, result = self._pipeline.decrypt(user, **self._kwargs)
        # ok may be False due to invalid crypto inputs, but message must not be the gate errors.
        if not ok:
            self.assertNotIn(result, ("Authentication required", "Internal decrypt not permitted"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
