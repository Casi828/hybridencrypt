"""
test_agent_boundaries.py — N-C5 agent boundary safety + Batch 7 contract tests.

Verifies that spy/agents/ files:
  - contain no direct PEM loading (load_pem_private_key)
  - contain no direct provider._registry access
  - route all calls through the approved engine/pipeline paths
  - fail closed for unauthenticated callers
  - propagate FileCryptoError without suppression (contract test)

Also includes static hygiene checks:
  - _check_access has no production call sites outside its definition
  - .env.example does not use the old relative AUDIT_LOG_PATH default
"""

from __future__ import annotations

import pathlib
import unittest
from unittest.mock import patch

_SPY_ROOT = pathlib.Path(__file__).resolve().parent.parent / "spy"
_ENCRYPT_AGENT_SRC = _SPY_ROOT / "agents" / "encrypt_agent.py"
_DECRYPT_AGENT_SRC = _SPY_ROOT / "agents" / "decrypt_agent.py"


class TestAgentSourceBoundaries(unittest.TestCase):
    """Static analysis: agent source files must not contain unsafe patterns."""

    def _read(self, path: pathlib.Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_encrypt_agent_no_pem_loading(self):
        self.assertNotIn("load_pem_private_key", self._read(_ENCRYPT_AGENT_SRC))

    def test_decrypt_agent_no_pem_loading(self):
        self.assertNotIn("load_pem_private_key", self._read(_DECRYPT_AGENT_SRC))

    def test_encrypt_agent_no_registry_access(self):
        self.assertNotIn("_registry", self._read(_ENCRYPT_AGENT_SRC))

    def test_decrypt_agent_no_registry_access(self):
        self.assertNotIn("_registry", self._read(_DECRYPT_AGENT_SRC))


class TestAgentRuntimeBoundaries(unittest.TestCase):
    """Runtime: agents must route through approved paths and fail closed."""

    def _unauth_user(self):
        from spy.user_model import User
        return User("testuser", "analyst", "high", authenticated=False)

    def test_encrypt_agent_unauthenticated_fails_closed(self):
        """GovernancePipeline rejects unauthenticated users before any crypto."""
        import spy.agents.encrypt_agent as encrypt_agent
        user = self._unauth_user()
        ok, _ = encrypt_agent.run(user, {"workspace": "internal"}, b"hello", "low")
        self.assertFalse(ok)

    def test_decrypt_agent_unauthenticated_fails_closed(self):
        """stream_decrypt_file raises FileCryptoError for unauthenticated users."""
        from spy.file_crypto_engine import FileCryptoError
        import spy.agents.decrypt_agent as decrypt_agent
        user = self._unauth_user()
        with patch(
            "spy.agents.decrypt_agent.stream_decrypt_file",
            side_effect=FileCryptoError("Decryption denied"),
        ) as mock_sdf:
            with self.assertRaises(FileCryptoError):
                decrypt_agent.run(user, "/fake/path.enc")
        mock_sdf.assert_called_once_with("/fake/path.enc", output_path=None, user=user)

    def test_decrypt_agent_contract_propagates_file_crypto_error(self):
        """FileCryptoError from stream_decrypt_file must propagate — never suppressed."""
        from spy.user_model import User
        from spy.file_crypto_engine import FileCryptoError
        import spy.agents.decrypt_agent as decrypt_agent
        user = User("testuser", "admin", "high", authenticated=True)
        with self.assertRaises(FileCryptoError):
            decrypt_agent.run(user, "/nonexistent/path.enc")


_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestDistributionHygiene(unittest.TestCase):
    """Static hygiene: dead-code call sites and config example correctness."""

    def test_no_check_access_active_production_call_sites(self):
        """_check_access must have zero production call sites outside its definition file."""
        spy_root = _PROJECT_ROOT / "spy"
        definition_file = spy_root / "file_crypto_engine.py"
        violations = []
        for py_file in spy_root.rglob("*.py"):
            if "__pycache__" in py_file.parts:
                continue
            if py_file.resolve() == definition_file.resolve():
                continue
            if "_check_access(" in py_file.read_text(encoding="utf-8"):
                violations.append(str(py_file))
        self.assertEqual(
            violations, [],
            f"_check_access called outside its definition file: {violations}",
        )

    def test_env_example_no_relative_audit_path(self):
        """AUDIT_LOG_PATH in .env.example must not be the old relative default."""
        env_example = _PROJECT_ROOT / ".env.example"
        content = env_example.read_text(encoding="utf-8")
        for line in content.splitlines():
            if line.startswith("AUDIT_LOG_PATH="):
                value = line.split("=", 1)[1].strip()
                self.assertNotEqual(
                    value, "audit_log.json",
                    ".env.example still contains the misleading relative AUDIT_LOG_PATH default",
                )
                break


if __name__ == "__main__":
    unittest.main()
