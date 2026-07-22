"""
test_provider_centralization.py — Enforce provider boundary for private key loading
and registry access.

Security invariants:
  1. Only spy/key_provider.py may call load_pem_private_key directly.
  2. No module outside spy/key_provider.py may access provider._registry directly.

Violations here mean a module is bypassing lifecycle enforcement (revocation checks,
status validation, error sanitization) or breaking the KeyProvider encapsulation
boundary.
"""

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SPY_DIR = REPO_ROOT / "spy"
FORBIDDEN_PEM = "load_pem_private_key"
FORBIDDEN_REGISTRY = "provider._registry"
ALLOWED = {SPY_DIR / "key_provider.py"}


class TestProviderCentralization(unittest.TestCase):
    """Assert that private PEM key loading is centralized in key_provider.py."""

    def test_no_direct_pem_loading_outside_provider(self):
        violations = []
        for py_file in sorted(SPY_DIR.rglob("*.py")):
            if "__pycache__" in py_file.parts:
                continue
            if py_file.resolve() in {p.resolve() for p in ALLOWED}:
                continue
            for lineno, line in enumerate(py_file.read_text(encoding="utf-8").splitlines(), 1):
                if FORBIDDEN_PEM in line:
                    violations.append(f"{py_file.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")
        self.assertEqual(
            violations,
            [],
            "Direct private PEM loading detected outside key_provider.py:\n" + "\n".join(violations),
        )

    def test_no_direct_registry_access_outside_provider(self):
        violations = []
        for py_file in sorted(SPY_DIR.rglob("*.py")):
            if "__pycache__" in py_file.parts:
                continue
            if py_file.resolve() in {p.resolve() for p in ALLOWED}:
                continue
            for lineno, line in enumerate(py_file.read_text(encoding="utf-8").splitlines(), 1):
                if FORBIDDEN_REGISTRY in line:
                    violations.append(f"{py_file.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")
        self.assertEqual(
            violations,
            [],
            "Direct provider._registry access detected outside key_provider.py:\n" + "\n".join(violations),
        )
