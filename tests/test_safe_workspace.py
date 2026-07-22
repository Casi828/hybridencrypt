"""
test_safe_workspace.py — Safe workspace boundary enforcement.

Verifies:
  - SAFE_FILE_ROOT, SAFE_ENCRYPT_INPUT_DIR, classified output dirs
  - is_inside_safe_root containment checks
  - _is_safe_entry filtering (dotfiles, BLOCKED_NAMES, symlink escapes)
  - ensure_safe_workspace directory creation
  - browse_for_file entry filtering (dotfiles, blocked names, .enc exclusion for encrypt)
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import spy.workspace as ws_module


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tmproot() -> Path:
    """Return a resolved temporary directory to use as a fake SAFE_FILE_ROOT."""
    td = tempfile.mkdtemp()
    return Path(td).resolve()


# ---------------------------------------------------------------------------
# TestIsSafeRoot
# ---------------------------------------------------------------------------

class TestIsSafeRoot(unittest.TestCase):

    def setUp(self):
        self._root = _make_tmproot()
        self._orig_root = ws_module.SAFE_FILE_ROOT
        ws_module.SAFE_FILE_ROOT = self._root
        # cli.py imports SAFE_FILE_ROOT from workspace; also patch it there for
        # _is_inside_safe_root calls that go through cli module path.
        import spy.cli as cli_module
        self._cli = cli_module
        self._cli_orig_root = cli_module.SAFE_FILE_ROOT
        cli_module.SAFE_FILE_ROOT = self._root

    def tearDown(self):
        ws_module.SAFE_FILE_ROOT = self._orig_root
        self._cli.SAFE_FILE_ROOT = self._cli_orig_root
        shutil.rmtree(str(self._root), ignore_errors=True)

    def test_path_inside_root(self):
        p = self._root / "input" / "file.txt"
        self.assertTrue(ws_module.is_inside_safe_root(p))

    def test_path_equals_root(self):
        self.assertTrue(ws_module.is_inside_safe_root(self._root))

    def test_path_outside_root(self):
        self.assertFalse(ws_module.is_inside_safe_root(Path.home()))

    def test_path_traversal_rejected(self):
        p = self._root / ".." / ".." / "etc"
        self.assertFalse(ws_module.is_inside_safe_root(p))

    def test_nested_path_inside_root(self):
        p = self._root / "output" / "encrypted" / "high" / "file.enc"
        self.assertTrue(ws_module.is_inside_safe_root(p))


# ---------------------------------------------------------------------------
# TestIsSafeEntry
# ---------------------------------------------------------------------------

class TestIsSafeEntry(unittest.TestCase):

    def setUp(self):
        self._root = _make_tmproot()
        self._orig_root = ws_module.SAFE_FILE_ROOT
        ws_module.SAFE_FILE_ROOT = self._root
        import spy.cli as cli_module
        self._cli = cli_module
        self._cli_orig_root = cli_module.SAFE_FILE_ROOT
        cli_module.SAFE_FILE_ROOT = self._root

    def tearDown(self):
        ws_module.SAFE_FILE_ROOT = self._orig_root
        self._cli.SAFE_FILE_ROOT = self._cli_orig_root
        shutil.rmtree(str(self._root), ignore_errors=True)

    def _touch(self, name: str) -> Path:
        p = self._root / name
        p.touch()
        return p

    def _mkdir(self, name: str) -> Path:
        p = self._root / name
        p.mkdir(exist_ok=True)
        return p

    def test_normal_file_allowed(self):
        p = self._touch("report.txt")
        self.assertTrue(self._cli._is_safe_entry(p))

    def test_normal_dir_allowed(self):
        p = self._mkdir("documents")
        self.assertTrue(self._cli._is_safe_entry(p))

    def test_dotfile_blocked(self):
        p = self._touch(".hidden")
        self.assertFalse(self._cli._is_safe_entry(p))

    def test_dotdir_blocked(self):
        p = self._mkdir(".cache")
        self.assertFalse(self._cli._is_safe_entry(p))

    def test_blocked_name_keys(self):
        p = self._mkdir("keys")
        self.assertFalse(self._cli._is_safe_entry(p))

    def test_blocked_name_runtime(self):
        p = self._mkdir("runtime")
        self.assertFalse(self._cli._is_safe_entry(p))

    def test_blocked_name_claude(self):
        p = self._mkdir("claude")
        self.assertFalse(self._cli._is_safe_entry(p))

    def test_blocked_name_tests(self):
        p = self._mkdir("tests")
        self.assertFalse(self._cli._is_safe_entry(p))

    def test_blocked_name_git(self):
        p = self._mkdir(".git")
        self.assertFalse(self._cli._is_safe_entry(p))

    def test_blocked_name_pycache(self):
        p = self._mkdir("__pycache__")
        self.assertFalse(self._cli._is_safe_entry(p))

    def test_symlink_inside_root_allowed(self):
        target = self._touch("real.txt")
        link = self._root / "link.txt"
        link.symlink_to(target)
        self.assertTrue(self._cli._is_safe_entry(link))

    def test_symlink_escape_blocked(self):
        link = self._root / "escape"
        link.symlink_to("/etc")
        self.assertFalse(self._cli._is_safe_entry(link))


# ---------------------------------------------------------------------------
# TestEnsureWorkspace
# ---------------------------------------------------------------------------

class TestEnsureWorkspace(unittest.TestCase):

    def setUp(self):
        self._root = _make_tmproot()
        self._orig = {k: getattr(ws_module, k) for k in (
            "SAFE_FILE_ROOT", "SAFE_INPUT_DIR", "SAFE_ENCRYPT_INPUT_DIR",
            "SAFE_DECRYPT_INPUT_DIR", "SAFE_OUTPUT_DIR",
            "SAFE_ENCRYPTED_OUTPUT_DIR", "SAFE_DECRYPTED_OUTPUT_DIR", "SAFE_SIG_DIR",
        )}
        ws_module.SAFE_FILE_ROOT            = self._root
        ws_module.SAFE_INPUT_DIR            = self._root / "input"
        ws_module.SAFE_ENCRYPT_INPUT_DIR    = self._root / "input" / "encrypt"
        ws_module.SAFE_DECRYPT_INPUT_DIR    = self._root / "input" / "decrypt"
        ws_module.SAFE_OUTPUT_DIR           = self._root / "output"
        ws_module.SAFE_ENCRYPTED_OUTPUT_DIR = self._root / "output" / "encrypted"
        ws_module.SAFE_DECRYPTED_OUTPUT_DIR = self._root / "output" / "decrypted"
        ws_module.SAFE_SIG_DIR              = self._root / "sig"

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(ws_module, k, v)
        shutil.rmtree(str(self._root), ignore_errors=True)

    def test_creates_classified_encrypted_dirs(self):
        ws_module.ensure_safe_workspace()
        for cls in ("low", "medium", "high"):
            self.assertTrue((self._root / "output" / "encrypted" / cls).is_dir())

    def test_creates_classified_decrypted_dirs(self):
        ws_module.ensure_safe_workspace()
        for cls in ("low", "medium", "high"):
            self.assertTrue((self._root / "output" / "decrypted" / cls).is_dir())

    def test_creates_input_subdirs(self):
        ws_module.ensure_safe_workspace()
        self.assertTrue((self._root / "input" / "encrypt").is_dir())
        self.assertTrue((self._root / "input" / "decrypt").is_dir())

    def test_creates_sig_dir(self):
        ws_module.ensure_safe_workspace()
        self.assertTrue((self._root / "sig").is_dir())

    def test_idempotent(self):
        ws_module.ensure_safe_workspace()
        ws_module.ensure_safe_workspace()
        for cls in ("low", "medium", "high"):
            self.assertTrue((self._root / "output" / "encrypted" / cls).is_dir())

    def test_does_not_raise_if_already_exists(self):
        (self._root / "output" / "encrypted" / "high").mkdir(parents=True)
        ws_module.ensure_safe_workspace()


# ---------------------------------------------------------------------------
# TestBlockedNamesConstant
# ---------------------------------------------------------------------------

class TestBlockedNamesConstant(unittest.TestCase):

    def setUp(self):
        from spy.cli import BLOCKED_NAMES
        self._names = BLOCKED_NAMES

    def test_contains_keys(self):
        self.assertIn("keys", self._names)

    def test_contains_runtime(self):
        self.assertIn("runtime", self._names)

    def test_contains_claude(self):
        self.assertIn("claude", self._names)

    def test_contains_tests(self):
        self.assertIn("tests", self._names)

    def test_contains_build(self):
        self.assertIn("build", self._names)

    def test_contains_pycache(self):
        self.assertIn("__pycache__", self._names)

    def test_contains_git(self):
        self.assertIn(".git", self._names)

    def test_contains_egg_info(self):
        self.assertIn("spy.egg-info", self._names)


# ---------------------------------------------------------------------------
# TestBrowseFilterEntries
# ---------------------------------------------------------------------------

class TestBrowseFilterEntries(unittest.TestCase):
    """Test that _is_safe_entry correctly filters the entry types browse_for_file would hide."""

    def setUp(self):
        self._root = _make_tmproot()
        self._orig_ws_root = ws_module.SAFE_FILE_ROOT
        ws_module.SAFE_FILE_ROOT = self._root
        import spy.cli as cli_module
        self._cli = cli_module
        self._cli_orig_root = cli_module.SAFE_FILE_ROOT
        cli_module.SAFE_FILE_ROOT = self._root

        (self._root / "normal.txt").touch()
        (self._root / "archive.zip").touch()
        (self._root / "secret.enc").touch()
        (self._root / ".hidden").touch()
        (self._root / "keys").mkdir()
        (self._root / "runtime").mkdir()
        (self._root / "documents").mkdir()

    def tearDown(self):
        ws_module.SAFE_FILE_ROOT = self._orig_ws_root
        self._cli.SAFE_FILE_ROOT = self._cli_orig_root
        shutil.rmtree(str(self._root), ignore_errors=True)

    def _safe_files(self, extensions=None):
        entries = sorted(self._root.iterdir(), key=lambda p: p.name)
        return [
            e for e in entries
            if e.is_file()
            and self._cli._is_safe_entry(e)
            and (extensions is None or e.suffix.lower() in extensions)
        ]

    def _safe_dirs(self):
        entries = sorted(self._root.iterdir(), key=lambda p: p.name)
        return [e for e in entries if e.is_dir() and self._cli._is_safe_entry(e)]

    def test_dotfile_not_in_safe_files(self):
        names = [f.name for f in self._safe_files()]
        self.assertNotIn(".hidden", names)

    def test_enc_excluded_from_encrypt_filter(self):
        from spy.cli import ENCRYPTABLE_EXTENSIONS
        names = [f.name for f in self._safe_files(ENCRYPTABLE_EXTENSIONS)]
        self.assertNotIn("secret.enc", names)

    def test_only_enc_shown_for_decrypt_filter(self):
        names = [f.name for f in self._safe_files(frozenset({".enc"}))]
        self.assertEqual(names, ["secret.enc"])

    def test_blocked_dirs_not_in_safe_dirs(self):
        names = [d.name for d in self._safe_dirs()]
        self.assertNotIn("keys", names)
        self.assertNotIn("runtime", names)

    def test_normal_dir_in_safe_dirs(self):
        names = [d.name for d in self._safe_dirs()]
        self.assertIn("documents", names)

    def test_normal_files_in_safe_files(self):
        names = [f.name for f in self._safe_files()]
        self.assertIn("normal.txt", names)
        self.assertIn("archive.zip", names)


# ---------------------------------------------------------------------------
# TestOutputContainment
# ---------------------------------------------------------------------------

class TestOutputContainment(unittest.TestCase):

    def setUp(self):
        self._root = _make_tmproot()
        self._orig_ws_root = ws_module.SAFE_FILE_ROOT
        ws_module.SAFE_FILE_ROOT = self._root
        import spy.cli as cli_module
        self._cli = cli_module
        self._cli_orig_root = cli_module.SAFE_FILE_ROOT
        cli_module.SAFE_FILE_ROOT = self._root

    def tearDown(self):
        ws_module.SAFE_FILE_ROOT = self._orig_ws_root
        self._cli.SAFE_FILE_ROOT = self._cli_orig_root
        shutil.rmtree(str(self._root), ignore_errors=True)

    def test_rejects_path_outside_root(self):
        self.assertFalse(ws_module.is_inside_safe_root(Path("/tmp/evil.enc")))

    def test_accepts_path_inside_root(self):
        p = self._root / "output" / "encrypted" / "high" / "file.enc"
        self.assertTrue(ws_module.is_inside_safe_root(p))

    def test_rejects_home_directory(self):
        self.assertFalse(ws_module.is_inside_safe_root(Path.home() / "evil.enc"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
