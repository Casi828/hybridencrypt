"""workspace.py — Shared workspace path constants and helpers.

Neutral module: no imports from cli.py or file_crypto_engine.py.
Both cli.py and file_crypto_engine.py import from here; no circular dependency.
"""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SAFE_FILE_ROOT = PROJECT_ROOT / "workspace"
SAFE_FILE_ROOT = Path(os.getenv("SAFE_FILE_ROOT", str(DEFAULT_SAFE_FILE_ROOT))).resolve()

SAFE_INPUT_DIR          = SAFE_FILE_ROOT / "input"
SAFE_ENCRYPT_INPUT_DIR  = SAFE_INPUT_DIR / "encrypt"
SAFE_DECRYPT_INPUT_DIR  = SAFE_INPUT_DIR / "decrypt"

SAFE_OUTPUT_DIR           = SAFE_FILE_ROOT / "output"
SAFE_ENCRYPTED_OUTPUT_DIR = SAFE_OUTPUT_DIR / "encrypted"
SAFE_DECRYPTED_OUTPUT_DIR = SAFE_OUTPUT_DIR / "decrypted"

SAFE_SIG_DIR = SAFE_FILE_ROOT / "sig"
SAFE_AUDIT_OUTPUT_DIR = SAFE_OUTPUT_DIR / "audit"

CLASSIFIED_DIRS = ("low", "medium", "high")


def ensure_safe_workspace() -> None:
    """Create the full bounded-workspace directory tree if it does not exist.

    Idempotent (``exist_ok=True``). Establishes the input, signature, audit-output,
    and per-classification encrypted/decrypted output directories that every file
    operation is confined to.
    """
    SAFE_ENCRYPT_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    SAFE_DECRYPT_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    SAFE_SIG_DIR.mkdir(parents=True, exist_ok=True)
    SAFE_AUDIT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for cls in CLASSIFIED_DIRS:
        (SAFE_ENCRYPTED_OUTPUT_DIR / cls).mkdir(parents=True, exist_ok=True)
        (SAFE_DECRYPTED_OUTPUT_DIR / cls).mkdir(parents=True, exist_ok=True)


def is_inside_safe_root(path: Path) -> bool:
    """Return True only if ``path`` resolves to a location inside the safe root.

    Resolves symlinks first (``path.resolve()``), so a symlink pointing outside
    the workspace is rejected — this is the containment check that prevents path
    traversal and symlink-escape when reading or writing user files.
    """
    try:
        path.resolve().relative_to(SAFE_FILE_ROOT)
        return True
    except ValueError:
        return False


def classified_encrypted_output_path(input_path: Path, classification: str) -> Path:
    """Return the encrypted-output path for a file under its classification subdir.

    Raises:
        ValueError: if ``classification`` is not a recognized level — output is
            never written to an unclassified/arbitrary location.
    """
    if classification not in CLASSIFIED_DIRS:
        raise ValueError("Invalid classification")
    return SAFE_ENCRYPTED_OUTPUT_DIR / classification / f"{input_path.name}.enc"


def classified_decrypted_output_path(input_path: Path, classification: str) -> Path:
    """Return the decrypted-output path for a file under its classification subdir.

    Strips a trailing ``.enc`` from the source name.

    Raises:
        ValueError: if ``classification`` is not a recognized level.
    """
    if classification not in CLASSIFIED_DIRS:
        raise ValueError("Invalid classification")
    name = input_path.name.removesuffix(".enc")
    return SAFE_DECRYPTED_OUTPUT_DIR / classification / name
