"""
cli.py — Command-line interface for file encryption, decryption, and signing.

Interactive mode (no arguments):
  Presents a guided menu — Encrypt, Decrypt, Exit.
  Prompts the user step-by-step and validates all inputs before execution.

Direct commands (for scripting / automation):
  encrypt     <file> [--method rsa|ecc] [--output PATH] [--delete-original]
  decrypt     <file> [--output PATH]
  sign        <file> [--method rsa|ecc] [--output PATH]
  verify      <file> --sig SIG_FILE
  rotate-keys [--method rsa|ecc|all]

No cryptographic logic lives here. All crypto is delegated to the engine modules.
"""

from __future__ import annotations
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")
import argparse
import getpass
import os
import sys

from .audit_logger import (AuditLogger, AuditLogError, check_chain, scan_audit_chain,
                           read_logs, export_logs)
from .file_crypto_engine import (
    FileCryptoError,
    FileCryptoOverwriteError,
    rewrap_dek,
    stream_decrypt_file,
    stream_encrypt_file,
)
from .key_provider import KeyProviderError, LocalPemKeyProvider
from .key_registry import KeyRegistry, KeyRegistryError
from .rsa_engine import (RSAEngineError, key_fingerprint as rsa_key_fingerprint,
                         rotate_rsa_encryption_keys, rotate_rsa_signing_keys)
from .ecc_engine import (ECCEngineError, key_fingerprint as ecc_key_fingerprint,
                         rotate_ecc_encryption_keys, rotate_ecc_signing_keys)
from .signature_engine import (
    SignatureError,
    decode_sig_file_full,
    encode_sig_file,
    sign_stream,
    verify_stream,
)
from .workspace import (
    SAFE_FILE_ROOT,
    SAFE_INPUT_DIR,
    SAFE_ENCRYPT_INPUT_DIR,
    SAFE_DECRYPT_INPUT_DIR,
    SAFE_OUTPUT_DIR,
    SAFE_ENCRYPTED_OUTPUT_DIR,
    SAFE_SIG_DIR,
    SAFE_AUDIT_OUTPUT_DIR,
    ensure_safe_workspace as _ensure_safe_workspace,
    is_inside_safe_root as _is_inside_safe_root,
)


# ---------------------------------------------------------------------------
# Encryptable file types — enforced in the browser (display) and in run_encrypt()
# (execution backstop).  Executables, scripts, and system files are excluded.
# ---------------------------------------------------------------------------

ENCRYPTABLE_EXTENSIONS: frozenset[str] = frozenset({
    # Documents
    ".pdf", ".txt", ".rtf", ".md",
    ".doc", ".docx", ".odt",
    ".xls", ".xlsx", ".ods",
    ".ppt", ".pptx", ".odp",
    # Data / config
    ".csv", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".env",
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".svg", ".webp",
    # Archives
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    # Credentials / keys / certs
    ".pem", ".crt", ".cer", ".key", ".p12", ".pfx", ".jks",
    # Generic binary / data
    ".bin", ".dat", ".db", ".sqlite",
})

# ---------------------------------------------------------------------------
# Safe workspace — file picker is bounded to this directory tree.
# ---------------------------------------------------------------------------

BLOCKED_NAMES: frozenset[str] = frozenset({
    "keys", "runtime", "claude", "tests", "build",
    "spy.egg-info", "__pycache__", ".git",
})


def _is_safe_entry(entry: Path) -> bool:
    """Return False for dotfiles, blocked names, and symlinks that escape the workspace."""
    if entry.name.startswith("."):
        return False
    if entry.name in BLOCKED_NAMES:
        return False
    if entry.is_symlink() and not _is_inside_safe_root(entry.resolve()):
        return False
    return True


# ---------------------------------------------------------------------------
# Interactive helpers
# ---------------------------------------------------------------------------

def _prompt(label: str, default: str = "") -> str:
    """Print a prompt and return stripped user input."""
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"  {label}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return value if value else default


def _confirm(question: str) -> bool:
    """Ask a yes/no question; return True only for explicit 'y' or 'yes'."""
    try:
        answer = input(f"  {question} [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes")


def browse_for_file(
    start_dir: str = "",
    prompt_label: str = "Select a file",
    extensions: frozenset[str] | None = None,
) -> str | None:
    """Terminal file browser — navigate directories and select a file by number.

    Navigation is hard-bounded to SAFE_FILE_ROOT. Attempts to go above it are
    silently blocked. Returns the absolute path of the selected file, or None
    if the user cancels. Folders are never returned as a final selection.

    Args:
        extensions: If provided, only files whose suffix (lowercased) is in this
                    set are shown. Files with other extensions are hidden entirely.
    """
    root = SAFE_FILE_ROOT
    current = Path(start_dir).resolve() if start_dir else SAFE_ENCRYPT_INPUT_DIR

    # If caller passes a start_dir outside the root, clamp to root.
    try:
        current.relative_to(root)
    except ValueError:
        current = root

    while True:
        at_root = current == root
        # Display path relative to root for clarity, with root shown as "[workspace]".
        try:
            rel = current.relative_to(root)
            display = f"[workspace]/{rel}" if str(rel) != "." else "[workspace]"
        except ValueError:
            display = str(current)

        print(f"\n  {prompt_label}")
        print(f"  Location: {display}")
        if at_root:
            print("  (workspace root — cannot go higher)")
        print()

        # Build listing: sorted dirs first, then files.
        try:
            entries = sorted(current.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except PermissionError:
            print("  [!] Permission denied.")
            # Step back only if still within root.
            parent = current.parent
            try:
                parent.relative_to(root)
                current = parent
            except ValueError:
                current = root
            continue

        dirs  = [e for e in entries if e.is_dir()  and _is_safe_entry(e)]
        files = [
            e for e in entries
            if e.is_file()
            and _is_safe_entry(e)
            and (extensions is None or e.suffix.lower() in extensions)
        ]

        index = 1
        dir_map: dict[int, Path] = {}
        file_map: dict[int, Path] = {}

        # Show "go up" only when not already at the root boundary.
        if at_root:
            print("  [0] .. (blocked — already at workspace root)")
        else:
            print("  [0] .. (go up)")

        for d in dirs:
            print(f"  [{index}] {d.name}/")
            dir_map[index] = d
            index += 1

        for f in files:
            print(f"  [{index}] {f.name}")
            file_map[index] = f
            index += 1

        if not dirs and not files:
            print("  (empty directory)")

        print()
        print("  [q] Cancel")
        print()

        try:
            raw = input("  Enter number: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return None

        if raw in ("q", "quit", "cancel"):
            return None

        if raw == "0":
            if at_root:
                print("  [!] Already at workspace root — cannot navigate higher.")
            else:
                parent = current.parent
                try:
                    parent.relative_to(root)
                    current = parent
                except ValueError:
                    print("  [!] Boundary reached — cannot leave workspace root.")
            continue

        try:
            choice = int(raw)
        except ValueError:
            print("  [!] Invalid input — enter a number.")
            continue

        if choice in dir_map:
            current = dir_map[choice]
            continue

        if choice in file_map:
            selected = file_map[choice]
            print(f"\n  Selected: {selected}")
            return str(selected)

        print(f"  [!] No item {choice} in this directory.")


def run_encrypt() -> None:
    """Interactive encrypt flow.

    1. Prompt for input file path — must exist and must not be .enc.
    2. Prompt for encryption method (RSA / ECC).
    3. Prompt for optional output path (default: <file>.enc).
    4. Confirm before executing.
    5. Call stream_encrypt_file() — policy engine and signing are enforced inside.
    6. Report success or failure.
    """
    print("\n--- Encrypt File ---")
    _ensure_safe_workspace()

    # Step 1 — input file via browser (only encryptable types shown)
    while True:
        result = browse_for_file(
            start_dir=str(SAFE_ENCRYPT_INPUT_DIR),
            prompt_label="Select a plaintext file to encrypt",
            extensions=ENCRYPTABLE_EXTENSIONS,
        )
        if result is None:
            print("  [~] Cancelled. Returning to menu.")
            return
        p = Path(result)
        # Execution backstop — defence-in-depth if browser filter is bypassed.
        if p.suffix.lower() not in ENCRYPTABLE_EXTENSIONS:
            print(f"  [!] File type '{p.suffix}' is not supported for encryption.")
            print(f"  [!] Allowed types: {', '.join(sorted(ENCRYPTABLE_EXTENSIONS))}")
            continue
        if p.suffix.lower() == ".enc":
            print("  [!] File is already encrypted (.enc). Refusing double-encryption.")
            continue
        input_path = result
        break

    # Step 2 — method
    while True:
        method_raw = _prompt("Encryption method (rsa / ecc)", default="rsa").lower()
        if method_raw in ("rsa", "ecc"):
            method = method_raw
            break
        print("  [!] Enter 'rsa' or 'ecc'.")

    # Step 3 — context signals (optional; policy engine assigns classification)
    context: dict = {}
    sensitive_raw = _prompt("Contains sensitive data? (y/n)", default="n").lower()
    if sensitive_raw in ("y", "yes"):
        context["sensitive"] = True
    elif not context.get("sensitive"):
        internal_raw = _prompt("Internal use only? (y/n)", default="n").lower()
        if internal_raw in ("y", "yes"):
            context["internal"] = True

    # Step 4 — confirm (output folder is determined by policy-assigned classification)
    print(f"\n  Input          : {input_path}")
    print(f"  Method         : {method.upper()}")
    print(f"  Output         : workspace/output/encrypted/<classification>/ (policy-assigned)")
    if not _confirm("Proceed with encryption?"):
        print("  [~] Cancelled.")
        return

    # Step 5 — execute; engine routes output to the correct classified folder
    _overwrite = False
    try:
        result = stream_encrypt_file(
            input_path,
            output_path=None,
            method=method,
            delete_original=False,
            overwrite=_overwrite,
            context=context,
        )
        print(f"\n  [OK] Encrypted: {result}")
    except FileCryptoOverwriteError:
        print("\n  [!] An encrypted output file already exists for this input.")
        if _confirm("Overwrite the existing encrypted file?"):
            try:
                result = stream_encrypt_file(
                    input_path,
                    output_path=None,
                    method=method,
                    delete_original=False,
                    overwrite=True,
                    context=context,
                )
                print(f"\n  [OK] Encrypted: {result}")
            except FileCryptoError:
                print("\n  [FAIL] Encryption failed.")
            except Exception:  # noqa: BLE001
                print("\n  [FAIL] An unexpected error occurred.")
        else:
            print("  [~] Cancelled.")
    except FileCryptoError:
        print("\n  [FAIL] Encryption failed.")
    except Exception:  # noqa: BLE001
        print("\n  [FAIL] An unexpected error occurred.")


def run_decrypt() -> None:
    """Interactive decrypt flow.

    1. Prompt for .enc file path — must exist.
    2. Optional custom output path.
    3. Confirm before executing.
    4. Call stream_decrypt_file() — signature verification is mandatory inside.
    5. Report success or failure.
    """
    print("\n--- Decrypt File ---")
    _ensure_safe_workspace()

    # Step 1 — input file via browser (.enc files only)
    while True:
        result = browse_for_file(
            start_dir=str(SAFE_ENCRYPTED_OUTPUT_DIR),
            prompt_label="Select an encrypted file (.enc) to decrypt",
            extensions=frozenset({".enc"}),
        )
        if result is None:
            print("  [~] Cancelled. Returning to menu.")
            return
        input_path = result
        break

    # Step 2 — confirm (output folder is determined by container classification)
    print(f"\n  Input  : {input_path}")
    print(f"  Output : workspace/output/decrypted/<classification>/ (read from container)")
    if not _confirm("Proceed with decryption?"):
        print("  [~] Cancelled.")
        return

    # Step 3 — execute; engine reads classification from container header and routes output
    try:
        result = stream_decrypt_file(input_path, output_path=None, overwrite=False)
        print(f"\n  [OK] Decrypted: {result}")
    except FileCryptoOverwriteError:
        print("\n  [!] A decrypted output file already exists for this input.")
        if _confirm("Overwrite the existing decrypted file?"):
            try:
                result = stream_decrypt_file(input_path, output_path=None, overwrite=True)
                print(f"\n  [OK] Decrypted: {result}")
            except FileCryptoError:
                print("\n  [FAIL] Decryption failed.")
            except Exception:  # noqa: BLE001
                print("\n  [FAIL] An unexpected error occurred.")
        else:
            print("  [~] Cancelled.")
    except FileCryptoError:
        print("\n  [FAIL] Decryption failed.")
    except Exception:  # noqa: BLE001
        print("\n  [FAIL] An unexpected error occurred.")


def _prompt_username(prompt: str = "  Username: ") -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  Cancelled.")
        return ""


def _interactive_add_user(user) -> None:
    """Add a user from the interactive menu using the already-authenticated admin."""
    from .auth import AuthError, create_user
    try:
        username = input("  Username: ").strip()
        if not username:
            print("  Error: username required.")
            return
        role = input("  Role (admin/analyst/auditor): ").strip()
        clearance = input("  Clearance (low/medium/high): ").strip()
        if sys.stdin.isatty():
            password = getpass.getpass("  New user password: ")
            confirm = getpass.getpass("  Confirm password: ")
        else:
            password = input("  New user password: ")
            confirm = input("  Confirm password: ")
    except (EOFError, KeyboardInterrupt):
        print("\n  Cancelled.")
        return
    if password != confirm:
        print("  Error: passwords do not match.")
        return
    try:
        create_user(username, password, role, clearance, admin_user=user)
        print(f"  User '{username}' created successfully.")
    except AuthError:
        print("  Operation failed.")


def _run_user_management_menu(user) -> None:
    """Interactive user management submenu — admin only."""
    USER_MENU = (
        "\n"
        "  ── User Management ──────────────────────\n"
        "  [1] Add User\n"
        "  [2] List Users\n"
        "  [3] Disable User\n"
        "  [4] Enable User\n"
        "  [5] Change Role\n"
        "  [6] Change Clearance\n"
        "  [7] Reset Password\n"
        "  [8] Delete User\n"
        "  [9] Back\n"
    )

    while True:
        print(USER_MENU)
        try:
            choice = input("  Select option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Returning to main menu.")
            break

        if choice == "1":
            _interactive_add_user(user)
        elif choice == "2":
            _cmd_list_users(argparse.Namespace(), user)
        elif choice == "3":
            u = _prompt_username()
            if u:
                _cmd_disable_user(argparse.Namespace(username=u), user)
        elif choice == "4":
            u = _prompt_username()
            if u:
                _cmd_enable_user(argparse.Namespace(username=u), user)
        elif choice == "5":
            u = _prompt_username()
            if u:
                try:
                    role = input("  New role (admin/analyst/auditor): ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\n  Cancelled.")
                    continue
                _cmd_change_role(argparse.Namespace(username=u, role=role), user)
        elif choice == "6":
            u = _prompt_username()
            if u:
                try:
                    clearance = input("  New clearance (low/medium/high): ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\n  Cancelled.")
                    continue
                _cmd_change_clearance(argparse.Namespace(username=u, clearance=clearance), user)
        elif choice == "7":
            u = _prompt_username()
            if u:
                _cmd_reset_password(argparse.Namespace(username=u), user)
        elif choice == "8":
            u = _prompt_username()
            if u:
                _cmd_delete_user(argparse.Namespace(username=u), user)
        elif choice in ("9", "b", "back"):
            break
        else:
            print("  [!] Invalid option. Enter 1–9.")


def run_interactive(user=None) -> None:
    """Main interactive loop — menu rendered dynamically via authorize()."""
    from .auth_engine import AuthorizationEngine

    BANNER = (
        "\n"
        "╔══════════════════════════════════════════╗\n"
        "║   Hybrid File Encryption System          ║\n"
        "║   AES-256-GCM + RSA-3072 / ECC P-256     ║\n"
        "║   Sign-then-Encrypt · Verify-before-Dec  ║\n"
        "╚══════════════════════════════════════════╝"
    )

    print(BANNER)

    _CANDIDATES = [
        ("encrypt",      "Encrypt File",       lambda: run_encrypt()),
        ("decrypt",      "Decrypt File",       lambda: run_decrypt()),
        ("view_logs",    "View Audit Logs",    lambda: _cmd_view_logs(argparse.Namespace(role="", action="", result=""), user)),
        ("verify_audit", "Verify Audit Chain", lambda: _cmd_verify_chain(argparse.Namespace(), user)),
        ("export_logs",  "Export Logs",        lambda: _cmd_export_logs(argparse.Namespace(), user)),
    ]

    available: list[tuple[str, object]] = [
        (label, fn) for action, label, fn in _CANDIDATES
        if AuthorizationEngine.authorize(user, action, "low")[0]
    ]

    if getattr(user, "role", None) == "admin":
        available.append(("Manage Users", lambda: _run_user_management_menu(user)))

    available.append(("Exit", None))

    menu = "\n" + "".join(f"  [{i}] {label}\n" for i, (label, _) in enumerate(available, 1))

    while True:
        print(menu)
        try:
            choice = input("  Select option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting.")
            break
        try:
            idx = int(choice) - 1
        except ValueError:
            print(f"  [!] Invalid option. Enter 1–{len(available)}.")
            continue
        if idx < 0 or idx >= len(available):
            print(f"  [!] Invalid option. Enter 1–{len(available)}.")
            continue
        label, fn = available[idx]
        if fn is None:
            print("\n  Goodbye.")
            break
        fn()


def _cmd_encrypt(args: argparse.Namespace, user=None) -> int:
    input_path = args.file
    if not Path(input_path).is_file():
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        return 1

    # Resolve output path: explicit --output wins, then --output-dir, then same dir as input.
    if args.output:
        output_path = args.output
    elif args.output_dir:
        out_dir = Path(args.output_dir)
        if not out_dir.is_dir():
            print(f"Error: output directory does not exist: {args.output_dir}", file=sys.stderr)
            return 1
        output_path = str(out_dir / (Path(input_path).name + ".enc"))
    else:
        output_path = None

    overwrite = args.overwrite

    if output_path is not None and Path(output_path).exists() and not overwrite:
        print(f"Error: output file already exists: {output_path}", file=sys.stderr)
        print("Use --overwrite to replace it.", file=sys.stderr)
        return 1

    context: dict = {}
    if getattr(args, "sensitive", False):
        context["sensitive"] = True
    elif getattr(args, "internal", False):
        context["internal"] = True

    try:
        result = stream_encrypt_file(
            input_path,
            output_path=output_path,
            method=args.method,
            delete_original=args.delete_original,
            overwrite=overwrite,
            user=user,
            context=context,
        )
        print(f"Encrypted: {result}")
        return 0
    except FileCryptoError:
        print("Encryption failed.", file=sys.stderr)
        return 1


def _cmd_decrypt(args: argparse.Namespace, user=None) -> int:
    input_path = args.file
    if not Path(input_path).is_file():
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        return 1

    output_path = args.output
    overwrite = args.overwrite

    if output_path and Path(output_path).exists() and not overwrite:
        print(f"Error: output file already exists: {output_path}", file=sys.stderr)
        print("Use --overwrite to replace it.", file=sys.stderr)
        return 1

    print("Note: classification is read from the encrypted container.", file=sys.stderr)
    try:
        result = stream_decrypt_file(
            input_path,
            output_path=output_path,
            overwrite=overwrite,
            user=user,
        )
        print(f"Decrypted: {result}")
        return 0
    except FileCryptoError:
        print("Decryption failed.", file=sys.stderr)
        return 1


def _log_audit(action: str, outcome: str, key_id: str | None = None, reason: str | None = None, *, user=None) -> bool:
    """Write an audit entry. Returns False if the audit write fails; caller must treat that as a hard error."""
    try:
        AuditLogger.log_event(user, action=action, outcome=outcome, key_id=key_id, reason=reason)
        return True
    except AuditLogError:
        print("Audit failure: operation aborted.", file=sys.stderr)
        return False


def _require_admin(user) -> int | None:
    if not getattr(user, "authenticated", False):
        print("Access denied.", file=sys.stderr)
        return 1
    if getattr(user, "role", "") != "admin":
        print("Access denied.", file=sys.stderr)
        return 1
    return None


def _cmd_sign(args: argparse.Namespace, user=None) -> int:
    if _require_admin(user):
        return 1
    input_path = args.file
    if not Path(input_path).is_file():
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        return 1

    sig_path = args.output or f"{input_path}.sig"
    method = args.method

    try:
        provider = LocalPemKeyProvider()
        if method == "rsa":
            key_id = provider.get_active_rsa_signing_key_id()
            private_key = provider.get_rsa_signing_private_key()
        else:
            key_id = provider.get_active_ecc_signing_key_id()
            private_key = provider.get_ecc_signing_private_key()
    except KeyProviderError:
        print("Key load failed.", file=sys.stderr)
        if not _log_audit("SIGN", "error", user=user):
            return 1
        return 1

    try:
        with Path(input_path).open("rb") as in_f:
            signature = sign_stream(method, private_key, in_f)
        Path(sig_path).write_bytes(encode_sig_file(method, signature, key_id=key_id))
        if not _log_audit("SIGN", "success", key_id=key_id, user=user):
            return 1
        print(f"Signature: {sig_path}")
        return 0
    except SignatureError:
        print("Signing failed.", file=sys.stderr)
        if not _log_audit("SIGN", "error", key_id=key_id, user=user):
            return 1
        return 1


def _cmd_verify(args: argparse.Namespace, user=None) -> int:
    if _require_admin(user):
        return 1
    input_path = args.file
    sig_path = args.sig

    if not Path(input_path).is_file():
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        return 1
    if not Path(sig_path).is_file():
        print(f"Error: signature file not found: {sig_path}", file=sys.stderr)
        return 1

    # Read algorithm and key_id from the .sig file header.
    try:
        method, signature, sig_key_id = decode_sig_file_full(Path(sig_path).read_bytes())
    except SignatureError:
        print("Error reading signature file.", file=sys.stderr)
        if not _log_audit("VERIFY", "error", user=user):
            return 1
        return 1

    # Resolve signing public key by exact key_id embedded in artifact — no fallback.
    if sig_key_id is None:
        print("Error: signature file does not contain a key_id. Legacy format not supported.", file=sys.stderr)
        if not _log_audit("VERIFY", "denied", user=user):
            return 1
        return 1

    try:
        provider = LocalPemKeyProvider()
        public_key = provider.get_signing_public_key(sig_key_id)
    except KeyProviderError:
        print("Key load failed.", file=sys.stderr)
        if not _log_audit("VERIFY", "error", key_id=sig_key_id, user=user):
            return 1
        return 1

    try:
        with Path(input_path).open("rb") as in_f:
            verify_stream(method, public_key, signature, in_f)
        if not _log_audit("VERIFY", "success", key_id=sig_key_id, user=user):
            return 1
        print(f"Signature valid: {input_path}")
        return 0
    except SignatureError:
        print("Signature INVALID.", file=sys.stderr)
        if not _log_audit("VERIFY", "denied", key_id=sig_key_id, user=user):
            return 1
        return 2


def _cmd_rotate_keys(args: argparse.Namespace, user=None) -> int:
    if _require_admin(user):
        return 1
    registry = KeyRegistry()
    try:
        registry.load()
    except Exception:
        print("Error: could not load key registry.", file=sys.stderr)
        return 1
    methods = ["rsa", "ecc"] if args.method == "all" else [args.method]
    ok = True
    for method in methods:
        try:
            if method == "rsa":
                _, pub, key_id = rotate_rsa_signing_keys(registry, user=user)
                fp = rsa_key_fingerprint(pub)
            else:
                _, pub, key_id = rotate_ecc_signing_keys(registry, user=user)
                fp = ecc_key_fingerprint(pub)
            print(f"{method.upper()} signing keys rotated. key_id={key_id}  fingerprint={fp}")
        except (RSAEngineError, ECCEngineError):
            print(f"Error rotating {method.upper()} signing keys.", file=sys.stderr)
            ok = False
    return 0 if ok else 1


def _cmd_rotate_enc_keys(args: argparse.Namespace, user=None) -> int:
    """Rotate encryption keypairs for RSA, ECC, or both."""
    if _require_admin(user):
        return 1
    methods = ["rsa", "ecc"] if args.method == "all" else [args.method]
    registry = KeyRegistry()
    try:
        registry.load()
    except KeyRegistryError:
        print("Error loading key registry.", file=sys.stderr)
        return 1

    ok = True
    for method in methods:
        try:
            if method == "rsa":
                _, pub, key_id = rotate_rsa_encryption_keys(registry, user=user)
                fp = rsa_key_fingerprint(pub)
            else:
                _, pub, key_id = rotate_ecc_encryption_keys(registry, user=user)
                fp = ecc_key_fingerprint(pub)
            print(f"{method.upper()} encryption keys rotated.")
            print(f"  New key_id:     {key_id}")
            print(f"  Fingerprint:    {fp}")
        except (RSAEngineError, ECCEngineError):
            print(f"Error rotating {method.upper()} encryption keys.", file=sys.stderr)
            ok = False
    return 0 if ok else 1


def _cmd_rewrap(args: argparse.Namespace, user=None) -> int:
    """Re-wrap the DEK in an SVST container with the current active encryption key."""
    if _require_admin(user):
        return 1
    try:
        out = rewrap_dek(
            args.file,
            output_path=args.output,
            overwrite=args.overwrite,
            user=user,
        )
        print(f"DEK rewrapped successfully: {out}")
        return 0
    except FileCryptoError:
        print("Error: DEK rewrap operation failed.", file=sys.stderr)
        return 1


def _cmd_audit_repair(args: argparse.Namespace, user=None) -> int:
    """Scan the audit log and report corruption. Requires authenticated admin."""
    result = _require_admin(user)
    if result is not None:
        _log_audit("ACCESS_DENIED", outcome="denied", user=user)
        return result

    from .audit_logger import AUDIT_LOG_FILE
    try:
        last_valid_hash, corrupt_count = scan_audit_chain()
    except AuditLogError as exc:
        print("Error: audit log unavailable.", file=sys.stderr)
        return 1

    if not AUDIT_LOG_FILE.exists():
        print("Audit log does not exist yet.")
        return 0

    if corrupt_count == 0:
        print("Audit log chain is intact. No corrupt entries found.")
        print(f"Last valid hash: {last_valid_hash}")
        return 0

    print(f"Audit log has {corrupt_count} corrupt entr{'y' if corrupt_count == 1 else 'ies'}.")
    print(f"Last valid hash: {last_valid_hash}")
    print(
        "Auto-recovery is active: the next log_event() call will write an "
        "AUDIT_RECOVERY marker and resume the chain from the last valid entry."
    )
    print("No action required — operations are not blocked.")
    return 0


def _cmd_view_logs(args: argparse.Namespace, user=None) -> int:
    """Display audit log entries (auditor only)."""
    from .auth_engine import AuthorizationEngine
    ok, reason = AuthorizationEngine.authorize(user, "view_logs", "low")
    if not ok:
        print(f"Access denied: {reason}", file=sys.stderr)
        return 1

    filters: dict = {}
    if getattr(args, "username", ""):
        filters["username"] = args.username
    if getattr(args, "role", ""):
        filters["role"] = args.role
    if getattr(args, "action", ""):
        filters["action"] = args.action
    if getattr(args, "result", ""):
        filters["result"] = args.result

    try:
        entries = read_logs(filters if filters else None)
    except AuditLogError as exc:
        print(f"Error reading audit log: {exc}", file=sys.stderr)
        return 1

    corrupt = [e for e in entries if e.get("_corrupt")]
    clean = [e for e in entries if not e.get("_corrupt")]

    if getattr(args, "oldest_first", False):
        clean = list(reversed(clean))

    total = len(clean)
    if total == 0 and not corrupt:
        print("No log entries found.")
        return 0

    limit = max(1, getattr(args, "limit", 500))
    page = max(1, getattr(args, "page", 1))
    total_pages = max(1, (total + limit - 1) // limit)
    page = min(page, total_pages)
    start = (page - 1) * limit
    page_entries = clean[start:start + limit]

    print(f"Page {page}/{total_pages} | Showing {start + 1}–{min(start + limit, total)} of {total} entries")
    header = (f"{'Timestamp':<20} {'Username':<14} {'Role':<10} {'Action':<14} "
              f"{'Result':<8} {'Key ID':<22} {'Classification'}")
    print(header)
    print("-" * len(header))
    for e in page_entries:
        ts = str(e.get("timestamp", ""))[:19]
        print(f"{ts:<20} {str(e.get('username','') or ''):<14} {str(e.get('role','')):<10} "
              f"{str(e.get('action','')):<14} {str(e.get('result','')):<8} "
              f"{str(e.get('key_id','') or ''):<22} {str(e.get('classification',''))}")

    if corrupt:
        print(f"\n  [{len(corrupt)} corrupt entr{'y' if len(corrupt)==1 else 'ies'} found — run audit-repair for details]")
    return 0


def _cmd_verify_chain(args: argparse.Namespace, user=None) -> int:
    """Verify audit log chain integrity (auditor only)."""
    from .auth_engine import AuthorizationEngine
    ok, reason = AuthorizationEngine.authorize(user, "verify_audit", "low")
    if not ok:
        print(f"Access denied: {reason}", file=sys.stderr)
        return 1

    try:
        last_valid_hash, corrupt_count = scan_audit_chain()
        check_chain()
    except AuditLogError as exc:
        print(f"Chain integrity FAIL: {exc}", file=sys.stderr)
        if corrupt_count:
            print(f"  {corrupt_count} corrupt entr{'y' if corrupt_count==1 else 'ies'} detected.")
        return 1

    if corrupt_count:
        print(f"Chain integrity FAIL: {corrupt_count} corrupt entr{'y' if corrupt_count==1 else 'ies'} detected.")
        print(f"Last valid hash: {last_valid_hash}")
        return 1

    print("Chain integrity OK — no corrupt entries.")
    print(f"Last valid hash: {last_valid_hash}")
    return 0


def _cmd_export_logs(args: argparse.Namespace, user=None) -> int:
    """Export audit log to workspace/output/audit/ (auditor only)."""
    from .auth_engine import AuthorizationEngine
    ok, reason = AuthorizationEngine.authorize(user, "export_logs", "low")
    if not ok:
        print(f"Access denied: {reason}", file=sys.stderr)
        return 1

    from . import workspace as _ws
    _ws.SAFE_AUDIT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        result = export_logs(str(_ws.SAFE_AUDIT_OUTPUT_DIR))
    except AuditLogError as exc:
        print(f"Export failed: {exc}", file=sys.stderr)
        return 1

    from pathlib import Path as _Path
    sidecar = str(_Path(result).with_suffix(".json.sha256"))
    print(f"Exported audit log → {result}")
    print(f"Integrity sidecar  → {sidecar}")
    return 0


def _auth_login() -> object:
    """Prompt for username and password; return authenticated User or exit 1."""
    from .auth import authenticate
    try:
        username = input("Username: ").strip()
        # Use getpass for TTY (hides password); fall back to input() for non-interactive stdin.
        if sys.stdin.isatty():
            password = getpass.getpass("Password: ")
        else:
            password = input("Password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nAuthentication cancelled.", file=sys.stderr)
        sys.exit(1)
    user = authenticate(username, password)
    if user is None:
        print("Authentication failed.", file=sys.stderr)
        sys.exit(1)
    return user


def _cmd_add_user(args: argparse.Namespace) -> int:
    """Bootstrap first user or create additional users (requires admin auth)."""
    from .auth import AuthError, authenticate, create_user, user_store_exists

    is_bootstrap = not user_store_exists()

    username = args.username
    if not username:
        try:
            username = input("Username: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.", file=sys.stderr)
            return 1
    if not username:
        print("Error: username is required.", file=sys.stderr)
        return 1

    if is_bootstrap:
        print("No user store found. Creating first admin user (bootstrap).")
        print("Role: admin, Clearance: high (forced for first user).")
        role = "admin"
        clearance = "high"
        admin_user = None
    else:
        role = args.role
        clearance = args.clearance
        if not role:
            try:
                role = input("Role (admin/analyst/auditor): ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nCancelled.", file=sys.stderr)
                return 1
        if not clearance:
            try:
                clearance = input("Clearance (low/medium/high): ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nCancelled.", file=sys.stderr)
                return 1
        print("\nAdmin authentication required:")
        try:
            admin_username = input("Admin username: ").strip()
            admin_password = getpass.getpass("Admin password: ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.", file=sys.stderr)
            return 1
        admin_user = authenticate(admin_username, admin_password)
        if admin_user is None or admin_user.role != "admin":
            print("Authentication failed.", file=sys.stderr)
            return 1

    try:
        password = getpass.getpass("New user password: ")
        confirm = getpass.getpass("Confirm password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 1
    if password != confirm:
        print("Error: passwords do not match.", file=sys.stderr)
        return 1

    try:
        create_user(username, password, role, clearance, admin_user=admin_user)
        print(f"User '{username}' created successfully.")
        return 0
    except AuthError as exc:
        print("Error: user creation failed.", file=sys.stderr)
        return 1


def _cmd_disable_user(args: argparse.Namespace, user=None) -> int:
    from .auth import AuthError, disable_user
    try:
        disable_user(args.username, admin_user=user)
        print(f"User '{args.username}' disabled.")
        return 0
    except AuthError:
        print("Operation failed.", file=sys.stderr)
        return 1


def _cmd_enable_user(args: argparse.Namespace, user=None) -> int:
    from .auth import AuthError, enable_user
    try:
        enable_user(args.username, admin_user=user)
        print(f"User '{args.username}' enabled.")
        return 0
    except AuthError:
        print("Operation failed.", file=sys.stderr)
        return 1


def _cmd_list_users(args: argparse.Namespace, user=None) -> int:
    from .auth import AuthError, list_users
    try:
        users = list_users(admin_user=user)
    except AuthError:
        print("Operation failed.", file=sys.stderr)
        return 1
    if not users:
        print("No users found.")
        return 0
    print(f"{'Username':<20} {'Role':<12} {'Clearance':<10} {'Status'}")
    print("-" * 56)
    for u in users:
        print(f"{u['username']:<20} {u['role']:<12} {u['clearance']:<10} {u['status']}")
    return 0


def _cmd_change_role(args: argparse.Namespace, user=None) -> int:
    from .auth import AuthError, change_role
    try:
        change_role(args.username, args.role, admin_user=user)
        print(f"Role updated for '{args.username}'.")
        return 0
    except AuthError:
        print("Operation failed.", file=sys.stderr)
        return 1


def _cmd_change_clearance(args: argparse.Namespace, user=None) -> int:
    from .auth import AuthError, change_clearance
    try:
        change_clearance(args.username, args.clearance, admin_user=user)
        print(f"Clearance updated for '{args.username}'.")
        return 0
    except AuthError:
        print("Operation failed.", file=sys.stderr)
        return 1


def _cmd_reset_password(args: argparse.Namespace, user=None) -> int:
    from .auth import AuthError, reset_password
    try:
        if sys.stdin.isatty():
            new_password = getpass.getpass(f"New password for '{args.username}': ")
            confirm = getpass.getpass("Confirm new password: ")
        else:
            new_password = input("New password: ")
            confirm = input("Confirm new password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 1
    if new_password != confirm:
        print("Error: passwords do not match.", file=sys.stderr)
        return 1
    try:
        reset_password(args.username, new_password, admin_user=user)
        print(f"Password reset for '{args.username}'.")
        return 0
    except AuthError:
        print("Operation failed.", file=sys.stderr)
        return 1


def _cmd_delete_user(args: argparse.Namespace, user=None) -> int:
    from .auth import AuthError, delete_user
    try:
        confirm = input(f"Delete user '{args.username}'? This cannot be undone. [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 1
    if confirm not in ("y", "yes"):
        print("Cancelled.", file=sys.stderr)
        return 0
    try:
        delete_user(args.username, admin_user=user)
        print(f"User '{args.username}' deleted.")
        return 0
    except AuthError:
        print("Operation failed.", file=sys.stderr)
        return 1


def _dispatch_users(args: argparse.Namespace, user=None) -> int:
    """Route spy-cli users <subcommand> to the appropriate handler."""
    users_dispatch = {
        "add":              lambda a: _cmd_add_user(a),  # handles auth internally
        "list":             lambda a: _cmd_list_users(a, user),
        "disable":          lambda a: _cmd_disable_user(a, user),
        "enable":           lambda a: _cmd_enable_user(a, user),
        "change-role":      lambda a: _cmd_change_role(a, user),
        "change-clearance": lambda a: _cmd_change_clearance(a, user),
        "reset-password":   lambda a: _cmd_reset_password(a, user),
        "delete":           lambda a: _cmd_delete_user(a, user),
    }
    return users_dispatch[args.users_command](args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="file_crypto_cli",
        description="AI-Orchestrated Hybrid Encryption — file encryption CLI",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # encrypt
    p_enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("file", help="Path to the plaintext file")
    p_enc.add_argument("--method", choices=["rsa", "ecc"], default="rsa",
                       help="Encryption method (default: rsa)")
    p_enc.add_argument("--output", metavar="PATH", help="Full output file path (default: FILE.enc)")
    p_enc.add_argument("--output-dir", metavar="DIR",
                       help="Destination directory for the .enc file (uses input filename + .enc)")
    p_enc.add_argument("--delete-original", action="store_true",
                       help="Delete the plaintext file after encryption")
    p_enc.add_argument("--overwrite", action="store_true",
                       help="Overwrite output file if it exists")
    p_enc.add_argument("--sensitive", action="store_true",
                       help="Signal that data is sensitive (policy assigns high classification)")
    p_enc.add_argument("--internal", action="store_true",
                       help="Signal that data is for internal use (policy assigns medium classification)")

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("file", help="Path to the encrypted file")
    p_dec.add_argument("--output", metavar="PATH",
                       help="Output path (default: strip .enc or append .decrypted)")
    p_dec.add_argument("--overwrite", action="store_true",
                       help="Overwrite output file if it exists")

    # sign
    p_sign = subparsers.add_parser("sign", help="Sign a file")
    p_sign.add_argument("file", help="Path to the file to sign")
    p_sign.add_argument("--method", choices=["rsa", "ecc"], default="rsa",
                        help="Signature algorithm (default: rsa → RSA-PSS; ecc → ECDSA)")
    p_sign.add_argument("--output", metavar="PATH", help="Signature output path (default: FILE.sig)")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify a file signature")
    p_verify.add_argument("file", help="Path to the file to verify")
    p_verify.add_argument("--sig", required=True, metavar="SIG_FILE",
                          help="Path to the signature file (algorithm is read from the file header)")

    # rotate-keys
    p_rot = subparsers.add_parser("rotate-keys", help="Rotate signing keys (archives old keys)")
    p_rot.add_argument("--method", choices=["rsa", "ecc", "all"], default="all",
                       help="Which signing keypair to rotate (default: all)")

    # rotate-enc-keys
    p_rot_enc = subparsers.add_parser(
        "rotate-enc-keys",
        help="Rotate encryption keypairs (old key becomes decrypt-only)",
    )
    p_rot_enc.add_argument("--method", choices=["rsa", "ecc", "all"], default="all",
                           help="Which encryption keypair to rotate (default: all)")

    # rewrap
    p_rewrap = subparsers.add_parser(
        "rewrap",
        help="Re-wrap the DEK in an SVST file with the current active encryption key",
    )
    p_rewrap.add_argument("file", help="Path to the SVST .enc file")
    p_rewrap.add_argument("--output", metavar="PATH",
                          help="Output path (default: overwrite the input file in-place)")
    p_rewrap.add_argument("--overwrite", action="store_true",
                          help="Overwrite output file if it exists")

    # audit-repair
    subparsers.add_parser(
        "audit-repair",
        help="Scan the audit log for corrupt entries and report findings",
    )

    # view-logs (auditor only)
    p_view = subparsers.add_parser("view-logs", help="View audit log entries (auditor only)")
    p_view.add_argument("--username", metavar="USERNAME", default="",
                        help="Filter by username field (exact log key)")
    p_view.add_argument("--role", metavar="ROLE", default="",
                        help="Filter by role field (exact log key)")
    p_view.add_argument("--action", metavar="ACTION", default="",
                        help="Filter by action field (e.g. ENCRYPT, DECRYPT)")
    p_view.add_argument("--result", metavar="RESULT", default="",
                        help="Filter by result field (e.g. SUCCESS, DENIED)")
    p_view.add_argument("--limit", type=int, default=500, metavar="N",
                        help="Entries per page (default: 500)")
    p_view.add_argument("--page", type=int, default=1, metavar="N",
                        help="Page number, 1-based (default: 1)")
    p_view.add_argument("--oldest-first", action="store_true",
                        help="Show oldest entries first (default: newest first)")

    # verify-chain (auditor only)
    subparsers.add_parser("verify-chain", help="Verify audit log chain integrity (auditor only)")

    # export-logs (auditor only)
    subparsers.add_parser("export-logs", help="Export audit log to workspace/output/audit/ (auditor only)")

    # add-user
    p_add_user = subparsers.add_parser(
        "add-user",
        help="Create a user (bootstrap first user; admin auth required for subsequent users)",
    )
    p_add_user.add_argument("--username", metavar="NAME", default="", help="Username")
    p_add_user.add_argument("--role", choices=["admin", "analyst", "auditor"], default="",
                            help="Role (ignored on bootstrap — forced to admin)")
    p_add_user.add_argument("--clearance", choices=["low", "medium", "high"], default="",
                            help="Clearance (ignored on bootstrap — forced to high)")

    # disable-user
    p_dis = subparsers.add_parser("disable-user", help="Disable a user account")
    p_dis.add_argument("--username", required=True, metavar="NAME")

    # enable-user
    p_ena = subparsers.add_parser("enable-user", help="Re-enable a disabled user account")
    p_ena.add_argument("--username", required=True, metavar="NAME")

    # list-users
    subparsers.add_parser("list-users", help="List all user accounts (admin only)")

    # change-role
    p_cr = subparsers.add_parser("change-role", help="Change a user's role")
    p_cr.add_argument("--username", required=True, metavar="NAME")
    p_cr.add_argument("--role", required=True, choices=["admin", "analyst", "auditor"])

    # change-clearance
    p_cc = subparsers.add_parser("change-clearance", help="Change a user's clearance level")
    p_cc.add_argument("--username", required=True, metavar="NAME")
    p_cc.add_argument("--clearance", required=True, choices=["low", "medium", "high"])

    # reset-password
    p_rp = subparsers.add_parser("reset-password", help="Admin force-reset a user's password")
    p_rp.add_argument("--username", required=True, metavar="NAME")

    # delete-user (legacy)
    p_del = subparsers.add_parser("delete-user", help="Permanently delete a user account")
    p_del.add_argument("--username", required=True, metavar="NAME")

    # users namespace — groups all user management under one subcommand
    users_parser = subparsers.add_parser("users", help="User management commands")
    users_sub = users_parser.add_subparsers(dest="users_command", required=True)

    p_u_add = users_sub.add_parser("add", help="Create a user")
    p_u_add.add_argument("--username", metavar="NAME", default="", help="Username")
    p_u_add.add_argument("--role", choices=["admin", "analyst", "auditor"], default="",
                         help="Role (ignored on bootstrap — forced to admin)")
    p_u_add.add_argument("--clearance", choices=["low", "medium", "high"], default="",
                         help="Clearance (ignored on bootstrap — forced to high)")

    users_sub.add_parser("list", help="List all user accounts (admin only)")

    p_u_dis = users_sub.add_parser("disable", help="Disable a user account")
    p_u_dis.add_argument("--username", required=True, metavar="NAME")

    p_u_ena = users_sub.add_parser("enable", help="Re-enable a disabled user account")
    p_u_ena.add_argument("--username", required=True, metavar="NAME")

    p_u_cr = users_sub.add_parser("change-role", help="Change a user's role")
    p_u_cr.add_argument("--username", required=True, metavar="NAME")
    p_u_cr.add_argument("--role", required=True, choices=["admin", "analyst", "auditor"])

    p_u_cc = users_sub.add_parser("change-clearance", help="Change a user's clearance level")
    p_u_cc.add_argument("--username", required=True, metavar="NAME")
    p_u_cc.add_argument("--clearance", required=True, choices=["low", "medium", "high"])

    p_u_rp = users_sub.add_parser("reset-password", help="Admin force-reset a user's password")
    p_u_rp.add_argument("--username", required=True, metavar="NAME")

    p_u_del = users_sub.add_parser("delete", help="Permanently delete a user account")
    p_u_del.add_argument("--username", required=True, metavar="NAME")

    return parser


def _startup_validate() -> None:
    """Validate system prerequisites before accepting any operation.

    Checks (in order):
      1. Audit log hash chain is intact or absent
      2. Key registry loads without error
      3. Key provider initializes without error
      4. Required passphrase environment variables are present and non-empty

    Prints a sanitized message and exits with code 1 on any failure.
    """
    import os

    try:
        check_chain()
    except AuditLogError:
        # Corrupt tail entries are auto-recovered by log_event(). Startup continues.
        # Run 'spy-cli audit-repair' for a full diagnostic report.
        print("Warning: audit log has corrupt entries — auto-recovery active.", file=sys.stderr)
    except OSError:
        print("Startup error: audit log cannot be read. Cannot proceed.", file=sys.stderr)
        sys.exit(1)

    try:
        r = KeyRegistry()
        r.load()
    except Exception:
        print("Startup error: key registry is unavailable or corrupt. Cannot proceed.", file=sys.stderr)
        sys.exit(1)

    try:
        LocalPemKeyProvider()
    except Exception:
        print("Startup error: key provider failed to initialize. Cannot proceed.", file=sys.stderr)
        sys.exit(1)

    required_env = [
        "RSA_KEY_PASSPHRASE", "ECC_KEY_PASSPHRASE",
        "RSA_SIGN_KEY_PASSPHRASE", "ECC_SIGN_KEY_PASSPHRASE",
        "USERS_HMAC_KEY",
    ]
    missing = [k for k in required_env if not os.environ.get(k, "").strip()]
    if missing:
        print("Startup error: required configuration is missing. Cannot proceed.", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    # add-user / users add bypasses startup validation — bootstrap flow only.
    _is_users_add = (len(sys.argv) > 2 and sys.argv[1] == "users" and sys.argv[2] == "add")
    if len(sys.argv) > 1 and (sys.argv[1] == "add-user" or _is_users_add):
        parser = build_parser()
        args = parser.parse_args()
        if args.command == "add-user":
            sys.exit(_cmd_add_user(args))
        elif args.command == "users" and args.users_command == "add":
            sys.exit(_cmd_add_user(args))

    _startup_validate()

    # All other operations require authentication.
    authenticated_user = _auth_login()

    # No arguments → interactive guided mode.
    if len(sys.argv) == 1:
        run_interactive(authenticated_user)
        return

    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "encrypt":          lambda a: _cmd_encrypt(a, authenticated_user),
        "decrypt":          lambda a: _cmd_decrypt(a, authenticated_user),
        "sign":             lambda a: _cmd_sign(a, authenticated_user),
        "verify":           lambda a: _cmd_verify(a, authenticated_user),
        "rotate-keys":      lambda a: _cmd_rotate_keys(a, authenticated_user),
        "rotate-enc-keys":  lambda a: _cmd_rotate_enc_keys(a, authenticated_user),
        "rewrap":           lambda a: _cmd_rewrap(a, authenticated_user),
        "audit-repair":     lambda a: _cmd_audit_repair(a, authenticated_user),
        "view-logs":        lambda a: _cmd_view_logs(a, authenticated_user),
        "verify-chain":     lambda a: _cmd_verify_chain(a, authenticated_user),
        "export-logs":      lambda a: _cmd_export_logs(a, authenticated_user),
        "add-user":         _cmd_add_user,
        "disable-user":     lambda a: _cmd_disable_user(a, authenticated_user),
        "enable-user":      lambda a: _cmd_enable_user(a, authenticated_user),
        "list-users":       lambda a: _cmd_list_users(a, authenticated_user),
        "change-role":      lambda a: _cmd_change_role(a, authenticated_user),
        "change-clearance": lambda a: _cmd_change_clearance(a, authenticated_user),
        "reset-password":   lambda a: _cmd_reset_password(a, authenticated_user),
        "delete-user":      lambda a: _cmd_delete_user(a, authenticated_user),
        "users":            lambda a: _dispatch_users(a, authenticated_user),
    }
    sys.exit(dispatch[args.command](args))


if __name__ == "__main__":
    main()
