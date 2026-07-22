"""
gui.py — Interactive GUI launcher for the Hybrid File Encryption system.

Presents a menu of four operations (Encrypt, Decrypt, Sign, Verify), opens a
native file picker for each, and dispatches directly to the engine functions.
No cryptographic logic lives here.

Run with:
    spy-gui
"""

from __future__ import annotations
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")
import sys
import traceback
import unicodedata
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from .workspace import (
    is_inside_safe_root as _is_inside_safe_root,
    SAFE_ENCRYPT_INPUT_DIR,
    SAFE_ENCRYPTED_OUTPUT_DIR,
    SAFE_SIG_DIR,
    SAFE_AUDIT_OUTPUT_DIR,
)

# ---------------------------------------------------------------------------
# Engine imports — imported lazily inside each handler so the GUI opens
# instantly even if the crypto stack takes a moment to initialise.
# ---------------------------------------------------------------------------


def _import_engines():
    from .file_crypto_engine import (
        FileCryptoError, FileCryptoOverwriteError, stream_decrypt_file, stream_encrypt_file,
    )
    from .key_provider import KeyProviderError, LocalPemKeyProvider
    from .key_registry import KeyRegistryError
    from .rsa_engine import RSAEngineError
    from .ecc_engine import ECCEngineError
    from .signature_engine import (
        SignatureError,
        decode_sig_file_full,
        encode_sig_file,
        sign_stream,
        verify_stream,
    )
    from .audit_logger import AuditLogger, AuditLogError
    from .auth_engine import AuthorizationEngine
    return {
        "stream_encrypt_file": stream_encrypt_file,
        "stream_decrypt_file": stream_decrypt_file,
        "LocalPemKeyProvider": LocalPemKeyProvider,
        "FileCryptoOverwriteError": FileCryptoOverwriteError,
        "KeyRegistryError": KeyRegistryError,
        "encode_sig_file": encode_sig_file,
        "decode_sig_file_full": decode_sig_file_full,
        "sign_stream": sign_stream,
        "verify_stream": verify_stream,
        "FileCryptoError": FileCryptoError,
        "KeyProviderError": KeyProviderError,
        "RSAEngineError": RSAEngineError,
        "ECCEngineError": ECCEngineError,
        "SignatureError": SignatureError,
        "AuditLogger": AuditLogger,
        "AuditLogError": AuditLogError,
        "AuthorizationEngine": AuthorizationEngine,
    }


def _import_audit_tools():
    from .audit_logger import (read_logs, check_chain, scan_audit_chain,
                                export_logs, AuditLogError)
    from .auth_engine import AuthorizationEngine
    return {
        "read_logs": read_logs,
        "check_chain": check_chain,
        "scan_audit_chain": scan_audit_chain,
        "export_logs": export_logs,
        "AuditLogError": AuditLogError,
        "AuthorizationEngine": AuthorizationEngine,
    }


# ---------------------------------------------------------------------------
# Colour palette and fonts
# ---------------------------------------------------------------------------

_BG         = "#1a1a2e"   # deep navy background
_SURFACE    = "#16213e"   # card / panel
_ACCENT     = "#2563eb"   # bright blue — pops against dark surface
_ACCENT_HOV = "#1d4ed8"   # hover (slightly deeper)
_SUCCESS    = "#2d6a4f"   # muted green
_WARN       = "#b5700a"   # muted amber
_ERROR      = "#9b2226"   # muted red
_FG         = "#ccd6f6"   # soft lavender-white — easy on eyes
_FG_DIM     = "#8892b0"   # muted slate

_FONT_TITLE  = ("Helvetica", 18, "bold")
_FONT_BODY   = ("Helvetica", 11)
_FONT_BUTTON = ("Helvetica", 12, "bold")
_FONT_MONO   = ("Courier", 10)


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _resolve_picker_path(picker_path: str) -> str:
    """Return the real filesystem path for a macOS file-picker path.

    macOS Finder/filedialog replaces U+202F NARROW NO-BREAK SPACE with U+0020
    SPACE in returned paths. NFKD normalization maps both to the same form, so
    we can locate the real file by iterating the parent directory.

    Returns picker_path unchanged if it already resolves, or if no matching
    entry is found (caller's is_file() check will fail as normal).
    """
    p = Path(picker_path)
    if p.is_file():
        return picker_path
    parent = p.parent
    if not parent.is_dir():
        return picker_path
    target = unicodedata.normalize('NFKD', p.name)
    for entry in parent.iterdir():
        if unicodedata.normalize('NFKD', entry.name) == target:
            return str(entry)
    return picker_path


# ---------------------------------------------------------------------------
# Reusable widgets
# ---------------------------------------------------------------------------

class _MethodDialog(tk.Toplevel):
    """Small modal dialog for choosing RSA or ECC."""

    def __init__(self, parent: tk.Widget, title: str = "Choose method"):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.configure(bg=_SURFACE)
        self.grab_set()
        self.result: str | None = None

        tk.Label(
            self, text="Encryption / signature algorithm:",
            bg=_SURFACE, fg=_FG, font=_FONT_BODY, pady=12, padx=20,
        ).pack()

        btn_frame = tk.Frame(self, bg=_SURFACE)
        btn_frame.pack(pady=(0, 16), padx=20)

        for label, value in [("RSA-3072 (OAEP / PSS)", "rsa"),
                              ("ECC P-256 (ECDH / ECDSA)", "ecc")]:
            tk.Button(
                btn_frame, text=label, width=28,
                bg=_ACCENT, fg="black", font=_FONT_BUTTON,
                activebackground=_ACCENT_HOV, activeforeground="black",
                relief="flat", cursor="hand2",
                command=lambda v=value: self._pick(v),
            ).pack(pady=4)

        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.transient(parent)
        parent.wait_window(self)

    def _pick(self, value: str) -> None:
        self.result = value
        self.destroy()


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------

class _LoginDialog(tk.Tk):
    """Standalone login window — must authenticate before the main app opens."""

    def __init__(self):
        super().__init__()
        self.title("Login — Hybrid File Encryption")
        self.configure(bg=_BG)
        self.resizable(False, False)
        self.authenticated_user = None
        self._build_ui()
        self._center()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        header = tk.Frame(self, bg=_ACCENT, padx=24, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="Hybrid File Encryption — Login",
                 bg=_ACCENT, fg="white", font=_FONT_TITLE).pack(side="left")

        form = tk.Frame(self, bg=_BG, padx=40, pady=24)
        form.pack()

        tk.Label(form, text="Username:", bg=_BG, fg=_FG,
                 font=_FONT_BODY, anchor="w").pack(fill="x")
        self._username_var = tk.StringVar()
        tk.Entry(form, textvariable=self._username_var, font=_FONT_BODY,
                 bg=_SURFACE, fg=_FG, insertbackground=_FG,
                 relief="flat", width=30).pack(pady=(4, 14), fill="x")

        tk.Label(form, text="Password:", bg=_BG, fg=_FG,
                 font=_FONT_BODY, anchor="w").pack(fill="x")
        self._password_var = tk.StringVar()
        tk.Entry(form, textvariable=self._password_var, show="*",
                 font=_FONT_BODY, bg=_SURFACE, fg=_FG,
                 insertbackground=_FG, relief="flat", width=30).pack(pady=(4, 14), fill="x")

        self._error_var = tk.StringVar()
        tk.Label(form, textvariable=self._error_var,
                 bg=_BG, fg="#f87171", font=_FONT_BODY).pack()

        tk.Button(form, text="Login", font=_FONT_BUTTON,
                  bg=_ACCENT, fg="black", activebackground=_ACCENT_HOV,
                  activeforeground="black", relief="flat", cursor="hand2",
                  padx=14, pady=6, command=self._do_login).pack(pady=10)

        self.bind("<Return>", lambda _e: self._do_login())

    def _do_login(self) -> None:
        from .auth import authenticate
        username = self._username_var.get().strip()
        password = self._password_var.get()
        if not username:
            self._error_var.set("Username is required.")
            return
        user = authenticate(username, password)
        if user is None:
            self._error_var.set("Authentication failed.")
            self._password_var.set("")
            return
        self.authenticated_user = user
        self.destroy()

    def _on_close(self) -> None:
        self.authenticated_user = None
        self.destroy()

    def _center(self) -> None:
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")


class CryptoLauncher(tk.Tk):

    def __init__(self, authenticated_user=None):
        super().__init__()
        self.title("Hybrid File Encryption")
        self.configure(bg=_BG)
        self.resizable(False, False)
        self._authenticated_user = authenticated_user
        self._engines = _import_engines()
        self._audit_tools: dict | None = None
        self._build_ui()
        self._center()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        # ── Header ──────────────────────────────────────────────────────
        header = tk.Frame(self, bg=_ACCENT, padx=24, pady=16)
        header.pack(fill="x")
        tk.Label(
            header, text="Hybrid File Encryption",
            bg=_ACCENT, fg="white", font=_FONT_TITLE,
        ).pack(side="left")
        tk.Label(
            header, text="AES-256-GCM + RSA/ECC",
            bg=_ACCENT, fg=_FG_DIM, font=_FONT_BODY,
        ).pack(side="right", padx=4)

        # ── Content area: role-based ────────────────────────────────────
        role = getattr(self._authenticated_user, "role", None)
        if role == "auditor":
            self._audit_tools = _import_audit_tools()
            self._build_audit_dashboard()
        else:
            # ── Operation buttons ─────────────────────────────────────
            btn_outer = tk.Frame(self, bg=_BG, padx=32, pady=24)
            btn_outer.pack()

            ops = [
                ("Encrypt File",  "Protect a file with hybrid encryption",   self._do_encrypt),
                ("Decrypt File",  "Restore an encrypted .enc file",           self._do_decrypt),
                ("Sign File",     "Create a detached digital signature",      self._do_sign),
                ("Verify File",   "Verify a detached signature",              self._do_verify),
            ]

            for label, subtitle, cmd in ops:
                card = tk.Frame(btn_outer, bg=_SURFACE, padx=20, pady=14,
                                highlightthickness=1, highlightbackground=_ACCENT)
                card.pack(fill="x", pady=6)

                tk.Label(card, text=label, bg=_SURFACE, fg=_FG,
                         font=_FONT_BUTTON, anchor="w").pack(side="left")
                tk.Label(card, text=subtitle, bg=_SURFACE, fg=_FG_DIM,
                         font=_FONT_BODY, anchor="w").pack(side="left", padx=12)
                tk.Button(
                    card, text="Select file →", font=_FONT_BUTTON,
                    bg=_ACCENT, fg="black", activebackground=_ACCENT_HOV,
                    activeforeground="black", relief="flat", cursor="hand2",
                    padx=14, pady=6, command=cmd,
                ).pack(side="right")

            # ── Classification display (read-only — assigned by policy engine)
            cls_frame = tk.Frame(self, bg=_BG)
            cls_frame.pack(pady=(0, 8))
            tk.Label(cls_frame, text="Classification:", bg=_BG, fg=_FG_DIM,
                     font=_FONT_BODY).pack(side="left")
            self._classification_display = tk.Label(
                cls_frame, text="(policy assigned)", bg=_BG, fg=_FG, font=_FONT_BODY
            )
            self._classification_display.pack(side="left", padx=8)

        # ── Status bar ──────────────────────────────────────────────────
        status_frame = tk.Frame(self, bg=_SURFACE, padx=16, pady=10)
        status_frame.pack(fill="x", side="bottom")

        self._status_icon = tk.Label(status_frame, text="●", bg=_SURFACE,
                                     fg=_FG_DIM, font=_FONT_BODY)
        self._status_icon.pack(side="left")

        self._status_var = tk.StringVar(value="Ready — select an operation above.")
        tk.Label(
            status_frame, textvariable=self._status_var,
            bg=_SURFACE, fg=_FG, font=_FONT_MONO, anchor="w",
        ).pack(side="left", padx=8)

    def _center(self) -> None:
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")

    # ------------------------------------------------------------------
    # Audit dashboard (auditor role only)
    # ------------------------------------------------------------------

    def _build_audit_dashboard(self) -> None:
        outer = tk.Frame(self, bg=_BG, padx=24, pady=16)
        outer.pack(fill="both", expand=True)

        tk.Label(outer, text="Audit Dashboard", bg=_BG, fg=_FG,
                 font=_FONT_TITLE, anchor="w").pack(fill="x", pady=(0, 12))

        # Filter row
        filter_frame = tk.Frame(outer, bg=_BG)
        filter_frame.pack(fill="x", pady=(0, 8))

        for label, attr in (("Role:", "_filter_role"), ("Action:", "_filter_action"),
                             ("Result:", "_filter_result")):
            tk.Label(filter_frame, text=label, bg=_BG, fg=_FG_DIM,
                     font=_FONT_BODY).pack(side="left", padx=(0, 4))
            entry = tk.Entry(filter_frame, font=_FONT_MONO, width=12,
                             bg=_SURFACE, fg=_FG, insertbackground=_FG, relief="flat")
            entry.pack(side="left", padx=(0, 16))
            setattr(self, attr, entry)

        # Button row
        btn_frame = tk.Frame(outer, bg=_BG)
        btn_frame.pack(fill="x", pady=(0, 10))
        for label, cmd in (("Refresh Logs", self._audit_refresh),
                            ("Verify Integrity", self._audit_verify),
                            ("Export Logs", self._audit_export)):
            tk.Button(btn_frame, text=label, font=_FONT_BUTTON,
                      bg=_ACCENT, fg="black", activebackground=_ACCENT_HOV,
                      activeforeground="black", relief="flat", cursor="hand2",
                      padx=12, pady=5, command=cmd).pack(side="left", padx=(0, 10))

        # Log table
        table_frame = tk.Frame(outer, bg=_BG)
        table_frame.pack(fill="both", expand=True)

        cols = ("timestamp", "username", "role", "action", "result", "key_id", "classification")
        self._audit_tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                         height=15)
        widths = {"timestamp": 160, "username": 110, "role": 80, "action": 110, "result": 75,
                  "key_id": 210, "classification": 100}
        for col in cols:
            self._audit_tree.heading(col, text=col.capitalize())
            self._audit_tree.column(col, width=widths.get(col, 100), anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical",
                             command=self._audit_tree.yview)
        self._audit_tree.configure(yscrollcommand=vsb.set)
        self._audit_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Pagination controls
        nav_frame = tk.Frame(outer, bg=_BG)
        nav_frame.pack(fill="x", pady=(6, 0))
        self._btn_prev = tk.Button(nav_frame, text="← Previous", font=_FONT_BUTTON,
                                    bg=_SURFACE, fg=_FG, activebackground=_ACCENT_HOV,
                                    activeforeground="black", relief="flat", cursor="hand2",
                                    padx=10, pady=4, command=self._audit_prev_page)
        self._btn_prev.pack(side="left", padx=(0, 8))
        self._audit_page_label = tk.Label(nav_frame, text="", bg=_BG, fg=_FG_DIM,
                                           font=_FONT_BODY)
        self._audit_page_label.pack(side="left", padx=8)
        self._btn_next = tk.Button(nav_frame, text="Next →", font=_FONT_BUTTON,
                                    bg=_SURFACE, fg=_FG, activebackground=_ACCENT_HOV,
                                    activeforeground="black", relief="flat", cursor="hand2",
                                    padx=10, pady=4, command=self._audit_next_page)
        self._btn_next.pack(side="left", padx=(0, 8))

        self._row_cap_label = tk.Label(outer, text="", bg=_BG, fg="#fbbf24",
                                        font=_FONT_BODY)
        self._row_cap_label.pack(fill="x")

        self._audit_page = 0
        self._audit_clean_entries: list = []
        self._audit_refresh()

    _AUDIT_ROW_CAP = 500

    def _audit_refresh(self) -> None:
        at = self._audit_tools
        AuthEngine = at["AuthorizationEngine"]
        ok, reason = AuthEngine.authorize(self._authenticated_user, "view_logs", "low")
        if not ok:
            messagebox.showerror("Access Denied", reason)
            return

        filters: dict = {}
        for attr, key in (("_filter_role", "role"), ("_filter_action", "action"),
                           ("_filter_result", "result")):
            val = getattr(self, attr, None)
            if val:
                v = val.get().strip()
                if v:
                    filters[key] = v

        try:
            entries = at["read_logs"](filters if filters else None)
        except at["AuditLogError"] as exc:
            messagebox.showerror("Audit Error", str(exc))
            return

        self._audit_corrupt_entries = [e for e in entries if e.get("_corrupt")]
        self._audit_clean_entries = [e for e in entries if not e.get("_corrupt")]
        self._audit_page = 0  # filter change always resets to page 1
        self._render_audit_page()

    def _render_audit_page(self) -> None:
        total = len(self._audit_clean_entries)
        total_pages = max(1, (total + self._AUDIT_ROW_CAP - 1) // self._AUDIT_ROW_CAP)
        page = min(self._audit_page, total_pages - 1)
        self._audit_page = page

        start = page * self._AUDIT_ROW_CAP
        page_entries = self._audit_clean_entries[start:start + self._AUDIT_ROW_CAP]

        for item in self._audit_tree.get_children():
            self._audit_tree.delete(item)
        for e in page_entries:
            self._audit_tree.insert("", "end", values=(
                str(e.get("timestamp", ""))[:19],
                str(e.get("username", "") or ""),
                e.get("role", ""),
                e.get("action", ""),
                e.get("result", ""),
                str(e.get("key_id", "") or ""),
                e.get("classification", ""),
            ))

        self._audit_page_label.configure(
            text=f"Page {page + 1} of {total_pages}  |  {total} total entries"
        )
        self._btn_prev.configure(state="normal" if page > 0 else "disabled")
        self._btn_next.configure(state="normal" if page < total_pages - 1 else "disabled")

        corrupt = getattr(self, "_audit_corrupt_entries", [])
        corrupt_msg = f"  {len(corrupt)} corrupt entr{'y' if len(corrupt)==1 else 'ies'} found." \
                      if corrupt else ""
        self._row_cap_label.configure(text=corrupt_msg.strip())
        self._set_status(f"{len(page_entries)} entr{'y' if len(page_entries)==1 else 'ies'} shown "
                         f"(page {page + 1}/{total_pages}).", "info")

    def _audit_prev_page(self) -> None:
        if self._audit_page > 0:
            self._audit_page -= 1
            self._render_audit_page()

    def _audit_next_page(self) -> None:
        total_pages = max(1, (len(self._audit_clean_entries) + self._AUDIT_ROW_CAP - 1)
                          // self._AUDIT_ROW_CAP)
        if self._audit_page < total_pages - 1:
            self._audit_page += 1
            self._render_audit_page()

    def _audit_verify(self) -> None:
        at = self._audit_tools
        AuthEngine = at["AuthorizationEngine"]
        ok, reason = AuthEngine.authorize(self._authenticated_user, "verify_audit", "low")
        if not ok:
            messagebox.showerror("Access Denied", reason)
            return

        corrupt_count = 0
        try:
            last_valid_hash, corrupt_count = at["scan_audit_chain"]()
            at["check_chain"]()
        except at["AuditLogError"] as exc:
            self._set_status("Chain integrity FAIL.", "error")
            msg = str(exc)
            if corrupt_count:
                msg += f"\n{corrupt_count} corrupt entr{'y' if corrupt_count==1 else 'ies'} detected."
            messagebox.showerror("Integrity Check Failed", msg)
            return

        self._set_status("Chain integrity OK.", "ok")
        messagebox.showinfo("Integrity Check", f"Audit chain intact.\nLast valid hash: {last_valid_hash[:16]}…")

    def _audit_export(self) -> None:
        at = self._audit_tools
        AuthEngine = at["AuthorizationEngine"]
        ok, reason = AuthEngine.authorize(self._authenticated_user, "export_logs", "low")
        if not ok:
            messagebox.showerror("Access Denied", reason)
            return

        SAFE_AUDIT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        try:
            result = at["export_logs"](str(SAFE_AUDIT_OUTPUT_DIR))
        except at["AuditLogError"] as exc:
            self._set_status("Export failed.", "error")
            messagebox.showerror("Export Failed", str(exc))
            return

        sidecar = str(Path(result).with_suffix(".json.sha256"))
        self._set_status(f"Exported → {Path(result).name}", "ok")
        messagebox.showinfo("Export Complete",
                            f"Log exported to:\n{result}\n\nIntegrity sidecar:\n{sidecar}")

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    def _set_status(self, text: str, level: str = "info") -> None:
        if not hasattr(self, "_status_icon"):
            return
        colour_map = {
            "info":  _FG_DIM,
            "ok":    "#4ade80",   # readable bright green on dark bg
            "warn":  "#fbbf24",   # readable amber on dark bg
            "error": "#f87171",   # readable soft red on dark bg
        }
        colour = colour_map.get(level, _FG_DIM)
        self._status_icon.configure(fg=colour)
        self._status_var.set(text)
        self.update_idletasks()

    # ------------------------------------------------------------------
    # Operation handlers
    # ------------------------------------------------------------------

    def _do_encrypt(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select file to encrypt",
            initialdir=str(SAFE_ENCRYPT_INPUT_DIR),
            filetypes=[("All files", "*.*")],
        )
        if not file_path:
            return

        file_path = _resolve_picker_path(file_path)

        if not _is_inside_safe_root(Path(file_path).resolve()):
            messagebox.showerror("Invalid File", "File must be inside the safe workspace.")
            return

        if Path(file_path).suffix.lower() == ".enc":
            messagebox.showerror(
                "Already encrypted",
                f"This file is already encrypted:\n{file_path}\n\n"
                "Choose the original plaintext file instead.",
            )
            return

        dialog = _MethodDialog(self, "Choose encryption method")
        method = dialog.result
        if not method:
            return

        # Output is routed automatically to workspace/output/encrypted/<classification>/
        self._set_status(f"Encrypting with {method.upper()}…")
        _enc_kwargs = dict(
            output_path=None, method=method, provider=None,
            user=self._authenticated_user, context={},
        )
        try:
            _enc_kwargs["provider"] = self._engines["LocalPemKeyProvider"]()
            enc = self._engines["stream_encrypt_file"](file_path, **_enc_kwargs)
            self._set_status(f"Encrypted → {Path(enc).name}", "ok")
            messagebox.showinfo("Encrypted", f"Output file:\n{enc}")
        except self._engines["FileCryptoOverwriteError"]:
            if messagebox.askyesno("File Exists", "An encrypted output already exists.\nOverwrite it?"):
                try:
                    _enc_kwargs["provider"] = self._engines["LocalPemKeyProvider"]()
                    _enc_kwargs["overwrite"] = True
                    enc = self._engines["stream_encrypt_file"](file_path, **_enc_kwargs)
                    self._set_status(f"Encrypted → {Path(enc).name}", "ok")
                    messagebox.showinfo("Encrypted", f"Output file:\n{enc}")
                except (self._engines["FileCryptoError"], self._engines["KeyProviderError"],
                        self._engines["KeyRegistryError"], RuntimeError):
                    self._set_status("Encryption failed.", "error")
                    messagebox.showerror("Encryption failed", "Encryption operation failed.")
                except Exception as exc:
                    traceback.print_exc()
                    self._set_status("Encryption failed.", "error")
                    messagebox.showerror("Unexpected Error", f"{type(exc).__name__}: {exc}")
            else:
                self._set_status("Encryption cancelled.", "warn")
        except (self._engines["FileCryptoError"], self._engines["KeyProviderError"],
                self._engines["KeyRegistryError"], RuntimeError):
            self._set_status("Encryption failed.", "error")
            messagebox.showerror("Encryption failed", "Encryption operation failed.")
        except Exception as exc:
            traceback.print_exc()
            self._set_status("Encryption failed.", "error")
            messagebox.showerror("Unexpected Error", f"{type(exc).__name__}: {exc}")

    def _do_decrypt(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select encrypted file (.enc)",
            initialdir=str(SAFE_ENCRYPTED_OUTPUT_DIR / "high"),
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
        )
        if not file_path:
            return

        file_path = _resolve_picker_path(file_path)

        if not _is_inside_safe_root(Path(file_path).resolve()):
            messagebox.showerror("Invalid File", "File must be inside the safe workspace.")
            return

        if Path(file_path).suffix.lower() != ".enc":
            messagebox.showerror("Invalid File", "Only .enc files are allowed for decryption.")
            return

        # Output is routed automatically to workspace/output/decrypted/<classification>/
        self._set_status("Decrypting…")
        _dec_kwargs = dict(output_path=None, overwrite=False, provider=None,
                           user=self._authenticated_user)
        try:
            _dec_kwargs["provider"] = self._engines["LocalPemKeyProvider"]()
            dec = self._engines["stream_decrypt_file"](file_path, **_dec_kwargs)
            self._set_status(f"Decrypted → {Path(dec).name}", "ok")
            messagebox.showinfo("Decrypted", f"Output file:\n{dec}")
        except self._engines["FileCryptoOverwriteError"]:
            if messagebox.askyesno("File Exists", "A decrypted output already exists.\nOverwrite it?"):
                try:
                    _dec_kwargs["provider"] = self._engines["LocalPemKeyProvider"]()
                    _dec_kwargs["overwrite"] = True
                    dec = self._engines["stream_decrypt_file"](file_path, **_dec_kwargs)
                    self._set_status(f"Decrypted → {Path(dec).name}", "ok")
                    messagebox.showinfo("Decrypted", f"Output file:\n{dec}")
                except (self._engines["FileCryptoError"], self._engines["KeyProviderError"],
                        self._engines["KeyRegistryError"], RuntimeError):
                    self._set_status("Decryption failed.", "error")
                    messagebox.showerror("Decryption failed", "Decryption operation failed.")
                except Exception as exc:
                    traceback.print_exc()
                    self._set_status("Decryption failed.", "error")
                    messagebox.showerror("Unexpected Error", f"{type(exc).__name__}: {exc}")
            else:
                self._set_status("Decryption cancelled.", "warn")
        except (self._engines["FileCryptoError"], self._engines["KeyProviderError"],
                self._engines["KeyRegistryError"], RuntimeError):
            self._set_status("Decryption failed.", "error")
            messagebox.showerror("Decryption failed", "Decryption operation failed.")
        except Exception as exc:
            traceback.print_exc()
            self._set_status("Decryption failed.", "error")
            messagebox.showerror("Unexpected Error", f"{type(exc).__name__}: {exc}")

    def _do_sign(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select file to sign",
            initialdir=str(SAFE_ENCRYPT_INPUT_DIR),
            filetypes=[("All files", "*.*")],
        )
        if not file_path:
            return

        file_path = _resolve_picker_path(file_path)

        if not _is_inside_safe_root(Path(file_path).resolve()):
            messagebox.showerror("Invalid File", "File must be inside the safe workspace.")
            return

        dialog = _MethodDialog(self, "Choose signature algorithm")
        method = dialog.result
        if not method:
            return

        self._set_status(f"Signing with {method.upper()}…")
        key_id = "rsa-sign" if method == "rsa" else "ecc-sign"
        try:
            provider = self._engines["LocalPemKeyProvider"]()
            if method == "rsa":
                private_key = provider.get_rsa_signing_private_key()
            else:
                private_key = provider.get_ecc_signing_private_key()

            with Path(file_path).open("rb") as in_f:
                signature = self._engines["sign_stream"](method, private_key, in_f)
            sig_path = file_path + ".sig"
            if not _is_inside_safe_root(Path(sig_path).resolve()):
                messagebox.showerror("Invalid Path", "Output must be inside the safe workspace.")
                return
            Path(sig_path).write_bytes(
                self._engines["encode_sig_file"](method, signature, key_id=key_id)
            )
            self._set_status(f"Signature → {Path(sig_path).name}", "ok")
            messagebox.showinfo("Signed", f"Signature file:\n{sig_path}")
        except (
            self._engines["KeyProviderError"],
            self._engines["RSAEngineError"],
            self._engines["ECCEngineError"],
            self._engines["SignatureError"],
        ):
            self._set_status("Signing failed.", "error")
            messagebox.showerror("Signing failed", "Signing operation failed.")

    def _do_verify(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select file to verify",
            initialdir=str(SAFE_ENCRYPT_INPUT_DIR),
            filetypes=[("All files", "*.*")],
        )
        if not file_path:
            return

        file_path = _resolve_picker_path(file_path)

        if not _is_inside_safe_root(Path(file_path).resolve()):
            messagebox.showerror("Invalid File", "File must be inside the safe workspace.")
            return

        sig_path = filedialog.askopenfilename(
            title="Select signature file (.sig)",
            initialdir=str(SAFE_SIG_DIR),
            filetypes=[("Signature files", "*.sig"), ("All files", "*.*")],
        )
        if not sig_path:
            return

        sig_path = _resolve_picker_path(sig_path)

        if not _is_inside_safe_root(Path(sig_path).resolve()):
            messagebox.showerror("Invalid File", "Signature file must be inside the safe workspace.")
            return

        # Read algorithm and key_id from the .sig file header — no method dialog needed.
        try:
            method, signature, sig_key_id = self._engines["decode_sig_file_full"](
                Path(sig_path).read_bytes()
            )
        except self._engines["SignatureError"]:
            self._set_status("Invalid signature file.", "error")
            messagebox.showerror("Signature file error", "Could not read signature file.")
            return

        resolved_key_id = sig_key_id or method + "-sign"
        self._set_status(f"Verifying {method.upper()} signature…")
        try:
            provider = self._engines["LocalPemKeyProvider"]()
            if sig_key_id is not None:
                public_key = provider.get_signing_public_key(sig_key_id)
            elif method == "rsa":
                public_key = provider.get_rsa_signing_public_key()
            else:
                public_key = provider.get_ecc_signing_public_key()

            with Path(file_path).open("rb") as in_f:
                self._engines["verify_stream"](method, public_key, signature, in_f)
            self._set_status(f"Signature VALID — {Path(file_path).name}", "ok")
            messagebox.showinfo("Verified", f"Signature is VALID for:\n{file_path}")
        except self._engines["SignatureError"]:
            self._set_status("Signature INVALID.", "error")
            messagebox.showerror("Verification failed", "Signature is INVALID.")
        except self._engines["KeyProviderError"]:
            self._set_status("Key load failed.", "error")
            messagebox.showerror("Key error", "Failed to load signing key.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _startup_validate() -> None:
    """Validate system prerequisites before the GUI window opens.

    Checks (in order):
      1. Audit log hash chain is intact or absent
      2. Key registry loads without error
      3. Key provider initializes without error
      4. Required passphrase environment variables are present and non-empty

    Shows an error dialog and exits with code 1 on any failure.
    """
    import os
    from .audit_logger import AuditLogError, check_chain
    from .key_registry import KeyRegistry
    from .key_provider import LocalPemKeyProvider

    error_msg: str | None = None

    try:
        check_chain()
    except (AuditLogError, OSError):
        error_msg = "Audit log is corrupt or unreadable."

    if error_msg is None:
        try:
            r = KeyRegistry()
            r.load()
        except Exception:
            error_msg = "Key registry is unavailable or corrupt."

    if error_msg is None:
        try:
            LocalPemKeyProvider()
        except Exception:
            error_msg = "Key provider failed to initialize."

    if error_msg is None:
        required_env = [
            "RSA_KEY_PASSPHRASE", "ECC_KEY_PASSPHRASE",
            "RSA_SIGN_KEY_PASSPHRASE", "ECC_SIGN_KEY_PASSPHRASE",
            "USERS_HMAC_KEY",
        ]
        missing = [k for k in required_env if not os.environ.get(k, "").strip()]
        if missing:
            error_msg = "Required configuration is missing."

    if error_msg is not None:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Startup Error",
            f"Cannot start: {error_msg}\n\nResolve the issue and restart.",
        )
        root.destroy()
        sys.exit(1)


def main() -> None:
    if sys.platform == "darwin":
        # Suppress macOS Tk deprecation noise
        import os
        os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

    _startup_validate()

    # Login screen — must authenticate before accessing the main application.
    login = _LoginDialog()
    login.mainloop()

    if login.authenticated_user is None:
        sys.exit(0)  # User closed the login dialog without authenticating.

    app = CryptoLauncher(login.authenticated_user)
    app.mainloop()


if __name__ == "__main__":
    main()
