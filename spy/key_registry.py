"""
key_registry.py — Encryption key lifecycle registry.

Maintains a JSON registry of encryption keypair metadata in KEY_DIR/key_registry.json.
Tracks key_id, key_type, status, algorithm, and file references for all encryption keys.

Status lifecycle:
  active       → used for encryption and decryption
  decrypt-only → decryption only; new files must not be encrypted with this key
  retired      → decryption still allowed (with audit warning); no new use
  revoked      → decryption blocked; key is permanently disabled

The registry is the authoritative source for which key to use for encryption and
which private key file to load for decryption. It does not store key material.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

def _get_key_dir() -> Path:
    d = os.environ.get("CRYPTO_KEY_DIR", "")
    if not d:
        raise RuntimeError(
            "CRYPTO_KEY_DIR environment variable is not set. "
            "Set it to the path of your key directory before running "
            "(e.g. CRYPTO_KEY_DIR=runtime/keys)."
        )
    return Path(d)


def get_key_dir() -> Path:
    """Public accessor — returns the resolved key directory path."""
    return _get_key_dir()


VALID_KEY_TYPES = frozenset({"rsa_enc", "ecc_enc", "rsa_sign", "ecc_sign"})
VALID_STATUSES = frozenset({"active", "decrypt-only", "retired", "revoked"})

# Map key_type to the algorithm label stored in the registry.
_ALGORITHM_LABELS: dict[str, str] = {
    "rsa_enc": "RSA-3072-OAEP-SHA256",
    "ecc_enc": "ECC-P256-ECDH-AES-GCM",
    "rsa_sign": "RSA-3072-PSS-SHA256",
    "ecc_sign": "ECC-P256-ECDSA-SHA256",
}
VALID_ALGORITHMS: frozenset[str] = frozenset(_ALGORITHM_LABELS.values())


class KeyRegistryError(Exception):
    pass


@dataclass
class KeyEntry:
    """One registry record describing a managed keypair and its lifecycle state.

    The registry tracks metadata only — never private-key bytes. ``key_reference``
    names the private-key PEM relative to the key directory; ``status`` drives the
    rotation lifecycle (only an ``active`` key is chosen for new encryption, while
    ``decrypt-only``/``retired`` keys remain usable for unwrapping existing data,
    and ``revoked`` keys are refused).
    """

    key_id: str
    key_type: str           # "rsa_enc" | "ecc_enc"
    status: str             # "active" | "decrypt-only" | "retired" | "revoked"
    created_at: str         # ISO-8601 UTC
    activate_at: str        # ISO-8601 UTC
    retire_at: str | None   # ISO-8601 UTC, or None if not scheduled
    algorithm: str          # e.g. "RSA-3072-OAEP-SHA256"
    key_reference: str      # filename relative to KEY_DIR (private key PEM)


class KeyRegistry:
    """Load, query, and persist the encryption key registry.

    Usage::

        registry = KeyRegistry()
        registry.load()                          # load from disk (creates empty if absent)
        key_id = registry.get_active_key_id("rsa_enc")
        entry  = registry.get_entry(key_id)
        path   = registry.get_private_key_path(key_id)
    """

    def __init__(self) -> None:
        self._entries: list[KeyEntry] = []

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Load the registry from disk. Creates an empty in-memory registry if absent."""
        registry_file = _get_key_dir() / "key_registry.json"
        if not registry_file.exists():
            self._entries = []
            return
        try:
            raw = json.loads(registry_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KeyRegistryError("Key registry unavailable") from exc

        if not isinstance(raw, dict) or "keys" not in raw:
            raise KeyRegistryError("key_registry.json has unexpected format")

        entries = []
        for item in raw["keys"]:
            try:
                entries.append(KeyEntry(
                    key_id=item["key_id"],
                    key_type=item["key_type"],
                    status=item["status"],
                    created_at=item["created_at"],
                    activate_at=item["activate_at"],
                    retire_at=item.get("retire_at"),
                    algorithm=item["algorithm"],
                    key_reference=item["key_reference"],
                ))
            except KeyError as exc:
                raise KeyRegistryError("Malformed key entry") from exc

        # Validate integrity of loaded entries — fail closed on any inconsistency.
        seen_ids: set[str] = set()
        active_by_type: dict[str, str] = {}
        for entry in entries:
            if entry.key_type not in VALID_KEY_TYPES:
                raise KeyRegistryError(
                    f"Registry contains entry with invalid key_type: {entry.key_type!r}"
                )
            if entry.status not in VALID_STATUSES:
                raise KeyRegistryError(
                    f"Registry contains entry with invalid status: {entry.status!r}"
                )
            if entry.key_id in seen_ids:
                raise KeyRegistryError(
                    f"Registry contains duplicate key_id: {entry.key_id!r}"
                )
            seen_ids.add(entry.key_id)
            if entry.retire_at is not None:
                try:
                    datetime.fromisoformat(entry.retire_at)
                except ValueError as exc:
                    raise KeyRegistryError("Invalid retire_at format") from exc
            if entry.status == "active":
                if entry.key_type in active_by_type:
                    raise KeyRegistryError(
                        f"Registry inconsistency: duplicate active {entry.key_type!r} key — "
                        f"{active_by_type[entry.key_type]!r} and {entry.key_id!r} are both active. "
                        "Registry must be repaired before use."
                    )
                active_by_type[entry.key_type] = entry.key_id

        self._entries = entries

    def save(self) -> None:
        """Persist the registry to disk using an atomic temp-write + fsync + rename.

        Writing to a temp file in the same directory and then calling os.replace
        ensures that a concurrent read always sees either the old complete file or
        the new complete file — never a partial write.
        """
        key_dir = _get_key_dir()
        registry_file = key_dir / "key_registry.json"
        try:
            key_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise KeyRegistryError("Key directory unavailable") from exc
        data = {
            "version": 1,
            "keys": [asdict(e) for e in self._entries],
        }
        serialized = json.dumps(data, indent=2, ensure_ascii=True)
        tmp_fd, tmp_path_str = tempfile.mkstemp(dir=key_dir, suffix=".tmp")
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                f.write(serialized)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path_str, str(registry_file))
        except OSError as exc:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise KeyRegistryError("Key registry write failed") from exc

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_active_key_id(self, key_type: str) -> str:
        """Return the key_id of the single active key for *key_type*.

        Fails closed if no active key exists or if more than one active key of
        the same type is found (registry inconsistency).
        """
        if key_type not in VALID_KEY_TYPES:
            raise KeyRegistryError(f"Unknown key_type: {key_type!r}")
        active = [e for e in self._entries if e.key_type == key_type and e.status == "active"]
        if len(active) > 1:
            raise KeyRegistryError(
                f"Registry inconsistency: multiple active {key_type!r} keys found. "
                "Registry must be repaired before encryption can continue."
            )
        if not active:
            raise KeyRegistryError(
                f"No active {key_type} key in registry. "
                "Run 'rotate-enc-keys' or 'rotate-keys' to generate a new key."
            )
        return active[0].key_id

    def get_entry(self, key_id: str) -> KeyEntry:
        """Return the KeyEntry for *key_id*. Raises KeyRegistryError if not found."""
        for entry in self._entries:
            if entry.key_id == key_id:
                return entry
        raise KeyRegistryError(f"Key not found in registry: {key_id!r}")

    def has_entry(self, key_id: str) -> bool:
        """Return True if *key_id* is present in the registry."""
        return any(e.key_id == key_id for e in self._entries)

    def list_by_type(self, key_type: str) -> list[KeyEntry]:
        """Return all entries for *key_type*, ordered by created_at ascending."""
        return sorted(
            [e for e in self._entries if e.key_type == key_type],
            key=lambda e: e.created_at,
        )

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def register(self, entry: KeyEntry) -> None:
        """Add *entry* to the registry.

        Raises KeyRegistryError if:
          - key_type or status is not valid
          - key_id is already registered
          - entry is active and an active key for the same type already exists
            (rotation must demote the existing active key first)
        """
        if entry.key_type not in VALID_KEY_TYPES:
            raise KeyRegistryError(f"Invalid key_type: {entry.key_type!r}")
        if entry.status not in VALID_STATUSES:
            raise KeyRegistryError(f"Invalid status: {entry.status!r}")
        if not entry.key_id or not all(c.isalnum() or c in "-_." for c in entry.key_id):
            raise KeyRegistryError(f"Invalid key_id format: {entry.key_id!r}")
        if entry.algorithm not in VALID_ALGORITHMS:
            raise KeyRegistryError(f"Algorithm not approved: {entry.algorithm!r}")
        if not entry.key_reference or not entry.key_reference.strip():
            raise KeyRegistryError("key_reference must be non-empty")
        if self.has_entry(entry.key_id):
            raise KeyRegistryError(f"key_id already registered: {entry.key_id!r}")
        if entry.status == "active":
            existing_active = [
                e for e in self._entries
                if e.key_type == entry.key_type and e.status == "active"
            ]
            if existing_active:
                raise KeyRegistryError(
                    f"Cannot register {entry.key_type!r} key {entry.key_id!r} as active: "
                    f"key {existing_active[0].key_id!r} is already active. "
                    "Demote the existing active key to 'decrypt-only' before registering a new active key."
                )
        self._entries.append(entry)

    def set_status(self, key_id: str, status: str) -> None:
        """Update the status of an existing key entry."""
        if status not in VALID_STATUSES:
            raise KeyRegistryError(f"Invalid status: {status!r}")
        for entry in self._entries:
            if entry.key_id == key_id:
                # dataclass is not frozen — replace in-place
                idx = self._entries.index(entry)
                self._entries[idx] = KeyEntry(
                    key_id=entry.key_id,
                    key_type=entry.key_type,
                    status=status,
                    created_at=entry.created_at,
                    activate_at=entry.activate_at,
                    retire_at=entry.retire_at,
                    algorithm=entry.algorithm,
                    key_reference=entry.key_reference,
                )
                return
        raise KeyRegistryError(f"Key not found in registry: {key_id!r}")

    # ------------------------------------------------------------------
    # Key file paths
    # ------------------------------------------------------------------

    def get_key_reference(self, key_id: str) -> str:
        """Return the key_reference string for *key_id* (private key filename, relative to KEY_DIR).

        The caller is responsible for constructing and validating the full path.
        KeyRegistry does not build filesystem paths.
        """
        return self.get_entry(key_id).key_reference

    def get_public_key_reference(self, key_id: str) -> str:
        """Return the public key filename for *key_id* (relative to KEY_DIR).

        Derived by replacing ``_private`` with ``_public`` in the key_reference
        (e.g. ``rsa_enc_..._private.pem`` → ``rsa_enc_..._public.pem``).
        The caller is responsible for constructing and validating the full path.
        """
        return self.get_entry(key_id).key_reference.replace("_private", "_public")

    def get_private_key_path(self, key_id: str) -> "Path":
        """Return full filesystem path to private key PEM for key_id (metadata only, no key loading)."""
        key_dir = _get_key_dir()
        ref = self.get_key_reference(key_id)
        path = key_dir / ref
        if not path.resolve().is_relative_to(key_dir.resolve()):
            raise KeyRegistryError(f"Key path escapes key directory: {ref!r}")
        return path

    def get_public_key_path(self, key_id: str) -> "Path":
        """Return full filesystem path to public key PEM for key_id (metadata only, no key loading)."""
        key_dir = _get_key_dir()
        ref = self.get_public_key_reference(key_id)
        path = key_dir / ref
        if not path.resolve().is_relative_to(key_dir.resolve()):
            raise KeyRegistryError(f"Key path escapes key directory: {ref!r}")
        return path


# ------------------------------------------------------------------
# Convenience helpers used by engine modules
# ------------------------------------------------------------------

def now_iso() -> str:
    """Return current UTC time as ISO-8601 string (second precision)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_key_id(key_type: str) -> str:
    """Derive a collision-resistant key_id from key_type, timestamp, and random suffix."""
    prefix = "rsa-enc" if key_type == "rsa_enc" else "ecc-enc"
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{prefix}-{ts}-{secrets.token_hex(4)}"


def algorithm_for_type(key_type: str) -> str:
    """Return the canonical algorithm label for a key type (e.g. 'rsa_enc').

    Falls back to ``"unknown"`` for an unrecognized type rather than raising, so
    it is safe to use when annotating registry entries for display or logging.
    """
    return _ALGORITHM_LABELS.get(key_type, "unknown")


def make_sign_key_id(key_type: str, version: int) -> str:
    """Return a deterministic signing key_id for *key_type* at *version*.

    Examples: make_sign_key_id("rsa_sign", 1) → "rsa-sign-v1"
    """
    prefix = "rsa-sign" if key_type == "rsa_sign" else "ecc-sign"
    return f"{prefix}-v{version}"


def next_sign_version(registry: "KeyRegistry", key_type: str) -> int:
    """Return the next version number for *key_type* signing keys.

    Scans all existing entries for key_type, extracts the version suffix from
    IDs formatted as ``{prefix}-v{n}``, and returns max(versions) + 1.
    Returns 1 if no entries of that type exist yet.
    """
    versions = []
    for entry in registry.list_by_type(key_type):
        try:
            version_str = entry.key_id.split("-v")[-1]
            versions.append(int(version_str))
        except (ValueError, IndexError):
            pass
    return max(versions) + 1 if versions else 1
