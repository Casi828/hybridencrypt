"""
key_provider.py — KeyProvider abstraction for all key material access.

All cryptographic engines and file-level operations must resolve key material
through a KeyProvider. No engine may open PEM files directly.

Responsibilities:
  - Define the KeyProvider interface (ABC)
  - Implement LocalPemKeyProvider: PEM-file-backed provider with registry lifecycle
    enforcement

Lifecycle rules enforced by LocalPemKeyProvider:
  active       → encrypt (public key) and decrypt (private key) allowed
  decrypt-only → private key access allowed; public key access denied
  retired      → private key access allowed (audit warning should be logged by caller);
                 public key access denied
  revoked      → all access denied; fail closed

No key material is cached. Every call reads from disk.
"""

from __future__ import annotations

import hashlib
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .key_registry import get_key_dir as _get_default_key_dir, KeyRegistry, KeyRegistryError


class KeyProviderError(Exception):
    pass


class KeyProvider(ABC):
    """Abstract interface for all key material resolution.

    Engines must accept a KeyProvider instance rather than loading PEM files
    directly. This enables future KMS/HSM backends without refactoring engines.
    """

    @abstractmethod
    def get_active_rsa_key_id(self) -> str:
        """Return the key_id of the currently active RSA encryption key."""
        raise NotImplementedError

    @abstractmethod
    def get_active_ecc_key_id(self) -> str:
        """Return the key_id of the currently active ECC encryption key."""
        raise NotImplementedError

    @abstractmethod
    def get_rsa_public_key(self, key_id: str):
        """Return the RSA public key for *key_id* (encrypt path).

        Raises KeyProviderError if the key is not active.
        """
        raise NotImplementedError

    @abstractmethod
    def get_rsa_private_key(self, key_id: str):
        """Return the RSA private key for *key_id* (decrypt path).

        Raises KeyProviderError if the key is revoked.
        """
        raise NotImplementedError

    @abstractmethod
    def get_ecc_public_key(self, key_id: str):
        """Return the ECC public key for *key_id* (encrypt path).

        Raises KeyProviderError if the key is not active.
        """
        raise NotImplementedError

    @abstractmethod
    def get_ecc_private_key(self, key_id: str):
        """Return the ECC private key for *key_id* (decrypt path).

        Raises KeyProviderError if the key is revoked.
        """
        raise NotImplementedError

    @abstractmethod
    def get_active_rsa_signing_key_id(self) -> str:
        """Return the key_id of the currently active RSA signing key."""
        raise NotImplementedError

    @abstractmethod
    def get_active_ecc_signing_key_id(self) -> str:
        """Return the key_id of the currently active ECC signing key."""
        raise NotImplementedError

    @abstractmethod
    def get_rsa_signing_private_key(self):
        """Return the active RSA signing private key."""
        raise NotImplementedError

    @abstractmethod
    def get_rsa_signing_public_key(self):
        """Return the active RSA signing public key (fingerprint-verified)."""
        raise NotImplementedError

    @abstractmethod
    def get_ecc_signing_private_key(self):
        """Return the active ECC signing private key."""
        raise NotImplementedError

    @abstractmethod
    def get_ecc_signing_public_key(self):
        """Return the active ECC signing public key (fingerprint-verified)."""
        raise NotImplementedError

    @abstractmethod
    def get_signing_public_key(self, key_id: str):
        """Return the signing public key for *key_id* (fingerprint-verified).

        Used by verify_with_key_id to resolve the correct public key without
        the caller needing to know the signing algorithm. key_id prefix
        determines which key is returned: 'rsa' → RSA signing key,
        'ecc' → ECC signing key.

        Raises KeyProviderError if key_id cannot be resolved.
        """
        raise NotImplementedError

    @abstractmethod
    def get_key_entry(self, key_id: str):
        """Return the registry entry for *key_id*.

        Raises KeyProviderError if the key_id is not found.
        """
        raise NotImplementedError


# ---------------------------------------------------------------------------
# LocalPemKeyProvider — filesystem-backed implementation
# ---------------------------------------------------------------------------

class LocalPemKeyProvider(KeyProvider):
    """PEM-file-backed KeyProvider that enforces key_registry lifecycle rules.

    Args:
        key_dir: Directory containing PEM key files. Defaults to the value of
                 CRYPTO_KEY_DIR or the project-local ``keys/`` directory.
        registry: A loaded KeyRegistry instance. The caller is responsible for
                  loading it; the provider does not modify registry state.
    """

    def __init__(
        self,
        key_dir: Path | None = None,
        registry: KeyRegistry | None = None,
    ) -> None:
        self._key_dir = key_dir if key_dir is not None else _get_default_key_dir()
        if registry is None:
            r = KeyRegistry()
            r.load()
            self._registry = r
        else:
            self._registry = registry

    # ------------------------------------------------------------------
    # Passphrase helpers — read once per call, never cached
    # ------------------------------------------------------------------

    def _rsa_passphrase(self) -> bytearray | None:
        p = os.environ.get("RSA_KEY_PASSPHRASE", "").strip()
        return bytearray(p.encode("utf-8")) if p else None

    def _ecc_passphrase(self) -> bytearray | None:
        p = os.environ.get("ECC_KEY_PASSPHRASE", "").strip()
        return bytearray(p.encode("utf-8")) if p else None

    def _rsa_sign_passphrase(self) -> bytearray | None:
        p = os.environ.get("RSA_SIGN_KEY_PASSPHRASE", "").strip()
        return bytearray(p.encode("utf-8")) if p else None

    def _ecc_sign_passphrase(self) -> bytearray | None:
        p = os.environ.get("ECC_SIGN_KEY_PASSPHRASE", "").strip()
        return bytearray(p.encode("utf-8")) if p else None

    # ------------------------------------------------------------------
    # Path resolution — single authority for key file paths
    # ------------------------------------------------------------------

    def _resolve_key_path(self, reference: str) -> Path:
        """Resolve a key_reference string to an absolute path within self._key_dir.

        Raises KeyProviderError if the resolved path escapes self._key_dir
        (path traversal guard). This is the single location in the system where
        a key_reference string is converted to a filesystem path.
        """
        path = (self._key_dir / reference).resolve()
        if not path.is_relative_to(self._key_dir.resolve()):
            raise KeyProviderError("Key path boundary violation")
        return path

    # ------------------------------------------------------------------
    # Low-level PEM loaders — only this module reads PEM files
    # ------------------------------------------------------------------

    def _load_private_pem(self, path: Path, passphrase: bytes | None):
        if not path.exists():
            raise KeyProviderError("Private key file not found")
        try:
            return serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
        except OSError:
            raise KeyProviderError("Cannot read private key") from None
        except (ValueError, TypeError):
            raise KeyProviderError(
                "Private key is invalid, corrupt, or wrong passphrase"
            ) from None

    def _load_public_pem(self, path: Path):
        if not path.exists():
            raise KeyProviderError("Public key file not found")
        try:
            return serialization.load_pem_public_key(path.read_bytes())
        except OSError:
            raise KeyProviderError("Public key file could not be read")
        except (ValueError, TypeError):
            raise KeyProviderError("Public key is invalid or corrupt")

    # ------------------------------------------------------------------
    # Lifecycle enforcement
    # ------------------------------------------------------------------

    def _check_encrypt_allowed(self, key_id: str) -> None:
        """Raise KeyProviderError unless the key is active (encrypt path)."""
        try:
            entry = self._registry.get_entry(key_id)
        except KeyRegistryError as exc:
            raise KeyProviderError("Encryption key not available.") from exc
        if entry.status != "active":
            raise KeyProviderError(
                "Encryption denied: key is not in an active state."
            )
        if entry.retire_at is not None:
            retire_dt = datetime.strptime(entry.retire_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
            if datetime.now(timezone.utc) >= retire_dt:
                raise KeyProviderError(
                    "Encryption denied: key is no longer valid for use."
                )

    def _check_decrypt_allowed(self, key_id: str) -> None:
        """Raise KeyProviderError unless the key is allowed for decryption."""
        try:
            entry = self._registry.get_entry(key_id)
        except KeyRegistryError as exc:
            raise KeyProviderError("Decryption key not available") from exc
        if entry.status == "revoked":
            raise KeyProviderError(
                "Decryption denied: key is revoked"
            )
        if entry.status not in ("active", "decrypt-only", "retired"):
            raise KeyProviderError(
                "Decryption denied: key is not valid for use"
            )

    # ------------------------------------------------------------------
    # Fingerprint verification for signing keys
    # ------------------------------------------------------------------

    def _verify_encryption_key_fingerprint(self, public_key, fingerprint_file: Path) -> None:
        """Raise KeyProviderError if the encryption public key does not match the stored fingerprint."""
        if not fingerprint_file.exists():
            raise KeyProviderError(
                "Encryption key fingerprint file missing. "
                "Key identity cannot be confirmed."
            )
        try:
            lines = [
                ln.strip()
                for ln in fingerprint_file.read_text(encoding="ascii").splitlines()
                if ln.strip()
            ]
        except OSError as exc:
            raise KeyProviderError(
                "Cannot read encryption key fingerprint file."
            ) from exc
        if not lines:
            raise KeyProviderError(
                "Encryption key fingerprint file is empty."
            )
        stored = lines[-1].split()[-1]
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        computed = hashlib.sha256(der_bytes).hexdigest()
        if computed != stored:
            raise KeyProviderError(
                "Encryption public key fingerprint mismatch. "
                "Key has been replaced or corrupted. Do not proceed."
            )

    def _verify_signing_key_fingerprint(self, public_key, fingerprint_file: Path) -> None:
        """Raise KeyProviderError if the public key does not match the stored fingerprint."""
        if not fingerprint_file.exists():
            raise KeyProviderError(
                "Signing key fingerprint file missing. "
                "Key identity cannot be confirmed."
            )
        try:
            lines = [
                ln.strip()
                for ln in fingerprint_file.read_text(encoding="ascii").splitlines()
                if ln.strip()
            ]
        except OSError as exc:
            raise KeyProviderError(
                "Cannot read fingerprint file."
            ) from exc
        if not lines:
            raise KeyProviderError(
                "Signing key fingerprint file is empty."
            )
        stored = lines[-1].split()[-1]
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        computed = hashlib.sha256(der_bytes).hexdigest()
        if computed != stored:
            raise KeyProviderError(
                "Signing public key fingerprint mismatch. "
                "Key has been replaced or corrupted. Do not proceed."
            )

    # ------------------------------------------------------------------
    # KeyProvider interface — RSA encryption keys
    # ------------------------------------------------------------------

    def get_active_rsa_key_id(self) -> str:
        try:
            return self._registry.get_active_key_id("rsa_enc")
        except KeyRegistryError as exc:
            raise KeyProviderError("Invalid key state") from exc

    def get_rsa_public_key(self, key_id: str):
        self._check_encrypt_allowed(key_id)
        pub_ref = self._registry.get_public_key_reference(key_id)
        path = self._resolve_key_path(pub_ref)
        key = self._load_public_pem(path)
        fp_path = self._resolve_key_path(str(Path(pub_ref).with_suffix(".fp")))
        self._verify_encryption_key_fingerprint(key, fp_path)
        return key

    def get_rsa_private_key(self, key_id: str):
        self._check_decrypt_allowed(key_id)
        path = self._resolve_key_path(self._registry.get_key_reference(key_id))
        passphrase = self._rsa_passphrase()
        try:
            return self._load_private_pem(path, passphrase)
        finally:
            if passphrase is not None:
                passphrase[:] = bytes(len(passphrase))

    # ------------------------------------------------------------------
    # KeyProvider interface — ECC encryption keys
    # ------------------------------------------------------------------

    def get_active_ecc_key_id(self) -> str:
        try:
            return self._registry.get_active_key_id("ecc_enc")
        except KeyRegistryError as exc:
            raise KeyProviderError("Invalid key state") from exc

    def get_ecc_public_key(self, key_id: str):
        self._check_encrypt_allowed(key_id)
        pub_ref = self._registry.get_public_key_reference(key_id)
        path = self._resolve_key_path(pub_ref)
        key = self._load_public_pem(path)
        fp_path = self._resolve_key_path(str(Path(pub_ref).with_suffix(".fp")))
        self._verify_encryption_key_fingerprint(key, fp_path)
        return key

    def get_ecc_private_key(self, key_id: str):
        self._check_decrypt_allowed(key_id)
        path = self._resolve_key_path(self._registry.get_key_reference(key_id))
        passphrase = self._ecc_passphrase()
        try:
            return self._load_private_pem(path, passphrase)
        finally:
            if passphrase is not None:
                passphrase[:] = bytes(len(passphrase))

    # ------------------------------------------------------------------
    # KeyProvider interface — signing key identity
    # ------------------------------------------------------------------

    def get_active_rsa_signing_key_id(self) -> str:
        try:
            return self._registry.get_active_key_id("rsa_sign")
        except KeyRegistryError as exc:
            raise KeyProviderError("No active RSA signing key") from exc

    def get_active_ecc_signing_key_id(self) -> str:
        try:
            return self._registry.get_active_key_id("ecc_sign")
        except KeyRegistryError as exc:
            raise KeyProviderError("No active ECC signing key") from exc

    # ------------------------------------------------------------------
    # Signing key helper — registry-backed public key loader
    # ------------------------------------------------------------------

    def _load_signing_public_key_by_id(self, key_id: str):
        """Load and fingerprint-verify the signing public key for *key_id* from registry."""
        try:
            entry = self._registry.get_entry(key_id)
        except KeyRegistryError:
            raise KeyProviderError("Signing key not available")
        pub_ref = entry.key_reference.replace("_private", "_public")
        fp_ref = pub_ref.replace(".pem", ".fp")
        pub_path = self._resolve_key_path(pub_ref)
        fp_path = self._resolve_key_path(fp_ref)
        key = self._load_public_pem(pub_path)
        self._verify_signing_key_fingerprint(key, fp_path)
        return key

    # ------------------------------------------------------------------
    # KeyProvider interface — RSA signing keys
    # ------------------------------------------------------------------

    def get_rsa_signing_private_key(self):
        key_id = self.get_active_rsa_signing_key_id()
        try:
            entry = self._registry.get_entry(key_id)
        except KeyRegistryError:
            raise KeyProviderError("RSA signing key not available")
        path = self._resolve_key_path(entry.key_reference)
        passphrase = self._rsa_sign_passphrase()
        try:
            return self._load_private_pem(path, passphrase)
        finally:
            if passphrase is not None:
                passphrase[:] = bytes(len(passphrase))

    def get_rsa_signing_public_key(self):
        key_id = self.get_active_rsa_signing_key_id()
        return self._load_signing_public_key_by_id(key_id)

    # ------------------------------------------------------------------
    # KeyProvider interface — ECC signing keys
    # ------------------------------------------------------------------

    def get_ecc_signing_private_key(self):
        key_id = self.get_active_ecc_signing_key_id()
        try:
            entry = self._registry.get_entry(key_id)
        except KeyRegistryError:
            raise KeyProviderError("ECC signing key not available")
        path = self._resolve_key_path(entry.key_reference)
        passphrase = self._ecc_sign_passphrase()
        try:
            return self._load_private_pem(path, passphrase)
        finally:
            if passphrase is not None:
                passphrase[:] = bytes(len(passphrase))

    def get_ecc_signing_public_key(self):
        key_id = self.get_active_ecc_signing_key_id()
        return self._load_signing_public_key_by_id(key_id)

    def get_signing_public_key(self, key_id: str):
        """Return the signing public key for *key_id* via registry lookup.

        Supports legacy IDs ('rsa-sign', 'ecc-sign') and versioned IDs
        ('rsa-sign-v1', 'ecc-sign-v2', etc.). Legacy IDs map to v1 — correct
        because before versioned signing there was exactly one key per type,
        which the migration registered as v1.

        Status rules: active and retired keys are allowed for verification
        (needed for historical artifact checking). Revoked keys are denied.
        """
        if not key_id or not isinstance(key_id, str):
            raise KeyProviderError("key_id must be a non-empty string")
        # Legacy alias map — pre-Phase-3 artifacts embed bare IDs without version suffix.
        _LEGACY_ALIAS: dict[str, str] = {
            "rsa-sign": "rsa-sign-v1",
            "ecc-sign": "ecc-sign-v1",
        }
        resolved_key_id = _LEGACY_ALIAS.get(key_id, key_id)
        try:
            entry = self._registry.get_entry(resolved_key_id)
        except KeyRegistryError:
            raise KeyProviderError("Signing key not available")
        if entry.key_type not in ("rsa_sign", "ecc_sign"):
            raise KeyProviderError("Signing key not available")
        if entry.status == "revoked":
            raise KeyProviderError("Signing key not available")
        if entry.status not in ("active", "retired"):
            raise KeyProviderError("Signing key not available")
        return self._load_signing_public_key_by_id(resolved_key_id)

    def get_key_entry(self, key_id: str):
        try:
            return self._registry.get_entry(key_id)
        except KeyRegistryError:
            raise KeyProviderError(f"Key not found: {key_id}") from None
