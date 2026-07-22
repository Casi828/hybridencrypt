"""
rsa_engine.py — RSA-3072 key generation, persistence, and AES key wrap/unwrap.

Responsibilities:
  - Generate and persist RSA-3072 keypairs (PEM/PKCS8 format)
  - Wrap (encrypt) an AES key with an RSA public key using OAEP/SHA-256
  - Unwrap (decrypt) an AES key with an RSA private key
  - No symmetric encryption logic lives here

Key security:
  - Private keys are encrypted at rest using the passphrase from the
    RSA_KEY_PASSPHRASE environment variable. Missing or empty passphrase
    raises RSAEngineError — no fallback to unencrypted storage.
  - Minimum key size enforced: RSA_KEY_SIZE >= 3072 bits.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_KEY_SIZE = 3072
RSA_MIN_KEY_SIZE = 3072


def _get_key_dir() -> Path:
    d = os.environ.get("CRYPTO_KEY_DIR", "")
    if not d:
        raise RuntimeError(
            "CRYPTO_KEY_DIR environment variable is not set. "
            "Set it to the path of your key directory before running "
            "(e.g. CRYPTO_KEY_DIR=runtime/keys)."
        )
    return Path(d)

_OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


class RSAEngineError(Exception):
    pass


def _get_passphrase() -> bytes | None:
    """Return the encryption private key passphrase from the environment, or None if unset."""
    passphrase = os.environ.get("RSA_KEY_PASSPHRASE", "").strip()
    return passphrase.encode("utf-8") if passphrase else None


def _get_sign_passphrase() -> bytes | None:
    """Return the signing private key passphrase from the environment, or None if unset."""
    passphrase = os.environ.get("RSA_SIGN_KEY_PASSPHRASE", "").strip()
    return passphrase.encode("utf-8") if passphrase else None


def _encryption_algorithm(passphrase: bytes | None):
    if not passphrase:
        raise RSAEngineError(
            "Private key passphrase is required. "
            "Set RSA_KEY_PASSPHRASE or RSA_SIGN_KEY_PASSPHRASE in the environment."
        )
    return serialization.BestAvailableEncryption(passphrase)


def _ensure_key_directory() -> None:
    _get_key_dir().mkdir(parents=True, exist_ok=True)


def generate_rsa_keypair():
    """Generate a new RSA-3072 keypair. Returns (private_key, public_key)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    return private_key, private_key.public_key()


def _validate_key_size(private_key) -> None:
    """Raise RSAEngineError if the key is smaller than the minimum required size."""
    key_size = private_key.key_size
    if key_size < RSA_MIN_KEY_SIZE:
        raise RSAEngineError(
            f"RSA key size {key_size} bits is below minimum {RSA_MIN_KEY_SIZE} bits"
        )


def _public_key_fingerprint(public_key) -> str:
    """Return SHA-256 hex fingerprint of the DER-encoded public key (SubjectPublicKeyInfo)."""
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der_bytes).hexdigest()


def key_fingerprint(public_key) -> str:
    """Return the SHA-256 hex fingerprint of an RSA public key (SubjectPublicKeyInfo DER)."""
    return _public_key_fingerprint(public_key)


def _write_fingerprint(public_key, fingerprint_file: Path) -> None:
    """Append a versioned fingerprint entry to the fingerprint file.

    Format: ``v{N} {iso8601_utc} {sha256_hex}``

    Existing entries are preserved so the full rotation history is retained.
    """
    computed = _public_key_fingerprint(public_key)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Determine next version number from existing entries.
    next_version = 1
    if fingerprint_file.exists():
        lines = [l.strip() for l in fingerprint_file.read_text(encoding="ascii").splitlines() if l.strip()]
        # Support legacy bare-hex files (single line, no prefix).
        if lines and not lines[-1].startswith("v"):
            next_version = 2
        elif lines:
            try:
                next_version = int(lines[-1].split()[0][1:]) + 1
            except (IndexError, ValueError):
                next_version = len(lines) + 1

    entry = f"v{next_version} {ts} {computed}\n"
    with fingerprint_file.open("a", encoding="ascii") as fh:
        fh.write(entry)


def _verify_fingerprint(public_key, fingerprint_file: Path) -> None:
    """Raise RSAEngineError if the loaded public key does not match the stored fingerprint.

    Reads the *last* entry in the fingerprint file (current active key).
    Supports both legacy bare-hex format and versioned ``v{N} {ts} {hex}`` format.
    """
    if not fingerprint_file.exists():
        raise RSAEngineError(
            "RSA signing key fingerprint file missing. "
            "Key identity cannot be confirmed. Re-generate signing keys."
        )
    lines = [l.strip() for l in fingerprint_file.read_text(encoding="ascii").splitlines() if l.strip()]
    if not lines:
        raise RSAEngineError("RSA signing key fingerprint file is empty")
    last = lines[-1]
    # Last field is always the hex — works for both legacy and versioned format.
    stored = last.split()[-1]
    computed = _public_key_fingerprint(public_key)
    if computed != stored:
        raise RSAEngineError(
            "RSA signing public key fingerprint mismatch. "
            "Key has been replaced or corrupted. Do not proceed."
        )


def wrap_key(public_key, aes_key: bytes) -> bytes:
    """Encrypt an AES key with an RSA public key using OAEP/SHA-256.

    Args:
        public_key: RSA public key object.
        aes_key: Raw AES key bytes to protect.

    Returns:
        Ciphertext bytes of the wrapped AES key.
    """
    try:
        return public_key.encrypt(aes_key, _OAEP_PADDING)
    except (ValueError, TypeError) as exc:
        raise RSAEngineError("RSA key wrap failed") from exc


def unwrap_key(private_key, wrapped_key: bytes) -> bytes:
    """Decrypt a wrapped AES key using an RSA private key.

    Args:
        private_key: RSA private key object.
        wrapped_key: Ciphertext produced by wrap_key.

    Returns:
        Raw AES key bytes.

    Raises:
        RSAEngineError: If decryption fails (wrong key, corrupted ciphertext, etc.)
    """
    try:
        return private_key.decrypt(wrapped_key, _OAEP_PADDING)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise RSAEngineError("RSA key unwrap failed: wrong key or corrupted data") from exc


def save_keys(private_key, public_key) -> None:
    """Serialize and write RSA keypair to the key directory (PEM/PKCS8 format).

    Private key is encrypted with RSA_KEY_PASSPHRASE env var if set.

    Raises:
        RSAEngineError: If the key directory cannot be created or files cannot be written.
    """
    _validate_key_size(private_key)
    try:
        _ensure_key_directory()
    except OSError as exc:
        raise RSAEngineError("Could not create RSA key directory") from exc

    key_dir = _get_key_dir()
    private_key_file = key_dir / "rsa_private.pem"
    public_key_file = key_dir / "rsa_public.pem"
    passphrase = _get_passphrase()
    private_key_file.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=_encryption_algorithm(passphrase),
        )
    )
    public_key_file.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    try:
        private_key_file.chmod(0o600)
        public_key_file.chmod(0o644)
    except OSError:
        pass



# ---------------------------------------------------------------------------
# Signing key management (separate from encryption keys — NIST SP 800-56)
# ---------------------------------------------------------------------------

def save_rsa_signing_keys(private_key, public_key) -> None:
    """Serialize and write the RSA signing keypair to the key directory.

    Uses RSA_SIGN_KEY_PASSPHRASE env var to encrypt the private key at rest.
    Signing keys are kept separate from encryption keys per NIST requirements.

    Raises:
        RSAEngineError: If the key directory cannot be created or files cannot be written.
    """
    _validate_key_size(private_key)
    try:
        _ensure_key_directory()
    except OSError as exc:
        raise RSAEngineError("Could not create RSA key directory") from exc

    key_dir = _get_key_dir()
    rsa_sign_private_file = key_dir / "rsa_sign_private.pem"
    rsa_sign_public_file = key_dir / "rsa_sign_public.pem"
    rsa_sign_fingerprint_file = key_dir / "rsa_sign_public.fp"
    passphrase = _get_sign_passphrase()
    rsa_sign_private_file.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=_encryption_algorithm(passphrase),
        )
    )
    rsa_sign_public_file.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    _write_fingerprint(public_key, rsa_sign_fingerprint_file)
    try:
        rsa_sign_private_file.chmod(0o600)
        rsa_sign_public_file.chmod(0o644)
        rsa_sign_fingerprint_file.chmod(0o644)
    except OSError:
        pass


def rotate_rsa_encryption_keys(registry, user=None) -> tuple:
    """Generate a new RSA-3072 encryption keypair, register it as active, and
    move the previous active key to decrypt-only status.

    New key files are written as:
      ``rsa_enc_{key_id}_private.pem`` / ``rsa_enc_{key_id}_public.pem``

    Args:
        registry: A loaded KeyRegistry instance. Updated in-place and saved to disk.

    Returns:
        (private_key, public_key, key_id) — the newly generated keypair and its registry id.

    Raises:
        RSAEngineError: If key generation or file I/O fails.
    """
    from .key_registry import KeyEntry, KeyRegistryError, make_key_id, algorithm_for_type, now_iso

    _ensure_key_directory()
    ts = now_iso()
    key_id = make_key_id("rsa_enc")

    private_key, public_key = generate_rsa_keypair()

    priv_filename = f"rsa_enc_{key_id}_private.pem"
    pub_filename = f"rsa_enc_{key_id}_public.pem"
    priv_path = _get_key_dir() / priv_filename
    pub_path = _get_key_dir() / pub_filename

    passphrase = _get_passphrase()
    try:
        priv_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=_encryption_algorithm(passphrase),
            )
        )
        pub_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        try:
            _write_fingerprint(public_key, pub_path.with_suffix(".fp"))
        except OSError as exc:
            raise RSAEngineError("Could not write RSA encryption key fingerprint") from exc
        priv_path.chmod(0o600)
        pub_path.chmod(0o644)
    except OSError as exc:
        raise RSAEngineError("Could not write new RSA encryption keys") from exc

    # Move any currently active key to decrypt-only before registering the new one.
    try:
        old_active_id = registry.get_active_key_id("rsa_enc")
        registry.set_status(old_active_id, "decrypt-only")
    except KeyRegistryError:
        pass  # No active key yet — first rotation, nothing to demote.

    entry = KeyEntry(
        key_id=key_id,
        key_type="rsa_enc",
        status="active",
        created_at=ts,
        activate_at=ts,
        retire_at=None,
        algorithm=algorithm_for_type("rsa_enc"),
        key_reference=priv_filename,
    )
    try:
        registry.register(entry)
        registry.save()
    except KeyRegistryError as exc:
        raise RSAEngineError("Registry update failed") from exc

    from .audit_logger import AuditLogger, AuditLogError, _SYSTEM_USER
    audit_actor = user if user is not None else _SYSTEM_USER
    try:
        AuditLogger.log_event(audit_actor, "KEY_ROTATE", outcome="success", key_id=key_id)
    except AuditLogError as exc:
        raise RSAEngineError("Audit failure: operation aborted") from exc

    return private_key, public_key, key_id


def rotate_rsa_signing_keys(registry, user=None) -> tuple:
    """Generate a new RSA signing keypair, register it as active, and retire the old key.

    Version-stamped file naming:
      v1 → rsa_sign_private.pem / rsa_sign_public.pem (backward-compatible)
      v2+ → rsa_sign_v{n}_private.pem / rsa_sign_v{n}_public.pem

    Each version occupies a permanent unique path — v1 files are never moved or
    overwritten. The fingerprint file for each version is independent. The old
    active registry entry is demoted to 'retired' so historical artifacts can
    still be verified against their original key material.

    Args:
        registry: A loaded KeyRegistry instance. Updated in-place and saved.

    Returns:
        (private_key, public_key, key_id) — the newly generated signing keypair
        and its registry key_id (e.g. 'rsa-sign-v2').

    Raises:
        RSAEngineError: If archiving, writing new keys, or registry update fails.
    """
    from .key_registry import (
        KeyEntry, KeyRegistryError,
        make_sign_key_id, next_sign_version, algorithm_for_type, now_iso,
    )

    _ensure_key_directory()
    version = next_sign_version(registry, "rsa_sign")
    key_id = make_sign_key_id("rsa_sign", version)

    if version == 1:
        priv_filename = "rsa_sign_private.pem"
        pub_filename = "rsa_sign_public.pem"
        fp_filename = "rsa_sign_public.fp"
    else:
        priv_filename = f"rsa_sign_v{version}_private.pem"
        pub_filename = f"rsa_sign_v{version}_public.pem"
        fp_filename = f"rsa_sign_v{version}_public.fp"

    priv_path = _get_key_dir() / priv_filename
    pub_path = _get_key_dir() / pub_filename
    fp_path = _get_key_dir() / fp_filename

    private_key, public_key = generate_rsa_keypair()
    passphrase = _get_sign_passphrase()
    try:
        priv_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=_encryption_algorithm(passphrase),
            )
        )
        pub_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        _write_fingerprint(public_key, fp_path)
        priv_path.chmod(0o600)
        pub_path.chmod(0o644)
        fp_path.chmod(0o644)
    except OSError as exc:
        raise RSAEngineError("Could not write new RSA signing keys") from exc

    # Demote old active signing key to retired (preserves verification for old artifacts).
    try:
        old_active_id = registry.get_active_key_id("rsa_sign")
        registry.set_status(old_active_id, "retired")
    except KeyRegistryError:
        pass  # No active signing key yet — first rotation.

    created = now_iso()
    entry = KeyEntry(
        key_id=key_id,
        key_type="rsa_sign",
        status="active",
        created_at=created,
        activate_at=created,
        retire_at=None,
        algorithm=algorithm_for_type("rsa_sign"),
        key_reference=priv_filename,
    )
    try:
        registry.register(entry)
        registry.save()
    except KeyRegistryError as exc:
        raise RSAEngineError("Registry update failed") from exc

    from .audit_logger import AuditLogger, AuditLogError, _SYSTEM_USER
    audit_actor = user if user is not None else _SYSTEM_USER
    try:
        AuditLogger.log_event(audit_actor, "KEY_ROTATE", outcome="success", key_id=key_id)
    except AuditLogError as exc:
        raise RSAEngineError("Audit failure: operation aborted") from exc

    return private_key, public_key, key_id
