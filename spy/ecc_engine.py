"""
ecc_engine.py — ECC (SECP256R1) key generation, persistence, and AES key wrap/unwrap.

Responsibilities:
  - Generate and persist ECC keypairs (PEM/PKCS8 format)
  - Derive a shared secret via ECDH and stretch it with HKDF-SHA256
  - Wrap (encrypt) an AES key using the derived shared secret + AES-256-GCM
  - Unwrap (decrypt) an AES key using the derived shared secret
  - Serialize/deserialize public keys for wire transport
  - No file I/O or symmetric file encryption lives here

Key security:
  - Private keys are encrypted at rest using the passphrase from the
    ECC_KEY_PASSPHRASE environment variable. Missing or empty passphrase
    raises ECCEngineError — no fallback to unencrypted storage.
  - Curve enforced: SECP256R1 (P-256), equivalent to 128-bit symmetric security.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = ec.SECP256R1()


def _get_key_dir() -> Path:
    d = os.environ.get("CRYPTO_KEY_DIR", "")
    if not d:
        raise RuntimeError(
            "CRYPTO_KEY_DIR environment variable is not set. "
            "Set it to the path of your key directory before running "
            "(e.g. CRYPTO_KEY_DIR=runtime/keys)."
        )
    return Path(d)
APPROVED_CURVES = frozenset({"secp256r1", "secp384r1", "secp521r1"})

# KDF info string — changing this value invalidates all previously wrapped keys.
_WRAP_INFO = b"claudeproject/ecc-key-wrap/v1"
_GCM_NONCE_SIZE = 12
_MIN_WRAPPED_KEY_SIZE = _GCM_NONCE_SIZE + 16  # nonce + GCM tag minimum


class ECCEngineError(Exception):
    pass


def _get_passphrase() -> bytes | None:
    """Return the encryption private key passphrase from the environment, or None if unset."""
    passphrase = os.environ.get("ECC_KEY_PASSPHRASE", "").strip()
    return passphrase.encode("utf-8") if passphrase else None


def _get_sign_passphrase() -> bytes | None:
    """Return the signing private key passphrase from the environment, or None if unset."""
    passphrase = os.environ.get("ECC_SIGN_KEY_PASSPHRASE", "").strip()
    return passphrase.encode("utf-8") if passphrase else None


def _encryption_algorithm(passphrase: bytes | None):
    if not passphrase:
        raise ECCEngineError(
            "Private key passphrase is required. "
            "Set ECC_KEY_PASSPHRASE or ECC_SIGN_KEY_PASSPHRASE in the environment."
        )
    return serialization.BestAvailableEncryption(passphrase)


def _ensure_key_directory() -> None:
    _get_key_dir().mkdir(parents=True, exist_ok=True)


def _validate_curve(private_key) -> None:
    """Raise ECCEngineError if the key uses a non-approved curve."""
    curve_name = private_key.curve.name.lower()
    if curve_name not in APPROVED_CURVES:
        raise ECCEngineError(
            f"ECC curve '{curve_name}' is not approved. Use one of: {sorted(APPROVED_CURVES)}"
        )


def _public_key_fingerprint(public_key) -> str:
    """Return SHA-256 hex fingerprint of the DER-encoded public key (SubjectPublicKeyInfo)."""
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der_bytes).hexdigest()


def key_fingerprint(public_key) -> str:
    """Return the SHA-256 hex fingerprint of an ECC public key (SubjectPublicKeyInfo DER)."""
    return _public_key_fingerprint(public_key)


def _write_fingerprint(public_key, fingerprint_file: Path) -> None:
    """Append a versioned fingerprint entry to the fingerprint file.

    Format: ``v{N} {iso8601_utc} {sha256_hex}``

    Existing entries are preserved so the full rotation history is retained.
    """
    computed = _public_key_fingerprint(public_key)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    next_version = 1
    if fingerprint_file.exists():
        lines = [l.strip() for l in fingerprint_file.read_text(encoding="ascii").splitlines() if l.strip()]
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
    """Raise ECCEngineError if the loaded public key does not match the stored fingerprint.

    Reads the *last* entry in the fingerprint file (current active key).
    Supports both legacy bare-hex format and versioned ``v{N} {ts} {hex}`` format.
    """
    if not fingerprint_file.exists():
        raise ECCEngineError(
            "ECC signing key fingerprint file missing. "
            "Key identity cannot be confirmed. Re-generate signing keys."
        )
    lines = [l.strip() for l in fingerprint_file.read_text(encoding="ascii").splitlines() if l.strip()]
    if not lines:
        raise ECCEngineError("ECC signing key fingerprint file is empty")
    last = lines[-1]
    stored = last.split()[-1]
    computed = _public_key_fingerprint(public_key)
    if computed != stored:
        raise ECCEngineError(
            "ECC signing public key fingerprint mismatch. "
            "Key has been replaced or corrupted. Do not proceed."
        )


def generate_ecc_keypair():
    """Generate a new ephemeral or persistent ECC keypair. Returns (private_key, public_key)."""
    private_key = ec.generate_private_key(CURVE)
    return private_key, private_key.public_key()


def serialize_public_key(public_key) -> bytes:
    """Serialize an ECC public key to PEM bytes for storage or wire transport."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(public_key_bytes: bytes):
    """Deserialize an ECC public key from PEM bytes.

    Raises:
        ECCEngineError: If bytes are empty or cannot be parsed.
    """
    if not public_key_bytes:
        raise ECCEngineError("Missing ECC public key bytes")
    try:
        return serialization.load_pem_public_key(public_key_bytes)
    except (ValueError, TypeError) as exc:
        raise ECCEngineError("Failed to deserialize ECC public key") from exc


def serialize_public_key_raw(public_key) -> bytes:
    """Serialize an ECC public key to uncompressed point bytes (X9.62 format).

    Returns 65 bytes for P-256, 97 bytes for P-384, 133 bytes for P-521.
    Used in the SVST streaming container header for compact binary storage.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def deserialize_public_key_raw(data: bytes):
    """Deserialize an ECC public key from uncompressed point bytes (X9.62 format).

    The curve is inferred from the key size: 65 bytes → P-256, 97 → P-384, 133 → P-521.

    Raises:
        ECCEngineError: If bytes are empty, size is unrecognized, or parsing fails.
    """
    if not data:
        raise ECCEngineError("Missing ECC public key bytes")
    _size_to_curve = {65: ec.SECP256R1(), 97: ec.SECP384R1(), 133: ec.SECP521R1()}
    curve = _size_to_curve.get(len(data))
    if curve is None:
        raise ECCEngineError(
            f"Cannot infer ECC curve from key size {len(data)} bytes. "
            "Expected 65 (P-256), 97 (P-384), or 133 (P-521)."
        )
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, data)
    except (ValueError, TypeError) as exc:
        raise ECCEngineError("Failed to deserialize ECC public key from raw bytes") from exc


def _derive_shared_key(private_key, peer_public_key) -> bytes:
    """Perform ECDH and stretch the shared secret to 32 bytes with HKDF-SHA256."""
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_WRAP_INFO,
    ).derive(shared_secret)


def wrap_key(sender_private_key, receiver_public_key, aes_key: bytes, associated_data: bytes | None = None) -> bytes:
    """Wrap an AES key using ECDH-derived shared secret + AES-256-GCM.

    Format: nonce (12 bytes) || GCM-ciphertext+tag

    Args:
        sender_private_key: Sender's ECC private key for ECDH.
        receiver_public_key: Receiver's ECC public key for ECDH.
        aes_key: Raw AES key bytes to protect.
        associated_data: Optional AAD bound into the GCM authentication tag.

    Returns:
        Wrapped key bytes (nonce + ciphertext + tag).
    """
    shared_key = _derive_shared_key(sender_private_key, receiver_public_key)
    nonce = os.urandom(_GCM_NONCE_SIZE)
    try:
        wrapped = AESGCM(shared_key).encrypt(nonce, aes_key, associated_data)
    except (ValueError, TypeError) as exc:
        raise ECCEngineError("ECC key wrap failed") from exc
    return nonce + wrapped


def unwrap_key(receiver_private_key, sender_public_key, wrapped_key: bytes, associated_data: bytes | None = None) -> bytes:
    """Unwrap an AES key using ECDH-derived shared secret + AES-256-GCM.

    Args:
        receiver_private_key: Receiver's ECC private key for ECDH.
        sender_public_key: Sender's ECC public key for ECDH.
        wrapped_key: Bytes produced by wrap_key.
        associated_data: Must match the AAD used during wrap_key.

    Returns:
        Raw AES key bytes.

    Raises:
        ECCEngineError: If the payload is too short, the tag fails, or the key is wrong.
    """
    if len(wrapped_key) < _MIN_WRAPPED_KEY_SIZE:
        raise ECCEngineError(f"ECC wrapped key is too short ({len(wrapped_key)} bytes)")
    shared_key = _derive_shared_key(receiver_private_key, sender_public_key)
    nonce = wrapped_key[:_GCM_NONCE_SIZE]
    ciphertext = wrapped_key[_GCM_NONCE_SIZE:]
    try:
        return AESGCM(shared_key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise ECCEngineError("ECC key unwrap failed: authentication tag mismatch") from exc
    except (ValueError, TypeError) as exc:
        raise ECCEngineError("ECC key unwrap failed") from exc


def save_ecc_keys(private_key, public_key) -> None:
    """Serialize and write the ECC keypair to the key directory (PEM/PKCS8 format).

    Private key is encrypted with ECC_KEY_PASSPHRASE env var if set.

    Raises:
        ECCEngineError: If the key directory cannot be created or files cannot be written.
    """
    _validate_curve(private_key)
    try:
        _ensure_key_directory()
    except OSError as exc:
        raise ECCEngineError("Could not create ECC key directory") from exc

    key_dir = _get_key_dir()
    ecc_private_file = key_dir / "ecc_private.pem"
    ecc_public_file = key_dir / "ecc_public.pem"
    passphrase = _get_passphrase()
    ecc_private_file.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=_encryption_algorithm(passphrase),
        )
    )
    ecc_public_file.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    try:
        ecc_private_file.chmod(0o600)
        ecc_public_file.chmod(0o644)
    except OSError:
        pass



# ---------------------------------------------------------------------------
# Signing key management (separate from encryption keys — NIST SP 800-56)
# ---------------------------------------------------------------------------

def save_ecc_signing_keys(private_key, public_key) -> None:
    """Serialize and write the ECC signing keypair to the key directory.

    Uses ECC_SIGN_KEY_PASSPHRASE env var to encrypt the private key at rest.
    Signing keys are kept separate from encryption keys per NIST requirements.

    Raises:
        ECCEngineError: If the key directory cannot be created or files cannot be written.
    """
    _validate_curve(private_key)
    try:
        _ensure_key_directory()
    except OSError as exc:
        raise ECCEngineError("Could not create ECC key directory") from exc

    key_dir = _get_key_dir()
    ecc_sign_private_file = key_dir / "ecc_sign_private.pem"
    ecc_sign_public_file = key_dir / "ecc_sign_public.pem"
    ecc_sign_fingerprint_file = key_dir / "ecc_sign_public.fp"
    passphrase = _get_sign_passphrase()
    ecc_sign_private_file.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=_encryption_algorithm(passphrase),
        )
    )
    ecc_sign_public_file.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    _write_fingerprint(public_key, ecc_sign_fingerprint_file)
    try:
        ecc_sign_private_file.chmod(0o600)
        ecc_sign_public_file.chmod(0o644)
        ecc_sign_fingerprint_file.chmod(0o644)
    except OSError:
        pass


def rotate_ecc_encryption_keys(registry, user=None) -> tuple:
    """Generate a new ECC encryption keypair, register it as active, and
    move the previous active key to decrypt-only status.

    New key files are written as:
      ``ecc_enc_{key_id}_private.pem`` / ``ecc_enc_{key_id}_public.pem``

    Args:
        registry: A loaded KeyRegistry instance. Updated in-place and saved to disk.

    Returns:
        (private_key, public_key, key_id) — the newly generated keypair and its registry id.

    Raises:
        ECCEngineError: If key generation or file I/O fails.
    """
    from .key_registry import KeyEntry, KeyRegistryError, make_key_id, algorithm_for_type, now_iso

    _ensure_key_directory()
    ts = now_iso()
    key_id = make_key_id("ecc_enc")

    private_key, public_key = generate_ecc_keypair()

    priv_filename = f"ecc_enc_{key_id}_private.pem"
    pub_filename = f"ecc_enc_{key_id}_public.pem"
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
            raise ECCEngineError("Could not write ECC encryption key fingerprint") from exc
        priv_path.chmod(0o600)
        pub_path.chmod(0o644)
    except OSError as exc:
        raise ECCEngineError("Could not write new ECC encryption keys") from exc

    # Move any currently active key to decrypt-only before registering the new one.
    try:
        old_active_id = registry.get_active_key_id("ecc_enc")
        registry.set_status(old_active_id, "decrypt-only")
    except KeyRegistryError:
        pass  # No active key yet — first rotation, nothing to demote.

    entry = KeyEntry(
        key_id=key_id,
        key_type="ecc_enc",
        status="active",
        created_at=ts,
        activate_at=ts,
        retire_at=None,
        algorithm=algorithm_for_type("ecc_enc"),
        key_reference=priv_filename,
    )
    try:
        registry.register(entry)
        registry.save()
    except KeyRegistryError as exc:
        raise ECCEngineError("Registry update failed") from exc

    from .audit_logger import AuditLogger, AuditLogError, _SYSTEM_USER
    audit_actor = user if user is not None else _SYSTEM_USER
    try:
        AuditLogger.log_event(audit_actor, "KEY_ROTATE", outcome="success", key_id=key_id)
    except AuditLogError as exc:
        raise ECCEngineError("Audit failure: operation aborted") from exc

    return private_key, public_key, key_id


def rotate_ecc_signing_keys(registry, user=None) -> tuple:
    """Generate a new ECC signing keypair, register it as active, and retire the old key.

    Version-stamped file naming:
      v1 → ecc_sign_private.pem / ecc_sign_public.pem (backward-compatible)
      v2+ → ecc_sign_v{n}_private.pem / ecc_sign_v{n}_public.pem

    Each version occupies a permanent unique path — v1 files are never moved or
    overwritten. The old active registry entry is demoted to 'retired' so
    historical artifacts can still be verified against their original key material.

    Args:
        registry: A loaded KeyRegistry instance. Updated in-place and saved.

    Returns:
        (private_key, public_key, key_id) — the newly generated signing keypair
        and its registry key_id (e.g. 'ecc-sign-v2').

    Raises:
        ECCEngineError: If writing new keys or registry update fails.
    """
    from .key_registry import (
        KeyEntry, KeyRegistryError,
        make_sign_key_id, next_sign_version, algorithm_for_type, now_iso,
    )

    _ensure_key_directory()
    version = next_sign_version(registry, "ecc_sign")
    key_id = make_sign_key_id("ecc_sign", version)

    if version == 1:
        priv_filename = "ecc_sign_private.pem"
        pub_filename = "ecc_sign_public.pem"
        fp_filename = "ecc_sign_public.fp"
    else:
        priv_filename = f"ecc_sign_v{version}_private.pem"
        pub_filename = f"ecc_sign_v{version}_public.pem"
        fp_filename = f"ecc_sign_v{version}_public.fp"

    priv_path = _get_key_dir() / priv_filename
    pub_path = _get_key_dir() / pub_filename
    fp_path = _get_key_dir() / fp_filename

    private_key, public_key = generate_ecc_keypair()
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
        raise ECCEngineError("Could not write new ECC signing keys") from exc

    # Demote old active signing key to retired (preserves verification for old artifacts).
    try:
        old_active_id = registry.get_active_key_id("ecc_sign")
        registry.set_status(old_active_id, "retired")
    except KeyRegistryError:
        pass  # No active signing key yet — first rotation.

    created = now_iso()
    entry = KeyEntry(
        key_id=key_id,
        key_type="ecc_sign",
        status="active",
        created_at=created,
        activate_at=created,
        retire_at=None,
        algorithm=algorithm_for_type("ecc_sign"),
        key_reference=priv_filename,
    )
    try:
        registry.register(entry)
        registry.save()
    except KeyRegistryError as exc:
        raise ECCEngineError("Registry update failed") from exc

    from .audit_logger import AuditLogger, AuditLogError, _SYSTEM_USER
    audit_actor = user if user is not None else _SYSTEM_USER
    try:
        AuditLogger.log_event(audit_actor, "KEY_ROTATE", outcome="success", key_id=key_id)
    except AuditLogError as exc:
        raise ECCEngineError("Audit failure: operation aborted") from exc

    return private_key, public_key, key_id
