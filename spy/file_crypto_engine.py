"""
file_crypto_engine.py — File-level encryption and decryption.

Responsible for file I/O and calling into hybrid_engine. All container
serialization is delegated to crypto_container. No cryptographic logic lives here.

Key access: all key material is resolved through a KeyProvider instance.
No engine in this module opens PEM files directly.
"""

from __future__ import annotations

import hashlib
import os
import struct
import tempfile
from pathlib import Path
from typing import BinaryIO

from .container_reader import StreamingContainerReader, StreamingError
from .container_writer import ContainerWriterError, StreamingContainerWriter
from .crypto_container import (
    KEY_WRAP_ID_ECC,
    KEY_WRAP_ID_RSA,
    SIG_METHOD_ID_ECC,
    SIG_METHOD_ID_RSA,
    STREAMING_MAGIC,
    is_streaming_container,
)
from .crypto_engine import STREAM_CHUNK_SIZE, generate_key
from .ecc_engine import (
    ECCEngineError,
    deserialize_public_key_raw,
    generate_ecc_keypair,
    serialize_public_key_raw,
    unwrap_key as ecc_unwrap_key,
    wrap_key as ecc_wrap_key,
)
from .rsa_engine import (
    RSAEngineError,
    unwrap_key as rsa_unwrap_key,
    wrap_key as rsa_wrap_key,
)
from .governance_rules import GovernanceViolation, enforce_all
from .policy_engine import PolicyError, determine_classification
from .key_provider import KeyProvider, KeyProviderError, LocalPemKeyProvider
from .audit_logger import AuditLogger, AuditLogError, _SYSTEM_USER
from .auth_engine import AuthorizationEngine
from .signature_engine import SignatureError, sign
from .workspace import (
    classified_encrypted_output_path,
    classified_decrypted_output_path,
    is_inside_safe_root,
)

DEFAULT_CHUNK_SIZE = STREAM_CHUNK_SIZE

# AAD used when wrapping/unwrapping the DEK in SVST ECC mode.
# Must be identical on encrypt and decrypt paths.
_SVST_ECC_DEK_WRAP_AAD = b"svst/ecc-dek-wrap/v1"

# Streaming copy buffer: 256 KiB per read() when re-hashing the body during rewrap.
_REWRAP_COPY_BUFFER_SIZE = 262144


class FileCryptoError(Exception):
    pass


class FileCryptoOverwriteError(FileCryptoError):
    """Raised when the output file already exists and overwrite=False."""
    pass


CLEARANCE_ORDER: dict[str, int] = {"low": 1, "medium": 2, "high": 3}
_VALID_CLASSIFICATIONS: frozenset[str] = frozenset({"low", "medium", "high"})


# DEPRECATED: All production call sites replaced by AuthorizationEngine.authorize()
# (Batch 4, 2026-04-27). Retained because tests/test_authorization_matrix.py imports
# and calls this function directly for matrix coverage. Removal requires migrating
# those tests to AuthorizationEngine.authorize() first — deferred to a future batch.
def _check_access(user, classification: str, action: str) -> None:
    """Hard authorization gate — called before any crypto operation begins.

    Raises FileCryptoError on any denial. user=None passes (system/internal call).
    """
    if user is None:
        return
    if not getattr(user, "authenticated", False):
        raise FileCryptoError("Authentication required")
    if getattr(user, "role", "") == "auditor":
        raise FileCryptoError("Access denied")
    if CLEARANCE_ORDER.get(getattr(user, "clearance", ""), 0) < CLEARANCE_ORDER.get(classification, 3):
        raise FileCryptoError("Access denied")


def _default_encrypted_path(input_path: str) -> str:
    return f"{input_path}.enc"


def _default_decrypted_path(input_path: str) -> str:
    return input_path[:-4] if input_path.endswith(".enc") else f"{input_path}.decrypted"


def _make_provider() -> LocalPemKeyProvider:
    """Construct a default LocalPemKeyProvider using the current key directory."""
    return LocalPemKeyProvider()


# ---------------------------------------------------------------------------
# Streaming API (SVST format — chunked AES-256-GCM, O(chunk_size) memory)
# ---------------------------------------------------------------------------

def stream_encrypt_file(
    input_path: str,
    output_path: str | None = None,
    method: str = "rsa",
    delete_original: bool = False,
    overwrite: bool = False,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    provider: KeyProvider | None = None,
    user=None,
    context: dict | None = None,
) -> str:
    """Encrypt a file using the SVST streaming container format.

    Memory usage is bounded by chunk_size (default 1 MiB). The entire plaintext
    is never loaded into memory.

    Args:
        input_path: Path to the plaintext file.
        output_path: Destination path. Defaults to input_path + '.enc'.
        method: 'rsa' or 'ecc'.
        delete_original: If True, removes the plaintext file after encryption.
        overwrite: If False (default), raises FileCryptoError if output exists.
        chunk_size: Plaintext bytes per chunk (default 1 MiB).
        provider: KeyProvider to use for key resolution. Defaults to LocalPemKeyProvider.

    Returns:
        Path to the encrypted output file.
    """
    if provider is None:
        provider = _make_provider()

    method = method.lower().strip()
    if method not in ("rsa", "ecc"):
        raise FileCryptoError("Encryption failed")

    # Policy engine assigns classification; clearance sets the minimum (no-write-down).
    # user=None (system call) uses _SYSTEM_CLEARANCE so internal APIs cannot downgrade.
    _SYSTEM_CLEARANCE = "high"
    _RANK_TO_CLS = {1: "low", 2: "medium", 3: "high"}
    try:
        _policy_cls = determine_classification(context or {})
    except PolicyError:
        raise FileCryptoError("Encryption failed")
    _user_clearance = getattr(user, "clearance", "low") if user is not None else _SYSTEM_CLEARANCE
    _user_rank = CLEARANCE_ORDER.get(_user_clearance, 1)
    _policy_rank = CLEARANCE_ORDER.get(_policy_cls, 1)
    data_classification = _RANK_TO_CLS[max(_user_rank, _policy_rank)]
    if data_classification not in _VALID_CLASSIFICATIONS:
        raise FileCryptoError("Encryption failed")

    input_file = Path(input_path)
    if not input_file.is_file():
        raise FileCryptoError("Encryption failed")

    if input_file.suffix.lower() == ".enc":
        raise FileCryptoError("Encryption failed")

    if output_path is None:
        _cls_out = classified_encrypted_output_path(input_file, data_classification)
        _cls_out.parent.mkdir(parents=True, exist_ok=True)
        output_path = str(_cls_out)
    else:
        _resolved = Path(output_path).resolve()
        if not is_inside_safe_root(_resolved):
            raise FileCryptoError("Encryption failed")
        _expected_dir = classified_encrypted_output_path(input_file, data_classification).parent
        if _resolved.parent != _expected_dir.resolve():
            raise FileCryptoError("Encryption failed")
    output_file = Path(output_path)

    _audit_user = _SYSTEM_USER
    if user is not None:
        _denial = None
        if not getattr(user, "authenticated", False):
            _denial = FileCryptoError("Authentication required")
        else:
            _allowed, _ = AuthorizationEngine.authorize(user, "encrypt", data_classification)
            if not _allowed:
                _denial = FileCryptoError("Access denied")
        if _denial is not None:
            try:
                AuditLogger.log_event(user, "ENCRYPT",
                                      classification=data_classification, outcome="denied")
            except AuditLogError:
                raise FileCryptoError("Audit failure: operation aborted")
            raise _denial
        _audit_user = user

    # Generate a fresh AES-256 DEK for this file.
    # bytearray allows explicit overwrite in the finally block (best-effort CPython).
    aes_key = bytearray(generate_key())
    active_key_id: str | None = None
    try:
        try:
            if output_file.exists() and not overwrite:
                raise FileCryptoOverwriteError("Encryption failed")

            # Enforce governance policy before any key operation.
            try:
                enforce_all(method, aes_key=aes_key)
            except GovernanceViolation:
                raise FileCryptoError("Encryption failed")

            # Step 1 — Resolve key_id only. No crypto yet.
            try:
                if method == "rsa":
                    active_key_id = provider.get_active_rsa_key_id()
                else:
                    active_key_id = provider.get_active_ecc_key_id()
            except KeyProviderError:
                raise FileCryptoError("Encryption failed")

            # Task A — explicit gate before any crypto execution.
            if not active_key_id:
                raise FileCryptoError("Encryption denied: no active key_id")

            # Step 2 — Load keys and wrap DEK. key_id is confirmed.
            try:
                if method == "rsa":
                    public_key = provider.get_rsa_public_key(active_key_id)
                    enforce_all(method, private_key=public_key)
                    wrapped_dek = rsa_wrap_key(public_key, bytes(aes_key))
                    sign_key_id = provider.get_active_rsa_signing_key_id()
                    sign_private_key = provider.get_rsa_signing_private_key()
                    key_wrap_id = KEY_WRAP_ID_RSA
                    sig_method_id = SIG_METHOD_ID_RSA
                    sender_pubkey_raw = None
                else:
                    receiver_public = provider.get_ecc_public_key(active_key_id)
                    sender_private = None
                    try:
                        sender_private, sender_public = generate_ecc_keypair()
                        enforce_all(method, private_key=sender_private)
                        sender_pubkey_raw = serialize_public_key_raw(sender_public)
                        wrapped_dek = ecc_wrap_key(
                            sender_private, receiver_public, bytes(aes_key), _SVST_ECC_DEK_WRAP_AAD
                        )
                    finally:
                        sender_private = None  # Best-effort cleanup only — CPython/OpenSSL do not guarantee zeroization of key material
                    sign_key_id = provider.get_active_ecc_signing_key_id()
                    sign_private_key = provider.get_ecc_signing_private_key()
                    key_wrap_id = KEY_WRAP_ID_ECC
                    sig_method_id = SIG_METHOD_ID_ECC
            except KeyProviderError:
                raise FileCryptoError("Encryption failed")
            except (RSAEngineError, ECCEngineError):
                raise FileCryptoError("Encryption failed")
            except GovernanceViolation:
                raise FileCryptoError("Encryption failed")

            try:
                with input_file.open("rb") as in_f, output_file.open("wb") as out_f:
                    writer = StreamingContainerWriter(
                        out_file=out_f,
                        key_wrap_id=key_wrap_id,
                        sig_method_id=sig_method_id,
                        wrapped_dek=wrapped_dek,
                        sender_pubkey_raw=sender_pubkey_raw,
                        sign_private_key=sign_private_key,
                        aes_key=aes_key,
                        chunk_size=chunk_size,
                        key_id=active_key_id,
                        sign_key_id=sign_key_id,
                        classification=data_classification,
                    )
                    writer.write_header()
                    writer.write_chunks(in_f)
                    writer.close()
            except (ContainerWriterError, OSError):
                # Clean up partial output on failure.
                try:
                    output_file.unlink(missing_ok=True)
                except OSError:
                    pass
                raise FileCryptoError("Encryption failed")

            if delete_original:
                input_file.unlink(missing_ok=False)

            try:
                AuditLogger.log_event(_audit_user, "ENCRYPT", classification=data_classification,
                                      outcome="success", key_id=active_key_id)
            except AuditLogError:
                raise FileCryptoError("Audit failure: operation aborted")

            return str(output_file)
        except FileCryptoError as exc:
            _outcome = "denied" if isinstance(exc, FileCryptoOverwriteError) else "error"
            try:
                AuditLogger.log_event(_audit_user, "ENCRYPT", classification=data_classification,
                                      outcome=_outcome, key_id=active_key_id)
            except AuditLogError:
                raise FileCryptoError("Audit failure: operation aborted")
            raise
    finally:
        aes_key[:] = bytes(len(aes_key))


def stream_decrypt_file(
    input_path: str,
    output_path: str | None = None,
    overwrite: bool = False,
    provider: KeyProvider | None = None,
    user=None,
) -> str:
    """Decrypt an SVST streaming container file.

    Header signature is verified before any chunk data is decrypted.
    Chunks are decrypted into a temp file then atomically renamed to the
    final output path — no partial plaintext is written on failure.

    This is the sole production decrypt path. Authorization classification is
    read from the signed SVST container header — never caller-supplied.

    Args:
        input_path: Path to the .enc file.
        output_path: Destination path. Defaults to stripping '.enc'.
        overwrite: If False (default), raises FileCryptoError if output exists.
        provider: KeyProvider to use for key resolution. Defaults to LocalPemKeyProvider.

    Returns:
        Path to the decrypted output file.
    """
    if provider is None:
        provider = _make_provider()

    input_file = Path(input_path)
    if not input_file.is_file():
        raise FileCryptoError("Decryption denied")

    if input_file.suffix.lower() != ".enc":
        raise FileCryptoError("Decryption denied")

    # Verify magic bytes — only SVST containers are supported.
    with input_file.open("rb") as f:
        first_bytes = f.read(4)

    if not is_streaming_container(first_bytes):
        raise FileCryptoError("Decryption denied")

    # output_file and tmp_path are set after classification is read from the container header.
    output_file: Path | None = None
    tmp_path: Path | None = None
    _container_classification: str = ""

    # bytearray allows explicit overwrite in the finally block (best-effort CPython).
    aes_key: bytearray | None = None
    _audit_key_id: str | None = None
    _audit_user = _SYSTEM_USER
    try:
        with input_file.open("rb") as in_f:
            reader = StreamingContainerReader(in_f)

            # Gate 1 — header authenticity
            try:
                header = reader.read_and_verify_header(_make_svst_sign_key_resolver(provider))
            except StreamingError:
                raise FileCryptoError("Integrity/authenticity check failed")

            # Gate 2 — body authenticity: verified BEFORE DEK unwrap and plaintext output
            try:
                reader.verify_body_signature(_make_svst_sign_key_resolver(provider))
            except StreamingError:
                raise FileCryptoError("Integrity/authenticity check failed")

            # Gate 3 — extract classification from trusted container header.
            # Classification is authoritative from the signed container — not caller-supplied.
            # Legacy containers (v1/v2/v3) without a classification field are denied.
            _container_classification = header.classification
            if _container_classification not in _VALID_CLASSIFICATIONS:
                raise FileCryptoError("Decryption denied")

            # Resolve output path now that classification is known.
            if output_path is None:
                _cls_out = classified_decrypted_output_path(input_file, _container_classification)
                _cls_out.parent.mkdir(parents=True, exist_ok=True)
                output_file = _cls_out
            else:
                _resolved = Path(output_path).resolve()
                if not is_inside_safe_root(_resolved):
                    raise FileCryptoError("Decryption denied")
                _expected_dir = classified_decrypted_output_path(input_file, _container_classification).parent
                if _resolved.parent != _expected_dir.resolve():
                    raise FileCryptoError("Decryption denied")
                output_file = Path(output_path)

            if output_file.exists() and not overwrite:
                raise FileCryptoOverwriteError("Decryption denied")

            # Decrypt into a temp file in the same directory (ensures same filesystem for
            # atomic rename). mkstemp creates a unique name with O_EXCL — no symlink pre-placement.
            _tmp_fd, _tmp_path_str = tempfile.mkstemp(
                dir=output_file.parent, suffix=".svst_decrypt_tmp"
            )
            os.close(_tmp_fd)
            tmp_path = Path(_tmp_path_str)

            # Gate 4 — authorization against container classification.
            if user is not None:
                _denial = None
                if not getattr(user, "authenticated", False):
                    _denial = FileCryptoError("Authentication required")
                else:
                    _allowed, _ = AuthorizationEngine.authorize(user, "decrypt", _container_classification)
                    if not _allowed:
                        _denial = FileCryptoError("Access denied")
                if _denial is not None:
                    try:
                        AuditLogger.log_event(user, "DECRYPT",
                                              classification=_container_classification, outcome="denied")
                    except AuditLogError:
                        raise FileCryptoError("Audit failure: operation aborted")
                    raise _denial
                _audit_user = user

            # Unwrap DEK — dispatch by key_id (v2/v3/v4). V1 containers without an
            # embedded key_id are rejected: the active key at decrypt time may differ
            # from the key used during encryption, making best-effort fallback wrong.
            if header.key_id is not None:
                _audit_key_id = header.key_id
                aes_key = bytearray(_unwrap_svst_dek_by_key_id(header, provider))
            else:
                raise FileCryptoError("Decryption denied")

            # Decrypt chunks to temp file — fail-closed on any error.
            with tmp_path.open("wb") as out_f:
                try:
                    for chunk in reader.iter_plaintext_chunks(aes_key):
                        out_f.write(chunk)
                except StreamingError:
                    raise FileCryptoError("Decryption denied")

        # All chunks verified — atomic rename to final destination.
        os.replace(str(tmp_path), str(output_file))

    except FileCryptoError:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            AuditLogger.log_event(_audit_user, "DECRYPT", classification=_container_classification,
                              outcome="error", key_id=_audit_key_id)
        except AuditLogError:
            raise FileCryptoError("Audit failure: operation aborted")
        raise
    except Exception:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise FileCryptoError("Decryption denied")
    finally:
        if aes_key is not None:
            aes_key[:] = bytes(len(aes_key))

    try:
        AuditLogger.log_event(_audit_user, "DECRYPT", classification=_container_classification,
                              outcome="success", key_id=_audit_key_id)
    except AuditLogError:
        raise FileCryptoError("Audit failure: operation aborted")

    return str(output_file)


def rewrap_dek(
    enc_file_path: str,
    output_path: str | None = None,
    overwrite: bool = False,
    provider: KeyProvider | None = None,
    user=None,
) -> str:
    """Re-wrap the DEK in an SVST container with the current active encryption key.

    The chunk ciphertext is copied unchanged — only the header (wrapped DEK, key_id,
    and header signature) is rewritten. This allows key rotation without re-encrypting
    file data.

    Only SVST containers are supported. SENV containers must be re-encrypted.

    Args:
        enc_file_path: Path to the existing SVST .enc file.
        output_path: Destination path. Defaults to overwriting enc_file_path in-place
                     (via temp file + atomic rename).
        overwrite: If False (default), raises if output_path already exists and
                   is different from enc_file_path.

    Returns:
        Path to the rewritten file.
    """
    if provider is None:
        provider = _make_provider()

    input_file = Path(enc_file_path)
    if not input_file.is_file():
        raise FileCryptoError("Decryption denied")

    # Read first 4 bytes to verify this is SVST.
    with input_file.open("rb") as f:
        magic = f.read(4)
    if not is_streaming_container(magic):
        raise FileCryptoError("Decryption denied")

    # Resolve output path.
    if output_path is None:
        # Default: rewrite the input file in-place.
        output_file = input_file
    else:
        output_file = Path(output_path)
        if output_file.exists() and not overwrite and output_file != input_file:
            raise FileCryptoError("Decryption denied")

    _tmp_fd, _tmp_path_str = tempfile.mkstemp(
        dir=input_file.parent, suffix=".rewrap_tmp"
    )
    os.close(_tmp_fd)
    tmp_path = Path(_tmp_path_str)

    # bytearray allows explicit overwrite in the finally block (best-effort CPython).
    old_dek: bytearray | None = None
    _classification = ""       # set after header read; used in all audit events
    _audit_written = False     # ensures exactly one audit event per authenticated attempt
    active_key_id: str | None = None  # new key_id; set after resolution; used for success audit
    try:
        with input_file.open("rb") as in_f:
            reader = StreamingContainerReader(in_f)

            # Gate 1 — header authenticity
            try:
                header = reader.read_and_verify_header(_make_svst_sign_key_resolver(provider))
            except StreamingError:
                raise FileCryptoError("Integrity/authenticity check failed")

            _classification = header.classification

            # Auth gate — engine enforces its own boundary; CLI is not a security layer.
            # 1. Existence + authentication check (no audit — no actor to attribute).
            if user is None or not getattr(user, "authenticated", False):
                raise FileCryptoError("Rewrap denied")

            # 2. Role/clearance check via AuthorizationEngine — rewrap is admin-only.
            _allowed, _ = AuthorizationEngine.authorize(user, "rewrap", _classification)
            if not _allowed:
                try:
                    AuditLogger.log_event(user, "KEY_ROTATE", classification=_classification,
                                          outcome="denied", key_id=None)
                    _audit_written = True
                except AuditLogError:
                    raise FileCryptoError("Audit failure: operation aborted")
                raise FileCryptoError("Rewrap denied")

            # Gate 2 — body authenticity: verified BEFORE any DEK operation
            try:
                reader.verify_body_signature(_make_svst_sign_key_resolver(provider))
            except StreamingError:
                raise FileCryptoError("Integrity/authenticity check failed")

            # Record where the chunk data starts (set by read_and_verify_header).
            chunk_start_offset = reader._chunk_start_offset

            # Unwrap old DEK via provider. V1 containers (no key_id) are rejected.
            if header.key_id is not None:
                old_dek = bytearray(_unwrap_svst_dek_by_key_id(header, provider))
            else:
                raise FileCryptoError("Decryption denied")

            # Resolve active key for the same method via provider.
            method = "rsa" if header.key_wrap_id == KEY_WRAP_ID_RSA else "ecc"
            try:
                active_key_id = (
                    provider.get_active_rsa_key_id()
                    if method == "rsa"
                    else provider.get_active_ecc_key_id()
                )
            except KeyProviderError:
                raise FileCryptoError("Decryption denied")

            if header.key_id == active_key_id:
                raise FileCryptoError("Decryption denied")

            # Wrap DEK with new active public key via provider.
            try:
                if method == "rsa":
                    new_public_key = provider.get_rsa_public_key(active_key_id)
                    new_wrapped_dek = rsa_wrap_key(new_public_key, bytes(old_dek))
                    sender_pubkey_raw = None
                    key_wrap_id = KEY_WRAP_ID_RSA
                    sig_method_id = header.sig_method_id
                else:
                    new_receiver_public = provider.get_ecc_public_key(active_key_id)
                    new_sender_private = None
                    try:
                        new_sender_private, new_sender_public = generate_ecc_keypair()
                        new_sender_pubkey_raw = serialize_public_key_raw(new_sender_public)
                        new_wrapped_dek = ecc_wrap_key(
                            new_sender_private, new_receiver_public, bytes(old_dek), _SVST_ECC_DEK_WRAP_AAD
                        )
                    finally:
                        new_sender_private = None  # Best-effort cleanup only — CPython/OpenSSL do not guarantee zeroization of key material
                    sender_pubkey_raw = new_sender_pubkey_raw
                    key_wrap_id = KEY_WRAP_ID_ECC
                    sig_method_id = header.sig_method_id
            except (KeyProviderError, RSAEngineError, ECCEngineError):
                raise FileCryptoError("Decryption denied")

            # Load signing key for re-signing the new header via provider.
            try:
                if sig_method_id == SIG_METHOD_ID_RSA:
                    rewrap_sign_key_id = provider.get_active_rsa_signing_key_id()
                    sign_private_key = provider.get_rsa_signing_private_key()
                else:
                    rewrap_sign_key_id = provider.get_active_ecc_signing_key_id()
                    sign_private_key = provider.get_ecc_signing_private_key()
            except KeyProviderError:
                raise FileCryptoError("Decryption denied")

            # Write new header + original chunk bytes to temp file.
            # Re-use the original base_nonce so all chunk nonces remain valid.
            with tmp_path.open("wb") as out_f:
                writer = StreamingContainerWriter(
                    out_file=out_f,
                    key_wrap_id=key_wrap_id,
                    sig_method_id=sig_method_id,
                    wrapped_dek=new_wrapped_dek,
                    sender_pubkey_raw=sender_pubkey_raw,
                    sign_private_key=sign_private_key,
                    aes_key=b"\x00" * 32,  # placeholder — not used for chunk writing
                    key_id=active_key_id,
                    sign_key_id=rewrap_sign_key_id,
                    classification=header.classification,
                )
                # Override the random base_nonce with the original to keep chunk nonces valid.
                writer._base_nonce = header.base_nonce
                writer._header_written = False
                # Manually sign and write the header (bypassing write_header's nonce generation).
                # Returns (signed_region, version) to seed the body digest and verify version invariant.
                new_signed_region, output_version = _rewrap_write_header(writer, forced_version=header.version)
                if header.version is not None and output_version != header.version:
                    raise FileCryptoError("Container version mismatch: rewrap aborted")

                # Copy chunk body bytes only (excluding old trailer) and compute
                # the new body digest: signed_region + chunk body bytes.
                body_hasher = hashlib.sha256()
                body_hasher.update(new_signed_region)
                body_section_size = reader._body_end_offset - chunk_start_offset
                in_f.seek(chunk_start_offset)
                remaining = body_section_size
                while remaining > 0:
                    buf = in_f.read(min(_REWRAP_COPY_BUFFER_SIZE, remaining))
                    if not buf:
                        raise FileCryptoError("Integrity/authenticity check failed")
                    out_f.write(buf)
                    body_hasher.update(buf)
                    remaining -= len(buf)

                # Write fresh body signature trailer: [ body_sig ][ sig_len (4 BE) ]
                body_digest = body_hasher.digest()
                body_sig_method = "rsa" if sig_method_id == SIG_METHOD_ID_RSA else "ecc"
                new_body_sig = sign(body_sig_method, sign_private_key, body_digest)
                out_f.write(new_body_sig)
                out_f.write(struct.pack(">I", len(new_body_sig)))

        try:
            AuditLogger.log_event(user, "KEY_ROTATE", classification=_classification,
                                  outcome="success", key_id=active_key_id)
            _audit_written = True
        except AuditLogError:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise FileCryptoError("Audit failure: operation aborted")

        os.replace(str(tmp_path), str(output_file))

    except FileCryptoError:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        if not _audit_written and user is not None and getattr(user, "authenticated", False):
            try:
                AuditLogger.log_event(user, "KEY_ROTATE", classification=_classification,
                                      outcome="error", key_id=None)
            except AuditLogError:
                raise FileCryptoError("Audit failure: operation aborted")
        raise
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise FileCryptoError("Decryption denied")
    finally:
        if old_dek is not None:
            old_dek[:] = bytes(len(old_dek))

    return str(output_file)


def _rewrap_write_header(writer: "StreamingContainerWriter", forced_version=None) -> tuple:
    """Write the SVST header using writer's pre-set _base_nonce (for rewrap).

    This is a variant of StreamingContainerWriter.write_header() that skips
    nonce generation and uses the already-set _base_nonce instead.

    Returns (signed_region_bytes, container_version) so the caller can seed
    the body digest and verify version invariants.
    """
    if writer._header_written:
        raise ContainerWriterError("_rewrap_write_header called on already-written header")

    wrapped_dek_len = len(writer._wrapped_dek)
    if wrapped_dek_len > 65535:
        raise ContainerWriterError(f"wrapped_dek too large: {wrapped_dek_len} bytes")

    from .crypto_container import (
        STREAMING_CONTAINER_VERSION_V2 as _V2,
        STREAMING_CONTAINER_VERSION_V3 as _V3,
        STREAMING_CONTAINER_VERSION_V4 as _V4,
    )
    if forced_version is not None:
        container_version = forced_version
    elif writer._classification is not None and writer._sign_key_id is not None:
        container_version = _V4
    elif writer._sign_key_id is not None:
        container_version = _V3
    else:
        container_version = _V2

    signed_region = (
        STREAMING_MAGIC
        + struct.pack(">BBBB", container_version, writer._key_wrap_id, writer._sig_method_id, 0x00)
        + struct.pack(">H", wrapped_dek_len)
        + writer._wrapped_dek
    )
    if writer._key_wrap_id == KEY_WRAP_ID_ECC:
        pubkey_len = len(writer._sender_pubkey_raw)
        signed_region += struct.pack(">H", pubkey_len) + writer._sender_pubkey_raw

    signed_region += writer._base_nonce

    key_id_bytes = writer._key_id.encode("ascii")  # type: ignore[union-attr]
    signed_region += struct.pack(">H", len(key_id_bytes)) + key_id_bytes

    if writer._sign_key_id is not None:
        sign_key_id_bytes = writer._sign_key_id.encode("ascii")
        signed_region += struct.pack(">H", len(sign_key_id_bytes)) + sign_key_id_bytes

    if container_version == _V4:
        cls_bytes = writer._classification.encode("ascii")  # type: ignore[union-attr]
        signed_region += struct.pack(">B", len(cls_bytes)) + cls_bytes

    sig_method = "rsa" if writer._sig_method_id == SIG_METHOD_ID_RSA else "ecc"
    try:
        signature = sign(sig_method, writer._sign_private_key, signed_region)
    except SignatureError as exc:
        raise ContainerWriterError("Header signing failed") from exc

    writer._out.write(signed_region)
    writer._out.write(struct.pack(">I", len(signature)))
    writer._out.write(signature)
    writer._header_written = True
    return signed_region, container_version


def _make_svst_sign_key_resolver(provider: KeyProvider):
    """Return a signing-key resolver for use with StreamingContainerReader.read_and_verify_header.

    The returned callable is invoked by the reader after the full header is parsed,
    with the sig_method_id and sign_key_id extracted from the container:

      resolver(sig_method_id: int, sign_key_id: str | None) -> public_key

    Routing rules:
      - V3 containers (sign_key_id present): exact lookup via
        provider.get_signing_public_key(sign_key_id). No fallback.
      - V1/V2 containers (sign_key_id is None): route by sig_method_id
        (RSA or ECC), same as the previous behaviour.

    Fails closed via StreamingError on any provider error.
    """
    def _resolver(sig_method_id: int, sign_key_id: str | None):
        try:
            if sign_key_id is not None:
                # V3: must use the embedded key identity — no guessed fallback.
                return provider.get_signing_public_key(sign_key_id)
            # V1/V2: route by sig_method_id.
            if sig_method_id == SIG_METHOD_ID_RSA:
                return provider.get_rsa_signing_public_key()
            elif sig_method_id == SIG_METHOD_ID_ECC:
                return provider.get_ecc_signing_public_key()
            else:
                raise KeyProviderError(f"Unknown sig_method_id: {sig_method_id:#04x}")
        except KeyProviderError as exc:
            raise StreamingError(
                "Signing key not available — cannot verify SVST header signature."
            ) from exc

    return _resolver


def _unwrap_svst_dek_by_key_id(header, provider: KeyProvider) -> bytes:
    """Unwrap the DEK from a v2 StreamingHeader using the key_id from the registry.

    The provider enforces the revoked-key check. Deprecated key status is visible
    via the key_id field in the caller's DECRYPT audit event.
    """
    key_id = header.key_id
    method = "rsa" if header.key_wrap_id == KEY_WRAP_ID_RSA else "ecc"

    if header.key_wrap_id == KEY_WRAP_ID_RSA:
        try:
            private_key = provider.get_rsa_private_key(key_id)
            return rsa_unwrap_key(private_key, header.wrapped_dek)
        except KeyProviderError:
            raise FileCryptoError("Decryption denied")
        except RSAEngineError:
            raise FileCryptoError("Decryption denied")
    else:
        try:
            receiver_private = provider.get_ecc_private_key(key_id)
            sender_public = deserialize_public_key_raw(header.sender_pubkey_raw)
            return ecc_unwrap_key(
                receiver_private, sender_public, header.wrapped_dek, _SVST_ECC_DEK_WRAP_AAD
            )
        except KeyProviderError:
            raise FileCryptoError("Decryption denied")
        except ECCEngineError:
            raise FileCryptoError("Decryption denied")
