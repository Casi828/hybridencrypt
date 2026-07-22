"""
governance_pipeline.py — Connects policy decisions to hybrid crypto execution.

Responsibilities:
  - Run authorization checks before any crypto operation
  - Delegate method selection to policy_engine
  - Delegate encryption/decryption to hybrid_engine via the shared crypto path
  - Record all outcomes (success, denial, error) to the audit log
  - No cryptographic primitives or raw key serialization live here

Audit-control rules enforced here:
  - POLICY_DECISION action: policy selection and authorization events (key_id not required)
  - KEY_ACCESS action: key resolution failures (no crypto ran)
  - ENCRYPT / DECRYPT actions: only after key_id is resolved (key_id always present)
  - Success audit on crypto path is fail-closed: AuditLogError propagates as pipeline failure
  - Failure-path audit failures are tolerated (already returning False)
"""

from __future__ import annotations

from dataclasses import dataclass

from .ecc_engine import generate_ecc_keypair, serialize_public_key
from .hybrid_engine import HybridEngineError, decrypt_hybrid, encrypt_hybrid
from .policy_engine import PolicyError, select_encryption_method
from .auth_engine import AuthorizationEngine
from .audit_logger import AuditLogger, AuditLogError
from .key_provider import KeyProvider, KeyProviderError

_PIPELINE_AAD_PREFIX = b"governance-pipeline"


@dataclass(frozen=True)
class _GovernancePackage:
    """Governance-layer encryption result. Carries crypto output plus metadata for decrypt()."""
    method: str
    key_id: str
    encrypted_aes_key: bytes
    encrypted_message: bytes
    aad: bytes
    sender_public_key: object | None


def _build_aad(method: str, sender_public_bytes: bytes = b"") -> bytes:
    """Construct the AES-GCM additional authenticated data for a pipeline package.

    Binds a fixed domain-separation prefix, the wrapping ``method`` ('rsa'/'ecc'),
    and (for ECC) the sender's ephemeral public key into the AEAD tag. Because the
    AAD is authenticated but not encrypted, tampering with any of these fields
    causes decryption to fail rather than silently accepting mismatched material.
    """
    parts = [_PIPELINE_AAD_PREFIX, method.encode("ascii")]
    if sender_public_bytes:
        parts.append(sender_public_bytes)
    return b"|".join(parts)


class GovernancePipeline:
    def __init__(self, key_provider: KeyProvider) -> None:
        self.key_provider = key_provider

    def _run_roundtrip(self, user, context: dict, message: bytes | str, data_classification: str) -> tuple[bool, object]:
        """Test-only compatibility helper: encrypt then immediately decrypt.

        Not for production use. Use encrypt() and decrypt() as explicit operations.
        """
        ok, pkg = self.encrypt(user, context, message, data_classification)
        if not ok:
            return False, pkg
        return self.decrypt(
            user, pkg.method, pkg.key_id,
            pkg.encrypted_aes_key, pkg.encrypted_message,
            data_classification,
            sender_public_key=pkg.sender_public_key,
            associated_data=pkg.aad,
        )

    def encrypt(self, user, context: dict, message: bytes | str, data_classification: str) -> tuple[bool, object]:
        """Governance-controlled encryption pipeline.

        Flow:
          0. Reject unauthenticated users — cannot be bypassed by external User construction
          1. Select encryption method via policy engine
          2. Authorize the user for the requested action and data classification
          3. Resolve the active key_id and load the public key
          4. Encrypt the message using the selected method
          5. Audit log the outcome — fail closed on success path

        Args:
            user: User object with username, role, and clearance attributes.
            context: Policy context dict (environment, compliance_level, etc.)
            message: Plaintext bytes or str to encrypt.
            data_classification: 'low', 'medium', or 'high'.

        Note:
            This in-memory pipeline authorizes against the caller-supplied
            ``data_classification``; it does NOT re-derive classification from
            user clearance and policy. The classification-authoritative path is
            the streaming file engine (``file_crypto_engine.stream_encrypt_file``),
            which computes the effective classification as ``max(user, policy)``
            and binds it into the signed container header. Callers of this API
            (and the demonstration agents in ``spy/agents/``) are responsible for
            supplying a correct classification.

        Returns:
            (True, EncryptedPackage) on success, or (False, reason_string) on failure.
        """
        # Phase 0 — Authentication gate: only users from auth.authenticate() may proceed.
        if not getattr(user, "authenticated", False):
            return False, "Authentication required"

        # Phase 1 — Policy selection
        method: str | None = None
        try:
            method = select_encryption_method(context)
        except PolicyError:
            try:
                AuditLogger.log_event(
                    user, action="ACCESS_DENIED",
                    classification=data_classification,
                    outcome="error",
                )
            except AuditLogError:
                return False, "Audit failure: operation aborted"
            return False, "Encryption failed"

        # Phase 2 — Authorization
        try:
            allowed, auth_reason = AuthorizationEngine.authorize(
                user=user, action="encrypt", data_classification=data_classification
            )
        except Exception:
            try:
                AuditLogger.log_event(
                    user, action="ACCESS_DENIED",
                    classification=data_classification,
                    outcome="error",
                )
            except AuditLogError:
                return False, "Audit failure: operation aborted"
            return False, "Encryption failed"

        if not allowed:
            try:
                AuditLogger.log_event(
                    user, action="ACCESS_DENIED",
                    classification=data_classification,
                    outcome="denied",
                )
            except AuditLogError:
                return False, "Audit failure: operation aborted"
            return False, "Encryption failed"

        # Phase 3 — Key resolution
        active_key_id: str | None = None
        try:
            if method == "rsa":
                active_key_id = self.key_provider.get_active_rsa_key_id()
                public_key = self.key_provider.get_rsa_public_key(active_key_id)
            else:  # ecc
                active_key_id = self.key_provider.get_active_ecc_key_id()
                receiver_public = self.key_provider.get_ecc_public_key(active_key_id)
        except KeyProviderError:
            try:
                AuditLogger.log_event(
                    user, action="ACCESS_DENIED",
                    classification=data_classification,
                    outcome="error",
                )
            except AuditLogError:
                return False, "Audit failure: operation aborted"
            return False, "Encryption failed"

        # Task A — key_id must be resolved before any crypto execution.
        if active_key_id is None:
            return False, "Encryption denied: no active key_id"

        # Phase 4 — Crypto operation (key_id is resolved; ENCRYPT action is safe)
        # Initialise variables needed by the decrypt round-trip below.
        aad: bytes = b""
        sender_public = None
        try:
            if method == "rsa":
                aad = _build_aad(method)
                pkg = encrypt_hybrid(
                    message, method=method, public_key=public_key, associated_data=aad
                )
            else:  # ecc
                sender_private = None
                try:
                    sender_private, sender_public = generate_ecc_keypair()
                    sender_public_bytes = serialize_public_key(sender_public)
                    aad = _build_aad(method, sender_public_bytes)
                    pkg = encrypt_hybrid(
                        message,
                        method=method,
                        public_key=receiver_public,
                        sender_private_key=sender_private,
                        associated_data=aad,
                    )
                finally:
                    sender_private = None  # Best-effort cleanup only — CPython/OpenSSL do not guarantee zeroization of key material
        except HybridEngineError:
            try:
                AuditLogger.log_event(
                    user, action="ENCRYPT",
                    classification=data_classification,
                    outcome="error", key_id=active_key_id,
                )
            except AuditLogError:
                return False, "Audit failure: operation aborted"
            return False, "Encryption failed"
        except Exception:
            try:
                AuditLogger.log_event(
                    user, action="ENCRYPT",
                    classification=data_classification,
                    outcome="error", key_id=active_key_id,
                )
            except AuditLogError:
                return False, "Audit failure: operation aborted"
            return False, "Encryption failed"

        # Phase 5 — Success audit: fail closed — audit failure stops execution.
        try:
            AuditLogger.log_event(
                user, action="ENCRYPT",
                classification=data_classification,
                outcome="success", key_id=active_key_id,
            )
        except AuditLogError:
            return False, "Audit failure: operation aborted"

        return True, _GovernancePackage(
            method=method,
            key_id=active_key_id,
            encrypted_aes_key=pkg.encrypted_aes_key,
            encrypted_message=pkg.encrypted_message,
            aad=aad,
            sender_public_key=sender_public,
        )

    def decrypt(self, user, method: str, key_id: str, encrypted_aes_key: bytes, encrypted_message: bytes, data_classification: str, sender_public_key=None, associated_data: bytes = b"") -> tuple[bool, object]:
        """Execute the governance-controlled decryption pipeline.

        NOTE: Internal/test-only. Not for production decryption.
        Production decrypt path is stream_decrypt_file() which reads
        classification from the authenticated SVST container header.
        Classification passed here is caller-supplied and not container-verified.

        Args:
            user: User object with username, role, and clearance attributes.
            method: 'rsa' or 'ecc'.
            encrypted_aes_key: Wrapped DEK from encryption result.
            encrypted_message: Ciphertext from encryption result.
            data_classification: 'low', 'medium', or 'high'.
            sender_public_key: ECC sender public key (required for ECC method).
            associated_data: AAD used during encryption.

        Returns:
            (True, plaintext_bytes) on success, or (False, reason_string) on failure.
        """
        # Phase 0 — Authentication gate: only users from auth.authenticate() may proceed.
        if not getattr(user, "authenticated", False):
            return False, "Authentication required"

        # Internal-only guard: production decryption must use stream_decrypt_file().
        if getattr(user, "role", "") != "admin":
            return False, "Internal decrypt not permitted"

        # Task A — key_id must be present before any crypto execution.
        if not key_id:
            return False, "Decryption denied"

        # Phase 1 — Authorization
        try:
            allowed, auth_reason = AuthorizationEngine.authorize(
                user=user, action="decrypt", data_classification=data_classification
            )
        except Exception:
            try:
                AuditLogger.log_event(
                    user, action="ACCESS_DENIED",
                    classification=data_classification,
                    outcome="error",
                )
            except AuditLogError:
                return False, "Audit failure: operation aborted"
            return False, "Decryption denied"

        if not allowed:
            try:
                AuditLogger.log_event(
                    user, action="ACCESS_DENIED",
                    classification=data_classification,
                    outcome="denied",
                )
            except AuditLogError:
                return False, "Audit failure: operation aborted"
            return False, "Decryption denied"

        # Phase 2 — Key resolution using the exact key_id from the encrypted artifact.
        # Never re-resolve to the active key; key rotation must not break existing artifacts.
        resolved_key_id: str = key_id
        try:
            if method == "rsa":
                private_key = self.key_provider.get_rsa_private_key(resolved_key_id)
            else:  # ecc
                private_key = self.key_provider.get_ecc_private_key(resolved_key_id)
        except KeyProviderError:
            try:
                AuditLogger.log_event(
                    user, action="ACCESS_DENIED",
                    classification=data_classification,
                    outcome="error",
                )
            except AuditLogError:
                return False, "Audit failure: operation aborted"
            return False, "Decryption denied"

        # Phase 3 — Crypto operation (key_id is resolved; DECRYPT action is safe)
        try:
            if method == "rsa":
                result = decrypt_hybrid(
                    method=method,
                    private_key=private_key,
                    encrypted_aes_key=encrypted_aes_key,
                    encrypted_message=encrypted_message,
                    associated_data=associated_data,
                )
            else:  # ecc
                result = decrypt_hybrid(
                    method=method,
                    private_key=private_key,
                    encrypted_aes_key=encrypted_aes_key,
                    encrypted_message=encrypted_message,
                    sender_public_key=sender_public_key,
                    associated_data=associated_data,
                )
        except HybridEngineError:
            try:
                AuditLogger.log_event(
                    user, action="DECRYPT",
                    classification=data_classification,
                    outcome="error", key_id=resolved_key_id,
                )
            except AuditLogError:
                return False, "Audit failure: operation aborted"
            return False, "Decryption denied"
        except Exception:
            try:
                AuditLogger.log_event(
                    user, action="DECRYPT",
                    classification=data_classification,
                    outcome="error", key_id=resolved_key_id,
                )
            except AuditLogError:
                return False, "Audit failure: operation aborted"
            return False, "Decryption denied"

        # Phase 4 — Success audit: fail closed.
        try:
            AuditLogger.log_event(
                user, action="DECRYPT",
                classification=data_classification,
                outcome="success", key_id=resolved_key_id,
            )
        except AuditLogError:
            return False, "Audit failure: operation aborted"

        return True, result
