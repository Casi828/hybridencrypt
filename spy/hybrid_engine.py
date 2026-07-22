"""
hybrid_engine.py — Single source of truth for hybrid encryption/decryption.

Combines AES-256-GCM (data encryption) with RSA or ECC (AES key protection).
All callers — CLI, governance pipeline, agents — must go through this module.
No file I/O or key persistence lives here.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidTag

from . import ecc_engine
from . import rsa_engine
from .crypto_engine import CryptoError, decrypt_message, encrypt_message, generate_key
from .governance_rules import GovernanceViolation, enforce_all

SUPPORTED_METHODS = frozenset({"rsa", "ecc"})


class HybridEngineError(Exception):
    pass


@dataclass(frozen=True)
class EncryptedPackage:
    """Immutable result of encrypt_hybrid. Pass fields to decrypt_hybrid or the container layer."""
    method: str
    encrypted_aes_key: bytes
    encrypted_message: bytes


def encrypt_hybrid(
    message: bytes | str,
    method: str,
    public_key,
    sender_private_key=None,
    associated_data: bytes | None = None,
) -> EncryptedPackage:
    """Encrypt a message using hybrid encryption (AES-256-GCM + RSA or ECC key wrap).

    Args:
        message: Plaintext bytes or str to encrypt.
        method: 'rsa' or 'ecc'.
        public_key: RSA or ECC public key used to wrap the AES key.
        sender_private_key: Required for ECC mode (sender's private key for ECDH).
        associated_data: Optional AAD bound into both the AES-GCM and ECC-wrap tags.

    Returns:
        EncryptedPackage with method, encrypted_aes_key, and encrypted_message.

    Raises:
        HybridEngineError: On unsupported method or missing ECC sender key.
    """
    method = str(method).lower().strip()
    if method not in SUPPORTED_METHODS:
        raise HybridEngineError("Encryption failed")

    if public_key is None:
        raise HybridEngineError("Encryption denied: no active key_id")

    try:
        enforce_all(method, private_key=sender_private_key)
    except GovernanceViolation:
        raise HybridEngineError("Encryption failed")

    aes_key = generate_key()
    encrypted_message = encrypt_message(aes_key, message, associated_data=associated_data)

    if method == "rsa":
        try:
            encrypted_aes_key = rsa_engine.wrap_key(public_key, aes_key)
        except rsa_engine.RSAEngineError:
            raise HybridEngineError("Encryption failed")
    else:
        if sender_private_key is None:
            raise HybridEngineError("Encryption failed")
        try:
            encrypted_aes_key = ecc_engine.wrap_key(
                sender_private_key, public_key, aes_key, associated_data=associated_data
            )
        except ecc_engine.ECCEngineError:
            raise HybridEngineError("Encryption failed")

    return EncryptedPackage(
        method=method,
        encrypted_aes_key=encrypted_aes_key,
        encrypted_message=encrypted_message,
    )


def decrypt_hybrid(
    method: str,
    private_key,
    encrypted_aes_key: bytes,
    encrypted_message: bytes,
    sender_public_key=None,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt a message produced by encrypt_hybrid.

    Args:
        method: 'rsa' or 'ecc'.
        private_key: RSA or ECC private key used to unwrap the AES key.
        encrypted_aes_key: Wrapped AES key bytes from encrypt_hybrid output.
        encrypted_message: AES-GCM ciphertext from encrypt_hybrid output.
        sender_public_key: Required for ECC mode (sender's public key for ECDH).
        associated_data: Must match the AAD used during encryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        HybridEngineError: On unsupported method, missing ECC sender key, or decryption failure.
    """
    method = str(method).lower().strip()
    if method not in SUPPORTED_METHODS:
        raise HybridEngineError("Decryption denied")

    if private_key is None:
        raise HybridEngineError("Decryption denied")

    try:
        enforce_all(method, private_key=private_key)
    except GovernanceViolation:
        raise HybridEngineError("Decryption denied")

    if method == "rsa":
        try:
            aes_key = rsa_engine.unwrap_key(private_key, encrypted_aes_key)
        except rsa_engine.RSAEngineError:
            raise HybridEngineError("Decryption denied")
    else:
        if sender_public_key is None:
            raise HybridEngineError("Decryption denied")
        try:
            aes_key = ecc_engine.unwrap_key(
                private_key, sender_public_key, encrypted_aes_key, associated_data=associated_data
            )
        except ecc_engine.ECCEngineError:
            raise HybridEngineError("Decryption denied")

    try:
        return decrypt_message(aes_key, encrypted_message, associated_data=associated_data)
    except (InvalidTag, CryptoError):
        raise HybridEngineError("Decryption denied")
