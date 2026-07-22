"""
crypto_engine.py — AES-256-GCM symmetric encryption primitives.

Responsibilities:
  - Generate cryptographically secure 256-bit AES keys
  - Encrypt plaintext with AES-256-GCM (nonce prepended to output)
  - Decrypt AES-256-GCM ciphertext and verify the authentication tag

The nonce (12 bytes) is prepended to the ciphertext output so the decrypt
function can extract it without out-of-band storage. Each encrypt call
generates a fresh random nonce via os.urandom.

No key persistence, no file I/O, and no asymmetric operations live here.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY_SIZE_BYTES = 32
GCM_NONCE_SIZE_BYTES = 12
GCM_TAG_SIZE_BYTES = 16
MIN_ENCRYPTED_SIZE_BYTES = GCM_NONCE_SIZE_BYTES + GCM_TAG_SIZE_BYTES

# Chunk size used by the streaming encrypt/decrypt functions.
STREAM_CHUNK_SIZE = 1 * 1024 * 1024  # 1 MiB


class CryptoError(Exception):
    pass


def _validate_aes_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise CryptoError("AES key must be bytes")
    if len(key) != AES_KEY_SIZE_BYTES:
        raise CryptoError(f"AES key must be {AES_KEY_SIZE_BYTES} bytes for AES-256-GCM")


def generate_key() -> bytes:
    """Generate a cryptographically secure random 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_message(key: bytes, plaintext: bytes | str, associated_data: bytes | None = None) -> bytes:
    """Encrypt plaintext with AES-256-GCM using a fresh random nonce.

    Args:
        key: 32-byte AES-256 key.
        plaintext: Data to encrypt (bytes or UTF-8 string).
        associated_data: Optional AAD authenticated but not encrypted.

    Returns:
        nonce (12 bytes) + ciphertext + GCM tag (16 bytes).

    Raises:
        CryptoError: If the key or plaintext type/length is invalid.
    """
    _validate_aes_key(key)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    elif not isinstance(plaintext, (bytes, bytearray)):
        raise CryptoError("Plaintext must be bytes or string")
    nonce = os.urandom(GCM_NONCE_SIZE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, bytes(plaintext), associated_data)
    return nonce + ciphertext


def decrypt_message(key: bytes, encrypted_data: bytes, associated_data: bytes | None = None) -> bytes:
    """Decrypt AES-256-GCM ciphertext and verify the authentication tag.

    Args:
        key: 32-byte AES-256 key used during encryption.
        encrypted_data: nonce + ciphertext + tag produced by encrypt_message.
        associated_data: Must match the AAD provided during encryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        CryptoError: If the payload is too short or the key/data are invalid types.
        cryptography.exceptions.InvalidTag: If the authentication tag does not match
            (ciphertext tampered or wrong key). Callers should catch this.
    """
    _validate_aes_key(key)
    if not isinstance(encrypted_data, (bytes, bytearray)):
        raise CryptoError("Encrypted data must be bytes")
    if len(encrypted_data) < MIN_ENCRYPTED_SIZE_BYTES:
        raise CryptoError(
            f"Encrypted payload is too short: {len(encrypted_data)} bytes "
            f"(minimum {MIN_ENCRYPTED_SIZE_BYTES})"
        )
    nonce = encrypted_data[:GCM_NONCE_SIZE_BYTES]
    ciphertext = encrypted_data[GCM_NONCE_SIZE_BYTES:]
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
