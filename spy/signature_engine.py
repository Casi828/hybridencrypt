"""
signature_engine.py — Digital signature support for RSA-PSS and ECDSA.

Workflow: encrypt → sign → verify → decrypt

Sign produces a detached signature over the ciphertext. Verify checks the
signature before decryption, providing protection against impersonation and
ciphertext tampering.

Algorithms:
  - RSA-PSS with SHA-256 (when RSA keys are available)
  - ECDSA with SHA-256 (when ECC keys are available)

Signatures are serialized as DER bytes for compact storage.
"""

from __future__ import annotations

import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils as asym_utils


class SignatureError(Exception):
    """Raised when signing or verification fails."""


# ---------------------------------------------------------------------------
# Standalone .sig file format (self-describing)
#
# Layout: SSIG (4) | version (1) | method_id (1) | sig_len (4 BE) | DER sig
# method_id: 1 = RSA-PSS, 2 = ECDSA
# ---------------------------------------------------------------------------

_SIG_MAGIC = b"SSIG"
_SIG_VERSION = 1    # v1: SSIG | version | method_id | sig_len(4BE) | DER sig
_SIG_VERSION_V2 = 2 # v2: SSIG | version | method_id | key_id_len(2BE) | key_id | sig_len(4BE) | DER sig
_SIG_HEADER_SIZE = 10  # v1 fixed header: 4 magic + 1 version + 1 method_id + 4 sig_len
_SIG_METHOD_TO_ID: dict[str, int] = {"rsa": 1, "ecc": 2}
_SIG_ID_TO_METHOD: dict[int, str] = {1: "rsa", 2: "ecc"}

_STREAM_CHUNK_SIZE = 1 << 20  # 1 MiB


def _iter_stream(source) -> bytes:
    """Yield fixed-size chunks from a file-like object or a bytes iterator.

    Accepts:
      - File-like objects (anything with a .read() method)
      - Iterables of bytes (chunk generators)

    Raises:
        SignatureError: If a yielded item is not bytes.
    """
    if hasattr(source, "read"):
        while True:
            chunk = source.read(_STREAM_CHUNK_SIZE)
            if not chunk:
                break
            if not isinstance(chunk, (bytes, bytearray)):
                raise SignatureError("Stream returned non-bytes chunk")
            yield chunk
    else:
        for chunk in source:
            if not isinstance(chunk, (bytes, bytearray)):
                raise SignatureError("Stream yielded non-bytes chunk")
            yield chunk


def encode_sig_file(method: str, signature: bytes, key_id: str | None = None) -> bytes:
    """Encode a DER signature into a self-describing .sig file.

    The file header embeds the algorithm so verify needs no --method flag.
    When key_id is provided the output uses SSIG v2 format, which embeds the
    signing key identity so verification can route by key_id rather than by
    algorithm prefix. v1 format (no key_id) is written when key_id is None.

    SSIG v1: SSIG | 0x01 | method_id | sig_len(4BE) | DER sig
    SSIG v2: SSIG | 0x02 | method_id | key_id_len(2BE) | key_id | sig_len(4BE) | DER sig

    Args:
        method: 'rsa' or 'ecc'.
        signature: DER-encoded signature bytes from sign().
        key_id: Optional signing key identifier. When provided, writes SSIG v2.

    Returns:
        Bytes ready to write to a .sig file.

    Raises:
        SignatureError: If method is unsupported or inputs are invalid.
    """
    method_id = _SIG_METHOD_TO_ID.get(method.lower().strip() if method else "")
    if method_id is None:
        raise SignatureError(f"Unsupported signature method: {method!r}")
    if not isinstance(signature, (bytes, bytearray)) or not signature:
        raise SignatureError("Signature must be non-empty bytes")

    if key_id is not None:
        # SSIG v2: include signing key_id.
        if not isinstance(key_id, str) or not key_id:
            raise SignatureError("key_id must be a non-empty string")
        try:
            key_id_bytes = key_id.encode("ascii")
        except UnicodeEncodeError as exc:
            raise SignatureError("key_id encoding error") from exc
        if len(key_id_bytes) > 65535:
            raise SignatureError("key_id is too long (max 65535 bytes)")
        header = (
            _SIG_MAGIC
            + struct.pack(">BB", _SIG_VERSION_V2, method_id)
            + struct.pack(">H", len(key_id_bytes))
            + key_id_bytes
            + struct.pack(">I", len(signature))
        )
    else:
        # SSIG v1: no key_id (backward compatible).
        header = _SIG_MAGIC + struct.pack(">BB", _SIG_VERSION, method_id) + struct.pack(">I", len(signature))

    return header + signature


def decode_sig_file_full(data: bytes) -> tuple[str, bytes, str | None]:
    """Decode a self-describing .sig file into (method, der_signature, key_id).

    Supports both SSIG v1 (key_id=None) and SSIG v2 (key_id populated).

    Args:
        data: Raw bytes from a .sig file.

    Returns:
        (method, signature, key_id) where method is 'rsa' or 'ecc' and
        key_id is the signing key identifier (None for v1 files).

    Raises:
        SignatureError: If the file is not a valid SSIG file or is truncated.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise SignatureError("Signature file data must be bytes")
    if len(data) < _SIG_HEADER_SIZE:
        raise SignatureError("Signature file is too short to contain a valid header")
    if data[:4] != _SIG_MAGIC:
        raise SignatureError(
            "Not a valid signature file: missing SSIG header.\n"
            "This file may have been produced by an older version — re-sign the file."
        )
    version = data[4]
    if version not in (_SIG_VERSION, _SIG_VERSION_V2):
        raise SignatureError(f"Unsupported signature file version: {version}")
    method_id = data[5]
    method = _SIG_ID_TO_METHOD.get(method_id)
    if method is None:
        raise SignatureError(f"Unknown signature method ID in file: {method_id}")

    if version == _SIG_VERSION:
        # v1: fixed header, no key_id.
        (sig_len,) = struct.unpack(">I", data[6:10])
        if len(data) < _SIG_HEADER_SIZE + sig_len:
            raise SignatureError("Signature file is truncated: DER bytes missing")
        return method, bytes(data[_SIG_HEADER_SIZE: _SIG_HEADER_SIZE + sig_len]), None

    # v2: key_id_len(2BE) + key_id + sig_len(4BE) + DER sig
    _V2_MIN_HEADER = 8  # 4 magic + 1 version + 1 method_id + 2 key_id_len
    if len(data) < _V2_MIN_HEADER:
        raise SignatureError("SSIG v2 file is too short to contain key_id_len")
    (key_id_len,) = struct.unpack(">H", data[6:8])
    if key_id_len == 0:
        raise SignatureError("SSIG v2 key_id_len is 0")
    key_id_end = 8 + key_id_len
    if len(data) < key_id_end + 4:
        raise SignatureError("SSIG v2 file is truncated: key_id or sig_len missing")
    try:
        key_id = data[8:key_id_end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise SignatureError("key_id encoding error") from exc
    (sig_len,) = struct.unpack(">I", data[key_id_end: key_id_end + 4])
    sig_start = key_id_end + 4
    if len(data) < sig_start + sig_len:
        raise SignatureError("SSIG v2 file is truncated: DER bytes missing")
    return method, bytes(data[sig_start: sig_start + sig_len]), key_id


def decode_sig_file(data: bytes) -> tuple[str, bytes]:
    """Decode a self-describing .sig file into (method, der_signature).

    Supports both SSIG v1 and v2. The signing key_id embedded in v2 files is
    silently dropped; use decode_sig_file_full() to retrieve it.

    Args:
        data: Raw bytes from a .sig file.

    Returns:
        (method, signature) where method is 'rsa' or 'ecc'.

    Raises:
        SignatureError: If the file is not a valid SSIG file or is truncated.
    """
    method, signature, _ = decode_sig_file_full(data)
    return method, signature


# ---------------------------------------------------------------------------
# RSA-PSS
# ---------------------------------------------------------------------------

_RSA_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def sign_rsa(private_key, data: bytes) -> bytes:
    """Sign data with an RSA private key using RSA-PSS/SHA-256.

    Args:
        private_key: RSA private key object.
        data: Bytes to sign (typically ciphertext or its hash).

    Returns:
        DER-encoded RSA-PSS signature bytes.

    Raises:
        SignatureError: If signing fails.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise SignatureError("Data to sign must be bytes")
    try:
        return private_key.sign(data, _RSA_PSS_PADDING, hashes.SHA256())
    except (ValueError, TypeError) as exc:
        raise SignatureError("Signing failed") from exc


def verify_rsa(public_key, signature: bytes, data: bytes) -> None:
    """Verify an RSA-PSS/SHA-256 signature.

    Args:
        public_key: RSA public key object.
        signature: DER-encoded signature bytes produced by sign_rsa.
        data: Original data that was signed.

    Raises:
        SignatureError: If the signature is invalid or verification fails.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise SignatureError("Data to verify must be bytes")
    try:
        public_key.verify(signature, data, _RSA_PSS_PADDING, hashes.SHA256())
    except InvalidSignature as exc:
        raise SignatureError("RSA-PSS signature verification failed: signature is invalid") from exc
    except (ValueError, TypeError) as exc:
        raise SignatureError("Verification failed") from exc


# ---------------------------------------------------------------------------
# ECDSA
# ---------------------------------------------------------------------------

def sign_ecdsa(private_key, data: bytes) -> bytes:
    """Sign data with an ECC private key using ECDSA/SHA-256.

    Args:
        private_key: ECC private key object (SECP256R1 or similar).
        data: Bytes to sign.

    Returns:
        DER-encoded ECDSA signature bytes.

    Raises:
        SignatureError: If signing fails.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise SignatureError("Data to sign must be bytes")
    try:
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    except (ValueError, TypeError) as exc:
        raise SignatureError("Signing failed") from exc


def verify_ecdsa(public_key, signature: bytes, data: bytes) -> None:
    """Verify an ECDSA/SHA-256 signature.

    Args:
        public_key: ECC public key object.
        signature: DER-encoded signature bytes produced by sign_ecdsa.
        data: Original data that was signed.

    Raises:
        SignatureError: If the signature is invalid or verification fails.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise SignatureError("Data to verify must be bytes")
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise SignatureError("ECDSA signature verification failed: signature is invalid") from exc
    except (ValueError, TypeError) as exc:
        raise SignatureError("Verification failed") from exc


# ---------------------------------------------------------------------------
# Unified interface
# ---------------------------------------------------------------------------

def sign(method: str, private_key, data: bytes) -> bytes:
    """Sign data using the specified method ('rsa' or 'ecc').

    Args:
        method: 'rsa' uses RSA-PSS; 'ecc' uses ECDSA.
        private_key: Corresponding private key.
        data: Bytes to sign.

    Returns:
        DER-encoded signature bytes.

    Raises:
        SignatureError: On unsupported method or signing failure.
    """
    method = method.lower().strip()
    if method == "rsa":
        return sign_rsa(private_key, data)
    if method == "ecc":
        return sign_ecdsa(private_key, data)
    raise SignatureError(f"Unsupported signature method: {method!r}")


def verify(method: str, public_key, signature: bytes, data: bytes) -> None:
    """Verify a signature using the specified method ('rsa' or 'ecc').

    Args:
        method: 'rsa' uses RSA-PSS; 'ecc' uses ECDSA.
        public_key: Corresponding public key.
        signature: DER-encoded signature bytes.
        data: Original signed data.

    Raises:
        SignatureError: If the signature is invalid or the method is unsupported.
    """
    method = method.lower().strip()
    if method == "rsa":
        return verify_rsa(public_key, signature, data)
    if method == "ecc":
        return verify_ecdsa(public_key, signature, data)
    raise SignatureError(f"Unsupported signature method: {method!r}")


# ---------------------------------------------------------------------------
# Key-identity-aware interface
# ---------------------------------------------------------------------------

def sign_with_key_id(method: str, private_key, key_id: str, data: bytes) -> dict:
    """Sign data and embed key_id in the returned artifact.

    Args:
        method: 'rsa' or 'ecc'.
        private_key: Signing private key.
        key_id: Identifier of the signing key (for verification routing).
        data: Bytes to sign.

    Returns:
        dict with keys 'key_id' (str) and 'signature' (DER bytes).

    Raises:
        SignatureError: If method is unsupported or signing fails.
    """
    if not key_id or not isinstance(key_id, str):
        raise SignatureError("key_id must be a non-empty string")
    signature = sign(method, private_key, data)
    return {"key_id": key_id, "signature": signature}


def verify_with_key_id(method: str, signed_artifact: dict, data: bytes, provider) -> None:
    """Verify a signed artifact, resolving the signing key via provider.

    Args:
        method: 'rsa' or 'ecc'.
        signed_artifact: dict produced by sign_with_key_id, containing
                         'key_id' and 'signature'.
        data: Original signed data.
        provider: KeyProvider instance. Must implement
                  get_signing_public_key(key_id).

    Raises:
        SignatureError: If key_id is missing, key cannot be resolved,
                        or signature is invalid.
    """
    if not isinstance(signed_artifact, dict):
        raise SignatureError("signed_artifact must be a dict")
    key_id = signed_artifact.get("key_id")
    if not key_id:
        raise SignatureError("Signed artifact missing key_id")
    signature = signed_artifact.get("signature")
    if not signature:
        raise SignatureError("Signed artifact missing signature")
    try:
        public_key = provider.get_signing_public_key(key_id)
    except Exception as exc:
        raise SignatureError("Signing key not available") from exc
    verify(method, public_key, signature, data)


# ---------------------------------------------------------------------------
# Streaming interface — sign/verify without loading the full payload into memory
# ---------------------------------------------------------------------------

def sign_stream(method: str, private_key, source) -> bytes:
    """Sign a stream incrementally using SHA-256 prehashing.

    Hashes the stream in chunks, then signs the final digest. The full
    payload is never held in memory simultaneously.

    Args:
        method: 'rsa' uses RSA-PSS; 'ecc' uses ECDSA.
        private_key: Corresponding private key.
        source: File-like object (has .read()) or an iterable of bytes chunks.

    Returns:
        DER-encoded signature bytes.

    Raises:
        SignatureError: On unsupported method, bad input, or signing failure.
    """
    method = method.lower().strip()
    if method not in ("rsa", "ecc"):
        raise SignatureError(f"Unsupported signature method: {method!r}")
    hasher = hashes.Hash(hashes.SHA256())
    try:
        for chunk in _iter_stream(source):
            hasher.update(chunk)
        digest = hasher.finalize()
    except SignatureError:
        raise
    except Exception as exc:
        raise SignatureError("Stream hashing failed") from exc
    try:
        if method == "rsa":
            return private_key.sign(
                digest, _RSA_PSS_PADDING, asym_utils.Prehashed(hashes.SHA256())
            )
        return private_key.sign(
            digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()))
        )
    except (ValueError, TypeError) as exc:
        raise SignatureError("Signing failed") from exc


def verify_stream(method: str, public_key, signature: bytes, source) -> None:
    """Verify a signature over a stream incrementally using SHA-256 prehashing.

    Hashes the stream in chunks, then verifies the signature against the
    final digest. The full payload is never held in memory simultaneously.

    Args:
        method: 'rsa' uses RSA-PSS; 'ecc' uses ECDSA.
        public_key: Corresponding public key.
        signature: DER-encoded signature bytes produced by sign_stream.
        source: File-like object (has .read()) or an iterable of bytes chunks.

    Raises:
        SignatureError: If the signature is invalid, the method is unsupported,
                        or stream reading fails.
    """
    method = method.lower().strip()
    if method not in ("rsa", "ecc"):
        raise SignatureError(f"Unsupported signature method: {method!r}")
    if not isinstance(signature, (bytes, bytearray)) or not signature:
        raise SignatureError("Signature must be non-empty bytes")
    hasher = hashes.Hash(hashes.SHA256())
    try:
        for chunk in _iter_stream(source):
            hasher.update(chunk)
        digest = hasher.finalize()
    except SignatureError:
        raise
    except Exception as exc:
        raise SignatureError("Stream hashing failed") from exc
    try:
        if method == "rsa":
            public_key.verify(
                signature, digest, _RSA_PSS_PADDING, asym_utils.Prehashed(hashes.SHA256())
            )
        else:
            public_key.verify(
                signature, digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()))
            )
    except InvalidSignature as exc:
        raise SignatureError("Streaming signature verification failed: signature is invalid") from exc
    except (ValueError, TypeError) as exc:
        raise SignatureError("Verification failed") from exc
