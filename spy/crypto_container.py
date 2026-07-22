"""
crypto_container.py — Single source of truth for encrypted container serialization.

JSON format (v2) — the only supported format:
  {
    "version": 2,
    "cipher": "AES-256-GCM",
    "key_wrap": "RSA-OAEP" | "ECDH-AES-GCM",
    "sig_alg": "RSA-PSS" | "ECDSA",        (identifies signing algorithm)
    "nonce": "<base64>",
    "wrapped_key": "<base64>",
    "ciphertext": "<base64>",
    "tag": "<base64>",
    "sender_public_key": "<base64>" (ECC only, omitted for RSA)
  }

This JSON container is always wrapped in a SENV signed envelope before being written
to disk. The SENV envelope encodes the sig algorithm as a binary method ID so
verification selects the correct key without guessing.

Legacy binary v1/v2 formats (AHGS magic and no-magic) are no longer supported.
Files produced by older versions must be re-encrypted.
"""

from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass

# Signed envelope format constants
# Layout: SENV (4) | version (1) | sig_method_id (1) | sig_len (4 BE) | sig_bytes | container_bytes
_SIGNED_MAGIC = b"SENV"
_SIGNED_VERSION = 1
_SIGNED_HEADER_SIZE = 10  # 4 magic + 1 version + 1 method_id + 4 sig_len
_SIG_METHOD_RSA = 1
_SIG_METHOD_ECC = 2
_SIG_METHOD_TO_ID: dict[str, int] = {"rsa": _SIG_METHOD_RSA, "ecc": _SIG_METHOD_ECC}
_SIG_ID_TO_METHOD: dict[int, str] = {_SIG_METHOD_RSA: "rsa", _SIG_METHOD_ECC: "ecc"}

CONTAINER_VERSION = 2
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16

# ---------------------------------------------------------------------------
# Streaming container format constants (SVST)
# Layout: SVST(4)|version(1)|key_wrap_id(1)|sig_method_id(1)|flags(1)
#         |wrapped_dek_len(2 BE)|wrapped_dek
#         [ECC only: sender_pubkey_len(2 BE)|sender_pubkey_raw]
#         |base_nonce(8)|sig_len(4 BE)|header_signature
#         followed by: [chunk_len(4 BE)|ciphertext+tag]*
# ---------------------------------------------------------------------------
STREAMING_MAGIC = b"SVST"
STREAMING_CONTAINER_VERSION = 1      # v1: no key_id in header
STREAMING_CONTAINER_VERSION_V2 = 2   # v2: encryption key_id embedded in signed region
STREAMING_CONTAINER_VERSION_V3 = 3   # v3: encryption key_id + signing key_id in signed region
STREAMING_CONTAINER_VERSION_V4 = 4   # v4: v3 + data_classification in signed region
KEY_WRAP_ID_RSA = 0x01
KEY_WRAP_ID_ECC = 0x02
SIG_METHOD_ID_RSA = 0x01
SIG_METHOD_ID_ECC = 0x02

KEY_WRAP_LABELS: dict[str, str] = {
    "rsa": "RSA-OAEP",
    "ecc": "ECDH-AES-GCM",
}

# Human-readable signature algorithm labels stored in the JSON container header.
SIG_ALGORITHM_LABELS: dict[str, str] = {
    "rsa": "RSA-PSS",
    "ecc": "ECDSA",
}


class ContainerError(Exception):
    pass


@dataclass(frozen=True)
class EncryptedContainer:
    method: str
    sender_public_bytes: bytes   # empty bytes for RSA
    encrypted_key: bytes
    encrypted_message: bytes     # nonce + ciphertext + tag (as in crypto_engine output)


# ---------------------------------------------------------------------------
# JSON encoding / decoding (current format)
# ---------------------------------------------------------------------------

def encode_container(
    method: str,
    encrypted_key: bytes,
    encrypted_message: bytes,
    sender_public_bytes: bytes = b"",
    signature_algorithm: str | None = None,
) -> bytes:
    """Serialize an encrypted package into the JSON container format.

    Args:
        method: 'rsa' or 'ecc' — determines key_wrap label.
        encrypted_key: Wrapped AES key bytes.
        encrypted_message: nonce + ciphertext + GCM tag bytes.
        sender_public_bytes: ECC sender public key (omitted for RSA).
        signature_algorithm: Human-readable signing algorithm (e.g. 'RSA-PSS' or 'ECDSA').
            Stored as 'sig_alg' in the header so the container is fully self-describing.
            Derived automatically from method if not provided.
    """
    method = method.lower().strip()
    if method not in KEY_WRAP_LABELS:
        raise ContainerError(f"Unsupported encryption method: {method!r}")

    if len(encrypted_message) < GCM_NONCE_SIZE + GCM_TAG_SIZE:
        raise ContainerError("encrypted_message is too short to contain nonce and tag")

    nonce = encrypted_message[:GCM_NONCE_SIZE]
    tag = encrypted_message[-GCM_TAG_SIZE:]
    ciphertext = encrypted_message[GCM_NONCE_SIZE:-GCM_TAG_SIZE]

    sig_alg = signature_algorithm or SIG_ALGORITHM_LABELS.get(method, "")

    container: dict = {
        "version": CONTAINER_VERSION,
        "cipher": "AES-256-GCM",
        "key_wrap": KEY_WRAP_LABELS[method],
        "sig_alg": sig_alg,
        "nonce": base64.b64encode(nonce).decode(),
        "wrapped_key": base64.b64encode(encrypted_key).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
    }
    if method == "ecc" and sender_public_bytes:
        container["sender_public_key"] = base64.b64encode(sender_public_bytes).decode()

    return json.dumps(container, separators=(",", ":")).encode("utf-8")


def decode_container(data: bytes) -> EncryptedContainer:
    """Deserialize a JSON v2 container extracted from a SENV signed envelope.

    Args:
        data: Raw JSON bytes from encode_container (as extracted by decode_signed_envelope).

    Returns:
        EncryptedContainer with parsed fields.

    Raises:
        ContainerError: If data is not valid JSON v2 format.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ContainerError("Container data must be bytes")

    try:
        obj = json.loads(data)  # accepts bytes directly (Python 3.6+)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContainerError("Invalid container format") from exc

    return _decode_json_container(obj)


def _decode_json_container(obj: dict) -> EncryptedContainer:
    """Parse a JSON container dict into an EncryptedContainer."""
    if not isinstance(obj, dict):
        raise ContainerError("JSON container must be an object")

    version = obj.get("version")
    if version != CONTAINER_VERSION:
        raise ContainerError(f"Unsupported container version: {version!r}")

    cipher = obj.get("cipher", "")
    if cipher != "AES-256-GCM":
        raise ContainerError(f"Unsupported cipher: {cipher!r}")

    key_wrap = obj.get("key_wrap", "")
    if key_wrap == "RSA-OAEP":
        method = "rsa"
    elif key_wrap == "ECDH-AES-GCM":
        method = "ecc"
    else:
        raise ContainerError(f"Unsupported key_wrap: {key_wrap!r}")

    try:
        nonce = base64.b64decode(obj["nonce"])
        wrapped_key = base64.b64decode(obj["wrapped_key"])
        ciphertext = base64.b64decode(obj["ciphertext"])
        tag = base64.b64decode(obj["tag"])
    # Intentional fail-closed catch-all: any missing field (KeyError) or malformed
    # base64 (binascii.Error) is mapped to a single generic ContainerError so no
    # parser detail leaks to the caller. (Exception already subsumes KeyError.)
    except Exception as exc:
        raise ContainerError("Invalid container format") from exc

    if len(nonce) != GCM_NONCE_SIZE:
        raise ContainerError(f"Invalid nonce length: {len(nonce)}")
    if len(tag) != GCM_TAG_SIZE:
        raise ContainerError(f"Invalid tag length: {len(tag)}")

    encrypted_message = nonce + ciphertext + tag

    sender_public_bytes = b""
    if method == "ecc" and "sender_public_key" in obj:
        try:
            sender_public_bytes = base64.b64decode(obj["sender_public_key"])
        except Exception as exc:
            raise ContainerError("Invalid container format") from exc

    return EncryptedContainer(
        method=method,
        sender_public_bytes=sender_public_bytes,
        encrypted_key=wrapped_key,
        encrypted_message=encrypted_message,
    )


# ---------------------------------------------------------------------------
# Signed envelope (wraps the JSON container with a detached signature)
# ---------------------------------------------------------------------------

def is_signed_envelope(data: bytes) -> bool:
    """Return True if data begins with the SENV signed envelope magic header."""
    return isinstance(data, (bytes, bytearray)) and len(data) >= 4 and data[:4] == _SIGNED_MAGIC


def is_streaming_container(data: bytes) -> bool:
    """Return True if data begins with the SVST streaming container magic header."""
    return isinstance(data, (bytes, bytearray)) and len(data) >= 4 and data[:4] == STREAMING_MAGIC


def encode_signed_envelope(container_bytes: bytes, signature: bytes, sig_method: str) -> bytes:
    """Wrap a serialized container in a signed envelope.

    Layout: SENV (4) | version (1) | method_id (1) | sig_len (4 BE uint32) | sig | container

    Args:
        container_bytes: Raw bytes from encode_container.
        signature: DER-encoded signature bytes over container_bytes.
        sig_method: 'rsa' or 'ecc' — identifies which signing key was used.

    Returns:
        Signed envelope bytes ready to write to disk.

    Raises:
        ContainerError: If sig_method is unknown or inputs are invalid.
    """
    if not isinstance(container_bytes, (bytes, bytearray)) or not container_bytes:
        raise ContainerError("container_bytes must be non-empty bytes")
    if not isinstance(signature, (bytes, bytearray)) or not signature:
        raise ContainerError("signature must be non-empty bytes")
    method_id = _SIG_METHOD_TO_ID.get(sig_method.lower() if sig_method else "")
    if method_id is None:
        raise ContainerError(f"Unknown sig_method: {sig_method!r}")
    header = (
        _SIGNED_MAGIC
        + struct.pack(">BB", _SIGNED_VERSION, method_id)
        + struct.pack(">I", len(signature))
    )
    return header + signature + container_bytes


def decode_signed_envelope(data: bytes) -> tuple[bytes, bytes, str]:
    """Parse a signed envelope into its component parts.

    Args:
        data: Raw bytes from disk (must start with SENV magic).

    Returns:
        (container_bytes, signature, sig_method) where sig_method is 'rsa' or 'ecc'.

    Raises:
        ContainerError: If the data is not a valid signed envelope or is truncated.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ContainerError("Data must be bytes")
    if len(data) < _SIGNED_HEADER_SIZE:
        raise ContainerError("Data too short to be a signed envelope")
    if data[:4] != _SIGNED_MAGIC:
        raise ContainerError("Not a signed envelope: missing SENV magic")
    version = data[4]
    if version != _SIGNED_VERSION:
        raise ContainerError(f"Unsupported signed envelope version: {version}")
    method_id = data[5]
    sig_method = _SIG_ID_TO_METHOD.get(method_id)
    if sig_method is None:
        raise ContainerError(f"Unknown signature method ID in envelope: {method_id}")
    (sig_len,) = struct.unpack(">I", data[6:10])
    if len(data) < _SIGNED_HEADER_SIZE + sig_len:
        raise ContainerError("Signed envelope is truncated: signature bytes missing")
    signature = bytes(data[_SIGNED_HEADER_SIZE: _SIGNED_HEADER_SIZE + sig_len])
    container_bytes = bytes(data[_SIGNED_HEADER_SIZE + sig_len:])
    if not container_bytes:
        raise ContainerError("Signed envelope has empty container payload")
    return container_bytes, signature, sig_method
