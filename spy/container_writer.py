"""
container_writer.py — SVST streaming container writer.

Serializes an encrypted file in the SVST chunked format:
  Header: magic | version | key_wrap_id | sig_method_id | flags |
          wrapped_dek_len | wrapped_dek
          [ECC only: sender_pubkey_len | sender_pubkey_raw]
          base_nonce
          [v2/v3/v4: key_id_len (2 BE) | key_id (ASCII)]
          [v3/v4:    sign_key_id_len (2 BE) | sign_key_id (ASCII)]
          [v4:       classification_len (1) | classification (ASCII)]
          sig_len | header_signature
  Body:   [chunk_len (4 BE) | AES-256-GCM(plaintext_chunk)]*

The header signature covers all bytes from magic through the last version-specific
field (the "signed region") — i.e. everything before sig_len.
Each chunk is encrypted with a unique nonce derived from base_nonce + chunk_index,
and bound to chunk_index + is_last via AAD so reordering and truncation are detected.

``build_signed_region()`` is the single authority for that byte layout. Every code
path that emits an SVST header — the streaming encrypt path via
``StreamingContainerWriter.write_header()`` and the DEK rewrap path in
``file_crypto_engine.py`` — assembles its header through that one function, so the
wire format and its validation rules cannot drift between them. It is pure and
stateless: no I/O, no signing, no hashing, no writer state.

No key loading — callers supply pre-loaded signing keys and pre-wrapped DEK bytes.
"""

from __future__ import annotations

import hashlib
import os
import struct
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto_container import (
    KEY_WRAP_ID_ECC,
    KEY_WRAP_ID_RSA,
    SIG_METHOD_ID_ECC,
    SIG_METHOD_ID_RSA,
    STREAMING_CONTAINER_VERSION,
    STREAMING_CONTAINER_VERSION_V2,
    STREAMING_CONTAINER_VERSION_V3,
    STREAMING_CONTAINER_VERSION_V4,
    STREAMING_MAGIC,
)
from .crypto_engine import STREAM_CHUNK_SIZE
from .signature_engine import SignatureError, sign

_BASE_NONCE_SIZE = 8      # random prefix shared by all chunks
_CHUNK_NONCE_SIZE = 12    # base_nonce(8) + chunk_index(4)
# Max length for any header field serialized with a 2-byte (>H) length prefix.
_MAX_U16_FIELD_LEN = 0xFFFF   # 65535
# Max length for the classification field, serialized with a 1-byte (>B) length prefix.
_MAX_CLASSIFICATION_LEN = 0xFF   # 255

# Container versions this module can serialize.
_SUPPORTED_VERSIONS = (
    STREAMING_CONTAINER_VERSION,
    STREAMING_CONTAINER_VERSION_V2,
    STREAMING_CONTAINER_VERSION_V3,
    STREAMING_CONTAINER_VERSION_V4,
)
# Which versions carry each optional signed-region field. A field must be present
# for exactly the versions listed here and absent (None) for every other version —
# writing a field the reader will not parse produces an unreadable container.
_VERSIONS_WITH_KEY_ID = (
    STREAMING_CONTAINER_VERSION_V2,
    STREAMING_CONTAINER_VERSION_V3,
    STREAMING_CONTAINER_VERSION_V4,
)
_VERSIONS_WITH_SIGN_KEY_ID = (
    STREAMING_CONTAINER_VERSION_V3,
    STREAMING_CONTAINER_VERSION_V4,
)
_VERSIONS_WITH_CLASSIFICATION = (STREAMING_CONTAINER_VERSION_V4,)


class ContainerWriterError(Exception):
    pass


def _encode_ascii_field(value, field_name: str, max_len: int) -> bytes:
    """ASCII-encode a header string field, enforcing type, emptiness, and length.

    Empty values are rejected because the reader treats a zero-length key_id,
    sign_key_id, or classification as a malformed container.
    """
    if not isinstance(value, str):
        raise ContainerWriterError(f"{field_name} must be a string")
    if not value:
        raise ContainerWriterError(f"{field_name} must not be empty")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ContainerWriterError("Header encoding error") from exc
    if len(encoded) > max_len:
        raise ContainerWriterError(
            f"{field_name} too long: {len(encoded)} bytes (max {max_len})"
        )
    return encoded


def build_signed_region(
    *,
    version: int,
    key_wrap_id: int,
    sig_method_id: int,
    wrapped_dek: bytes,
    sender_pubkey_raw: bytes | None,
    base_nonce: bytes,
    key_id: str | None,
    sign_key_id: str | None,
    classification: str | None,
) -> bytes:
    """Assemble the SVST header signed region for *version* and return its bytes.

    This is the single authority for the SVST header byte layout. It is pure and
    stateless — it performs no I/O, no signing, no hashing, and holds no writer
    state — so both the encrypt path and the rewrap path can share it without one
    reaching into the other's internals.

    Because the rewrap path calls this function directly and never constructs a
    ``StreamingContainerWriter``, this function owns *all* header validation,
    including the checks the writer constructor also performs.

    Args:
        version: One of the supported STREAMING_CONTAINER_VERSION* constants.
        key_wrap_id: KEY_WRAP_ID_RSA or KEY_WRAP_ID_ECC.
        sig_method_id: SIG_METHOD_ID_RSA or SIG_METHOD_ID_ECC.
        wrapped_dek: Non-empty wrapped DEK bytes, at most 65535 bytes.
        sender_pubkey_raw: ``None`` for RSA; non-empty raw point bytes for ECC.
                           There is no empty-bytes sentinel — ``b""`` is rejected.
        base_nonce: Exactly ``_BASE_NONCE_SIZE`` bytes.
        key_id: Encryption key_id. Required for v2/v3/v4, must be None for v1.
        sign_key_id: Signing key_id. Required for v3/v4, must be None for v1/v2.
        classification: Data classification. Required for v4, must be None otherwise.

    Returns:
        The signed-region bytes: magic through the last version-specific field.
        The caller signs these bytes and writes them followed by
        ``sig_len (4 BE) || signature``.

    Raises:
        ContainerWriterError: On any invalid, missing, or forbidden field. The
            message is sanitized — it never contains key or plaintext material.
    """
    # ---------- version ----------
    if version not in _SUPPORTED_VERSIONS:
        raise ContainerWriterError(f"Unsupported container version: {version!r}")

    # ---------- algorithm identifiers ----------
    if key_wrap_id not in (KEY_WRAP_ID_RSA, KEY_WRAP_ID_ECC):
        raise ContainerWriterError(f"Unknown key_wrap_id: {key_wrap_id!r}")
    if sig_method_id not in (SIG_METHOD_ID_RSA, SIG_METHOD_ID_ECC):
        raise ContainerWriterError(f"Unknown sig_method_id: {sig_method_id!r}")

    # ---------- wrapped DEK ----------
    if not isinstance(wrapped_dek, (bytes, bytearray)):
        raise ContainerWriterError("wrapped_dek must be bytes")
    if not wrapped_dek:
        raise ContainerWriterError("wrapped_dek must not be empty")
    wrapped_dek_len = len(wrapped_dek)
    if wrapped_dek_len > _MAX_U16_FIELD_LEN:
        raise ContainerWriterError(
            f"wrapped_dek too large: {wrapped_dek_len} bytes (max {_MAX_U16_FIELD_LEN})"
        )

    # ---------- sender public key (ECC only, no empty sentinel) ----------
    if key_wrap_id == KEY_WRAP_ID_RSA:
        if sender_pubkey_raw is not None:
            raise ContainerWriterError("sender_pubkey_raw must be None for RSA mode")
    else:
        if not isinstance(sender_pubkey_raw, (bytes, bytearray)):
            raise ContainerWriterError("sender_pubkey_raw required for ECC mode")
        if not sender_pubkey_raw:
            raise ContainerWriterError("sender_pubkey_raw required for ECC mode")
        if len(sender_pubkey_raw) > _MAX_U16_FIELD_LEN:
            raise ContainerWriterError(
                f"sender_pubkey_raw too large: {len(sender_pubkey_raw)} bytes "
                f"(max {_MAX_U16_FIELD_LEN})"
            )

    # ---------- base nonce ----------
    if not isinstance(base_nonce, (bytes, bytearray)):
        raise ContainerWriterError("base_nonce must be bytes")
    if len(base_nonce) != _BASE_NONCE_SIZE:
        raise ContainerWriterError(
            f"base_nonce must be exactly {_BASE_NONCE_SIZE} bytes, got {len(base_nonce)}"
        )

    # ---------- per-version field invariants ----------
    # Each optional field is required for exactly the versions that define it and
    # forbidden for all others. Enforced here so no caller can emit a header whose
    # payload disagrees with its version byte.
    for _name, _value, _required in (
        ("key_id", key_id, version in _VERSIONS_WITH_KEY_ID),
        ("sign_key_id", sign_key_id, version in _VERSIONS_WITH_SIGN_KEY_ID),
        ("classification", classification, version in _VERSIONS_WITH_CLASSIFICATION),
    ):
        if _required and _value is None:
            raise ContainerWriterError(
                f"{_name} is required for v{version} containers"
            )
        if not _required and _value is not None:
            raise ContainerWriterError(
                f"{_name} is not permitted in v{version} containers"
            )

    # ---------- assemble ----------
    signed_region = (
        STREAMING_MAGIC
        + struct.pack(
            ">BBBB",
            version,
            key_wrap_id,
            sig_method_id,
            0x00,  # flags (reserved)
        )
        + struct.pack(">H", wrapped_dek_len)
        + bytes(wrapped_dek)
    )

    if key_wrap_id == KEY_WRAP_ID_ECC:
        signed_region += (
            struct.pack(">H", len(sender_pubkey_raw)) + bytes(sender_pubkey_raw)
        )

    signed_region += bytes(base_nonce)

    # v2/v3/v4: encryption key_id_len (2 BE) + key_id (ASCII).
    if key_id is not None:
        key_id_bytes = _encode_ascii_field(key_id, "key_id", _MAX_U16_FIELD_LEN)
        signed_region += struct.pack(">H", len(key_id_bytes)) + key_id_bytes

    # v3/v4: signing key_id_len (2 BE) + sign_key_id (ASCII).
    if sign_key_id is not None:
        sign_key_id_bytes = _encode_ascii_field(
            sign_key_id, "sign_key_id", _MAX_U16_FIELD_LEN
        )
        signed_region += struct.pack(">H", len(sign_key_id_bytes)) + sign_key_id_bytes

    # v4: classification_len (1 byte) + classification (ASCII).
    if classification is not None:
        cls_bytes = _encode_ascii_field(
            classification, "classification", _MAX_CLASSIFICATION_LEN
        )
        signed_region += struct.pack(">B", len(cls_bytes)) + cls_bytes

    return signed_region


class StreamingContainerWriter:
    """Writes an SVST streaming encrypted container to a binary output stream.

    Usage::

        writer = StreamingContainerWriter(
            out_file, key_wrap_id, sig_method_id,
            wrapped_dek, sender_pubkey_raw, sign_private_key, aes_key
        )
        writer.write_header()
        writer.write_chunks(in_file)
        writer.close()
    """

    def __init__(
        self,
        out_file: BinaryIO,
        key_wrap_id: int,
        sig_method_id: int,
        wrapped_dek: bytes,
        sender_pubkey_raw: bytes | None,
        sign_private_key,
        aes_key: bytes,
        chunk_size: int = STREAM_CHUNK_SIZE,
        key_id: str | None = None,
        sign_key_id: str | None = None,
        classification: str | None = None,
    ) -> None:
        if key_wrap_id not in (KEY_WRAP_ID_RSA, KEY_WRAP_ID_ECC):
            raise ContainerWriterError(f"Unknown key_wrap_id: {key_wrap_id!r}")
        if sig_method_id not in (SIG_METHOD_ID_RSA, SIG_METHOD_ID_ECC):
            raise ContainerWriterError(f"Unknown sig_method_id: {sig_method_id!r}")
        if not wrapped_dek:
            raise ContainerWriterError("wrapped_dek must not be empty")
        if key_wrap_id == KEY_WRAP_ID_ECC and not sender_pubkey_raw:
            raise ContainerWriterError("sender_pubkey_raw required for ECC mode")
        if not aes_key:
            raise ContainerWriterError("aes_key must not be empty")
        if not (1 <= chunk_size <= 64 * 1024 * 1024):
            raise ContainerWriterError("chunk_size must be between 1 and 64 MiB")

        self._out = out_file
        self._key_wrap_id = key_wrap_id
        self._sig_method_id = sig_method_id
        self._wrapped_dek = wrapped_dek
        # Preserved as-is: None for RSA, non-empty bytes for ECC. Never normalized
        # to b"" — build_signed_region() rejects an empty-bytes sentinel, and an
        # RSA header must pass None rather than b"".
        self._sender_pubkey_raw: bytes | None = sender_pubkey_raw
        self._sign_private_key = sign_private_key
        self._aes_key = aes_key
        self._chunk_size = chunk_size
        self._key_id: str | None = key_id
        self._sign_key_id: str | None = sign_key_id
        self._classification: str | None = classification
        self._base_nonce: bytes | None = None
        self._header_written = False
        self._body_hash = hashlib.sha256()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def write_header(self) -> None:
        """Build, sign, and write the SVST header to the output stream."""
        if self._header_written:
            raise ContainerWriterError("write_header() called more than once")

        self._base_nonce = os.urandom(_BASE_NONCE_SIZE)

        # If classification is provided, both key_ids must also be present — otherwise the
        # container cannot be V4 and writing classification bytes would produce a malformed
        # container (version mismatch with payload).
        if self._classification is not None:
            if self._key_id is None or self._sign_key_id is None:
                raise ContainerWriterError(
                    "classification requires both key_id and sign_key_id (V4 container)"
                )

        # Select container version:
        #   v4 when classification + both key_ids present (authenticated classification binding).
        #   v3 when both encryption key_id and signing key_id are present.
        #   v2 when only encryption key_id is present.
        #   v1 when no key_id is present (legacy).
        if self._classification is not None and self._sign_key_id is not None and self._key_id is not None:
            container_version = STREAMING_CONTAINER_VERSION_V4
        elif self._sign_key_id is not None and self._key_id is not None:
            container_version = STREAMING_CONTAINER_VERSION_V3
        elif self._key_id is not None:
            container_version = STREAMING_CONTAINER_VERSION_V2
        else:
            container_version = STREAMING_CONTAINER_VERSION

        # Assemble the signed region through the shared serializer — the single
        # authority for the SVST header byte layout and its validation rules.
        signed_region = build_signed_region(
            version=container_version,
            key_wrap_id=self._key_wrap_id,
            sig_method_id=self._sig_method_id,
            wrapped_dek=self._wrapped_dek,
            sender_pubkey_raw=self._sender_pubkey_raw,
            base_nonce=self._base_nonce,
            key_id=self._key_id,
            sign_key_id=self._sign_key_id,
            classification=self._classification,
        )

        # Seed the body hash with the header-authenticated region so the body
        # signature binds to both the header data and the ciphertext body.
        self._body_hash.update(signed_region)

        # Sign the assembled header region.
        sig_method = "rsa" if self._sig_method_id == SIG_METHOD_ID_RSA else "ecc"
        try:
            signature = sign(sig_method, self._sign_private_key, signed_region)
        except SignatureError as exc:
            raise ContainerWriterError("Header signing failed") from exc

        # Write: signed_region || sig_len (4 BE uint32) || signature
        self._out.write(signed_region)
        self._out.write(struct.pack(">I", len(signature)))
        self._out.write(signature)

        self._header_written = True

    def write_chunks(self, in_file: BinaryIO) -> None:
        """Read plaintext from *in_file* in chunks and write encrypted chunks.

        Always emits at least one chunk (terminal). For empty input, emits a
        zero-byte terminal chunk so the decoder can confirm the file is complete.
        """
        if not self._header_written:
            raise ContainerWriterError("Must call write_header() before write_chunks()")

        aesgcm = AESGCM(self._aes_key)
        chunk_index = 0

        # Read first chunk; then peek ahead so we know when we're on the last one.
        current = in_file.read(self._chunk_size)

        while True:
            nxt = in_file.read(self._chunk_size)
            is_last = len(nxt) == 0

            self._write_chunk(aesgcm, chunk_index, current, is_last)
            chunk_index += 1

            if is_last:
                break
            current = nxt

    def close(self) -> None:
        """Sign the body digest and write the body signature trailer, then flush."""
        digest = self._body_hash.digest()
        sig_method = "rsa" if self._sig_method_id == SIG_METHOD_ID_RSA else "ecc"
        try:
            body_sig = sign(sig_method, self._sign_private_key, digest)
        except SignatureError as exc:
            raise ContainerWriterError("Body signing failed") from exc
        # Trailer layout: [ body_signature ][ sig_len (4 BE) ]
        self._out.write(body_sig)
        self._out.write(struct.pack(">I", len(body_sig)))
        self._out.flush()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_chunk(
        self, aesgcm: AESGCM, chunk_index: int, plaintext: bytes, is_last: bool
    ) -> None:
        """Encrypt *plaintext* as chunk *chunk_index* and write it to the output."""
        # Nonce: base_nonce (8 bytes) || chunk_index (4 bytes BE) = 12 bytes
        nonce = self._base_nonce + struct.pack(">I", chunk_index)  # type: ignore[operator]

        # AAD: magic(4) || version(1) || chunk_index(4 BE) || is_last(1)
        aad = (
            STREAMING_MAGIC
            + struct.pack(">B", STREAMING_CONTAINER_VERSION)
            + struct.pack(">I", chunk_index)
            + (b"\x01" if is_last else b"\x00")
        )

        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, aad)

        serialized_chunk = struct.pack(">I", len(ciphertext_and_tag)) + ciphertext_and_tag
        self._out.write(serialized_chunk)
        self._body_hash.update(serialized_chunk)
