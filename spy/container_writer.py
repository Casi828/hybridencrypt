"""
container_writer.py — SVST streaming container writer.

Serializes an encrypted file in the SVST chunked format:
  Header: magic | version | key_wrap_id | sig_method_id | flags |
          wrapped_dek_len | wrapped_dek
          [ECC only: sender_pubkey_len | sender_pubkey_raw]
          base_nonce | sig_len | header_signature
  Body:   [chunk_len (4 BE) | AES-256-GCM(plaintext_chunk)]*

The header signature covers all bytes from magic through base_nonce (inclusive).
Each chunk is encrypted with a unique nonce derived from base_nonce + chunk_index,
and bound to chunk_index + is_last via AAD so reordering and truncation are detected.

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


class ContainerWriterError(Exception):
    pass


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
        self._sender_pubkey_raw: bytes = sender_pubkey_raw or b""
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

        wrapped_dek_len = len(self._wrapped_dek)
        if wrapped_dek_len > _MAX_U16_FIELD_LEN:
            raise ContainerWriterError(
                f"wrapped_dek too large: {wrapped_dek_len} bytes (max 65535)"
            )

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

        # Assemble the signed region: magic through base_nonce (+ key_id for v2).
        signed_region = (
            STREAMING_MAGIC
            + struct.pack(
                ">BBBB",
                container_version,
                self._key_wrap_id,
                self._sig_method_id,
                0x00,  # flags (reserved)
            )
            + struct.pack(">H", wrapped_dek_len)
            + self._wrapped_dek
        )

        if self._key_wrap_id == KEY_WRAP_ID_ECC:
            pubkey_len = len(self._sender_pubkey_raw)
            if pubkey_len > _MAX_U16_FIELD_LEN:
                raise ContainerWriterError(
                    f"sender_pubkey_raw too large: {pubkey_len} bytes (max 65535)"
                )
            signed_region += struct.pack(">H", pubkey_len) + self._sender_pubkey_raw

        signed_region += self._base_nonce

        # v2/v3: append encryption key_id_len (2 BE) + key_id (ASCII) to signed region.
        if self._key_id is not None:
            try:
                key_id_bytes = self._key_id.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ContainerWriterError("Header encoding error") from exc
            if len(key_id_bytes) > _MAX_U16_FIELD_LEN:
                raise ContainerWriterError(
                    f"key_id too long: {len(key_id_bytes)} bytes (max 65535)"
                )
            signed_region += struct.pack(">H", len(key_id_bytes)) + key_id_bytes

        # v3: append signing key_id_len (2 BE) + sign_key_id (ASCII) to signed region.
        if self._sign_key_id is not None:
            try:
                sign_key_id_bytes = self._sign_key_id.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ContainerWriterError("Header encoding error") from exc
            if len(sign_key_id_bytes) > _MAX_U16_FIELD_LEN:
                raise ContainerWriterError(
                    f"sign_key_id too long: {len(sign_key_id_bytes)} bytes (max 65535)"
                )
            signed_region += struct.pack(">H", len(sign_key_id_bytes)) + sign_key_id_bytes

        # v4: append classification_len (1 byte) + classification (ASCII) to signed region.
        if container_version == STREAMING_CONTAINER_VERSION_V4:
            try:
                cls_bytes = self._classification.encode("ascii")  # type: ignore[union-attr]
            except UnicodeEncodeError as exc:
                raise ContainerWriterError("Header encoding error") from exc
            if len(cls_bytes) > 255:
                raise ContainerWriterError(
                    f"classification too long: {len(cls_bytes)} bytes (max 255)"
                )
            signed_region += struct.pack(">B", len(cls_bytes)) + cls_bytes

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
