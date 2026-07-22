"""
container_reader.py — SVST streaming container reader.

Parses and authenticates the SVST chunked encrypted container format.
All operations are fail-closed: any malformed header field, bad signature,
GCM tag mismatch, truncated data, or missing terminal chunk raises
StreamingError immediately and yields no plaintext.

Chunk decryption is fail-closed because AESGCM.decrypt() is all-or-nothing
(it raises InvalidTag before returning any plaintext). Callers writing to disk
must use a temp file and atomic rename so partial output is never exposed.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from cryptography.exceptions import InvalidTag
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
from .crypto_engine import AES_KEY_SIZE_BYTES, STREAM_CHUNK_SIZE
from .signature_engine import SignatureError, verify


class StreamingError(Exception):
    """Raised by StreamingContainerReader on any parsing or authentication failure."""

# Maximum plausible sender public key size (P-521 uncompressed = 133 bytes; allow 200 as guard)
_MAX_PUBKEY_RAW_LEN = 200
# Maximum plausible signature size (RSA-3072 DER ≈ 387 bytes; allow 2 KiB as guard)
_MAX_SIG_LEN = 2048
# Maximum plausible chunk size: 2× the configured chunk size
_MAX_CHUNK_LEN = STREAM_CHUNK_SIZE * 2
# Minimum chunk payload: GCM tag only (16 bytes) — valid for a zero-byte plaintext chunk
_MIN_CHUNK_LEN = 16
# Maximum bytes accepted for the key_id / sign_key_id length-prefixed header fields
_MAX_KEY_ID_LEN = 256
# Maximum bytes accepted for the classification length-prefixed header field
_MAX_CLASSIFICATION_LEN = 255
# Streaming read buffer: 256 KiB per read() while verifying/decrypting the body
_READ_BUFFER_SIZE = 262144


@dataclass(frozen=True)
class StreamingHeader:
    """Parsed and signature-verified SVST header."""
    key_wrap_id: int
    sig_method_id: int
    wrapped_dek: bytes
    sender_pubkey_raw: bytes | None  # None for RSA; uncompressed ECC point for ECC
    base_nonce: bytes                # 8 bytes random prefix
    key_id: str | None               # None for v1; ASCII encryption key_id for v2/v3/v4
    sign_key_id: str | None          # None for v1/v2; ASCII signing key_id for v3/v4
    classification: str | None       # None for v1/v2/v3; data classification for v4
    version: int | None = None       # parsed container version byte


class StreamingContainerReader:
    """Reads and authenticates an SVST streaming encrypted container.

    Usage::

        reader = StreamingContainerReader(in_file)
        header = reader.read_and_verify_header(sign_public_key)
        # unwrap header.wrapped_dek to get aes_key ...
        for plaintext_chunk in reader.iter_plaintext_chunks(aes_key):
            out_file.write(plaintext_chunk)
    """

    def __init__(self, in_file: BinaryIO) -> None:
        self._in = in_file
        self._header: StreamingHeader | None = None
        self._chunk_start_offset: int | None = None
        self._body_end_offset: int | None = None
        self._signed_region_bytes: bytes | None = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def read_and_verify_header(self, sign_key_resolver) -> StreamingHeader:
        """Parse the SVST header and verify the header signature.

        ``sign_key_resolver`` may be either a public key object (backward-compatible
        with existing callers that load the key before calling this method) or a
        callable with signature ``(sig_method_id: int, sign_key_id: str | None) -> key``.
        When callable, it is invoked after the full header is parsed — this is the
        preferred path for v3 containers where the signing key_id is embedded in the
        header and must be used for exact key resolution.

        Raises StreamingError on:
          - wrong magic bytes
          - unsupported version
          - unknown algorithm IDs
          - non-zero flags byte
          - zero-length wrapped_dek or sender_pubkey
          - oversized fields
          - truncated data
          - sign key resolution failure
          - signature verification failure
        """
        # ---------- magic ----------
        magic = self._read_exact(4)
        if magic != STREAMING_MAGIC:
            raise StreamingError(
                f"Not an SVST container: expected {STREAMING_MAGIC!r}, got {magic!r}"
            )

        # ---------- version ----------
        version = self._read_exact(1)[0]
        if version not in (STREAMING_CONTAINER_VERSION, STREAMING_CONTAINER_VERSION_V2, STREAMING_CONTAINER_VERSION_V3, STREAMING_CONTAINER_VERSION_V4):
            raise StreamingError(f"Unsupported SVST container version: {version}")

        # ---------- algorithm IDs + flags ----------
        key_wrap_id = self._read_exact(1)[0]
        if key_wrap_id not in (KEY_WRAP_ID_RSA, KEY_WRAP_ID_ECC):
            raise StreamingError(f"Unknown key_wrap_id: {key_wrap_id:#04x}")

        sig_method_id = self._read_exact(1)[0]
        if sig_method_id not in (SIG_METHOD_ID_RSA, SIG_METHOD_ID_ECC):
            raise StreamingError(f"Unknown sig_method_id: {sig_method_id:#04x}")

        flags = self._read_exact(1)[0]
        if flags != 0x00:
            raise StreamingError(f"Unsupported flags byte: {flags:#04x}")

        # ---------- wrapped DEK ----------
        (wrapped_dek_len,) = struct.unpack(">H", self._read_exact(2))
        if wrapped_dek_len == 0:
            raise StreamingError("wrapped_dek_length is 0")
        wrapped_dek = self._read_exact(wrapped_dek_len)

        # ---------- sender public key (ECC only) ----------
        sender_pubkey_raw: bytes | None = None
        sender_pubkey_field: bytes = b""
        if key_wrap_id == KEY_WRAP_ID_ECC:
            (pubkey_len,) = struct.unpack(">H", self._read_exact(2))
            if pubkey_len == 0:
                raise StreamingError("sender_pubkey_length is 0 in ECC container")
            if pubkey_len > _MAX_PUBKEY_RAW_LEN:
                raise StreamingError(
                    f"sender_pubkey_length {pubkey_len} exceeds maximum {_MAX_PUBKEY_RAW_LEN}"
                )
            sender_pubkey_raw = self._read_exact(pubkey_len)
            sender_pubkey_field = struct.pack(">H", pubkey_len) + sender_pubkey_raw

        # ---------- base_nonce ----------
        base_nonce = self._read_exact(8)

        # ---------- key_id (v2/v3/v4: encryption key_id) ----------
        key_id: str | None = None
        key_id_field: bytes = b""
        if version in (STREAMING_CONTAINER_VERSION_V2, STREAMING_CONTAINER_VERSION_V3, STREAMING_CONTAINER_VERSION_V4):
            (key_id_len,) = struct.unpack(">H", self._read_exact(2))
            if key_id_len == 0:
                raise StreamingError("key_id_length is 0 in v2/v3/v4 container")
            if key_id_len > _MAX_KEY_ID_LEN:
                raise StreamingError(
                    f"key_id_length {key_id_len} exceeds maximum 256"
                )
            key_id_bytes = self._read_exact(key_id_len)
            try:
                key_id = key_id_bytes.decode("ascii")
            except UnicodeDecodeError as exc:
                raise StreamingError("Header encoding error") from exc
            key_id_field = struct.pack(">H", key_id_len) + key_id_bytes

        # ---------- sign_key_id (v3/v4: signing key_id) ----------
        sign_key_id: str | None = None
        sign_key_id_field: bytes = b""
        if version in (STREAMING_CONTAINER_VERSION_V3, STREAMING_CONTAINER_VERSION_V4):
            (sign_key_id_len,) = struct.unpack(">H", self._read_exact(2))
            if sign_key_id_len == 0:
                raise StreamingError("sign_key_id_length is 0 in v3/v4 container")
            if sign_key_id_len > _MAX_KEY_ID_LEN:
                raise StreamingError(
                    f"sign_key_id_length {sign_key_id_len} exceeds maximum 256"
                )
            sign_key_id_bytes = self._read_exact(sign_key_id_len)
            try:
                sign_key_id = sign_key_id_bytes.decode("ascii")
            except UnicodeDecodeError as exc:
                raise StreamingError("Header encoding error") from exc
            sign_key_id_field = struct.pack(">H", sign_key_id_len) + sign_key_id_bytes

        # ---------- classification (v4 only) ----------
        classification: str | None = None
        classification_field: bytes = b""
        if version == STREAMING_CONTAINER_VERSION_V4:
            (cls_len,) = struct.unpack(">B", self._read_exact(1))
            if cls_len == 0:
                raise StreamingError("classification_length is 0 in v4 container")
            if cls_len > _MAX_CLASSIFICATION_LEN:
                raise StreamingError(
                    f"classification_length {cls_len} exceeds maximum 255"
                )
            cls_bytes = self._read_exact(cls_len)
            try:
                classification = cls_bytes.decode("ascii")
            except UnicodeDecodeError as exc:
                raise StreamingError("Header encoding error") from exc
            classification_field = struct.pack(">B", cls_len) + cls_bytes

        # ---------- signature ----------
        (sig_len,) = struct.unpack(">I", self._read_exact(4))
        if sig_len == 0:
            raise StreamingError("sig_len is 0")
        if sig_len > _MAX_SIG_LEN:
            raise StreamingError(f"sig_len {sig_len} exceeds maximum {_MAX_SIG_LEN}")
        signature = self._read_exact(sig_len)

        # ---------- reconstruct signed region and verify ----------
        signed_region = (
            STREAMING_MAGIC
            + struct.pack(
                ">BBBB",
                version,
                key_wrap_id,
                sig_method_id,
                0x00,
            )
            + struct.pack(">H", wrapped_dek_len)
            + wrapped_dek
            + sender_pubkey_field
            + base_nonce
            + key_id_field
            + sign_key_id_field
            + classification_field
        )

        # Resolve signing public key — callable resolver (v3 path) or direct key (legacy path).
        if callable(sign_key_resolver):
            try:
                sign_public_key = sign_key_resolver(sig_method_id, sign_key_id)
            except StreamingError:
                raise
            except Exception as exc:
                raise StreamingError("Signing key resolution failed") from exc
        else:
            sign_public_key = sign_key_resolver

        sig_method = "rsa" if sig_method_id == SIG_METHOD_ID_RSA else "ecc"
        try:
            verify(sig_method, sign_public_key, signature, signed_region)
        except SignatureError as exc:
            raise StreamingError("Integrity/authenticity check failed") from exc

        self._header = StreamingHeader(
            key_wrap_id=key_wrap_id,
            sig_method_id=sig_method_id,
            wrapped_dek=wrapped_dek,
            sender_pubkey_raw=sender_pubkey_raw,
            base_nonce=base_nonce,
            key_id=key_id,
            sign_key_id=sign_key_id,
            classification=classification,
            version=version,
        )
        self._signed_region_bytes = signed_region
        self._chunk_start_offset = self._in.tell()
        return self._header

    def verify_body_signature(self, sign_key_resolver) -> None:
        """Verify the body signature trailer before any DEK unwrap or chunk decryption.

        The body digest covers the header signed_region followed by all serialized
        chunk bytes, matching exactly what StreamingContainerWriter.close() produces.
        Trailer layout: [ body_signature (N bytes) ][ sig_len (4 bytes BE) ]

        Raises StreamingError on missing trailer, invalid signature, or key failure.
        Restores file position to chunk_start_offset on success.
        """
        if self._header is None or self._chunk_start_offset is None or self._signed_region_bytes is None:
            raise StreamingError("verify_body_signature called before read_and_verify_header")

        # Find file size and read sig_len from EOF-4
        self._in.seek(0, 2)
        file_size = self._in.tell()

        if file_size < self._chunk_start_offset + 5:
            raise StreamingError("Body signature missing")

        self._in.seek(-4, 2)
        (sig_len,) = struct.unpack(">I", self._in.read(4))

        if sig_len == 0 or sig_len > _MAX_SIG_LEN:
            raise StreamingError("Body signature missing or invalid")

        body_end = file_size - 4 - sig_len
        if body_end < self._chunk_start_offset:
            raise StreamingError("Body signature missing or invalid")

        # Read body signature bytes from body_end offset
        self._in.seek(body_end)
        body_sig = self._in.read(sig_len)
        if len(body_sig) != sig_len:
            raise StreamingError("Body signature truncated")

        # Recompute digest: signed_region + chunk body bytes
        hasher = hashlib.sha256()
        hasher.update(self._signed_region_bytes)
        self._in.seek(self._chunk_start_offset)
        remaining = body_end - self._chunk_start_offset
        while remaining > 0:
            buf = self._in.read(min(_READ_BUFFER_SIZE, remaining))
            if not buf:
                raise StreamingError("Unexpected EOF while computing body digest")
            hasher.update(buf)
            remaining -= len(buf)

        # Resolve signing public key
        if callable(sign_key_resolver):
            try:
                sign_public_key = sign_key_resolver(
                    self._header.sig_method_id, self._header.sign_key_id
                )
            except StreamingError:
                raise
            except Exception as exc:
                raise StreamingError("Signing key resolution failed") from exc
        else:
            sign_public_key = sign_key_resolver

        # Verify body signature
        sig_method = "rsa" if self._header.sig_method_id == SIG_METHOD_ID_RSA else "ecc"
        try:
            verify(sig_method, sign_public_key, body_sig, hasher.digest())
        except SignatureError:
            raise StreamingError("Body signature verification failed")

        # Store boundary for iter_plaintext_chunks and rewrap_dek
        self._body_end_offset = body_end

        # Restore position to chunk start so iter_plaintext_chunks works normally
        self._in.seek(self._chunk_start_offset)

    def iter_plaintext_chunks(self, aes_key: bytes) -> Iterator[bytes]:
        """Decrypt and yield plaintext chunks one at a time.

        Raises StreamingError on:
          - header not yet verified
          - wrong aes_key length
          - chunk_length out of range
          - truncated chunk data
          - GCM authentication tag mismatch (ciphertext tampered or wrong key)
          - chunk reordering (chunk_index bound into AAD)
          - no terminal chunk found (file truncated after header)

        Never yields data from a chunk until AESGCM.decrypt() completes
        successfully (all-or-nothing GCM guarantee from the cryptography library).
        """
        if self._header is None:
            raise StreamingError(
                "Must call read_and_verify_header() before iter_plaintext_chunks()"
            )
        if len(aes_key) != AES_KEY_SIZE_BYTES:
            raise StreamingError(
                f"AES key must be {AES_KEY_SIZE_BYTES} bytes, got {len(aes_key)}"
            )

        aesgcm = AESGCM(aes_key)
        base_nonce = self._header.base_nonce
        chunk_index = 0
        saw_terminal = False

        while True:
            # Stop at body_end_offset to avoid reading into the body signature trailer.
            if self._body_end_offset is not None and self._in.tell() >= self._body_end_offset:
                break

            # Read chunk_length field (4 bytes)
            chunk_len_bytes = self._in.read(4)
            if len(chunk_len_bytes) == 0:
                break  # clean EOF — terminal check below will catch truncation
            if len(chunk_len_bytes) != 4:
                raise StreamingError(
                    "Container truncated: partial chunk_length field"
                )

            (chunk_len,) = struct.unpack(">I", chunk_len_bytes)
            if chunk_len < _MIN_CHUNK_LEN:
                raise StreamingError(
                    f"chunk_length {chunk_len} is below minimum {_MIN_CHUNK_LEN} "
                    "(GCM tag requires at least 16 bytes)"
                )
            if chunk_len > _MAX_CHUNK_LEN:
                raise StreamingError(
                    f"chunk_length {chunk_len} exceeds maximum {_MAX_CHUNK_LEN}"
                )

            # Read ciphertext + GCM tag
            ciphertext_and_tag = self._in.read(chunk_len)
            if len(ciphertext_and_tag) != chunk_len:
                raise StreamingError(
                    f"Container truncated: chunk {chunk_index} expected "
                    f"{chunk_len} bytes, got {len(ciphertext_and_tag)}"
                )

            nonce = base_nonce + struct.pack(">I", chunk_index)

            # Attempt decryption with is_last=False first (non-terminal),
            # then is_last=True (terminal). Whichever GCM tag validates is correct.
            # The chunk_index in AAD prevents reordering attacks regardless.
            plaintext, is_terminal = self._decrypt_chunk(
                aesgcm, nonce, ciphertext_and_tag, chunk_index
            )

            yield plaintext
            chunk_index += 1

            if is_terminal:
                saw_terminal = True
                break

        if not saw_terminal:
            raise StreamingError(
                "SVST container is missing the required terminal chunk. "
                "The file is truncated or has been tampered with."
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_exact(self, n: int) -> bytes:
        """Read exactly *n* bytes or raise StreamingError on truncation."""
        data = self._in.read(n)
        if len(data) != n:
            raise StreamingError(
                f"SVST container truncated in header: expected {n} bytes, got {len(data)}"
            )
        return data

    def _decrypt_chunk(
        self,
        aesgcm: AESGCM,
        nonce: bytes,
        ciphertext_and_tag: bytes,
        chunk_index: int,
    ) -> tuple[bytes, bool]:
        """Try decrypting as non-terminal then terminal. Return (plaintext, is_terminal).

        Raises StreamingError if neither AAD variant authenticates.
        """
        for is_last_flag in (b"\x00", b"\x01"):
            aad = (
                STREAMING_MAGIC
                + struct.pack(">B", STREAMING_CONTAINER_VERSION)
                + struct.pack(">I", chunk_index)
                + is_last_flag
            )
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
                return plaintext, (is_last_flag == b"\x01")
            except InvalidTag:
                continue

        raise StreamingError(
            f"Authentication tag mismatch on chunk {chunk_index}. "
            "The file is corrupted or has been tampered with."
        )
