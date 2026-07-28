"""
test_rewrap_version.py — SVST header serialization and DEK rewrap invariants.

The SVST signed-region byte layout has exactly one implementation:
``spy.container_writer.build_signed_region``. Both the streaming encrypt path
(``StreamingContainerWriter.write_header``) and the DEK rewrap path
(``file_crypto_engine.rewrap_dek``) assemble their headers through it, so these
tests pin the wire format once and assert both callers stay bound to it.

Covers:
  TestBuildSignedRegionLayout   — byte-exact layout for v1/v2/v3/v4, RSA and ECC
  TestBuildSignedRegionValidation — every validation the serializer owns, including
                                    the ones inherited from the writer constructor
  TestWriterUsesSharedSerializer  — writer output is exactly serializer output
  TestRewrapWireFormatMatrix    — header rewrite + re-parse + decrypt for v2/v3/v4
                                  (RSA and ECC), base_nonce preservation, trailer
                                  replacement
  TestRewrapEngine              — end-to-end rewrap_dek for the versions the engine
                                  accepts (v4 RSA / v4 ECC) and the legacy denial
  TestRewrapVersionPreservation — subprocess regression guards (version byte,
                                  decrypt-after-rewrap through stream_decrypt_file)
  TestRewrapVersionMismatch     — StreamingHeader version field + invariant logic

Engine note: ``rewrap_dek`` authorizes against the container's classification, which
only v4 containers carry. v1/v2/v3 containers are therefore denied by the engine's
authorization gate before any header is written — the same fail-closed rule
``stream_decrypt_file`` applies to classification-less containers. Wire-format
coverage for those versions is exercised through the serializer directly.
"""

from __future__ import annotations

import hashlib
import io
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from spy.container_reader import StreamingContainerReader, StreamingError
from spy.container_writer import (
    ContainerWriterError,
    StreamingContainerWriter,
    build_signed_region,
)
from spy.crypto_container import (
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
from spy.crypto_engine import generate_key
from spy.signature_engine import sign

_HERE = Path(__file__).resolve().parent.parent

_NONCE = b"\x01\x02\x03\x04\x05\x06\x07\x08"
_DEK = b"\xaa" * 384                 # RSA-3072 ciphertext size; content is opaque here
_ECC_PUB = b"\x04" + b"\x11" * 64    # uncompressed P-256 point shape


def _run_subprocess(code: str, cwd: str = None) -> str:
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        cwd=cwd or str(_HERE),
        env=os.environ.copy(),
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Subprocess failed:\n{result.stdout.decode()}\n{result.stderr.decode()}"
        )
    return result.stdout.decode()


# ---------------------------------------------------------------------------
# Pure serializer tests — no key material, no I/O
# ---------------------------------------------------------------------------

def _region(**overrides) -> bytes:
    """Call build_signed_region with a valid v4 RSA baseline plus *overrides*."""
    kwargs = dict(
        version=STREAMING_CONTAINER_VERSION_V4,
        key_wrap_id=KEY_WRAP_ID_RSA,
        sig_method_id=SIG_METHOD_ID_RSA,
        wrapped_dek=_DEK,
        sender_pubkey_raw=None,
        base_nonce=_NONCE,
        key_id="rsa-enc-v1",
        sign_key_id="rsa-sign-v1",
        classification="low",
    )
    kwargs.update(overrides)
    return build_signed_region(**kwargs)


class TestBuildSignedRegionLayout(unittest.TestCase):
    """The serializer emits the exact documented SVST byte layout per version."""

    def test_v1_rsa_layout(self):
        got = _region(
            version=STREAMING_CONTAINER_VERSION,
            key_id=None, sign_key_id=None, classification=None,
        )
        expected = (
            STREAMING_MAGIC
            + struct.pack(">BBBB", 1, KEY_WRAP_ID_RSA, SIG_METHOD_ID_RSA, 0x00)
            + struct.pack(">H", len(_DEK)) + _DEK
            + _NONCE
        )
        self.assertEqual(got, expected)

    def test_v2_rsa_layout(self):
        got = _region(
            version=STREAMING_CONTAINER_VERSION_V2,
            sign_key_id=None, classification=None,
        )
        expected = (
            STREAMING_MAGIC
            + struct.pack(">BBBB", 2, KEY_WRAP_ID_RSA, SIG_METHOD_ID_RSA, 0x00)
            + struct.pack(">H", len(_DEK)) + _DEK
            + _NONCE
            + struct.pack(">H", 10) + b"rsa-enc-v1"
        )
        self.assertEqual(got, expected)

    def test_v3_rsa_layout(self):
        got = _region(version=STREAMING_CONTAINER_VERSION_V3, classification=None)
        expected = (
            STREAMING_MAGIC
            + struct.pack(">BBBB", 3, KEY_WRAP_ID_RSA, SIG_METHOD_ID_RSA, 0x00)
            + struct.pack(">H", len(_DEK)) + _DEK
            + _NONCE
            + struct.pack(">H", 10) + b"rsa-enc-v1"
            + struct.pack(">H", 11) + b"rsa-sign-v1"
        )
        self.assertEqual(got, expected)

    def test_v4_rsa_layout(self):
        got = _region()
        expected = (
            STREAMING_MAGIC
            + struct.pack(">BBBB", 4, KEY_WRAP_ID_RSA, SIG_METHOD_ID_RSA, 0x00)
            + struct.pack(">H", len(_DEK)) + _DEK
            + _NONCE
            + struct.pack(">H", 10) + b"rsa-enc-v1"
            + struct.pack(">H", 11) + b"rsa-sign-v1"
            + struct.pack(">B", 3) + b"low"
        )
        self.assertEqual(got, expected)

    def test_v3_ecc_layout_includes_sender_pubkey(self):
        got = _region(
            version=STREAMING_CONTAINER_VERSION_V3,
            key_wrap_id=KEY_WRAP_ID_ECC,
            sig_method_id=SIG_METHOD_ID_ECC,
            sender_pubkey_raw=_ECC_PUB,
            key_id="ecc-enc-v1",
            sign_key_id="ecc-sign-v1",
            classification=None,
        )
        expected = (
            STREAMING_MAGIC
            + struct.pack(">BBBB", 3, KEY_WRAP_ID_ECC, SIG_METHOD_ID_ECC, 0x00)
            + struct.pack(">H", len(_DEK)) + _DEK
            + struct.pack(">H", len(_ECC_PUB)) + _ECC_PUB
            + _NONCE
            + struct.pack(">H", 10) + b"ecc-enc-v1"
            + struct.pack(">H", 11) + b"ecc-sign-v1"
        )
        self.assertEqual(got, expected)

    def test_v4_ecc_layout_includes_sender_pubkey_and_classification(self):
        got = _region(
            key_wrap_id=KEY_WRAP_ID_ECC,
            sig_method_id=SIG_METHOD_ID_ECC,
            sender_pubkey_raw=_ECC_PUB,
            key_id="ecc-enc-v1",
            sign_key_id="ecc-sign-v1",
            classification="high",
        )
        expected = (
            STREAMING_MAGIC
            + struct.pack(">BBBB", 4, KEY_WRAP_ID_ECC, SIG_METHOD_ID_ECC, 0x00)
            + struct.pack(">H", len(_DEK)) + _DEK
            + struct.pack(">H", len(_ECC_PUB)) + _ECC_PUB
            + _NONCE
            + struct.pack(">H", 10) + b"ecc-enc-v1"
            + struct.pack(">H", 11) + b"ecc-sign-v1"
            + struct.pack(">B", 4) + b"high"
        )
        self.assertEqual(got, expected)

    def test_version_byte_is_at_offset_four(self):
        """rewrap_dek's post-condition reads the version byte at offset 4."""
        for version in (1, 2, 3, 4):
            with self.subTest(version=version):
                region = _region(
                    version=version,
                    key_id=None if version == 1 else "rsa-enc-v1",
                    sign_key_id=None if version < 3 else "rsa-sign-v1",
                    classification=None if version < 4 else "low",
                )
                self.assertEqual(region[4], version)

    def test_is_pure_and_deterministic(self):
        """Repeated calls with identical arguments produce identical bytes."""
        self.assertEqual(_region(), _region())

    def test_accepts_bytearray_inputs_without_mutating_output_type(self):
        got = _region(
            wrapped_dek=bytearray(_DEK), base_nonce=bytearray(_NONCE)
        )
        self.assertIsInstance(got, bytes)
        self.assertEqual(got, _region())


class TestBuildSignedRegionValidation(unittest.TestCase):
    """All header validation lives in the serializer — including the checks the
    rewrap path used to inherit from StreamingContainerWriter.__init__."""

    # ---- version / field invariants ----

    def test_unsupported_version_rejected(self):
        for bad in (0, 5, 255, -1):
            with self.subTest(version=bad):
                with self.assertRaises(ContainerWriterError):
                    _region(version=bad, key_id=None, sign_key_id=None, classification=None)

    def test_v1_forbids_key_id(self):
        with self.assertRaises(ContainerWriterError):
            _region(version=STREAMING_CONTAINER_VERSION,
                    key_id="rsa-enc-v1", sign_key_id=None, classification=None)

    def test_v1_forbids_sign_key_id(self):
        with self.assertRaises(ContainerWriterError):
            _region(version=STREAMING_CONTAINER_VERSION,
                    key_id=None, sign_key_id="rsa-sign-v1", classification=None)

    def test_v1_forbids_classification(self):
        with self.assertRaises(ContainerWriterError):
            _region(version=STREAMING_CONTAINER_VERSION,
                    key_id=None, sign_key_id=None, classification="low")

    def test_v2_requires_key_id(self):
        with self.assertRaises(ContainerWriterError):
            _region(version=STREAMING_CONTAINER_VERSION_V2,
                    key_id=None, sign_key_id=None, classification=None)

    def test_v2_forbids_sign_key_id(self):
        with self.assertRaises(ContainerWriterError) as ctx:
            _region(version=STREAMING_CONTAINER_VERSION_V2,
                    sign_key_id="rsa-sign-v1", classification=None)
        self.assertIn("sign_key_id", str(ctx.exception))

    def test_v2_forbids_classification(self):
        with self.assertRaises(ContainerWriterError):
            _region(version=STREAMING_CONTAINER_VERSION_V2,
                    sign_key_id=None, classification="low")

    def test_v3_requires_sign_key_id(self):
        with self.assertRaises(ContainerWriterError):
            _region(version=STREAMING_CONTAINER_VERSION_V3,
                    sign_key_id=None, classification=None)

    def test_v3_requires_key_id(self):
        with self.assertRaises(ContainerWriterError):
            _region(version=STREAMING_CONTAINER_VERSION_V3,
                    key_id=None, classification=None)

    def test_v3_forbids_classification(self):
        with self.assertRaises(ContainerWriterError) as ctx:
            _region(version=STREAMING_CONTAINER_VERSION_V3, classification="low")
        self.assertIn("classification", str(ctx.exception))

    def test_v4_requires_classification(self):
        with self.assertRaises(ContainerWriterError) as ctx:
            _region(classification=None)
        self.assertIn("classification", str(ctx.exception))

    def test_v4_requires_key_id(self):
        with self.assertRaises(ContainerWriterError):
            _region(key_id=None)

    def test_v4_requires_sign_key_id(self):
        with self.assertRaises(ContainerWriterError):
            _region(sign_key_id=None)

    # ---- base_nonce ----

    def test_base_nonce_wrong_length_rejected(self):
        for bad in (b"", b"\x00" * 7, b"\x00" * 9, b"\x00" * 12):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ContainerWriterError):
                    _region(base_nonce=bad)

    def test_base_nonce_wrong_type_rejected(self):
        with self.assertRaises(ContainerWriterError):
            _region(base_nonce="abcdefgh")

    # ---- checks inherited from StreamingContainerWriter.__init__ ----

    def test_unrecognized_key_wrap_id_rejected(self):
        for bad in (0x00, 0x03, 0xFF):
            with self.subTest(key_wrap_id=bad):
                with self.assertRaises(ContainerWriterError) as ctx:
                    _region(key_wrap_id=bad)
                self.assertIn("key_wrap_id", str(ctx.exception))

    def test_unrecognized_sig_method_id_rejected(self):
        for bad in (0x00, 0x03, 0xFF):
            with self.subTest(sig_method_id=bad):
                with self.assertRaises(ContainerWriterError) as ctx:
                    _region(sig_method_id=bad)
                self.assertIn("sig_method_id", str(ctx.exception))

    def test_empty_wrapped_dek_rejected(self):
        with self.assertRaises(ContainerWriterError) as ctx:
            _region(wrapped_dek=b"")
        self.assertIn("wrapped_dek", str(ctx.exception))

    def test_wrapped_dek_wrong_type_rejected(self):
        with self.assertRaises(ContainerWriterError):
            _region(wrapped_dek="not-bytes")

    def test_wrapped_dek_exceeding_uint16_bound_rejected(self):
        with self.assertRaises(ContainerWriterError) as ctx:
            _region(wrapped_dek=b"\x00" * 65536)
        self.assertIn("wrapped_dek too large", str(ctx.exception))

    def test_wrapped_dek_at_uint16_bound_accepted(self):
        region = _region(wrapped_dek=b"\x00" * 65535)
        self.assertIn(struct.pack(">H", 65535), region[:12])

    def test_rsa_rejects_non_none_sender_pubkey(self):
        with self.assertRaises(ContainerWriterError) as ctx:
            _region(key_wrap_id=KEY_WRAP_ID_RSA, sender_pubkey_raw=_ECC_PUB)
        self.assertIn("sender_pubkey_raw", str(ctx.exception))

    def test_rsa_rejects_empty_bytes_sentinel(self):
        """b'' is not an accepted 'absent' representation — only None is."""
        with self.assertRaises(ContainerWriterError):
            _region(key_wrap_id=KEY_WRAP_ID_RSA, sender_pubkey_raw=b"")

    def test_ecc_rejects_none_sender_pubkey(self):
        with self.assertRaises(ContainerWriterError) as ctx:
            _region(key_wrap_id=KEY_WRAP_ID_ECC, sig_method_id=SIG_METHOD_ID_ECC,
                    sender_pubkey_raw=None)
        self.assertIn("sender_pubkey_raw", str(ctx.exception))

    def test_ecc_rejects_empty_sender_pubkey(self):
        with self.assertRaises(ContainerWriterError):
            _region(key_wrap_id=KEY_WRAP_ID_ECC, sig_method_id=SIG_METHOD_ID_ECC,
                    sender_pubkey_raw=b"")

    def test_sender_pubkey_wrong_type_rejected(self):
        with self.assertRaises(ContainerWriterError):
            _region(key_wrap_id=KEY_WRAP_ID_ECC, sig_method_id=SIG_METHOD_ID_ECC,
                    sender_pubkey_raw="04aabb")

    def test_sender_pubkey_exceeding_uint16_bound_rejected(self):
        with self.assertRaises(ContainerWriterError) as ctx:
            _region(key_wrap_id=KEY_WRAP_ID_ECC, sig_method_id=SIG_METHOD_ID_ECC,
                    sender_pubkey_raw=b"\x04" * 65536)
        self.assertIn("sender_pubkey_raw too large", str(ctx.exception))

    # ---- string field type / length / encoding ----

    def test_key_id_wrong_type_rejected(self):
        with self.assertRaises(ContainerWriterError):
            _region(key_id=b"rsa-enc-v1")

    def test_empty_key_id_rejected(self):
        """The reader treats a zero-length key_id as malformed — never emit one."""
        with self.assertRaises(ContainerWriterError):
            _region(key_id="")

    def test_empty_sign_key_id_rejected(self):
        with self.assertRaises(ContainerWriterError):
            _region(sign_key_id="")

    def test_empty_classification_rejected(self):
        with self.assertRaises(ContainerWriterError):
            _region(classification="")

    def test_non_ascii_key_id_rejected(self):
        with self.assertRaises(ContainerWriterError) as ctx:
            _region(key_id="rsa-enc-café")
        self.assertIn("Header encoding error", str(ctx.exception))

    def test_non_ascii_sign_key_id_rejected(self):
        with self.assertRaises(ContainerWriterError):
            _region(sign_key_id="rsa-sign-café")

    def test_non_ascii_classification_rejected(self):
        with self.assertRaises(ContainerWriterError):
            _region(classification="lów")

    def test_key_id_exceeding_uint16_bound_rejected(self):
        with self.assertRaises(ContainerWriterError) as ctx:
            _region(key_id="k" * 65536)
        self.assertIn("key_id too long", str(ctx.exception))

    def test_sign_key_id_exceeding_uint16_bound_rejected(self):
        with self.assertRaises(ContainerWriterError):
            _region(sign_key_id="s" * 65536)

    def test_classification_exceeding_byte_bound_rejected(self):
        with self.assertRaises(ContainerWriterError) as ctx:
            _region(classification="c" * 256)
        self.assertIn("classification too long", str(ctx.exception))

    def test_classification_at_byte_bound_accepted(self):
        region = _region(classification="c" * 255)
        self.assertEqual(region[-256], 255)

    def test_keyword_only_signature(self):
        """Positional calls are rejected — every field is keyword-only."""
        with self.assertRaises(TypeError):
            build_signed_region(4, KEY_WRAP_ID_RSA, SIG_METHOD_ID_RSA, _DEK,
                                None, _NONCE, "k", "s", "low")  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Key-backed fixtures
# ---------------------------------------------------------------------------

_RSA = {}
_ECC = {}


def setUpModule():
    """Capture the pre-rotation encryption keys, then rotate once for both methods.

    Containers are wrapped to the captured (now decrypt-only) keys so rewrap always
    has a different active key to move to, without one rotation per test.
    """
    from spy.key_provider import LocalPemKeyProvider
    from spy.key_registry import KeyRegistry
    from spy.rsa_engine import rotate_rsa_encryption_keys
    from spy.ecc_engine import rotate_ecc_encryption_keys

    provider = LocalPemKeyProvider()

    _RSA["old_key_id"] = provider.get_active_rsa_key_id()
    _RSA["old_public"] = provider.get_rsa_public_key(_RSA["old_key_id"])
    _RSA["sign_key_id"] = provider.get_active_rsa_signing_key_id()
    _RSA["sign_private"] = provider.get_rsa_signing_private_key()

    _ECC["old_key_id"] = provider.get_active_ecc_key_id()
    _ECC["old_public"] = provider.get_ecc_public_key(_ECC["old_key_id"])
    _ECC["sign_key_id"] = provider.get_active_ecc_signing_key_id()
    _ECC["sign_private"] = provider.get_ecc_signing_private_key()

    registry = KeyRegistry()
    registry.load()
    rotate_rsa_encryption_keys(registry)
    registry = KeyRegistry()
    registry.load()
    rotate_ecc_encryption_keys(registry)

    fresh = LocalPemKeyProvider()
    _RSA["new_key_id"] = fresh.get_active_rsa_key_id()
    _ECC["new_key_id"] = fresh.get_active_ecc_key_id()
    assert _RSA["new_key_id"] != _RSA["old_key_id"]
    assert _ECC["new_key_id"] != _ECC["old_key_id"]


def _wrap_dek(method: str, dek: bytes, public_key):
    """Wrap *dek* to *public_key*. Returns (wrapped_dek, sender_pubkey_raw)."""
    if method == "rsa":
        from spy.rsa_engine import wrap_key as rsa_wrap_key
        return rsa_wrap_key(public_key, dek), None
    from spy.ecc_engine import (
        generate_ecc_keypair, serialize_public_key_raw, wrap_key as ecc_wrap_key,
    )
    from spy.file_crypto_engine import _SVST_ECC_DEK_WRAP_AAD
    sender_private, sender_public = generate_ecc_keypair()
    wrapped = ecc_wrap_key(sender_private, public_key, dek, _SVST_ECC_DEK_WRAP_AAD)
    return wrapped, serialize_public_key_raw(sender_public)


def _build_container(method: str, version: int, plaintext: bytes) -> tuple[bytes, bytes]:
    """Write an SVST container of *version* for *method*. Returns (raw_bytes, dek)."""
    cfg = _RSA if method == "rsa" else _ECC
    dek = generate_key()
    wrapped_dek, sender_pubkey_raw = _wrap_dek(method, dek, cfg["old_public"])

    buf = io.BytesIO()
    writer = StreamingContainerWriter(
        out_file=buf,
        key_wrap_id=KEY_WRAP_ID_RSA if method == "rsa" else KEY_WRAP_ID_ECC,
        sig_method_id=SIG_METHOD_ID_RSA if method == "rsa" else SIG_METHOD_ID_ECC,
        wrapped_dek=wrapped_dek,
        sender_pubkey_raw=sender_pubkey_raw,
        sign_private_key=cfg["sign_private"],
        aes_key=dek,
        key_id=cfg["old_key_id"] if version >= STREAMING_CONTAINER_VERSION_V2 else None,
        sign_key_id=cfg["sign_key_id"] if version >= STREAMING_CONTAINER_VERSION_V3 else None,
        classification="low" if version == STREAMING_CONTAINER_VERSION_V4 else None,
    )
    writer.write_header()
    writer.write_chunks(io.BytesIO(plaintext))
    writer.close()
    raw = buf.getvalue()
    assert raw[4] == version, f"expected v{version}, wrote v{raw[4]}"
    return raw, dek


def _resolver():
    from spy.file_crypto_engine import _make_svst_sign_key_resolver
    from spy.key_provider import LocalPemKeyProvider
    return _make_svst_sign_key_resolver(LocalPemKeyProvider())


def _parse(raw: bytes):
    """Parse + fully verify *raw*. Returns (header, chunk_bytes)."""
    buf = io.BytesIO(raw)
    reader = StreamingContainerReader(buf)
    resolver = _resolver()
    header = reader.read_and_verify_header(resolver)
    reader.verify_body_signature(resolver)
    return header, raw[reader._chunk_start_offset:reader._body_end_offset]


def _decrypt(raw: bytes, dek: bytes) -> bytes:
    """Verify and decrypt a container with a known DEK."""
    buf = io.BytesIO(raw)
    reader = StreamingContainerReader(buf)
    resolver = _resolver()
    reader.read_and_verify_header(resolver)
    reader.verify_body_signature(resolver)
    return b"".join(reader.iter_plaintext_chunks(dek))


def _unwrap_dek(header) -> bytes:
    from spy.file_crypto_engine import _unwrap_svst_dek_by_key_id
    from spy.key_provider import LocalPemKeyProvider
    return _unwrap_svst_dek_by_key_id(header, LocalPemKeyProvider())


def _rewrap_header(raw: bytes, method: str) -> bytes:
    """Rewrite *raw*'s header to the new active key, mirroring rewrap_dek exactly.

    Uses the shared serializer with the input container's version and re-uses the
    original base_nonce, then copies the chunk body verbatim and writes a fresh
    body-signature trailer.
    """
    cfg = _RSA if method == "rsa" else _ECC
    from spy.key_provider import LocalPemKeyProvider
    provider = LocalPemKeyProvider()

    header, body = _parse(raw)
    old_dek = _unwrap_dek(header)

    new_public = (
        provider.get_rsa_public_key(cfg["new_key_id"]) if method == "rsa"
        else provider.get_ecc_public_key(cfg["new_key_id"])
    )
    new_wrapped_dek, new_sender_pubkey_raw = _wrap_dek(method, old_dek, new_public)

    signed_region = build_signed_region(
        version=header.version,
        key_wrap_id=header.key_wrap_id,
        sig_method_id=header.sig_method_id,
        wrapped_dek=new_wrapped_dek,
        sender_pubkey_raw=new_sender_pubkey_raw,
        base_nonce=header.base_nonce,
        key_id=cfg["new_key_id"],
        sign_key_id=(
            cfg["sign_key_id"]
            if header.version >= STREAMING_CONTAINER_VERSION_V3 else None
        ),
        classification=header.classification,
    )
    sig_method = "rsa" if method == "rsa" else "ecc"
    header_sig = sign(sig_method, cfg["sign_private"], signed_region)
    body_sig = sign(
        sig_method, cfg["sign_private"],
        hashlib.sha256(signed_region + body).digest(),
    )
    return (
        signed_region
        + struct.pack(">I", len(header_sig)) + header_sig
        + body
        + body_sig + struct.pack(">I", len(body_sig))
    )


# ---------------------------------------------------------------------------
# Writer / serializer agreement
# ---------------------------------------------------------------------------

class TestWriterUsesSharedSerializer(unittest.TestCase):
    """StreamingContainerWriter emits exactly what build_signed_region returns."""

    def _assert_agrees(self, method: str, version: int):
        raw, _dek = _build_container(method, version, b"agreement payload")
        header, _body = _parse(raw)
        expected = build_signed_region(
            version=version,
            key_wrap_id=header.key_wrap_id,
            sig_method_id=header.sig_method_id,
            wrapped_dek=header.wrapped_dek,
            sender_pubkey_raw=header.sender_pubkey_raw,
            base_nonce=header.base_nonce,
            key_id=header.key_id,
            sign_key_id=header.sign_key_id,
            classification=header.classification,
        )
        self.assertEqual(raw[:len(expected)], expected)

    def test_rsa_v2(self):
        self._assert_agrees("rsa", STREAMING_CONTAINER_VERSION_V2)

    def test_rsa_v3(self):
        self._assert_agrees("rsa", STREAMING_CONTAINER_VERSION_V3)

    def test_rsa_v4(self):
        self._assert_agrees("rsa", STREAMING_CONTAINER_VERSION_V4)

    def test_ecc_v3(self):
        self._assert_agrees("ecc", STREAMING_CONTAINER_VERSION_V3)

    def test_ecc_v4(self):
        self._assert_agrees("ecc", STREAMING_CONTAINER_VERSION_V4)

    def test_rsa_header_passes_none_not_empty_bytes(self):
        """The writer no longer normalizes sender_pubkey_raw to b'' for RSA."""
        writer = StreamingContainerWriter(
            out_file=io.BytesIO(),
            key_wrap_id=KEY_WRAP_ID_RSA,
            sig_method_id=SIG_METHOD_ID_RSA,
            wrapped_dek=_DEK,
            sender_pubkey_raw=None,
            sign_private_key=_RSA["sign_private"],
            aes_key=b"\x00" * 32,
            key_id="rsa-enc-v1",
        )
        self.assertIsNone(writer._sender_pubkey_raw)


# ---------------------------------------------------------------------------
# Rewrap wire-format matrix
# ---------------------------------------------------------------------------

class TestRewrapWireFormatMatrix(unittest.TestCase):
    """Header rewrite through the shared serializer, for every version the format
    defines a rewrap for (v2/v3/v4 — v1 has no key_id to rewrap against)."""

    PLAINTEXT = b"rewrap matrix payload " * 300  # multi-KiB, still one chunk

    def _round_trip(self, method: str, version: int):
        raw, dek = _build_container(method, version, self.PLAINTEXT)
        before_header, before_body = _parse(raw)

        rewrapped = _rewrap_header(raw, method)

        # Byte-exact re-parse through the reader (validates the new signature too).
        after_header, after_body = _parse(rewrapped)

        cfg = _RSA if method == "rsa" else _ECC
        self.assertEqual(after_header.version, version)
        self.assertEqual(after_header.key_wrap_id, before_header.key_wrap_id)
        self.assertEqual(after_header.sig_method_id, before_header.sig_method_id)
        self.assertEqual(after_header.key_id, cfg["new_key_id"])
        self.assertNotEqual(after_header.key_id, before_header.key_id)
        self.assertEqual(after_header.classification, before_header.classification)
        if version >= STREAMING_CONTAINER_VERSION_V3:
            self.assertEqual(after_header.sign_key_id, cfg["sign_key_id"])
        else:
            self.assertIsNone(after_header.sign_key_id)
        if method == "ecc":
            self.assertIsNotNone(after_header.sender_pubkey_raw)
            self.assertNotEqual(
                after_header.sender_pubkey_raw, before_header.sender_pubkey_raw
            )
        else:
            self.assertIsNone(after_header.sender_pubkey_raw)

        # base_nonce preserved — pre-rewrap chunk nonces stay valid.
        self.assertEqual(after_header.base_nonce, before_header.base_nonce)

        # Chunk body copied verbatim; old trailer excluded from the new digest.
        self.assertEqual(after_body, before_body)
        self.assertNotIn(before_body + raw[len(raw) - 4:], rewrapped[:-4])

        # Decrypts with the re-wrapped DEK, and to the original plaintext.
        new_dek = _unwrap_dek(after_header)
        self.assertEqual(new_dek, dek)
        self.assertEqual(_decrypt(rewrapped, new_dek), self.PLAINTEXT)

    def test_rsa_v2(self):
        self._round_trip("rsa", STREAMING_CONTAINER_VERSION_V2)

    def test_rsa_v3(self):
        self._round_trip("rsa", STREAMING_CONTAINER_VERSION_V3)

    def test_rsa_v4(self):
        self._round_trip("rsa", STREAMING_CONTAINER_VERSION_V4)

    def test_ecc_v2(self):
        self._round_trip("ecc", STREAMING_CONTAINER_VERSION_V2)

    def test_ecc_v3(self):
        self._round_trip("ecc", STREAMING_CONTAINER_VERSION_V3)

    def test_ecc_v4(self):
        self._round_trip("ecc", STREAMING_CONTAINER_VERSION_V4)

    def test_old_body_trailer_is_replaced_not_appended(self):
        """The rewritten container ends with exactly one body-signature trailer."""
        raw, _dek = _build_container("rsa", STREAMING_CONTAINER_VERSION_V4, b"trailer")
        _header, body = _parse(raw)
        rewrapped = _rewrap_header(raw, "rsa")

        (old_sig_len,) = struct.unpack(">I", raw[-4:])
        old_trailer = raw[-(4 + old_sig_len):]
        self.assertNotIn(old_trailer, rewrapped)

        # A second verification pass would fail if stale trailer bytes were left
        # inside the body region.
        after_header, after_body = _parse(rewrapped)
        self.assertEqual(after_body, body)


# ---------------------------------------------------------------------------
# Engine-level rewrap
# ---------------------------------------------------------------------------

class TestRewrapEngine(unittest.TestCase):
    """rewrap_dek end-to-end for the versions the engine accepts."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        from spy.user_model import User
        self._admin = User("admin", "admin", "high", authenticated=True)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _write(self, name: str, raw: bytes) -> Path:
        path = self._tmp / name
        path.write_bytes(raw)
        return path

    def _rewrap_v4(self, method: str):
        from spy.file_crypto_engine import rewrap_dek
        plaintext = b"engine rewrap payload"
        raw, dek = _build_container(method, STREAMING_CONTAINER_VERSION_V4, plaintext)
        path = self._write(f"{method}_v4.enc", raw)
        before_header, before_body = _parse(raw)

        rewrap_dek(str(path), overwrite=True, user=self._admin)

        rewrapped = path.read_bytes()
        after_header, after_body = _parse(rewrapped)
        cfg = _RSA if method == "rsa" else _ECC

        self.assertEqual(rewrapped[4], raw[4])
        self.assertEqual(after_header.version, STREAMING_CONTAINER_VERSION_V4)
        self.assertEqual(after_header.key_id, cfg["new_key_id"])
        self.assertEqual(after_header.sign_key_id, cfg["sign_key_id"])
        self.assertEqual(after_header.classification, before_header.classification)
        self.assertEqual(after_header.base_nonce, before_header.base_nonce)
        self.assertEqual(after_body, before_body)
        self.assertEqual(_unwrap_dek(after_header), dek)
        self.assertEqual(_decrypt(rewrapped, dek), plaintext)

    def test_rewrap_v4_rsa(self):
        self._rewrap_v4("rsa")

    def test_rewrap_v4_ecc(self):
        self._rewrap_v4("ecc")

    def test_rewrap_v4_rsa_replaces_body_trailer(self):
        from spy.file_crypto_engine import rewrap_dek
        raw, _dek = _build_container("rsa", STREAMING_CONTAINER_VERSION_V4, b"trailer")
        path = self._write("trailer.enc", raw)
        (old_sig_len,) = struct.unpack(">I", raw[-4:])
        old_trailer = raw[-(4 + old_sig_len):]

        rewrap_dek(str(path), overwrite=True, user=self._admin)

        rewrapped = path.read_bytes()
        self.assertNotIn(old_trailer, rewrapped)
        _parse(rewrapped)  # raises if the trailer boundary is wrong

    def test_rewrap_of_legacy_container_is_denied(self):
        """v2/v3 containers carry no classification, so the engine's authorization
        gate denies rewrap before any header is written — the same fail-closed rule
        stream_decrypt_file applies to classification-less containers."""
        from spy.file_crypto_engine import FileCryptoError, rewrap_dek
        for version in (STREAMING_CONTAINER_VERSION_V2, STREAMING_CONTAINER_VERSION_V3):
            with self.subTest(version=version):
                raw, _dek = _build_container("rsa", version, b"legacy")
                path = self._write(f"legacy_v{version}.enc", raw)
                with self.assertRaises(FileCryptoError):
                    rewrap_dek(str(path), overwrite=True, user=self._admin)
                # Input left untouched on denial.
                self.assertEqual(path.read_bytes(), raw)

    def test_rewrap_does_not_construct_a_writer(self):
        """The rewrap path must not touch StreamingContainerWriter at all."""
        from unittest.mock import patch
        import spy.file_crypto_engine as engine

        raw, _dek = _build_container("rsa", STREAMING_CONTAINER_VERSION_V4, b"no writer")
        path = self._write("no_writer.enc", raw)

        with patch.object(engine, "StreamingContainerWriter") as writer_cls:
            writer_cls.side_effect = AssertionError(
                "rewrap must not construct a StreamingContainerWriter"
            )
            engine.rewrap_dek(str(path), overwrite=True, user=self._admin)

        writer_cls.assert_not_called()
        _parse(path.read_bytes())


# ---------------------------------------------------------------------------
# Existing regression guards
# ---------------------------------------------------------------------------

class TestRewrapVersionPreservation(unittest.TestCase):
    """Container version byte must be identical before and after rewrap."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)
        self._src = self._tmp / "plain.txt"
        self._src.write_bytes(b"version preservation payload")

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_rewrap_preserves_v4_version(self):
        ws_root = str(self._tmp)

        enc_output = _run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.file_crypto_engine import stream_encrypt_file; "
            f"print(stream_encrypt_file({str(self._src)!r}, output_path=None, method='rsa', overwrite=True))"
        )
        enc = Path(enc_output.strip())

        # Record the version byte from the original container (offset 4 after 4-byte magic).
        original_bytes = enc.read_bytes()
        original_version = original_bytes[4]

        # Rotate RSA enc key so rewrap has a different active key to wrap to.
        _run_subprocess(
            f"from spy.key_registry import KeyRegistry; "
            f"from spy.rsa_engine import rotate_rsa_encryption_keys; "
            f"reg = KeyRegistry(); reg.load(); "
            f"rotate_rsa_encryption_keys(reg)"
        )

        # Rewrap.
        _run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.user_model import User; "
            f"admin = User('admin', 'admin', 'high', authenticated=True); "
            f"from spy.file_crypto_engine import rewrap_dek; "
            f"rewrap_dek({str(enc)!r}, overwrite=True, user=admin)"
        )

        rewrapped_bytes = enc.read_bytes()
        rewrapped_version = rewrapped_bytes[4]

        self.assertEqual(
            original_version,
            rewrapped_version,
            f"Version byte changed: {original_version} → {rewrapped_version}",
        )

    def test_decrypt_after_rewrap_unchanged(self):
        ws_root = str(self._tmp)
        plaintext = b"decrypt after rewrap must be identical"
        self._src.write_bytes(plaintext)

        enc_output = _run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.file_crypto_engine import stream_encrypt_file; "
            f"print(stream_encrypt_file({str(self._src)!r}, output_path=None, method='rsa', overwrite=True))"
        )
        enc = Path(enc_output.strip())

        _run_subprocess(
            f"from spy.key_registry import KeyRegistry; "
            f"from spy.rsa_engine import rotate_rsa_encryption_keys; "
            f"reg = KeyRegistry(); reg.load(); "
            f"rotate_rsa_encryption_keys(reg)"
        )

        _run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.user_model import User; "
            f"admin = User('admin', 'admin', 'high', authenticated=True); "
            f"from spy.file_crypto_engine import rewrap_dek; "
            f"rewrap_dek({str(enc)!r}, overwrite=True, user=admin)"
        )

        dec_output = _run_subprocess(
            f"import os; os.environ['SAFE_FILE_ROOT']={ws_root!r}; "
            f"from spy.workspace import ensure_safe_workspace; ensure_safe_workspace(); "
            f"from spy.user_model import User; "
            f"admin = User('admin', 'admin', 'high', authenticated=True); "
            f"from spy.file_crypto_engine import stream_decrypt_file; "
            f"print(stream_decrypt_file({str(enc)!r}, output_path=None, overwrite=True, user=admin))"
        )
        dec = Path(dec_output.strip())

        self.assertEqual(dec.read_bytes(), plaintext)


class TestRewrapVersionMismatch(unittest.TestCase):
    """Version mismatch between input and output must raise FileCryptoError."""

    def test_version_field_captured_in_streaming_header(self):
        """StreamingHeader stores the version byte from the parsed container."""
        from spy.container_reader import StreamingHeader
        header = StreamingHeader(
            key_wrap_id=0x01,
            sig_method_id=0x01,
            wrapped_dek=b"\x00" * 256,
            sender_pubkey_raw=None,
            base_nonce=b"\x00" * 8,
            key_id="rsa-enc-v1",
            sign_key_id="rsa-sign-v1",
            classification="internal",
            version=4,
        )
        self.assertEqual(header.version, 4)

    def test_version_field_defaults_to_none(self):
        """StreamingHeader constructed without version= defaults to None (backward compat)."""
        from spy.container_reader import StreamingHeader
        header = StreamingHeader(
            key_wrap_id=0x01,
            sig_method_id=0x01,
            wrapped_dek=b"\x00" * 256,
            sender_pubkey_raw=None,
            base_nonce=b"\x00" * 8,
            key_id="rsa-enc-v1",
            sign_key_id=None,
            classification=None,
        )
        self.assertIsNone(header.version)

    def test_version_mismatch_logic_raises_file_crypto_error(self):
        """The version invariant condition correctly raises on mismatch."""
        from spy.file_crypto_engine import FileCryptoError
        input_version = 4
        output_version = 2  # simulated drift
        with self.assertRaises(FileCryptoError) as ctx:
            if input_version is not None and output_version != input_version:
                raise FileCryptoError("Container version mismatch: rewrap aborted")
        self.assertIn("version mismatch", str(ctx.exception))

    def test_version_mismatch_logic_passes_when_matching(self):
        """The version invariant condition does not raise when versions match."""
        from spy.file_crypto_engine import FileCryptoError
        input_version = 4
        output_version = 4
        try:
            if input_version is not None and output_version != input_version:
                raise FileCryptoError("Container version mismatch: rewrap aborted")
        except FileCryptoError:
            self.fail("FileCryptoError raised unexpectedly for matching versions")

    def test_version_mismatch_logic_skipped_when_input_none(self):
        """The invariant check is skipped when input header has no version (legacy path)."""
        from spy.file_crypto_engine import FileCryptoError
        input_version = None
        output_version = 2
        try:
            if input_version is not None and output_version != input_version:
                raise FileCryptoError("Container version mismatch: rewrap aborted")
        except FileCryptoError:
            self.fail("FileCryptoError raised when input_version is None")


if __name__ == "__main__":
    unittest.main(verbosity=2)
