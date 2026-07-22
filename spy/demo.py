"""
demo.py — Final system demonstration.

Demonstrates the complete encryption governance system:
  1. Create a plaintext file
  2. Encrypt the file (SVST streaming container)
  3. Sign the encrypted file with a detached .sig (SSIG format)
  4. Verify audit log entry
  5. Tamper with the encrypted file
  6. Attempt decryption → system detects tampering
  7. Decrypt the untampered file → success

Run with: python3 demo.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from .file_crypto_engine import FileCryptoError, stream_decrypt_file, stream_encrypt_file
from .audit_logger import AUDIT_LOG_FILE, AuditLogger
from .crypto_container import STREAMING_MAGIC
from .key_provider import KeyProviderError, LocalPemKeyProvider
from .signature_engine import SignatureError, decode_sig_file, encode_sig_file, sign, verify
from .user_model import User

DIVIDER = "-" * 60


def section(title: str) -> None:
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)


def main() -> None:
    print("\nAI-Orchestrated Hybrid Encryption Governance System")
    print("Final System Demonstration")

    provider = LocalPemKeyProvider()

    # -----------------------------------------------------------------------
    # Step 1 — Create a plaintext file
    # -----------------------------------------------------------------------
    section("STEP 1 — Create plaintext file")

    tmpdir = tempfile.mkdtemp()
    plaintext_path = os.path.join(tmpdir, "confidential_report.txt")
    secret_content = (
        b"CONFIDENTIAL REPORT\n"
        b"Project: Hybrid Encryption Governance\n"
        b"Status: Operational\n"
        b"Clearance: HIGH\n"
    )
    Path(plaintext_path).write_bytes(secret_content)
    print(f"  File created : {plaintext_path}")
    print(f"  Content      : {secret_content.decode()}")

    # -----------------------------------------------------------------------
    # Step 2 — Encrypt the file
    # -----------------------------------------------------------------------
    section("STEP 2 — Encrypt the file")

    enc_path = plaintext_path + ".enc"
    enc_result = stream_encrypt_file(
        plaintext_path, output_path=enc_path, method="rsa", overwrite=True, provider=provider
    )
    print(f"  Encrypted    : {enc_result}")

    # Inspect the SVST streaming container header
    enc_bytes = Path(enc_path).read_bytes()
    magic = enc_bytes[:4]
    version = enc_bytes[4]
    key_wrap_id = enc_bytes[5]
    sig_method_id = enc_bytes[6]
    key_wrap_name = {1: "RSA-OAEP", 2: "ECDH-AES"}.get(key_wrap_id, "unknown")
    sig_method_name = {1: "RSA-PSS", 2: "ECDSA"}.get(sig_method_id, "unknown")
    print(f"  Format       : SVST streaming container")
    print(f"  Magic        : {magic!r}  version={version}")
    print(f"  Key wrap     : {key_wrap_name}  |  Sig method: {sig_method_name}")
    print(f"  Total size   : {len(enc_bytes)} bytes")

    # -----------------------------------------------------------------------
    # Step 2b — Sign the encrypted file with a detached .sig
    # -----------------------------------------------------------------------
    section("STEP 2b — Sign the encrypted file (RSA-PSS, detached .sig)")

    try:
        sign_priv_key = provider.get_rsa_signing_private_key()
        sign_pub_key = provider.get_rsa_signing_public_key()
    except KeyProviderError as exc:
        print("  Key load failed.", file=sys.stderr)
        sys.exit(1)

    raw_signature = sign("rsa", sign_priv_key, enc_bytes)
    sig_path = enc_path + ".sig"
    Path(sig_path).write_bytes(encode_sig_file("rsa", raw_signature))
    print(f"  Signature    : {sig_path}")
    print(f"  Sig size     : {len(raw_signature)} bytes (DER) — SSIG header added")

    # -----------------------------------------------------------------------
    # Step 3 — Verify audit log entry
    # -----------------------------------------------------------------------
    section("STEP 3 — Write and inspect audit log")

    demo_user = User("demo_admin", "admin", "high")
    try:
        demo_key_id = provider.get_active_rsa_key_id()
    except KeyProviderError:
        demo_key_id = "rsa-enc-v1"
    AuditLogger.log_event(
        demo_user,
        action="ENCRYPT",
        classification="high",
        outcome="success",
        key_id=demo_key_id,
    )

    audit_log_path = AUDIT_LOG_FILE
    if audit_log_path.exists():
        lines = audit_log_path.read_text().strip().splitlines()
        last_entry = json.loads(lines[-1]) if lines else {}
        print(f"  Audit entry  :")
        for k, v in last_entry.items():
            print(f"    {k:22s}: {v}")
    else:
        print("  (Audit log not found — entry was written to memory logger)")

    # -----------------------------------------------------------------------
    # Step 4 — Tamper with encrypted file (flip a byte in the chunk payload)
    # -----------------------------------------------------------------------
    section("STEP 4 — Tamper with the encrypted file")

    tampered_enc = enc_path + ".tampered.enc"
    raw = bytearray(Path(enc_path).read_bytes())
    # Flip a byte well into the chunk payload — AES-GCM authentication will
    # detect the corruption when the chunk is decrypted.
    flip_offset = len(raw) // 2
    raw[flip_offset] ^= 0xFF
    Path(tampered_enc).write_bytes(bytes(raw))
    print(f"  Tampered copy: {tampered_enc}")
    print(f"  (Flipped byte at offset {flip_offset} — inside encrypted chunk payload)")

    # -----------------------------------------------------------------------
    # Step 5 — Attempt decryption of tampered file → system detects tampering
    # -----------------------------------------------------------------------
    section("STEP 5 — Attempt decryption of tampered file")

    tampered_out = tampered_enc + ".dec"
    try:
        stream_decrypt_file(tampered_enc, output_path=tampered_out, overwrite=True, provider=provider)
        print("  FAIL: decryption should have been rejected!", file=sys.stderr)
        sys.exit(1)
    except FileCryptoError:
        print("  Tampering DETECTED (FileCryptoError):")
        print("    Integrity check failed.")
        print("  System correctly refused to decrypt tampered ciphertext.")

    # Also show that the detached .sig catches tampering on the external signature
    _, decoded_sig = decode_sig_file(Path(sig_path).read_bytes())
    try:
        verify("rsa", sign_pub_key, decoded_sig, bytes(raw))
        print("  FAIL: signature verification should have failed!", file=sys.stderr)
    except SignatureError:
        print("\n  Detached .sig check FAILED on tampered data (as expected):")
        print("    Signature check failed.")

    # -----------------------------------------------------------------------
    # Step 6 — Decrypt the untampered file → success
    # -----------------------------------------------------------------------
    section("STEP 6 — Decrypt the original (untampered) file")

    # Verify detached signature against original
    try:
        verify("rsa", sign_pub_key, decoded_sig, enc_bytes)
        print("  Detached .sig verified: authentic and unmodified")
    except SignatureError as exc:
        print("  Signature FAILED.", file=sys.stderr)
        sys.exit(1)

    dec_path = plaintext_path + ".dec"
    result = stream_decrypt_file(
        enc_path, output_path=dec_path, overwrite=True, provider=provider
    )
    recovered = Path(dec_path).read_bytes()

    print(f"  Decrypted    : {result}")
    print(f"  Content      :\n{recovered.decode()}")

    if recovered == secret_content:
        print("  Content integrity: VERIFIED — plaintext matches original exactly")
    else:
        print("  FAIL: content mismatch!", file=sys.stderr)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Cleanup temp files
    # -----------------------------------------------------------------------
    for p in [plaintext_path, enc_path, sig_path, tampered_enc, dec_path]:
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    try:
        os.rmdir(tmpdir)
    except OSError:
        pass

    print(f"\n{DIVIDER}")
    print("  DEMONSTRATION COMPLETE — All steps passed successfully")
    print(DIVIDER)


if __name__ == "__main__":
    main()
