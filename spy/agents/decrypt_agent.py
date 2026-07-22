"""
agents/decrypt_agent.py — Decryption agent.

Delegates to stream_decrypt_file(), which enforces authentication,
authorization (AuthorizationEngine), and audit logging.
No crypto logic is implemented here.
"""

from __future__ import annotations

from spy.file_crypto_engine import stream_decrypt_file


def run(user, encrypted_path: str, output_path: str | None = None) -> str:
    """Decrypt a file through the file crypto engine.

    Returns:
        Absolute path to the decrypted output file as a str.

    Raises:
        FileCryptoError: On authentication failure, authorization denial,
            missing or invalid container, signature verification failure, or
            any other crypto error. Never caught here — propagates to the caller.

    Security: stream_decrypt_file() enforces authentication (user.authenticated),
    authorization (AuthorizationEngine.authorize()), audit logging, and header +
    body signature verification before releasing any plaintext.
    """
    return stream_decrypt_file(encrypted_path, output_path=output_path, user=user)
