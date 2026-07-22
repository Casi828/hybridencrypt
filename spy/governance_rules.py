"""
governance_rules.py — Mandatory security policy enforcement.

These rules are evaluated before any cryptographic operation is allowed.
Violations raise GovernanceViolation and must never be silently bypassed.

Enforced rules:
  - AES key must be exactly 256 bits (32 bytes) — AES-128 is rejected
  - RSA key size must be >= 3072 bits
  - ECC curve must be an approved NIST curve (P-256, P-384, P-521)
  - Encryption method must be 'rsa' or 'ecc' (no legacy/weak methods)
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec, rsa

AES_REQUIRED_KEY_BYTES = 32       # 256 bits only
RSA_MIN_KEY_BITS = 3072
APPROVED_ECC_CURVES = frozenset({"secp256r1", "secp384r1", "secp521r1"})
APPROVED_METHODS = frozenset({"rsa", "ecc"})


class GovernanceViolation(Exception):
    """Raised when a security policy rule is violated."""


def enforce_aes_key_size(aes_key: bytes) -> None:
    """Reject any AES key that is not exactly 256 bits (32 bytes)."""
    if not isinstance(aes_key, (bytes, bytearray)):
        raise GovernanceViolation("AES key must be bytes")
    if len(aes_key) != AES_REQUIRED_KEY_BYTES:
        raise GovernanceViolation(
            f"AES key is {len(aes_key) * 8} bits — only AES-256 (32 bytes) is permitted"
        )


def enforce_rsa_key_size(public_key) -> None:
    """Reject RSA keys smaller than RSA_MIN_KEY_BITS."""
    key_size = getattr(public_key, "key_size", 0)
    if key_size < RSA_MIN_KEY_BITS:
        raise GovernanceViolation(
            f"RSA key is {key_size} bits — minimum is {RSA_MIN_KEY_BITS} bits"
        )


def enforce_ecc_curve(private_key) -> None:
    """Reject ECC keys on non-approved curves."""
    curve_name = getattr(getattr(private_key, "curve", None), "name", "").lower()
    if curve_name not in APPROVED_ECC_CURVES:
        raise GovernanceViolation(
            f"ECC curve '{curve_name}' is not approved. "
            f"Approved curves: {sorted(APPROVED_ECC_CURVES)}"
        )


def enforce_method(method: str) -> None:
    """Reject any encryption method not in the approved set."""
    if method not in APPROVED_METHODS:
        raise GovernanceViolation(
            f"Encryption method '{method}' is not approved. "
            f"Approved methods: {sorted(APPROVED_METHODS)}"
        )


def enforce_all(method: str, private_key=None, aes_key: bytes | None = None) -> None:
    """Run all applicable governance checks for a given operation.

    Args:
        method: Encryption method string ('rsa' or 'ecc').
        private_key: The asymmetric private key to validate (optional).
        aes_key: The AES key bytes to validate (optional).

    Raises:
        GovernanceViolation: On any policy violation.
    """
    enforce_method(method)

    if aes_key is not None:
        enforce_aes_key_size(aes_key)

    if private_key is not None:
        if method == "rsa":
            enforce_rsa_key_size(private_key)
        elif method == "ecc":
            enforce_ecc_curve(private_key)
