"""
policy_engine.py — Context-driven encryption method selection.

Scores RSA and ECC against deployment context signals and returns the
higher-scoring method. Raises PolicyError on invalid context values.
"""

from __future__ import annotations

VALID_ENVIRONMENTS = frozenset({"mobile", "enterprise", "embedded", "cloud"})
VALID_COMPLIANCE = frozenset({"strict", "moderate", "none"})
VALID_PERFORMANCE = frozenset({"high", "medium", "low"})
VALID_BANDWIDTH = frozenset({"low", "medium", "high"})


class PolicyError(Exception):
    pass


def _normalized_bool(value) -> bool:
    """Coerce a value to bool, accepting string representations."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1"}:
            return True
        if normalized in {"false", "no", "0", ""}:
            return False
    return bool(value)


def select_encryption_method(context: dict) -> str:
    """Select 'rsa' or 'ecc' based on weighted scoring of deployment context signals.

    Args:
        context: Dict with keys: environment, compliance_level, performance_priority,
                 legacy_support_required, bandwidth_constraint.

    Returns:
        'rsa' or 'ecc'.

    Raises:
        PolicyError: If context is not a dict or contains invalid field values.
    """
    if not isinstance(context, dict):
        raise PolicyError("Policy context must be a dictionary")

    env = str(context.get("environment", "")).lower()
    compliance = str(context.get("compliance_level", "")).lower()
    performance = str(context.get("performance_priority", "")).lower()
    bandwidth = str(context.get("bandwidth_constraint", "")).lower()
    legacy_support = _normalized_bool(context.get("legacy_support_required", False))

    if env and env not in VALID_ENVIRONMENTS:
        raise PolicyError(f"Invalid environment value: {env!r}")
    if compliance and compliance not in VALID_COMPLIANCE:
        raise PolicyError(f"Invalid compliance level: {compliance!r}")
    if performance and performance not in VALID_PERFORMANCE:
        raise PolicyError(f"Invalid performance priority: {performance!r}")
    if bandwidth and bandwidth not in VALID_BANDWIDTH:
        raise PolicyError(f"Invalid bandwidth constraint: {bandwidth!r}")

    rsa_score = 0
    ecc_score = 0

    if env in {"mobile", "embedded"}:
        ecc_score += 3
    elif env == "cloud":
        ecc_score += 2
    elif env == "enterprise":
        rsa_score += 2

    if compliance == "strict":
        rsa_score += 3
    elif compliance == "moderate":
        rsa_score += 1

    if performance == "high":
        ecc_score += 3
    elif performance == "medium":
        ecc_score += 1

    if legacy_support:
        rsa_score += 3

    if bandwidth == "low":
        ecc_score += 2
    elif bandwidth == "medium":
        ecc_score += 1

    return "ecc" if ecc_score >= rsa_score else "rsa"


def determine_classification(context: dict) -> str:
    """Assign data classification from context signals.

    Classification is policy-assigned — callers provide signals, not the result.

    Args:
        context: Dict with optional keys: sensitive (bool), internal (bool).

    Returns:
        'high', 'medium', or 'low'.

    Raises:
        PolicyError: If context is not a dict.
    """
    if not isinstance(context, dict):
        raise PolicyError("Policy context must be a dictionary")
    if context.get("sensitive"):
        return "high"
    if context.get("internal"):
        return "medium"
    return "low"
