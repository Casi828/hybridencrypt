"""
user_model.py — User entity for RBAC and audit logging.
"""

from __future__ import annotations

VALID_ROLES: frozenset[str] = frozenset({"admin", "analyst", "auditor", "guest"})
VALID_CLEARANCES: frozenset[str] = frozenset({"low", "medium", "high"})
_VALID_STATUSES: frozenset[str] = frozenset({"active", "disabled"})


class UserRecordError(ValueError):
    """Raised when a user store record fails schema validation."""


def validate_user_record(record: dict) -> None:
    """Validate a raw user store record dict after HMAC verification.

    Raises UserRecordError if any required field is missing, the wrong type,
    or has an invalid value. Call this at the load boundary before the record
    is used to construct a User or make authorization decisions.
    """
    required = ("username", "role", "clearance", "status", "password_hash")
    for field in required:
        if field not in record:
            raise UserRecordError(f"User record missing required field: {field!r}")
    if not isinstance(record["username"], str) or not record["username"].strip():
        raise UserRecordError("username must be a non-empty string")
    if record["role"] not in VALID_ROLES:
        raise UserRecordError(f"role {record['role']!r} is not a valid role")
    if record["clearance"] not in VALID_CLEARANCES:
        raise UserRecordError(f"clearance {record['clearance']!r} is not a valid clearance level")
    if record["status"] not in _VALID_STATUSES:
        raise UserRecordError(f"status {record['status']!r} is not a valid status")


class User:
    """Authenticated identity carried through authorization and audit.

    ``authenticated`` defaults to False and is set True only by ``auth.authenticate``
    on a verified login. Governance checks require ``authenticated is True``, so a
    ``User`` constructed directly elsewhere cannot bypass authentication.
    """

    def __init__(self, username: str, role: str, clearance: str, authenticated: bool = False) -> None:
        """Create a user identity.

        Args:
            username: Account name used for audit attribution.
            role: RBAC role (see ``VALID_ROLES``) governing permitted actions.
            clearance: Clearance level (see ``VALID_CLEARANCES``) bounding the
                maximum data classification this user may access.
            authenticated: Whether this identity has passed authentication. Leave
                False unless set by the authentication path.
        """
        self.username = username
        self.role = role
        self.clearance = clearance
        self.authenticated = authenticated

    def to_dict(self) -> dict[str, str]:
        """Return the non-secret identity fields (username, role, clearance).

        Deliberately omits ``authenticated`` and any credential material so the
        result is safe to embed in packages, logs, or serialized output.
        """
        return {"username": self.username, "role": self.role, "clearance": self.clearance}

    def __repr__(self) -> str:
        """Return a debug representation. Contains no password or credential data."""
        return f"User(username={self.username!r}, role={self.role!r}, clearance={self.clearance!r}, authenticated={self.authenticated!r})"
