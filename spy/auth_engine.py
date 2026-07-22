"""
auth_engine.py — Role-based access control (RBAC) with clearance-level enforcement.

Roles define which actions a user may perform.
Clearance levels define the maximum data classification a user may access.
Both checks must pass for an operation to be authorized.
"""

from __future__ import annotations

_ROLE_PERMISSIONS: dict[str, list[str]] = {
    "admin":   ["encrypt", "decrypt", "rotate_keys", "rewrap", "sign", "verify",
               "verify_audit", "export_logs"],
    "analyst": ["encrypt", "decrypt"],
    "auditor": ["view_logs", "verify_audit", "export_logs"],
    "guest":   [],
}

_CLEARANCE_RANK: dict[str, int] = {
    "low":    1,
    "medium": 2,
    "high":   3,
}

_CLASSIFICATION_RANK: dict[str, int] = {
    "low":    1,
    "medium": 2,
    "high":   3,
}


class AuthorizationEngine:
    """Stateless authorization decision point for governed operations.

    Enforces two independent checks, both of which must pass (fail-closed):

    1. **Role permission** — the user's role must grant the requested action
       (see ``_ROLE_PERMISSIONS``).
    2. **Clearance dominance** — the user's clearance rank must be greater than
       or equal to the data's classification rank (see ``_CLEARANCE_RANK`` /
       ``_CLASSIFICATION_RANK``).

    The engine holds no state and performs no I/O; callers pass the already
    authenticated user, and the returned reason string is safe to record in the
    audit log without leaking sensitive detail.
    """

    @staticmethod
    def authorize(user, action: str, data_classification: str) -> tuple[bool, str]:
        """Check whether a user is permitted to perform an action on classified data.

        Args:
            user: Object with 'role' and 'clearance' string attributes.
            action: Requested operation (e.g. 'encrypt', 'decrypt').
            data_classification: Classification of the target data ('low', 'medium', 'high').

        Returns:
            (True, 'Authorized') if both role and clearance checks pass.
            (False, reason) otherwise — reason is safe to surface in audit logs.
        """
        if user is None:
            return False, "Invalid user"

        if not getattr(user, "authenticated", False):
            return False, "Not authenticated"

        role = getattr(user, "role", "").lower()
        clearance = getattr(user, "clearance", "").lower()
        action = str(action).lower()
        classification = str(data_classification).lower()

        if role not in _ROLE_PERMISSIONS:
            return False, "Unknown role"

        if classification not in _CLASSIFICATION_RANK:
            return False, "Invalid data classification"

        if action not in _ROLE_PERMISSIONS[role]:
            return False, "Role not permitted for this action"

        if clearance not in _CLEARANCE_RANK:
            return False, "Invalid clearance"
        user_rank = _CLEARANCE_RANK[clearance]
        required_rank = _CLASSIFICATION_RANK[classification]
        if user_rank < required_rank:
            return False, "Insufficient clearance"

        return True, "Authorized"
