"""
agents/encrypt_agent.py — Encryption agent.

Delegates to GovernancePipeline.encrypt(), which enforces authentication,
authorization (AuthorizationEngine), KeyProvider boundary, and audit logging.
No crypto logic is implemented here.
"""

from __future__ import annotations

from spy.governance_pipeline import GovernancePipeline
from spy.key_provider import LocalPemKeyProvider


def run(user, context: dict, message: bytes | str, data_classification: str) -> tuple[bool, object]:
    """Encrypt a message through the governance pipeline."""
    provider = LocalPemKeyProvider()
    pipeline = GovernancePipeline(provider)
    return pipeline.encrypt(user, context, message, data_classification)
