"""
orchestrator.py — Optional natural-language context extraction for encryption policy.

Converts a free-text description of an encryption scenario into the structured
context dict (environment, compliance level, performance priority, etc.) that the
policy engine consumes when selecting an algorithm. This is an optional,
research-oriented convenience layer: it is NOT part of the cryptographic core and
performs no encryption, authentication, or authorization itself.

When no OpenAI API key is configured (or the LLM call fails), it falls back to a
safe DEFAULT_CONTEXT — fail-safe, never raising into the caller.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# When True, skips the LLM entirely and always returns DEFAULT_CONTEXT (offline mode).
DEV_MODE = False

SYSTEM_PROMPT = """
You are a security context extraction engine.
Convert enterprise encryption requirements into structured JSON.
Return JSON only.
Allowed values:
environment: mobile | enterprise | embedded | cloud
compliance_level: strict | moderate | none
performance_priority: high | medium | low
legacy_support_required: true | false
bandwidth_constraint: low | medium | high
""".strip()

DEFAULT_CONTEXT = {
    "environment": "cloud",
    "compliance_level": "none",
    "performance_priority": "medium",
    "legacy_support_required": False,
    "bandwidth_constraint": "medium",
}

REQUIRED_FIELDS = {
    "environment": ["mobile", "enterprise", "embedded", "cloud"],
    "compliance_level": ["strict", "moderate", "none"],
    "performance_priority": ["high", "medium", "low"],
    "legacy_support_required": [True, False],
    "bandwidth_constraint": ["low", "medium", "high"],
}


def validate_context(context: dict) -> bool:
    if not isinstance(context, dict):
        return False
    for field, allowed_values in REQUIRED_FIELDS.items():
        if field not in context:
            return False
        value = context[field]
        if field == "legacy_support_required":
            if not isinstance(value, bool):
                return False
        elif value not in allowed_values:
            return False
    return True


def _get_openai_client():
    api_key = os.getenv("OPENAI_API_KEY")
    if DEV_MODE or not api_key:
        return None
    try:
        from openai import OpenAI
        return OpenAI(api_key=api_key)
    except Exception:
        return None


def llm_extract_context(user_input: str):
    client = _get_openai_client()
    if client is None:
        return DEFAULT_CONTEXT.copy()
    try:
        response = client.responses.create(
            model="gpt-4.1-mini",
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_input},
            ],
            temperature=0,
        )
        raw_output = getattr(response, "output_text", "") or ""
        start = raw_output.find("{")
        end = raw_output.rfind("}")
        if start == -1 or end == -1:
            return DEFAULT_CONTEXT.copy()
        context = json.loads(raw_output[start:end + 1])
        return context if validate_context(context) else DEFAULT_CONTEXT.copy()
    except Exception:
        return DEFAULT_CONTEXT.copy()


def _display_result(result):
    if isinstance(result, bytes):
        try:
            return result.decode("utf-8")
        except UnicodeDecodeError:
            return result.hex()
    return str(result)
