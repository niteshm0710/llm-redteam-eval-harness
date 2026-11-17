"""Credential scrubbing utilities ensuring provider secrets never leak into logs or errors."""

from __future__ import annotations

import re

from redteam_harness.config import SYNTHETIC_GATEWAY_KEY

_BEARER_RE = re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._\-]{8,}")
_API_KEY_RE = re.compile(r"\b(sk-(?:proj-|live-|test-)?)[A-Za-z0-9_\-]{12,}\b")


def redact_secrets(text: str, extra_secrets: list[str] | None = None) -> str:
    """Scrub real bearer tokens and API keys while preserving synthetic eval canaries."""
    if not text:
        return text

    sanitized = text
    for secret in extra_secrets or []:
        if secret and len(secret) >= 6 and secret != SYNTHETIC_GATEWAY_KEY:
            sanitized = sanitized.replace(secret, "[REDACTED_SECRET]")

    def _replace_api_key(match: re.Match[str]) -> str:
        full = match.group(0)
        if full == SYNTHETIC_GATEWAY_KEY:
            return full
        return f"{match.group(1)}[REDACTED]"

    sanitized = _BEARER_RE.sub(r"\1[REDACTED]", sanitized)
    sanitized = _API_KEY_RE.sub(_replace_api_key, sanitized)
    return sanitized
