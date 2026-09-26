"""
AI Context Sanitization — Ask Sentinel

Applies strict secret redaction to all scan/finding context data before it is
sent to any LLM provider. This is a defense-in-depth layer on top of the
existing app.utils.sanitize module (which handles exports/PDFs).

All credential redaction patterns are CENTRALIZED in app.utils.sanitize
(REDACT_PATTERNS) and reused here — there is exactly one source of truth for
secret formats. This module adds AI-context-specific hardening:
  - Recursive dict/list context scrubbing with a sensitive-key denylist
  - Truncation budgets so hostile targets cannot bloat the prompt
  - Header allowlisting (only security-relevant headers reach the LLM)
  - Env-var leak patterns for Sentinel's own configuration names

Secrets redacted / excluded:
  - Authorization headers and values
  - Cookie / Set-Cookie headers
  - JWT tokens (eyJ... three-segment shape)
  - API keys (X-API-Key, api_key=... assignments, Google AIza, Stripe sk_,
    Anthropic sk-ant-api, OpenAI sk-proj-, SendGrid SG.) 
  - Private key PEM blocks
  - Passwords, secret_key, smtp_password, smtp_user assignments
  - AWS access key IDs (AKIA/ASIA prefix) and secret-access-key assignments
  - GitHub / Slack token patterns
  - Database URL passwords (scheme://user:pass@host shape)
  - Any field whose KEY name matches a known sensitive term

The sanitize_context_for_llm() function takes an arbitrary dict and returns
a new dict with sensitive data redacted. Keys whose names signal credential
material are dropped entirely (fail-safe).
"""
import re
from typing import Any

from app.utils.sanitize import REDACT_PATTERNS as _CANONICAL_REDACT_PATTERNS

# ── Key-level denylist: drop any dict key whose name contains these terms ─────
# Applied recursively on the context dict before it reaches the LLM.
# This is a belt-and-braces approach complementing value-level regex redaction.
_SENSITIVE_KEY_TERMS = frozenset({
    "password", "passwd", "secret", "api_key", "apikey", "api_secret",
    "token", "access_token", "refresh_token", "auth_token", "session_token",
    "secret_key", "private_key", "client_secret",
    "authorization", "authorisation", "bearer",
    "smtp_password", "smtp_user", "smtp_pass",
    "database_url", "db_url", "connection_string",
    "jwt", "session", "cookie",
    "credential", "credentials",
})


def _key_is_sensitive(key: str) -> bool:
    """Return True if a dict key name signals credential/secret material."""
    lower = key.lower()
    return any(term in lower for term in _SENSITIVE_KEY_TERMS)


# ── Value-level redaction patterns (applied to all string values) ─────────────
# The canonical credential patterns live in app.utils.sanitize.REDACT_PATTERNS
# (single source of truth used by exports, PDFs and persistence clamping).
# AI-specific additions below target SentinelScan's own configuration shape
# and stand-alone env-var leaks.
_AI_ONLY_PATTERNS = [
    # Environment variable leaks (KEY=VALUE lines with common secret names)
    (re.compile(
        r'(?i)\b(SECRET_KEY|OPENAI_API_KEY|AI_OPENAI_API_KEY|GEMINI_API_KEY|AI_GEMINI_API_KEY|NVD_API_KEY|'
        r'GOOGLE_CLIENT_SECRET|SMTP_PASSWORD|DATABASE_URL|REDIS_URL)\s*=\s*\S+'
    ), r'\1=[REDACTED]'),
]

_REDACT_PATTERNS = list(_CANONICAL_REDACT_PATTERNS) + _AI_ONLY_PATTERNS

# ── Raw headers field denylist — specific HTTP header names to redact values ──
_SENSITIVE_HEADER_NAMES = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key", "api-key",
    "x-auth-token", "x-access-token", "proxy-authorization",
})

_MAX_EVIDENCE_CHARS = 800   # truncate long evidence strings before sending to LLM
_MAX_STRING_CHARS  = 2000   # truncate any individual string value in context


def _redact_string(value: str) -> str:
    """Apply all value-level redaction patterns to a string."""
    for pattern, replacement in _REDACT_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def sanitize_text(text: str | None) -> str:
    """Redact secrets from free-text (user messages, selected text, evidence).

    Redaction only — no truncation. Returns '' for empty/None input.
    """
    if not text:
        return text or ""
    return _redact_string(text)


def _sanitize_value(value: Any, key: str = "") -> Any:
    """
    Recursively sanitize a single context value.
    - Strings: apply regex redaction and truncate
    - Dicts: recurse, dropping sensitive keys
    - Lists: recurse over elements
    - Other scalar: pass through
    """
    if isinstance(value, str):
        redacted = _redact_string(value)
        return redacted[:_MAX_STRING_CHARS]
    if isinstance(value, dict):
        return _sanitize_dict(value)
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    return value  # int, float, bool, None — safe to pass through


def _sanitize_dict(d: dict) -> dict:
    """Return a new dict with sensitive keys dropped and values sanitized."""
    result = {}
    for k, v in d.items():
        if _key_is_sensitive(str(k)):
            continue  # drop the key entirely — fail-safe
        result[str(k)] = _sanitize_value(v, key=str(k))
    return result


def sanitize_raw_headers(headers: dict | None) -> dict | None:
    """
    Sanitize a raw HTTP response headers dict before including in context.
    Drops security-sensitive header values (Authorization, Cookie, etc.).
    Only includes headers that are relevant to security assessment.
    """
    if not headers:
        return None

    # Headers relevant to security analysis (allowlist approach)
    _RELEVANT_HEADERS = {
        "content-security-policy", "x-content-type-options", "x-frame-options",
        "strict-transport-security", "referrer-policy", "permissions-policy",
        "x-xss-protection", "x-powered-by", "server", "content-type",
        "cache-control", "access-control-allow-origin", "cross-origin-opener-policy",
        "cross-origin-embedder-policy", "cross-origin-resource-policy",
        "x-download-options", "x-permitted-cross-domain-policies",
        "nel", "report-to", "expect-ct", "alt-svc",
    }

    result = {}
    for header_name, header_value in headers.items():
        name_lower = header_name.lower().strip()
        # Always drop sensitive headers
        if name_lower in _SENSITIVE_HEADER_NAMES:
            continue
        # Only include security-relevant headers
        if name_lower in _RELEVANT_HEADERS:
            result[header_name] = str(header_value)[:500]
    return result or None


def sanitize_evidence(evidence: str | None) -> str | None:
    """
    Sanitize finding evidence before sending to LLM.
    Applies full redaction and truncates to _MAX_EVIDENCE_CHARS.
    """
    if not evidence:
        return None
    redacted = _redact_string(evidence)
    if len(redacted) > _MAX_EVIDENCE_CHARS:
        redacted = redacted[:_MAX_EVIDENCE_CHARS] + "... [truncated for brevity]"
    return redacted


def sanitize_context_for_llm(context: dict) -> dict:
    """
    Main entry point. Takes an arbitrary context dict and returns a sanitized
    copy with all sensitive data removed or redacted.

    This is the last line of defense before context reaches the LLM.
    """
    return _sanitize_dict(context)
