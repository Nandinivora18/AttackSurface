"""
Centralized server-side text sanitization for exported artifacts and persisted findings.

Used by:
  - app/utils/pdf_generator.py  (credential redaction before PDF rendering)
  - app/utils/exporter.py       (HTML escaping, CSV formula neutralization,
                                 credential redaction for CSV/JSON/HTML exports)
  - app/tasks/scan_task.py      (clamping of target-controlled strings before
                                 Finding persistence)

Security controls implemented here:
  - Credential/secret redaction (Authorization/Cookie/API keys/JWTs/.env secrets)
  - HTML entity escaping of untrusted values before interpolation into reports
  - CSV spreadsheet formula-injection neutralization (=, +, -, @ prefixes)
  - Length clamping so hostile targets cannot overflow DB columns or bloat reports
"""
import html as _html
import re

# ─────────────────────────────────────────────────────────────────────────────
# Credential / secret redaction (server-side)
# ─────────────────────────────────────────────────────────────────────────────

# Patterns that match credential-bearing header values or standalone secrets.
#
# Design rules (per-pattern "detects / ignores / why FP-risk is controlled"):
#
#   Authorization schemes        VALUE portion only, so prose such as
#                                "authorization controls need review" survives.
#   Cookie/Set-Cookie            Whole remainder of THE LINE — cookies are
#                                pure credential material; multiline values
#                                are redacted per line (documented limit).
#   JWT                          Requires the eyJ…x.y.z three-segment shape;
#                                ordinary sentences never match.
#   Credential assignments       Matches KEY = value / KEY: value forms for
#                                password/passwd/pwd/pass/api_key/client_secret/
#                                api_secret/access_token/auth_token/
#                                refresh_token/session_token/secret_key/smtp_*.
#                                Quoted values may contain spaces (≤128 chars,
#                                same line only); unquoted values are limited to
#                                the next whitespace token (\S+), so an entire
#                                sentence is never consumed. Prose mentioning
#                                these words WITHOUT an assignment operator
#                                never matches.
#   AWS access keys              Canonical 20-char ID shape (AKIA|ASIA +
#                                16 uppercase alphanumerics), case-sensitive.
#                                Lowercase lookalikes and the bare word "AKIA"
#                                do not match.
#   GitHub tokens                Documented prefixes ghp_/gho_/ghu_/ghs_/ghr_
#                                (≥20 trailing base62; canonical is 36 — floor
#                                kept lower for resilience) and fine-grained
#                                github_pat_ tokens. Random prose cannot
#                                contain these prefixes.
#   Slack tokens                 Documented prefixes xoxa/xoxb/xoxp/xoxr
#                                followed by ≥10 token characters. "xoxo-" or
#                                plain "slack" do not match.
#   Standalone Basic auth        "Basic <base64blob>" WITHOUT an Authorization:
#                                prefix, only when the blob is ≥16 base64 chars
#                                containing BOTH upper- and lowercase letters
#                                (real base64 of "user:pass" always mixes case;
#                                ordinary words like "authentication" are
#                                lowercase-only and rejected).
#   Database URLs                scheme://user:<password>@ shapes for common
#                                DB/broker schemes — the classic .env
#                                DATABASE_URL leak. Host/port/path retained so
#                                the evidence stays useful.
#
# KNOWN LIMITATIONS (intentional, documented):
#   * Unquoted secret values CONTAINING SPACES are only partially redacted
#     (first token) — quoted values are fully redacted instead. Consuming
#     arbitrary whitespace runs would destroy legitimate technical prose.
#   * Multiline header values are redacted per line.
#   * Raw high-entropy strings without a recognizable format (custom API keys
#     with no prefix/assignment) are out of scope for pattern redaction.
REDACT_PATTERNS = [
    # ── Authorization header values (value portion only) ──────────────────
    (re.compile(r'(?i)(Authorization\s*:\s*Bearer\s+)\S+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(Authorization\s*:\s*Basic\s+)\S+'),  r'\1[REDACTED]'),
    (re.compile(r'(?i)(Authorization\s*:\s*Token\s+)\S+'),  r'\1[REDACTED]'),
    # ── Cookie headers (whole line remainder) ─────────────────────────────
    (re.compile(r'(?i)(Cookie\s*:\s*)(.+)'),      r'\1[REDACTED]'),
    (re.compile(r'(?i)(Set-Cookie\s*:\s*)(.+)'),  r'\1[REDACTED]'),
    # ── JWT tokens (three base64url segments) ─────────────────────────────
    (re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'), '[REDACTED_JWT]'),
    # ── AWS access key IDs (canonical, case-sensitive) ────────────────────
    (re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'), '[REDACTED_AWS_KEY]'),
    # ── GitHub tokens (documented prefixes; classic suffix is 36 chars,
    #    floor of 20 kept for resilience against truncation) ───────────────
    (re.compile(r'\bgh[pousr]_[A-Za-z0-9]{20,}\b'), '[REDACTED_GITHUB_TOKEN]'),
    (re.compile(r'\bgithub_pat_[A-Za-z0-9_]{22,}\b'), '[REDACTED_GITHUB_TOKEN]'),
    # ── Slack tokens (bot/user/app/refresh classes) ───────────────────────
    (re.compile(r'\bxox[abpr]-[A-Za-z0-9-]{10,}\b'), '[REDACTED_SLACK_TOKEN]'),
    # ── Standalone Basic auth (no Authorization: prefix needed) ───────────
    # Only fires on a ≥16-char base64-shaped blob mixing upper+lowercase,
    # so prose like "HTTP Basic authentication is enabled" is untouched.
    (re.compile(
        r'(?i)((?<![A-Za-z0-9])basic\s+'
        r'(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z])'
        r'[A-Za-z0-9+/]{16,}={0,2})'
    ), '[REDACTED_BASIC]'),
    # ── Database URL passwords (.env-style DATABASE_URL leaks) ────────────
    (re.compile(
        r'(?i)((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqps?)://'
        r'[^:/@\s]+):([^@\s]+)@'
    ), r'\1:[REDACTED]@'),
    # ── API key assignments / header values ───────────────────────────────
    (re.compile(r'(?i)(X-API[-_]?Key\s*:\s*|API[-_]?Key\s*:\s*|api_key\s*[=:]\s*)(\S+)'), r'\1[REDACTED]'),
    # ── Credential assignments: QUOTED values (may contain spaces, one line,
    #    ≤128 chars inside the quotes) — must precede the unquoted rule ─────
    (re.compile(
        r"""(?i)\b(password|passwd|pwd|pass|client_secret|api_secret|"""
        r"""access_token|auth_token|refresh_token|session_token|"""
        r"""secret_key|smtp_password|smtp_user)\s*[:=]\s*"""
        r"""("[^"\n]{1,128}"|'[^'\n]{1,128}')"""
    ), r'\1=[REDACTED]'),
    # ── Credential assignments: UNQUOTED values (next whitespace token) ───
    (re.compile(
        r'(?i)\b(password|passwd|pwd|pass|client_secret|api_secret|'
        r'access_token|auth_token|refresh_token|session_token|'
        r'secret_key|smtp_password|smtp_user)\s*[:=]\s*(\S+)'
    ), r'\1=[REDACTED]'),
]


def redact_secrets(text: str | None) -> str:
    """Apply server-side credential redaction to any text before export/persistence."""
    if not text:
        return text or ""
    for pattern, replacement in REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_secrets_deep(obj):
    """Recursively redact credential patterns in a JSON-like structure.

    Returns a NEW structure; the input (e.g. SQLAlchemy models' dumped
    payloads) is never mutated. Every string is passed through
    ``redact_secrets`` — including dictionary KEYS, because target-controlled
    key material exists in practice (response-header names persisted into
    ``raw_headers``, banner-derived names inside ``tech_stack``).

    Application-controlled schema keys ("issuer", "note", "id", "records",
    ...) contain no credential-assignment patterns and pass through
    untouched — only smuggled key strings such as ``pwd=hunter22`` are
    rewritten.

    Known limitation: two distinct keys may collapse to the same redacted
    form ({"pwd=a": x, "pwd=b": y} both become "pwd=[REDACTED]") — one entry
    is lost. Acceptable for delivery copies; never used on persistence data.
    """
    if isinstance(obj, str):
        return redact_secrets(obj)
    if isinstance(obj, dict):
        return {
            (redact_secrets(k) if isinstance(k, str) else k): redact_secrets_deep(v)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [redact_secrets_deep(v) for v in obj]
    return obj


# Backward-compatible alias (historical name used inside pdf_generator).
_redact = redact_secrets


# ─────────────────────────────────────────────────────────────────────────────
# HTML escaping (defense against stored HTML/script injection in reports)
# ─────────────────────────────────────────────────────────────────────────────

def escape_html(value: str | None) -> str:
    """Entity-escape a potentially attacker-controlled string for safe HTML interpolation."""
    if value is None:
        return ""
    return _html.escape(str(value), quote=True)


# ─────────────────────────────────────────────────────────────────────────────
# CSV formula-injection neutralization
# ─────────────────────────────────────────────────────────────────────────────

# Cells beginning with these characters can be interpreted as formulas by
# spreadsheet applications (Excel / Google Sheets / LibreOffice). OWASP
# recommends neutralizing them by prefixing with an apostrophe.
_CSV_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_field(value):
    """Neutralize spreadsheet formula injection in a CSV cell.

    Normal values pass through unchanged; only cells that could be evaluated
    as formulas get a leading apostrophe.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        return value
    if value.startswith(_CSV_DANGEROUS_PREFIXES):
        return "'" + value
    return value


# ─────────────────────────────────────────────────────────────────────────────
# Length clamping for target-controlled data (Finding persistence safety)
# ─────────────────────────────────────────────────────────────────────────────

def clamp_str(value: str | None, max_len: int, suffix: str = "…") -> str | None:
    """Clamp a string to max_len characters, appending a truncation marker."""
    if value is None:
        return None
    if len(value) <= max_len:
        return value
    cut = max(max_len - len(suffix), 0)
    return value[:cut] + suffix


# Field limits chosen to fit the SQLAlchemy column definitions
# (see app/models/finding.py) while preserving useful evidence.
_FINDING_LIMITS = {
    "category": 100,          # String(100)
    "title": 255,             # String(255)
    "cve_id": 25,             # String(25)
    "endpoint": 255,          # String(255)
    # Text columns — bounded to keep reports/PDF/export rendering sane.
    "description": 4000,
    "evidence": 4000,
    "recommendation": 4000,
    "problem": 4000,
    "impact": 4000,
    "risk_analysis": 4000,
    "technical_details": 4000,
    "configuration_example": 4000,
    "best_practices": 4000,
    "official_documentation": 4000,
}

_LIST_ITEM_LIMIT = 500     # per item in fix_steps / references
_LIST_MAX_ITEMS = 20


def sanitize_finding_data(finding: dict) -> dict:
    """Clamp every target-controlled field of a finding dict IN PLACE.

    Applied before threat-intel enrichment and database persistence so that a
    hostile target returning oversized header/DNS/content values can neither
    overflow DB columns nor bloat enriched copies of the finding.
    """
    if not isinstance(finding, dict):
        return finding

    for field, limit in _FINDING_LIMITS.items():
        if field in finding:
            finding[field] = clamp_str(finding[field], limit)

    for list_field in ("fix_steps", "references"):
        items = finding.get(list_field)
        if isinstance(items, list):
            clamped = []
            for item in items[:_LIST_MAX_ITEMS]:
                if isinstance(item, str):
                    item = clamp_str(item, _LIST_ITEM_LIMIT)
                    if item is not None:
                        clamped.append(item)
            finding[list_field] = clamped

    return finding
