"""
Unit tests for app/utils/sanitize.py — the shared server-side sanitization
module used by PDF generation (H3), report exports (H1) and finding
persistence clamping (H6).
"""
import pytest

from app.utils.sanitize import (
    clamp_str,
    escape_html,
    redact_secrets,
    sanitize_csv_field,
    sanitize_finding_data,
)


# ─────────────────────────────────────────────────────────────────────────────
# Credential / secret redaction
# ─────────────────────────────────────────────────────────────────────────────

def test_redact_bearer_token():
    result = redact_secrets("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature")
    assert "eyJhbGciOiJIUzI1NiJ9" not in result
    assert "Authorization:" in result
    assert "[REDACTED]" in result


def test_redact_basic_auth():
    result = redact_secrets("Authorization: Basic dXNlcjpwYXNz")
    assert "dXNlcjpwYXNz" not in result
    assert "[REDACTED]" in result


def test_redact_cookie_header():
    result = redact_secrets("Cookie: session=abc123; refresh_token=def456")
    assert "abc123" not in result
    assert "def456" not in result
    assert "[REDACTED]" in result


def test_redact_set_cookie():
    result = redact_secrets("Set-Cookie: refresh_token=eyJhb; HttpOnly; Secure")
    assert "refresh_token=eyJhb" not in result
    assert "[REDACTED]" in result


def test_redact_jwt_standalone():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    result = redact_secrets(f"Token found in response body: {jwt}")
    assert jwt not in result
    assert "[REDACTED_JWT]" in result


def test_redact_api_key():
    result = redact_secrets("X-API-Key: sk_live_abc123xyz")
    assert "sk_live_abc123xyz" not in result
    assert "[REDACTED]" in result


def test_redact_password_assignment():
    result = redact_secrets("password=mysecret123")
    assert "mysecret123" not in result
    assert "[REDACTED]" in result


def test_redact_secret_key_assignment():
    result = redact_secrets("SECRET_KEY=supersecretjwtkey32chars")
    assert "supersecretjwtkey32chars" not in result


def test_redact_smtp_credentials():
    text = "SMTP_PASSWORD=mysmtppassword\nSMTP_USER=user@domain.com"
    result = redact_secrets(text)
    assert "mysmtppassword" not in result


def test_redact_preserves_legitimate_prose():
    """Security prose mentioning keywords without assignments must survive."""
    phrases = [
        "password security should be improved",
        "cookie management requires attention",
        "authorization controls need review",
        "the API endpoint should enforce authentication",
    ]
    for phrase in phrases:
        assert redact_secrets(phrase) == phrase, f"prose damaged: {phrase!r}"


def test_redact_none_and_empty():
    assert redact_secrets(None) == ""
    assert redact_secrets("") == ""
    assert redact_secrets("   ") == "   "


# ─────────────────────────────────────────────────────────────────────────────
# Credential alias assignments (H3 remediation)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("alias", ["pwd", "passwd", "pass", "password"])
def test_redact_password_aliases(alias):
    result = redact_secrets(f"{alias}=hunter22")
    assert "hunter22" not in result
    assert f"{alias}=[REDACTED]" in result


@pytest.mark.parametrize("alias", ["Pwd", "PASSWD", "PassWD"])
def test_redact_password_aliases_mixed_case(alias):
    result = redact_secrets(f"{alias}=hunter22")
    assert "hunter22" not in result


def test_redact_password_assignment_with_spaces_around_operator():
    result = redact_secrets("password = hunter22")
    assert "hunter22" not in result
    # Only the first token is consumed — never the whole sentence.
    assert "password=[REDACTED]" in result


def test_redact_password_colon_separator():
    result = redact_secrets("password: mysecret123")
    assert "mysecret123" not in result


@pytest.mark.parametrize("payload", [
    'password="my secret value"',
    "password='my secret value'",
])
def test_redact_quoted_password_values_with_spaces(payload):
    """Quoted secrets containing spaces must be fully redacted."""
    result = redact_secrets(payload)
    assert "my secret value" not in result
    assert "[REDACTED]" in result


def test_redact_quoted_secret_bounded_to_one_line():
    payload = 'password="first"\npassword="second"'
    result = redact_secrets(payload)
    assert "first" not in result
    assert "second" not in result


def test_redact_env_style_token_assignments():
    for key in ("access_token", "auth_token", "refresh_token",
                "client_secret", "api_secret", "session_token"):
        result = redact_secrets(f"{key}=leakedvalue9999")
        assert "leakedvalue9999" not in result, f"{key} value survived"


def test_redact_database_url_password():
    text = "DATABASE_URL=postgres://admin:sup3rs3cret@db.internal:5432/prod"
    result = redact_secrets(text)
    assert "sup3rs3cret" not in result
    assert "admin:[REDACTED]@db.internal:5432/prod" in result  # host stays useful


# ─────────────────────────────────────────────────────────────────────────────
# Cloud / SaaS token formats (H3 remediation)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("key_id", [
    "AKIAIOSFODNN7EXAMPLE",
    "ASIAIOSFODNN7EXAMPLE",
])
def test_redact_aws_access_key_ids(key_id):
    result = redact_secrets(f"aws_access_key_id={key_id}")
    assert key_id not in result
    assert "[REDACTED_AWS_KEY]" in result


def test_aws_lowercase_lookalike_not_matched():
    """AWS IDs are uppercase-only; lowercase prose must survive."""
    phrase = "the akia prefix identifies aws keys"
    assert redact_secrets(phrase) == phrase


def test_redact_github_classic_tokens():
    tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # canonical 36 chars
    result = redact_secrets(f"token {tok} found")
    assert tok not in result
    assert "[REDACTED_GITHUB_TOKEN]" in result


@pytest.mark.parametrize("prefix", ["gho_", "ghu_", "ghs_", "ghr_"])
def test_redact_github_oauth_app_server_tokens(prefix):
    tok = prefix + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3h2"
    assert tok not in redact_secrets(f"cred {tok}")


def test_redact_github_fine_grained_pat():
    tok = "github_pat_" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1Ll2M3"
    result = redact_secrets(f"pat {tok}")
    assert tok not in result


def test_github_short_fragment_not_matched():
    """A bare 'ghp_' with no plausible suffix is prose, not a token."""
    phrase = "tokens start with ghp_ then 36 characters"
    assert "ghp_ then" in redact_secrets(phrase)


@pytest.mark.parametrize("prefix", ["xoxb-", "xoxp-", "xoxa-", "xoxr-"])
def test_redact_slack_tokens(prefix):
    tok = prefix + "1234567890-abcdefghijklmnop"
    result = redact_secrets(f"slack {tok}")
    assert tok not in result
    assert "[REDACTED_SLACK_TOKEN]" in result


def test_slack_lookalike_xoxo_not_matched():
    phrase = "we xoxo-approve this message"
    assert "xoxo-approve" in redact_secrets(phrase)


# ─────────────────────────────────────────────────────────────────────────────
# Standalone Basic auth credentials (H3 remediation)
# ─────────────────────────────────────────────────────────────────────────────

def test_redact_standalone_basic_credentials():
    result = redact_secrets("Basic dXNlcjpwYXNzd29yZA==")
    assert "dXNlcjpwYXNzd29yZA==" not in result
    assert "[REDACTED_BASIC]" in result


def test_standalone_basic_case_insensitive_scheme():
    result = redact_secrets("basic dXNlcjpwYXNzd29yZA== tail")
    assert "dXNlcjpwYXNzd29yZA==" not in result
    assert "tail" in result  # surrounding prose survives


def test_authorization_basic_still_redacted():
    result = redact_secrets("Authorization: Basic dXNlcjpwYXNzd29yZA==")
    assert "dXNlcjpwYXNzd29yZA==" not in result


def test_basic_prose_without_blob_untouched():
    phrases = [
        "HTTP Basic authentication is enabled",
        "basic auth should use TLS",
        "The server uses Basic auth.",
    ]
    for phrase in phrases:
        assert redact_secrets(phrase) == phrase, f"prose damaged: {phrase!r}"


def test_multiple_secret_types_in_one_string():
    gh_tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    text = (
        "pwd=hunter22 "
        f"and {gh_tok} "
        "plus AKIAIOSFODNN7EXAMPLE "
        'and password="hidden words here"'
    )
    result = redact_secrets(text)
    assert "hunter22" not in result
    assert gh_tok not in result
    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "hidden words here" not in result


def test_prose_with_password_words_survives():
    phrases = [
        "password policy requires 12 characters",
        "This is a normal sentence containing password information.",
        "The server returned a 401 response.",
        "Rotate your pass word every 90 days.",  # no assignment operator
    ]
    for phrase in phrases:
        assert redact_secrets(phrase) == phrase, f"prose damaged: {phrase!r}"


# ─────────────────────────────────────────────────────────────────────────────
# CSV formula-injection neutralization (H1)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("payload", [
    '=cmd|\' /C calc\'!A0',
    '+1+cmd|\' /C calc\'!A0',
    '-2+3+cmd|\' /C calc\'!A0',
    '@SUM(1+1)*cmd|\' /C calc\'!A0',
    '\t=HYPERLINK("http://evil")',
])
def test_csv_formula_injection_neutralized(payload):
    result = sanitize_csv_field(payload)
    assert result.startswith("'"), f"dangerous cell not neutralized: {payload!r}"
    assert "'" + payload == result


def test_csv_crlf_stripped_from_cell_prefix():
    # A leading CR would be interpreted as a formula trigger by some spreadsheets
    result = sanitize_csv_field("\r=1+1")
    assert result.startswith("'")


def test_csv_normal_values_pass_through():
    assert sanitize_csv_field("Normal Title") == "Normal Title"
    assert sanitize_csv_field("example.com") == "example.com"
    assert sanitize_csv_field("Score: 85/100 (high)") == "Score: 85/100 (high)"


def test_csv_none_and_non_string():
    assert sanitize_csv_field(None) == ""
    assert sanitize_csv_field(85) == 85
    assert sanitize_csv_field(9.8) == 9.8


# ─────────────────────────────────────────────────────────────────────────────
# HTML escaping
# ─────────────────────────────────────────────────────────────────────────────

def test_escape_html_script_tag():
    result = escape_html("<script>alert('xss')</script>")
    assert "<script>" not in result
    assert "&lt;script&gt;" in result


def test_escape_html_quotes():
    result = escape_html('"><img src=x onerror=alert(1)>')
    assert '"' not in result
    assert "&quot;" in result


def test_escape_html_none():
    assert escape_html(None) == ""


def test_escape_html_plain_text_unchanged():
    assert escape_html("Missing Content-Security-Policy header") == \
        "Missing Content-Security-Policy header"


# ─────────────────────────────────────────────────────────────────────────────
# Length clamping (H6)
# ─────────────────────────────────────────────────────────────────────────────

def test_clamp_str_short_value_unchanged():
    assert clamp_str("short", 255) == "short"


def test_clamp_str_truncates_with_suffix():
    long = "x" * 500
    result = clamp_str(long, 255)
    assert len(result) == 255
    assert result.endswith("…")
    assert set(result[:-1]) == {"x"}


def test_clamp_str_exact_length_unchanged():
    exact = "y" * 255
    assert clamp_str(exact, 255) == exact


def test_clamp_str_none_passthrough():
    assert clamp_str(None, 100) is None


# ─────────────────────────────────────────────────────────────────────────────
# sanitize_finding_data — dict-level clamping before persistence
# ─────────────────────────────────────────────────────────────────────────────

def test_sanitize_finding_data_clamps_oversized_fields():
    finding = {
        "title": "T" * 400,
        "description": "D" * 10_000,
        "evidence": "E" * 10_000,
        "category": "C" * 300,
    }
    sanitize_finding_data(finding)
    assert len(finding["title"]) <= 255
    assert len(finding["description"]) <= 4000
    assert len(finding["evidence"]) <= 4000
    assert len(finding["category"]) <= 100


def test_sanitize_finding_data_leaves_normal_fields_intact():
    finding = {
        "title": "Missing HSTS Header",
        "description": "The target does not send Strict-Transport-Security.",
        "severity": "high",
    }
    original = dict(finding)
    sanitize_finding_data(finding)
    assert finding["title"] == original["title"]
    assert finding["description"] == original["description"]
    assert finding["severity"] == "high"


def test_sanitize_finding_data_clamps_lists():
    finding = {
        "fix_steps": ["s" * 900 for _ in range(30)],
        "references": ["https://ref.example/" + "r" * 600],
    }
    sanitize_finding_data(finding)
    assert len(finding["fix_steps"]) == 20          # capped item count
    assert all(len(s) <= 500 for s in finding["fix_steps"])
    assert len(finding["references"][0]) <= 500     # per-item cap


def test_sanitize_finding_data_handles_missing_fields():
    finding = {"title": "Only a title"}
    sanitize_finding_data(finding)
    assert finding == {"title": "Only a title"}


def test_sanitize_finding_data_non_dict_passthrough():
    assert sanitize_finding_data(None) is None
    assert sanitize_finding_data("not-a-dict") == "not-a-dict"
