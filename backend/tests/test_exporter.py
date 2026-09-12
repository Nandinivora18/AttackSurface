"""
Regression tests for export sanitization — generate_json_report
and PDF generation must never emit:

  - credential-bearing strings (Bearer/JWT/Cookie/API keys/.env secrets)
  - unescaped/corrupted target-controlled findings
"""
import datetime
import json
import uuid

from app.models.finding import Finding, Severity
from app.models.report import Report
from app.models.scan import Scan
from app.models.user import User
from app.utils.exporter import generate_json_report


def _user(email: str = "analyst@example.com") -> User:
    return User(email=email, name="Test Analyst")


def _report(findings=None, **kw) -> Report:
    defaults = dict(
        id=uuid.uuid4(),
        scan=Scan(url="https://example.com"),
        user=_user(),
        overall_score=75,
        grade="B",
        summary="Assessment complete.",
        findings=findings or [],
        score_breakdown={
            "ssl_tls": {"label": "SSL / TLS", "score": 18, "max": 20, "pct": 90, "color": "green"},
        },
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    defaults.update(kw)
    return Report(**defaults)


def _finding(**kw) -> Finding:
    defaults = dict(
        title="Test Finding",
        severity=Severity.medium,
        category="Security Headers",
        is_passed_control=False,
        description="A test finding description.",
        recommendation="Fix this issue.",
    )
    defaults.update(kw)
    return Finding(**defaults)


SECRET_EVIDENCE = (
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig123\n"
    "Cookie: session=topsecretcookievalue\n"
    "X-API-Key: sk_live_exporttest12345\n"
)

XSS_TITLE = "<script>alert('pwned')</script>"


# ─────────────────────────────────────────────────────────────────────────────
# JSON export
# ─────────────────────────────────────────────────────────────────────────────

def test_json_redacts_nested_credentials():
    f = _finding(
        evidence=SECRET_EVIDENCE,
        description=f"Leaked token: eyJhbGciOiJIUzI1NiJ9.a.b",
        owasp_mapping={"id": "A05", "note": "password=hunter2secret"},
    )
    json_str = generate_json_report(_report(findings=[f]), _user())
    data = json.loads(json_str)  # must remain valid JSON after redaction
    assert data["findings"][0]["evidence"] != SECRET_EVIDENCE
    flat = json.dumps(data)
    assert "eyJhbGciOiJIUzI1NiJ9" not in flat
    assert "topsecretcookievalue" not in flat
    assert "sk_live_exporttest12345" not in flat
    assert "hunter2secret" not in flat


def test_json_deep_redaction_reaches_score_breakdown():
    report = _report(score_breakdown={
        "headers": {
            "label": "Headers",
            "detail": "SECRET_KEY=leakedvalue123456",
            "score": 1, "max": 10, "pct": 10, "color": "red",
        },
    })
    data = json.loads(generate_json_report(report, _user()))
    assert "leakedvalue123456" not in json.dumps(data)


def test_json_valid_with_empty_findings():
    data = json.loads(generate_json_report(_report(findings=[]), _user()))
    assert data["findings"] == []
    assert data["overall_score"] == 75


# ─────────────────────────────────────────────────────────────────────────────
# End-to-end battery across retained exporters (JSON and PDF)
# ─────────────────────────────────────────────────────────────────────────────

GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
BASIC_B64 = "dXNlcjpwYXNzd29yZA=="

LEAK_FRAGMENTS = [
    "hunter22",
    "leakypass123",
    "hidden pass phrase",
    "AKIAIOSFODNN7",
    "ghp_" + "A1b2C3d4E5f6",
    "xox" + "b-1234567890",
    "dXNlcjpwYXNz",
    "sup3rs3cret",
]

MALICIOUS_EVIDENCE = (
    "pwd=hunter22\n"
    "passwd=hunter22\n"
    "pass=hunter22\n"
    'password="my hidden pass phrase"\n'
    "password=leakypass123\n"
    f"AWS key {('AKIAIOSFODNN7EXAMPLE')}\n"
    f"GitHub {GITHUB_TOKEN}\n"
    f"Slack {'xox' + 'b-1234567890-abcdefghijklmnop'}\n"
    f"Creds Basic {BASIC_B64}\n"
    "DATABASE_URL=postgres://admin:sup3rs3cret@db.internal:5432/prod"
)


def _malicious_report() -> Report:
    f = _finding(
        title="Credential Exposure",
        description=(
            f"Found leaked credentials: {('pwd=hunter22')} and "
            f"{('password = leakypass123')} plus {('ASIAIOSFODNN7EXAMPLE')}"
        ),
        evidence=MALICIOUS_EVIDENCE,
        recommendation=(
            f"Rotate immediately. Example of what NOT to ship: "
            f"xoxp-111222333-aabbccddeeff and basic dXNlcjpwYXNzd29yZA== tail"
        ),
        fix_steps=[
            f"Remove {GITHUB_TOKEN} from config",
            'Replace client_secret="very hidden phrase"',
        ],
        owasp_mapping={
            "id": "A07",
            "note": "access_token=leakytokenvalue77",
        },
        references=["https://owasp.org/A07"],
    )
    return _report(
        findings=[f],
        ssl_info={"issuer": "Test CA", "handshake_note": "passwd=hunter22 seen"},
        dns_info={"records": ["A -> 93.184.216.34"], "note": "xoxa-12345678901-zzzzzzzzzz leaked"},
        tech_stack={"server": "nginx", "header": f"Basic {BASIC_B64}"},
        score_breakdown={
            "creds": {
                "label": "Credentials",
                "detail": "refresh_token=leakyrefreshtoken55",
                "score": 0, "max": 20, "pct": 0, "color": "red",
            },
        },
    )


def _assert_no_leaks(text: str, surface: str):
    for frag in LEAK_FRAGMENTS:
        assert frag not in text, f"[{surface}] secret fragment leaked: {frag!r}"


def test_e2e_json_all_secret_classes_redacted_still_valid():
    json_str = generate_json_report(_malicious_report(), _user())
    data = json.loads(json_str)          # must remain parseable after redaction
    flat = json.dumps(data)              # walk every serialized node
    _assert_no_leaks(flat, "json")
    assert "leakytokenvalue77" not in flat
    assert "leakyrefreshtoken55" not in flat
    assert "very hidden phrase" not in flat
    assert "[REDACTED" in flat


def _extract_pdf_text_stdlib(pdf_bytes: bytes) -> str:
    import base64
    import re as _re
    import zlib

    chunks = []
    for m in _re.finditer(rb"stream\r?\n(.*?)endstream", pdf_bytes, _re.DOTALL):
        raw = m.group(1).strip(b"\r\n")
        try:
            data = zlib.decompress(base64.a85decode(raw, adobe=True))
        except Exception:
            try:
                data = zlib.decompress(raw)
            except Exception:
                continue
        if b"Tj" not in data and b"TJ" not in data:
            continue
        for sm in _re.finditer(rb"\(((?:[^()\\]|\\.)*)\)\s*T[jJ]", data):
            s = sm.group(1)
            s = s.replace(rb"\(", b"(").replace(rb"\)", b")").replace(rb"\\\\", b"\\")
            chunks.append(s.decode("latin-1", errors="replace"))
    return "\n".join(chunks)


def test_e2e_pdf_all_secret_classes_redacted_in_extracted_text():
    from app.utils.pdf_generator import _build_pdf

    pdf_bytes = _build_pdf(_malicious_report(), _user(), mode="technical")
    assert pdf_bytes[:4] == b"%PDF"
    text = _extract_pdf_text_stdlib(pdf_bytes)
    assert len(text) > 500
    assert "Credential Exposure" in text
    _assert_no_leaks(text, "pdf")
    assert "[REDACTED" in text


def test_e2e_prose_survives_retained_exports():
    """Benign technical phrasing must remain readable in JSON export."""
    benign_phrases = [
        "password policy requires 12 characters",
        "HTTP Basic authentication is enabled",
        "The server returned a 401 response.",
    ]
    f = _finding(description="\n".join(benign_phrases),
                 evidence=" ".join(benign_phrases))
    report = _report(findings=[f], summary=" ".join(benign_phrases))

    json_out = generate_json_report(report, _user())

    for phrase in benign_phrases:
        assert phrase in json.dumps(json.loads(json_out)), \
            f"prose damaged in JSON: {phrase!r}"
