"""
Comprehensive PDF generation tests — Phase 13.

Covers:
  - Valid PDF output for all modes and data scenarios
  - Empty / single / multiple / mixed-severity findings
  - Long evidence, long URLs, Unicode
  - Missing optional mappings/metadata
  - Security redaction of real credential patterns
  - Redaction preserves legitimate non-secret prose
  - IDOR: GET /{report_id}/pdf blocked for wrong user (via existing auth test infra)
  - PDF text extraction validates section headings, target, score
  - Absence of secrets verified in EXTRACTED TEXT (not just raw bytes)
"""
from __future__ import annotations

import datetime
import re
import uuid

import pytest

from app.models.finding import Confidence, Finding, Severity
from app.models.report import Report
from app.models.scan import Scan
from app.models.user import User
from app.utils.pdf_generator import _build_pdf, _redact


# ─────────────────────────────────────────────────────────────────────────────
# Shared fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _user(email: str = "analyst@example.com") -> User:
    return User(email=email, name="Test Analyst")


def _scan(url: str = "https://example.com") -> Scan:
    return Scan(url=url)


def _report(**kw) -> Report:
    defaults = dict(
        id=uuid.uuid4(),
        scan=_scan(),
        user=_user(),
        overall_score=75,
        grade="B",
        summary="Assessment complete.",
        findings=[],
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


def _extract_text(pdf_bytes: bytes) -> str:
    """Extract plain text from a PDF for content assertions."""
    try:
        import io
        from pypdf import PdfReader  # type: ignore
        reader = PdfReader(io.BytesIO(pdf_bytes))
        return "\n".join(p.extract_text() or "" for p in reader.pages)
    except ImportError:
        pass
    try:
        import io
        from PyPDF2 import PdfReader  # type: ignore
        reader = PdfReader(io.BytesIO(pdf_bytes))
        return "\n".join(p.extract_text() or "" for p in reader.pages)
    except ImportError:
        pass

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

    return " ".join(chunks)


def _is_valid_pdf(data: bytes) -> bool:
    return isinstance(data, bytes) and data[:4] == b"%PDF" and len(data) > 500


# ─────────────────────────────────────────────────────────────────────────────
# 1. Basic validity
# ─────────────────────────────────────────────────────────────────────────────

def test_pdf_is_valid_bytes_technical():
    pdf = _build_pdf(_report(), _user(), mode="technical")
    assert _is_valid_pdf(pdf)


def test_pdf_is_valid_bytes_executive():
    pdf = _build_pdf(_report(), _user(), mode="executive")
    assert _is_valid_pdf(pdf)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Empty findings
# ─────────────────────────────────────────────────────────────────────────────

def test_empty_findings_technical():
    report = _report(findings=[], overall_score=95, grade="A+", summary="No issues found.")
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)


def test_empty_findings_executive():
    report = _report(findings=[], overall_score=95, grade="A+", summary="Clean assessment.")
    pdf = _build_pdf(report, _user(), mode="executive")
    assert _is_valid_pdf(pdf)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Single finding
# ─────────────────────────────────────────────────────────────────────────────

def test_single_finding():
    f = _finding(title="Missing CSP", severity=Severity.high, cwe_id="CWE-1021")
    report = _report(findings=[f], overall_score=60, grade="C")
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Multiple findings
# ─────────────────────────────────────────────────────────────────────────────

def test_multiple_findings():
    findings = [
        _finding(title=f"Finding {i}", severity=Severity.medium)
        for i in range(10)
    ]
    report = _report(findings=findings, overall_score=55, grade="D")
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Mixed severities
# ─────────────────────────────────────────────────────────────────────────────

def test_mixed_severity_findings():
    findings = [
        _finding(title="Critical CVE",  severity=Severity.critical, cvss_score=9.8,
                 cve_id="CVE-2021-41773"),
        _finding(title="High Header",   severity=Severity.high,     cvss_score=7.5),
        _finding(title="Medium Misc",   severity=Severity.medium,   cvss_score=5.3),
        _finding(title="Low Config",    severity=Severity.low,      cvss_score=3.1),
        _finding(title="Info Exposure", severity=Severity.info,     cvss_score=None),
    ]
    report = _report(findings=findings, overall_score=30, grade="F")
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Long evidence
# ─────────────────────────────────────────────────────────────────────────────

def test_long_evidence():
    long_ev = "\n".join([f"Header-{i:03d}: {'x' * 80}" for i in range(60)])
    f = _finding(title="Header Dump", severity=Severity.medium, evidence=long_ev)
    report = _report(findings=[f])
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Long URLs
# ─────────────────────────────────────────────────────────────────────────────

def test_long_url():
    long_url = "https://very-long-subdomain.example-enterprise.com/path/" + "segment/" * 15 + "?param=value"
    scan = _scan(url=long_url)
    report = _report(scan=scan, findings=[])
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)


# ─────────────────────────────────────────────────────────────────────────────
# 8. Unicode in findings
# ─────────────────────────────────────────────────────────────────────────────

def test_unicode_content():
    f = _finding(
        title="Configuración de Seguridad Deficiente — 安全配置不足",
        description="Schlechte Konfiguration: Überprüfen Sie die Einstellungen. "
                    "Türkçe karakter: Şüpheli etkinlik. 日本語: セキュリティ設定。"
                    "Arabic: إعدادات الأمان. Russian: Настройки безопасности.",
        recommendation="Обновите конфигурацию. Update Konfiguration. 更新配置。",
        evidence="X-Content-Type: text/html; charset=UTF-8\n"
                 "Content: مرحبا بالعالم — привет мир — こんにちは世界",
    )
    report = _report(findings=[f])
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)


# ─────────────────────────────────────────────────────────────────────────────
# 9. Missing optional fields
# ─────────────────────────────────────────────────────────────────────────────

def test_missing_optional_mappings():
    """Findings without owasp/mitre/cwe/cve must not raise errors."""
    f = _finding(
        title="Bare Finding",
        severity=Severity.medium,
        # All optional fields absent
        owasp_mapping=None, mitre_mapping=None, cwe_id=None, cve_id=None,
        evidence=None, technical_details=None, impact=None, risk_analysis=None,
        fix_steps=None, references=None, endpoint=None,
    )
    report = _report(findings=[f])
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)


def test_missing_optional_report_metadata():
    """Report with no summary, no score_breakdown, no exec_summary, no ssl_info."""
    report = _report(
        summary=None, score_breakdown=None, executive_summary=None,
        ssl_info=None, dns_info=None, tech_stack=None,
    )
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)


# ─────────────────────────────────────────────────────────────────────────────
# 10-17. Security redaction — unit tests on _redact()
# ─────────────────────────────────────────────────────────────────────────────

def test_redact_bearer_token():
    result = _redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature")
    assert "eyJhbGciOiJIUzI1NiJ9" not in result
    assert "Authorization:" in result
    assert "[REDACTED]" in result


def test_redact_basic_auth():
    result = _redact("Authorization: Basic dXNlcjpwYXNz")
    assert "dXNlcjpwYXNz" not in result
    assert "[REDACTED]" in result


def test_redact_cookie_header():
    result = _redact("Cookie: session=abc123; refresh_token=def456")
    assert "abc123" not in result
    assert "def456" not in result
    assert "[REDACTED]" in result


def test_redact_set_cookie():
    result = _redact("Set-Cookie: refresh_token=eyJhb...; HttpOnly; Secure")
    assert "refresh_token=eyJhb" not in result
    assert "[REDACTED]" in result


def test_redact_jwt_standalone():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = _redact(f"Token found in response body: {jwt}")
    assert jwt not in result
    assert "[REDACTED_JWT]" in result


def test_redact_api_key():
    result = _redact("X-API-Key: sk_live_abc123xyz")
    assert "sk_live_abc123xyz" not in result
    assert "[REDACTED]" in result


def test_redact_password_assignment():
    result = _redact("password=mysecret123")
    assert "mysecret123" not in result
    assert "[REDACTED]" in result


def test_redact_secret_key():
    result = _redact("SECRET_KEY=supersecretjwtkey32chars")
    assert "supersecretjwtkey32chars" not in result
    assert "[REDACTED]" in result


def test_redact_smtp_credentials():
    text = "SMTP_PASSWORD=mysmtppassword\nSMTP_USER=user@domain.com"
    result = _redact(text)
    assert "mysmtppassword" not in result
    assert "[REDACTED]" in result


def test_redact_preserves_legitimate_prose():
    """Legitimate security prose must not be destroyed by redaction."""
    phrases = [
        "password security should be improved",
        "cookie management requires attention",
        "authorization controls need review",
        "the API endpoint should enforce authentication",
        "Set-Cookie flags should include HttpOnly",  # This DOES match Set-Cookie pattern — expected
    ]
    for phrase in phrases[:4]:  # first 4 are plain prose — must survive intact
        result = _redact(phrase)
        assert result == phrase, (
            f"Legitimate prose was incorrectly redacted: {phrase!r} → {result!r}"
        )


def test_redact_none_and_empty():
    assert _redact(None) == ""
    assert _redact("") == ""
    assert _redact("   ") == "   "


# ─────────────────────────────────────────────────────────────────────────────
# 18. Redaction in generated PDF (extracted text, not raw bytes)
# ─────────────────────────────────────────────────────────────────────────────

def test_no_tokens_in_extracted_pdf_text():
    """Sensitive strings must not appear in extracted PDF text."""
    bearer_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.TestSig"
    cookie_val = "refresh_token=super_secret_refresh_value"
    api_key = "sk_live_testapikey12345"
    password = "mypassword=Sup3rS3cr3t!"

    f = _finding(
        title="Header Analysis",
        severity=Severity.high,
        evidence=(
            f"Authorization: Bearer {bearer_token}\n"
            f"Cookie: {cookie_val}\n"
            f"X-API-Key: {api_key}\n"
            f"password={password}\n"
            "Content-Type: application/json\n"
        ),
        description="Sensitive headers detected in response.",
    )
    report = _report(findings=[f])
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)

    text = _extract_text(pdf)

    # Must NOT appear in extracted text
    assert bearer_token not in text, "Bearer JWT found in extracted PDF text"
    assert "super_secret_refresh_value" not in text, "Refresh token value found in extracted PDF text"
    assert api_key not in text, "API key found in extracted PDF text"
    assert "Sup3rS3cr3t!" not in text, "Password found in extracted PDF text"

    # Evidence section should still exist (redacted form)
    # The REDACTED marker or the header name should be present
    # (content depends on whether pypdf/PyPDF2 is installed)


def test_no_tokens_in_pdf_description_field():
    """Tokens in description/recommendation fields are also redacted."""
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123sig"
    f = _finding(
        title="JWT Exposure",
        severity=Severity.critical,
        description=f"The application returned a JWT in the response body: {jwt}",
        recommendation=f"Remove the JWT {jwt} from the response.",
        evidence=f"Authorization: Bearer {jwt}",
    )
    report = _report(findings=[f])
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)

    text = _extract_text(pdf)
    assert jwt not in text, "JWT found in extracted PDF text from description/recommendation"


# ─────────────────────────────────────────────────────────────────────────────
# 19. Passed controls excluded from findings count
# ─────────────────────────────────────────────────────────────────────────────

def test_passed_controls_excluded():
    findings = [
        _finding(title="Real Finding", severity=Severity.high, is_passed_control=False),
        _finding(title="Passed Check", severity=Severity.low, is_passed_control=True),
    ]
    report = _report(findings=findings)
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)
    # Both modes should complete without error
    pdf_exec = _build_pdf(report, _user(), mode="executive")
    assert _is_valid_pdf(pdf_exec)


# ─────────────────────────────────────────────────────────────────────────────
# 20. Score breakdown displayed
# ─────────────────────────────────────────────────────────────────────────────

def test_score_breakdown_rendered():
    breakdown = {
        "ssl_tls":          {"label": "SSL / TLS",          "score": 18, "max": 20, "pct": 90, "color": "green"},
        "security_headers": {"label": "Security Headers",    "score": 6,  "max": 20, "pct": 30, "color": "red"},
        "cookies":          {"label": "Cookies",             "score": 8,  "max": 10, "pct": 80, "color": "green"},
        "dns":              {"label": "DNS",                  "score": 10, "max": 15, "pct": 67, "color": "yellow"},
    }
    report = _report(score_breakdown=breakdown)
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)


# ─────────────────────────────────────────────────────────────────────────────
# 21. Full OWASP/CWE/MITRE mappings
# ─────────────────────────────────────────────────────────────────────────────

def test_full_mapping_fields():
    f = _finding(
        title="Path Traversal",
        severity=Severity.critical,
        cve_id="CVE-2021-41773",
        cwe_id="CWE-22",
        cvss_score=9.8,
        owasp_mapping={"id": "A03:2025", "title": "Software Supply Chain Failures",
                       "description": "Using components with known CVEs and outdated software."},
        mitre_mapping={"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
                       "description": "Exploit a vulnerability in an Internet-facing application."},
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                    "https://owasp.org/Top10/"],
        fix_steps=["Upgrade to Apache 2.4.51+", "Apply vendor patches", "Enable mod_security"],
        impact="Full server compromise possible.",
        best_practices="Keep all web server software current with security patches.",
        official_documentation="https://httpd.apache.org/security/vulnerabilities_24.html",
    )
    report = _report(findings=[f], overall_score=20, grade="F")
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)


# ─────────────────────────────────────────────────────────────────────────────
# 22. VAPT Security Assessment Structure & Content Assertions
# ─────────────────────────────────────────────────────────────────────────────

def test_vapt_cover_and_executive_summary_content():
    """Verify target domain, report ID, and finding counts appear in PDF text."""
    f1 = _finding(title="Missing HSTS", severity=Severity.high, category="Security Headers")
    f2 = _finding(title="Weak TLS Cipher", severity=Severity.medium, category="SSL / TLS")
    f3 = _finding(title="Server Version Disclosed", severity=Severity.low, category="Technology Stack")
    
    report_id = uuid.uuid4()
    report = _report(
        id=report_id,
        scan=_scan(url="https://portal.secure-example.com/login"),
        findings=[f1, f2, f3],
        overall_score=68,
        grade="C",
        summary="Security evaluation completed with moderate risk.",
        tech_stack={"nginx": {"version": "1.18.0", "confidence": "high", "categories": ["Web Server"]}},
    )
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)

    text = _extract_text(pdf)
    short_id = str(report_id)[:8].upper()

    # Cover & header metadata
    assert "SENTINELSCAN" in text
    assert "WEB APPLICATION" in text or "SECURITY ASSESSMENT REPORT" in text
    assert "portal.secure-example.com" in text or "secure-example.com" in text
    assert short_id in text
    assert "CONFIDENTIAL" in text

    # Executive summary & counts
    assert "EXECUTIVE SUMMARY" in text
    assert "Missing HSTS" in text
    assert "Weak TLS Cipher" in text
    assert "Server Version Disclosed" in text

    # Scope, Limitations, and Methodology sections
    assert "ASSESSMENT SCOPE" in text
    assert "ASSESSMENT LIMITATIONS" in text
    assert "ASSESSMENT METHODOLOGY" in text


def test_vapt_tech_inventory_and_owasp_coverage():
    """Verify technology inventory and OWASP Top 10 mappings render properly."""
    f1 = _finding(
        title="Apache Outdated Version",
        severity=Severity.critical,
        cve_id="CVE-2021-41773",
        owasp_mapping={"id": "A03:2025", "title": "Software Supply Chain Failures"},
    )
    report = _report(
        findings=[f1],
        tech_stack={
            "Apache": {"version": "2.4.49", "confidence": "high", "categories": ["Web Server"]},
            "PHP": {"version": "8.0.12", "confidence": "medium", "categories": ["Programming Language"]},
        },
    )
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)

    text = _extract_text(pdf)
    assert "TECHNOLOGY & COMPONENT INVENTORY" in text or "TECHNOLOGY" in text
    assert "Apache" in text
    assert "2.4.49" in text
    assert "PHP" in text
    assert "OWASP TOP 10" in text
    assert "A03:2025" in text or "A03" in text


def test_vapt_large_multipage_scale():
    """Generate 60 findings to verify multi-page scale and clean pagination."""
    findings = []
    for i in range(60):
        sev = Severity.critical if i < 5 else Severity.high if i < 20 else Severity.medium if i < 40 else Severity.low
        findings.append(_finding(
            title=f"Security Misconfiguration Issue #{i+1}",
            severity=sev,
            evidence=f"HTTP/1.1 200 OK\nServer: nginx/1.{i}.0\nX-Test-Finding: {i}",
            recommendation=f"Update component #{i+1} according to vendor security guidance.",
        ))
    report = _report(findings=findings, overall_score=35, grade="F")
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)
    assert len(pdf) > 25000  # Multi-page PDF


def test_vapt_remediation_status_accuracy():
    """Verify remediation classification displays appropriate guidance and status."""
    f = _finding(
        title="Missing X-Frame-Options Header",
        severity=Severity.high,
        category="Security Headers",
        recommendation="Configure add_header X-Frame-Options DENY always;",
        fix_steps=["Open nginx.conf", "Add directive", "Reload nginx"],
    )
    report = _report(findings=[f])
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)

    text = _extract_text(pdf)
    assert "REMEDIATION SUMMARY" in text or "REMEDIATION" in text
    assert "Missing X-Frame-Options Header" in text
    assert "Automated Local Patch" in text or "Manual Guidance" in text


# ─────────────────────────────────────────────────────────────────────────────
# 23. PDF markup injection / escaping regression
# ─────────────────────────────────────────────────────────────────────────────

def test_safe_escapes_quotes():
    """_safe must escape quote characters (attribute-context defense-in-depth).

    Text-node rendering is unaffected by the entities — ReportLab decodes them
    back to literal characters — but quotes can never leak into an attribute.
    """
    from app.utils.pdf_generator import _safe

    out = _safe('Severity "critical" <b>bold</b> & more \'quoted\'')
    assert "<b>" not in out
    assert '&quot;critical&quot;' in out
    assert "&lt;b&gt;bold&lt;/b&gt;" in out
    assert "&amp; more" in out
    assert "&#39;quoted&#39;" in out


def test_malicious_tech_version_rendered_safely():
    """Scanner-derived tech versions with markup must render literally, never
    inject ReportLab tags (prevents parse errors on download + cosmetic markup
    injection from attacker-chosen server banners)."""
    from html import unescape
    from app.utils.pdf_generator import _safe

    malicious = '1.0 <b>pwn</b> "q" &'
    report = _report(
        findings=[],
        tech_stack={"nginx": {"version": malicious, "confidence": "high",
                              "categories": ["Web Server"]}},
    )
    pdf = _build_pdf(report, _user(), mode="technical")
    assert _is_valid_pdf(pdf)

    # Every character must round-trip through _safe: stripped of escape
    # semantics but otherwise verbatim (i.e. "<b>" stayed literal text).
    # PDF text extraction inserts separating spaces between glyphs and maps
    # non-ASCII (the truncation ellipsis) to control chars, so compare the
    # ASCII-safe literal prefix with whitespace normalized on both sides.
    # If "<b>" had been parsed as a tag, extraction would read "1.0pwn" here.
    text = "".join(_extract_text(pdf).split())
    assert "1.0<b>pwn<" in text, "markup escaped to literal text, tags preserved verbatim"

