"""Regression tests for email template output injection hardening.

Verifies:
- User-supplied `name` / `url` values are HTML-escaped in every email body
- CR/LF characters cannot survive into the scan-complete email subject
  (no header-injection surface)
"""
import pytest

from app.services.email_service import (
    _build_reset_html,
    _build_verification_html,
    send_scan_complete_email,
)


XSS_NAME = '<img src=x onerror="alert(1)">Bob'
XSS_URL = 'https://example.com/?q="><script>alert(1)</script>'


# ─────────────────────────────────────────────────────────────────────────────
# Verification / reset HTML bodies
# ─────────────────────────────────────────────────────────────────────────────

def test_verification_html_escapes_name():
    html = _build_verification_html(XSS_NAME, "https://frontend.example/verify?token=abc")
    assert "<img" not in html
    assert "<script>" not in html
    assert "&lt;img src=x onerror=" in html
    assert "Bob" in html
    assert "onerror=&quot;alert(1)&quot;&gt;Bob" in html  # fully escaped attribute


def test_reset_html_escapes_name():
    html = _build_reset_html(XSS_NAME, "https://frontend.example/reset?token=abc")
    assert "<img" not in html
    assert "<script>" not in html
    assert "&lt;img src=x onerror=" in html


def test_verification_html_plain_name_unchanged():
    html = _build_verification_html("Alice", "https://frontend.example/verify?token=abc")
    assert "Alice" in html and "&lt;" not in html


def test_verification_html_escapes_none_name():
    html = _build_verification_html(None, "https://frontend.example/verify?token=abc")
    assert "None" in html  # str(None) rendered safely


# ─────────────────────────────────────────────────────────────────────────────
# Scan-complete email: URL escaped in body + subject, CR/LF stripped
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_complete_email_escapes_url_in_body_and_subject(monkeypatch):
    captured = {}

    def fake_send(to_email, subject, html_body):
        captured["subject"] = subject
        captured["body"] = html_body
        return True

    monkeypatch.setattr("app.services.email_service._send_email", fake_send)

    status = await send_scan_complete_email(
        "analyst@example.com", "Analyst", XSS_URL, 85, "report-123"
    )
    assert status is True
    assert "<script>" not in captured["body"]
    assert "&lt;script&gt;" in captured["body"]
    assert "<script>" not in captured["subject"]
    assert "&lt;script&gt;" in captured["subject"]


@pytest.mark.asyncio
async def test_scan_complete_email_with_crlf_url_never_builds_raw_header(monkeypatch):
    captured = {}

    def fake_send(to_email, subject, html_body):
        captured["subject"] = subject
        captured["body"] = html_body
        return True

    monkeypatch.setattr("app.services.email_service._send_email", fake_send)

    evil_url = "https://example.com\r\nBcc: attacker@evil.com"
    await send_scan_complete_email("analyst@example.com", "Analyst", evil_url, 85, "report-123")

    # The injected CR/LF must never survive — smtplib would otherwise be able
    # to split the subject into new headers.
    assert "\r" not in captured["subject"] and "\n" not in captured["subject"]
    assert "\r" not in captured["body"]
    assert "\r\nBcc" not in captured["body"]


@pytest.mark.asyncio
async def test_scan_complete_email_plain_url_unchanged(monkeypatch):
    captured = {}

    def fake_send(to_email, subject, html_body):
        captured["subject"] = subject
        return True

    monkeypatch.setattr("app.services.email_service._send_email", fake_send)

    await send_scan_complete_email("analyst@example.com", "Analyst", "https://example.com", 85, "r1")
    assert "https://example.com" in captured["subject"]


# ─────────────────────────────────────────────────────────────────────────────
# Severity-calibration evidence: the email library itself hard-rejects CR/LF.
# Even if a header value somehow survived the strip above, the stdlib raises
# ValueError and delivery FAILS CLOSED — injection cannot occur, only a failed
# send (which the code turns into a returned False, never an exception).
# ─────────────────────────────────────────────────────────────────────────────

import email.message


def test_email_library_hard_rejects_crlf_in_headers():
    """Evidence: Python's email cannot construct a header containing CR/LF.

    This is the fail-closed guarantee that turns the former 'header-injection
    primitive' finding into a mere delivery-denial-of-self (Low). The strip in
    send_scan_complete_email is defense-in-depth on top of this hard barrier.
    """
    msg = email.message.EmailMessage()
    with pytest.raises(ValueError):
        msg["Subject"] = "Hello\r\nBcc: attacker@evil.com"


def test_send_email_fails_closed_on_crlf_headers(monkeypatch):
    """_send_email must never propagate a partially-built injection message.

    When any header value carries CR/LF, MIMEMultipart construction raises
    ValueError, which _send_email catches and converts to a False return.
    """
    import app.services.email_service as es

    monkeypatch.setattr(es.settings, "SMTP_USER", "smtp-user")
    monkeypatch.setattr(es.settings, "SMTP_PASSWORD", "smtp-pass")
    monkeypatch.setattr(es.settings, "SMTP_HOST", "localhost")
    monkeypatch.setattr(es.settings, "SMTP_PORT", 25)
    monkeypatch.setattr(es.settings, "SMTP_FROM", "sentinelscan@example.com")
    monkeypatch.setattr(es.settings, "SMTP_FROM_NAME", "SentinelScan")

    evil_to = "victim@example.com\r\nBcc: attacker@evil.com"
    ok = es._send_email(evil_to, "Subject", "<b>body</b>")
    assert ok is False