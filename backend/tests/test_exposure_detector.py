"""
Unit tests for app.scanner.exposure_detector
All tests use no live network; no external HTTP calls are made.
"""
import asyncio
from unittest.mock import patch
import pytest


def _run(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


@pytest.fixture(autouse=True)
def mock_safefetchclient():
    class _MockResponse:
        status_code = 404
        text = ""
        headers = {}

    class _MockClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, *args, **kwargs):
            return _MockResponse()

        async def post(self, *args, **kwargs):
            return _MockResponse()

    with patch("app.scanner.exposure_detector.SafeFetchClient", _MockClient):
        yield


# ── 1. Web Security Configuration ────────────────────────────────────────────

def test_cors_wildcard_detected():
    from app.scanner.exposure_detector import analyze_web_security_config
    findings = _run(analyze_web_security_config(
        "https://example.com",
        {"access-control-allow-origin": "*"},
    ))
    assert any("CORS" in f["title"] for f in findings)
    assert any(f["severity"] == "critical" for f in findings)


def test_cors_null_origin_detected():
    from app.scanner.exposure_detector import analyze_web_security_config
    findings = _run(analyze_web_security_config(
        "https://example.com",
        {"access-control-allow-origin": "null"},
    ))
    assert any("CORS" in f["title"] for f in findings)
    assert any(f["severity"] == "high" for f in findings)


def test_cors_wildcard_plus_credentials_escalates():
    from app.scanner.exposure_detector import analyze_web_security_config
    findings = _run(analyze_web_security_config(
        "https://example.com",
        {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        },
    ))
    assert any("CORS" in f["title"] for f in findings)
    cors = next(f for f in findings if "CORS" in f["title"])
    assert cors["severity"] == "critical"


def test_server_version_disclosure():
    from app.scanner.exposure_detector import analyze_web_security_config
    findings = _run(analyze_web_security_config(
        "https://example.com",
        {"server": "Apache/2.4.51 (Unix)"},
    ))
    assert any("Server Version" in f["title"] for f in findings)


def test_xpoweredby_version_disclosure():
    from app.scanner.exposure_detector import analyze_web_security_config
    findings = _run(analyze_web_security_config(
        "https://example.com",
        {"x-powered-by": "PHP/8.1.0"},
    ))
    assert any("X-Powered-By" in f["title"] for f in findings)


def test_clean_headers_no_cors_finding():
    from app.scanner.exposure_detector import analyze_web_security_config
    findings = _run(analyze_web_security_config(
        "https://example.com",
        {"access-control-allow-origin": "https://trusted.example.com"},
    ))
    assert not any("CORS" in f["title"] for f in findings)


# ── 2. Auth and Session Security ──────────────────────────────────────────────

def test_session_cookie_missing_httponly():
    from app.scanner.exposure_detector import analyze_auth_session_security
    findings = _run(analyze_auth_session_security(
        "https://example.com",
        {},
        ["sessionid=abc123; Path=/; SameSite=Lax"],
    ))
    assert any("Insecure Session Cookie" in f["title"] for f in findings)
    f = next(f for f in findings if "Insecure Session Cookie" in f["title"])
    assert "HttpOnly" in f["description"]


def test_session_cookie_missing_secure_on_https():
    from app.scanner.exposure_detector import analyze_auth_session_security
    findings = _run(analyze_auth_session_security(
        "https://example.com",
        {},
        ["sessionid=abc123; Path=/; HttpOnly; SameSite=Lax"],
    ))
    assert any("Insecure Session Cookie" in f["title"] for f in findings)
    f = next(f for f in findings if "Insecure Session Cookie" in f["title"])
    assert "Secure" in f["description"]


def test_session_cookie_all_flags_no_finding():
    from app.scanner.exposure_detector import analyze_auth_session_security
    findings = _run(analyze_auth_session_security(
        "https://example.com",
        {},
        ["sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"],
    ))
    assert not any("Insecure Session Cookie" in f["title"] for f in findings)


def test_plaintext_login_form():
    from app.scanner.exposure_detector import analyze_auth_session_security
    findings = _run(analyze_auth_session_security(
        "http://example.com",
        {},
        [],
        html_body='<form><input type="password" name="pwd"></form>',
    ))
    assert any("Plaintext" in f["title"] or "Unencrypted" in f["title"] for f in findings)
    assert any(f["severity"] == "critical" for f in findings)


def test_basic_auth_https_medium():
    from app.scanner.exposure_detector import analyze_auth_session_security
    findings = _run(analyze_auth_session_security(
        "https://example.com",
        {"www-authenticate": 'Basic realm="Test"'},
        [],
    ))
    basic = next((f for f in findings if "Basic Authentication" in f["title"]), None)
    assert basic is not None
    assert basic["severity"] == "medium"


def test_basic_auth_http_high():
    from app.scanner.exposure_detector import analyze_auth_session_security
    findings = _run(analyze_auth_session_security(
        "http://example.com",
        {"www-authenticate": 'Basic realm="Test"'},
        [],
    ))
    basic = next((f for f in findings if "Basic Authentication" in f["title"]), None)
    assert basic is not None
    assert basic["severity"] == "high"


# ── 4. JavaScript Secret Detection ───────────────────────────────────────────

def test_aws_key_detected():
    from app.scanner.exposure_detector import analyze_js_secrets
    html = '<script>var key = "AKIAIOSFODNN7EXAMPLE";</script>'
    findings = _run(analyze_js_secrets("https://example.com", html))
    assert any("AWS Access Key ID" in f["title"] for f in findings)
    assert any(f["severity"] == "critical" for f in findings)


def test_stripe_live_key_detected():
    from app.scanner.exposure_detector import analyze_js_secrets
    dummy_key = "sk_" + "live_" + "abcdefghijklmnopqrstuvwx"
    html = f'<script>const sk = "{dummy_key}";</script>'
    findings = _run(analyze_js_secrets("https://example.com", html))
    assert any("Stripe" in f["title"] for f in findings)


def test_stripe_test_key_medium():
    from app.scanner.exposure_detector import analyze_js_secrets
    dummy_key = "sk_" + "test_" + "abcdefghijklmnopqrstuvwx"
    html = f'<script>const sk = "{dummy_key}";</script>'
    findings = _run(analyze_js_secrets("https://example.com", html))
    sf = next((f for f in findings if "Stripe" in f["title"]), None)
    assert sf is not None
    assert sf["severity"] == "medium"


def test_google_api_key_detected():
    from app.scanner.exposure_detector import analyze_js_secrets
    html = '<script>var k = "AIzaSyD-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";</script>'
    findings = _run(analyze_js_secrets("https://example.com", html))
    assert any("Google API Key" in f["title"] for f in findings)


def test_pem_private_key_detected():
    from app.scanner.exposure_detector import analyze_js_secrets
    html = '<script>var k = "-----BEGIN RSA PRIVATE KEY-----";</script>'
    findings = _run(analyze_js_secrets("https://example.com", html))
    assert any("Private Key" in f["title"] for f in findings)
    assert any(f["severity"] == "critical" for f in findings)


def test_secret_not_in_evidence():
    from app.scanner.exposure_detector import analyze_js_secrets
    html = '<script>var key = "AKIAIOSFODNN7EXAMPLE";</script>'
    findings = _run(analyze_js_secrets("https://example.com", html))
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.get("evidence", "")


def test_short_string_no_false_positive():
    from app.scanner.exposure_detector import analyze_js_secrets
    html = '<script>var id = "abc123";</script>'
    findings = _run(analyze_js_secrets("https://example.com", html))
    assert not any("AWS" in f["title"] for f in findings)


# ── 8. DNS Intelligence ───────────────────────────────────────────────────────

def test_spf_passall():
    from app.scanner.exposure_detector import analyze_dns_intelligence
    dns = {"records": {"TXT": ["v=spf1 include:_spf.g.com +all"]}, "findings": []}
    findings = _run(analyze_dns_intelligence("example.com", dns))
    assert any("pass-all" in f["title"] for f in findings)
    assert any(f["severity"] == "high" for f in findings)


def test_spf_softfail():
    from app.scanner.exposure_detector import analyze_dns_intelligence
    dns = {"records": {"TXT": ["v=spf1 include:_spf.g.com ~all"]}, "findings": []}
    findings = _run(analyze_dns_intelligence("example.com", dns))
    assert any("Softfail" in f["title"] for f in findings)


def test_spf_hardfail_no_finding():
    from app.scanner.exposure_detector import analyze_dns_intelligence
    dns = {"records": {"TXT": ["v=spf1 include:_spf.g.com -all"]}, "findings": []}
    findings = _run(analyze_dns_intelligence("example.com", dns))
    assert not any("SPF" in f["title"] for f in findings)


def test_dmarc_missing():
    from app.scanner.exposure_detector import analyze_dns_intelligence
    dns = {"records": {"TXT": []}, "findings": []}
    findings = _run(analyze_dns_intelligence("example.com", dns))
    assert any("DMARC" in f["title"] for f in findings)


def test_dmarc_none_policy():
    from app.scanner.exposure_detector import analyze_dns_intelligence
    dns = {"records": {"TXT": ["v=DMARC1; p=none; rua=mailto:d@e.com"]}, "findings": []}
    findings = _run(analyze_dns_intelligence("example.com", dns))
    assert any("none" in f["title"].lower() for f in findings)


def test_dmarc_reject_no_finding():
    from app.scanner.exposure_detector import analyze_dns_intelligence
    dns = {"records": {"TXT": ["v=spf1 -all", "v=DMARC1; p=reject; rua=mailto:d@e.com"]}, "findings": []}
    findings = _run(analyze_dns_intelligence("example.com", dns))
    assert not any("DMARC" in f["title"] for f in findings)


# ── 10. Mixed Content ─────────────────────────────────────────────────────────

def test_active_mixed_content():
    from app.scanner.exposure_detector import analyze_mixed_content
    html = '<script src="http://cdn.evil.com/lib.js"></script>'
    findings = _run(analyze_mixed_content("https://secure.example.com", html))
    assert any("Active Mixed Content" in f["title"] for f in findings)


def test_passive_mixed_content():
    from app.scanner.exposure_detector import analyze_mixed_content
    html = '<img src="http://cdn.evil.com/logo.png">'
    findings = _run(analyze_mixed_content("https://secure.example.com", html))
    assert any("Passive Mixed Content" in f["title"] for f in findings)


def test_mixed_content_only_on_https():
    from app.scanner.exposure_detector import analyze_mixed_content
    html = '<script src="http://cdn.evil.com/lib.js"></script>'
    findings = _run(analyze_mixed_content("http://insecure.example.com", html))
    assert not findings


# ── 11. SRI ───────────────────────────────────────────────────────────────────

def test_cdn_no_sri():
    from app.scanner.exposure_detector import analyze_third_party_sri
    html = '<script src="https://cdn.jsdelivr.net/npm/jquery.min.js"></script>'
    findings = _run(analyze_third_party_sri("https://example.com", html))
    assert any("CDN" in f["title"] for f in findings)


def test_cdn_with_sri_ok():
    from app.scanner.exposure_detector import analyze_third_party_sri
    html = '<script src="https://cdn.jsdelivr.net/npm/jquery.min.js" integrity="sha384-abc" crossorigin="anonymous"></script>'
    findings = _run(analyze_third_party_sri("https://example.com", html))
    assert not any("CDN" in f["title"] for f in findings)


# ── 12. Cache Exposure ────────────────────────────────────────────────────────

def test_auth_page_cacheable():
    from app.scanner.exposure_detector import analyze_cache_exposure
    findings = _run(analyze_cache_exposure(
        "https://example.com",
        {"content-type": "text/html", "www-authenticate": "Bearer", "cache-control": "public"},
    ))
    assert any("Authenticated Page" in f["title"] for f in findings)


def test_auth_page_no_store_ok():
    from app.scanner.exposure_detector import analyze_cache_exposure
    findings = _run(analyze_cache_exposure(
        "https://example.com",
        {"content-type": "text/html", "www-authenticate": "Bearer", "cache-control": "no-store"},
    ))
    assert not any("Authenticated Page" in f["title"] for f in findings)


# ── Schema contract ───────────────────────────────────────────────────────────

def test_findings_have_required_fields():
    from app.scanner.exposure_detector import analyze_web_security_config, analyze_js_secrets
    findings = _run(analyze_web_security_config(
        "https://example.com",
        {"access-control-allow-origin": "*", "server": "Apache/2.4.51"},
    ))
    findings += _run(analyze_js_secrets(
        "https://example.com",
        '<script>var key = "AKIAIOSFODNN7EXAMPLE";</script>',
    ))
    required = {"category", "title", "description", "severity", "confidence",
                "recommendation", "references", "endpoint", "evidence", "detector_id"}
    for f in findings:
        missing = required - set(f.keys())
        assert not missing, f"Finding missing fields: {missing} -- {f.get('title')}"


def test_detector_ids_registered():
    from app.scanner.exposure_detector import analyze_web_security_config, analyze_js_secrets
    from app.scanner.metadata import DETECTOR_REGISTRY
    findings = _run(analyze_web_security_config(
        "https://example.com",
        {"access-control-allow-origin": "*", "server": "nginx/1.20.0"},
    ))
    findings += _run(analyze_js_secrets(
        "https://example.com",
        '<script>var k = "AKIAIOSFODNN7EXAMPLE";</script>',
    ))
    for f in findings:
        det_id = f.get("detector_id", "")
        assert det_id in DETECTOR_REGISTRY, f"Unregistered detector_id: {det_id!r}"


def test_severity_values_valid():
    from app.scanner.exposure_detector import analyze_web_security_config
    findings = _run(analyze_web_security_config(
        "https://example.com",
        {"access-control-allow-origin": "*"},
    ))
    valid = {"critical", "high", "medium", "low", "info"}
    for f in findings:
        assert f["severity"] in valid


def test_orchestrator_returns_list():
    from app.scanner.exposure_detector import run_exposure_detection
    result = _run(run_exposure_detection(
        target_url="https://example.com",
        response_headers={},
        html_body="<html><body>ok</body></html>",
        cookies=[],
        dns_result={"records": {}, "findings": []},
        ssl_result={},
        hostname="example.com",
    ))
    assert isinstance(result, list)
