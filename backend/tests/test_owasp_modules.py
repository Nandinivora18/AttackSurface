"""
Tests for OWASP Top 10:2025 Assessment Modules
==============================================
Validates assessment mechanisms, honest 5-state reporting, confidence scoring,
and non-destructive evidence generation across A01:2025 through A10:2025.
"""
import pytest
from unittest.mock import AsyncMock, patch
import httpx

from app.scanner.modules import (
    assess_a01_access_control,
    assess_a02_misconfiguration,
    assess_a03_supply_chain,
    assess_a04_cryptography,
    assess_a05_injection,
    assess_a06_insecure_design,
    assess_a07_authentication,
    assess_a08_integrity,
    assess_a09_logging,
    assess_a10_exceptional_conditions,
)


# ─── A01:2025 Broken Access Control ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_a01_access_control_cors_browser_semantics():
    """
    Wildcard origin with credentials allowed is rejected by modern browsers.
    Per browser CORS semantics, it must NOT be classified as confirmed exploitable vulnerability.
    """
    headers = {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
    }
    result = await assess_a01_access_control(
        "https://app.test",
        headers,
        ["https://app.test"],
    )

    # Inconsistent policy recorded but blocked by browsers (status PASS / severity low)
    assert result["confidence"] == "HIGH"
    assert len(result["findings"]) >= 1
    assert any("cors" in f["category"].lower() for f in result["findings"])
    assert result["findings"][0]["severity"] in ("low", "info")
    assert "Browser-Blocked" in result["findings"][0]["title"]


@pytest.mark.asyncio
async def test_a01_access_control_cors_unsafe_null_origin():
    """Null origin with credentials true is genuinely unsafe (exploitable via sandboxed iframe)."""
    headers = {
        "access-control-allow-origin": "null",
        "access-control-allow-credentials": "true",
    }
    result = await assess_a01_access_control(
        "https://app.test",
        headers,
        ["https://app.test"],
    )

    assert result["status"] == "FAIL"
    assert result["confidence"] == "HIGH"
    assert len(result["findings"]) >= 1
    assert result["findings"][0]["severity"] == "high"


@pytest.mark.asyncio
async def test_a01_access_control_clean():
    headers = {
        "access-control-allow-origin": "https://trusted.app.test",
        "access-control-allow-credentials": "true",
    }
    result = await assess_a01_access_control(
        "https://app.test",
        headers,
        ["https://app.test"],
    )

    assert result["status"] == "PASS"
    assert len(result["findings"]) == 0


@pytest.mark.asyncio
async def test_a01_ssrf_parameter_surface_not_verifiable():
    """SSRF parameter surface evaluated under A01 remains strictly NOT VERIFIABLE for execution."""
    params = {"dest": ["https://app.test/fetch?dest=https://internal.test"]}
    result = await assess_a01_access_control(
        "https://app.test",
        {},
        ["https://app.test"],
        discovered_parameters=params,
    )

    assert "Potential server-side request parameter surface identified" in result["limitations"]
    assert "server-side request execution cannot be externally verified" in result["limitations"]


# ─── A02:2025 Security Misconfiguration ──────────────────────────────────────

@pytest.mark.asyncio
async def test_a02_misconfiguration_header_finding():
    header_findings = [
        {
            "id": "headers.missing_csp",
            "title": "Missing Content-Security-Policy",
            "severity": "medium",
            "confidence": "CONFIRMED",
        }
    ]
    result = await assess_a02_misconfiguration(
        "https://app.test",
        header_findings,
        [],
        [],
        headers={"server": "Apache/2.4.41"},
    )
    assert result["status"] == "FAIL"
    assert len(result["findings"]) >= 1
    assert "provide direct externally observable evidence of the evaluated security configuration" in result["limitations"]


# ─── A03:2025 Software Supply Chain Failures ─────────────────────────────────

@pytest.mark.asyncio
async def test_a03_supply_chain_eol_component():
    inventory = [
        {
            "technology": "Python",
            "category": "Programming Language",
            "detected_version": "2.7.18",
            "normalized_version": "2.7.18",
            "lifecycle_status": "END_OF_LIFE",
            "eol_date": "2020-01-01",
            "latest_version": "3.13.0",
            "version_confidence": "CONFIRMED",
        }
    ]
    result = await assess_a03_supply_chain("https://app.test", component_inventory=inventory)
    assert result["status"] == "FAIL"
    assert len(result["findings"]) == 1
    assert "End-of-Life" in result["findings"][0]["title"]


@pytest.mark.asyncio
async def test_a03_supply_chain_sri_cdn():
    html_samples = ['<script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"></script>']
    result = await assess_a03_supply_chain(
        "https://app.test",
        component_inventory=[],
        crawled_html_samples=html_samples,
    )
    assert result["status"] == "FAIL"
    assert any("subresource integrity" in f["category"].lower() for f in result["findings"])


@pytest.mark.asyncio
async def test_a03_supply_chain_supported_component():
    inventory = [
        {
            "technology": "Nginx",
            "category": "Web Server",
            "detected_version": "1.24.0",
            "normalized_version": "1.24.0",
            "lifecycle_status": "SUPPORTED",
            "eol_date": None,
            "latest_version": "1.24.0",
            "version_confidence": "HIGH",
        }
    ]
    result = await assess_a03_supply_chain("https://app.test", component_inventory=inventory)
    assert result["status"] == "PASS"
    assert len(result["findings"]) == 0


# ─── A04:2025 Cryptographic Failures ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_a04_cryptography_issues():
    ssl_issues = [
        {
            "id": "ssl.weak_cipher",
            "message": "Weak Cipher Suite Supported: RC4",
            "severity": "high",
            "confidence": "HIGH",
        }
    ]
    headers = {"strict-transport-security": "max-age=31536000"}
    result = await assess_a04_cryptography(
        "https://app.test",
        ssl_issues,
        headers,
    )

    assert result["status"] == "FAIL"
    assert len(result["findings"]) >= 1
    assert "provide direct externally observable evidence of the evaluated transport-security configuration" in result["limitations"]


@pytest.mark.asyncio
async def test_a04_cryptography_not_applicable_for_http():
    result = await assess_a04_cryptography(
        "http://insecure.test",
        [],
        {},
    )
    assert result["status"] == "NOT_APPLICABLE"


# ─── A05:2025 Injection ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a05_injection_empty():
    result = await assess_a05_injection({})
    assert result["status"] == "PASS"
    assert len(result["findings"]) == 0


@pytest.mark.asyncio
async def test_a05_injection_differential_reflection():
    params = {"q": ["https://app.test/search?q=test"]}

    async def fake_get(url, *args, **kwargs):
        if "sentinelscan" in url:
            token = url.split("sentinelscan")[1].split("&")[0]
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=f"<div>Results for sentinelscan{token}</div>")
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<div>Baseline</div>")

    with patch("httpx.AsyncClient.get", side_effect=fake_get):
        with patch("app.scanner.modules.a05_injection.async_resolve_and_pin", new_callable=AsyncMock) as mock_val:
            mock_val.return_value = (True, "OK", "http://app.test/search?q=test",
                                     "http://app.test/search?q=test", "app.test")
            result = await assess_a05_injection(params)
            assert len(result["findings"]) >= 1


# ─── A06:2025 Insecure Design ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a06_insecure_design_unverified():
    result = await assess_a06_insecure_design(
        design_questionnaire=None,
        openapi_spec=None,
    )
    assert result["status"] == "NOT_VERIFIABLE"
    assert "cannot be proven solely from external HTTP observation" in result["limitations"]


@pytest.mark.asyncio
async def test_a06_insecure_design_evaluated():
    questionnaire = {
        "rate_limiting_designed": False,
        "threat_modeling_conducted": True,
    }
    result = await assess_a06_insecure_design(
        design_questionnaire=questionnaire,
        openapi_spec=None,
    )
    assert result["status"] == "FAIL"
    assert len(result["findings"]) >= 1


# ─── A07:2025 Authentication Failures ────────────────────────────────────────

@pytest.mark.asyncio
async def test_a07_authentication_insecure_cookie():
    raw_cookies = ["session=secret123; Path=/"]
    result = await assess_a07_authentication(
        "https://app.test",
        raw_cookies,
        ["https://app.test"],
        [],
    )
    assert result["status"] == "FAIL"
    assert len(result["findings"]) >= 1
    assert any("cookie" in f["title"].lower() for f in result["findings"])


# ─── A08:2025 Software or Data Integrity Failures ────────────────────────────

@pytest.mark.asyncio
async def test_a08_integrity_missing_sri():
    html_sample = ['<script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"></script>']
    result = await assess_a08_integrity(
        "https://app.test",
        html_sample,
        ["https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"],
    )
    assert result["status"] == "FAIL"
    assert len(result["findings"]) >= 1
    assert any("sri" in f["category"].lower() or "integrity" in f["title"].lower() for f in result["findings"])


@pytest.mark.asyncio
async def test_a08_integrity_malformed_target_not_applicable():
    """A target without a parseable http(s) origin must be skipped cleanly
    (PASS + no findings), not crash or emit false positives against ""."""
    html_sample = ['<script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"></script>']
    for bad_target in ("", "not-a-url", "ftp://example.com/x", None):
        result = await assess_a08_integrity(bad_target, html_sample, [])
        assert result["status"] == "PASS"
        assert result["findings"] == []


@pytest.mark.asyncio
async def test_a08_integrity_sri_present_no_finding():
    html_sample = [
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js" '
        'integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>'
    ]
    result = await assess_a08_integrity("https://app.test", html_sample, [])
    assert result["status"] == "PASS"
    assert result["findings"] == []


# ─── A09:2025 Security Logging and Alerting Failures ─────────────────────────

@pytest.mark.asyncio
async def test_a09_logging():
    content_findings = [
        {
            "id": "content.error_disclosure",
            "title": "Stack Trace or Debug Information Disclosed",
            "severity": "medium",
            "confidence": "HIGH",
        }
    ]
    result = await assess_a09_logging(
        "https://app.test",
        {"server": "nginx"},
        content_findings,
    )
    assert result["status"] == "FAIL"
    assert len(result["findings"]) >= 1


# ─── A10:2025 Mishandling of Exceptional Conditions ──────────────────────────

@pytest.mark.asyncio
async def test_a10_exceptional_conditions_stack_trace():
    html_sample = [
        "<html><body><h1>Internal Server Error</h1><pre>Traceback (most recent call last):\n  File 'app.py', line 42</pre></body></html>"
    ]
    result = await assess_a10_exceptional_conditions(
        "https://app.test",
        content_findings=[],
        crawled_html_samples=html_sample,
    )
    assert result["status"] == "FAIL"
    assert len(result["findings"]) >= 1
    assert any("stack trace" in f["title"].lower() for f in result["findings"])


@pytest.mark.asyncio
async def test_a10_exceptional_conditions_clean():
    result = await assess_a10_exceptional_conditions(
        "https://app.test",
        content_findings=[],
        crawled_html_samples=["<html><body><h1>Welcome</h1></body></html>"],
    )
    assert result["status"] == "PASS"
    assert len(result["findings"]) == 0
