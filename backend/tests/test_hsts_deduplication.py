"""
Regression test suite for HSTS finding deduplication and normalization.

Verifies:
1. TEST 1: Header completely absent produces exactly 1 HSTS finding.
2. TEST 2: Header present but empty/whitespace produces exactly 1 HSTS finding.
3. TEST 3: Both conditions / multiple observations in the same scan aggregation path
   normalize and deduplicate to exactly 1 HSTS finding.
4. TEST 4: Valid HSTS header produces 0 Missing HSTS findings.
5. TEST 5: Existing legitimate duplicate-prevention behavior for unrelated findings
   (unrelated findings are never incorrectly merged).
6. TEST 6: Invalid/ineffective HSTS values produce the single appropriate directive finding.
7. Scoring: Verified that deduplication prevents double penalty in scoring.
8. End-to-end ginandjuice.shop dataset verification.
"""
import pytest
import httpx
from unittest.mock import AsyncMock, patch

from app.scanner.header_analyzer import analyze_headers, _analyze_hsts
from app.scanner.modules.a04_cryptography import assess_a04_cryptography
from app.scanner.modules.a02_cryptography import assess_a02_cryptography
from app.scanner.scoring import calculate_score
from app.tasks.scan_task import get_finding_identity, deduplicate_findings


def _mock_fetch_client(headers: dict, text: str = "<html><body>Test</body></html>", status_code: int = 200, url: str = "https://target.local"):
    """Helper to mock SafeFetchClient response."""
    req = httpx.Request("GET", url)
    resp = httpx.Response(status_code, headers=headers, text=text, request=req)
    mock_inst = AsyncMock()
    mock_inst.get = AsyncMock(return_value=resp)
    mock_inst.__aenter__ = AsyncMock(return_value=mock_inst)
    mock_inst.__aexit__ = AsyncMock(return_value=None)
    return mock_inst


# ─── TEST 1: Header completely absent ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_hsts_header_completely_absent():
    """TEST 1: When Strict-Transport-Security header is completely absent,
    exactly 1 Missing HSTS finding is produced."""
    url = "https://target.local"
    headers_without_hsts = {
        "content-type": "text/html",
        "content-security-policy": "default-src 'self'",
    }

    with patch("app.utils.safe_http.SafeFetchClient") as mock_cls:
        mock_cls.return_value = _mock_fetch_client(headers_without_hsts, url=url)
        res = await analyze_headers(url)

    hsts_findings = [
        f for f in res["findings"]
        if "strict transport security" in f.get("title", "").lower()
    ]
    assert len(hsts_findings) == 1, f"Expected exactly 1 HSTS finding, got {len(hsts_findings)}"
    finding = hsts_findings[0]
    assert finding["title"] == "Missing HTTP Strict Transport Security (HSTS)"
    assert finding["severity"] == "high"
    assert finding["category"] == "Transport Security"
    assert "not present in response" in finding["evidence"]


# ─── TEST 2: Header present but empty ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_hsts_header_present_but_empty():
    """TEST 2: When Strict-Transport-Security header exists but is empty or whitespace,
    it normalizes to exactly 1 Missing HSTS finding (not directive misconfiguration)."""
    url = "https://target.local"

    for empty_val in ["", "   ", "\t"]:
        headers_empty_hsts = {
            "content-type": "text/html",
            "strict-transport-security": empty_val,
        }

        with patch("app.utils.safe_http.SafeFetchClient") as mock_cls:
            mock_cls.return_value = _mock_fetch_client(headers_empty_hsts, url=url)
            res = await analyze_headers(url)

        hsts_findings = [
            f for f in res["findings"]
            if "strict transport security" in f.get("title", "").lower()
        ]
        assert len(hsts_findings) == 1, f"For empty value '{empty_val}', expected 1 HSTS finding, got {len(hsts_findings)}"
        finding = hsts_findings[0]
        assert finding["title"] == "Missing HTTP Strict Transport Security (HSTS)"
        assert finding["severity"] == "high"
        assert finding["category"] == "Transport Security"
        assert "empty value in response" in finding["evidence"]


# ─── TEST 3: Both conditions in same scan / aggregation path ─────────────────

@pytest.mark.asyncio
async def test_hsts_deduplication_across_stages_and_conditions():
    """TEST 3: When absent HSTS and empty HSTS, or observations from both
    header_analyzer and a04_cryptography are present in the same scan aggregation path,
    deduplication yields exactly 1 Missing HSTS finding, not 2."""
    url = "https://target.local"

    # Observation 1 from header_analyzer (absent)
    finding_absent = {
        "category": "Transport Security",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "severity": "high",
        "confidence": "high",
        "cvss_score": 6.5,
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
        "endpoint": url,
        "evidence": "Header 'strict-transport-security' not present in response",
    }

    # Observation 2 from a04_cryptography (evaluated during OWASP module stage)
    finding_owasp = {
        "category": "Transport Security",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "severity": "high",
        "confidence": "confirmed",
        "cvss_score": 6.5,
        "recommendation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "references": ["https://owasp.org/Top10/A04_2025-Cryptographic_Failures/"],
        "endpoint": url,
        "evidence": "Strict-Transport-Security: <absent>",
    }

    # Observation 3 (empty value observation on a redirect or secondary probe)
    finding_empty = {
        "category": "Transport Security",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "severity": "high",
        "confidence": "high",
        "cvss_score": 6.5,
        "endpoint": url,
        "evidence": "Header 'strict-transport-security' present with empty value in response",
    }

    # All three in the aggregation pool
    all_findings = [finding_absent, finding_owasp, finding_empty]

    deduped = deduplicate_findings(all_findings, target_url=url)
    hsts_in_deduped = [
        f for f in deduped
        if "strict transport security" in f.get("title", "").lower()
    ]
    assert len(hsts_in_deduped) == 1, (
        f"Expected exactly 1 HSTS finding after deduplication, got {len(hsts_in_deduped)}: "
        f"{[f.get('title') for f in hsts_in_deduped]}"
    )
    # Ensure first observation's evidence is preserved
    assert "not present in response" in hsts_in_deduped[0]["evidence"]


# ─── TEST 4: Valid HSTS header ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_valid_hsts_header_produces_no_missing_finding():
    """TEST 4: When a valid HSTS header is configured, 0 Missing HSTS findings are produced."""
    url = "https://target.local"
    headers_valid_hsts = {
        "content-type": "text/html",
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    }

    # 1. Test header_analyzer
    with patch("app.utils.safe_http.SafeFetchClient") as mock_cls:
        mock_cls.return_value = _mock_fetch_client(headers_valid_hsts, url=url)
        res = await analyze_headers(url)

    missing_hsts = [
        f for f in res["findings"]
        if "strict transport security" in f.get("title", "").lower()
        and "missing" in f.get("title", "").lower()
    ]
    assert len(missing_hsts) == 0, f"Expected 0 Missing HSTS findings for valid header, got {len(missing_hsts)}"

    # 2. Test a04_cryptography
    a04_res = await assess_a04_cryptography(url, [], headers_valid_hsts)
    missing_hsts_a04 = [
        f for f in a04_res["findings"]
        if "strict transport security" in f.get("title", "").lower()
        and "missing" in f.get("title", "").lower()
    ]
    assert len(missing_hsts_a04) == 0, f"Expected 0 Missing HSTS findings in A04, got {len(missing_hsts_a04)}"

    # 3. Test a02_cryptography backward compatibility alias
    a02_res = await assess_a02_cryptography(url, [], headers_valid_hsts)
    missing_hsts_a02 = [
        f for f in a02_res["findings"]
        if "strict transport security" in f.get("title", "").lower()
        and "missing" in f.get("title", "").lower()
    ]
    assert len(missing_hsts_a02) == 0


# ─── TEST 5: Unrelated findings NOT merged ────────────────────────────────────

def test_unrelated_findings_not_merged():
    """TEST 5: Distinct security findings and endpoint-specific findings must NOT be
    incorrectly merged by the deduplication engine."""
    url = "https://target.local"
    unrelated_findings = [
        {
            "category": "Transport Security",
            "title": "Missing HTTP Strict Transport Security (HSTS)",
            "severity": "high",
            "endpoint": url,
        },
        {
            "category": "Injection Prevention",
            "title": "Missing Content Security Policy (CSP)",
            "severity": "high",
            "endpoint": url,
        },
        {
            "category": "Clickjacking Protection",
            "title": "Missing X-Frame-Options",
            "severity": "medium",
            "endpoint": url,
        },
        {
            "category": "MIME Sniffing Prevention",
            "title": "Missing X-Content-Type-Options",
            "severity": "low",
            "endpoint": url,
        },
        {
            "category": "Cookie Security",
            "title": "Session Cookie Missing HttpOnly Flag: session_id",
            "severity": "medium",
            "endpoint": f"{url}/login",
        },
        {
            "category": "Cookie Security",
            "title": "Cookie Missing Secure Flag over HTTPS: AWSALB",
            "severity": "low",
            "endpoint": url,
        },
        {
            "category": "DNS",
            "title": "Missing DMARC Record",
            "severity": "medium",
            "endpoint": "target.local",
        },
    ]

    deduped = deduplicate_findings(unrelated_findings, target_url=url)
    assert len(deduped) == len(unrelated_findings), (
        f"Expected all {len(unrelated_findings)} distinct findings to be preserved, "
        f"got {len(deduped)}"
    )
    titles_orig = [f["title"] for f in unrelated_findings]
    titles_dedup = [f["title"] for f in deduped]
    assert titles_orig == titles_dedup


# ─── TEST 6: Invalid/ineffective HSTS values ──────────────────────────────────

def test_hsts_invalid_directive_produces_directive_finding():
    """TEST 6: A header present with an invalid/ineffective value (e.g. missing max-age
    or short max-age) produces the appropriate directive finding according to existing
    detector semantics, NOT 'Missing HSTS'."""
    # 1. Missing max-age directive (e.g. only 'preload')
    issues = _analyze_hsts("preload; includeSubDomains")
    assert any("missing max-age directive" in i["message"].lower() for i in issues)

    # 2. Too short max-age
    issues_short = _analyze_hsts("max-age=3600; includeSubDomains")
    assert any("max-age too short" in i["message"].lower() for i in issues_short)

    # 3. Empty string in _analyze_hsts returns [] (handled at missing level)
    assert _analyze_hsts("") == []
    assert _analyze_hsts("   ") == []


# ─── TEST 7: Scoring double-deduction prevention ──────────────────────────────

def test_scoring_deduplication_prevents_double_penalty():
    """Verify that deduplicating HSTS prevents double penalty in scoring."""
    url = "https://target.local"
    duplicate_hsts_findings = [
        {
            "category": "Transport Security",
            "title": "Missing HTTP Strict Transport Security (HSTS)",
            "severity": "high",
            "endpoint": url,
            "is_passed_control": False,
        },
        {
            "category": "Transport Security",
            "title": "Missing HTTP Strict Transport Security (HSTS)",
            "severity": "high",
            "endpoint": url,
            "is_passed_control": False,
        },
    ]

    # Without deduplication: 2 high findings, double penalty
    score_with_dup = calculate_score(duplicate_hsts_findings)
    assert score_with_dup["severity_counts"]["high"] == 2
    assert len(score_with_dup["category_scores"]["ssl_tls"]["deductions"]) == 2

    # With deduplication: 1 high finding, single penalty
    deduped = deduplicate_findings(duplicate_hsts_findings, target_url=url)
    assert len(deduped) == 1

    score_deduped = calculate_score(deduped)
    assert score_deduped["severity_counts"]["high"] == 1
    assert len(score_deduped["category_scores"]["ssl_tls"]["deductions"]) == 1
    # Deductions: single deduction of 4.8 points
    deduction = score_deduped["category_scores"]["ssl_tls"]["deductions"][0]
    assert deduction["finding_title"] == "Missing HTTP Strict Transport Security (HSTS)"
    assert deduction["points_deducted"] == 4.8

    # Overall score must naturally be higher with 1 finding than with 2
    assert score_deduped["overall_score"] > score_with_dup["overall_score"]


# ─── TEST 8: Real-world ginandjuice.shop scan dataset regression ──────────────

def test_ginandjuice_real_dataset_deduplication():
    """Verify that the exact 15-finding ginandjuice.shop dataset correctly deduplicates
    from 2 HSTS findings to 1 HSTS finding, with 14 unique findings total."""
    url = "https://ginandjuice.shop"

    # Exact findings from the real ginandjuice.shop scan
    raw_findings = [
        {"category": "Email Security", "title": "Missing DMARC Record", "severity": "medium", "endpoint": "ginandjuice.shop"},
        {"category": "Transport Security", "title": "Missing HTTP Strict Transport Security (HSTS)", "severity": "high", "endpoint": url, "evidence": "Header 'strict-transport-security' not present in response"},
        {"category": "Injection Prevention", "title": "Missing Content Security Policy (CSP)", "severity": "high", "endpoint": url},
        {"category": "MIME Sniffing Prevention", "title": "Missing X-Content-Type-Options", "severity": "low", "endpoint": url},
        {"category": "Privacy", "title": "Missing Referrer-Policy", "severity": "low", "endpoint": url},
        {"category": "Feature Control", "title": "Missing Permissions-Policy", "severity": "low", "endpoint": url},
        {"category": "XSS Protection (Legacy)", "title": "Missing X-XSS-Protection", "severity": "info", "endpoint": url},
        {"category": "Isolation", "title": "Missing Cross-Origin-Opener-Policy (COOP)", "severity": "low", "endpoint": url},
        {"category": "Isolation", "title": "Missing Cross-Origin-Embedder-Policy (COEP)", "severity": "info", "endpoint": url},
        {"category": "Isolation", "title": "Missing Cross-Origin-Resource-Policy (CORP)", "severity": "info", "endpoint": url},
        {"category": "Cookie Security", "title": "Session Cookie 'session' Missing SameSite Attribute", "severity": "medium", "endpoint": url},
        {"category": "Transport Security", "title": "Missing HTTP Strict Transport Security (HSTS)", "severity": "high", "endpoint": url, "evidence": "Strict-Transport-Security: <absent>"},
        {"category": "Session Management", "title": "Cookie Missing Secure Flag over HTTPS: AWSALB", "severity": "low", "endpoint": url},
        {"category": "Session Management", "title": "Cookie Missing SameSite Attribute: AWSALB", "severity": "low", "endpoint": url},
        {"category": "Telemetry & Observability", "title": "Correlation header not externally observed", "severity": "info", "endpoint": url},
    ]

    assert len(raw_findings) == 15
    raw_hsts = [f for f in raw_findings if "strict transport security" in f["title"].lower()]
    assert len(raw_hsts) == 2, "Raw dataset has 2 HSTS findings before deduplication"

    deduped = deduplicate_findings(raw_findings, target_url=url)
    assert len(deduped) == 14, f"Expected 14 unique findings, got {len(deduped)}"

    deduped_hsts = [f for f in deduped if "strict transport security" in f["title"].lower()]
    assert len(deduped_hsts) == 1, f"Expected exactly 1 HSTS finding, got {len(deduped_hsts)}"
    assert deduped_hsts[0]["title"] == "Missing HTTP Strict Transport Security (HSTS)"
    assert deduped_hsts[0]["severity"] == "high"

    # Score calculation on deduplicated findings
    score = calculate_score(deduped)
    assert score["overall_score"] == 81
    assert score["grade"] == "A"
    assert score["severity_counts"]["high"] == 2
    assert score["severity_counts"]["medium"] == 2
    assert score["severity_counts"]["low"] == 6
    assert score["severity_counts"]["info"] == 4
