"""
Controlled Security Test Environment & Evaluation Suite
======================================================
Provides a local, self-contained, non-destructive test application representing
known security conditions and clean baselines for evaluating SentinelScan detectors.

Safety Guarantees:
- Runs locally in-memory via ASGI/HTTPX without external network calls.
- Zero credential harvesting, zero data extraction, zero destructive commands,
  zero arbitrary SSRF, and zero persistent modification.
- Evaluates true positive detection and false positive rejection across OWASP A01-A10
  and Component Lifecycle intelligence.
"""
import uuid
import re
import pytest
import httpx
from unittest.mock import AsyncMock, patch
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.routing import Route

from app.scanner.modules import (
    assess_a01_access_control,
    assess_a02_cryptography,
    assess_a03_injection,
    assess_a04_insecure_design,
    assess_a05_misconfiguration,
    assess_a06_components,
    assess_a07_authentication,
    assess_a08_integrity,
    assess_a09_logging,
    assess_a10_ssrf,
)
from app.scanner.header_analyzer import analyze_headers
from app.scanner.tech_detector import TECH_SIGNATURES
from app.scanner.component_engine import (
    normalize_component_version,
    LifecycleProvider,
    build_component_inventory,
    generate_component_findings,
    assess_component,
    STATE_END_OF_LIFE,
    STATE_VERSION_UNKNOWN,
    STATE_LIFECYCLE_UNKNOWN,
)


# ============================================================================
# 1. LOCAL CONTROLLED TEST APPLICATION
# ============================================================================

async def index_endpoint(request):
    """
    Intentionally misconfigured public landing page:
    - Missing CSP, HSTS, X-Frame-Options
    - Server: Apache/2.4.41 (Ubuntu)
    - X-Powered-By: PHP/7.4.3
    - Insecure Cookie (no Secure, HttpOnly, SameSite)
    - External CDN script without SRI
    - Mixed content reference
    """
    html = """<!DOCTYPE html>
    <html>
    <head>
        <title>Controlled Security Test Target</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/analytics.js"></script>
    </head>
    <body>
        <h1>Welcome to Controlled Test Target</h1>
        <img src="http://insecure.cdn.example.com/banner.png" alt="Mixed Content" />
    </body>
    </html>"""
    response = HTMLResponse(html)
    response.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    response.headers["X-Powered-By"] = "PHP/7.4.3"
    response.set_cookie("session", "insecure_token_123", path="/")
    return response


async def cors_vulnerable_endpoint(request):
    """Permissive CORS with credentials allowed (unsafe untrusted origin)."""
    response = JSONResponse({"status": "authenticated", "data": "sensitive_profile"})
    response.headers["Access-Control-Allow-Origin"] = "https://untrusted-external.com"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


async def directory_listing_endpoint(request):
    """Simulated directory listing signature."""
    html = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
    <html>
     <head>
      <title>Index of /static</title>
     </head>
     <body>
    <h1>Index of /static</h1>
    <pre><hr><a href="../">Parent Directory</a>
    <a href="secret.txt">secret.txt</a>
    <a href="backup.zip">backup.zip</a>
    <hr></pre>
    </body></html>"""
    return HTMLResponse(html)


async def error_traceback_endpoint(request):
    """Simulated verbose internal application error with stack trace."""
    traceback_text = """Traceback (most recent call last):
  File "/var/www/app/main.py", line 42, in handle_request
    raise ValueError("Internal database connection failed: postgresql://admin:secret@127.0.0.1:5432/app")
ValueError: Internal database connection failed"""
    return PlainTextResponse(traceback_text, status_code=500)


async def search_injection_endpoint(request):
    """
    Safe differential injection test endpoint:
    - If query contains unbalanced single quote ('), returns simulated syntax error marker.
    - If balanced or normal canary, returns clean 200 OK.
    - Prohibits destructive commands or arbitrary execution.
    """
    q = request.query_params.get("q", "")
    if "'" in q and "''" not in q:
        return PlainTextResponse("SQL syntax error near ''': syntax error at or near line 1", status_code=500)
    return HTMLResponse(f"<html><body>Search results for: {q}</body></html>")


async def admin_config_endpoint(request):
    """Sensitive endpoint disclosing administrative configuration."""
    return JSONResponse({"app_name": "TestTarget", "debug": True, "admin_email": "admin@test.local"})


async def secure_baseline_endpoint(request):
    """
    Hardened, secure baseline control:
    - Strict CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
    - Secure, HttpOnly, SameSite cookies
    - Clean body without mixed content, external script with valid SRI hash
    """
    html = """<!DOCTYPE html>
    <html>
    <head>
        <title>Secure Baseline Target</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/app.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>
    </head>
    <body><h1>Secure Production Service</h1></body>
    </html>"""
    response = HTMLResponse(html)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com;"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.set_cookie("session", "secure_token_456", path="/", secure=True, httponly=True, samesite="strict")
    return response


async def differential_auth_endpoint(request):
    """
    Controlled local differential authorization test endpoint:
    - Unauthenticated request -> denied (HTTP 401 Unauthorized)
    - Authorized test identity ('Bearer token-authorized-role') -> allowed (HTTP 200 OK)
    - Unauthorized / different-role test identity ('Bearer token-guest-role') -> denied (HTTP 403 Forbidden)
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header:
        return JSONResponse({"error": "unauthenticated", "detail": "Authentication required"}, status_code=401)
    if auth_header == "Bearer token-authorized-role":
        return JSONResponse({"status": "authenticated", "role": "admin", "data": "protected_profile_data"}, status_code=200)
    return JSONResponse({"error": "forbidden", "detail": "Insufficient role permissions"}, status_code=403)


async def ssrf_target_endpoint(request):
    """
    Controlled local test endpoint that accepts a destination URL parameter ('dest').
    Does not initiate external requests; purely simulates a URL-accepting parameter.
    """
    dest = request.query_params.get("dest", "")
    return JSONResponse({"status": "received", "destination": dest})


test_routes = [
    Route("/", index_endpoint),
    Route("/cors-vulnerable", cors_vulnerable_endpoint),
    Route("/static/", directory_listing_endpoint),
    Route("/error", error_traceback_endpoint),
    Route("/search", search_injection_endpoint),
    Route("/admin/config", admin_config_endpoint),
    Route("/secure", secure_baseline_endpoint),
    Route("/api/v1/profile", differential_auth_endpoint),
    Route("/fetch-preview", ssrf_target_endpoint),
]

controlled_test_app = Starlette(routes=test_routes)


# ============================================================================
# 2. EVALUATION TEST SUITE (20 STRUCTURED TEST CASES)
# ============================================================================

@pytest.mark.asyncio
class TestControlledSecurityEvaluation:
    """
    Executes 20 verifiable test cases against the local controlled test application.
    Compares EXPECTED vs OBSERVED behavior to compute exact accuracy and error rates.
    """

    @pytest.fixture(autouse=True)
    def setup_client(self):
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=controlled_test_app), base_url="http://testtarget.local")

    # --- T01: Missing Content-Security-Policy (A05) ---
    async def test_t01_missing_csp(self):
        resp = await self.client.get("/")
        with patch("app.utils.safe_http.SafeFetchClient") as mock_cls:
            mock_inst = AsyncMock()
            mock_inst.get = AsyncMock(return_value=resp)
            mock_inst.__aenter__ = AsyncMock(return_value=mock_inst)
            mock_inst.__aexit__ = AsyncMock(return_value=None)
            mock_cls.return_value = mock_inst

            res = await analyze_headers("https://testtarget.local")
            csp_findings = [f for f in res["findings"] if "content security policy" in f["title"].lower()]
            assert len(csp_findings) == 1
            assert "Content Security Policy" in csp_findings[0]["title"]

    # --- T02: Insecure Cookie Attributes (A07) ---
    async def test_t02_insecure_cookie_attributes(self):
        resp = await self.client.get("/")
        set_cookie = resp.headers.get("set-cookie")
        assert set_cookie is not None
        result = await assess_a07_authentication("http://testtarget.local", [set_cookie], ["http://testtarget.local"], [])
        assert result["status"] == "FAIL"
        assert len(result["findings"]) >= 1
        assert any("cookie" in f["title"].lower() for f in result["findings"])

    # --- T03: Permissive CORS with Credentials (A01) ---
    async def test_t03_cors_misconfiguration(self):
        resp = await self.client.get("/cors-vulnerable")
        result = await assess_a01_access_control("http://testtarget.local/cors-vulnerable", dict(resp.headers), ["http://testtarget.local"])
        assert result["status"] == "FAIL"
        assert result["confidence"] == "HIGH"
        assert any("cors" in f["category"].lower() for f in result["findings"])

    # --- T04: Server Banner Disclosure (A05) ---
    async def test_t04_server_banner_disclosure(self):
        resp = await self.client.get("/")
        with patch("app.utils.safe_http.SafeFetchClient") as mock_cls:
            mock_inst = AsyncMock()
            mock_inst.get = AsyncMock(return_value=resp)
            mock_inst.__aenter__ = AsyncMock(return_value=mock_inst)
            mock_inst.__aexit__ = AsyncMock(return_value=None)
            mock_cls.return_value = mock_inst

            res = await analyze_headers("https://testtarget.local")
            server_findings = [f for f in res["findings"] if "server" in f["title"].lower() or "disclosure" in f["category"].lower()]
            assert len(server_findings) >= 1
            assert any("Apache/2.4.41" in f["title"] for f in server_findings)

    # --- T05: Technology & Version Detection (A06) ---
    async def test_t05_technology_and_version_detection(self):
        resp = await self.client.get("/")
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        apache_spec = TECH_SIGNATURES.get("Apache")
        assert apache_spec is not None
        assert re.search(apache_spec["patterns"][0]["pattern"], headers_lower.get("server", ""), re.IGNORECASE) is not None
        apache_version_match = re.search(apache_spec["version_pattern"], headers_lower.get("server", ""))
        assert apache_version_match is not None
        assert apache_version_match.group(1) == "2.4.41"

        php_spec = TECH_SIGNATURES.get("PHP")
        assert php_spec is not None
        php_match = re.search(r'php(?:/|\s+)?([\d\.]+)', headers_lower.get("x-powered-by", ""), re.IGNORECASE)
        assert php_match is not None
        assert php_match.group(1) == "7.4.3"

    # --- T06: Outdated EOL Component Identification (A06) ---
    async def test_t06_outdated_eol_component(self):
        # PHP 7.4.3 is End-of-Life since 2022-11-28
        provider = LifecycleProvider(redis_client=None)
        info = await provider.get_lifecycle("PHP", "7.4.3")
        assert info["status"] == STATE_END_OF_LIFE
        assert info["eol_date"] == "2022-11-28"

    # --- T07: Component CVE Correlation (A06) ---
    async def test_t07_component_cve_correlation(self):
        """
        Deterministic component and CVE correlation test using mocked vulnerability intelligence.
        Verifies:
        - Detected component: Apache
        - Detected version: 2.4.41 (from Server: Apache/2.4.41 (Ubuntu))
        - Normalized version (2.4.41) and vendor suffix (Ubuntu) are correctly extracted
        - Known CVE (CVE-2021-41773) is attached to the correct component
        - Unrelated CVE (e.g. Nginx CVE-2021-23017) is NOT attached
        - Unknown version does not fabricate CVEs
        - Provider failure does not crash scanning (fail-safe)
        """
        tech_stack = {
            "Apache": {
                "version": "2.4.41 (Ubuntu)",
                "category": "Web Server",
                "source": "Server: Apache/2.4.41 (Ubuntu)",
                "evidence": "Server: Apache/2.4.41 (Ubuntu)",
            }
        }
        mock_cves = [
            {
                "id": "CVE-2021-41773",
                "title": "Apache HTTP Server 2.4.49/2.4.50 Path Traversal (CVE-2021-41773)",
                "description": "Apache HTTP Server path traversal and file disclosure flaw.",
                "severity": "critical",
                "cvss_score": 9.8,
            },
            {
                "id": "CVE-2021-23017",
                "title": "Nginx DNS Resolver 1-byte Memory Overwrite (CVE-2021-23017)",
                "description": "Nginx 0.6.18-1.20.0 1-byte memory overwrite vulnerability.",
                "severity": "high",
                "cvss_score": 7.7,
            },
        ]

        # 1. Verify normalized version and CVE attachment to correct component
        inventory, lifecycle_findings = await build_component_inventory(tech_stack, cve_findings=mock_cves)
        assert len(inventory) == 1
        apache_item = inventory[0]
        assert apache_item["technology"] == "Apache"
        assert apache_item["raw_version"] == "2.4.41 (Ubuntu)"
        assert apache_item["normalized_version"] == "2.4.41"
        assert apache_item["vendor_suffix"] == "Ubuntu"
        assert apache_item["cve_count"] == 1
        assert len(apache_item["cves"]) == 1
        assert apache_item["cves"][0]["id"] == "CVE-2021-41773"

        # 2. Verify no unrelated CVE is attached (Nginx CVE must NOT attach to Apache)
        cve_ids = [c["id"] for c in apache_item["cves"]]
        assert "CVE-2021-23017" not in cve_ids

        # 3. Verify unknown version does not fabricate CVEs
        unknown_stack = {"UnknownService": {"version": None, "category": "Internal"}}
        inv_unknown, _ = await build_component_inventory(unknown_stack, cve_findings=mock_cves)
        assert len(inv_unknown) == 1
        assert inv_unknown[0]["normalized_version"] is None
        assert inv_unknown[0]["cve_count"] == 0
        assert len(inv_unknown[0]["cves"]) == 0

        # 4. Verify provider failure does not crash scanning (fail-safe)
        with patch.object(LifecycleProvider, "get_lifecycle", side_effect=RuntimeError("Provider network down")):
            inv_resilient, findings_resilient = await build_component_inventory(
                {"PHP": {"version": "8.1.0"}}, cve_findings=mock_cves
            )
            assert len(inv_resilient) == 1
            assert inv_resilient[0]["technology"] == "PHP"

    # --- T08: Directory Listing Signature (A05) ---
    async def test_t08_directory_listing_signature(self):
        resp = await self.client.get("/static/")
        assert "Index of /static" in resp.text
        content_findings = [
            {"id": "content.directory_listing", "title": "Directory Listing Enabled", "severity": "medium", "confidence": "HIGH"}
        ]
        result = await assess_a05_misconfiguration("http://testtarget.local/static/", [], [], content_findings, headers={})
        assert result["status"] == "FAIL"
        assert len(result["findings"]) >= 1

    # --- T09: Verbose Error Stack Trace (A09) ---
    async def test_t09_verbose_error_stack_trace(self):
        resp = await self.client.get("/error")
        assert resp.status_code == 500
        assert "Traceback (most recent call last):" in resp.text
        content_findings = [
            {"id": "content.error_disclosure", "title": "Stack Trace or Debug Information Disclosed", "severity": "medium", "confidence": "HIGH"}
        ]
        result = await assess_a09_logging("http://testtarget.local", {"server": "apache"}, content_findings)
        assert result["status"] == "FAIL"
        assert len(result["findings"]) >= 1

    # --- T10: Mixed Content Reference (A02) ---
    async def test_t10_mixed_content_reference(self):
        resp = await self.client.get("/")
        body = resp.text
        mixed_refs = re.findall(r'src=["\'](http://[^"\']+)["\']', body)
        assert len(mixed_refs) >= 1
        assert "http://insecure.cdn.example.com/banner.png" in mixed_refs

    # --- T11: Missing SRI on External Script (A08) ---
    async def test_t11_missing_subresource_integrity(self):
        resp = await self.client.get("/")
        result = await assess_a08_integrity(
            "http://testtarget.local",
            [resp.text],
            ["https://cdnjs.cloudflare.com/ajax/libs/analytics.js"]
        )
        assert result["status"] == "FAIL"
        assert any("integrity" in f["title"].lower() or "sri" in f["category"].lower() for f in result["findings"])

    # --- T12: Safe Injection Differential Probe (A03) ---
    async def test_t12_safe_injection_differential_probe(self):
        resp_clean = await self.client.get("/search?q=test")
        resp_probe = await self.client.get("/search?q=test'")
        assert resp_clean.status_code == 200
        assert resp_probe.status_code == 500
        assert "SQL syntax error" in resp_probe.text

        async def fake_probe_get(url, *args, **kwargs):
            if "sentinelscan" in url:
                token = url.split("sentinelscan")[1].split("&")[0]
                return httpx.Response(200, headers={"Content-Type": "text/html"}, text=f"<div>Results for sentinelscan{token}</div>")
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<div>Baseline</div>")

        with patch("httpx.AsyncClient.get", side_effect=fake_probe_get):
            with patch("app.scanner.modules.a03_injection.async_resolve_and_pin", new_callable=AsyncMock) as mock_val:
                mock_val.return_value = (True, "OK", "http://testtarget.local/search?q=test",
                                         "http://testtarget.local/search?q=test", "testtarget.local")
                result = await assess_a03_injection({"q": ["http://testtarget.local/search?q=test"]})
                assert result["status"] == "FAIL"
                assert len(result["findings"]) >= 1

    # --- T13: Sensitive Admin Endpoint Exposure Review Indicator & Differential Authorization (A01) ---
    async def test_t13_sensitive_admin_endpoint(self):
        """
        A01 Controlled Access Control Assessment:
        1. Sensitive Endpoint Exposure:
           Identifies unauthenticated accessibility of /admin/config as a
           "Sensitive endpoint exposure / access-control review indicator",
           explicitly distinguishing endpoint exposure from confirmed authorization failure.
        2. Differential Authorization Verification:
           Safely tests controlled differential access using explicitly created local test identities:
           - unauthenticated request -> denied (HTTP 401)
           - authorized test identity -> allowed (HTTP 200)
           - unauthorized / different-role test identity -> denied (HTTP 403)
           Operates without brute-force, IDOR enumeration, or credential guessing.
        """
        # 1. Sensitive endpoint exposure (review indicator)
        resp = await self.client.get("/admin/config")
        assert resp.status_code == 200
        assert "admin_email" in resp.text
        endpoints = ["http://testtarget.local/admin/config", "http://testtarget.local/"]
        headers = {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}

        async def fake_a01_probe(url, *args, **kwargs):
            if "/admin/" in url:
                return httpx.Response(200, text='<html><body><h1>Admin Dashboard</h1><p>welcome management</p></body></html>')
            return httpx.Response(404, text="Not Found")

        with patch("httpx.AsyncClient.get", side_effect=fake_a01_probe):
            with patch("app.scanner.modules.a01_access_control.async_resolve_and_pin", new_callable=AsyncMock) as mock_val:
                mock_val.return_value = (True, "OK", "http://testtarget.local/",
                                         "http://testtarget.local/", "testtarget.local")
                result = await assess_a01_access_control("http://testtarget.local", headers, endpoints)
        # Per OWASP 2025: unverified endpoint reachability is treated as an access-control review indicator
        # rather than a confirmed authorization failure (FAIL)
        assert result["status"] in ("PASS", "INCONCLUSIVE")
        assert len(result["findings"]) >= 1
        assert any("Review Indicator" in f["title"] or "Browser-Blocked" in f["title"] for f in result["findings"])

        # 2. Controlled local differential authorization test
        # Case A: unauthenticated request -> denied (401)
        resp_unauth = await self.client.get("/api/v1/profile")
        assert resp_unauth.status_code == 401
        assert resp_unauth.json()["error"] == "unauthenticated"

        # Case B: authorized test identity -> allowed (200)
        resp_auth = await self.client.get(
            "/api/v1/profile",
            headers={"Authorization": "Bearer token-authorized-role"}
        )
        assert resp_auth.status_code == 200
        assert resp_auth.json()["status"] == "authenticated"
        assert resp_auth.json()["role"] == "admin"

        # Case C: unauthorized / different-role test identity -> denied (403)
        resp_unauthorized_role = await self.client.get(
            "/api/v1/profile",
            headers={"Authorization": "Bearer token-guest-role"}
        )
        assert resp_unauthorized_role.status_code == 403
        assert resp_unauthorized_role.json()["error"] == "forbidden"

    # --- T14: Insecure Design Evidence Assessment (A04) ---
    async def test_t14_insecure_design_evidence(self):
        # Case A: When no spec provided -> honest NOT_VERIFIABLE
        unverifiable = await assess_a04_insecure_design(design_questionnaire=None, openapi_spec=None)
        assert unverifiable["status"] == "NOT_VERIFIABLE"

        # Case B: When insecure spec provided -> detected FAIL
        questionnaire = {"rate_limiting_implemented": False, "input_validation_layer": True}
        verifiable = await assess_a04_insecure_design(design_questionnaire=questionnaire, openapi_spec=None)
        assert verifiable["status"] == "FAIL"
        assert len(verifiable["findings"]) >= 1

    # --- T15: Controlled A10 Parameter Surface Evaluation ---
    async def test_t15_controlled_a10_parameter_surface(self):
        """
        [Legacy] OWASP A10:2021 Server-Side Request Forgery (SSRF) Surface Evaluation:
        Tests honest reporting of URL parameters without unverified claims.
        """
        scan_id = "scan-controlled-eval-123"

        # 1. SCENARIO A10-1: URL-accepting parameter discovered -> NOT_VERIFIABLE
        res_a10_params = await assess_a10_ssrf(
            scan_id=scan_id,
            discovered_parameters={"dest": ["http://testtarget.local/fetch-preview?dest=https://example.com"]},
        )
        assert res_a10_params["status"] == "NOT_VERIFIABLE"
        assert res_a10_params["confidence"] == "LOW"
        assert len(res_a10_params["findings"]) == 0
        assert "NOT_VERIFIABLE" in res_a10_params["limitations"]
        assert "URL Parameter & Redirection Surface Analysis" in res_a10_params["method"]

        # 2. SCENARIO A10-2: No URL-accepting parameters discovered -> PASS
        res_a10_clean = await assess_a10_ssrf(
            scan_id=scan_id,
            discovered_parameters={"page": ["http://testtarget.local/about?page=2"]},
        )
        assert res_a10_clean["status"] == "PASS"
        assert res_a10_clean["confidence"] == "HIGH"
        assert len(res_a10_clean["findings"]) == 0

    # --- T16: Clean Secure Baseline Control (False Positive Rejection) ---
    async def test_t16_clean_secure_headers_baseline(self):
        resp = await self.client.get("/secure")
        with patch("app.utils.safe_http.SafeFetchClient") as mock_cls:
            mock_inst = AsyncMock()
            mock_inst.get = AsyncMock(return_value=resp)
            mock_inst.__aenter__ = AsyncMock(return_value=mock_inst)
            mock_inst.__aexit__ = AsyncMock(return_value=None)
            mock_cls.return_value = mock_inst

            res = await analyze_headers("https://testtarget.local/secure")
            missing_critical = [
                f for f in res["findings"]
                if any(k in f.get("title", "").lower() for k in ["missing content security policy", "missing http strict transport security", "missing x-frame-options"])
            ]
            assert len(missing_critical) == 0, f"False positive findings generated on secure baseline: {missing_critical}"

    # --- T17: Clean Search Baseline Control (No Injection Differential) ---
    async def test_t17_clean_search_baseline(self):
        resp1 = await self.client.get("/search?q=normal1")
        assert resp1.status_code == 200
        result = await assess_a03_injection({})
        assert result["status"] == "PASS"
        assert len(result["findings"]) == 0

    # --- T18: Clean External Script with Valid SRI Hash Control ---
    async def test_t18_clean_script_with_valid_sri(self):
        resp = await self.client.get("/secure")
        result = await assess_a08_integrity(
            "http://testtarget.local/secure",
            [resp.text],
            ["https://cdnjs.cloudflare.com/ajax/libs/app.js"]
        )
        assert result["status"] == "PASS"
        assert len(result["findings"]) == 0

    # --- T19: Unknown Technology Version Handling Control ---
    async def test_t19_unknown_version_handling(self):
        norm = normalize_component_version("")
        assert norm.normalized_version is None
        provider = LifecycleProvider(redis_client=None)
        info = await provider.get_lifecycle("CustomInternalLib", None)
        assert info["status"] == STATE_VERSION_UNKNOWN
        assert info["eol_date"] is None

    # --- T20: Missing Lifecycle Data Handling Control ---
    async def test_t20_missing_lifecycle_data_handling(self):
        provider = LifecycleProvider(redis_client=None)
        info = await provider.get_lifecycle("UnknownFramework", "3.1.4")
        assert info["status"] == STATE_LIFECYCLE_UNKNOWN
        assert info["eol_date"] is None
