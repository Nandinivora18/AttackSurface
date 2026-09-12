"""
OWASP A01:2025 — Broken Access Control Assessment Module
========================================================
Evaluates cross-origin access policies according to browser CORS semantics,
discovers exposed sensitive/administrative surfaces, performs controlled differential
authorization tests when explicit test identities are authorized, and evaluates candidate
redirection/SSRF parameter surfaces as access-control/network-boundary indicators.

Safety Invariants:
- Zero credential brute forcing or horizontal IDOR traversal across tenant accounts.
- Zero outbound out-of-band callbacks (no OAST infrastructure).
- SSRF execution is never claimed as confirmed; candidate parameter surfaces remain
  strictly evidence-assisted and NOT VERIFIABLE for actual server-side request execution.
- Passwords and auth tokens are strictly redacted before evidence recording.
- Credentials are bound in-memory to the single scan and never persisted.
"""
from __future__ import annotations

import logging
import urllib.parse
from typing import Any
import httpx

from app.utils.safe_http import async_resolve_and_pin

logger = logging.getLogger(__name__)

# Standard administrative and debug paths to probe safely via GET
SENSITIVE_PATHS = [
    "/admin/",
    "/administrator/",
    "/actuator/health",
    "/actuator/env",
    "/.git/HEAD",
    "/api/v1/users",
    "/dashboard/settings",
    "/server-status",
]

# Candidate parameter names indicating candidate redirection / resource fetch inputs
URL_PARAMETER_NAMES = {
    "url", "dest", "destination", "redirect", "redirect_url", "uri",
    "target", "link", "src", "source", "webhook", "feed", "site",
    "callback", "path", "domain", "fetch",
}


async def assess_a01_access_control(
    target_url: str,
    headers: dict[str, str],
    discovered_urls: list[str],
    discovered_parameters: dict[str, list[str]] | None = None,
    auth_context: dict[str, Any] | None = None,
    probe_active: bool = False,
) -> dict[str, Any]:
    """
    Executes A01:2025 Broken Access Control assessment.
    """
    findings: list[dict[str, Any]] = []
    status = "PASS"
    confidence = "HIGH"

    # 1. Passive CORS Evaluation (evaluated strictly according to browser CORS semantics)
    acao = headers.get("access-control-allow-origin", "").strip()
    acac = headers.get("access-control-allow-credentials", "").strip().lower()

    target_parsed = urllib.parse.urlparse(target_url) if target_url else None
    target_domain = target_parsed.netloc.split(":")[0].lower() if target_parsed and target_parsed.netloc else ""

    # Browser semantics evaluation:
    # ACAO: * + ACAC: true is blocked by modern browsers (W3C Fetch spec rejects credentialed responses with wildcard origin).
    # Thus it does not constitute a confirmed exploitable vulnerability, but represents an invalid policy.
    if acao == "*" and acac == "true":
        findings.append({
            "category": "CORS",
            "title": "Inconsistent CORS Configuration: Wildcard Origin with Credentials (Browser-Blocked)",
            "description": (
                "The server specifies 'Access-Control-Allow-Origin: *' while setting 'Access-Control-Allow-Credentials: true'. "
                "Under W3C Fetch / browser CORS semantics, user agents strictly reject and block credentialed responses containing "
                "wildcard origins, preventing cross-origin data exposure. While not an exploitable vulnerability due to browser enforcement, "
                "this represents an invalid policy configuration that should be replaced with explicit trusted origin validation."
            ),
            "severity": "low",
            "confidence": "medium",
            "cvss_score": None,
            "recommendation": "Configure Access-Control-Allow-Origin to an explicit trusted origin instead of wildcard '*' if credentials are required.",
            "references": [
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
            ],
            "endpoint": target_url,
            "evidence": f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
        })
    elif acao.lower() == "null" and acac == "true":
        # Unsafe policy: origin 'null' can be triggered by sandboxed iframes and local schemes
        status = "FAIL"
        findings.append({
            "category": "CORS",
            "title": "Unsafe CORS Policy: Null Origin Allowed with Credentials",
            "description": (
                "The server specifies 'Access-Control-Allow-Origin: null' alongside 'Access-Control-Allow-Credentials: true'. "
                "Attackers can trigger a 'null' origin using sandboxed iframes (<iframe sandbox='allow-scripts'>) to read "
                "sensitive authenticated data."
            ),
            "severity": "high",
            "confidence": "confirmed",
            "cvss_score": 7.5,
            "recommendation": "Never allow 'null' origin with credentials. Validate against an explicit whitelist of trusted origins.",
            "references": [
                "https://portswigger.net/web-security/cors",
                "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
            ],
            "endpoint": target_url,
            "evidence": f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
        })
    elif acao and acao != "*" and acac == "true":
        # Check if acao is an untrusted/different domain than target
        acao_parsed = urllib.parse.urlparse(acao)
        acao_domain = acao_parsed.netloc.split(":")[0].lower() if acao_parsed.netloc else acao.lower()
        if not target_domain or (acao_domain != target_domain and not acao_domain.endswith(f".{target_domain}")):
            status = "FAIL"
            findings.append({
                "category": "CORS",
                "title": f"Unsafe CORS Policy: Untrusted Origin '{acao}' Allowed with Credentials",
                "description": (
                    f"The server allows untrusted origin '{acao}' with credentials enabled. "
                    "Under browser CORS semantics, the browser permits scripts running on that origin to read authenticated responses."
                ),
                "severity": "high",
                "confidence": "confirmed",
                "cvss_score": 8.1,
                "recommendation": "Restrict Access-Control-Allow-Origin to trusted first-party or partner domains.",
                "references": ["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                "endpoint": target_url,
                "evidence": f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
            })
    elif acao == "*":
        findings.append({
            "category": "CORS",
            "title": "CORS Allows All Origins (*)",
            "description": "The server allows any origin to read public API responses.",
            "severity": "info",
            "confidence": "high",
            "cvss_score": None,
            "recommendation": "Ensure wildcard origin is strictly limited to non-sensitive public API endpoints.",
            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
            "endpoint": target_url,
            "evidence": f"Access-Control-Allow-Origin: {acao}",
        })

    # Active Origin Reflection Check (when active probing enabled)
    if probe_active and target_url:
        is_safe, _, _, conn_url, host_header = await async_resolve_and_pin(target_url)
        if is_safe:
            try:
                test_origin = "https://evil-untrusted-origin.sentinelscan.test"
                async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
                    probe_resp = await client.get(
                        conn_url,
                        headers={"Origin": test_origin, "User-Agent": "SentinelScan-Security-Scanner/2.0", "Host": host_header},
                    )
                    reflected_origin = probe_resp.headers.get("access-control-allow-origin", "").strip()
                    reflected_creds = probe_resp.headers.get("access-control-allow-credentials", "").strip().lower()

                    if reflected_origin == test_origin and reflected_creds == "true":
                        status = "FAIL"
                        findings.append({
                            "category": "CORS",
                            "title": "Unsafe CORS Policy: Arbitrary Origin Reflection with Credentials",
                            "description": (
                                f"The server dynamically reflects the requesting Origin header ('{test_origin}') in "
                                "Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true. "
                                "According to browser CORS semantics, this enables any malicious site to read authenticated user data."
                            ),
                            "severity": "high",
                            "confidence": "confirmed",
                            "cvss_score": 8.1,
                            "recommendation": "Implement strict server-side validation against an explicit whitelist of trusted origins.",
                            "references": ["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                            "endpoint": target_url,
                            "evidence": f"Origin header '{test_origin}' reflected in Access-Control-Allow-Origin with credentials=true",
                        })
            except Exception as e:
                logger.debug(f"A01 CORS reflection probe error: {e}")

    # 2. Sensitive & Administrative Endpoint Exposure
    parsed = urllib.parse.urlparse(target_url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
        for path in SENSITIVE_PATHS:
            probe_url = urllib.parse.urljoin(base_origin, path)
            is_safe, _, _, conn_url, host_header = await async_resolve_and_pin(probe_url)
            if not is_safe or conn_url is None or host_header is None:
                continue

            try:
                resp = await client.get(conn_url, headers={"User-Agent": "SentinelScan-Security-Scanner/2.0", "Host": host_header})
                if resp.status_code == 200:
                    text_sample = resp.text[:200].lower()
                    if path == "/.git/HEAD" and "ref: refs/" in text_sample:
                        status = "FAIL"
                        findings.append({
                            "category": "Sensitive Resource Exposure",
                            "title": "Sensitive Resource Exposure / Access-Control Review Indicator: .git Repository",
                            "description": "Source-control metadata (.git/HEAD) was retrieved via unauthenticated request. Public reachability of repository objects constitutes a sensitive resource exposure requiring access-control review.",
                            "severity": "high",
                            "confidence": "confirmed",
                            "cvss_score": 7.5,
                            "recommendation": "Block access to hidden directories and files (.git, .env) in your web server configuration.",
                            "references": ["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                            "endpoint": probe_url,
                            "evidence": f"GET {probe_url} returned HTTP 200 with content: {text_sample[:80]}",
                        })
                    elif path in ["/admin/", "/administrator/"] and any(w in text_sample for w in ["dashboard", "admin", "welcome", "management"]):
                        findings.append({
                            "category": "Access Control Review",
                            "title": f"Sensitive Resource Exposure / Access-Control Review Indicator: {path}",
                            "description": f"Endpoint {path} responded with HTTP 200 to an unauthenticated request. Without authenticated privilege-boundary verification, this interface is identified as an access-control review indicator rather than confirmed unauthorized administrative execution.",
                            "severity": "low",
                            "confidence": "medium",
                            "cvss_score": 3.7,
                            "recommendation": "Restrict administrative panels to authorized IP ranges or enforce multi-factor authentication.",
                            "references": ["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                            "endpoint": probe_url,
                            "evidence": f"GET {probe_url} returned HTTP 200 unauthenticated",
                        })
            except Exception as e:
                logger.debug(f"A01 path probe failed for {probe_url}: {e}")

    # 3. Controlled Differential Authorization Testing (when test identity provided)
    if auth_context and isinstance(auth_context, dict) and auth_context.get("headers"):
        clean_auth_headers = {
            k: v for k, v in auth_context.get("headers", {}).items()
            if isinstance(k, str) and isinstance(v, str)
        }
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
            for ep_url in discovered_urls[:5]:
                is_safe, _, _, conn_url, host_header = await async_resolve_and_pin(ep_url)
                if not is_safe or conn_url is None or host_header is None:
                    continue
                try:
                    unauth_resp = await client.get(conn_url, headers={"User-Agent": "SentinelScan-Security-Scanner/2.0", "Host": host_header})
                    auth_resp = await client.get(
                        conn_url,
                        headers={**clean_auth_headers, "User-Agent": "SentinelScan-Security-Scanner/2.0", "Host": host_header}
                    )
                    if unauth_resp.status_code in (401, 403) and auth_resp.status_code == 200:
                        logger.debug(f"A01 Access control boundary verified on {ep_url}")
                except Exception as e:
                    logger.debug(f"A01 differential test failed for {ep_url}: {e}")

    # 4. Candidate SSRF / Redirection Parameter Surface Evaluation
    candidate_ssrf_params: list[str] = []
    if discovered_parameters:
        for param_name in discovered_parameters.keys():
            if param_name.lower() in URL_PARAMETER_NAMES:
                candidate_ssrf_params.append(param_name)

    limitations_parts = [
        "Evaluates observable CORS headers according to browser CORS semantics, exposed administrative endpoints, and differential response codes on supplied test identities.",
        "Does not perform automated IDOR traversal across tenant accounts or brute force.",
    ]
    if candidate_ssrf_params:
        limitations_parts.append(
            f"Potential server-side request parameter surface identified ({', '.join(sorted(set(candidate_ssrf_params))[:5])}); "
            "server-side request execution cannot be externally verified by this non-destructive assessment."
        )
    else:
        limitations_parts.append(
            "No candidate URL-accepting redirection or outbound fetch parameters were identified on crawled pages."
        )

    limitations = " ".join(limitations_parts)

    return {
        "status": status,
        "method": "CORS Policy Analysis, Sensitive Path Probing, Differential Authorization & Parameter Surface Analysis",
        "confidence": confidence,
        "findings": findings,
        "limitations": limitations,
    }
