"""
OWASP A10:2025 — Mishandling of Exceptional Conditions Assessment Module
========================================================================
Evaluates application and framework behavior when processing exceptional, invalid,
or unexpected input conditions:
- Unhandled stack traces and runtime debug error disclosures
- Framework debug diagnostic exposures (Werkzeug, Django DEBUG=True, Rails, Spring Boot Whitelabel, ASP.NET)
- Graceful vs hazardous degradation: generic opaque error responses vs internal implementation leakage
- Controlled error triggering via safe malformed requests (e.g. invalid URI encoding)

Safety Invariants:
- Zero fuzzing or high-volume load testing.
- Safe, single probe requests with non-destructive payloads.
- Preserves honest boundaries: internal exception logging and background worker failures are NOT VERIFIABLE.
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any
import httpx

from app.utils.safe_http import async_resolve_and_pin

logger = logging.getLogger(__name__)

# Signatures for stack traces and framework debug displays
STACK_TRACE_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE), "Python / Django / Flask Stack Trace"),
    (re.compile(r"at (?:[\w\.]+\/)+[\w\.]+\.js:\d+:\d+", re.IGNORECASE), "Node.js Stack Trace"),
    (re.compile(r"java\.lang\.\w+Exception:", re.IGNORECASE), "Java Stack Trace"),
    (re.compile(r"org\.springframework\.web\.", re.IGNORECASE), "Spring Framework Exception"),
    (re.compile(r"Whitelabel Error Page", re.IGNORECASE), "Spring Boot Whitelabel Debug Page"),
    (re.compile(r"Microsoft\.AspNetCore\.", re.IGNORECASE), "ASP.NET Core Developer Exception Page"),
    (re.compile(r"Server Error in '\/' Application", re.IGNORECASE), "ASP.NET Exception Page"),
    (re.compile(r"ActionController::RoutingError", re.IGNORECASE), "Ruby on Rails Debug Page"),
    (re.compile(r"Fatal error: Uncaught \w+Exception:", re.IGNORECASE), "PHP Uncaught Exception"),
]


async def assess_a10_exceptional_conditions(
    target_url: str = "",
    content_findings: list[dict[str, Any]] | None = None,
    crawled_html_samples: list[str] | None = None,
    probe_active: bool = False,
) -> dict[str, Any]:
    """
    Executes A10:2025 Mishandling of Exceptional Conditions assessment.
    """
    findings: list[dict[str, Any]] = []
    status = "PASS"
    confidence = "HIGH"

    content_findings = content_findings or []
    crawled_html_samples = crawled_html_samples or []

    # 1. Inspect Content Findings for Known Error and Debug Disclosures
    for cf in content_findings:
        title = cf.get("title", "").lower()
        if any(term in title for term in ["stack trace", "debug", "error disclosure", "unhandled exception"]):
            status = "FAIL"
            findings.append({
                "category": "Exceptional Conditions",
                "title": f"Mishandled Exception Exposure: {cf.get('title')}",
                "description": (
                    "The application exposes internal implementation details or stack traces when encountering "
                    "an exceptional condition, violating safe degradation and exception handling principles."
                ),
                "severity": cf.get("severity", "medium"),
                "confidence": cf.get("confidence", "high"),
                "cvss_score": cf.get("cvss_score", 5.3),
                "recommendation": "Configure generic custom error pages (404, 500) and ensure debug mode is disabled in production.",
                "references": ["https://owasp.org/Top10/A10_2025-Mishandling_of_Exceptional_Conditions/"],
                "endpoint": cf.get("endpoint", target_url),
                "evidence": cf.get("evidence", ""),
            })

    # 2. Inspect Crawled HTML Samples for Stack Trace Signatures
    for sample in crawled_html_samples:
        for pattern, sig_name in STACK_TRACE_PATTERNS:
            if pattern.search(sample):
                status = "FAIL"
                match_text = pattern.search(sample).group(0)
                findings.append({
                    "category": "Exceptional Conditions",
                    "title": f"Internal Stack Trace Disclosed: {sig_name}",
                    "description": (
                        f"A response body contained signatures of an internal {sig_name}. "
                        "Exposing raw exceptions reveals source code paths, database schema details, "
                        "and internal dependencies to unauthenticated users."
                    ),
                    "severity": "medium",
                    "confidence": "confirmed",
                    "cvss_score": 5.3,
                    "recommendation": "Implement global exception middleware to catch unhandled errors and return sanitized generic error pages.",
                    "references": ["https://owasp.org/Top10/A10_2025-Mishandling_of_Exceptional_Conditions/"],
                    "endpoint": target_url,
                    "evidence": f"Matched pattern '{match_text}' in response body sample.",
                })
                break

    # 3. Controlled Exceptional Condition Probe (when probe_active is True)
    # Safely probe with non-existent path and malformed URI to evaluate error degradation
    if probe_active and target_url:
        parsed = urllib.parse.urlparse(target_url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        err_probes = [
            ("/non_existent_exceptional_path_sentinel_test_404", "404 Error Handling"),
            ("/%00_invalid_encoding_probe", "Malformed URI Handling"),
        ]

        async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
            for probe_path, probe_label in err_probes:
                probe_url = urllib.parse.urljoin(base_origin, probe_path)
                is_safe, _, _, conn_url, host_header = await async_resolve_and_pin(probe_url)
                if not is_safe or conn_url is None or host_header is None:
                    continue

                try:
                    resp = await client.get(conn_url, headers={"User-Agent": "SentinelScan-Security-Scanner/2.0", "Host": host_header})
                    # If status is 500, check if it leaked stack traces
                    if resp.status_code == 500:
                        for pattern, sig_name in STACK_TRACE_PATTERNS:
                            if pattern.search(resp.text):
                                status = "FAIL"
                                findings.append({
                                    "category": "Exceptional Conditions",
                                    "title": f"Unhandled Server Exception on {probe_label}: {sig_name}",
                                    "description": (
                                        f"When tested with an exceptional request ({probe_path}), the server returned HTTP 500 "
                                        f"with a raw {sig_name} instead of a sanitized error handler."
                                    ),
                                    "severity": "medium",
                                    "confidence": "confirmed",
                                    "cvss_score": 5.3,
                                    "recommendation": "Catch exceptions at the web application boundary and log internally rather than returning raw exceptions.",
                                    "references": ["https://owasp.org/Top10/A10_2025-Mishandling_of_Exceptional_Conditions/"],
                                    "endpoint": probe_url,
                                    "evidence": f"GET {probe_url} returned HTTP 500 with {sig_name}",
                                })
                                break
                except Exception as e:
                    logger.debug(f"A10 exceptional probe failed for {probe_url}: {e}")

    limitations = (
        "Evaluates observable error responses, framework debug diagnostic exposures, and stack trace leakage "
        "on triggered exceptional conditions. Internal exception logging, asynchronous thread crashes without HTTP output, "
        "and unmonitored server-side exception telemetry are NOT VERIFIABLE externally."
    )

    return {
        "status": status,
        "method": "Exception Diagnostic & Error Handling Analysis",
        "confidence": confidence,
        "findings": findings,
        "limitations": limitations,
    }
