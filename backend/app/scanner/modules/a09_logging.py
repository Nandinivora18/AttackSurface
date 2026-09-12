"""
OWASP A09:2025 — Security Logging and Alerting Failures Assessment Module
========================================================================
Evaluates external indicators of security logging and monitoring:
- Exposed public log files and debug actuator endpoints
- Unhandled verbose error exposures (indicating missing custom error handlers/logging boundaries)
- Presence of distributed request tracing headers (X-Request-ID, Traceparent)
- Explicit acknowledgement that internal SIEM and alert pipelines are NOT_VERIFIABLE_EXTERNALLY
"""
from __future__ import annotations

import logging
import urllib.parse
from typing import Any
import httpx

from app.utils.safe_http import async_resolve_and_pin

logger = logging.getLogger(__name__)

# Common publicly exposed log and telemetry paths to probe safely via GET
LOG_PATHS = [
    "/actuator/logfile",
    "/debug/vars",
    "/error.log",
    "/debug.log",
    "/access.log",
    "/var/log/",
]

CORRELATION_HEADERS = [
    "x-request-id",
    "x-correlation-id",
    "traceparent",
    "x-trace-id",
    "x-amzn-trace-id",
    "cf-ray",
]


async def assess_a09_logging(
    target_url: str,
    response_headers: dict[str, str],
    content_findings: list[dict[str, Any]] | None = None,
    probe_active: bool = False,
) -> dict[str, Any]:
    """
    Executes A09 Security Logging and Monitoring Failures assessment.
    """
    findings: list[dict[str, Any]] = []
    status = "NOT_VERIFIABLE"
    confidence = "LOW"

    content_findings = content_findings or []

    # 1. Check for Exposed Verbose Error / Stack Trace Findings
    # If the application leaked raw stack traces or internal errors to client, logging handling is deficient
    for cf in content_findings:
        title = cf.get("title", "").lower()
        if "stack trace" in title or "debug" in title or "exception" in title or "error disclosure" in title:
            status = "FAIL"
            findings.append({
                "category": "Logging & Error Handling",
                "title": f"Unhandled Error Exposure Indicates Deficient Error Boundary: {cf.get('title')}",
                "description": (
                    "The application exposes internal runtime exceptions directly to clients instead of capturing "
                    "them in centralized logging systems and returning generic error identifiers."
                ),
                "severity": "medium",
                "confidence": "high",
                "cvss_score": 5.3,
                "recommendation": (
                    "Capture unhandled exceptions centrally, emit structured log events with correlation IDs, "
                    "and return opaque error references to end users."
                ),
                "references": ["https://owasp.org/Top10/A09_2025-Security_Logging_and_Alerting_Failures/"],
                "endpoint": cf.get("endpoint", target_url),
                "evidence": cf.get("evidence", ""),
            })

    # 2. Check Tracing & Correlation Headers
    has_correlation = any(h.lower() in response_headers for h in CORRELATION_HEADERS)
    if not has_correlation:
        # Note: missing correlation header is an observation, not a confirmed vulnerability
        findings.append({
            "category": "Telemetry & Observability",
            "title": "Correlation header not externally observed",
            "description": (
                "The server response did not include standard distributed tracing headers "
                "(e.g. X-Request-ID, Traceparent, or X-Correlation-ID). While not directly exploitable, "
                "correlation headers significantly improve auditability, incident detection, and forensic response."
            ),
            "severity": "info",
            "confidence": "high",
            "cvss_score": None,
            "recommendation": "Configure reverse proxies or gateways to inject and propagate unique X-Request-ID headers across services.",
            "references": ["https://owasp.org/Top10/A09_2025-Security_Logging_and_Alerting_Failures/"],
            "endpoint": target_url,
            "evidence": "Headers inspected: missing X-Request-ID, Traceparent",
        })

    # 3. Probe for Exposed Log Endpoints (in active mode)
    if probe_active and target_url:
        parsed = urllib.parse.urlparse(target_url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
            for path in LOG_PATHS:
                probe_url = urllib.parse.urljoin(base_origin, path)
                is_safe, _, _, conn_url, host_header = await async_resolve_and_pin(probe_url)
                if not is_safe or conn_url is None or host_header is None:
                    continue

                try:
                    resp = await client.get(conn_url, headers={"User-Agent": "SentinelScan-Security-Scanner/2.0", "Host": host_header})
                    if resp.status_code == 200 and len(resp.text) > 10:
                        sample = resp.text[:200].lower()
                        # Verify it is not a soft 404 HTML page
                        if not sample.startswith("<!doctype") and not sample.startswith("<html"):
                            status = "FAIL"
                            findings.append({
                                "category": "Exposed Telemetry",
                                "title": f"Publicly Accessible Application Log File: {path}",
                                "description": (
                                    f"Application log or metrics endpoint '{path}' responded with HTTP 200 without authentication. "
                                    "Exposed log files frequently contain sensitive session tokens, internal IP addresses, and user data."
                                ),
                                "severity": "high",
                                "confidence": "confirmed",
                                "cvss_score": 7.5,
                                "recommendation": "Restrict log and metrics endpoints from public access immediately.",
                                "references": ["https://owasp.org/Top10/A09_2025-Security_Logging_and_Alerting_Failures/"],
                                "endpoint": probe_url,
                                "evidence": f"GET {probe_url} returned HTTP 200 with non-HTML content (length {len(resp.text)} bytes).",
                            })
                except Exception as e:
                    logger.debug(f"A09 log endpoint probe error for {probe_url}: {e}")

    if status == "FAIL":
        confidence = "HIGH"
        limitations = (
            "Evaluates external telemetry indicators: exposed log files, correlation headers, and unhandled exception leaks. "
            "Internal SIEM alerting rules, retention policies, log tampering protections, and SOC response capabilities "
            "are not verifiable from external HTTP probing alone (NOT_VERIFIABLE_EXTERNALLY)."
        )
    else:
        status = "NOT_VERIFIABLE"
        confidence = "LOW"
        limitations = (
            "Internal security logging, SIEM integration, alerting thresholds, and retention policies cannot be verified "
            "from external HTTP observation alone. Correlation header presence is recorded as an observation only."
        )

    return {
        "status": status,
        "method": "Telemetry Header Analysis, Verbose Error Leak Detection & Log Endpoint Inspection",
        "confidence": confidence,
        "findings": findings,
        "limitations": limitations,
    }
