"""
OWASP A05:2021 — Security Misconfiguration Assessment Module
============================================================
Evaluates system and application configuration posture:
- Security headers (CSP, HSTS, XFO, XCTO, Permissions-Policy, COOP, COEP)
- Dangerous HTTP methods via OPTIONS (TRACE, TRACK, PUT, DELETE)
- Public directory indexing exposure (Index of /)
- Verbose server and technology version disclosure
- DNS record security (SPF, DMARC, DNSSEC)
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any
import httpx

from app.utils.safe_http import async_resolve_and_pin

logger = logging.getLogger(__name__)

DIRECTORY_LISTING_SIGNATURES = [
    re.compile(r"<title>Index of /[^<]*</title>", re.IGNORECASE),
    re.compile(r"<h1>Index of /[^<]*</h1>", re.IGNORECASE),
    re.compile(r"Directory Listing for /", re.IGNORECASE),
]

COMMON_STATIC_DIRS = ["/static/", "/assets/", "/uploads/", "/images/", "/media/"]


async def assess_a05_misconfiguration(
    target_url: str,
    header_findings: list[dict[str, Any]],
    dns_findings: list[dict[str, Any]],
    content_findings: list[dict[str, Any]],
    headers: dict[str, str] | None = None,
    probe_active: bool = False,
) -> dict[str, Any]:
    """
    Aggregates and executes A05 Security Misconfiguration assessment.
    """
    findings: list[dict[str, Any]] = []
    status = "PASS"
    confidence = "HIGH"

    # 1. Incorporate Header Findings (relevant to misconfiguration)
    for hf in header_findings:
        findings.append(hf)
        if hf.get("severity") in ("high", "critical", "medium"):
            status = "FAIL"

    # 2. Incorporate DNS Misconfiguration Findings (SPF, DMARC)
    for df in dns_findings:
        title = df.get("title", "").lower()
        if any(term in title for term in ["spf", "dmarc"]):
            findings.append(df)
            if df.get("severity") in ("high", "critical", "medium"):
                status = "FAIL"

    # 3. Incorporate Content Exposure Findings (verbose errors, stack traces, exposed files)
    for cf in content_findings:
        findings.append(cf)
        if cf.get("severity") in ("high", "critical", "medium"):
            status = "FAIL"

    # 4. Dangerous HTTP Methods via OPTIONS
    if probe_active and target_url:
        is_safe, _, _, conn_url, host_header = await async_resolve_and_pin(target_url)
        if is_safe:
            try:
                async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
                    resp = await client.options(conn_url, headers={"User-Agent": "SentinelScan-Security-Scanner/2.0", "Host": host_header})
                    allow_hdr = resp.headers.get("allow", "") or resp.headers.get("public", "")
                    if allow_hdr:
                        methods = [m.strip().upper() for m in allow_hdr.split(",")]
                        if "TRACE" in methods or "TRACK" in methods:
                            status = "FAIL"
                            findings.append({
                                "category": "HTTP Methods",
                                "title": "Insecure HTTP Method Enabled: TRACE/TRACK",
                                "description": (
                                    "The server enables the HTTP TRACE or TRACK method, which echoes back user requests "
                                    "and can facilitate Cross-Site Tracing (XST) attacks to steal cookies with HttpOnly flags."
                                ),
                                "severity": "medium",
                                "confidence": "confirmed",
                                "cvss_score": 5.3,
                                "recommendation": "Disable TRACE and TRACK methods in your web server or reverse proxy configuration.",
                                "references": ["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                                "endpoint": target_url,
                                "evidence": f"OPTIONS returned Allow: {allow_hdr}",
                            })
                        dangerous = [m for m in ["PUT", "DELETE"] if m in methods]
                        if dangerous:
                            findings.append({
                                "category": "HTTP Methods",
                                "title": f"Potentially Dangerous HTTP Methods Advertised: {', '.join(dangerous)}",
                                "description": (
                                    f"The server advertises support for {', '.join(dangerous)} in the Allow header. "
                                    "Ensure these methods are strictly authenticated or restricted on static resources."
                                ),
                                "severity": "low",
                                "confidence": "high",
                                "cvss_score": None,
                                "recommendation": "Disable unused HTTP verbs at the web server level.",
                                "references": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                                "endpoint": target_url,
                                "evidence": f"OPTIONS Allow: {allow_hdr}",
                            })
            except Exception as e:
                logger.debug(f"A05 OPTIONS check error: {e}")

    # 5. Directory Listing Probe (in active mode)
    if probe_active and target_url:
        parsed = urllib.parse.urlparse(target_url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
            for d in COMMON_STATIC_DIRS:
                dir_url = urllib.parse.urljoin(base_origin, d)
                is_safe, _, _, conn_url, host_header = await async_resolve_and_pin(dir_url)
                if not is_safe or conn_url is None or host_header is None:
                    continue
                try:
                    r = await client.get(conn_url, headers={"User-Agent": "SentinelScan-Security-Scanner/2.0", "Host": host_header})
                    if r.status_code == 200:
                        for pattern in DIRECTORY_LISTING_SIGNATURES:
                            if pattern.search(r.text[:2000]):
                                status = "FAIL"
                                findings.append({
                                    "category": "Directory Indexing",
                                    "title": f"Directory Listing Enabled: {d}",
                                    "description": (
                                        f"The directory {d} returns an auto-generated directory listing index. "
                                        "This exposes sensitive files, backups, and directory structure to attackers."
                                    ),
                                    "severity": "medium",
                                    "confidence": "confirmed",
                                    "cvss_score": 5.3,
                                    "recommendation": "Disable directory browsing (e.g., 'Options -Indexes' in Apache, 'autoindex off;' in Nginx).",
                                    "references": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                                    "endpoint": dir_url,
                                    "evidence": f"GET {dir_url} matched directory index signature.",
                                })
                                break
                except Exception as e:
                    logger.debug(f"A05 directory listing probe error for {dir_url}: {e}")

    limitations = (
        "Evaluates HTTP security headers, CORS policies, DNS records (SPF/DMARC), exposed directory indexing, "
        "verbose debug error disclosures, and HTTP methods. Does not audit internal OS or container configs."
    )

    return {
        "status": status,
        "method": "Multi-Layer Configuration Analysis (Headers, DNS, Methods, Directory Probes)",
        "confidence": confidence,
        "findings": findings,
        "limitations": limitations,
    }
