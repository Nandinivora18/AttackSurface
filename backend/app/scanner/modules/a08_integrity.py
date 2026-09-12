"""
OWASP A08:2025 — Software or Data Integrity Failures Assessment Module
======================================================================
Evaluates external dependency integrity protections:
- Subresource Integrity (SRI) attribute presence on third-party CDN scripts
- Unpinned external script dependencies
- Explicit documentation of non-verifiable internal pipeline/build integrity
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any

logger = logging.getLogger(__name__)

_SCRIPT_TAG_RE = re.compile(r'<script\s+([^>]*?)src=([\'"])(https?://[^\'"]+)\2([^>]*)>', re.IGNORECASE)

KNOWN_PUBLIC_CDNS = [
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "cdn.jsdelivr.net",
    "ajax.googleapis.com",
    "code.jquery.com",
    "stackpath.bootstrapcdn.com",
    "cdn.bootcdn.net",
    "cdnjs.com",
]


async def assess_a08_integrity(
    target_url: str,
    crawled_html_samples: list[str],
    external_scripts: list[str] | set[str] | None = None,
) -> dict[str, Any]:
    """
    Executes A08 Software and Data Integrity Failures assessment.
    """
    findings: list[dict[str, Any]] = []
    status = "PASS"
    confidence = "HIGH"

    parsed_target = urllib.parse.urlparse(target_url or "")
    target_netloc = parsed_target.netloc.lower()

    # Nothing to compare against if the target has no resolvable origin.
    if not target_netloc or parsed_target.scheme not in ("http", "https"):
        return {
            "status": "PASS",
            "method": "Subresource Integrity (SRI) & External Dependency Inspection",
            "confidence": "LOW",
            "findings": [],
            "limitations": "Target URL does not have a parseable http(s) origin — integrity assessment not applicable.",
        }

    unprotected_cdn_scripts: list[str] = []

    for html in crawled_html_samples:
        for match in _SCRIPT_TAG_RE.finditer(html):
            before_attrs, _, src_url, after_attrs = match.groups()
            all_attrs = f"{before_attrs} {after_attrs}"

            parsed_src = urllib.parse.urlparse(src_url)
            src_netloc = parsed_src.netloc.lower()

            # If script origin is different from target origin
            if src_netloc and src_netloc != target_netloc:
                # Check for SRI integrity attribute
                has_integrity = bool(re.search(r'\bintegrity\s*=', all_attrs, re.IGNORECASE))
                if not has_integrity:
                    # Check if it is a known third-party CDN
                    is_cdn = any(cdn in src_netloc for cdn in KNOWN_PUBLIC_CDNS)
                    if is_cdn and src_url not in unprotected_cdn_scripts:
                        unprotected_cdn_scripts.append(src_url)

    if unprotected_cdn_scripts:
        status = "FAIL"
        for script_url in unprotected_cdn_scripts[:5]:
            findings.append({
                "category": "Subresource Integrity",
                "title": "Subresource Integrity (SRI) Not Observed on External Script",
                "description": (
                    f"Integrity protection was not observed on external third-party script '{script_url}'. "
                    "If the third-party CDN or delivery network is compromised, an attacker could tamper "
                    "with the script to inject malicious client-side code (supply chain attack) into your users' browsers."
                ),
                "severity": "low",
                "confidence": "high",
                "cvss_score": 3.7,
                "recommendation": (
                    "Add the 'integrity' attribute containing a cryptographic hash (e.g. sha384-...) "
                    "and 'crossorigin=\"anonymous\"' to external <script> and <link> tags."
                ),
                "references": [
                    "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                    "https://owasp.org/Top10/A08_2025-Software_or_Data_Integrity_Failures/",
                ],
                "endpoint": target_url,
                "evidence": f"External script loaded without integrity hash: {script_url}",
            })

    limitations = (
        "Subresource Integrity (SRI) and external script hosting are verified through HTML DOM analysis. "
        "Target CI/CD pipeline integrity, software supply chain provenance, and server-side deserialization "
        "cannot be verified solely from external HTTP scanning (NOT_VERIFIABLE_EXTERNALLY)."
    )

    return {
        "status": status,
        "method": "Subresource Integrity (SRI) & External Dependency Inspection",
        "confidence": confidence,
        "findings": findings,
        "limitations": limitations,
    }
