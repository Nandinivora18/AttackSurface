"""
OWASP A04:2025 — Cryptographic Failures Assessment Module
=========================================================
Evaluates transport cryptography, TLS protocol and cipher suite security,
certificate validity, HSTS enforcement, and mixed-content leakage.
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_HTTP_RESOURCE_RE = re.compile(
    r'<(?:script|link|img|iframe|audio|video)\s+[^>]*?(?:src|href)=([\'"])(http://[^\'"]+)\1',
    re.IGNORECASE
)


async def assess_a04_cryptography(
    target_url: str,
    ssl_issues: list[dict[str, Any]],
    headers: dict[str, str],
    crawled_html_samples: list[str] | None = None,
) -> dict[str, Any]:
    """
    Executes A04:2025 Cryptographic Failures assessment.
    """
    findings: list[dict[str, Any]] = []
    status = "PASS"
    confidence = "HIGH"

    # Plain HTTP target without TLS
    if target_url.startswith("http://") and not ssl_issues:
        return {
            "status": "NOT_APPLICABLE",
            "method": "TLS Handshake Inspection",
            "confidence": "HIGH",
            "findings": [],
            "limitations": "Target endpoint uses plain HTTP without TLS. Cryptographic transport controls not applicable.",
        }

    # 1. Evaluate SSL/TLS analysis issues
    for issue in ssl_issues:
        status = "FAIL"
        findings.append({
            "category": "SSL/TLS",
            "title": issue.get("message", "TLS Configuration Issue"),
            "description": "Cryptographic transport failure detected during TLS handshake inspection.",
            "severity": issue.get("severity", "medium"),
            "confidence": "high",
            "cvss_score": 5.9 if issue.get("severity") == "high" else None,
            "recommendation": "Enforce modern TLS (TLS 1.2+), strong cipher suites, and renew certificates before expiry.",
            "references": ["https://ssl-config.mozilla.org/"],
            "endpoint": target_url,
            "evidence": f"TLS issue: {issue.get('message')}",
        })

    # 2. Check HSTS Header
    hsts = headers.get("strict-transport-security", "")
    if not (hsts and str(hsts).strip()) and target_url.startswith("https://"):
        status = "FAIL"
        findings.append({
            "category": "Transport Security",
            "title": "Missing HTTP Strict Transport Security (HSTS)",
            "description": (
                "The Strict-Transport-Security header is missing. Without HSTS, attackers can perform "
                "adversary-in-the-middle downgrade attacks to intercept plain HTTP traffic."
            ),
            "severity": "high",
            "confidence": "confirmed",
            "cvss_score": 6.5,
            "recommendation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "references": ["https://owasp.org/Top10/A04_2025-Cryptographic_Failures/"],
            "endpoint": target_url,
            "evidence": "Strict-Transport-Security: <absent>" if not hsts else "Strict-Transport-Security: <empty>",
        })

    # 3. Mixed Content Analysis on Crawled Pages
    if crawled_html_samples and target_url.startswith("https://"):
        mixed_resources = set()
        for html in crawled_html_samples[:5]:
            for _, res_url in _HTTP_RESOURCE_RE.findall(html):
                mixed_resources.add(res_url)

        if mixed_resources:
            status = "FAIL"
            sample_list = list(mixed_resources)[:3]
            findings.append({
                "category": "Cryptographic Failures",
                "title": f"Mixed Content Detected ({len(mixed_resources)} Insecure HTTP Resource{'s' if len(mixed_resources) != 1 else ''})",
                "description": (
                    "The HTTPS website embeds active or passive resources loaded over unencrypted HTTP. "
                    "This compromises transport confidentiality and integrity."
                ),
                "severity": "medium",
                "confidence": "confirmed",
                "cvss_score": 5.4,
                "recommendation": "Update all resource links (scripts, styles, images) to use HTTPS or protocol-relative paths.",
                "references": ["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
                "endpoint": target_url,
                "evidence": f"Insecure HTTP assets: {', '.join(sample_list)}",
            })

    limitations = (
        "Evaluates external TLS configuration, certificates, HSTS headers, and embedded mixed-content resources "
        "to provide direct externally observable evidence of the evaluated transport-security configuration. "
        "Does not inspect internal cryptographic implementations (data at rest, database column encryption, key management)."
    )

    return {
        "status": status,
        "method": "TLS Handshake Inspection, Certificate Revocation Check & Mixed-Content Parsing",
        "confidence": confidence,
        "findings": findings,
        "limitations": limitations,
    }
