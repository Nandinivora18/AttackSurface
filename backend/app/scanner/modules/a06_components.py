"""
OWASP A06:2021 — Vulnerable and Outdated Components Assessment Module
=====================================================================
Integrates Component Intelligence Engine analysis with NIST NVD CVE correlation.
Produces distinct, non-conflated finding records:
- Known CVEs with CVSS scores and explicit vendor backport limitations.
- End-of-Life (EOL) software lifecycle notifications.
- Security support expiration alerts.
- Available stable version upgrade notices.
- Undisclosed version observations.
"""
from __future__ import annotations

import logging
from typing import Any

from app.scanner.component_engine import (
    STATE_END_OF_LIFE,
    STATE_SECURITY_SUPPORT_ENDED,
    STATE_UPDATE_AVAILABLE,
    STATE_VERSION_UNKNOWN,
    STATE_SUPPORTED,
    STATE_LIFECYCLE_UNKNOWN,
)

logger = logging.getLogger(__name__)


async def assess_a06_components(
    component_inventory: list[dict[str, Any]],
    cve_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Executes A06 Vulnerable and Outdated Components assessment.
    """
    findings: list[dict[str, Any]] = []
    status = "PASS"
    confidence = "HIGH"

    cve_findings = cve_findings or []

    # 1. Incorporate Known CVE Findings
    for cve in cve_findings:
        status = "FAIL"
        # Ensure backport note is prominent
        desc = cve.get("description", "")
        if "backport" not in desc.lower():
            desc = (
                f"{desc}\n\nNote on Enterprise Linux & Container Backports: Linux distributions (RHEL, Debian, Ubuntu) "
                "often backport security fixes into older package versions without incrementing upstream version numbers. "
                "Verify if distribution package changelogs indicate this CVE has been backported."
            )
        findings.append({
            "category": "Vulnerable Components",
            "title": cve.get("title", f"Vulnerability in {cve.get('technology', 'Component')}"),
            "description": desc,
            "severity": cve.get("severity", "high"),
            "confidence": cve.get("confidence", "high"),
            "cvss_score": cve.get("cvss_score"),
            "recommendation": cve.get("recommendation", "Upgrade the affected component to the latest patched release."),
            "references": cve.get("references", ["https://nvd.nist.gov/"]),
            "endpoint": cve.get("endpoint", "Technology Stack"),
            "evidence": cve.get("evidence", ""),
        })

    # 2. Evaluate Component Lifecycle Statuses
    for comp in component_inventory:
        tech = comp.get("technology", "Component")
        ver = comp.get("normalized_version") or comp.get("raw_version") or "Unknown"
        l_status = comp.get("lifecycle_status", STATE_LIFECYCLE_UNKNOWN)
        eol_date = comp.get("eol_date")
        latest = comp.get("latest_version")
        evidence = comp.get("evidence", f"Detected {tech} {ver}")
        v_conf = comp.get("version_confidence", "high").lower()

        if l_status == STATE_END_OF_LIFE:
            status = "FAIL"
            eol_str = f" on {eol_date}" if eol_date else ""
            findings.append({
                "category": "Outdated Components",
                "title": f"End-of-Life Component Detected: {tech} {ver}",
                "description": (
                    f"The detected version of {tech} ({ver}) reached official End-of-Life (EOL){eol_str}. "
                    "The vendor no longer provides security patches or bug fixes for this release branch. "
                    "Operating unsupported software creates severe exposure to unpatched vulnerabilities."
                ),
                "severity": "high",
                "confidence": v_conf,
                "cvss_score": 7.5,
                "recommendation": (
                    f"Upgrade {tech} to an actively maintained release branch"
                    + (f" (latest release: {latest})" if latest else "")
                    + "."
                ),
                "references": [
                    f"https://endoflife.date/{tech.lower()}",
                    "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                ],
                "endpoint": "Component Stack",
                "evidence": f"{evidence}\nLifecycle status: END_OF_LIFE (EOL: {eol_date or 'discontinued'})",
            })

        elif l_status == STATE_SECURITY_SUPPORT_ENDED:
            if status != "FAIL":
                status = "FAIL"
            findings.append({
                "category": "Outdated Components",
                "title": f"Security Support Expired: {tech} {ver}",
                "description": (
                    f"Active general support has concluded for {tech} {ver}. "
                    "The component may receive only critical security fixes or is entering phase-out."
                ),
                "severity": "medium",
                "confidence": v_conf,
                "cvss_score": 5.3,
                "recommendation": f"Plan migration of {tech} to a currently supported LTS or stable release.",
                "references": [
                    f"https://endoflife.date/{tech.lower()}",
                    "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                ],
                "endpoint": "Component Stack",
                "evidence": f"{evidence}\nLifecycle status: SECURITY_SUPPORT_ENDED",
            })

        elif l_status == STATE_UPDATE_AVAILABLE:
            findings.append({
                "category": "Outdated Components",
                "title": f"Component Update Available: {tech} {ver} -> {latest}",
                "description": (
                    f"A newer stable release ({latest}) is available for {tech} (currently {ver}). "
                    "While the current release is supported, updating ensures access to the latest security fixes."
                ),
                "severity": "low",
                "confidence": v_conf,
                "cvss_score": None,
                "recommendation": f"Review release notes and upgrade {tech} to version {latest}.",
                "references": [
                    "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
                ],
                "endpoint": "Component Stack",
                "evidence": f"{evidence}\nCurrent: {ver}, Latest: {latest}",
            })

        elif l_status == STATE_VERSION_UNKNOWN:
            findings.append({
                "category": "Technology Disclosure",
                "title": f"Component Detected (Version Undisclosed): {tech}",
                "description": (
                    f"{tech} was detected in use via response headers or page indicators, but its specific "
                    "version was not disclosed. Good security practice: omitting version numbers impedes automated reconnaissance."
                ),
                "severity": "info",
                "confidence": "high",
                "cvss_score": None,
                "recommendation": "Maintain internal dependency tracking (SBOM) to track updates for undisclosed components.",
                "references": ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
                "endpoint": "Technology Stack",
                "evidence": evidence,
            })

    limitations = (
        "Component detection uses observable HTTP response headers, script paths, and meta tags. "
        "Vendor-backported patches (e.g. Debian/Ubuntu/RHEL security updates) cannot be confirmed "
        "without authenticated internal package manager inspection."
    )

    return {
        "status": status,
        "method": "Multi-Signal Component Fingerprinting & NIST NVD CVE / Lifecycle Correlation",
        "confidence": confidence,
        "findings": findings,
        "limitations": limitations,
    }
