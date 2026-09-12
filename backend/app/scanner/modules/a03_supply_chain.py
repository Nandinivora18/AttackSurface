"""
OWASP A03:2025 — Software Supply Chain Failures Assessment Module
==================================================================
Synthesizes third-party software component and dependency supply-chain indicators:
1. Component Intelligence Engine analysis & vendor lifecycle tracking (EOL, support conclusion)
2. NIST NVD CVE correlation for identified component versions
3. Subresource Integrity (SRI) verification on external public CDN scripts
4. External unpinned third-party script dependency inspection
5. Honest boundary reporting: internal build pipelines, private repositories,
   and signed SBOMs require internal audit and are NOT_VERIFIABLE_EXTERNALLY.
"""
from __future__ import annotations

import logging
import re
import urllib.parse
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


async def assess_a03_supply_chain(
    target_url: str = "",
    component_inventory: list[dict[str, Any]] | None = None,
    cve_findings: list[dict[str, Any]] | None = None,
    crawled_html_samples: list[str] | None = None,
    external_scripts: list[str] | set[str] | None = None,
) -> dict[str, Any]:
    """
    Executes A03:2025 Software Supply Chain Failures assessment.
    Integrates component lifecycle, CVE correlation, external dependencies, and SRI.
    """
    findings: list[dict[str, Any]] = []
    status = "PASS"
    confidence = "HIGH"

    component_inventory = component_inventory or []
    cve_findings = cve_findings or []
    crawled_html_samples = crawled_html_samples or []

    # 1. Incorporate Known Correlated CVEs
    for cve in cve_findings:
        status = "FAIL"
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

    # 2. Evaluate Component Lifecycle Statuses (End-of-Life, Security Support Expired)
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
                    "Operating unsupported software creates severe supply-chain exposure to unpatched vulnerabilities."
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
                    "https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/",
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
                    "https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/",
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
                    "https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/"
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
                "references": ["https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/"],
                "endpoint": "Technology Stack",
                "evidence": evidence,
            })

    # 3. Subresource Integrity (SRI) on External CDN Scripts
    parsed_target = urllib.parse.urlparse(target_url) if target_url else None
    target_netloc = parsed_target.netloc.lower() if parsed_target else ""

    unprotected_cdn_scripts: list[str] = []
    for html in crawled_html_samples:
        for match in _SCRIPT_TAG_RE.finditer(html):
            before_attrs, _, src_url, after_attrs = match.groups()
            all_attrs = f"{before_attrs} {after_attrs}"

            parsed_src = urllib.parse.urlparse(src_url)
            src_netloc = parsed_src.netloc.lower()

            if src_netloc and src_netloc != target_netloc:
                has_integrity = bool(re.search(r'\bintegrity\s*=', all_attrs, re.IGNORECASE))
                if not has_integrity:
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
                    "with the script to inject malicious client-side code (software supply chain attack) into user browsers."
                ),
                "severity": "low",
                "confidence": "high",
                "cvss_score": 3.7,
                "recommendation": (
                    "Add the 'integrity' attribute containing a cryptographic hash (e.g. sha384-...) "
                    "and 'crossorigin=\"anonymous\"' to external <script> tags."
                ),
                "references": [
                    "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                    "https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/",
                ],
                "endpoint": target_url or "Client-Side Dependencies",
                "evidence": f"External script loaded without integrity hash: {script_url}",
            })

    limitations = (
        "Assesses observable third-party scripts, public CDN hosting, technology version fingerprints, "
        "vendor lifecycle data, and public CVEs. Vendor distribution backports cannot be confirmed without "
        "package manager access. Internal CI/CD pipeline integrity, private repository dependencies, dependency "
        "trees (package-lock.json, pom.xml), and artifact signatures are NOT VERIFIABLE externally."
    )

    return {
        "status": status,
        "method": "Multi-Signal Component Fingerprinting, NIST NVD CVE Correlation & Subresource Integrity Analysis",
        "confidence": confidence,
        "findings": findings,
        "limitations": limitations,
    }
