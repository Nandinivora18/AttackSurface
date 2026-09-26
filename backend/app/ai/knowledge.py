"""
SentinelScan Knowledge Base — Ask Sentinel

Structured, maintainable knowledge about SentinelScan itself. Used to ground
the AI assistant's answers about the platform, its methodology, and its
limitations.

Design:
  - No vector database. Simple structured Python module.
  - get_knowledge_block() returns a compact text summary for the system prompt.
  - Future-ready: the get_relevant_knowledge(topic) function can be swapped to
    a RAG/embedding retrieval without changing any caller code.

Coverage:
  - SentinelScan purpose, architecture, scan workflow
  - All 37 detector categories and IDs
  - NOT_VERIFIABLE semantics
  - OWASP Top 10:2025 categories
  - Confidence levels
  - Evidence and severity classification
  - Known limitations (passive-only, SSRF protection, distribution backports)
  - Scoring and grading system
"""
from __future__ import annotations

from app.scanner.metadata import DETECTOR_REGISTRY


def _build_categories_from_registry() -> dict[str, list[str]]:
    """
    Derive the detector categories ONLY from the authoritative
    DETECTOR_REGISTRY, so the knowledge base can never drift from the
    detectors that actually exist.
    """
    categories: dict[str, list[str]] = {}
    for detector_id, meta in DETECTOR_REGISTRY.items():
        categories.setdefault(meta["category"], []).append(detector_id)
    for ids in categories.values():
        ids.sort()
    return {category: ids for category, ids in sorted(categories.items())}


# ── Detector categories (derived from metadata.py DETECTOR_REGISTRY) ─────────
DETECTOR_CATEGORIES: dict[str, list[str]] = _build_categories_from_registry()

# ── OWASP Top 10:2025 mapping ─────────────────────────────────────────────────
OWASP_TOP10_2025: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# ── Severity classification ───────────────────────────────────────────────────
SEVERITY_DEFINITIONS: dict[str, str] = {
    "critical": (
        "Immediate risk of full compromise, data exfiltration, or remote code execution. "
        "Requires emergency remediation. CVSS 9.0–10.0."
    ),
    "high": (
        "Significant security weakness that directly threatens confidentiality, integrity, "
        "or availability. Must be remediated with high priority. CVSS 7.0–8.9."
    ),
    "medium": (
        "Meaningful security gap that could be exploited in combination with other weaknesses "
        "or under specific conditions. Plan remediation. CVSS 4.0–6.9."
    ),
    "low": (
        "Minor security configuration gap or defense-in-depth improvement. "
        "Low exploitation likelihood on its own. CVSS 0.1–3.9."
    ),
    "info": (
        "Informational observation — not a vulnerability. Provided for transparency. "
        "No scoring impact. No CVSS score."
    ),
}

# ── Confidence levels ─────────────────────────────────────────────────────────
CONFIDENCE_DEFINITIONS: dict[str, str] = {
    "high": (
        "SentinelScan directly observed the condition from external evidence "
        "(e.g., header is definitively absent or present in the HTTP response). "
        "High confidence findings have strong evidentiary basis."
    ),
    "medium": (
        "SentinelScan observed partial evidence or made a reasonable inference "
        "from available signals. Some uncertainty remains."
    ),
    "low": (
        "Limited external evidence available. The finding may be a NOT_VERIFIABLE "
        "condition — SentinelScan cannot confirm or deny the vulnerability from "
        "the outside. Treat with appropriate caution."
    ),
}

# ── NOT_VERIFIABLE semantics ──────────────────────────────────────────────────
NOT_VERIFIABLE_EXPLANATION = """
NOT_VERIFIABLE findings represent security conditions that SentinelScan's passive
external scanner CANNOT confirm or deny from the outside.

Examples of NOT_VERIFIABLE conditions:
- Whether SQL injection exists (requires sending malicious payloads — out of scope)
- Whether input validation is enforced server-side (cannot test without active probing)
- Whether authentication bypass is possible (requires authenticated access)
- Whether rate limiting is enforced (cannot send enough requests ethically)
- Whether stored XSS exists (requires content injection and retrieval)

When SentinelScan reports something as NOT_VERIFIABLE, it means:
1. The technology or configuration COULD have this vulnerability based on its
   version or observed signals.
2. But SentinelScan cannot PROVE it from passive external observation alone.
3. Manual penetration testing or authenticated scanning would be required to confirm.

The AI assistant will always acknowledge NOT_VERIFIABLE status rather than
claiming a vulnerability is confirmed when it is not.
"""

# ── Known limitations ────────────────────────────────────────────────────────
KNOWN_LIMITATIONS = """
SentinelScan is a PASSIVE, external security assessment tool. Its known limitations:

1. PASSIVE ONLY: Cannot send malicious payloads, exploit vulnerabilities, or perform
   authenticated testing. Findings reflect external observation only.

2. VERSION-BASED CVE MATCHING: CVE correlation is based on detected version strings.
   Linux/vendor distributions (e.g. RHEL, Ubuntu, Debian) often backport security
   patches without incrementing the version number. A component may show as vulnerable
   by version but actually be patched. Always verify CVE applicability against the
   actual distribution's security advisory.

3. SSRF PROTECTION: SentinelScan enforces strict SSRF protection. Targets resolving
   to private/internal IP ranges are blocked. Internal infrastructure cannot be scanned.

4. REDIRECT FOLLOWING: The scanner follows redirects during HTTP crawling. Evidence
   reflects the final response after redirects.

5. JAVASCRIPT-HEAVY SITES: Client-side rendered content (heavy React/Angular/Vue SPAs)
   may not be fully analyzed. Header analysis and SSL inspection are always performed
   regardless of client-side rendering.

6. BEHIND-LOGIN CONTENT: SentinelScan cannot scan content that requires authentication.
   Findings reflect the publicly accessible attack surface only.

7. EVIDENCE IS OBSERVATION-BASED: All evidence is derived from HTTP responses, DNS
   records, SSL certificates, and HTTP headers observed during the scan.
"""

# ── Scoring system ────────────────────────────────────────────────────────────
SCORING_EXPLANATION = """
SentinelScan Security Score (0–100) and Grade (A+ to F):

- Score 90–100 (A+ / A): Excellent posture. Minimal findings.
- Score 75–89 (B): Good posture with some gaps to address.
- Score 60–74 (C): Moderate risk. Several findings need attention.
- Score 40–59 (D): Elevated risk. Multiple significant weaknesses present.
- Score 0–39 (F): Critical risk. Immediate remediation required.

Grade reflects score; risk_level reflects the WORST finding severity:
  - A scan can score B (75) but still be rated HIGH risk if it has even one
    unmitigated HIGH severity finding that wasn't penalized enough by scoring.
  - This is intentional: grade = overall posture, risk_level = worst-case exposure.

Scoring deductions per finding:
  - Critical: up to 25 points per finding (category-capped)
  - High: up to 15 points
  - Medium: up to 8 points
  - Low: up to 3 points
  - Info: 0 points (no penalty)
"""


def get_knowledge_block() -> str:
    """
    Return a compact, LLM-ready summary of SentinelScan knowledge.
    Called once per request as part of the system prompt construction.
    """
    owasp_summary = "\n".join(
        f"  - {k}: {v}" for k, v in OWASP_TOP10_2025.items()
    )
    detector_count = sum(len(v) for v in DETECTOR_CATEGORIES.values())
    category_summary = ", ".join(DETECTOR_CATEGORIES.keys())

    return f"""## SentinelScan Platform Knowledge
- **Purpose**: Passive external web security assessment platform. Evaluates external attack surfaces without intrusive exploitation.
- **Coverage**: {detector_count} detectors across: {category_summary}.
- **OWASP Top 10:2025**:
{owasp_summary}
- **Severity**: CRITICAL (immediate compromise, CVSS 9.0-10.0), HIGH (severe exposure, CVSS 7.0-8.9), MEDIUM (meaningful weakness, CVSS 4.0-6.9), LOW (minor gap/hardening, CVSS 0.1-3.9), INFO (informational observation).
- **Confidence**: HIGH (directly observed evidence), MEDIUM (partial observation/inference), LOW (limited external visibility / NOT_VERIFIABLE condition).
- **NOT_VERIFIABLE**: Conditions requiring active probing (e.g. SQLi exploitation, authenticated bypass, blind timing) that cannot be confirmed passively. Always caveated as unverified.
- **Scoring & Grades**: Overall score 0–100 (A+ to F). Grade reflects overall score; risk_level reflects worst unmitigated finding severity.
- **Key Limitations**: Passive-only (no exploit payloads); version-based CVE matching (vendor backports may patch vulnerabilities without version increment); SSRF protection blocks private IPs; JavaScript-rendered SPAs may have limited body visibility.""".strip()



def get_relevant_knowledge(topic: str) -> str:
    """
    Return knowledge relevant to a specific topic.
    Currently keyword-based. Future: swap to RAG/embedding retrieval.

    Args:
        topic: A keyword or phrase indicating what knowledge is needed.

    Returns:
        A relevant knowledge text snippet.
    """
    topic_lower = topic.lower()
    result_parts = []

    if any(kw in topic_lower for kw in ["not_verifiable", "cannot verify", "passive", "limitation"]):
        result_parts.append(NOT_VERIFIABLE_EXPLANATION)

    if any(kw in topic_lower for kw in ["score", "grade", "risk", "rating"]):
        result_parts.append(SCORING_EXPLANATION)

    if any(kw in topic_lower for kw in ["cve", "version", "backport", "lifecycle", "eol"]):
        result_parts.append(
            "**CVE Version Matching Caveat**: " + KNOWN_LIMITATIONS.split("2. VERSION-BASED")[1].split("3.")[0]
        )

    if any(kw in topic_lower for kw in ["owasp", "top 10", "mapping"]):
        result_parts.append("**OWASP Top 10:2025**: " + str(OWASP_TOP10_2025))

    if any(kw in topic_lower for kw in ["severity", "critical", "high", "medium", "low"]):
        result_parts.append("**Severity Definitions**: " + str(SEVERITY_DEFINITIONS))

    if not result_parts:
        result_parts.append(get_knowledge_block())

    return "\n\n".join(result_parts)
