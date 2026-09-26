"""
AI Security Context Builder — Ask Sentinel

Builds compact, structured context from the database for the authenticated user's
authorized scans and findings. Authorization is enforced at the query level —
ownership is checked via user_id before any data is returned.

Security principles:
  - Never returns data for a scan/finding the user doesn't own
  - All returned context is passed through sanitize_context_for_llm() before use
  - Raw headers are filtered to security-relevant headers only
  - Evidence is truncated and redacted
  - No internal infrastructure details (DB URLs, internal IPs) are exposed
  - Secrets are stripped by sanitize.py before the LLM ever sees the context
"""
import uuid
import logging
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.scan import Scan, ScanStatus
from app.models.report import Report
from app.models.finding import Finding
from app.models.user import User
from app.ai.sanitize import (
    sanitize_context_for_llm,
    sanitize_raw_headers,
    sanitize_evidence,
)

logger = logging.getLogger(__name__)

_MAX_FINDINGS_IN_SCAN_CONTEXT = 20   # prioritized top findings to avoid huge prompts
_MAX_EVIDENCE_CHARS = 400
_MAX_TECH_ITEMS = 15
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def build_scan_context(
    scan_id: uuid.UUID,
    user: User,
    db: AsyncSession,
) -> Optional[dict]:
    """
    Build a compact, sanitized scan context for the AI assistant.

    Authorization: scan must belong to the authenticated user.
    Returns None if the scan is not found or not owned by the user.

    Args:
        scan_id: The scan UUID to build context for.
        user: The authenticated User model instance.
        db: Database session.

    Returns:
        Sanitized context dict, or None if not authorized/found.
    """
    # Load scan + report + findings in a single authorized query
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id, Scan.user_id == user.id)
        .options(
            selectinload(Scan.report).selectinload(Report.findings)
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        return None

    report = scan.report
    if not report:
        # Scan exists but has no report yet (pending/running/failed)
        raw_context = {
            "scan_id": str(scan.id),
            "target_url": scan.url,
            "status": scan.status.value if scan.status else "unknown",
            "scan_mode": scan.scan_mode,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "note": "Scan has not yet completed. No report data available.",
        }
        return sanitize_context_for_llm(raw_context)

    # Calculate not_verifiable across all findings in report
    not_verifiable_count = sum(
        1 for f in (report.findings or [])
        if bool(
            (f.confidence and f.confidence.value == "low") or
            (f.evidence and "not_verifiable" in f.evidence.lower()) or
            (f.technical_details and "not verifiable" in f.technical_details.lower())
        )
    )

    # Sort findings by severity (critical first) so the top most impactful findings are in context
    all_findings = report.findings or []
    sorted_findings = sorted(
        all_findings,
        key=lambda f: (
            1 if f.is_passed_control else 0,
            _SEVERITY_ORDER.get(f.severity.value if f.severity else "info", 5),
        ),
    )

    # Build findings summary (compact, prioritized, no raw secrets in evidence)
    findings_data = []
    for f in sorted_findings[:_MAX_FINDINGS_IN_SCAN_CONTEXT]:
        is_not_verifiable = bool(
            (f.confidence and f.confidence.value == "low") or
            (f.evidence and "not_verifiable" in f.evidence.lower()) or
            (f.technical_details and "not verifiable" in f.technical_details.lower())
        )

        owasp = None
        if f.owasp_mapping and isinstance(f.owasp_mapping, dict):
            owasp = {
                "id": f.owasp_mapping.get("id"),
                "title": f.owasp_mapping.get("title"),
            }

        finding_entry = {
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity.value if f.severity else None,
            "confidence": f.confidence.value if f.confidence else None,
            "category": f.category,
            "is_passed_control": f.is_passed_control,
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "cvss_score": float(f.cvss_score) if f.cvss_score else None,
            "owasp": owasp,
            "evidence_summary": sanitize_evidence(f.evidence),
            "not_verifiable": is_not_verifiable,
            "status": f.status.value if f.status else None,
        }
        findings_data.append(finding_entry)

    # Build tech stack summary (compact)
    tech_items = []
    if report.tech_stack and isinstance(report.tech_stack, dict):
        for tech_name, tech_info in list(report.tech_stack.items())[:_MAX_TECH_ITEMS]:
            if isinstance(tech_info, dict):
                tech_items.append({
                    "name": tech_name,
                    "category": tech_info.get("category"),
                    "version": tech_info.get("version"),
                    "confidence": tech_info.get("confidence"),
                })

    # Component inventory (lifecycle/CVE data)
    components = []
    if report.component_inventory and isinstance(report.component_inventory, list):
        for comp in report.component_inventory[:15]:
            if isinstance(comp, dict):
                components.append({
                    "technology": comp.get("technology"),
                    "version": comp.get("raw_version") or comp.get("normalized_version"),
                    "lifecycle_status": comp.get("lifecycle_status"),
                    "eol_date": comp.get("eol_date"),
                    "cve_count": comp.get("cve_count", 0),
                    "cves": [
                        {"id": c.get("cve_id"), "cvss": c.get("cvss_score")}
                        for c in (comp.get("cves") or [])[:5]
                        if isinstance(c, dict)
                    ],
                })

    # SSL summary (no certificates' raw data, just key facts)
    ssl_summary = None
    if report.ssl_info and isinstance(report.ssl_info, dict):
        cert = report.ssl_info.get("certificate", {}) or {}
        ssl_summary = {
            "supported": report.ssl_info.get("supported"),
            "grade": report.ssl_info.get("grade"),
            "tls_version": report.ssl_info.get("tls_version"),
            "days_remaining": cert.get("days_remaining"),
            "issues": [
                {"severity": i.get("severity"), "message": i.get("message")}
                for i in (report.ssl_info.get("issues") or [])[:5]
                if isinstance(i, dict)
            ],
        }

    # DNS summary
    dns_summary = None
    if report.dns_info and isinstance(report.dns_info, dict):
        dns_summary = {
            "spf": report.dns_info.get("spf"),
            "dmarc": report.dns_info.get("dmarc"),
            "dnssec": report.dns_info.get("dnssec"),
            "has_mx": bool(report.dns_info.get("mx_records")),
        }

    # Executive summary (high-level, already sanitized at scan time)
    exec_summary = None
    if report.executive_summary and isinstance(report.executive_summary, dict):
        exec_summary = {
            "overall_risk": report.executive_summary.get("overall_risk"),
            "security_posture": report.executive_summary.get("security_posture"),
            "strengths": (report.executive_summary.get("strengths") or [])[:3],
            "weaknesses": (report.executive_summary.get("weaknesses") or [])[:3],
            "critical_issues": (report.executive_summary.get("critical_issues") or [])[:3],
            "priority_fixes": (report.executive_summary.get("priority_fixes") or [])[:3],
        }

    # Count severity breakdown
    severity_counts: dict[str, int] = {}
    for f in (report.findings or []):
        if not f.is_passed_control:
            sev = f.severity.value if f.severity else "info"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    raw_context = {
        "scan_id": str(scan.id),
        "report_id": str(report.id),
        "target_url": scan.url,
        "status": scan.status.value if scan.status else "unknown",
        "scan_mode": scan.scan_mode,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "overall_score": report.overall_score,
        "grade": report.grade,
        "risk_level": report.risk_level.value if report.risk_level else None,
        "severity_counts": severity_counts,
        "not_verifiable_findings_count": not_verifiable_count,
        "total_findings": len(report.findings or []),
        "findings": findings_data,
        "tech_stack": tech_items,
        "component_inventory": components,
        "ssl": ssl_summary,
        "dns": dns_summary,
        "executive_summary": exec_summary,
        "security_headers": sanitize_raw_headers(report.raw_headers),
    }

    return sanitize_context_for_llm(raw_context)


async def build_finding_context(
    finding_id: uuid.UUID,
    user: User,
    db: AsyncSession,
) -> Optional[dict]:
    """
    Build a detailed, sanitized finding context for the AI assistant.

    Authorization: finding must belong to a report owned by the authenticated user.
    Returns None if not found or not owned.

    Args:
        finding_id: The finding UUID to build context for.
        user: The authenticated User model instance.
        db: Database session.

    Returns:
        Sanitized context dict, or None if not authorized/found.
    """
    # Ownership enforced at query level — same pattern as get_finding_detail in reports.py
    result = await db.execute(
        select(Finding)
        .join(Finding.report)
        .where(
            Finding.id == finding_id,
            Report.user_id == user.id,
        )
        .options(
            selectinload(Finding.report).selectinload(Report.scan)
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        return None

    # Determine NOT_VERIFIABLE status
    is_not_verifiable = bool(
        (finding.confidence and finding.confidence.value == "low") or
        (finding.evidence and "not_verifiable" in finding.evidence.lower()) or
        (finding.technical_details and "not verifiable" in finding.technical_details.lower())
    )

    # OWASP mapping (full, as it's directly relevant to the finding)
    owasp = None
    if finding.owasp_mapping and isinstance(finding.owasp_mapping, dict):
        owasp = {
            "id": finding.owasp_mapping.get("id"),
            "title": finding.owasp_mapping.get("title"),
            "description": (finding.owasp_mapping.get("description") or "")[:300],
            "reference": finding.owasp_mapping.get("reference"),
        }

    # MITRE mapping
    mitre = None
    if finding.mitre_mapping and isinstance(finding.mitre_mapping, dict):
        mitre = {
            "technique_id": finding.mitre_mapping.get("technique_id"),
            "technique_name": finding.mitre_mapping.get("technique_name"),
        }

    # Containing scan context (minimal)
    scan_context = None
    if finding.report and finding.report.scan:
        scan = finding.report.scan
        scan_context = {
            "target_url": scan.url,
            "score": finding.report.overall_score,
            "grade": finding.report.grade,
            "risk_level": finding.report.risk_level.value if finding.report.risk_level else None,
        }

    raw_context = {
        "finding_id": str(finding.id),
        "report_id": str(finding.report_id),
        "title": finding.title,
        "category": finding.category,
        "severity": finding.severity.value if finding.severity else None,
        "confidence": finding.confidence.value if finding.confidence else None,
        "status": finding.status.value if finding.status else None,
        "not_verifiable": is_not_verifiable,
        "is_passed_control": finding.is_passed_control,
        "description": (finding.description or "")[:1000],
        "problem": (finding.problem or "")[:800],
        "impact": (finding.impact or "")[:800],
        "risk_analysis": (finding.risk_analysis or "")[:600],
        "technical_details": (finding.technical_details or "")[:800],
        "evidence": sanitize_evidence(finding.evidence),
        "cvss_score": float(finding.cvss_score) if finding.cvss_score else None,
        "cve_id": finding.cve_id,
        "cwe_id": finding.cwe_id,
        "endpoint": finding.endpoint,
        "published_date": finding.published_date.isoformat() if finding.published_date else None,
        "owasp_mapping": owasp,
        "mitre_mapping": mitre,
        "recommendation": (finding.recommendation or "")[:800],
        "fix_steps": (finding.fix_steps or [])[:10],
        "configuration_example": (finding.configuration_example or "")[:1000],
        "best_practices": (finding.best_practices or "")[:600],
        "references": (finding.references or [])[:8],
        "scan": scan_context,
    }

    return sanitize_context_for_llm(raw_context)


def determine_context_type(
    scan_id: Optional[uuid.UUID],
    finding_id: Optional[uuid.UUID],
) -> str:
    """
    Determine the context type string for the AI response.
    """
    if finding_id:
        return "finding"
    if scan_id:
        return "scan"
    return "general"
