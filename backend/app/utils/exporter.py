"""
Export generator for structured JSON reports.
Generates comprehensive report downloads including Executive Summary, Findings,
Category Scoring Breakdown, and Remediation Recommendations.

Security (server-side, applied to every export):
  - Credential/secret redaction before any content is serialized
"""
import json
from datetime import datetime, timezone
from app.models.report import Report
from app.models.user import User
from app.utils.sanitize import redact_secrets_deep


def _redact_strings(obj):
    """Recursively redact credential-bearing strings inside JSON-serializable data.

    Delegates to the canonical implementation in app.utils.sanitize (which
    also covers dictionary keys). Kept as a thin alias so existing call
    sites and tests remain stable.
    """
    return redact_secrets_deep(obj)


def generate_json_report(report: Report, user: User) -> str:
    """Generate a clean, structured JSON report string."""
    from app.scanner.threat_intel import resolve_finding_location

    scan_url = report.scan.url if report.scan else "N/A"
    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    findings = report.findings or []
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: sev_order.get(str(f.severity.value if hasattr(f.severity, 'value') else f.severity).lower(), 5)
    )

    findings_json = []
    for f in sorted_findings:
        sev = str(f.severity.value if hasattr(f.severity, 'value') else f.severity).lower()
        loc_res = resolve_finding_location(f, scan_url)
        findings_json.append({
            "id": str(f.id),
            "title": f.title,
            "category": f.category,
            "severity": sev,
            "cvss_score": float(f.cvss_score) if f.cvss_score is not None else None,
            "cve_id": f.cve_id,
            "affected_url": loc_res.get("value", scan_url),
            "location_label": loc_res.get("label", "Found on"),
            "location_type": loc_res.get("type", "url"),
            "location_badge": loc_res.get("badge", "Specific URL"),
            "what_we_found": getattr(f, "problem", None) or f.description,
            "why_it_matters": getattr(f, "impact", None) or "Security configuration issue that should be resolved.",
            "recommended_fix": f.recommendation,
            "fix_steps": getattr(f, "fix_steps", None) or [],
            "configuration_example": getattr(f, "configuration_example", None),
            "how_to_verify": "After applying this change, run another SentinelScan scan to confirm the finding disappears.",
            "published_date": f.published_date.isoformat() if hasattr(f.published_date, "isoformat") else str(f.published_date or ""),
            "description": f.description,
            "evidence": f.evidence,
            "references": f.references or [],
            "owasp_mapping": f.owasp_mapping,
            "mitre_mapping": f.mitre_mapping,
        })

    data = {
        "report_id": str(report.id),
        "scan_id": str(report.scan_id),
        "target_url": scan_url,
        "generated_for": user.name,
        "generated_at": gen_time,
        "overall_score": report.overall_score,
        "grade": report.grade,
        "risk_level": str(report.risk_level.value if hasattr(report.risk_level, 'value') else report.risk_level),
        "summary": report.summary,
        "category_score_breakdown": report.score_breakdown,
        "tech_stack": report.tech_stack,
        "ssl_info": report.ssl_info,
        "dns_info": report.dns_info,
        "findings_count": len(findings),
        "scan_mode": getattr(report, "scan_mode", "passive") or "passive",
        "owasp_summary": getattr(report, "owasp_summary", None) or {},
        "component_inventory": getattr(report, "component_inventory", None) or [],
        "discovered_endpoints": getattr(report, "discovered_endpoints", None) or [],
        "findings": findings_json,
    }
    # Server-side credential redaction across the whole payload before serialization.
    return json.dumps(_redact_strings(data), indent=2)
