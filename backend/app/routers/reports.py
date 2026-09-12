import uuid
from collections import Counter
from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from fastapi.responses import StreamingResponse, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.database import get_db
from app.models.report import Report
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.user import User, UserRole
from app.schemas.report import ReportResponse
from app.services.auth_service import get_verified_user, get_verified_user_or_token
from app.utils.pdf_generator import generate_pdf_report
from app.utils.exporter import generate_json_report
from app.utils.sanitize import redact_secrets_deep
from app.scanner.threat_intel import resolve_finding_location

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("", response_model=list[ReportResponse])
async def list_reports(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
    limit: int = 20,
    offset: int = 0,
    scan_id: uuid.UUID | None = None,
):
    query = (
        select(Report)
        .where(Report.user_id == current_user.id)
        .options(selectinload(Report.findings), selectinload(Report.scan))
        .order_by(Report.created_at.desc())
        .limit(max(1, min(limit, 100)))
        .offset(max(0, offset))
    )
    if scan_id is not None:
        query = query.where(Report.scan_id == scan_id)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/dashboard_stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    """Aggregate dashboard metrics based on the latest report for each unique asset."""
    from collections import defaultdict
    
    result = await db.execute(
        select(Report)
        .where(Report.user_id == current_user.id)
        .options(selectinload(Report.findings), selectinload(Report.scan))
        .order_by(Report.created_at.desc())
        .limit(500)
    )
    reports = result.scalars().all()

    assets = defaultdict(list)
    for r in reports:
        if r.scan and r.scan.url:
            url = r.scan.url.rstrip("/")
            assets[url].append(r)
            
    assets_monitored = len(assets)
    
    latest_reports = []
    previous_reports = []
    
    for url, r_list in assets.items():
        if len(r_list) > 0:
            latest_reports.append(r_list[0])
        if len(r_list) > 1:
            previous_reports.append(r_list[1])
            
    security_score = round(sum(r.overall_score for r in latest_reports) / len(latest_reports)) if latest_reports else 0
    prev_score = round(sum(r.overall_score for r in previous_reports) / len(previous_reports)) if previous_reports else 0
    
    score_trend = security_score - prev_score if previous_reports else 0
    
    critical_findings = 0
    high_findings = 0
    actionable_items = []
    
    from app.scanner.threat_intel import resolve_finding_location
    for r in latest_reports:
        url = r.scan.url.rstrip("/") if r.scan and r.scan.url else "Unknown"
        for f in r.findings:
            if f.is_passed_control:
                continue
            status_val = f.status.value if hasattr(f.status, "value") else str(f.status)
            if status_val != "open":
                continue
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            loc_info = resolve_finding_location(f, url)
            resolved_ep = f.endpoint or loc_info.get("value") or url

            if sev == "critical":
                critical_findings += 1
                actionable_items.append({
                    "id": str(f.id),
                    "report_id": str(r.id),
                    "severity": sev,
                    "title": f.title,
                    "problem": f.problem or f.description,
                    "impact": f.impact or "Requires immediate attention to protect application security.",
                    "endpoint": resolved_ep,
                    "category": f.category,
                    "asset": url,
                    "detected_at": r.created_at.isoformat() if r.created_at else None,
                    "cvss": float(f.cvss_score) if f.cvss_score else None,
                    "type": "finding"
                })
            elif sev == "high":
                high_findings += 1
                actionable_items.append({
                    "id": str(f.id),
                    "report_id": str(r.id),
                    "severity": sev,
                    "title": f.title,
                    "problem": f.problem or f.description,
                    "impact": f.impact or "Important security configuration issue that should be resolved.",
                    "endpoint": resolved_ep,
                    "category": f.category,
                    "asset": url,
                    "detected_at": r.created_at.isoformat() if r.created_at else None,
                    "cvss": float(f.cvss_score) if f.cvss_score else None,
                    "type": "finding"
                })
        
        # Check expiring SSL certs
        if r.ssl_info:
            cert = r.ssl_info.get("certificate")
            if cert and cert.get("days_remaining", 999) < 14:
                actionable_items.append({
                    "id": f"ssl_{r.id}",
                    "report_id": str(r.id),
                    "severity": "warning",
                    "title": f"SSL Certificate expires in {cert['days_remaining']} days",
                    "problem": f"Your SSL/TLS encryption certificate expires in {cert['days_remaining']} days.",
                    "impact": "Visitors will encounter browser security warnings if the certificate is not renewed.",
                    "endpoint": url,
                    "asset": url,
                    "detected_at": r.created_at.isoformat() if r.created_at else None,
                    "cvss": None,
                    "type": "ssl_expiry"
                })
                
    order = {"critical": 0, "high": 1, "warning": 2}
    actionable_items.sort(key=lambda x: order.get(x["severity"], 99))
    
    return {
        "security_score": security_score,
        "score_trend": score_trend,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "assets_monitored": assets_monitored,
        "actionable_items": actionable_items
    }


@router.get("/findings/{finding_id}")
async def get_finding_detail(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    """Fetch detailed finding information including target asset URL and scan history."""
    from app.models.finding import Finding
    # Ownership enforced at DB level: join Finding→Report and filter on
    # Report.user_id so that another user's finding_id returns nothing
    # (no post-load race, no information leak about existence of other users' findings).
    res = await db.execute(
        select(Finding)
        .join(Finding.report)
        .where(
            Finding.id == finding_id,
            Report.user_id == current_user.id,
        )
        .options(selectinload(Finding.report).selectinload(Report.scan))
    )
    finding = res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    # Fetch other reports for the same asset to calculate first/last seen.
    # occurrences counts how many reports contain a finding with the same title
    # for this asset (not the total number of reports for the asset).
    url = finding.report.scan.url if finding.report and finding.report.scan else ""
    asset_reports_res = await db.execute(
        select(Report)
        .join(Scan)
        .where(Report.user_id == current_user.id, Scan.url == url)
        .order_by(Report.created_at.asc())
    )
    asset_reports = asset_reports_res.scalars().all()

    first_seen = asset_reports[0].created_at if asset_reports else finding.created_at
    last_seen = finding.created_at

    # Count only reports that contain a finding with the same title (not all scans of this asset)
    if asset_reports:
        report_ids = [r.id for r in asset_reports]
        occ_res = await db.execute(
            select(Finding.report_id)
            .where(
                Finding.report_id.in_(report_ids),
                Finding.title == finding.title,
            )
            .distinct()
        )
        occurrences = len(occ_res.scalars().all())
    else:
        occurrences = 1

    return {
        "id": str(finding.id),
        "report_id": str(finding.report_id),
        "asset_url": url,
        "category": finding.category,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        "status": finding.status.value if hasattr(finding.status, "value") else str(finding.status),
        "confidence": finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
        "cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else None,
        "cve_id": finding.cve_id,
        "cwe_id": finding.cwe_id or ("CWE-693" if "header" in finding.category.lower() or "csp" in finding.title.lower() or "hsts" in finding.title.lower() else "CWE-200" if "disclosure" in finding.category.lower() else None),
        "endpoint": finding.endpoint or resolve_finding_location(finding, url).get("value") or url,
        "published_date": finding.published_date.isoformat() if finding.published_date else None,
        "recommendation": finding.recommendation,
        "problem": finding.problem,
        "impact": finding.impact or f"Vulnerability in {finding.title} exposes the target asset to potential security risks.",
        "risk_analysis": finding.risk_analysis,
        "technical_details": finding.technical_details,
        "fix_steps": finding.fix_steps,
        "configuration_example": finding.configuration_example,
        "best_practices": finding.best_practices,
        "official_documentation": finding.official_documentation,
        "references": finding.references,
        "evidence": finding.evidence or f"Identified {finding.title} during automated scan of {url}",
        "owasp_mapping": finding.owasp_mapping,
        "mitre_mapping": finding.mitre_mapping,
        "is_passed_control": finding.is_passed_control,
        "first_seen": first_seen.isoformat() if first_seen else None,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "occurrences": occurrences,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
    }


class UpdateFindingStatusRequest(BaseModel):
    status: str  # 'open', 'accepted_risk', 'resolved', 'false_positive'


@router.patch("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: uuid.UUID,
    payload: UpdateFindingStatusRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    """Update and persist a finding's workflow status."""
    from app.models.finding import Finding, FindingStatus
    # Ownership enforced at DB level via join — avoids lazy-load MissingGreenlet
    # and ensures no post-load ownership race.
    res = await db.execute(
        select(Finding)
        .join(Finding.report)
        .where(
            Finding.id == finding_id,
            Report.user_id == current_user.id,
        )
    )
    finding = res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    try:
        finding.status = FindingStatus(payload.status)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid status value '{payload.status}'")

    await db.commit()
    return {"id": str(finding.id), "status": finding.status.value, "message": f"Finding status updated to {finding.status.value}"}


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    query = select(Report).where(Report.id == report_id)
    if current_user.role != UserRole.admin:
        query = query.where(Report.user_id == current_user.id)
    result = await db.execute(
        query.options(selectinload(Report.findings), selectinload(Report.scan))
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.get("/{report_id}/pdf")
async def download_pdf(
    report_id: uuid.UUID,
    mode: str = "technical",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user_or_token),
):
    if mode not in ("technical", "executive"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="mode must be one of: technical, executive",
        )
    query = select(Report).where(Report.id == report_id)
    if current_user.role != UserRole.admin:
        query = query.where(Report.user_id == current_user.id)
    result = await db.execute(
        query.options(selectinload(Report.findings), selectinload(Report.scan))
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    pdf_bytes = await generate_pdf_report(report, current_user, mode=mode)
    filename = f"sentinelscan-report-{str(report_id)[:8]}-{mode}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@router.get("/{report_id}/json")
async def download_json(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user_or_token),
):
    """Download JSON export of a security report."""
    query = select(Report).where(Report.id == report_id)
    if current_user.role != UserRole.admin:
        query = query.where(Report.user_id == current_user.id)
    result = await db.execute(
        query.options(selectinload(Report.findings), selectinload(Report.scan))
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    json_content = generate_json_report(report, current_user)
    filename = f"sentinelscan-report-{str(report_id)[:8]}.json"
    return Response(
        content=json_content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.user_id == current_user.id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    await db.delete(report)
    await db.commit()
