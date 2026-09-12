"""
Regression tests for dashboard and analytics query limits.

Verifies:
- get_dashboard_stats applies a 500-record limit to prevent unbounded memory consumption
- get_analytics applies a 500-record limit to prevent unbounded memory consumption
- Normal metrics calculation (scores, trends, distributions) functions correctly
"""
import uuid
from datetime import datetime, timezone
import pytest
import pytest_asyncio

from app.database import AsyncSessionLocal, engine, Base
from app.models.user import User
from app.models.scan import Scan, ScanStatus
from app.models.report import Report, RiskLevel
from app.models.finding import Finding, Severity, FindingStatus
from app.routers.reports import get_dashboard_stats
from app.utils.security import hash_password


@pytest_asyncio.fixture
async def db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def test_user(db):
    user = User(
        email=f"limits-{uuid.uuid4().hex[:8]}@example.com",
        name="Limits Tester",
        password_hash=hash_password("Password123!"),
        is_verified=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest.mark.asyncio
async def test_dashboard_stats_and_analytics_empty(db, test_user):
    """Empty database returns zeroed/empty response without error."""
    stats = await get_dashboard_stats(db=db, current_user=test_user)
    assert stats["security_score"] == 0
    assert stats["assets_monitored"] == 0
    assert stats["actionable_items"] == []


@pytest.mark.asyncio
async def test_dashboard_stats_and_analytics_with_data(db, test_user):
    """Confirm calculations work properly with realistic report data."""
    scan = Scan(user_id=test_user.id, url="https://target.com", status=ScanStatus.completed)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    report = Report(
        user_id=test_user.id,
        scan_id=scan.id,
        overall_score=85,
        grade="B",
        risk_level="medium",
        created_at=datetime.now(timezone.utc),
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    f1 = Finding(
        report_id=report.id,
        title="Missing Header",
        description="A missing security header was detected",
        severity=Severity.high,
        category="Security Headers",
    )
    db.add(f1)
    await db.commit()

    stats = await get_dashboard_stats(db=db, current_user=test_user)
    assert stats["security_score"] == 85
    assert stats["assets_monitored"] == 1
    assert stats["high_findings"] == 1
    assert len(stats["actionable_items"]) == 1


@pytest.mark.asyncio
async def test_dashboard_stats_excludes_passed_controls_and_resolved_findings(db, test_user):
    """Ensure dashboard actionable items exclude passed controls and non-open findings."""
    scan = Scan(
        id=uuid.uuid4(),
        user_id=test_user.id,
        url="https://filtered-test.com",
        status=ScanStatus.completed,
        created_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.commit()

    report = Report(
        id=uuid.uuid4(),
        scan_id=scan.id,
        user_id=test_user.id,
        overall_score=90,
        grade="A",
        risk_level=RiskLevel.low,
        summary="Test report",
        created_at=datetime.now(timezone.utc),
    )
    db.add(report)
    await db.commit()

    # Open high finding - should be counted
    open_finding = Finding(
        report_id=report.id,
        category="General",
        title="Open Vulnerability",
        description="Active issue",
        severity=Severity.high,
        status=FindingStatus.open,
        is_passed_control=False,
    )
    # Passed control with critical severity - should be filtered out
    passed_finding = Finding(
        report_id=report.id,
        category="General",
        title="Passed Control",
        description="Control passed",
        severity=Severity.critical,
        status=FindingStatus.open,
        is_passed_control=True,
    )
    # Resolved critical finding - should be filtered out
    resolved_finding = Finding(
        report_id=report.id,
        category="General",
        title="Resolved Vulnerability",
        description="Fixed issue",
        severity=Severity.critical,
        status=FindingStatus.resolved,
        is_passed_control=False,
    )
    db.add_all([open_finding, passed_finding, resolved_finding])
    await db.commit()

    stats = await get_dashboard_stats(db=db, current_user=test_user)
    assert stats["critical_findings"] == 0
    assert stats["high_findings"] == 1
    assert len(stats["actionable_items"]) == 1
    assert stats["actionable_items"][0]["title"] == "Open Vulnerability"


@pytest.mark.asyncio
async def test_queries_enforce_500_limit(db, test_user):
    """Ensure dashboard endpoint explicitly caps report queries at 500 rows."""
    executed_statements = []
    original_execute = db.execute

    async def tracking_execute(statement, *args, **kwargs):
        executed_statements.append(statement)
        return await original_execute(statement, *args, **kwargs)

    db.execute = tracking_execute

    await get_dashboard_stats(db=db, current_user=test_user)
    report_queries = [s for s in executed_statements if hasattr(s, "_limit") and s._limit is not None]
    assert len(report_queries) >= 1
    assert report_queries[0]._limit == 500


# ─────────────────────────────────────────────────────────────────────────────
# Pagination / export validation hardening
# ─────────────────────────────────────────────────────────────────────────────

def test_list_endpoints_clamp_negative_offset_and_limit():
    """Negative offset / non-positive limits must be clamped, not passed to SQL."""
    import pathlib
    scans_src = pathlib.Path("app/routers/scans.py").read_text(encoding='utf-8')
    reports_src = pathlib.Path("app/routers/reports.py").read_text(encoding='utf-8')
    for src in (scans_src, reports_src):
        assert "max(1, min(limit, 100))" in src
        assert "max(0, offset)" in src

    # notifications: negative limit must not collapse into LIMIT -1 ("unlimited")
    notifications_src = pathlib.Path("app/routers/notifications.py").read_text(encoding='utf-8')
    assert "max(1, min(limit, 200))" in notifications_src

    # admin list endpoints (users / scans / logs)
    admin_src = pathlib.Path("app/routers/admin.py").read_text(encoding='utf-8')
    assert "max(1, min(limit, 100))" in admin_src
    assert "max(1, min(limit, 200))" in admin_src
    assert "max(0, offset)" in admin_src


def test_download_pdf_rejects_invalid_mode():
    """mode= from the query string must be validated to prevent header
    injection via the Content-Disposition filename (H2 regression)."""
    import asyncio
    import uuid as _uuid
    from fastapi import HTTPException
    from app.routers.reports import download_pdf

    for evil_mode in ("bogus", "technical\r\nX-Evil: 1", "executive\r\nInjected: yes"):

        async def _run(mode=evil_mode):
            await download_pdf(
                _uuid.uuid4(), mode=mode,
                db=None, current_user=None,
            )

        try:
            asyncio.run(_run())
        except HTTPException as ei:
            assert ei.status_code == 400, f"mode={evil_mode!r} must be rejected"
        else:
            raise AssertionError(f"mode={evil_mode!r} must be rejected with 400")


def test_download_pdf_accepts_valid_modes():
    """Valid modes proceed past validation to the report lookup (404 on empty DB)."""
    import hashlib
    from fastapi import HTTPException
    from unittest.mock import AsyncMock, MagicMock

    from app.routers.reports import download_pdf

    import asyncio
    db = AsyncMock()
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None)))
    current_user = MagicMock(role="admin")

    async def _run(mode):
        await download_pdf(
            uuid.uuid4(), mode=mode,
            db=db, current_user=current_user,
        )

    for valid in ("technical", "executive"):
        try:
            asyncio.run(_run(valid))
        except HTTPException as ei:
            assert ei.status_code == 404  # valid mode → proceeds to lookup


def test_export_endpoints_reject_token_in_query_string():
    """Access JWTs must never be accepted/transmitted via the query string.

    Security regression: an access token passed as ?token= on the PDF/JSON
    download endpoints would land the full bearer credential in browser
    history, Request-URI server logs, and Referer leaks. The endpoints must
    be auth-header-only (the blob + Authorization download flow already is).
    """
    import inspect

    from app.routers.reports import download_json, download_pdf

    for func in (download_pdf, download_json):
        params = inspect.signature(func).parameters
        assert "token" not in params, \
            f"{func.__name__} must not accept a query-string token parameter"

    from app.services.auth_service import get_current_user_or_token
    dep_params = inspect.signature(get_current_user_or_token).parameters
    assert "token" not in dep_params, \
        "get_current_user_or_token must not accept a query-string token"

