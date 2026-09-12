"""
Tests for Hybrid Pipeline Orchestration and OWASP / Component Matrix Integration
=================================================================================
Validates:
- End-to-end passive scan execution without crawling
- End-to-end safe active scan execution with bounded crawling
- Report persistence of owasp_summary, component_inventory, and discovered_endpoints
- 10-category OWASP matrix completeness and 5-state vocabulary adherence
"""
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from app.models.scan import Scan, ScanStatus
from app.models.report import Report
from app.tasks.scan_task import run_scan_job
from app.scanner.crawler import CrawlResult, DiscoveredEndpoint


@pytest.fixture
def mock_scan_passive():
    scan = MagicMock(spec=Scan)
    scan.id = uuid.uuid4()
    scan.url = "https://app.test"
    scan.status = ScanStatus.pending
    scan.scan_mode = "passive"
    scan.scope_config = {
        "scan_mode": "passive",
        "consent_acknowledged": False,
        "auth_context": None,
        "design_questionnaire": None,
        "openapi_spec": None,
    }
    scan.user_id = uuid.uuid4()
    scan.created_at = datetime.now(timezone.utc)
    scan.started_at = datetime.now(timezone.utc)
    return scan


@pytest.fixture
def mock_scan_active():
    scan = MagicMock(spec=Scan)
    scan.id = uuid.uuid4()
    scan.url = "https://app.test"
    scan.status = ScanStatus.pending
    scan.scan_mode = "safe_active"
    scan.scope_config = {
        "scan_mode": "safe_active",
        "consent_acknowledged": True,
        "max_pages": 10,
        "max_crawl_depth": 2,
        "max_requests": 25,
        "auth_context": None,
        "design_questionnaire": None,
        "openapi_spec": None,
    }
    scan.user_id = uuid.uuid4()
    scan.created_at = datetime.now(timezone.utc)
    scan.started_at = datetime.now(timezone.utc)
    return scan


def _build_mock_db(scan_obj, added_objects):
    mock_db = AsyncMock()

    async def mock_execute(stmt, *args, **kwargs):
        stmt_str = str(stmt).lower()
        res = MagicMock()
        if "from scans" in stmt_str or "scan.id" in stmt_str or "scans.id" in stmt_str:
            res.scalar_one_or_none.return_value = scan_obj
            res.scalars.return_value.all.return_value = [scan_obj]
        else:
            res.scalar_one_or_none.return_value = None
            res.scalars.return_value.all.return_value = []
        return res

    mock_db.execute = AsyncMock(side_effect=mock_execute)
    mock_db.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
    mock_db.commit = AsyncMock()
    mock_db.flush = AsyncMock()
    mock_db.refresh = AsyncMock()
    mock_db.__aenter__ = AsyncMock(return_value=mock_db)
    mock_db.__aexit__ = AsyncMock(return_value=None)
    return mock_db


@pytest.mark.asyncio
async def test_passive_scan_pipeline_populates_report(mock_scan_passive):
    """Passive mode executes all stages without crawler and persists OWASP matrix."""
    scan_id = str(mock_scan_passive.id)

    added_objects = []
    mock_db = _build_mock_db(mock_scan_passive, added_objects)

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock()
    mock_redis.publish = AsyncMock()

    ctx = {"redis": mock_redis, "job_id": f"scan:{scan_id}", "job_try": 1}

    mock_score = {
        "overall_score": 95,
        "grade": "A",
        "risk_level": "LOW",
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "category_scores": {},
    }

    with patch("app.tasks.scan_task.AsyncSessionLocal", return_value=mock_db), \
         patch("app.utils.safe_http.async_resolve_and_pin", new=AsyncMock(return_value=(True, "", "https://app.test", "https://93.184.216.34", "app.test"))), \
         patch("app.scanner.dns_checker.analyze_dns", new=AsyncMock(return_value={"findings": [], "dns_info": {}})), \
         patch("app.scanner.ssl_checker.analyze_ssl", new=AsyncMock(return_value={"findings": [], "issues": []})), \
         patch("app.scanner.header_analyzer.analyze_headers", new=AsyncMock(return_value={"findings": [], "headers": {"server": "nginx/1.24.0"}, "raw_headers": {}})), \
         patch("app.scanner.tech_detector.detect_technologies", new=AsyncMock(return_value={"findings": [], "detected_technologies": {"Nginx": {"version": "1.24.0", "category": "Web Server"}}, "html_body": "<html></html>"})), \
         patch("app.scanner.content_analyzer.analyze_content", new=AsyncMock(return_value={"findings": []})), \
         patch("app.scanner.cve_checker.check_all_technologies", new=AsyncMock(return_value=[])), \
         patch("app.scanner.scoring.calculate_score", return_value=mock_score), \
         patch("app.scanner.scoring.generate_executive_summary", return_value="Security posture is good."), \
         patch("app.scanner.scoring.generate_enriched_executive_summary", return_value={}):

        res = await run_scan_job(ctx, scan_id)

    assert res["status"] == "completed"

    # Find persisted Report object
    reports = [o for o in added_objects if isinstance(o, Report)]
    assert len(reports) == 1
    report = reports[0]

    # Verify OWASP matrix has all 10 categories
    assert report.owasp_summary is not None
    assert "A01_BrokenAccessControl" in report.owasp_summary
    assert "A03_SoftwareSupplyChainFailures" in report.owasp_summary
    assert "A10_MishandlingOfExceptionalConditions" in report.owasp_summary

    # Component inventory must be present
    assert report.component_inventory is not None
    assert any(c["technology"] == "Nginx" for c in report.component_inventory)

    # In passive mode, discovered_endpoints has the single target URL
    assert len(report.discovered_endpoints) == 1
    assert report.discovered_endpoints[0]["url"] == "https://app.test"


@pytest.mark.asyncio
async def test_safe_active_scan_pipeline_with_crawler(mock_scan_active):
    """Safe active mode runs crawler and attaches discovered endpoints."""
    scan_id = str(mock_scan_active.id)

    added_objects = []
    mock_db = _build_mock_db(mock_scan_active, added_objects)

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock()
    mock_redis.publish = AsyncMock()

    ctx = {"redis": mock_redis, "job_id": f"scan:{scan_id}", "job_try": 1}

    mock_crawl = CrawlResult(
        target_url="https://app.test",
        endpoints=[
            DiscoveredEndpoint(url="https://app.test", method="GET", status_code=200, content_type="text/html"),
            DiscoveredEndpoint(url="https://app.test/search", method="GET", status_code=200, content_type="text/html", query_params=["q"]),
            DiscoveredEndpoint(url="https://app.test/login", method="GET", status_code=200, content_type="text/html"),
        ],
        parameters={"q": ["https://app.test/search?q=test"]},
        forms=[{"action": "https://app.test/login", "method": "POST", "inputs": ["user", "pass"]}],
    )

    mock_score = {
        "overall_score": 90,
        "grade": "A",
        "risk_level": "LOW",
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "category_scores": {},
    }

    with patch("app.tasks.scan_task.AsyncSessionLocal", return_value=mock_db), \
         patch("app.utils.safe_http.async_resolve_and_pin", new=AsyncMock(return_value=(True, "", "https://app.test", "https://93.184.216.34", "app.test"))), \
         patch("app.scanner.dns_checker.analyze_dns", new=AsyncMock(return_value={"findings": [], "dns_info": {}})), \
         patch("app.scanner.ssl_checker.analyze_ssl", new=AsyncMock(return_value={"findings": [], "issues": []})), \
         patch("app.scanner.header_analyzer.analyze_headers", new=AsyncMock(return_value={"findings": [], "headers": {}, "raw_headers": {}})), \
         patch("app.scanner.tech_detector.detect_technologies", new=AsyncMock(return_value={"findings": [], "detected_technologies": {}, "html_body": "<html></html>"})), \
         patch("app.scanner.content_analyzer.analyze_content", new=AsyncMock(return_value={"findings": []})), \
         patch("app.scanner.cve_checker.check_all_technologies", new=AsyncMock(return_value=[])), \
         patch("app.scanner.scoring.calculate_score", return_value=mock_score), \
         patch("app.scanner.scoring.generate_executive_summary", return_value="Summary"), \
         patch("app.scanner.scoring.generate_enriched_executive_summary", return_value={}), \
         patch("app.scanner.crawler.ControlledCrawler.crawl", new_callable=AsyncMock, return_value=mock_crawl):

        res = await run_scan_job(ctx, scan_id)

    assert res["status"] == "completed"

    reports = [o for o in added_objects if isinstance(o, Report)]
    assert len(reports) == 1
    report = reports[0]

    # Verify discovered_endpoints has all 3 crawled endpoints
    assert len(report.discovered_endpoints) == 3
    urls = [ep["url"] for ep in report.discovered_endpoints]
    assert "https://app.test/search" in urls
    assert "https://app.test/login" in urls

    # Verify OWASP matrix has 10 categories
    assert len(report.owasp_summary) == 10
    valid_states = {"PASS", "FAIL", "INCONCLUSIVE", "NOT_APPLICABLE", "NOT_VERIFIABLE"}
    for cat_key, cat_data in report.owasp_summary.items():
        assert cat_data["status"] in valid_states
