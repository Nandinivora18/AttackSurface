"""
SentinelScan Durable Scan Task.

Executed by ARQ workers. The scan_id is the only argument needed;
all data is loaded from the database inside the worker.

Design:
- Idempotent: exits cleanly if scan already completed/cancelled
- Race-safe cancellation: cooperative checks between every stage
- Short transactions: no long-held DB locks during network I/O
- Progress: published to Redis pub/sub (cross-process SSE delivery)
- Terminal state order: persist everything → commit → mark completed → publish event
"""
import asyncio
import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Any

from arq.worker import Retry

from app.config import settings

from sqlalchemy import select, update

from app.database import AsyncSessionLocal
from app.models.scan import Scan, ScanStatus
from app.models.report import Report
from app.models.finding import Finding, Confidence
from app.models.misc import Notification
from app.utils.progress import publish_progress
from app.utils.sanitize import sanitize_finding_data, redact_secrets

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Cancellation helper                                                          #
# --------------------------------------------------------------------------- #

async def _is_cancelled(scan_id: str) -> bool:
    """Check the DB for cancellation. Called cooperatively between stages."""
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Scan.status).where(Scan.id == uuid.UUID(scan_id))
            )
            status_val = result.scalar_one_or_none()
            return status_val == ScanStatus.cancelled
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Progress helper                                                              #
# --------------------------------------------------------------------------- #

async def _emit(ctx: dict, scan_id: str, progress: int, stage: str,
                message: str, status: str = "running",
                report_id: str | None = None,
                findings_count: int | None = None) -> None:
    """Emit a progress event and persist to DB (short commit)."""
    redis = ctx.get("redis")

    # Persist current progress to DB for reconnect recovery
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Scan).where(Scan.id == uuid.UUID(scan_id))
            )
            scan = result.scalar_one_or_none()
            if scan and scan.status == ScanStatus.running:
                scan.progress = progress
                scan.current_stage = stage
                await db.commit()
    except Exception as e:
        logger.warning(f"SCAN_STAGE progress DB persist failed: {e}")

    # Publish to Redis pub/sub for live SSE delivery
    if redis:
        await publish_progress(
            redis, scan_id, progress, stage, message, status,
            report_id=report_id, findings_count=findings_count
        )
    else:
        logger.debug(f"[scan:{scan_id}] {progress}% {stage}: {message}")


# --------------------------------------------------------------------------- #
# Main job function                                                            #
# --------------------------------------------------------------------------- #

_AUTO_PASS_TITLE_KW = ["configured", "supported", "present", "enforced", "valid"]
_AUTO_PASS_NEGATION_KW = [
    "missing", "expired", "vulnerable", "insecure", "misconfiguration",
    "weak", "unsupported", "failed",
]


def _is_auto_passed_control(finding: dict) -> bool:
    """A "positive control" finding (info severity, or an affirmative title like
    "CSP Configured" / "TLS Supported") that records a passed control rather than
    an open vulnerability. Persistent Findings are tagged with these and the
    report/filter/stats views exclude them from open counts."""
    title_lower = (finding.get("title") or "").lower()
    sev_lower = (finding.get("severity") or "").lower()
    if sev_lower == "info" or any(kw in title_lower for kw in _AUTO_PASS_TITLE_KW):
        if not any(bad in title_lower for bad in _AUTO_PASS_NEGATION_KW):
            return True
    return False


def _normalize_host_or_endpoint(endpoint: str | None, default_url: str = "") -> str:
    """Normalize endpoint or URL to a host/hostname for host-wide control deduplication."""
    from urllib.parse import urlparse
    target = (endpoint or default_url or "").strip()
    if not target:
        return ""
    if "://" in target:
        try:
            p = urlparse(target)
            return (p.hostname or target).lower()
        except Exception:
            pass
    if ":" in target and not target.startswith("http"):
        host_part, _, _ = target.partition(":")
        return host_part.lower()
    return target.lower()


def get_finding_identity(finding: dict, target_url: str = "") -> tuple:
    """
    Computes a canonical finding identity key used for deduplication.

    Deduplication semantics:
    1. Host-wide security controls (e.g. Missing HSTS, Missing CSP) are keyed by
       their canonical control identity + normalized host, preventing duplicate findings
       when the same condition is observed across multiple stages, modules, or redirects.
    2. Missing HSTS specifically (whether completely absent or present-with-empty-value)
       normalizes to ('HSTS_MISSING', normalized_host).
    3. Asset/endpoint-specific findings (e.g. cookie flags for specific cookies, parameter
       vulnerabilities) retain their specific identity so distinct issues are never merged.
    """
    title = (finding.get("title") or "").strip()
    category = (finding.get("category") or "").strip()
    endpoint = (finding.get("endpoint") or target_url or "").strip()
    title_lower = title.lower()

    # Canonical identity for Missing HSTS
    if "strict transport security" in title_lower and "missing" in title_lower:
        return ("HSTS_MISSING", _normalize_host_or_endpoint(endpoint, target_url))

    # Host-wide missing security headers (e.g. Missing CSP, Missing X-Frame-Options, etc.)
    if title_lower.startswith("missing ") and any(
        h in title_lower for h in [
            "content security policy", "x-frame-options", "x-content-type-options",
            "referrer-policy", "permissions-policy", "x-xss-protection",
            "cross-origin-opener-policy", "cross-origin-embedder-policy",
            "cross-origin-resource-policy"
        ]
    ):
        return ("HEADER_MISSING", title_lower, _normalize_host_or_endpoint(endpoint, target_url))

    # General finding identity
    return (category.lower(), title_lower, endpoint.lower())


def deduplicate_findings(findings: list[dict], target_url: str = "") -> list[dict]:
    """
    Deduplicates findings while strictly preserving finding order and legitimate distinct issues.
    The first observed finding of each identity is retained; subsequent duplicates are dropped.
    """
    seen_identities: set[tuple] = set()
    deduped: list[dict] = []
    for f in findings:
        ident = get_finding_identity(f, target_url)
        if ident not in seen_identities:
            seen_identities.add(ident)
            deduped.append(f)
        else:
            logger.debug(f"Deduplicated duplicate finding: title='{f.get('title')}' identity={ident}")
    return deduped

async def run_scan_job(ctx: dict, scan_id: str) -> dict:
    """
    ARQ job function for running a security scan.

    Args:
        ctx:     ARQ worker context (contains 'redis', 'job_id', 'job_try')
        scan_id: UUID string of the Scan record to process

    Returns:
        dict with result summary

    Retry semantics:
        - job_try=1 on first attempt, incremented by ARQ on each retry
        - On attempt < WORKER_MAX_TRIES: non-fatal exceptions re-raise so ARQ retries
        - On final attempt (job_try >= WORKER_MAX_TRIES): scan is marked failed
        - asyncio.TimeoutError: treated as final failure (marks failed immediately)
        - DB cancelled/completed states always win over job retry state
    """
    job_id = ctx.get("job_id", "unknown")
    job_try = ctx.get("job_try", 1)
    redis = ctx.get("redis")
    max_tries = settings.WORKER_MAX_TRIES
    is_final_attempt = job_try >= max_tries

    logger.info(f"SCAN_STARTED scan_id={scan_id} job_id={job_id} attempt={job_try}")

    # ── PHASE 1: Load and validate scan (short transaction) ──────────────── #
    scan_user_email: str | None = None
    scan_user_name: str = "User"
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
        scan = result.scalar_one_or_none()

        if not scan:
            logger.error(f"SCAN_NOT_FOUND scan_id={scan_id}")
            return {"status": "not_found", "scan_id": scan_id}

        # ── IDEMPOTENCY: Exit safely if already terminal ──────────────── #
        if scan.status in (ScanStatus.completed, ScanStatus.cancelled):
            logger.info(
                f"SCAN_SKIP_DUPLICATE scan_id={scan_id} status={scan.status} "
                f"(duplicate delivery or replay — exiting)"
            )
            return {"status": scan.status.value, "scan_id": scan_id, "skipped": True}

        # INVALID STATE: If somehow in failed state, worker should not re-run
        # (retries come via ARQ re-delivery, not by finding a failed scan)
        # Guard against re-running a scan that was already permanently failed.
        # job_try == 1 means first delivery (not a retry): a pre-existing 'failed'
        # state is stale/duplicate, skip. For retries (job_try > 1) ARQ re-delivers
        # after a transient error; status should still be 'running' from the prior
        # attempt. If it has somehow become 'failed' on a retry, also skip to avoid
        # violating the terminal-state contract.
        if scan.status == ScanStatus.failed:
            logger.warning(f"SCAN_ALREADY_FAILED scan_id={scan_id} job_try={job_try} — skipping")
            return {"status": "already_failed", "scan_id": scan_id}

        # ── Mark running atomically (only pending -> running) ───────────── #
        # Guard against cancellation race: if the scan was cancelled between the
        # initial SELECT and this write, or was already terminal, rowcount is 0.
        # Worker must NEVER revive a cancelled scan or overwrite a terminal state.
        upd = await db.execute(
            update(Scan)
            .where(
                Scan.id == uuid.UUID(scan_id),
                Scan.status == ScanStatus.pending,
            )
            .values(
                status=ScanStatus.running,
                current_stage="Initializing",
                progress=0,
                task_id=job_id,
            )
            .execution_options(synchronize_session=False)
        )
        if upd.rowcount == 0:
            await db.commit()
            refetch = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
            current = refetch.scalar_one_or_none()
            current_status = current.status.value if current else "unknown"
            logger.info(
                f"SCAN_CLAIM_FAILED scan_id={scan_id} current_status={current_status} "
                f"(expected pending) — stopping cleanly without overwrite"
            )
            return {"status": current_status, "scan_id": scan_id, "skipped": True}

        await db.commit()

        url = scan.url
        scan_id_str = str(scan.id)
        user_id = scan.user_id
        scan_mode = scan.scan_mode or "passive"
        scope_data = scan.scope_config or {}
        auth_context = scope_data.get("auth_context")
        design_questionnaire = scope_data.get("design_questionnaire")
        openapi_spec = scope_data.get("openapi_spec")

    logger.info(f"SCAN_RUNNING scan_id={scan_id} url={url} job_id={job_id}")

    # Notify SSE that scan is now running
    await _emit(ctx, scan_id, 0, "Initializing", "Scan worker started", "running")

    # ── PHASE 2: Execute scanner stages ─────────────────────────────────── #
    from urllib.parse import urlparse
    from app.scanner.ssl_checker import analyze_ssl
    from app.scanner.header_analyzer import analyze_headers
    from app.scanner.dns_checker import analyze_dns
    from app.scanner.tech_detector import detect_technologies
    from app.scanner.content_analyzer import analyze_content
    from app.scanner.cve_checker import check_all_technologies
    from app.scanner.scoring import (
        calculate_score, generate_executive_summary,
        generate_enriched_executive_summary
    )
    from app.scanner.threat_intel import get_threat_intel, enrich_finding_recommendation
    from app.services.email_service import send_scan_complete_email

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    all_findings: list[dict] = []
    cve_findings: list[dict] = []  # Initialised here so it is always defined regardless of versioned_count

    # Real wall-clock timing per stage (monotonic — unaffected by NTP adjustments)
    _t: dict[str, float] = {}

    try:
        # ── SSRF GUARD: Re-validate the target at execution time ───────── #
        # The enqueue-time check (scans.py) can be raced via DNS rebinding or
        # stale resolution. Before ANY network stage runs, re-resolve and
        # re-validate the target. Fail-closed: a non-public or non-resolvable
        # destination is never scanned, and the scan is marked failed with the
        # SSRF reason (not retried — this is a permanent policy block).
        from app.utils.safe_http import async_resolve_and_pin
        target_safe, target_reason, _clean_url, _conn_url, _host_header = await async_resolve_and_pin(url)
        if not target_safe or not _conn_url or _host_header is None:
            reason = f"Target blocked by SSRF validation: {target_reason}"
            logger.warning(f"SCAN_SSRF_BLOCKED scan_id={scan_id} url={url} reason={target_reason}")
            await _mark_failed_safe(scan_id, reason, redis)
            return {"status": "failed", "scan_id": scan_id, "error": "ssrf_blocked"}

        # The validated, pinned connection URL hands the scanner a public IP
        # literal for the destination. DNS-rebinding defence: the DNS stages
        # (DNS analysis, SSL handshake) must dial THAT pinned literal, never a
        # second attacker-controlled resolution.
        target_ip = urlparse(_conn_url).hostname

        # ── Stage 1: DNS (0→15%) ─────────────────────────────────────── #
        if await _is_cancelled(scan_id):
            await _handle_cancellation(ctx, scan_id, redis)
            return {"status": "cancelled", "scan_id": scan_id}

        await _emit(ctx, scan_id, 5, "DNS Lookup", f"Resolving DNS records for {hostname}")
        _t["dns_start"] = time.monotonic()
        dns_result = await asyncio.wait_for(analyze_dns(hostname), timeout=30.0)
        _t["dns_ms"] = round((time.monotonic() - _t["dns_start"]) * 1000)
        for f in dns_result.get("findings", []):
            f.setdefault("endpoint", hostname)
        all_findings.extend(dns_result["findings"])
        await _emit(ctx, scan_id, 15, "DNS Lookup", "DNS analysis complete")

        # ── Stage 2: SSL/TLS (15→35%) ───────────────────────────────── #
        if await _is_cancelled(scan_id):
            await _handle_cancellation(ctx, scan_id, redis)
            return {"status": "cancelled", "scan_id": scan_id}

        await _emit(ctx, scan_id, 20, "SSL/TLS Analysis", f"Analyzing SSL certificate for {hostname}")
        _t["ssl_start"] = time.monotonic()
        ssl_result = await asyncio.wait_for(analyze_ssl(hostname, port=443, resolved_ip=target_ip), timeout=30.0)
        _t["ssl_ms"] = round((time.monotonic() - _t["ssl_start"]) * 1000)
        for issue in ssl_result.get("issues", []):
            all_findings.append({
                "category": "SSL/TLS",
                "title": issue["message"],
                "description": "SSL/TLS configuration issue detected.",
                "severity": issue["severity"],
                "confidence": "high",
                "cvss_score": None,
                "recommendation": "Review and update your SSL/TLS configuration.",
                "references": ["https://ssl-config.mozilla.org/"],
                "endpoint": f"{hostname}:443",
                "evidence": f"Host: {hostname}:443",
            })
        await _emit(ctx, scan_id, 35, "SSL/TLS Analysis", "SSL analysis complete")

        # ── Stage 3: HTTP Headers (35→55%) ──────────────────────────── #
        if await _is_cancelled(scan_id):
            await _handle_cancellation(ctx, scan_id, redis)
            return {"status": "cancelled", "scan_id": scan_id}

        await _emit(ctx, scan_id, 40, "Header Analysis", "Fetching and analyzing HTTP response headers")
        _t["headers_start"] = time.monotonic()
        header_result = await asyncio.wait_for(analyze_headers(url), timeout=30.0)
        _t["headers_ms"] = round((time.monotonic() - _t["headers_start"]) * 1000)
        for f in header_result.get("findings", []):
            f.setdefault("endpoint", url)
        all_findings.extend(header_result["findings"])
        await _emit(ctx, scan_id, 55, "Header Analysis", f"Found {len(header_result['findings'])} header issues")

        # ── Stage 4: Technology Detection (55→70%) ───────────────────── #
        if await _is_cancelled(scan_id):
            await _handle_cancellation(ctx, scan_id, redis)
            return {"status": "cancelled", "scan_id": scan_id}

        await _emit(ctx, scan_id, 60, "Technology Detection", "Fingerprinting technology stack and CMS")
        _t["tech_start"] = time.monotonic()
        tech_result = await asyncio.wait_for(detect_technologies(url), timeout=45.0)
        _t["tech_ms"] = round((time.monotonic() - _t["tech_start"]) * 1000)
        for f in tech_result.get("findings", []):
            f.setdefault("endpoint", url)
        all_findings.extend(tech_result["findings"])
        detected_techs = tech_result["detected_technologies"]
        versioned_count = sum(1 for t in detected_techs.values() if t.get("version"))
        await _emit(ctx, scan_id, 70, "Technology Detection",
                    f"Detected {len(detected_techs)} technologies ({versioned_count} with versions)")

        # ── Stage 4b: CVE Lookup (70→85%) ────────────────────────────── #
        # Always initialize so cve_findings is defined regardless of branch.
        cve_findings: list = []
        if versioned_count > 0:
            if await _is_cancelled(scan_id):
                await _handle_cancellation(ctx, scan_id, redis)
                return {"status": "cancelled", "scan_id": scan_id}

            await _emit(ctx, scan_id, 72, "CVE Database Lookup",
                        f"Querying NVD database for {versioned_count} versioned technologies…")

            _cve_progress_state = {"count": 0}

            async def _cve_progress(msg: str):
                _cve_progress_state["count"] += 1
                pct = min(85, 72 + _cve_progress_state["count"] * 3)
                await _emit(ctx, scan_id, pct, "CVE Database Lookup", msg)

            _t["cve_start"] = time.monotonic()
            cve_findings = await asyncio.wait_for(
                check_all_technologies(detected_techs, progress_callback=_cve_progress),
                timeout=120.0
            )
            _t["cve_ms"] = round((time.monotonic() - _t["cve_start"]) * 1000)
            for f in cve_findings:
                f.setdefault("endpoint", f"{hostname} — {f.get('title', '')}")
            all_findings.extend(cve_findings)
            await _emit(ctx, scan_id, 85, "CVE Database Lookup",
                        f"Found {len(cve_findings)} CVE{'s' if len(cve_findings) != 1 else ''}")
        else:
            _t["cve_ms"] = 0
            await _emit(ctx, scan_id, 85, "CVE Database Lookup",
                        "No versioned technologies detected — skipping CVE lookup")

        # ── Stage 5: Content Analysis (85→92%) ──────────────────────── #
        if await _is_cancelled(scan_id):
            await _handle_cancellation(ctx, scan_id, redis)
            return {"status": "cancelled", "scan_id": scan_id}

        await _emit(ctx, scan_id, 86, "Content Analysis",
                    "Probing for exposed files, emails, and sensitive content")
        _t["content_start"] = time.monotonic()
        content_result = await asyncio.wait_for(analyze_content(url), timeout=45.0)
        _t["content_ms"] = round((time.monotonic() - _t["content_start"]) * 1000)
        for f in content_result.get("findings", []):
            f.setdefault("endpoint", url)
        all_findings.extend(content_result["findings"])
        await _emit(ctx, scan_id, 87, "Content Analysis",
                    f"Found {len(content_result['findings'])} content issues")

        # ── Stage 5b: Component Intelligence & Lifecycle Analysis ────── #
        if await _is_cancelled(scan_id):
            await _handle_cancellation(ctx, scan_id, redis)
            return {"status": "cancelled", "scan_id": scan_id}

        await _emit(ctx, scan_id, 87, "Component Intelligence", "Analyzing component lifecycles and support status")
        from app.scanner.component_engine import build_component_inventory
        component_inventory_data, lifecycle_findings = await build_component_inventory(
            detected_techs, cve_findings if versioned_count > 0 else [], redis_client=redis
        )
        all_findings.extend(lifecycle_findings)

        # ── Stage 5c: Controlled Same-Origin Crawler ─────────────────── #
        is_active = scan_mode in ("safe_active", "authenticated_safe_active")
        crawl_result = None
        discovered_endpoints_data = []

        if is_active:
            if await _is_cancelled(scan_id):
                await _handle_cancellation(ctx, scan_id, redis)
                return {"status": "cancelled", "scan_id": scan_id}

            await _emit(ctx, scan_id, 88, "Same-Origin Crawler", f"Crawling same-origin endpoints for {hostname}")
            _t["crawler_start"] = time.monotonic()
            from app.scanner.crawler import SameOriginCrawler
            crawler = SameOriginCrawler(
                base_url=url,
                max_pages=min(scope_data.get("max_pages", 20) or 20, 20),
                max_depth=min(scope_data.get("max_crawl_depth", 2) or 2, 2),
                max_requests=min(scope_data.get("max_requests", 50) or 50, 50),
            )
            crawl_result = await crawler.crawl()
            _t["crawler_ms"] = round((time.monotonic() - _t["crawler_start"]) * 1000)
            discovered_endpoints_data = [ep.to_dict() for ep in crawl_result.discovered_endpoints]
            await _emit(ctx, scan_id, 89, "Same-Origin Crawler",
                        f"Discovered {len(discovered_endpoints_data)} endpoints, {len(crawl_result.parameters)} parameters")
        else:
            discovered_endpoints_data = [{"url": url, "method": "GET", "status": 200, "depth": 0, "content_type": "text/html"}]

        # ── Stage 5d: OWASP Top 10 Assessment Modules ────────────────── #
        if await _is_cancelled(scan_id):
            await _handle_cancellation(ctx, scan_id, redis)
            return {"status": "cancelled", "scan_id": scan_id}

        await _emit(ctx, scan_id, 90, "OWASP Top 10 Assessment", "Synthesizing OWASP Top 10 assessment matrix")
        _t["owasp_start"] = time.monotonic()
        from app.scanner.modules import (
            assess_a01_access_control,
            assess_a02_misconfiguration,
            assess_a03_supply_chain,
            assess_a04_cryptography,
            assess_a05_injection,
            assess_a06_insecure_design,
            assess_a07_authentication,
            assess_a08_integrity,
            assess_a09_logging,
            assess_a10_exceptional_conditions,
        )

        raw_cookies = header_result.get("cookies", []) or [
            v for k, v in header_result.get("raw_headers", {}).items() if k.lower() == "set-cookie"
        ]
        crawled_html = (
            [ep.get("sample_text", "") for ep in discovered_endpoints_data if ep.get("sample_text")]
            if is_active else [tech_result.get("html_body", "")]
        )
        if not any(crawled_html):
            crawled_html = [tech_result.get("html_body", "")]

        a01_res = await assess_a01_access_control(
            url,
            header_result.get("headers", {}),
            list(crawl_result.visited_urls) if crawl_result else [url],
            discovered_parameters=crawl_result.parameters if crawl_result else {},
            auth_context=auth_context,
            probe_active=is_active,
        )

        a02_res = await assess_a02_misconfiguration(
            url,
            header_result.get("findings", []),
            dns_result.get("findings", []),
            content_result.get("findings", []),
            headers=header_result.get("headers", {}),
            probe_active=is_active,
        )

        a03_res = await assess_a03_supply_chain(
            target_url=url,
            component_inventory=component_inventory_data,
            cve_findings=cve_findings if versioned_count > 0 else [],
            crawled_html_samples=crawled_html,
            external_scripts=crawl_result.external_scripts if crawl_result else [],
        )

        a04_res = await assess_a04_cryptography(
            url,
            ssl_result.get("issues", []),
            header_result.get("headers", {}),
            crawled_html_samples=crawled_html,
        )

        a05_res = await assess_a05_injection(
            crawl_result.parameters if crawl_result else {},
        )

        a06_res = await assess_a06_insecure_design(
            design_questionnaire=design_questionnaire,
            openapi_spec=openapi_spec,
        )

        a07_res = await assess_a07_authentication(
            url,
            raw_cookies=raw_cookies,
            discovered_urls=list(crawl_result.visited_urls) if crawl_result else [url],
            crawled_forms=crawl_result.forms if crawl_result else [],
            response_headers=header_result.get("headers", {}),
        )

        a08_res = await assess_a08_integrity(
            url,
            crawled_html_samples=crawled_html,
            external_scripts=crawl_result.external_scripts if crawl_result else [],
        )

        a09_res = await assess_a09_logging(
            url,
            header_result.get("headers", {}),
            content_findings=content_result.get("findings", []),
            probe_active=is_active,
        )

        a10_res = await assess_a10_exceptional_conditions(
            target_url=url,
            content_findings=content_result.get("findings", []),
            crawled_html_samples=crawled_html,
            probe_active=is_active,
        )
        _t["owasp_ms"] = round((time.monotonic() - _t["owasp_start"]) * 1000)

        owasp_matrix = {
            "A01_BrokenAccessControl": {
                "name": "Broken Access Control",
                "status": a01_res["status"],
                "confidence": a01_res["confidence"],
                "method": a01_res["method"],
                "findings_count": len(a01_res["findings"]),
                "limitations": a01_res["limitations"],
            },
            "A02_SecurityMisconfiguration": {
                "name": "Security Misconfiguration",
                "status": a02_res["status"],
                "confidence": a02_res["confidence"],
                "method": a02_res["method"],
                "findings_count": len(a02_res["findings"]),
                "limitations": a02_res["limitations"],
            },
            "A03_SoftwareSupplyChainFailures": {
                "name": "Software Supply Chain Failures",
                "status": a03_res["status"],
                "confidence": a03_res["confidence"],
                "method": a03_res["method"],
                "findings_count": len(a03_res["findings"]),
                "limitations": a03_res["limitations"],
            },
            "A04_CryptographicFailures": {
                "name": "Cryptographic Failures",
                "status": a04_res["status"],
                "confidence": a04_res["confidence"],
                "method": a04_res["method"],
                "findings_count": len(a04_res["findings"]),
                "limitations": a04_res["limitations"],
            },
            "A05_Injection": {
                "name": "Injection",
                "status": a05_res["status"],
                "confidence": a05_res["confidence"],
                "method": a05_res["method"],
                "findings_count": len(a05_res["findings"]),
                "limitations": a05_res["limitations"],
            },
            "A06_InsecureDesign": {
                "name": "Insecure Design",
                "status": a06_res["status"],
                "confidence": a06_res["confidence"],
                "method": a06_res["method"],
                "findings_count": len(a06_res["findings"]),
                "limitations": a06_res["limitations"],
            },
            "A07_AuthenticationFailures": {
                "name": "Authentication Failures",
                "status": a07_res["status"],
                "confidence": a07_res["confidence"],
                "method": a07_res["method"],
                "findings_count": len(a07_res["findings"]),
                "limitations": a07_res["limitations"],
            },
            "A08_SoftwareOrDataIntegrityFailures": {
                "name": "Software or Data Integrity Failures",
                "status": a08_res["status"],
                "confidence": a08_res["confidence"],
                "method": a08_res["method"],
                "findings_count": len(a08_res["findings"]),
                "limitations": a08_res["limitations"],
            },
            "A09_SecurityLoggingAndAlertingFailures": {
                "name": "Security Logging and Alerting Failures",
                "status": a09_res["status"],
                "confidence": a09_res["confidence"],
                "method": a09_res["method"],
                "findings_count": len(a09_res["findings"]),
                "limitations": a09_res["limitations"],
            },
            "A10_MishandlingOfExceptionalConditions": {
                "name": "Mishandling of Exceptional Conditions",
                "status": a10_res["status"],
                "confidence": a10_res["confidence"],
                "method": a10_res["method"],
                "findings_count": len(a10_res["findings"]),
                "limitations": a10_res["limitations"],
            },
        }

        # Deduplicated merge of active OWASP findings into all_findings
        existing_keys = {get_finding_identity(f, url) for f in all_findings}
        for mod_res in [a01_res, a02_res, a03_res, a04_res, a05_res, a06_res, a07_res, a08_res, a09_res, a10_res]:
            for finding_item in mod_res.get("findings", []):
                key = get_finding_identity(finding_item, url)
                if key not in existing_keys:
                    existing_keys.add(key)
                    all_findings.append(finding_item)

        # Global deduplication pass across all collected findings
        all_findings = deduplicate_findings(all_findings, url)

        # ── Stage 5a: Clamp target-controlled strings ─────────────────── #
        # Hostile targets can return oversized header/DNS/content values.
        # Clamping BEFORE enrichment and persistence prevents DB column
        # overflow (Postgres insert failures) and report bloat downstream.
        for finding in all_findings:
            sanitize_finding_data(finding)

        # ── Stage 5a-b: Normalize confidence values ──────────────────── #
        # Ensure every finding has a valid Confidence enum value.
        # Detectors that omit confidence get "high" (deterministic evidence).
        # Non-standard values ("confirmed", "none", etc.) are mapped to the
        # nearest valid enum member.
        _VALID_CONFIDENCE = {"high", "medium", "low"}
        _CONFIDENCE_MAP = {"confirmed": "high", "none": "low"}
        for finding in all_findings:
            conf = finding.get("confidence", "high")
            if conf not in _VALID_CONFIDENCE:
                finding["confidence"] = _CONFIDENCE_MAP.get(conf, "high")

        # ── Stage 5a-c: Classify "passed control" findings BEFORE scoring ─ #
        # Scoring (severity_counts, risk_level), the executive summary, and the
        # asset open_* counts all consume is_passed_control. Computing it here —
        # before calculate_score() — guarantees every downstream consumer agrees
        # on which findings are open vulnerabilities. Previously the flag was
        # only derived inside the persist loop, so severity_counts/exec summary/
        # asset counts over-counted auto-passed info findings (stats page
        # disagreed with the report's "passed" filter).
        for finding in all_findings:
            finding["is_passed_control"] = (
                finding.get("is_passed_control", False) or _is_auto_passed_control(finding)
            )

        # ── Stage 5b: Threat Intel enrichment ────────────────────────── #
        if await _is_cancelled(scan_id):
            await _handle_cancellation(ctx, scan_id, redis)
            return {"status": "cancelled", "scan_id": scan_id}

        await _emit(ctx, scan_id, 93, "Threat Intel",
                    "Mapping findings to OWASP Top 10, MITRE ATT&CK, and remediation steps")
        for finding in all_findings:
            intel = get_threat_intel(finding.get("category", ""), finding.get("title", ""))
            finding["owasp_mapping"] = intel["owasp"]
            finding["mitre_mapping"] = intel["mitre"]
            enrich_finding_recommendation(finding)

        # ── Stage 6: Scoring (93→95%) ────────────────────────────────── #
        if await _is_cancelled(scan_id):
            await _handle_cancellation(ctx, scan_id, redis)
            return {"status": "cancelled", "scan_id": scan_id}

        await _emit(ctx, scan_id, 95, "Generating Report", "Calculating security score")
        _t["scoring_start"] = time.monotonic()
        score_data = calculate_score(all_findings)
        summary = generate_executive_summary(
            url,
            score_data["overall_score"],
            score_data["grade"],
            score_data["severity_counts"],
            detected_techs,
        )
        enriched_exec_summary = generate_enriched_executive_summary(
            url,
            score_data["overall_score"],
            score_data["grade"],
            score_data["severity_counts"],
            all_findings,
            score_data["category_scores"],
        )
        _t["scoring_ms"] = round((time.monotonic() - _t["scoring_start"]) * 1000)

        now_iso = datetime.now(timezone.utc).isoformat()
        # Real measured durations — NOT hardcoded placeholders.
        # Each _t["*_ms"] value was captured by time.monotonic() around the actual stage call.
        stage_timeline = [
            {"stage": "queued", "label": "Queued", "status": "completed", "duration_ms": None},
            {"stage": "initializing", "label": "Initializing", "status": "completed", "duration_ms": None},
            {"stage": "dns", "label": "DNS Analysis", "status": "completed", "duration_ms": _t.get("dns_ms")},
            {"stage": "ssl", "label": "SSL/TLS Check", "status": "completed", "duration_ms": _t.get("ssl_ms")},
            {"stage": "headers", "label": "Security Headers", "status": "completed", "duration_ms": _t.get("headers_ms")},
            {"stage": "technology", "label": "Technology Detection", "status": "completed", "duration_ms": _t.get("tech_ms")},
            {"stage": "cve", "label": "CVE Database Lookup", "status": "completed", "duration_ms": _t.get("cve_ms")},
            {"stage": "content", "label": "Content Analysis", "status": "completed", "duration_ms": _t.get("content_ms")},
            {"stage": "scoring", "label": "Scoring Engine", "status": "completed", "duration_ms": _t.get("scoring_ms")},
            {"stage": "completed", "label": "Scan Completed", "status": "completed",
             "duration_ms": None, "timestamp": now_iso},
        ]

        # ── PHASE 3: Persist results ─────────────────────────────────── #
        # Final cancellation check BEFORE writing any results.
        # This prevents: cancelled → completed
        if await _is_cancelled(scan_id):
            await _handle_cancellation(ctx, scan_id, redis)
            return {"status": "cancelled", "scan_id": scan_id}

        await _emit(ctx, scan_id, 95, "Generating Report", "Persisting findings to database")
        scan_user_email = None
        scan_user_name = None
        report_id = None

        async with AsyncSessionLocal() as db:
            # Re-check scan state inside transaction (race-safe)
            result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
            scan = result.scalar_one_or_none()
            if not scan:
                raise RuntimeError(f"Scan {scan_id} disappeared during execution")

            if scan.status == ScanStatus.cancelled:
                logger.info(f"SCAN_CANCELLED_BEFORE_PERSIST scan_id={scan_id} — not writing results")
                await _handle_cancellation(ctx, scan_id, redis)
                return {"status": "cancelled", "scan_id": scan_id}

            # ── IDEMPOTENCY: Check for existing report ──────────────── #
            existing_report = await db.execute(
                select(Report).where(Report.scan_id == scan.id)
            )
            if existing_report.scalar_one_or_none():
                logger.warning(
                    f"SCAN_DUPLICATE_REPORT scan_id={scan_id} — report already exists, "
                    "skipping (idempotent duplicate delivery)"
                )
                return {"status": "completed", "scan_id": scan_id, "skipped": True}

            # Redact credential-bearing raw header values before persistence.
            # Set-Cookie, Authorization, and API-key values land verbatim in
            # the response header dict and must be sanitized to match the
            # policy enforced everywhere else (PDF, probes, export).
            _clean_raw = {
                str(k): redact_secrets(str(v))
                for k, v in (header_result.get("raw_headers") or {}).items()
            }
            report = Report(
                scan_id=scan.id,
                user_id=scan.user_id,
                overall_score=score_data["overall_score"],
                grade=score_data["grade"],
                risk_level=score_data["risk_level"],
                summary=summary,
                scan_mode=scan_mode,
                executive_summary=enriched_exec_summary,
                tech_stack=detected_techs,
                raw_headers=_clean_raw,
                ssl_info={
                    "certificate": ssl_result.get("certificate", {}),
                    "tls_version": ssl_result.get("tls_version"),
                    "cipher": ssl_result.get("cipher"),
                    "issues": ssl_result.get("issues", []),
                },
                dns_info=dns_result["dns_info"],
                score_breakdown=score_data["category_scores"],
                timeline=stage_timeline,
                owasp_summary=owasp_matrix,
                discovered_endpoints=discovered_endpoints_data,
                component_inventory=component_inventory_data,
            )
            db.add(report)
            await db.flush()
            report_id = str(report.id)

            # Persist findings
            from app.scanner.threat_intel import resolve_finding_location
            for finding_data in all_findings:
                published_date = None
                if finding_data.get("published_date"):
                    try:
                        from datetime import date
                        published_date = date.fromisoformat(finding_data["published_date"])
                    except (ValueError, TypeError):
                        pass

                # is_passed_control was already classified pre-scoring so that
                # severity_counts, risk_level, exec summary, and asset open_*
                # counts all use the same classification as the report filter.
                is_passed = finding_data.get("is_passed_control", False)

                loc_info = resolve_finding_location(finding_data, url)
                resolved_endpoint = finding_data.get("endpoint") or loc_info.get("value")

                # Server-side secret redaction in evidence strings before persistence.
                # Set-Cookie / Authorization / credential-bearing HTTP values sometimes
                # surface in detector evidence; they must be stripped to match the
                # policy enforced in PDF generation, remediation probes, and exports.
                for _evidence_field in ("evidence", "technical_details"):
                    _val = finding_data.get(_evidence_field)
                    if isinstance(_val, str):
                        finding_data[_evidence_field] = redact_secrets(_val)

                finding = Finding(
                    report_id=report.id,
                    category=finding_data.get("category", "General"),
                    title=finding_data.get("title", ""),
                    description=finding_data.get("description", ""),
                    severity=finding_data.get("severity", "info"),
                    confidence=finding_data.get("confidence", "high"),
                    cvss_score=finding_data.get("cvss_score"),
                    cve_id=finding_data.get("cve_id"),
                    cwe_id=finding_data.get("cwe_id"),
                    endpoint=resolved_endpoint,
                    published_date=published_date,
                    recommendation=finding_data.get("recommendation"),
                    problem=finding_data.get("problem"),
                    impact=finding_data.get("impact"),
                    risk_analysis=finding_data.get("risk_analysis"),
                    technical_details=finding_data.get("technical_details"),
                    fix_steps=finding_data.get("fix_steps"),
                    configuration_example=finding_data.get("configuration_example"),
                    best_practices=finding_data.get("best_practices"),
                    official_documentation=finding_data.get("official_documentation"),
                    references=finding_data.get("references", []),
                    evidence=finding_data.get("evidence"),
                    owasp_mapping=finding_data.get("owasp_mapping"),
                    mitre_mapping=finding_data.get("mitre_mapping"),
                    is_passed_control=is_passed,
                )
                db.add(finding)

            # ── Mark scan completed (guarded atomic transition) ───────── #
            # WHERE status='running' closes the lost-update race with a
            # concurrent cancel: if the user cancelled between this transaction's
            # snapshot read and this UPDATE, the guard fails (rowcount == 0) and
            # we roll back instead of overwriting cancelled → completed
            # (terminal states must never transition).
            terminal_update = (
                update(Scan)
                .where(Scan.id == scan.id, Scan.status == ScanStatus.running)
                .values(
                    status=ScanStatus.completed,
                    progress=100,
                    current_stage="Complete",
                    completed_at=datetime.now(timezone.utc),
                    timeline=stage_timeline,
                )
            )
            upd_result = await db.execute(terminal_update.execution_options(synchronize_session=False))
            if upd_result.rowcount == 0:
                # DB state changed underneath us. Distinguish the two benign
                # causes so the terminal SSE event is accurate:
                #   - user cancelled  → publish "cancelled by user"
                #   - reconcile failed the orphan → publish "failed"
                # Both keep the DB terminal state untouched (never clobber it).
                logger.info(f"SCAN_TERMINAL_DURING_PERSIST scan_id={scan_id} — discarding partial results")
                await db.rollback()
                async with AsyncSessionLocal() as recheck_db:
                    cur_status = (
                        await recheck_db.execute(
                            select(Scan.status).where(Scan.id == scan.id)
                        )
                    ).scalar_one_or_none()
                if cur_status == ScanStatus.failed:
                    if redis:
                        await publish_progress(
                            redis, scan_id, 0, "Failed",
                            "Scan failed while the worker was persisting results"
                            " (reconciled by the orphan scanner).",
                            "failed",
                        )
                    return {"status": "failed", "scan_id": scan_id}
                await _handle_cancellation(ctx, scan_id, redis)
                return {"status": "cancelled", "scan_id": scan_id}

            # ── Notification ─────────────────────────────────────────── #
            grade = score_data["grade"]
            overall_score = score_data["overall_score"]
            db.add(Notification(
                user_id=scan.user_id,
                type="scan_complete",
                title=f"Scan Complete — {url}",
                message=f"Security score: {overall_score}/100 (Grade: {grade}). View your report for detailed findings.",
                metadata_={"scan_id": scan_id, "report_id": report_id,
                           "score": overall_score, "grade": grade},
            ))

            # Fetch user for email notification
            scan_user_email = None
            scan_user_name = ""
            from app.models.user import User
            user_res = await db.execute(select(User).where(User.id == scan.user_id))
            scan_user = user_res.scalar_one_or_none()
            if scan_user:
                scan_user_email = scan_user.email
                scan_user_name = scan_user.name

            # Commit ALL results in one transaction — if this fails, scan stays running
            # and ARQ may retry (idempotency check prevents duplicate report on retry)
            await db.commit()

        # ── PHASE 4: Publish terminal event (AFTER commit succeeds) ──── #
        await _emit(
            ctx, scan_id, 100, "Complete", "Scan completed successfully", "completed",
            report_id=str(report_id), findings_count=len(all_findings)
        )

        # ── PHASE 5: Fire-and-forget email ────────────────────────────── #
        if scan_user_email:
            try:
                await send_scan_complete_email(
                    scan_user_email, scan_user_name, url, overall_score, report_id
                )
            except Exception as e:
                logger.warning(f"SCAN_EMAIL_FAILED scan_id={scan_id}: {e}")

        logger.info(
            f"SCAN_COMPLETED scan_id={scan_id} score={score_data['overall_score']} "
            f"grade={score_data['grade']} findings={len(all_findings)} job_id={job_id}"
        )
        return {
            "status": "completed",
            "scan_id": scan_id,
            "score": score_data["overall_score"],
            "grade": score_data["grade"],
            "report_id": report_id,
        }

    except asyncio.TimeoutError:
        # Hard timeout — ARQ's job_timeout or our per-stage asyncio.wait_for
        # Timeouts are treated as permanent failures (not retriable — the target is slow).
        timeout_msg = "Scan exceeded the maximum execution time and was terminated."
        logger.error(f"SCAN_TIMEOUT scan_id={scan_id} job_id={job_id} attempt={job_try}")
        await _mark_failed_safe(scan_id, timeout_msg, redis)
        # Return (not re-raise) — ARQ treats returns as success; we've already persisted failure
        return {"status": "failed", "scan_id": scan_id, "error": timeout_msg}

    except asyncio.CancelledError:
        # Worker was externally cancelled (SIGTERM, job abort, etc.)
        logger.warning(
            f"SCAN_TASK_CANCELLED scan_id={scan_id} job_id={job_id} attempt={job_try}/{max_tries} "
            f"(CancelledError — {'final attempt, marking failed' if is_final_attempt else 'retrying'})"
        )
        if is_final_attempt:
            # No more retries — mark scan as definitively failed
            await _mark_failed_safe(
                scan_id,
                "Scan execution failed after all retry attempts were exhausted (worker was interrupted).",
                redis,
            )
            return {"status": "failed", "scan_id": scan_id, "error": "retry_exhausted"}
        else:
            # Re-raise so ARQ can schedule the next retry.
            # scan.status remains 'running'; ARQ will re-deliver with job_try+1.
            # The scan will be picked up on next delivery without marking failed.
            raise

    except Exception as e:
        logger.error(
            f"SCAN_FAILED scan_id={scan_id} job_id={job_id} attempt={job_try}/{max_tries}: "
            f"{type(e).__name__}: {e}",
            exc_info=True,
        )
        if is_final_attempt:
            # Retry budget exhausted — mark permanently failed
            safe_msg = (
                "Scan execution failed after all retry attempts were exhausted. "
                f"Last error: {type(e).__name__} during {_last_stage(e)}."
            )
            logger.error(f"SCAN_RETRY_EXHAUSTED scan_id={scan_id} job_id={job_id}")
        else:
            # Not the final attempt — explicitly requeue for the next try.
            # IMPORTANT: a bare `raise` here would NOT retry — ARQ only requeues
            # on Retry / non-abort CancelledError (worker.py run_job). Any other
            # exception is terminal (job finished failed, job keys deleted), which
            # would strand the scan in 'running' until the 5-min reconcile cron.
            safe_msg = f"Transient error on attempt {job_try}: {type(e).__name__} during {_last_stage(e)}. Retrying..."
            logger.info(f"SCAN_RETRY scan_id={scan_id} attempt={job_try}/{max_tries} — re-raising for ARQ retry")
            # Update current_stage to show retry state (short transaction, no status change)
            try:
                async with AsyncSessionLocal() as db:
                    r = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
                    s = r.scalar_one_or_none()
                    if s and s.status == ScanStatus.running:
                        s.current_stage = f"Retrying (attempt {job_try}/{max_tries})"
                        s.error_message = f"{type(e).__name__}: {str(e)[:200]}"
                        await db.commit()
            except Exception:
                pass
            raise Retry(defer=2) from None

        await _mark_failed_safe(scan_id, safe_msg, redis)
        return {"status": "failed", "scan_id": scan_id, "error": safe_msg}


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _last_stage(exc: Exception) -> str:
    """Best-effort stage name for error messages."""
    msg = str(exc)
    for stage in ["DNS", "SSL", "header", "technology", "CVE", "content", "scoring", "persist"]:
        if stage.lower() in msg.lower():
            return stage
    return "execution"


async def _handle_cancellation(ctx: dict, scan_id: str, redis) -> None:
    """Emit terminal cancelled event. DB state is already cancelled (set by API)."""
    logger.info(f"SCAN_CANCELLED scan_id={scan_id}")
    if redis:
        await publish_progress(redis, scan_id, 0, "Cancelled", "Scan cancelled by user", "cancelled")


async def _mark_failed_safe(scan_id: str, message: str, redis) -> None:
    """
    Mark a scan as failed via an atomic status-guarded UPDATE.

    Only pending/running scans may transition to failed; a scan already in a
    terminal state (cancelled/completed/failed) is never overwritten, so a
    concurrent user cancel landing just before this write can never be clobbered
    back to failed (same guarded-UPDATE primitive as the completion path).
    """
    try:
        async with AsyncSessionLocal() as db:
            upd = await db.execute(
                update(Scan)
                .where(
                    Scan.id == uuid.UUID(scan_id),
                    Scan.status.in_([ScanStatus.pending, ScanStatus.running]),
                )
                .values(
                    status=ScanStatus.failed,
                    error_message=message,
                    completed_at=datetime.now(timezone.utc),
                    current_stage="Failed",
                )
                .execution_options(synchronize_session=False)
            )
            if upd.rowcount == 0:
                return  # already terminal — never overwrite cancelled/completed

            scan = (
                await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
            ).scalar_one_or_none()
            if scan:
                db.add(Notification(
                    user_id=scan.user_id,
                    type="scan_failed",
                    title=f"Scan Failed — {scan.url}",
                    message=f"The scan encountered an error: {message[:200]}",
                    metadata_={"scan_id": scan_id, "error": message[:500]},
                ))
            await db.commit()
    except Exception as e:
        logger.error(f"SCAN_MARK_FAILED_ERROR scan_id={scan_id}: {e}")
        return

    if redis:
        try:
            await publish_progress(redis, scan_id, 0, "Failed", message, "failed")
        except Exception:
            pass
