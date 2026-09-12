"""
Scans router — POST /api/scans enqueues durable ARQ jobs.
SSE endpoint reads from Redis pub/sub (cross-process progress delivery).
"""
import uuid
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, update
from sqlalchemy.orm import selectinload
from app.database import get_db
from app.models.scan import Scan, ScanStatus
from app.models.report import Report
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse
from app.services.auth_service import get_verified_user
from app.config import settings
from app.utils.security import decode_token
from app.utils.progress import stream_progress_events
from app.utils.cache import (
    RedisBlacklistError,
    consume_sse_ticket,
    is_token_blacklisted,
    issue_sse_ticket,
    get_redis,
)
import json

import socket
import ipaddress
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["Scans"])


# ─── SSRF Protection ────────────────────────────────────────────────────────

def _ssrf_check_blocking(hostname: str) -> tuple[bool, str]:
    """
    Synchronous inner implementation — runs in a thread pool via asyncio.to_thread().
    Never call this directly from async code; use _is_ssrf_safe_url() instead.

    All SSRF blocking logic lives in app.utils.safe_http.resolve_and_validate_host
    (single authoritative implementation):
    - localhost / loopback name literals
    - IPv4 private / loopback / link-local / multicast / reserved / unspecified
    - IPv6 loopback / private / link-local / multicast
    - IPv4-mapped IPv6 addresses (::ffff:...)
    - DNS failures are rejected (fail-closed)
    """
    from app.utils.safe_http import resolve_and_validate_host

    safe, reason, resolved_ips = resolve_and_validate_host(hostname)
    if not safe:
        if not resolved_ips:
            return False, reason
        # Surface the offending destination IP when it resolved to something internal.
        ip_str = resolved_ips[0]
        return False, (
            f"Target hostname '{hostname}' resolves to private/internal IP ({ip_str}). "
            "Scanning internal infrastructure is restricted for SSRF safety."
        )
    return True, ""


async def _is_ssrf_safe_url(url: str) -> tuple[bool, str]:
    """
    Async SSRF URL validator.

    Parses the URL and runs blocking DNS resolution inside a thread pool
    (asyncio.to_thread) so the FastAPI event loop is never blocked — even
    when DNS is slow or times out.

    All actual IP/network validation is delegated to _ssrf_check_blocking.
    Fail-closed: unexpected errors reject the target rather than letting it
    through (a bypass would be worse than a false rejection).
    """
    from urllib.parse import urlparse
    raw = url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    hostname = (parsed.hostname or raw).lower()

    if not hostname:
        return False, "URL contains no valid host destination."

    try:
        # Run blocking DNS + IP validation off the event loop
        return await asyncio.to_thread(_ssrf_check_blocking, hostname)
    except Exception as e:
        # Unexpected error — fail closed: never allow an unvalidated target through.
        return False, f"Unexpected error during SSRF validation of target ({type(e).__name__})."


# ─── ARQ pool helper ─────────────────────────────────────────────────────────

_arq_pool = None
_arq_pool_lock = asyncio.Lock()

SCAN_CREATE_LOCK_TTL = 10


async def _acquire_scan_create_lock(user_id) -> tuple[bool, object]:
    """Best-effort per-user mutex for the scan check+insert window.

    The active-scan and hourly rate-limit checks are not atomic with the
    INSERT: concurrent requests from the same user could all pass the checks
    and exceed the configured limits. Serialize the check+insert window with a
    short-lived per-user Redis lock. Degrades gracefully (no lock) when Redis
    is unavailable — the pre-existing behaviour is preserved.
    """
    try:
        r = await get_redis()
        ok = bool(await r.set(f"scan:create_lock:{user_id}", "1", nx=True, ex=SCAN_CREATE_LOCK_TTL))
        return ok, r
    except Exception:
        return False, None


async def _release_scan_create_lock(user_id, acquired: bool, r: object) -> None:
    if acquired and r is not None:
        try:
            await r.delete(f"scan:create_lock:{user_id}")
        except Exception:
            pass


async def _get_arq_pool():
    """Get the shared ARQ Redis connection pool (created lazily, reused).

    Creating/closing a pool per request is wasteful and adds latency to every
    scan enqueue/cancel. The pool is created once, shared across requests, and
    only closed during application shutdown (see _close_arq_pool).
    """
    global _arq_pool
    if _arq_pool is None:
        async with _arq_pool_lock:
            if _arq_pool is None:
                from arq.connections import create_pool, RedisSettings
                import urllib.parse
                url = settings.REDIS_URL
                parsed = urllib.parse.urlparse(url)
                rs = RedisSettings(
                    host=parsed.hostname or "localhost",
                    port=parsed.port or 6379,
                    database=int(parsed.path.lstrip("/") or 0),
                    password=parsed.password or None,
                )
                _arq_pool = await create_pool(rs, default_queue_name=settings.ARQ_QUEUE_NAME)
    return _arq_pool


async def _close_arq_pool():
    """Close the shared ARQ pool (call from app shutdown)."""
    global _arq_pool
    pool = _arq_pool
    _arq_pool = None
    if pool is not None:
        await pool.aclose()


# ─── POST /api/scans ─────────────────────────────────────────────────────────

@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    # ── SSRF check (async — DNS resolution runs in thread pool) ────────── #
    is_safe, ssrf_msg = await _is_ssrf_safe_url(payload.url)
    if not is_safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSRF Protection Safeguard: {ssrf_msg}"
        )

    # Sanitize auth_context so raw passwords and secrets are never stored
    # Denylist is intentionally conservative: ANY key whose name smells like a
    # credential (token/secret/key/session/cookie/credential/bearer/jwt/auth)
    # is dropped before persistence. Note the substring check deliberately
    # excludes the bare word "auth" so benign keys like "auth_type" survive.
    _SECRET_KEY_TERMS = (
        "password", "passwd", "secret", "private_key", "token", "api_key",
        "apikey", "credential", "session", "cookie", "bearer", "jwt",
        "authorization", "authorisation", "access_key",
    )
    sanitized_auth_context = None
    if payload.auth_context and isinstance(payload.auth_context, dict):
        sanitized_auth_context = {}
        for k, v in payload.auth_context.items():
            lower_k = str(k).lower()
            if any(term in lower_k for term in _SECRET_KEY_TERMS):
                continue
            sanitized_auth_context[k] = v

    scope_data = {
        "profile": payload.profile or "standard",
        "scan_mode": payload.scan_mode,
        "max_crawl_depth": max(1, min(5, getattr(payload, "max_depth", 2) or 2)),
        "max_requests": max(10, min(500, getattr(payload, "max_requests", 50) or 50)),
        "excluded_paths": getattr(payload, "excluded_paths", []) or [],
        "consent_acknowledged": payload.consent_acknowledged,
        "auth_context": sanitized_auth_context,
        "design_questionnaire": payload.design_questionnaire,
        "openapi_spec": payload.openapi_spec,
    }

    lock_acquired, lock_redis = await _acquire_scan_create_lock(current_user.id)
    try:
        # ── Rate limit: max active scans per user ──────────────────────── #
        active_result = await db.execute(
            select(Scan).where(
                Scan.user_id == current_user.id,
                Scan.status.in_([ScanStatus.pending, ScanStatus.running]),
            )
        )
        active_scans = active_result.scalars().all()
        if len(active_scans) >= settings.MAX_ACTIVE_SCANS_PER_USER:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"You already have {settings.MAX_ACTIVE_SCANS_PER_USER} active scan(s). "
                       "Please wait for them to complete.",
            )

        # ── Rate limit: max scans per hour per user ────────────────────── #
        # SQLite stores func.now() defaults as 'YYYY-MM-DD HH:MM:SS' (second
        # precision). Truncate microseconds on the cutoff so the lexicographic
        # string comparison is correct on SQLite; harmless on Postgres.
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0)
        hourly_count = (
            await db.execute(
                select(func.count(Scan.id)).where(
                    Scan.user_id == current_user.id,
                    Scan.created_at >= cutoff,
                )
            )
        ).scalar() or 0
        if hourly_count >= settings.RATE_LIMIT_SCANS_PER_HOUR:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Hourly scan limit reached ({settings.RATE_LIMIT_SCANS_PER_HOUR} scans/hour). "
                       "Please try again later.",
            )

        # Validate consent for active scanning modes
        if payload.scan_mode in ("safe_active", "authenticated_safe_active"):
            if not payload.consent_acknowledged:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Active assessment requires explicit authorization and consent acknowledgement.",
                )

        # ── Create Scan record ───────────────────────────────────────────── #
        scan = Scan(
            user_id=current_user.id,
            url=payload.url,
            scan_mode=payload.scan_mode,
            status=ScanStatus.pending,
            started_at=datetime.now(timezone.utc),
            scope_config=scope_data,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
    finally:
        await _release_scan_create_lock(current_user.id, lock_acquired, lock_redis)

    scan_id = str(scan.id)

    # ── Enqueue durable ARQ job ────────────────────────────────────────── #
    # Use deterministic job ID based on scan_id to prevent duplicate enqueueing.
    # ARQ returns None if a job with this ID already exists (deduplication).
    job_id = f"scan:{scan_id}"

    try:
        arq_pool = await _get_arq_pool()
        job = await arq_pool.enqueue_job(
            "run_scan_job",
            scan_id,
            _job_id=job_id,
            _job_try=1,
        )

        if job is None:
            # Job with this ID already exists — scan already enqueued (idempotent)
            logger.warning(f"SCAN_ENQUEUE_DUPLICATE scan_id={scan_id} job_id={job_id} (already in queue)")
        else:
            # Store job ID on scan for observability/cancellation
            scan.task_id = job_id
            await db.commit()
            logger.info(f"SCAN_ENQUEUED scan_id={scan_id} job_id={job_id} url={payload.url}")

    except Exception as e:
        # ── Enqueue failure: handle gracefully ────────────────────────── #
        # The DB record exists but cannot be processed. We must NOT leave it
        # permanently pending. Options:
        #   1. Return error to user (they can retry)
        #   2. Mark as failed immediately
        # We choose: mark failed + return 503 so user knows to retry.
        logger.error(f"SCAN_ENQUEUE_FAILED scan_id={scan_id}: {e}")
        from app.models.misc import Notification
        scan.status = ScanStatus.failed
        scan.error_message = (
            "Scan could not be queued: the job queue is temporarily unavailable. "
            "Please ensure Redis is running and try again."
        )
        scan.completed_at = datetime.now(timezone.utc)
        scan.current_stage = "Failed"
        db.add(Notification(
            user_id=current_user.id,
            type="scan_failed",
            title=f"Scan Queue Error — {payload.url}",
            message="The scan could not be queued because the job queue is unavailable. Please try again.",
            metadata_={"scan_id": scan_id, "error": str(e)[:500]},
        ))
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan queue unavailable. Please ensure Redis is running and try again.",
        )

    await db.refresh(scan)
    return scan




# ─── Stats ───────────────────────────────────────────────────────────────────

@router.get("/stats")
@router.get("/stats/summary")
async def get_scan_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    """Return personal scan statistics and dashboard aggregates for the current user."""
    from sqlalchemy import func
    from app.models.finding import Finding

    total_scans = (await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == current_user.id)
    )).scalar() or 0

    completed_scans = (await db.execute(
        select(func.count(Scan.id)).where(
            Scan.user_id == current_user.id,
            Scan.status == ScanStatus.completed,
        )
    )).scalar() or 0

    running_scans = (await db.execute(
        select(func.count(Scan.id)).where(
            Scan.user_id == current_user.id,
            Scan.status.in_([ScanStatus.running, ScanStatus.pending]),
        )
    )).scalar() or 0

    avg_score_result = await db.execute(
        select(func.avg(Report.overall_score)).where(Report.user_id == current_user.id)
    )
    avg_score = avg_score_result.scalar()

    # Monitored targets count (distinct scanned URLs)
    unique_urls_res = await db.execute(
        select(func.count(func.distinct(Scan.url))).where(Scan.user_id == current_user.id)
    )
    total_assets = unique_urls_res.scalar() or 0

    # Latest report metadata
    latest_report_res = await db.execute(
        select(Report)
        .where(Report.user_id == current_user.id)
        .order_by(desc(Report.created_at))
        .options(selectinload(Report.scan), selectinload(Report.findings))
        .limit(1)
    )
    latest_report = latest_report_res.scalar_one_or_none()
    latest_grade = latest_report.grade if latest_report else None

    # Aggregated findings breakdown by severity across user's reports
    findings_query = (
        select(Finding.severity, func.count(Finding.id))
        .join(Report, Finding.report_id == Report.id)
        .where(Report.user_id == current_user.id, Finding.is_passed_control.is_(False))
        .group_by(Finding.severity)
    )
    findings_result = await db.execute(findings_query)
    findings_by_severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for sev, count in findings_result.all():
        sev_str = sev.value if hasattr(sev, "value") else str(sev).lower()
        if sev_str in findings_by_severity:
            findings_by_severity[sev_str] = count

    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "average_score": round(float(avg_score)) if avg_score is not None else (latest_report.overall_score if latest_report else None),
        "latest_grade": latest_grade,
        "total_assets": total_assets,
        "findings_by_severity": findings_by_severity,
    }


# ─── List / Get / Delete ─────────────────────────────────────────────────────

@router.get("", response_model=list[ScanListResponse])
async def list_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
    limit: int = 20,
    offset: int = 0,
):
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(desc(Scan.created_at))
        .limit(max(1, min(limit, 100)))
        .offset(max(0, offset))
    )
    scans = result.scalars().all()

    scan_list = []
    for scan in scans:
        report_result = await db.execute(select(Report).where(Report.scan_id == scan.id))
        report = report_result.scalar_one_or_none()
        scan_data = ScanListResponse.model_validate(scan)
        if report:
            scan_data.overall_score = report.overall_score
            scan_data.grade = report.grade
            scan_data.report_id = report.id
        scan_list.append(scan_data)

    return scan_list


# ─── Fixed-path endpoints MUST come before /{scan_id} ────────────────────────
# FastAPI matches routes top-to-bottom. If /{scan_id} is registered first,
# it tries to parse "clear-all" as a UUID → 422 validation error.

@router.delete("/clear-all", status_code=status.HTTP_200_OK)
@router.delete("/clear", status_code=status.HTTP_200_OK)
async def clear_all_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    """
    Delete all scans (and cascaded reports/findings) for the authenticated user.
    Fixed-path route registered BEFORE /{scan_id} to avoid UUID parse conflict.
    """
    result = await db.execute(
        select(Scan).where(Scan.user_id == current_user.id)
    )
    user_scans = result.scalars().all()

    deleted = 0
    skipped_active = 0
    for s in user_scans:
        if s.status in (ScanStatus.pending, ScanStatus.running):
            skipped_active += 1
            continue
        await db.delete(s)
        deleted += 1
    await db.commit()
    return {
        "message": f"Cleared {deleted} scan(s) successfully",
        "cleared_count": deleted,
        "skipped_active_count": skipped_active,
    }


# ─── Parameterised /{scan_id} endpoints ───────────────────────────────────────

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    from sqlalchemy.orm import selectinload
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id).options(selectinload(Scan.report))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    resp = ScanResponse.model_validate(scan)
    if scan.report:
        resp.report_id = scan.report.id
    return resp


@router.delete("/{scan_id}", status_code=status.HTTP_200_OK)
async def delete_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.status in (ScanStatus.pending, ScanStatus.running):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot delete a scan with status '{scan.status.value}'. Cancel it first.",
        )
    await db.delete(scan)
    await db.commit()
    return {"message": "Scan deleted successfully", "scan_id": str(scan_id)}



# ─── Cancellation ────────────────────────────────────────────────────────────

@router.patch("/{scan_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_scan_patch(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    """
    Cancel a pending or running scan.

    Sets DB status to cancelled (authoritative). The worker cooperatively
    checks this flag between stages and will stop. We also attempt to abort
    the ARQ job if it's still queued (before worker picks it up).
    """
    # ── Guarded atomic transition ──────────────────────────────────────── #
    # The scan can transition pending/running → cancelled exactly once, guarded
    # at the row level (WHERE status ∈ pending/running). This closes the
    # lost-update race with the worker's concurrent completion commit: whichever
    # side commits second fails its status guard (rowcount == 0) instead of
    # silently overwriting the other's terminal state. Engine-neutral — on
    # Postgres the UPDATE re-evaluates the predicate against the latest row
    # version; on SQLite single-writer serialization plus the guard give the
    # same result.
    result = await db.execute(
        update(Scan)
        .where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
            Scan.status.in_([ScanStatus.pending, ScanStatus.running]),
        )
        .values(
            status=ScanStatus.cancelled,
            cancellation_reason="Cancelled by user",
            completed_at=datetime.now(timezone.utc),
            current_stage="Cancelled",
        )
    )
    if result.rowcount == 0:
        # Nothing matched: either the scan doesn't exist for this user or it is
        # already terminal (can't cancel). Distinguish without leaking existence.
        existing = await db.execute(
            select(Scan.status).where(Scan.id == scan_id, Scan.user_id == current_user.id)
        )
        status_val = existing.scalar_one_or_none()
        if status_val is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel a scan with status '{status_val.value}'",
        )
    await db.commit()

    task_id_res = await db.execute(select(Scan.task_id).where(Scan.id == scan_id))
    task_id = task_id_res.scalar_one_or_none()

    logger.info(f"SCAN_CANCELLED scan_id={scan_id} job_id={task_id}")

    # ── Attempt to abort queued job (best-effort) ─────────────────────── #
    if task_id:
        try:
            arq_pool = await _get_arq_pool()
            from arq.jobs import Job
            job = Job(task_id, arq_pool)
            job_status = await job.status()
            from arq.jobs import JobStatus
            if job_status == JobStatus.queued:
                # Job is queued but not yet running — abort it immediately
                aborted = await job.abort(timeout=5.0)
                if aborted:
                    logger.info(f"SCAN_JOB_ABORTED scan_id={scan_id} job_id={task_id} (was queued)")
                else:
                    logger.info(
                        f"SCAN_JOB_ABORT_MISS scan_id={scan_id} job_id={task_id} "
                        "(worker already picked up — cooperative cancel will handle it)"
                    )
            elif job_status == JobStatus.in_progress:
                # Worker is running — cooperative cancellation via DB will handle it
                logger.info(
                    f"SCAN_JOB_IN_PROGRESS scan_id={scan_id} job_id={task_id} "
                    "— worker will observe DB cancellation cooperatively"
                )
        except Exception as e:
            # Non-fatal — DB cancellation is authoritative
            logger.warning(f"SCAN_ABORT_ARQ_FAILED scan_id={scan_id}: {e} (DB cancellation still effective)")

    # ── Publish cancelled event to SSE ────────────────────────────────── #
    try:
        from app.utils.cache import get_redis
        from app.utils.progress import publish_progress
        redis = await get_redis()
        await publish_progress(redis, str(scan_id), 0, "Cancelled", "Scan cancelled by user", "cancelled")
    except Exception as e:
        logger.warning(f"SCAN_CANCEL_SSE_PUBLISH_FAILED scan_id={scan_id}: {e}")

    return {"message": "Scan cancelled successfully", "scan_id": str(scan_id)}


# ─── SSE Progress Stream ─────────────────────────────────────────────────────

@router.post("/{scan_id}/sse-ticket", status_code=status.HTTP_200_OK)
async def create_sse_ticket(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    """
    Issue a short-lived, single-use, opaque SSE ticket bound to this user + scan.

    Authenticated with the normal JWT (Authorization header, handled by
    get_verified_user). The returned ticket is the ONLY credential the browser
    sends to GET /{scan_id}/stream (as ?ticket=) — the JWT never appears in the
    SSE URL. Tickets are stored in Redis (SHA-256 hashed) with a ~5 minute TTL,
    consumed atomically on first stream connect, and rejected on reuse/expiry.
    """
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    try:
        ticket = await issue_sse_ticket(current_user.id, str(scan_id))
    except RedisBlacklistError:
        logger.warning(f"SSE_TICKET_ISSUE_FAILED scan_id={scan_id} (Redis unavailable)")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSE ticket service unavailable. Please try again.",
        )

    logger.info(f"SSE_TICKET_ISSUED scan_id={scan_id}")
    return {"ticket": ticket}


@router.get("/{scan_id}/stream")
async def stream_progress(
    scan_id: uuid.UUID,
    request: Request,
    ticket: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """
    Server-Sent Events endpoint for real-time scan progress.

    Authentication (JWT must never appear in the URL):
      - Preferred: ?ticket= — a short-lived, single-use, opaque SSE ticket
        obtained from POST /{scan_id}/sse-ticket. Consumed atomically on
        connect and resolved to the bound user + scan context.
      - Fallback: Authorization: Bearer <access JWT> header — for existing
        non-browser clients (EventSource cannot set headers).

    On connect:
    1. Resolves auth (ticket or Bearer) and verifies ownership
    2. Emits current DB state (reconnect recovery — no reset to 0%)
    3. If terminal (completed/failed/cancelled), returns immediately
    4. Otherwise subscribes to Redis pub/sub for live events
    """
    user_id: Optional[uuid.UUID] = None

    if ticket:
        # ── Opaque one-time ticket path (browser clients) ──────────────── #
        context = await consume_sse_ticket(ticket)
        if not context:
            # Unknown, expired, or already-reused ticket — uniform rejection.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired SSE ticket",
            )
        try:
            ticket_user_id = uuid.UUID(context["user_id"])
            ticket_scan_id = str(context["scan_id"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired SSE ticket",
            )
        if ticket_scan_id != str(scan_id):
            # Ticket is bound to a different scan — treat as not found so the
            # existence of another user's scan is never disclosed.
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        user_id = ticket_user_id
    else:
        # ── Bearer JWT fallback (existing non-browser clients) ─────────── #
        resolved_token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            resolved_token = auth_header[7:]

        if not resolved_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

        try:
            payload = decode_token(resolved_token, expected_type="access")
            user_id = uuid.UUID(payload["sub"])
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        # ── Blacklist check — reject revoked tokens (same semantics as REST API) #
        jti = payload.get("jti", "")
        if jti and await is_token_blacklisted(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
            )

    # Verify ownership
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    scan_id_str = str(scan_id)
    db_status = scan.status.value
    db_progress = scan.progress or 0
    db_stage = scan.current_stage

    # Get Redis for pub/sub
    try:
        from app.utils.cache import get_redis
        redis = await get_redis()
    except Exception:
        redis = None

    # Post-subscribe reconciliation needs a fresh DB read (the initial snapshot
    # above may predate the worker's terminal commit). Return None if the scan
    # is gone.
    async def _current_scan_state():
        res = await db.execute(
            select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
        )
        s = res.scalar_one_or_none()
        if s is None:
            return None
        return {
            "status": s.status.value,
            "progress": s.progress or 0,
            "stage": s.current_stage,
        }

    return StreamingResponse(
        stream_progress_events(
            redis,
            scan_id_str,
            db_status,
            db_progress,
            db_stage,
            state_provider=_current_scan_state,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
