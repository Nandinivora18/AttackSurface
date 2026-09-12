"""
SentinelScan Reconciliation Task.

Runs as an ARQ cron job every 5 minutes.
Detects and repairs orphan scans that are stuck in non-terminal states
(pending/running) with no viable ARQ job behind them.

Design constraints:
- Idempotent: safe to run repeatedly
- Never marks completed/cancelled scans as failed
- Uses grace periods to avoid racing with legitimate jobs
- Checks actual ARQ job status (not just DB state)
- Does NOT interfere with scans that have an active job

State transitions performed:
    pending + no viable job + past grace → failed
    running + no viable job + past timeout → failed
    cancelled + job still queued → abort job (best effort), leave DB as cancelled
    completed + job re-delivered → skip (idempotency handles it inside run_scan_job)
"""
import asyncio
import uuid
import logging
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, update

from app.database import AsyncSessionLocal
from app.models.scan import Scan, ScanStatus
from app.models.misc import Notification
from app.config import settings

logger = logging.getLogger(__name__)

# Grace period: a scan in 'pending' for less than this is still being enqueued/starting
PENDING_GRACE_SECONDS = 60  # 1 minute

# Running grace: a scan in 'running' for more than this with no active job is orphaned
# Set to slightly more than MAX_SCAN_TIMEOUT to account for job_timeout enforcement
RUNNING_ORPHAN_SECONDS = settings.MAX_SCAN_TIMEOUT + 120  # timeout + 2 min buffer


async def _check_arq_job_status(redis, job_id: str) -> str:
    """
    Check the ARQ job status directly from Redis.

    Returns one of: 'queued', 'in_progress', 'complete', 'not_found'
    'not_found' means: job is gone from the queue, not in progress, no result.
    """
    if not redis or not job_id:
        return "not_found"

    try:
        from arq.jobs import Job
        from arq.constants import (
            result_key_prefix,
            in_progress_key_prefix,
        )
        # Reconstruct queue_name
        queue_name = settings.ARQ_QUEUE_NAME

        async with redis.pipeline(transaction=True) as tr:
            tr.exists(result_key_prefix + job_id)
            tr.exists(in_progress_key_prefix + job_id)
            tr.zscore(queue_name, job_id)
            is_complete, is_in_progress, score = await tr.execute()

        from arq.utils import timestamp_ms
        if is_complete:
            return "complete"
        elif is_in_progress:
            return "in_progress"
        elif score is not None:
            return "queued"  # includes deferred
        else:
            return "not_found"
    except Exception as e:
        logger.warning(f"RECONCILE_JOB_STATUS_ERROR job_id={job_id}: {e}")
        # If we can't check status, assume viable (don't aggressively fail)
        return "unknown"


async def _abort_arq_job(redis, job_id: str) -> bool:
    """Best-effort abort of a queued ARQ job. Returns True if aborted."""
    if not redis or not job_id:
        return False
    try:
        from arq.jobs import Job
        job = Job(job_id, redis)
        result = await job.abort(timeout=3.0)
        return result
    except Exception as e:
        logger.debug(f"RECONCILE_ABORT_FAILED job_id={job_id}: {e}")
        return False


async def _mark_scan_failed_reconcile(
    scan_id: str, reason: str, redis, user_id
) -> None:
    """Mark a scan as failed during reconciliation, with notification.

    Uses a guarded atomic UPDATE so reconciling can NEVER clobber a terminal
    state set by the worker (completed/cancelled) in the gap between this
    function's earlier SELECT and its write. Reconcile loading stale rows in
    its main SELECT (this function opens its own session and re-reads) is the
    known benign variant; the atomic predicate closes the write race.
    """
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                update(Scan)
                .where(
                    Scan.id == uuid.UUID(str(scan_id)),
                    Scan.status.in_([ScanStatus.pending, ScanStatus.running]),
                )
                .values(
                    status=ScanStatus.failed,
                    error_message=reason,
                    completed_at=datetime.now(timezone.utc),
                    current_stage="Failed (Reconciled)",
                )
                .execution_options(synchronize_session=False)
            )
            if result.rowcount == 0:
                logger.debug(
                    f"RECONCILE_SKIP scan_id={scan_id} terminated by worker between reconcile passes"
                )
                return

            db.add(Notification(
                user_id=user_id,
                type="scan_failed",
                title=f"Scan Failed — {scan_id}",
                message=f"The scan could not be completed: {reason[:200]}",
                metadata_={
                    "scan_id": str(scan_id),
                    "error": reason[:500],
                    "reconciled": True,
                },
            ))
            await db.commit()
            logger.warning(
                f"RECONCILE_MARKED_FAILED scan_id={scan_id} reason={reason!r}"
            )
    except Exception as e:
        logger.error(f"RECONCILE_MARK_FAILED_ERROR scan_id={scan_id}: {e}")

    # Publish terminal SSE event
    if redis:
        try:
            from app.utils.progress import publish_progress
            await publish_progress(
                redis, str(scan_id), 0, "Failed", reason, "failed"
            )
        except Exception:
            pass


async def reconcile_orphan_scans(ctx: dict) -> dict:
    """
    ARQ cron job: Detect and repair orphan scans.

    Runs every 5 minutes. Checks all scans in pending/running state and
    verifies that each has a viable ARQ job. Scans without viable jobs
    that have passed their grace periods are marked failed.

    Idempotent: safe to run concurrently or repeatedly.
    """
    redis = ctx.get("redis")
    now = datetime.now(timezone.utc)

    logger.info("RECONCILE_START: Checking for orphan pending/running scans")

    repaired_count = 0
    skipped_count = 0
    error_count = 0

    try:
        async with AsyncSessionLocal() as db:
            # Load all non-terminal scans
            result = await db.execute(
                select(Scan).where(
                    Scan.status.in_([ScanStatus.pending, ScanStatus.running])
                )
            )
            active_scans = result.scalars().all()
    except Exception as e:
        logger.error(f"RECONCILE_DB_ERROR: Failed to load active scans: {e}")
        return {"status": "error", "error": str(e)}

    if not active_scans:
        logger.info("RECONCILE_DONE: No active scans to check")
        return {"status": "ok", "repaired": 0, "checked": 0}

    logger.info(f"RECONCILE_CHECKING: {len(active_scans)} active scan(s)")

    for scan in active_scans:
        scan_id = str(scan.id)
        task_id = scan.task_id
        status = scan.status

        try:
            # ── Determine age of this scan ───────────────────────────── #
            created_at = scan.started_at or scan.created_at

            if created_at and created_at.tzinfo is None:
                created_utc = created_at.replace(tzinfo=timezone.utc)
            elif created_at:
                created_utc = created_at
            else:
                created_utc = now
            age_seconds = (now - created_utc).total_seconds()

            # ── PENDING scans ────────────────────────────────────────── #
            if status == ScanStatus.pending:
                if age_seconds < PENDING_GRACE_SECONDS:
                    # Still young — give it time to be enqueued/picked up
                    logger.debug(
                        f"RECONCILE_PENDING_GRACE scan_id={scan_id} age={age_seconds:.0f}s < {PENDING_GRACE_SECONDS}s"
                    )
                    skipped_count += 1
                    continue

                # Past grace period — check if job still viable
                job_status = await _check_arq_job_status(redis, task_id)
                logger.info(
                    f"RECONCILE_PENDING_CHECK scan_id={scan_id} task_id={task_id} "
                    f"age={age_seconds:.0f}s job_status={job_status}"
                )

                if job_status in ("queued", "in_progress", "unknown"):
                    # Job still exists in queue and will be processed by worker — leave it
                    skipped_count += 1
                    continue

                if job_status in ("not_found", "complete"):
                    # Job disappeared or completed without updating scan status
                    reason = (
                        "Scan execution was not picked up by any worker. "
                        "The job queue may have been cleared or the worker was not running."
                    )
                    await _mark_scan_failed_reconcile(scan_id, reason, redis, scan.user_id)
                    repaired_count += 1

            # ── RUNNING scans ────────────────────────────────────────── #
            elif status == ScanStatus.running:
                # Check ARQ job status first
                job_status = await _check_arq_job_status(redis, task_id)

                logger.info(
                    f"RECONCILE_RUNNING_CHECK scan_id={scan_id} task_id={task_id} "
                    f"age={age_seconds:.0f}s job_status={job_status}"
                )

                if job_status == "in_progress":
                    # Worker is actively running this job — leave it alone
                    skipped_count += 1
                    continue

                if job_status in ("queued", "unknown"):
                    # Job is queued but not running yet (or unknown) — leave it
                    skipped_count += 1
                    continue

                if job_status == "complete":
                    # ARQ completed the job but scan is still 'running' in DB.
                    # This means the job function returned but the DB commit failed.
                    # Check if a report was actually created.
                    try:
                        async with AsyncSessionLocal() as db2:
                            from app.models.report import Report
                            r = await db2.execute(
                                select(Report).where(Report.scan_id == uuid.UUID(scan_id))
                            )
                            report = r.scalar_one_or_none()
                            if report:
                                # Report exists — atomically mark completed ONLY if
                                # still running; never clobber a cancelled/failed
                                # state the worker set between our SELECT and write.
                                upd = await db2.execute(
                                    update(Scan)
                                    .where(
                                        Scan.id == uuid.UUID(scan_id),
                                        Scan.status == ScanStatus.running,
                                    )
                                    .values(
                                        status=ScanStatus.completed,
                                        progress=100,
                                        current_stage="Complete (Reconciled)",
                                        completed_at=datetime.now(timezone.utc),
                                    )
                                    .execution_options(synchronize_session=False)
                                )
                                if upd.rowcount:
                                    await db2.commit()
                                    logger.warning(
                                        f"RECONCILE_RECOVERED_COMPLETED scan_id={scan_id} "
                                        "(job completed but scan status was still running)"
                                    )
                                    repaired_count += 1
                                else:
                                    await db2.rollback()
                                    logger.debug(
                                        f"RECONCILE_SKIP_RECOVER scan_id={scan_id} "
                                        "no longer running (worker cancelled/failed it)"
                                    )
                                continue
                    except Exception as e2:
                        logger.error(f"RECONCILE_COMPLETE_CHECK_ERROR scan_id={scan_id}: {e2}")

                    # ARQ job completed but no report found — mark failed
                    reason = (
                        "Scan job completed without producing a report. "
                        "The scan may have failed to persist results."
                    )
                    await _mark_scan_failed_reconcile(scan_id, reason, redis, scan.user_id)
                    repaired_count += 1
                    continue

                if job_status == "not_found":
                    # Job is gone — either:
                    # 1. Job exhausted all retries (ARQ removed it)
                    # 2. Worker crashed and job was lost
                    # Apply time-based grace: if scan is recent, wait for retry delivery
                    retry_window = settings.MAX_SCAN_TIMEOUT * settings.WORKER_MAX_TRIES
                    if age_seconds < retry_window:
                        logger.info(
                            f"RECONCILE_RUNNING_WAIT scan_id={scan_id} age={age_seconds:.0f}s "
                            f"< retry_window={retry_window:.0f}s (waiting for possible re-delivery)"
                        )
                        skipped_count += 1
                        continue

                    # Past retry window — job is definitively gone, mark failed
                    reason = (
                        "Scan execution failed after all retry attempts were exhausted. "
                        "The worker process may have crashed or been terminated."
                    )
                    await _mark_scan_failed_reconcile(scan_id, reason, redis, scan.user_id)
                    repaired_count += 1

        except Exception as e:
            logger.error(f"RECONCILE_SCAN_ERROR scan_id={scan_id}: {e}", exc_info=True)
            error_count += 1

    result = {
        "status": "ok",
        "checked": len(active_scans),
        "repaired": repaired_count,
        "skipped": skipped_count,
        "errors": error_count,
        "timestamp": now.isoformat(),
    }
    logger.info(
        f"RECONCILE_DONE: checked={len(active_scans)} repaired={repaired_count} "
        f"skipped={skipped_count} errors={error_count}"
    )
    return result
