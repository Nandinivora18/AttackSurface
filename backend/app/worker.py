"""
ARQ Worker Settings for SentinelScan.

Run with:
    python run_worker.py

or:
    python -m arq app.worker.WorkerSettings
"""
import logging
from arq import cron

from app.config import settings
from app.tasks.scan_task import run_scan_job
from app.tasks.reconcile import reconcile_orphan_scans

logger = logging.getLogger(__name__)


async def startup(ctx: dict) -> None:
    """Called once when the worker starts. Sets up shared resources."""
    logger.info("WORKER_STARTED: SentinelScan scan worker initializing")
    logger.info(
        f"WORKER_CONFIG: Redis={settings.REDIS_URL} "
        f"queue={settings.ARQ_QUEUE_NAME} "
        f"max_jobs={settings.WORKER_CONCURRENCY} "
        f"max_tries={settings.WORKER_MAX_TRIES} "
        f"timeout={settings.MAX_SCAN_TIMEOUT}s"
    )

    # Startup reconciliation: log scans in running state.
    # These may be scans whose jobs are being re-delivered by ARQ,
    # or scans that survived the previous worker crash.
    # The periodic cron reconciliation handles cleanup after grace periods.
    try:
        from app.database import AsyncSessionLocal
        from app.models.scan import Scan, ScanStatus
        from sqlalchemy import select

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Scan).where(Scan.status.in_([ScanStatus.running, ScanStatus.pending]))
            )
            active = result.scalars().all()
            if active:
                logger.warning(
                    f"WORKER_STARTUP_RECONCILE: Found {len(active)} scan(s) in active state. "
                    "Periodic cron reconciliation will handle orphans after grace periods."
                )
                for scan in active:
                    logger.warning(
                        f"WORKER_STARTUP_ACTIVE: scan_id={scan.id} "
                        f"status={scan.status} task_id={scan.task_id} "
                        f"started_at={scan.started_at}"
                    )
    except Exception as e:
        logger.error(f"WORKER_STARTUP_RECONCILE_ERROR: {e}")


async def shutdown(ctx: dict) -> None:
    """Called when worker shuts down gracefully."""
    logger.info("WORKER_STOPPED: SentinelScan scan worker shutting down cleanly")


class WorkerSettings:
    """
    ARQ WorkerSettings — referenced by arq CLI and run_worker.py.

    Cron jobs registered here:
      reconcile_orphan_scans                — every 5 minutes
    """

    # Job functions registered with this worker
    functions = [run_scan_job]

    # Cron jobs
    cron_jobs = [
        cron(
            reconcile_orphan_scans,
            minute={0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55},  # every 5 minutes
            run_at_startup=True,   # also run once immediately on worker start
            unique=True,           # only one reconciliation runs at a time
            max_tries=1,           # cron jobs should not retry (they're periodic)
            timeout=120,           # max 2 minutes for reconciliation
        ),
    ]

    # Lifecycle hooks
    on_startup = startup
    on_shutdown = shutdown

    # Queue name
    queue_name = settings.ARQ_QUEUE_NAME

    # Concurrency — max simultaneous scan jobs per worker process
    max_jobs = settings.WORKER_CONCURRENCY

    # Overall job timeout in seconds (entire scan must complete within this)
    job_timeout = settings.MAX_SCAN_TIMEOUT

    # Retry configuration — must match settings.WORKER_MAX_TRIES
    max_tries = settings.WORKER_MAX_TRIES

    # Keep results for 1 hour (allows Job.status() to be checked after completion)
    keep_result = 3600

    # Enable job abortion (supports Job.abort() for cancellation)
    allow_abort_jobs = True

    # Poll delay — how often worker checks for new jobs (seconds)
    poll_delay = 0.5

    # Health check key in Redis (updated by ARQ automatically)
    health_check_key = "arq:health:sentinelscan-worker"
    health_check_interval = 60

    # Redis settings — patched by run_worker.py at startup
    redis_settings = None
