"""
SentinelScan Worker Entry Point.

Usage:
    python run_worker.py

Environment:
    All settings read from backend/.env or environment variables.
    Requires Redis to be running.

This starts the ARQ worker that processes scan jobs independently of the API.
The API process enqueues jobs; this worker process executes them.
"""
import asyncio
import logging
import sys
import os

# Ensure the app package is importable when running from the backend/ directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from arq import run_worker
from arq.connections import RedisSettings
from app.config import settings
from app.worker import WorkerSettings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def _parse_redis_settings() -> RedisSettings:
    """Parse REDIS_URL into ARQ RedisSettings."""
    import urllib.parse
    url = settings.REDIS_URL
    parsed = urllib.parse.urlparse(url)
    return RedisSettings(
        host=parsed.hostname or "localhost",
        port=parsed.port or 6379,
        database=int(parsed.path.lstrip("/") or 0),
        password=parsed.password or None,
    )


if __name__ == "__main__":
    logger.info(f"Starting SentinelScan worker — Redis: {settings.REDIS_URL}")
    logger.info(f"Max jobs: {settings.WORKER_CONCURRENCY} | Timeout: {settings.MAX_SCAN_TIMEOUT}s | Max tries: {settings.WORKER_MAX_TRIES}")

    redis_settings = _parse_redis_settings()

    # Patch WorkerSettings with parsed Redis settings
    WorkerSettings.redis_settings = redis_settings

    run_worker(WorkerSettings)
