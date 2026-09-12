"""Regression tests for the per-user hourly scan rate limit (E).

POST /api/scans must reject requests once RATE_LIMIT_SCANS_PER_HOUR scans
were created in the previous hour (429), regardless of status.
"""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import func, select

from app.config import settings
from app.schemas.scan import ScanCreate


@pytest_asyncio.fixture
async def db():
    from app.database import AsyncSessionLocal, engine, Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session


def _mock_db(hourly_count):
    active_res = MagicMock()
    active_res.scalars.return_value.all.return_value = []
    count_res = MagicMock()
    count_res.scalar.return_value = hourly_count
    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[active_res, count_res])
    db.add = MagicMock()  # sync in SQLAlchemy
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


async def _create(payload, db):
    from app.routers.scans import create_scan
    current_user = MagicMock(id=uuid.uuid4())
    return await create_scan(payload, db=db, current_user=current_user)


@pytest.mark.asyncio
async def test_hourly_limit_blocked_at_threshold():
    """Exactly RATE_LIMIT_SCANS_PER_HOUR scans in the last hour → 429."""
    from fastapi import HTTPException

    db = _mock_db(hourly_count=settings.RATE_LIMIT_SCANS_PER_HOUR)
    with patch("app.routers.scans._is_ssrf_safe_url", new=AsyncMock(return_value=(True, ""))):
        with pytest.raises(HTTPException) as exc_info:
            await _create(ScanCreate(url="https://example.com"), db)

    assert exc_info.value.status_code == 429
    assert "Hourly scan limit" in exc_info.value.detail


@pytest.mark.asyncio
async def test_hourly_limit_blocks_above_threshold():
    db = _mock_db(hourly_count=settings.RATE_LIMIT_SCANS_PER_HOUR + 5)
    with patch("app.routers.scans._is_ssrf_safe_url", new=AsyncMock(return_value=(True, ""))):
        with pytest.raises(Exception) as exc_info:
            await _create(ScanCreate(url="https://example.com"), db)

    from fastapi import HTTPException
    assert isinstance(exc_info.value, HTTPException)
    assert exc_info.value.status_code == 429


@pytest.mark.asyncio
async def test_hourly_limit_allows_below_threshold():
    """Below the hourly limit, scan creation proceeds to enqueue."""
    db = _mock_db(hourly_count=settings.RATE_LIMIT_SCANS_PER_HOUR - 1)

    pool = AsyncMock()
    pool.enqueue_job = AsyncMock(return_value=MagicMock())
    pool.aclose = AsyncMock()

    with patch("app.routers.scans._is_ssrf_safe_url", new=AsyncMock(return_value=(True, ""))), \
         patch("app.routers.scans._get_arq_pool", new=AsyncMock(return_value=pool)):
        scan = await _create(ScanCreate(url="https://example.com"), db)

    pool.enqueue_job.assert_awaited_once()
    pool.aclose.assert_not_awaited()  # shared pool is reused, closed only at shutdown
    assert scan.task_id == f"scan:{scan.id}"


# ─── Real-SQLite count query regression (E) ─────────────────────────────────
# SQLite stores func.now() server defaults as 'YYYY-MM-DD HH:MM:SS'. The count
# query truncates microseconds on the cutoff; these tests pin that comparison.

@pytest.mark.asyncio
async def test_hourly_count_includes_recent_scan(db):
    from app.models.scan import Scan, ScanStatus
    user_id = uuid.uuid4()
    db.add(Scan(user_id=user_id, url="https://recent.example.com", status=ScanStatus.pending))
    await db.commit()

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0)
    count = (
        await db.execute(
            select(func.count(Scan.id)).where(
                Scan.user_id == user_id,
                Scan.created_at >= cutoff,
            )
        )
    ).scalar()

    assert count == 1


@pytest.mark.asyncio
async def test_hourly_count_excludes_old_scan(db):
    from app.models.scan import Scan, ScanStatus
    user_id = uuid.uuid4()
    old = Scan(user_id=user_id, url="https://old.example.com", status=ScanStatus.completed)
    old.created_at = datetime.now(timezone.utc) - timedelta(hours=2)
    db.add(old)
    await db.commit()

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0)
    count = (
        await db.execute(
            select(func.count(Scan.id)).where(
                Scan.user_id == user_id,
                Scan.created_at >= cutoff,
            )
        )
    ).scalar()

    assert count == 0


# ─── Scan-create lock (TOCTOU hardening) ─────────────────────────────────────
# The rate-limit check+insert window is serialized per-user with a best-effort
# Redis lock. When Redis is unavailable the lock MUST degrade gracefully so
# scan creation still works (pre-existing behaviour preserved).

@pytest.mark.asyncio
async def test_scan_create_lock_degrades_when_redis_unavailable():
    from app.routers.scans import _acquire_scan_create_lock, _release_scan_create_lock

    with patch("app.routers.scans.get_redis", new=AsyncMock(side_effect=RuntimeError("redis down"))):
        acquired, r = await _acquire_scan_create_lock(uuid.uuid4())

    assert acquired is False
    assert r is None
    # Release of a non-acquired lock must be a safe no-op
    await _release_scan_create_lock(uuid.uuid4(), acquired=False, r=None)


@pytest.mark.asyncio
async def test_scan_create_lock_release_tolerates_redis_failure():
    from app.routers.scans import _release_scan_create_lock

    r = MagicMock()
    r.delete = AsyncMock(side_effect=RuntimeError("redis down"))
    await _release_scan_create_lock(uuid.uuid4(), acquired=True, r=r)  # must not raise


@pytest.mark.asyncio
async def test_create_scan_succeeds_when_redis_lock_unavailable():
    """Even when the lock path cannot reach Redis, scan creation must work."""
    db = _mock_db(hourly_count=settings.RATE_LIMIT_SCANS_PER_HOUR - 1)

    pool = AsyncMock()
    pool.enqueue_job = AsyncMock(return_value=MagicMock())

    with patch("app.routers.scans._is_ssrf_safe_url", new=AsyncMock(return_value=(True, ""))), \
         patch("app.routers.scans._get_arq_pool", new=AsyncMock(return_value=pool)), \
         patch("app.routers.scans.get_redis", new=AsyncMock(side_effect=RuntimeError("redis down"))):
        scan = await _create(ScanCreate(url="https://example.com"), db)

    pool.enqueue_job.assert_awaited_once()
    assert scan.task_id == f"scan:{scan.id}"


@pytest.mark.asyncio
async def test_scan_create_lock_released_after_rate_limit_error():
    """The lock MUST be released (finally) even when the rate limit trips."""
    from app.routers.scans import _release_scan_create_lock, _acquire_scan_create_lock
    release_called = {"n": 0}
    orig_release = _release_scan_create_lock

    async def tracking_release(user_id, acquired, r):
        release_called["n"] += 1
        return await orig_release(user_id, acquired, r)

    db = _mock_db(hourly_count=settings.RATE_LIMIT_SCANS_PER_HOUR)
    with patch("app.routers.scans._is_ssrf_safe_url", new=AsyncMock(return_value=(True, ""))), \
         patch("app.routers.scans._release_scan_create_lock", new=tracking_release), \
         patch("app.routers.scans._acquire_scan_create_lock",
               new=AsyncMock(return_value=(True, MagicMock()))):
        with pytest.raises(Exception):
            await _create(ScanCreate(url="https://example.com"), db)

    assert release_called["n"] == 1
