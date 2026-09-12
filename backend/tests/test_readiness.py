"""Regression tests for GET /api/readiness worker heartbeat age check.

ARQ only refreshes the worker heartbeat (arq:health:sentinelscan-worker) between
jobs, so a stale heartbeat must be treated as NOT ready while tolerating
long-running scans (MAX_SCAN_TIMEOUT + health_check_interval).
"""
import json
import time
from unittest.mock import AsyncMock, patch

import pytest


async def _call_readiness():
    from app.main import readiness_check
    return await readiness_check()


class _FakeRedis:
    def __init__(self, heartbeat_value):
        self._value = heartbeat_value

    async def ping(self):
        return True

    async def get(self, key):
        assert key == "arq:health:sentinelscan-worker"
        return self._value


class _FakeDB:
    """Context-manager stand-in for AsyncSessionLocal."""

    def __init__(self):
        self.execute = AsyncMock(return_value=None)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@pytest.mark.asyncio
async def test_readiness_worker_fresh_heartbeat_ok():
    from app.config import settings

    fresh_ts = str(time.time() - 30)
    with patch("app.database.AsyncSessionLocal", return_value=_FakeDB()), \
         patch("app.utils.cache.get_redis", new=AsyncMock(return_value=_FakeRedis(fresh_ts))):
        response = await _call_readiness()

    assert response.status_code == 200
    body = json.loads(response.body)
    assert body["ready"] is True
    assert body["checks"]["worker"]["status"] == "ok"
    assert body["checks"]["worker"]["age_seconds"] <= 120


@pytest.mark.asyncio
async def test_readiness_worker_stale_heartbeat_not_ready():
    from app.config import settings

    stale_ts = str(time.time() - settings.WORKER_HEARTBEAT_STALE_SECONDS - 120)
    with patch("app.database.AsyncSessionLocal", return_value=_FakeDB()), \
         patch("app.utils.cache.get_redis", new=AsyncMock(return_value=_FakeRedis(stale_ts))):
        response = await _call_readiness()

    assert response.status_code == 503
    body = json.loads(response.body)
    assert body["ready"] is False
    assert body["checks"]["worker"]["status"] == "stale"
    assert "worker may be down" in body["checks"]["worker"]["detail"]


@pytest.mark.asyncio
async def test_readiness_worker_missing_heartbeat_unknown():
    with patch("app.database.AsyncSessionLocal", return_value=_FakeDB()), \
         patch("app.utils.cache.get_redis", new=AsyncMock(return_value=_FakeRedis(None))):
        response = await _call_readiness()

    body = json.loads(response.body)
    assert body["checks"]["worker"]["status"] == "unknown"


@pytest.mark.asyncio
async def test_readiness_worker_garbage_heartbeat_treated_as_stale():
    """A corrupt heartbeat value must not crash — treat as stale (fail closed)."""
    from app.config import settings

    with patch("app.database.AsyncSessionLocal", return_value=_FakeDB()), \
         patch("app.utils.cache.get_redis", new=AsyncMock(return_value=_FakeRedis("not-a-number"))):
        response = await _call_readiness()

    assert response.status_code == 503
    body = json.loads(response.body)
    assert body["checks"]["worker"]["status"] == "stale"
