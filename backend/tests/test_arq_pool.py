"""Regression tests for shared ARQ pool reuse (J).

The ARQ Redis pool must be created once and reused across requests instead of
being created+closed per request, and closed only at shutdown.
"""
import asyncio
from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture(autouse=True)
def _reset_arq_pool():
    import app.routers.scans as scans
    scans._arq_pool = None
    yield
    scans._arq_pool = None


@pytest.mark.asyncio
async def test_arq_pool_reused_across_calls():
    """Second _get_arq_pool() call must reuse the same pool — no re-create."""
    import app.routers.scans as scans

    mock_pool = AsyncMock()
    mock_create = AsyncMock(return_value=mock_pool)
    with patch("arq.connections.create_pool", new=mock_create):
        pool1 = await scans._get_arq_pool()
        pool2 = await scans._get_arq_pool()
        pool3 = await scans._get_arq_pool()

    assert pool1 is pool2 is pool3
    mock_create.assert_awaited_once()


@pytest.mark.asyncio
async def test_arq_pool_single_creation_under_concurrency():
    """Concurrent requests must not create multiple pools (double-checked lock)."""
    import app.routers.scans as scans

    calls = 0

    async def slow_create_pool(*args, **kwargs):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.05)
        return AsyncMock()

    with patch("arq.connections.create_pool", new=slow_create_pool):
        pool1, pool2 = await asyncio.gather(
            scans._get_arq_pool(), scans._get_arq_pool()
        )

    assert pool1 is pool2
    assert calls == 1


@pytest.mark.asyncio
async def test_close_arq_pool_resets_for_new_pool():
    """_close_arq_pool closes the pool and allows a fresh one on next use."""
    import app.routers.scans as scans

    pool1 = AsyncMock()
    with patch("arq.connections.create_pool", new=AsyncMock(return_value=pool1)):
        await scans._get_arq_pool()

    await scans._close_arq_pool()
    pool1.aclose.assert_awaited_once()
    assert scans._arq_pool is None

    pool2 = AsyncMock()
    with patch("arq.connections.create_pool", new=AsyncMock(return_value=pool2)):
        pool3 = await scans._get_arq_pool()
    assert pool3 is pool2
