"""Regression tests for scan deletion safeguards (H).

Active scans (pending/running) must never be deleted:
- DELETE /api/scans/{id} → 409 Conflict (cancel first)
- DELETE /api/scans/clear-all → active scans are skipped, not deleted
"""
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.scan import ScanStatus


class _MockScan:
    def __init__(self, status):
        self.status = status
        self.id = uuid.uuid4()
        self.task_id = None
        self.completed_at = None
        self.current_stage = None
        self.cancellation_reason = None


async def _call_delete(scan_id, db):
    from app.routers.scans import delete_scan
    return await delete_scan(scan_id, db, current_user=MagicMock())


async def _call_clear_all(db):
    from app.routers.scans import clear_all_scans
    return await clear_all_scans(db, current_user=MagicMock())


@pytest.mark.asyncio
async def test_delete_running_scan_blocked():
    from fastapi import HTTPException

    scan = _MockScan(ScanStatus.running)
    db = AsyncMock()
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=scan)))

    with pytest.raises(HTTPException) as exc_info:
        await _call_delete(scan.id, db)
    assert exc_info.value.status_code == 409
    assert "Cancel it first" in exc_info.value.detail


@pytest.mark.asyncio
async def test_delete_pending_scan_blocked():
    from fastapi import HTTPException

    scan = _MockScan(ScanStatus.pending)
    db = AsyncMock()
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=scan)))

    with pytest.raises(HTTPException) as exc_info:
        await _call_delete(scan.id, db)
    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_delete_completed_scan_allowed():
    scan = _MockScan(ScanStatus.completed)
    db = AsyncMock()
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=scan)))

    result = await _call_delete(scan.id, db)

    db.delete.assert_awaited_once_with(scan)
    db.commit.assert_awaited_once()
    assert result["scan_id"] == str(scan.id)


@pytest.mark.asyncio
async def test_clear_all_skips_active_scans():
    running = _MockScan(ScanStatus.running)
    completed = _MockScan(ScanStatus.completed)
    cancelled = _MockScan(ScanStatus.cancelled)

    db = AsyncMock()
    db.execute = AsyncMock(return_value=MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[running, completed, cancelled])))
    ))

    result = await _call_clear_all(db)

    assert result["cleared_count"] == 2
    assert result["skipped_active_count"] == 1
    # Only terminal scans get deleted
    deleted_ids = [call.kwargs["s"] if "s" in call.kwargs else call.args[0] for call in db.delete.await_args_list]
    assert running not in deleted_ids
    assert completed in deleted_ids
    assert cancelled in deleted_ids


# ─── Cancellation race hardening ──────────────────────────────────────────────
# cancel_scan_patch must implement a guarded atomic transition
# (UPDATE ... WHERE status IN (pending, running)) so a concurrent worker
# completion commit can never clobber 'cancelled' nor be clobbered by it.
# A row-level FOR UPDATE lock alone is insufficient: the worker's persist
# transaction reads its terminal state without a lock, so the winner must be
# decided by an atomic status predicate, not by whoever commits last.

def test_cancel_uses_guarded_status_transition():
    import pathlib
    src = pathlib.Path("app/routers/scans.py").read_text(encoding='utf-8')
    cancel_idx = src.find("async def cancel_scan_patch")
    assert cancel_idx != -1, "cancel_scan_patch not found"
    block = src[cancel_idx:cancel_idx + 1600]
    assert "update(Scan)" in block
    assert "Scan.status.in_([" in block
    assert "rowcount" in block


@pytest.mark.asyncio
async def test_cancel_completed_scan_rejected():
    """Terminal states must never transition; cancelling a completed scan → 400."""
    from fastapi import HTTPException
    from app.routers.scans import cancel_scan_patch

    scan = _MockScan(ScanStatus.completed)
    db = AsyncMock()
    # First execute: the guarded UPDATE matches 0 rows (scan is completed).
    # Second execute: the existence re-read reports the terminal status.
    db.execute = AsyncMock(side_effect=[
        MagicMock(rowcount=0),
        MagicMock(scalar_one_or_none=MagicMock(return_value=ScanStatus.completed)),
    ])

    with pytest.raises(HTTPException) as exc_info:
        await cancel_scan_patch(scan.id, db, current_user=MagicMock())
    assert exc_info.value.status_code == 400
    assert "Cannot cancel" in exc_info.value.detail
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancel_not_found_returns_404():
    """Cancelling a scan owned by nobody → 404 (no existence leak)."""
    from fastapi import HTTPException
    from app.routers.scans import cancel_scan_patch

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        MagicMock(rowcount=0),
        MagicMock(scalar_one_or_none=MagicMock(return_value=None)),
    ])

    with pytest.raises(HTTPException) as exc_info:
        await cancel_scan_patch(uuid.uuid4(), db, current_user=MagicMock())
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_cancel_running_scan_sets_cancelled():
    from app.routers.scans import cancel_scan_patch

    scan = _MockScan(ScanStatus.running)
    db = AsyncMock()
    # Guarded UPDATE matches exactly one row; task_id re-read returns None so
    # the queued-job abort is skipped (and the SSE publish degrades gracefully
    # when Redis is unavailable, as before).
    db.execute = AsyncMock(side_effect=[
        MagicMock(rowcount=1),
        MagicMock(scalar_one_or_none=MagicMock(return_value=scan.task_id)),
    ])
    db.commit = AsyncMock()

    result = await cancel_scan_patch(scan.id, db, current_user=MagicMock())
    assert result["message"] is not None
    assert db.commit.await_count >= 1
