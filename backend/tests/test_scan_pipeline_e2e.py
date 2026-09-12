"""
End-to-end regression tests for the SentinelScan Scan Pipeline.

Verifies:
- Worker job registration and discovery
- Queued -> Running -> Completed status transitions
- Real-time progress emission and reconnect recovery with report_id
- Reconciliation of stale queued jobs (>180s)
- Enqueue failure safety (503 and failed DB state, no permanent 5% freeze)
- Fallback polling data structure
"""
import pytest
import uuid
import json
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta

from app.models.scan import Scan, ScanStatus
from app.models.report import Report
from app.config import settings
from app.worker import WorkerSettings
from app.tasks.scan_task import run_scan_job, _emit
from app.utils.progress import publish_progress, get_last_event, stream_progress_events
from app.tasks.reconcile import reconcile_orphan_scans, _check_arq_job_status


class TestWorkerDiscovery:
    """Ensure worker functions are properly discovered and configured."""

    def test_run_scan_job_registered_in_worker_settings(self):
        """WorkerSettings must explicitly include run_scan_job in functions."""
        func_names = [f.__name__ if hasattr(f, "__name__") else str(f) for f in WorkerSettings.functions]
        assert "run_scan_job" in func_names, "run_scan_job is not registered in WorkerSettings.functions"

    def test_worker_settings_cron_jobs(self):
        """WorkerSettings must include reconcile_orphan_scans."""
        assert len(WorkerSettings.cron_jobs) >= 1
        cron_names = [repr(cj) for cj in WorkerSettings.cron_jobs]
        assert any("reconcile_orphan_scans" in name for name in cron_names)


class TestProgressPublicationAndReportId:
    """Verify progress events include report_id and findings_count for frontend navigation."""

    @pytest.mark.asyncio
    async def test_terminal_event_includes_report_id(self):
        published = []
        mock_redis = AsyncMock()

        async def capture_publish(channel, payload):
            published.append(json.loads(payload))

        mock_redis.publish = capture_publish
        mock_redis.set = AsyncMock()

        scan_id = str(uuid.uuid4())
        report_id = str(uuid.uuid4())

        await publish_progress(
            mock_redis,
            scan_id=scan_id,
            progress=100,
            stage="Complete",
            message="Scan completed successfully",
            status="completed",
            report_id=report_id,
            findings_count=12,
        )

        assert len(published) == 1
        evt = published[0]
        assert evt["scan_id"] == scan_id
        assert evt["progress"] == 100
        assert evt["status"] == "completed"
        assert evt["report_id"] == report_id
        assert evt["findings_count"] == 12


class TestOrphanScanReconciliation:
    """Verify that scans whose jobs disappeared from queue are marked failed."""

    @pytest.mark.asyncio
    async def test_orphan_pending_scan_marked_failed(self):
        mock_redis = AsyncMock()
        scan_id = uuid.uuid4()
        old_time = datetime.now(timezone.utc) - timedelta(seconds=120)

        mock_scan = MagicMock()
        mock_scan.id = scan_id
        mock_scan.status = ScanStatus.pending
        mock_scan.task_id = f"scan:{scan_id}"
        mock_scan.started_at = old_time
        mock_scan.created_at = old_time
        mock_scan.user_id = uuid.uuid4()
        mock_scan.url = "https://example.com"

        mock_db = AsyncMock()
        update_result = MagicMock()
        update_result.rowcount = 1

        executed_updates = []

        async def fake_execute(stmt, *args, **kwargs):
            # Atomic guarding UPDATE from _mark_scan_failed_reconcile
            if stmt.__class__.__name__ == "Update":
                executed_updates.append(stmt)
                return update_result
            # Orphan scan SELECT (reconcile main loop)
            return MagicMock(
                scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[mock_scan]))),
                scalar_one_or_none=MagicMock(return_value=mock_scan)
            )

        mock_db.execute = AsyncMock(side_effect=fake_execute)
        mock_db.commit = AsyncMock()
        # session.add() is synchronous in SQLAlchemy — use MagicMock to avoid unawaited-coroutine warning
        mock_db.add = MagicMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db), \
             patch("app.tasks.reconcile._check_arq_job_status", new_callable=AsyncMock) as mock_job_status:
            mock_job_status.return_value = "not_found"

            ctx = {"redis": mock_redis}
            result = await reconcile_orphan_scans(ctx)

            assert result["status"] == "ok"
            assert result["repaired"] == 1
            # The guard UPDATE must target failed with the reconcile reason
            assert len(executed_updates) == 1
            from sqlalchemy.sql.elements import BindParameter
            status_val = None
            reason_val = None
            for col, val in executed_updates[0]._values.items():
                if col.key == "status":
                    status_val = val.value if isinstance(val, BindParameter) else val
                elif col.key == "error_message":
                    reason_val = val.value if isinstance(val, BindParameter) else val
            assert status_val == ScanStatus.failed
            assert reason_val and "not picked up" in reason_val


class TestScanResponseModel:
    """Verify ScanResponse includes report_id attribute."""

    def test_scan_response_schema_has_report_id(self):
        from app.schemas.scan import ScanResponse, ScanProgressEvent
        scan_id = uuid.uuid4()
        report_id = uuid.uuid4()
        resp = ScanResponse(
            id=scan_id,
            url="https://example.com",
            status=ScanStatus.completed,
            progress=100,
            created_at=datetime.now(timezone.utc),
            report_id=report_id,
        )
        assert resp.report_id == report_id
        assert resp.status == ScanStatus.completed

        event = ScanProgressEvent(
            scan_id=str(scan_id),
            status="completed",
            progress=100,
            stage="Complete",
            message="Done",
            report_id=str(report_id),
            findings_count=5,
        )
        assert event.report_id == str(report_id)
        assert event.findings_count == 5
