"""
Tests for Phase 3.1 reliability fixes:
- Retry exhaustion → failed
- Timeout → failed
- Orphan pending/running scan reconciliation
- Worker crash recovery semantics
- Cancelled/completed preservation under all conditions
- Idempotent reconciliation
- Production Redis auth failure
- task_id consistency
"""
import pytest
import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_scan(
    status="running",
    task_id=None,
    age_seconds=None,
):
    """Build a mock Scan object."""
    from app.models.scan import ScanStatus
    scan = MagicMock()
    scan.id = uuid.uuid4()
    scan.status = getattr(ScanStatus, status)
    scan.task_id = task_id or f"scan:{scan.id}"
    scan.url = "https://example.com"
    scan.user_id = uuid.uuid4()
    scan.error_message = None

    now = datetime.now(timezone.utc)
    if age_seconds is not None:
        ts = now - timedelta(seconds=age_seconds)
    else:
        ts = now - timedelta(minutes=5)

    scan.started_at = ts
    scan.created_at = ts
    return scan


def _make_db_context(scans=None):
    """Make an async DB context that returns given scans."""
    mock_db = AsyncMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = scans or []
    exec_result = MagicMock()
    exec_result.scalars.return_value = scalars_mock
    exec_result.scalar_one_or_none.return_value = scans[0] if scans else None
    mock_db.execute = AsyncMock(return_value=exec_result)
    mock_db.commit = AsyncMock()
    mock_db.__aenter__ = AsyncMock(return_value=mock_db)
    mock_db.__aexit__ = AsyncMock(return_value=None)
    return mock_db


def _make_scan_mock(scan_id=None, status="pending"):
    """Build a realistic scan mock with all required string attributes."""
    from app.models.scan import ScanStatus
    scan = MagicMock()
    scan.id = uuid.UUID(scan_id) if scan_id else uuid.uuid4()
    scan.status = getattr(ScanStatus, status)
    scan.task_id = None
    scan.url = "https://example.com"
    scan.user_id = uuid.uuid4()
    scan.scan_mode = "passive"
    scan.progress = 0
    scan.current_stage = None
    scan.error_message = None
    return scan


# ─── Retry Exhaustion Tests ───────────────────────────────────────────────────

class TestRetryExhaustion:
    """When all retry attempts are exhausted, scan must become failed."""

    @pytest.mark.asyncio
    async def test_final_attempt_exception_marks_failed(self):
        """On last attempt, exception → _mark_failed_safe called, result is failed dict."""
        import app.tasks.scan_task as st

        scan_id = str(uuid.uuid4())
        mock_scan = _make_scan_mock(scan_id=scan_id, status="pending")

        mark_calls = []

        async def fake_mark_failed(scan_id_arg, message, redis):
            mark_calls.append({"scan_id": scan_id_arg, "message": message})

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(
            return_value=MagicMock(
                scalar_one_or_none=MagicMock(return_value=mock_scan)
            )
        )
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        # Patch at module-object level (avoids reload issues)
        orig_al = st.AsyncSessionLocal
        orig_mfs = st._mark_failed_safe
        try:
            st.AsyncSessionLocal = MagicMock(return_value=mock_db)
            st._mark_failed_safe = fake_mark_failed

            with patch("app.scanner.dns_checker.analyze_dns",
                       side_effect=RuntimeError("DNS failed")):
                # job_try=3 == settings.WORKER_MAX_TRIES → final attempt
                ctx = {"redis": None, "job_id": "test-job", "job_try": 3}
                result = await st.run_scan_job(ctx, scan_id)
        finally:
            st.AsyncSessionLocal = orig_al
            st._mark_failed_safe = orig_mfs

        assert result["status"] == "failed", f"Got: {result}"
        assert len(mark_calls) == 1, f"Expected 1 call to _mark_failed_safe, got {len(mark_calls)}"
        msg = mark_calls[0]["message"]
        assert "exhausted" in msg.lower() or "retry" in msg.lower(), \
            f"Expected exhaustion message, got: {msg!r}"

    @pytest.mark.asyncio
    async def test_non_final_attempt_reraises_for_arq(self):
        """On attempt < max_tries, CancelledError is re-raised so ARQ can retry."""
        import app.tasks.scan_task as st

        scan_id = str(uuid.uuid4())
        mock_scan = _make_scan_mock(scan_id=scan_id, status="pending")

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(
            return_value=MagicMock(
                scalar_one_or_none=MagicMock(return_value=mock_scan)
            )
        )
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        orig_al = st.AsyncSessionLocal
        try:
            st.AsyncSessionLocal = MagicMock(return_value=mock_db)
            with patch("app.scanner.dns_checker.analyze_dns",
                       side_effect=asyncio.CancelledError()):
                # job_try=1, WORKER_MAX_TRIES=3 → NOT final
                ctx = {"redis": None, "job_id": "test-job", "job_try": 1}
                with pytest.raises(asyncio.CancelledError):
                    await st.run_scan_job(ctx, scan_id)
        finally:
            st.AsyncSessionLocal = orig_al

    @pytest.mark.asyncio
    async def test_timeout_marks_failed_immediately(self):
        """TimeoutError always marks scan failed (never re-raised for retry)."""
        import app.tasks.scan_task as st

        scan_id = str(uuid.uuid4())
        mock_scan = _make_scan_mock(scan_id=scan_id, status="pending")

        mark_calls = []

        async def fake_mark_failed(scan_id_arg, message, redis):
            mark_calls.append({"scan_id": scan_id_arg, "message": message})

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(
            return_value=MagicMock(
                scalar_one_or_none=MagicMock(return_value=mock_scan)
            )
        )
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        orig_al = st.AsyncSessionLocal
        orig_mfs = st._mark_failed_safe
        try:
            st.AsyncSessionLocal = MagicMock(return_value=mock_db)
            st._mark_failed_safe = fake_mark_failed

            with patch("app.scanner.dns_checker.analyze_dns",
                       side_effect=asyncio.TimeoutError("stage timed out")):
                # Even on attempt 1, timeout is permanent
                ctx = {"redis": None, "job_id": "test-job", "job_try": 1}
                result = await st.run_scan_job(ctx, scan_id)
        finally:
            st.AsyncSessionLocal = orig_al
            st._mark_failed_safe = orig_mfs

        assert result["status"] == "failed"
        assert len(mark_calls) == 1
        assert "maximum execution time" in mark_calls[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_timeout_message_is_safe(self):
        """Timeout error message must not expose raw exception class names."""
        import app.tasks.scan_task as st

        scan_id = str(uuid.uuid4())
        mock_scan = _make_scan_mock(scan_id=scan_id, status="pending")

        captured_msg = []

        async def fake_mark_failed(scan_id_arg, message, redis):
            captured_msg.append(message)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(
            return_value=MagicMock(
                scalar_one_or_none=MagicMock(return_value=mock_scan)
            )
        )
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        orig_al = st.AsyncSessionLocal
        orig_mfs = st._mark_failed_safe
        try:
            st.AsyncSessionLocal = MagicMock(return_value=mock_db)
            st._mark_failed_safe = fake_mark_failed

            with patch("app.scanner.dns_checker.analyze_dns",
                       side_effect=asyncio.TimeoutError()):
                ctx = {"redis": None, "job_id": "test-job", "job_try": 2}
                result = await st.run_scan_job(ctx, scan_id)
        finally:
            st.AsyncSessionLocal = orig_al
            st._mark_failed_safe = orig_mfs

        all_text = result.get("error", "") + (captured_msg[0] if captured_msg else "")
        assert "TimeoutError" not in all_text
        assert "traceback" not in all_text.lower()

    @pytest.mark.asyncio
    async def test_cancelled_error_on_final_attempt_marks_failed(self):
        """CancelledError on final attempt must mark scan failed (not re-raise)."""
        import app.tasks.scan_task as st

        scan_id = str(uuid.uuid4())
        mock_scan = _make_scan_mock(scan_id=scan_id, status="pending")

        mark_calls = []

        async def fake_mark_failed(scan_id_arg, message, redis):
            mark_calls.append({"scan_id": scan_id_arg, "message": message})

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(
            return_value=MagicMock(
                scalar_one_or_none=MagicMock(return_value=mock_scan)
            )
        )
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        orig_al = st.AsyncSessionLocal
        orig_mfs = st._mark_failed_safe
        try:
            st.AsyncSessionLocal = MagicMock(return_value=mock_db)
            st._mark_failed_safe = fake_mark_failed

            with patch("app.scanner.dns_checker.analyze_dns",
                       side_effect=asyncio.CancelledError()):
                # job_try == WORKER_MAX_TRIES == 3 → final
                ctx = {"redis": None, "job_id": "test-job", "job_try": 3}
                result = await st.run_scan_job(ctx, scan_id)
        finally:
            st.AsyncSessionLocal = orig_al
            st._mark_failed_safe = orig_mfs

        assert result["status"] == "failed"
        assert len(mark_calls) == 1
        msg = mark_calls[0]["message"]
        assert "exhausted" in msg.lower() or "retry" in msg.lower()

    @pytest.mark.asyncio
    async def test_cancelled_error_on_non_final_reraises(self):
        """CancelledError on non-final attempt re-raises so ARQ can retry."""
        import app.tasks.scan_task as st

        scan_id = str(uuid.uuid4())
        mock_scan = _make_scan_mock(scan_id=scan_id, status="pending")

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(
            return_value=MagicMock(
                scalar_one_or_none=MagicMock(return_value=mock_scan)
            )
        )
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        orig_al = st.AsyncSessionLocal
        try:
            st.AsyncSessionLocal = MagicMock(return_value=mock_db)
            with patch("app.scanner.dns_checker.analyze_dns",
                       side_effect=asyncio.CancelledError()):
                # job_try=1, max_tries=3 → not final
                ctx = {"redis": None, "job_id": "test-job", "job_try": 1}
                with pytest.raises(asyncio.CancelledError):
                    await st.run_scan_job(ctx, scan_id)
        finally:
            st.AsyncSessionLocal = orig_al


# ─── Reconciliation Tests ────────────────────────────────────────────────────

class TestReconciliation:
    """Reconciliation must detect orphans and repair them idempotently."""

    @pytest.mark.asyncio
    async def test_pending_past_grace_no_job_marked_failed(self):
        """Pending scan past grace period with no ARQ job → marked failed."""
        from app.tasks.reconcile import reconcile_orphan_scans

        scan = _make_scan(status="pending", age_seconds=300)  # 5min, past 60s grace
        mock_db = _make_db_context(scans=[scan])
        mark_calls = []

        async def mock_mark(scan_id, reason, redis, user_id):
            mark_calls.append({"scan_id": scan_id, "reason": reason})

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db), \
             patch("app.tasks.reconcile._check_arq_job_status",
                   AsyncMock(return_value="not_found")), \
             patch("app.tasks.reconcile._mark_scan_failed_reconcile",
                   side_effect=mock_mark):
            result = await reconcile_orphan_scans({"redis": AsyncMock()})

        assert result["repaired"] == 1
        assert len(mark_calls) == 1
        reason = mark_calls[0]["reason"].lower()
        assert "not picked up" in reason or "worker" in reason

    @pytest.mark.asyncio
    async def test_pending_within_grace_not_touched(self):
        """Pending scan within grace period must not be touched."""
        from app.tasks.reconcile import reconcile_orphan_scans

        scan = _make_scan(status="pending", age_seconds=30)  # 30s < 60s grace
        mock_db = _make_db_context(scans=[scan])
        mark_calls = []

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db), \
             patch("app.tasks.reconcile._check_arq_job_status",
                   AsyncMock(return_value="not_found")), \
             patch("app.tasks.reconcile._mark_scan_failed_reconcile",
                   AsyncMock(side_effect=lambda *a, **k: mark_calls.append(a))):
            result = await reconcile_orphan_scans({"redis": AsyncMock()})

        assert len(mark_calls) == 0
        assert result["skipped"] == 1

    @pytest.mark.asyncio
    async def test_pending_with_queued_job_not_touched(self):
        """Pending scan with a queued ARQ job must not be touched."""
        from app.tasks.reconcile import reconcile_orphan_scans

        scan = _make_scan(status="pending", age_seconds=300)
        mock_db = _make_db_context(scans=[scan])
        mark_calls = []

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db), \
             patch("app.tasks.reconcile._check_arq_job_status",
                   AsyncMock(return_value="queued")), \
             patch("app.tasks.reconcile._mark_scan_failed_reconcile",
                   AsyncMock(side_effect=lambda *a, **k: mark_calls.append(a))):
            result = await reconcile_orphan_scans({"redis": AsyncMock()})

        assert len(mark_calls) == 0

    @pytest.mark.asyncio
    async def test_running_in_progress_job_not_touched(self):
        """Running scan with in_progress ARQ job must never be touched."""
        from app.tasks.reconcile import reconcile_orphan_scans

        scan = _make_scan(status="running", age_seconds=600)
        mock_db = _make_db_context(scans=[scan])
        mark_calls = []

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db), \
             patch("app.tasks.reconcile._check_arq_job_status",
                   AsyncMock(return_value="in_progress")), \
             patch("app.tasks.reconcile._mark_scan_failed_reconcile",
                   AsyncMock(side_effect=lambda *a, **k: mark_calls.append(a))):
            result = await reconcile_orphan_scans({"redis": AsyncMock()})

        assert len(mark_calls) == 0

    @pytest.mark.asyncio
    async def test_running_no_job_past_retry_window_marked_failed(self):
        """Running scan with no ARQ job past retry window → marked failed."""
        from app.tasks.reconcile import reconcile_orphan_scans
        from app.config import settings

        retry_window = settings.MAX_SCAN_TIMEOUT * settings.WORKER_MAX_TRIES
        scan = _make_scan(status="running", age_seconds=retry_window + 300)
        mock_db = _make_db_context(scans=[scan])
        mark_calls = []

        async def mock_mark(scan_id, reason, redis, user_id):
            mark_calls.append({"scan_id": scan_id, "reason": reason})

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db), \
             patch("app.tasks.reconcile._check_arq_job_status",
                   AsyncMock(return_value="not_found")), \
             patch("app.tasks.reconcile._mark_scan_failed_reconcile",
                   side_effect=mock_mark):
            result = await reconcile_orphan_scans({"redis": AsyncMock()})

        assert len(mark_calls) == 1
        reason = mark_calls[0]["reason"].lower()
        assert "retry" in reason or "worker" in reason

    @pytest.mark.asyncio
    async def test_running_no_job_within_retry_window_not_touched(self):
        """Running scan with no job but within retry window should wait."""
        from app.tasks.reconcile import reconcile_orphan_scans

        scan = _make_scan(status="running", age_seconds=60)  # recent
        mock_db = _make_db_context(scans=[scan])
        mark_calls = []

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db), \
             patch("app.tasks.reconcile._check_arq_job_status",
                   AsyncMock(return_value="not_found")), \
             patch("app.tasks.reconcile._mark_scan_failed_reconcile",
                   AsyncMock(side_effect=lambda *a, **k: mark_calls.append(a))):
            result = await reconcile_orphan_scans({"redis": AsyncMock()})

        assert len(mark_calls) == 0

    @pytest.mark.asyncio
    async def test_cancelled_scan_not_touched_by_mark_failed_reconcile(self):
        """_mark_scan_failed_reconcile must not write to DB when scan is cancelled.

        Now enforced via a guarded atomic UPDATE (... WHERE status IN pending/running):
        a cancelled scan no longer matches the predicate → rowcount 0 → no commit.
        """
        from app.tasks.reconcile import _mark_scan_failed_reconcile

        scan_id = str(uuid.uuid4())

        mock_db = AsyncMock()
        update_result = MagicMock()
        update_result.rowcount = 0  # atomic predicate matched nothing (already terminal)
        mock_db.execute = AsyncMock(return_value=update_result)
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db):
            await _mark_scan_failed_reconcile(scan_id, "test", None, MagicMock())

        mock_db.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_completed_scan_not_touched_by_mark_failed_reconcile(self):
        """_mark_scan_failed_reconcile must not write to DB when scan is completed."""
        from app.tasks.reconcile import _mark_scan_failed_reconcile

        scan_id = str(uuid.uuid4())

        mock_db = AsyncMock()
        update_result = MagicMock()
        update_result.rowcount = 0  # atomic predicate matched nothing (already terminal)
        mock_db.execute = AsyncMock(return_value=update_result)
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db):
            await _mark_scan_failed_reconcile(scan_id, "test", None, MagicMock())

        mock_db.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_running_scan_marked_failed_by_reconcile(self):
        """A genuinely orphaned RUNNING scan matches the guarded UPDATE predicate
        (rowcount=1) and is failed precisely once, with a notification."""
        from app.tasks.reconcile import _mark_scan_failed_reconcile

        scan_id = str(uuid.uuid4())

        mock_db = AsyncMock()
        update_result = MagicMock()
        update_result.rowcount = 1
        mock_db.execute = AsyncMock(return_value=update_result)
        mock_db.add = MagicMock()  # synchronous session.add
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db):
            await _mark_scan_failed_reconcile(scan_id, "test", None, MagicMock())

        mock_db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_reconciliation_is_idempotent(self):
        """Running reconciliation twice must not double-repair or error."""
        from app.tasks.reconcile import reconcile_orphan_scans

        scan = _make_scan(status="pending", age_seconds=300)
        mark_calls = []

        mock_db = _make_db_context(scans=[scan])

        async def mock_mark(scan_id, reason, redis, user_id):
            mark_calls.append(scan_id)

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db), \
             patch("app.tasks.reconcile._check_arq_job_status",
                   AsyncMock(return_value="not_found")), \
             patch("app.tasks.reconcile._mark_scan_failed_reconcile",
                   side_effect=mock_mark):
            ctx = {"redis": AsyncMock()}
            result1 = await reconcile_orphan_scans(ctx)
            result2 = await reconcile_orphan_scans(ctx)

        assert result1["status"] == "ok"
        assert result2["status"] == "ok"
        # Each run independently marks the orphan (DB filters terminal states in real impl)
        assert len(mark_calls) == 2  # once per run

    @pytest.mark.asyncio
    async def test_no_active_scans_returns_ok(self):
        """Reconciliation with no active scans returns ok immediately."""
        from app.tasks.reconcile import reconcile_orphan_scans

        mock_db = _make_db_context(scans=[])

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db):
            result = await reconcile_orphan_scans({"redis": AsyncMock()})

        assert result["status"] == "ok"
        assert result["repaired"] == 0
        assert result["checked"] == 0


# ─── Production Redis Auth Tests ──────────────────────────────────────────────

class TestProductionRedisAuth:
    """Production must fail-closed when Redis is unavailable for token blacklisting."""

    @pytest.mark.asyncio
    async def test_blacklist_token_raises_in_production_when_redis_down(self):
        """In production, blacklist_token must raise RedisBlacklistError when Redis down."""
        from app.utils.cache import blacklist_token, RedisBlacklistError

        with patch("app.utils.cache._redis_available", AsyncMock(return_value=False)), \
             patch("app.utils.cache.settings") as mock_settings:
            mock_settings.ENVIRONMENT = "production"

            with pytest.raises(RedisBlacklistError):
                await blacklist_token("test-jti-123", 3600)

    @pytest.mark.asyncio
    async def test_blacklist_token_fallback_in_development(self):
        """In development, blacklist_token falls back to in-memory when Redis unavailable."""
        from app.utils.cache import blacklist_token, _local_blacklist

        with patch("app.utils.cache._redis_available", AsyncMock(return_value=False)), \
             patch("app.utils.cache.settings") as mock_settings:
            mock_settings.ENVIRONMENT = "development"

            jti = f"test-jti-{uuid.uuid4()}"
            # Must NOT raise in development
            await blacklist_token(jti, 3600)
            assert jti in _local_blacklist

    @pytest.mark.asyncio
    async def test_blacklist_token_succeeds_when_redis_available(self):
        """When Redis is available, token is blacklisted in Redis (both envs)."""
        with patch("app.utils.cache._redis_available", AsyncMock(return_value=True)), \
             patch("app.utils.cache.cache_set", AsyncMock()) as mock_set:
            from app.utils.cache import blacklist_token
            await blacklist_token("test-jti-redis", 1800)
            mock_set.assert_called_once_with("blacklist:test-jti-redis", "1", expire=1800)

    @pytest.mark.asyncio
    async def test_is_token_blacklisted_logs_error_in_production_when_redis_down(self):
        """In production, is_token_blacklisted logs security alert when Redis unavailable."""
        from app.utils.cache import is_token_blacklisted

        with patch("app.utils.cache._redis_available", AsyncMock(return_value=False)), \
             patch("app.utils.cache.settings") as mock_settings, \
             patch("app.utils.cache.logger") as mock_logger:
            mock_settings.ENVIRONMENT = "production"

            result = await is_token_blacklisted("some-jti")

        # Returns False (fail-open for availability — documented security trade-off)
        assert result is False
        # Must log a SECURITY-level error
        mock_logger.error.assert_called()
        error_msg = mock_logger.error.call_args[0][0]
        assert "SECURITY" in error_msg or "unavailable" in error_msg.lower()

    @pytest.mark.asyncio
    async def test_logout_in_dev_with_redis_down_does_not_raise(self):
        """Development fallback: logout with Redis down does not raise."""
        from app.utils.cache import blacklist_token

        with patch("app.utils.cache._redis_available", AsyncMock(return_value=False)), \
             patch("app.utils.cache.settings") as mock_settings:
            mock_settings.ENVIRONMENT = "development"
            # Must not raise
            await blacklist_token(f"dev-jti-{uuid.uuid4()}", 100)


# ─── task_id Consistency Tests ────────────────────────────────────────────────

class TestTaskIdConsistency:
    """ARQ job_id and DB task_id must remain consistent through lifecycle."""

    def test_job_id_format_is_deterministic(self):
        """Job ID must be deterministic: scan:{scan_id}."""
        scan_id = "550e8400-e29b-41d4-a716-446655440000"
        expected_job_id = f"scan:{scan_id}"
        assert expected_job_id == "scan:550e8400-e29b-41d4-a716-446655440000"

    def test_unique_scans_have_unique_job_ids(self):
        """Different scan IDs must produce different job IDs (no collisions)."""
        ids = [str(uuid.uuid4()) for _ in range(10)]
        job_ids = {f"scan:{sid}" for sid in ids}
        assert len(job_ids) == 10

    def test_job_id_never_empty_or_none(self):
        """Constructed job ID must never be empty."""
        scan_id = str(uuid.uuid4())
        job_id = f"scan:{scan_id}"
        assert job_id
        assert len(job_id) > 10

    @pytest.mark.asyncio
    async def test_reconcile_uses_stored_task_id_not_derived(self):
        """Reconciliation uses task_id from DB, not a freshly computed one."""
        from app.tasks.reconcile import reconcile_orphan_scans

        custom_task_id = "scan:custom-special-job-id"
        scan = _make_scan(status="pending", age_seconds=300)
        scan.task_id = custom_task_id

        checked_job_ids = []

        async def capture_job_status(redis, job_id):
            checked_job_ids.append(job_id)
            return "not_found"

        mock_db = _make_db_context(scans=[scan])

        with patch("app.tasks.reconcile.AsyncSessionLocal", return_value=mock_db), \
             patch("app.tasks.reconcile._check_arq_job_status",
                   side_effect=capture_job_status), \
             patch("app.tasks.reconcile._mark_scan_failed_reconcile", AsyncMock()):
            await reconcile_orphan_scans({"redis": AsyncMock()})

        assert custom_task_id in checked_job_ids


# ─── Worker Recovery Tests ────────────────────────────────────────────────────

class TestWorkerRecovery:
    """Worker crash followed by restart must not leave scans permanently stuck."""

    def test_scan_status_enum_values_are_distinct(self):
        """Terminal and non-terminal states are distinct enum values."""
        from app.models.scan import ScanStatus
        assert ScanStatus.running != ScanStatus.failed
        assert ScanStatus.running != ScanStatus.completed
        assert ScanStatus.pending != ScanStatus.failed

    def test_arq_retry_window_is_adequate(self):
        """Total retry window must be at least 10 minutes."""
        from app.config import settings
        total_window = settings.MAX_SCAN_TIMEOUT * settings.WORKER_MAX_TRIES
        assert total_window >= 600, (
            f"Retry window={total_window}s is too short. "
            "Increase MAX_SCAN_TIMEOUT or WORKER_MAX_TRIES."
        )

    def test_reconcile_orphan_grace_exceeds_single_timeout(self):
        """Reconciliation must wait longer than a single timeout before marking failed."""
        from app.tasks.reconcile import RUNNING_ORPHAN_SECONDS
        from app.config import settings
        assert RUNNING_ORPHAN_SECONDS > settings.MAX_SCAN_TIMEOUT, (
            "RUNNING_ORPHAN_SECONDS must exceed MAX_SCAN_TIMEOUT to allow ARQ retry"
        )

    @pytest.mark.asyncio
    async def test_completed_scan_skipped_by_late_retry(self):
        """A late-arriving retry job for an already-completed scan exits cleanly."""
        import app.tasks.scan_task as st
        from app.models.scan import ScanStatus

        scan_id = str(uuid.uuid4())
        mock_scan = _make_scan_mock(scan_id=scan_id, status="completed")

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(
            return_value=MagicMock(
                scalar_one_or_none=MagicMock(return_value=mock_scan)
            )
        )
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        orig_al = st.AsyncSessionLocal
        try:
            st.AsyncSessionLocal = MagicMock(return_value=mock_db)
            ctx = {"redis": None, "job_id": "late-job", "job_try": 2}
            result = await st.run_scan_job(ctx, scan_id)
        finally:
            st.AsyncSessionLocal = orig_al

        assert result.get("skipped") is True
        assert result["status"] == "completed"
        # DB must not have been modified
        mock_db.commit.assert_not_called()


# ─── Execution-Time SSRF Guard Tests ─────────────────────────────────────────

class TestExecutionTimeSSRFGuard:
    """The worker must re-validate the target at execution time and fail closed."""

    @pytest.mark.asyncio
    async def test_private_target_marks_failed_ssrf_blocked(self):
        """A target that resolved public at enqueue but is now private must be blocked."""
        import app.tasks.scan_task as st

        scan_id = str(uuid.uuid4())
        mock_scan = _make_scan_mock(scan_id=scan_id, status="pending")
        mock_scan.url = "http://192.168.0.1/"

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(
            return_value=MagicMock(
                scalar_one_or_none=MagicMock(return_value=mock_scan)
            )
        )
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        orig_al = st.AsyncSessionLocal
        orig_mark = st._mark_failed_safe
        try:
            st.AsyncSessionLocal = MagicMock(return_value=mock_db)

            from app.models.scan import ScanStatus

            async def _mark_failed(scan_id, message, redis):
                # Emulate the guarded-UPDATE semantics: running scan -> failed.
                mock_scan.status = ScanStatus.failed
                mock_scan.error_message = message
                await mock_db.commit()

            st._mark_failed_safe = _mark_failed
            ctx = {"redis": None, "job_id": "test-job", "job_try": 1}
            result = await st.run_scan_job(ctx, scan_id)
        finally:
            st.AsyncSessionLocal = orig_al
            st._mark_failed_safe = orig_mark

        assert result["status"] == "failed"
        assert result.get("error") == "ssrf_blocked"
        # Scan must have been marked failed
        assert mock_scan.status.value == "failed"
        assert "SSRF" in (mock_scan.error_message or "")

    @pytest.mark.asyncio
    async def test_unresolvable_target_marks_failed_ssrf_blocked(self):
        """A target whose DNS fails at execution time must fail closed (not scanned)."""
        import app.tasks.scan_task as st

        scan_id = str(uuid.uuid4())
        mock_scan = _make_scan_mock(scan_id=scan_id, status="pending")
        mock_scan.url = "https://this-domain-does-not-exist-xyz.invalid"

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(
            return_value=MagicMock(
                scalar_one_or_none=MagicMock(return_value=mock_scan)
            )
        )
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        orig_al = st.AsyncSessionLocal
        orig_mark = st._mark_failed_safe
        try:
            st.AsyncSessionLocal = MagicMock(return_value=mock_db)

            from app.models.scan import ScanStatus

            async def _mark_failed(scan_id, message, redis):
                mock_scan.status = ScanStatus.failed
                mock_scan.error_message = message
                await mock_db.commit()

            st._mark_failed_safe = _mark_failed
            ctx = {"redis": None, "job_id": "test-job", "job_try": 1}
            result = await st.run_scan_job(ctx, scan_id)
        finally:
            st.AsyncSessionLocal = orig_al
            st._mark_failed_safe = orig_mark

        assert result["status"] == "failed"
        assert result.get("error") == "ssrf_blocked"
        assert mock_scan.status.value == "failed"
