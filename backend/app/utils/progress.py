"""
Cross-process scan progress via Redis Pub/Sub.

Architecture:
  Worker  →  Redis channel "scan:progress:{scan_id}"  →  SSE endpoint  →  Browser

The channel carries JSON-encoded progress events.
On SSE connect, the endpoint first emits the current DB state for reconnect recovery,
then subscribes to live events.
"""
import asyncio
import json
import logging
import time
from typing import AsyncGenerator, Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

PROGRESS_CHANNEL_PREFIX = "scan:progress:"
PROGRESS_TTL = 3600  # keep last event in Redis for 1 hour (for late SSE connects)
LAST_EVENT_KEY_PREFIX = "scan:last_event:"
# Safety-net cadence for re-checking terminal DB state while streaming. Redis
# pub/sub only delivers to subscribers present at publish time, so a terminal
# publish can in principle be lost; workers always commit the terminal DB state
# BEFORE publishing, so a slow DB re-check guarantees eventual termination
# without busy polling.
TERMINAL_RECHECK_INTERVAL = 30


def _channel(scan_id: str) -> str:
    return f"{PROGRESS_CHANNEL_PREFIX}{scan_id}"


def _last_event_key(scan_id: str) -> str:
    return f"{LAST_EVENT_KEY_PREFIX}{scan_id}"


async def publish_progress(
    redis,
    scan_id: str,
    progress: int,
    stage: str,
    message: str,
    status: str = "running",
    timeline: Optional[list] = None,
    report_id: Optional[str] = None,
    findings_count: Optional[int] = None,
) -> None:
    """Publish a progress event to Redis Pub/Sub and store as last known state."""
    event = {
        "scan_id": scan_id,
        "progress": progress,
        "stage": stage,
        "message": message,
        "status": status,
    }
    if timeline is not None:
        event["timeline"] = timeline
    if report_id is not None:
        event["report_id"] = str(report_id)
    if findings_count is not None:
        event["findings_count"] = findings_count

    payload = json.dumps(event)

    try:
        # Store last event for reconnect recovery (even before any subscribers)
        await redis.set(_last_event_key(scan_id), payload, ex=PROGRESS_TTL)
        # Publish to pub/sub channel
        await redis.publish(_channel(scan_id), payload)
    except Exception as e:
        logger.warning(f"Redis progress publish failed for scan {scan_id}: {e}")


async def get_last_event(redis, scan_id: str) -> Optional[dict]:
    """Retrieve the last persisted progress event for reconnect recovery."""
    try:
        raw = await redis.get(_last_event_key(scan_id))
        if raw:
            return json.loads(raw)
    except Exception as e:
        logger.warning(f"Redis get_last_event failed for scan {scan_id}: {e}")
    return None


async def stream_progress_events(
    redis,
    scan_id: str,
    db_status: str,
    db_progress: int,
    db_stage: Optional[str],
    state_provider: Optional[Callable[[], Awaitable[Optional[dict]]]] = None,
    recheck_interval: float = TERMINAL_RECHECK_INTERVAL,
) -> AsyncGenerator[str, None]:
    """
    Async generator for SSE: yields Server-Sent Event strings.

    1. First yields the current DB state (reconnect recovery).
    2. Subscribes to Redis Pub/Sub.
    3. Re-checks the DB terminal state once subscribed (closes the
       publish-before-subscribe race — workers commit the terminal DB state
       before publishing, so a publish missed during subscribe is always
       recoverable from the DB).
    4. Streams live events until terminal state or disconnect, re-checking the
       DB occasionally as a safety net for lost terminal publishes.

    state_provider: optional async callable returning the current scan state
    dict {"status", "progress", "stage"} (or None). Used for the post-subscribe
    reconciliation and periodic safety-net recheck.
    """

    def _fmt(data: dict) -> str:
        return f"data: {json.dumps(data)}\n\n"

    async def _terminal_event(state: dict) -> str:
        """Best terminal event: last stored event if terminal, else synthesize."""
        last = await get_last_event(redis, scan_id)
        if last and last.get("status") in ("completed", "failed", "cancelled"):
            return _fmt(last)
        status = state["status"]
        return _fmt({
            "scan_id": scan_id,
            "progress": state.get("progress", db_progress),
            "stage": state.get("stage") or status.capitalize(),
            "message": f"Scan {status}",
            "status": status,
        })

    async def _resolve_terminal_state() -> Optional[dict]:
        """Return a terminal state dict from state_provider, else None."""
        if state_provider is None:
            return None
        try:
            state = await state_provider()
        except Exception as e:
            logger.warning(f"SSE terminal state check failed for scan {scan_id}: {e}")
            return None
        if not state or state.get("status") not in ("completed", "failed", "cancelled"):
            return None
        return state

    # --- Step 1: Emit current state immediately (supports browser refresh) ---
    # Check if already in terminal state first
    if db_status in ("completed", "failed", "cancelled"):
        # Try to serve the last stored event, otherwise synthesise from DB
        yield await _terminal_event({
            "status": db_status,
            "progress": db_progress,
            "stage": db_stage,
        })
        return  # Terminal — no need to subscribe

    # Emit current non-terminal state for reconnect
    last = await get_last_event(redis, scan_id)
    if last:
        yield _fmt(last)
    else:
        yield _fmt({
            "scan_id": scan_id,
            "progress": db_progress,
            "stage": db_stage or "Queued",
            "message": "Scan queued and waiting for worker",
            "status": db_status,
        })

    # --- Step 2: Subscribe to live events ---
    if redis is None:
        # Redis unavailable — cannot deliver real-time events. Emit a graceful
        # error message so the client can surface a human-readable status
        # (e.g., "Refresh to see final status") rather than a silent disconnect.
        yield _fmt({
            "type": "error",
            "message": "Real-time progress unavailable (Redis offline). Refresh this page to see the latest scan status.",
            "status": db_status,
        })
        return

    pubsub = redis.pubsub()
    try:
        await pubsub.subscribe(_channel(scan_id))

        # --- Step 3: Post-subscribe reconciliation (publish-before-subscribe race) ---
        # Any terminal publish that happened before our subscribe is lost. Workers
        # commit the terminal DB state BEFORE publishing, so if we missed the
        # publish the DB is already terminal now that we are subscribed.
        terminal_state = await _resolve_terminal_state()
        if terminal_state is not None:
            yield await _terminal_event(terminal_state)
            return

        last_recheck = time.monotonic()

        # --- Step 4: Stream live events ---
        while True:
            try:
                # Poll with short timeout to allow client disconnect detection
                message = await asyncio.wait_for(
                    pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                # Send keepalive ping
                yield 'data: {"type":"ping"}\n\n'
                # Safety net: confirm the scan hasn't reached a terminal state
                # via a publish we missed (e.g. transient Redis error).
                if time.monotonic() - last_recheck >= recheck_interval:
                    terminal_state = await _resolve_terminal_state()
                    if terminal_state is not None:
                        yield await _terminal_event(terminal_state)
                        return
                    last_recheck = time.monotonic()
                continue

            if message is None:
                # No message yet, send keepalive
                yield 'data: {"type":"ping"}\n\n'
                await asyncio.sleep(0.5)
                continue

            if message.get("type") == "message":
                try:
                    event = json.loads(message["data"])
                    yield _fmt(event)
                    if event.get("status") in ("completed", "failed", "cancelled"):
                        break
                except (json.JSONDecodeError, KeyError):
                    pass

    except GeneratorExit:
        pass  # Client disconnected
    except Exception as e:
        logger.warning(f"SSE stream error for scan {scan_id}: {e}")
    finally:
        try:
            await pubsub.unsubscribe(_channel(scan_id))
            await pubsub.aclose()
        except Exception:
            pass
