"""Regression tests for SSE stream reliability (Phase 2).

Covers:
- The publish-before-subscribe race (terminal publish missed during subscribe)
- Pre-subscribe terminal scans (completed / failed / cancelled)
- Synthesized terminal events when no stored event exists
- Normal live streaming still working
- Safety-net recheck for lost terminal publishes
"""
import asyncio
import json

import pytest

from app.utils.progress import stream_progress_events


# ─── Fakes ───────────────────────────────────────────────────────────────────

class FakePubSub:
    def __init__(self, messages=None):
        # messages: list of payload-dicts; None/[] → get_message raises TimeoutError
        self.messages = list(messages or [])
        self.get_calls = 0
        self.subscribed = False
        self.unsubscribed = False
        self.closed = False

    async def subscribe(self, channel):
        self.subscribed = True

    async def unsubscribe(self, channel):
        self.unsubscribed = True

    async def aclose(self):
        self.closed = True

    async def get_message(self, ignore_subscribe_messages=True, timeout=1.0):
        self.get_calls += 1
        if self.messages:
            return {"type": "message", "data": json.dumps(self.messages.pop(0))}
        raise asyncio.TimeoutError()


class FakeRedis:
    def __init__(self, last_event=None, pubsub=None):
        self._last_event = last_event  # raw JSON string or None
        self._pubsub = pubsub if pubsub is not None else FakePubSub()

    async def get(self, key):
        return self._last_event

    async def set(self, key, value, ex=None):
        pass

    async def publish(self, channel, payload):
        pass

    def pubsub(self):
        return self._pubsub


def make_provider(*sequence):
    """Async state_provider returning states in order, then reusing the last."""
    last_val = sequence[-1] if sequence else {"status": "running"}
    states = list(sequence)

    async def prov():
        if states:
            return states.pop(0)
        return last_val

    return prov


async def collect(gen, timeout=5.0):
    """Consume the async generator and return parsed JSON events."""
    events = []

    async def _run():
        async for chunk in gen:
            if chunk.startswith("data: "):
                data = chunk[len("data: "):].strip()
                if data:
                    events.append(json.loads(data))

    await asyncio.wait_for(_run(), timeout=timeout)
    return events


TERMINAL_STATES = ["completed", "failed", "cancelled"]


# ─── Publish-before-subscribe race ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_publish_before_subscribe_race_terminates():
    """A terminal publish missed during subscribe must NOT hang the stream.

    Snapshot says 'running'; worker committed terminal DB state and published a
    terminal event that the (not-yet-subscribed) client missed. The post-
    subscribe DB recheck must synthesize the terminal event and stop without
    ever waiting on the channel.
    """
    pubsub = FakePubSub(messages=[])  # no channel messages will ever arrive
    redis = FakeRedis(
        last_event=json.dumps({
            "scan_id": "s1", "progress": 50, "stage": "SSL/TLS",
            "message": "Checking TLS", "status": "running",
        }),
        pubsub=pubsub,
    )
    provider = make_provider({"status": "completed", "progress": 100, "stage": "Complete"})

    events = await collect(stream_progress_events(
        redis, "s1", db_status="running", db_progress=50, db_stage="SSL/TLS",
        state_provider=provider,
    ))

    assert events[-1]["status"] == "completed"
    assert events[-1]["progress"] == 100
    assert pubsub.get_calls == 0  # never blocked waiting on the channel
    assert pubsub.unsubscribed is True
    assert pubsub.closed is True


# ─── Pre-subscribe terminal scans (synthesized path) ─────────────────────────

@pytest.mark.parametrize("terminal", TERMINAL_STATES)
@pytest.mark.asyncio
async def test_terminal_before_subscribe_synthesized(terminal):
    """A scan already terminal in the DB (no stored event) terminates cleanly."""
    redis = FakeRedis(last_event=None)  # nothing stored → synthesize

    events = await collect(stream_progress_events(
        redis, "s1", db_status=terminal, db_progress=95, db_stage="Finalising",
    ))

    assert len(events) == 1
    event = events[0]
    assert event["status"] == terminal
    assert event["progress"] == 95
    assert event["message"] == f"Scan {terminal}"
    assert event["stage"] == "Finalising"


@pytest.mark.parametrize("terminal", TERMINAL_STATES)
@pytest.mark.asyncio
async def test_terminal_before_subscribe_prefers_stored_event(terminal):
    """When a stored terminal event exists, serve it instead of synthesizing."""
    stored = {
        "scan_id": "s1", "progress": 100, "stage": "Complete",
        "message": "Scan done", "status": terminal,
    }
    redis = FakeRedis(last_event=json.dumps(stored))

    events = await collect(stream_progress_events(
        redis, "s1", db_status=terminal, db_progress=99, db_stage="Old",
    ))

    assert len(events) == 1
    assert events[0] == stored


# ─── Normal live streaming still works ───────────────────────────────────────

@pytest.mark.asyncio
async def test_live_streaming_delivers_events_and_terminates():
    """Fresh connect: initial state, then live events until a terminal message."""
    redis = FakeRedis(
        last_event=None,
        pubsub=FakePubSub(messages=[
            {"scan_id": "s1", "progress": 60, "stage": "Headers", "message": "Checking headers", "status": "running"},
            {"scan_id": "s1", "progress": 100, "stage": "Complete", "message": "Scan completed successfully", "status": "completed"},
        ]),
    )
    provider = make_provider({"status": "running"})  # DB never terminal

    events = await collect(stream_progress_events(
        redis, "s1", db_status="running", db_progress=0, db_stage=None,
        state_provider=provider,
    ))

    assert [e["status"] for e in events] == ["running", "running", "completed"]
    assert events[0]["message"] == "Scan queued and waiting for worker"
    assert events[-1]["status"] == "completed"


@pytest.mark.asyncio
async def test_live_stream_reconnect_recovery_from_last_event():
    """Reconnect: serve stored running event, then live terminal event."""
    redis = FakeRedis(
        last_event=json.dumps({
            "scan_id": "s1", "progress": 45, "stage": "SSL/TLS",
            "message": "Checking TLS", "status": "running",
        }),
        pubsub=FakePubSub(messages=[
            {"scan_id": "s1", "progress": 100, "stage": "Complete", "message": "done", "status": "failed"},
        ]),
    )
    provider = make_provider({"status": "running"})

    events = await collect(stream_progress_events(
        redis, "s1", db_status="running", db_progress=45, db_stage="SSL/TLS",
        state_provider=provider,
    ))

    assert [e["status"] for e in events] == ["running", "failed"]
    assert events[0]["progress"] == 45


@pytest.mark.asyncio
async def test_redis_offline_emits_graceful_error():
    """Redis unavailable: stream emits an error event and stops."""
    events = await collect(stream_progress_events(
        None, "s1", db_status="running", db_progress=10, db_stage="DNS",
    ))

    assert events[0]["status"] == "running"
    assert events[1]["type"] == "error"
    assert "Refresh this page" in events[1]["message"]


# ─── Safety-net recheck for lost terminal publishes ─────────────────────────

@pytest.mark.asyncio
async def test_safety_net_recheck_detects_lost_terminal_publish():
    """If no channel message ever arrives but DB becomes terminal, the stream
    must terminate via the periodic DB recheck (not wait forever)."""
    pubsub = FakePubSub(messages=[])  # channel completely silent
    redis = FakeRedis(last_event=None, pubsub=pubsub)
    provider = make_provider(
        {"status": "running", "progress": 10, "stage": "DNS"},
        {"status": "running", "progress": 50, "stage": "SSL"},
        {"status": "cancelled", "progress": 0, "stage": "Cancelled"},
    )

    events = await collect(stream_progress_events(
        redis, "s1", db_status="running", db_progress=10, db_stage="DNS",
        state_provider=provider,
        recheck_interval=0.05,
    ))

    # Initial state + at least one keepalive ping + terminal event
    pings = [e for e in events if e.get("type") == "ping"]
    assert len(pings) >= 1
    assert events[-1]["status"] == "cancelled"
    assert pubsub.get_calls > 0  # it did wait on the channel before giving up
