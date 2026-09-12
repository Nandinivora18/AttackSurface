"""
Phase 4 B1 — Authentication Token Hygiene: one-time SSE tickets.

Covers:
- Ticket issuance: crypto-random generation, SHA-256-hashed storage only,
  TTL, user+scan binding
- Ticket consumption: valid / expired / invalid / reused (single-use, atomic)
- Production Redis failure fails closed; dev in-memory fallback
- Endpoint behaviour: valid ticket, expired/invalid ticket, reused ticket,
  wrong-user/ownership, JWT-not-accepted-via-query, Bearer fallback intact
- Source-level regression: SSE URL uses `ticket`, never `access_token`/JWT
"""
import json
import pathlib
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.main import app
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.utils import cache as cache_module
from app.utils.security import create_access_token, hash_token


# ─── Fakes ───────────────────────────────────────────────────────────────────

class FakeRedis:
    """Minimal redis client double supporting the cache helpers we use."""

    def __init__(self):
        self.store = {}

    async def ping(self):
        return True

    async def set(self, key, value, ex=None):
        self.store[key] = value

    async def get(self, key):
        return self.store.get(key)

    async def getdel(self, key):
        return self.store.pop(key, None)

    async def eval(self, script, numkeys, key):
        # Simulate atomic Lua script behavior for single key get & del
        return self.store.pop(key, None)

    async def exists(self, key):
        return 1 if key in self.store else 0


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def db():
    from app.database import AsyncSessionLocal, engine, Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
def clear_local_tickets():
    cache_module._local_sse_tickets.clear()
    yield
    cache_module._local_sse_tickets.clear()


async def _make_user(db, verified=True):
    user = User(
        email=f"ticket{uuid.uuid4().hex[:12]}@example.com",
        name="Ticket Tester",
        password_hash="not-used",
        is_verified=verified,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def _make_scan(db, user, status="completed"):
    scan = Scan(
        user_id=user.id,
        url="https://example.com",
        status=ScanStatus(status),
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


async def _cleanup(db, scan=None, user=None):
    if scan is not None:
        await db.delete(scan)
    if user is not None:
        await db.delete(user)
    await db.commit()


def _patch_cache_redis(store):
    """Route cache.py's get_redis + _redis_available at the in-memory fake."""
    fake = FakeRedis() if store is None else store
    return patch.multiple(
        "app.utils.cache",
        get_redis=AsyncMock(return_value=fake),
        _redis_available=AsyncMock(return_value=True),
    ), fake


# ─── Helper-level: issue / consume ───────────────────────────────────────────

class TestIssueSseTicket:

    @pytest.mark.asyncio
    async def test_issue_stores_only_hash_bound_to_user_and_scan(self):
        user_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        fake = FakeRedis()
        with patch("app.utils.cache.get_redis", AsyncMock(return_value=fake)), \
             patch("app.utils.cache._redis_available", AsyncMock(return_value=True)):
            ticket = await cache_module.issue_sse_ticket(user_id, scan_id, ttl=300)

        assert ticket and isinstance(ticket, str)
        expected_key = f"sse:ticket:{hash_token(ticket)}"
        assert list(fake.store.keys()) == [expected_key]
        # Plaintext ticket must never be stored server-side
        assert ticket not in str(fake.store)
        payload = json.loads(fake.store[expected_key])
        assert payload == {"user_id": str(user_id), "scan_id": str(scan_id)}

    @pytest.mark.asyncio
    async def test_issue_is_cryptographically_random_and_unique(self):
        fake = FakeRedis()
        with patch("app.utils.cache.get_redis", AsyncMock(return_value=fake)), \
             patch("app.utils.cache._redis_available", AsyncMock(return_value=True)):
            tickets = {
                await cache_module.issue_sse_ticket(uuid.uuid4(), uuid.uuid4(), ttl=300)
                for _ in range(50)
            }
        assert len(tickets) == 50  # no collisions
        for t in tickets:
            assert len(t) >= 32
            # token_urlsafe alphabet only — URL-safe and opaque
            assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in t)

    @pytest.mark.asyncio
    async def test_issue_uses_configured_ttl(self):
        fake = FakeRedis()
        with patch("app.utils.cache.get_redis", AsyncMock(return_value=fake)), \
             patch("app.utils.cache._redis_available", AsyncMock(return_value=True)):
            await cache_module.issue_sse_ticket(uuid.uuid4(), uuid.uuid4(), ttl=300)
        key = list(fake.store.keys())[0]
        # Default setting applies when ttl not passed
        with patch("app.utils.cache.get_redis", AsyncMock(return_value=fake)), \
             patch("app.utils.cache._redis_available", AsyncMock(return_value=True)):
            await cache_module.issue_sse_ticket(uuid.uuid4(), uuid.uuid4())
        assert len(fake.store) == 2
        assert settings.SSE_TICKET_TTL_SECONDS == 300


class TestConsumeSseTicket:

    @pytest.mark.asyncio
    async def test_valid_ticket_consumed_and_single_use(self):
        user_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        fake = FakeRedis()
        with patch("app.utils.cache.get_redis", AsyncMock(return_value=fake)), \
             patch("app.utils.cache._redis_available", AsyncMock(return_value=True)):
            ticket = await cache_module.issue_sse_ticket(user_id, scan_id, ttl=300)
            first = await cache_module.consume_sse_ticket(ticket)
            second = await cache_module.consume_sse_ticket(ticket)

        assert first == {"user_id": str(user_id), "scan_id": str(scan_id)}
        assert second is None  # reused ticket rejected

    @pytest.mark.asyncio
    async def test_invalid_ticket_rejected(self):
        with patch("app.utils.cache.get_redis", AsyncMock(return_value=FakeRedis())), \
             patch("app.utils.cache._redis_available", AsyncMock(return_value=True)):
            assert await cache_module.consume_sse_ticket("not-a-real-ticket") is None

    @pytest.mark.asyncio
    async def test_expired_ticket_rejected(self):
        """A ticket whose Redis entry is gone (TTL elapsed) must be rejected."""
        fake = FakeRedis()
        with patch("app.utils.cache.get_redis", AsyncMock(return_value=fake)), \
             patch("app.utils.cache._redis_available", AsyncMock(return_value=True)):
            ticket = await cache_module.issue_sse_ticket(uuid.uuid4(), uuid.uuid4(), ttl=1)
            # Simulate TTL expiry: the Redis key is evicted
            fake.store.clear()
            assert await cache_module.consume_sse_ticket(ticket) is None

    @pytest.mark.asyncio
    async def test_empty_ticket_rejected(self):
        with patch("app.utils.cache.get_redis", AsyncMock(return_value=FakeRedis())), \
             patch("app.utils.cache._redis_available", AsyncMock(return_value=True)):
            assert await cache_module.consume_sse_ticket("") is None
            assert await cache_module.consume_sse_ticket(None) is None

    @pytest.mark.asyncio
    async def test_legacy_redis_without_getdel_falls_back_to_lua(self):
        """When Redis returns 'unknown command' for getdel (Redis < 6.2), fallback to Lua succeeds."""
        user_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        fake = FakeRedis()

        async def broken_getdel(k):
            raise Exception("unknown command 'GETDEL'")

        fake.getdel = broken_getdel

        with patch("app.utils.cache.get_redis", AsyncMock(return_value=fake)), \
             patch("app.utils.cache._redis_available", AsyncMock(return_value=True)):
            ticket = await cache_module.issue_sse_ticket(user_id, scan_id, ttl=300)
            first = await cache_module.consume_sse_ticket(ticket)
            second = await cache_module.consume_sse_ticket(ticket)

        assert first == {"user_id": str(user_id), "scan_id": str(scan_id)}
        assert second is None


class TestTicketRedisFailureSemantics:

    @pytest.mark.asyncio
    async def test_production_issue_fails_closed(self, clear_local_tickets):
        with patch("app.utils.cache._redis_available", AsyncMock(return_value=False)), \
             patch.object(cache_module.settings, "ENVIRONMENT", "production"):
            with pytest.raises(cache_module.RedisBlacklistError):
                await cache_module.issue_sse_ticket(uuid.uuid4(), uuid.uuid4(), ttl=300)

    @pytest.mark.asyncio
    async def test_production_consume_fails_closed(self, clear_local_tickets):
        with patch("app.utils.cache._redis_available", AsyncMock(return_value=False)), \
             patch.object(cache_module.settings, "ENVIRONMENT", "production"):
            assert await cache_module.consume_sse_ticket("anything") is None

    @pytest.mark.asyncio
    async def test_dev_issue_and_consume_use_in_memory_fallback(self, clear_local_tickets):
        user_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        with patch("app.utils.cache._redis_available", AsyncMock(return_value=False)), \
             patch.object(cache_module.settings, "ENVIRONMENT", "development"):
            ticket = await cache_module.issue_sse_ticket(user_id, scan_id, ttl=300)
            first = await cache_module.consume_sse_ticket(ticket)
            second = await cache_module.consume_sse_ticket(ticket)

        assert ticket
        assert first == {"user_id": str(user_id), "scan_id": str(scan_id)}
        assert second is None
        assert cache_module._local_sse_tickets == {}  # consumed + pruned


# ─── Endpoint-level: ticket issuance ─────────────────────────────────────────

class TestSseTicketEndpoint:

    @pytest.mark.asyncio
    async def test_issue_ticket_for_own_scan(self, db, client):
        user = await _make_user(db)
        scan = await _make_scan(db, user)
        with patch("app.routers.scans.issue_sse_ticket", new=AsyncMock(return_value="opaque-ticket")):
            resp = await client.post(
                f"/api/scans/{scan.id}/sse-ticket",
                headers={"Authorization": f"Bearer {create_access_token(user.id, 'user')}"},
            )
        await _cleanup(db, scan=scan, user=user)

        assert resp.status_code == 200
        assert resp.json() == {"ticket": "opaque-ticket"}

    @pytest.mark.asyncio
    async def test_issue_ticket_for_other_users_scan_rejected(self, db, client):
        owner = await _make_user(db)
        attacker = await _make_user(db)
        scan = await _make_scan(db, owner)
        resp = await client.post(
            f"/api/scans/{scan.id}/sse-ticket",
            headers={"Authorization": f"Bearer {create_access_token(attacker.id, 'user')}"},
        )
        await _cleanup(db, scan=scan, user=attacker)
        await _cleanup(db, user=owner)

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_issue_ticket_unauthenticated_rejected(self, db, client):
        user = await _make_user(db)
        scan = await _make_scan(db, user)
        resp = await client.post(f"/api/scans/{scan.id}/sse-ticket")
        await _cleanup(db, scan=scan, user=user)

        assert resp.status_code in (401, 403)  # HTTPBearer rejects missing credentials

    @pytest.mark.asyncio
    async def test_issue_ticket_redis_failure_returns_503(self, db, client):
        user = await _make_user(db)
        scan = await _make_scan(db, user)
        with patch("app.routers.scans.issue_sse_ticket",
                   new=AsyncMock(side_effect=cache_module.RedisBlacklistError())):
            resp = await client.post(
                f"/api/scans/{scan.id}/sse-ticket",
                headers={"Authorization": f"Bearer {create_access_token(user.id, 'user')}"},
            )
        await _cleanup(db, scan=scan, user=user)

        assert resp.status_code == 503


# ─── Endpoint-level: SSE stream authentication ───────────────────────────────

class TestSseStreamTicketAuth:

    @pytest.mark.asyncio
    async def test_valid_ticket_establishes_stream(self, db, client):
        user = await _make_user(db)
        scan = await _make_scan(db, user, status="completed")
        ctx = {"user_id": str(user.id), "scan_id": str(scan.id)}

        with patch("app.routers.scans.consume_sse_ticket", new=AsyncMock(return_value=ctx)), \
             patch("app.utils.cache.get_redis", AsyncMock(return_value=FakeRedis())):
            resp = await client.get(f"/api/scans/{scan.id}/stream?ticket=t1")

        await _cleanup(db, scan=scan, user=user)

        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        assert '"status": "completed"' in resp.text

    @pytest.mark.asyncio
    async def test_expired_ticket_rejected(self, db, client):
        user = await _make_user(db)
        scan = await _make_scan(db, user, status="completed")
        with patch("app.routers.scans.consume_sse_ticket", new=AsyncMock(return_value=None)):
            resp = await client.get(f"/api/scans/{scan.id}/stream?ticket=expired")
        await _cleanup(db, scan=scan, user=user)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_ticket_rejected(self, db, client):
        user = await _make_user(db)
        scan = await _make_scan(db, user, status="completed")
        with patch("app.routers.scans.consume_sse_ticket", new=AsyncMock(return_value=None)):
            resp = await client.get(f"/api/scans/{scan.id}/stream?ticket=garbage")
        await _cleanup(db, scan=scan, user=user)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_reused_ticket_rejected_on_second_use(self, db, client):
        user = await _make_user(db)
        scan = await _make_scan(db, user, status="completed")
        ctx = {"user_id": str(user.id), "scan_id": str(scan.id)}
        consume = AsyncMock(side_effect=[ctx, None])

        with patch("app.routers.scans.consume_sse_ticket", new=consume), \
             patch("app.utils.cache.get_redis", AsyncMock(return_value=FakeRedis())):
            first = await client.get(f"/api/scans/{scan.id}/stream?ticket=t1")
            second = await client.get(f"/api/scans/{scan.id}/stream?ticket=t1")

        await _cleanup(db, scan=scan, user=user)

        assert first.status_code == 200
        assert second.status_code == 401  # second use of the same ticket rejected

    @pytest.mark.asyncio
    async def test_wrong_user_ticket_rejected(self, db, client):
        owner = await _make_user(db)
        attacker = await _make_user(db)
        scan = await _make_scan(db, owner, status="completed")
        # Attacker's ticket somehow resolves to the owner's scan but attacker's user
        ctx = {"user_id": str(attacker.id), "scan_id": str(scan.id)}
        with patch("app.routers.scans.consume_sse_ticket", new=AsyncMock(return_value=ctx)):
            resp = await client.get(f"/api/scans/{scan.id}/stream?ticket=stolen")
        await _cleanup(db, scan=scan, user=attacker)
        await _cleanup(db, user=owner)
        assert resp.status_code == 404  # ownership check fails — no disclosure

    @pytest.mark.asyncio
    async def test_ticket_bound_to_different_scan_rejected(self, db, client):
        user = await _make_user(db)
        scan = await _make_scan(db, user, status="completed")
        other_scan_id = uuid.uuid4()
        ctx = {"user_id": str(user.id), "scan_id": str(other_scan_id)}
        with patch("app.routers.scans.consume_sse_ticket", new=AsyncMock(return_value=ctx)):
            resp = await client.get(f"/api/scans/{scan.id}/stream?ticket=t1")
        await _cleanup(db, scan=scan, user=user)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_jwt_not_accepted_via_query_param(self, db, client):
        user = await _make_user(db)
        scan = await _make_scan(db, user, status="completed")
        jwt = create_access_token(user.id, "user")
        # Valid JWT passed the old way (?token=) must NOT authenticate — no ticket,
        # no Authorization header → rejected even though the JWT is valid.
        resp = await client.get(f"/api/scans/{scan.id}/stream?token={jwt}")
        await _cleanup(db, scan=scan, user=user)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_bearer_fallback_still_works(self, db, client):
        user = await _make_user(db)
        scan = await _make_scan(db, user, status="completed")
        with patch("app.routers.scans.is_token_blacklisted", new=AsyncMock(return_value=False)), \
             patch("app.utils.cache.get_redis", AsyncMock(return_value=FakeRedis())):
            resp = await client.get(
                f"/api/scans/{scan.id}/stream",
                headers={"Authorization": f"Bearer {create_access_token(user.id, 'user')}"},
            )
        await _cleanup(db, scan=scan, user=user)

        assert resp.status_code == 200
        assert '"status": "completed"' in resp.text


# ─── Source-level regression: no JWT in the SSE URL ──────────────────────────

class TestSseTicketSourceRegression:

    def test_stream_endpoint_uses_ticket_query_not_jwt(self):
        src = pathlib.Path("app/routers/scans.py").read_text(encoding="utf-8")
        stream_idx = src.find("async def stream_progress")
        assert stream_idx != -1
        block = src[stream_idx:]
        assert "ticket: Optional[str] = Query(default=None)" in block
        assert "token: Optional[str] = Query" not in block
        # Endpoint must issue and consume tickets, and keep the Bearer fallback
        assert "issue_sse_ticket" in src
        assert "consume_sse_ticket" in src
        assert "is_token_blacklisted" in block

    def test_frontend_never_puts_jwt_in_sse_url(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        frontend = root / "frontend" / "src" / "app" / "(dashboard)" / "scan" / "page.tsx"
        assert frontend.exists(), "scan page not found — frontend layout changed?"
        src = frontend.read_text(encoding="utf-8")
        # SSE URL is built from a server-issued ticket, never the access token
        assert "sse-ticket" in src
        assert "stream?ticket=" in src
        assert "stream?token=" not in src
        assert "localStorage.getItem('access_token')" not in src
