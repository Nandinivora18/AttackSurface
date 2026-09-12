"""
Regression tests for authentication route rate limiting (SlowAPI).

Verifies that abuse-sensitive endpoints (reset-password, verify-email,
oauth, refresh, logout) enforce rate limits and return HTTP 429 when
thresholds are exceeded, while preserving legitimate functionality.
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.fixture(autouse=True)
def reset_limiters():
    """Ensure limiter buckets are clean before and after each test."""
    from app.main import app
    from app.routers import auth, oauth
    for lim in [app.state.limiter, auth.limiter, oauth.limiter]:
        try:
            lim._storage.reset()
        except Exception:
            pass
    yield
    for lim in [app.state.limiter, auth.limiter, oauth.limiter]:
        try:
            lim._storage.reset()
        except Exception:
            pass


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_reset_password_rate_limit_exceeded(client: AsyncClient):
    """Calling /api/auth/reset-password more than 5 times in a minute returns 429."""
    # First 5 attempts return 400 (invalid token), but are accepted by the limiter
    for _ in range(5):
        resp = await client.post(
            "/api/auth/reset-password",
            json={"token": "testtoken123", "new_password": "NewPassword123!"},
        )
        assert resp.status_code == 400

    # 6th attempt must exceed the 5/minute limit and return 429
    resp = await client.post(
        "/api/auth/reset-password",
        json={"token": "testtoken123", "new_password": "NewPassword123!"},
    )
    assert resp.status_code == 429
    assert "Too Many Requests" in resp.text or "rate limit exceeded" in resp.text.lower()


@pytest.mark.asyncio
async def test_verify_email_rate_limit_exceeded(client: AsyncClient):
    """Calling /api/auth/verify-email/{token} more than 10 times in a minute returns 429 even with distinct tokens."""
    for i in range(10):
        resp = await client.get(f"/api/auth/verify-email/testtoken{i}")
        assert resp.status_code == 400

    # 11th attempt must trigger 429
    resp = await client.get("/api/auth/verify-email/testtoken10")
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_google_oauth_rate_limit_exceeded(client: AsyncClient):
    """Calling /api/auth/google more than 20 times in a minute returns 429."""
    # When OAuth is not configured, it returns 307 redirect to error page
    for _ in range(20):
        resp = await client.get("/api/auth/google", follow_redirects=False)
        assert resp.status_code in (302, 307)

    # 21st attempt returns 429
    resp = await client.get("/api/auth/google", follow_redirects=False)
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_refresh_token_rate_limit_allows_normal_traffic(client: AsyncClient):
    """Calling /api/auth/refresh without a token returns 401, but is within the 30/min limit for first few calls."""
    for _ in range(5):
        resp = await client.post("/api/auth/refresh")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_rate_limit_allows_normal_traffic(client: AsyncClient):
    """Calling /api/auth/logout without a token returns 200, within the 20/min limit."""
    for _ in range(5):
        resp = await client.post("/api/auth/logout")
        assert resp.status_code == 200
