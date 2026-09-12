"""
Google OAuth 2.0 — Focused Integration Tests
=============================================
Tests are scoped to the OAuth router only. They mock:
  - The Redis state store (cache_set / cache_get / cache_delete)
  - Google's token and userinfo endpoints (httpx)
  - Settings (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)

No real Google credentials or network calls are made.
All existing password auth/JWT/cookie infrastructure is exercised via the real
app stack (aiosqlite in-memory DB, same as other auth tests).
"""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport, Response as HttpxResponse
from sqlalchemy import select

from app.main import app
from app.database import AsyncSessionLocal
from app.models.user import User
from app.utils.security import hash_password


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_userinfo(
    sub="google-123",
    email="oauthtest@example.com",
    name="OAuth User",
    email_verified=True,
    picture="https://example.com/avatar.jpg",
) -> dict:
    return {
        "sub": sub,
        "email": email,
        "name": name,
        "email_verified": email_verified,
        "picture": picture,
    }


def _mock_google_success(userinfo: dict):
    """
    Return a context-manager-compatible pair of httpx mock responses:
      - POST to token endpoint → {"access_token": "google-at"}
      - GET  to userinfo endpoint → userinfo dict
    """
    token_resp = MagicMock(spec=HttpxResponse)
    token_resp.status_code = 200
    token_resp.json.return_value = {"access_token": "google-at-mock"}

    userinfo_resp = MagicMock(spec=HttpxResponse)
    userinfo_resp.status_code = 200
    userinfo_resp.json.return_value = userinfo

    return token_resp, userinfo_resp


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def db():
    from app.database import engine, Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session


@pytest.fixture(autouse=True)
def reset_oauth_limiter():
    from app.routers.oauth import limiter
    try:
        limiter._storage.reset()
    except Exception:
        pass
    yield
    try:
        limiter._storage.reset()
    except Exception:
        pass


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


async def _cleanup_user(db, email: str):
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if user:
        await db.delete(user)
        await db.commit()


# ─── 1. OAuth start — redirect ─────────────────────────────────────────────────

class TestGoogleLoginStart:
    @pytest.mark.asyncio
    async def test_google_login_redirects_to_google(self, client):
        """When configured, /api/auth/google should redirect to Google's auth URL."""
        with patch("app.routers.oauth.settings") as mock_settings, \
             patch("app.routers.oauth.cache_set", new=AsyncMock()) as mock_cache:
            mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
            mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
            mock_settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/api/auth/google/callback"
            mock_settings.FRONTEND_URL = "http://localhost:3000"

            resp = await client.get("/api/auth/google", follow_redirects=False)

        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "accounts.google.com/o/oauth2/v2/auth" in location
        assert "client_id=test-client-id" in location
        assert "response_type=code" in location
        assert "state=" in location
        # State must have been stored in Redis
        assert mock_cache.called

    @pytest.mark.asyncio
    async def test_google_login_not_configured_redirects_error(self, client):
        """When Google is not configured, redirect to /login?error=oauth_not_configured."""
        with patch("app.routers.oauth.settings") as mock_settings:
            mock_settings.GOOGLE_CLIENT_ID = None
            mock_settings.GOOGLE_CLIENT_SECRET = None
            mock_settings.FRONTEND_URL = "http://localhost:3000"

            resp = await client.get("/api/auth/google", follow_redirects=False)

        assert resp.status_code == 302
        assert "oauth_not_configured" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_google_login_state_parameter_is_present(self, client):
        """The redirect URL must include a state parameter for CSRF protection."""
        with patch("app.routers.oauth.settings") as mock_settings, \
             patch("app.routers.oauth.cache_set", new=AsyncMock()):
            mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
            mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
            mock_settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/api/auth/google/callback"
            mock_settings.FRONTEND_URL = "http://localhost:3000"

            resp = await client.get("/api/auth/google", follow_redirects=False)

        location = resp.headers["location"]
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(location).query)
        assert "state" in qs
        state_val = qs["state"][0]
        assert len(state_val) >= 20  # Cryptographically random, not trivial


# ─── 2. Invalid state / CSRF protection ───────────────────────────────────────

class TestOAuthStateValidation:
    @pytest.mark.asyncio
    async def test_missing_state_redirects_invalid_state(self, client):
        """Callback with no state parameter → oauth_invalid_state."""
        with patch("app.routers.oauth.settings") as mock_settings:
            mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
            mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
            mock_settings.FRONTEND_URL = "http://localhost:3000"

            resp = await client.get(
                "/api/auth/google/callback?code=somecode",
                follow_redirects=False,
            )

        assert resp.status_code == 302
        assert "oauth_invalid_state" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_unknown_state_redirects_invalid_state(self, client):
        """Callback with an unrecognised state → oauth_invalid_state (state not in Redis)."""
        with patch("app.routers.oauth.settings") as mock_settings, \
             patch("app.routers.oauth.cache_get", new=AsyncMock(return_value=None)):
            mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
            mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
            mock_settings.FRONTEND_URL = "http://localhost:3000"

            resp = await client.get(
                "/api/auth/google/callback?code=somecode&state=forged-state-token",
                follow_redirects=False,
            )

        assert resp.status_code == 302
        assert "oauth_invalid_state" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_expired_state_redirects_invalid_state(self, client):
        """An expired OAuth state (TTL elapsed, Redis returned None) → oauth_invalid_state."""
        # Same as unknown — Redis returns None for expired keys
        with patch("app.routers.oauth.settings") as mock_settings, \
             patch("app.routers.oauth.cache_get", new=AsyncMock(return_value=None)):
            mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
            mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
            mock_settings.FRONTEND_URL = "http://localhost:3000"

            resp = await client.get(
                "/api/auth/google/callback?code=somecode&state=expired-state",
                follow_redirects=False,
            )

        assert resp.status_code == 302
        assert "oauth_invalid_state" in resp.headers["location"]


# ─── 3. User-cancelled OAuth ──────────────────────────────────────────────────

class TestOAuthCancellation:
    @pytest.mark.asyncio
    async def test_user_cancelled_redirects_oauth_cancelled(self, client):
        """Google sends ?error=access_denied when user clicks Cancel → oauth_cancelled."""
        with patch("app.routers.oauth.settings") as mock_settings, \
             patch("app.routers.oauth.cache_get", new=AsyncMock(return_value="1")), \
             patch("app.routers.oauth.cache_delete", new=AsyncMock()):
            mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
            mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
            mock_settings.FRONTEND_URL = "http://localhost:3000"

            resp = await client.get(
                "/api/auth/google/callback?error=access_denied&state=valid-state",
                follow_redirects=False,
            )

        assert resp.status_code == 302
        assert "oauth_cancelled" in resp.headers["location"]


# ─── 4. Callback errors — invalid/missing code ────────────────────────────────

class TestOAuthCallbackErrors:
    @pytest.mark.asyncio
    async def test_missing_code_redirects_oauth_failed(self, client):
        """No code in callback (and no error) → oauth_failed."""
        with patch("app.routers.oauth.settings") as mock_settings, \
             patch("app.routers.oauth.cache_get", new=AsyncMock(return_value="1")), \
             patch("app.routers.oauth.cache_delete", new=AsyncMock()):
            mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
            mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
            mock_settings.FRONTEND_URL = "http://localhost:3000"

            resp = await client.get(
                "/api/auth/google/callback?state=valid-state",
                follow_redirects=False,
            )

        assert resp.status_code == 302
        assert "oauth_failed" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_google_token_exchange_failure_redirects_oauth_failed(self, client):
        """Google returns non-200 on token exchange → oauth_failed."""
        bad_token_resp = MagicMock(spec=HttpxResponse)
        bad_token_resp.status_code = 400

        with patch("app.routers.oauth.settings") as mock_settings, \
             patch("app.routers.oauth.cache_get", new=AsyncMock(return_value="1")), \
             patch("app.routers.oauth.cache_delete", new=AsyncMock()), \
             patch("httpx.AsyncClient") as mock_httpx:
            mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
            mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
            mock_settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/api/auth/google/callback"
            mock_settings.FRONTEND_URL = "http://localhost:3000"
            mock_settings.REQUIRE_EMAIL_VERIFICATION = True

            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_ctx.post = AsyncMock(return_value=bad_token_resp)
            mock_httpx.return_value = mock_ctx

            resp = await client.get(
                "/api/auth/google/callback?code=bad-code&state=valid-state",
                follow_redirects=False,
            )

        assert resp.status_code == 302
        assert "oauth_failed" in resp.headers["location"]


# ─── 5. Unverified email rejection ────────────────────────────────────────────

class TestOAuthUnverifiedEmail:
    @pytest.mark.asyncio
    async def test_unverified_google_email_rejected(self, client):
        """Google accounts with email_verified=False must be rejected when verification required."""
        userinfo = _make_userinfo(email_verified=False)
        token_resp, userinfo_resp = _mock_google_success(userinfo)

        with patch("app.routers.oauth.settings") as mock_settings, \
             patch("app.routers.oauth.cache_get", new=AsyncMock(return_value="1")), \
             patch("app.routers.oauth.cache_delete", new=AsyncMock()), \
             patch("httpx.AsyncClient") as mock_httpx:
            mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
            mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
            mock_settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/callback"
            mock_settings.FRONTEND_URL = "http://localhost:3000"
            mock_settings.REQUIRE_EMAIL_VERIFICATION = True

            # First call: token exchange; second call: userinfo
            ctx1 = AsyncMock()
            ctx1.__aenter__ = AsyncMock(return_value=ctx1)
            ctx1.__aexit__ = AsyncMock(return_value=False)
            ctx1.post = AsyncMock(return_value=token_resp)

            ctx2 = AsyncMock()
            ctx2.__aenter__ = AsyncMock(return_value=ctx2)
            ctx2.__aexit__ = AsyncMock(return_value=False)
            ctx2.get = AsyncMock(return_value=userinfo_resp)

            mock_httpx.side_effect = [ctx1, ctx2]

            resp = await client.get(
                "/api/auth/google/callback?code=good-code&state=valid-state",
                follow_redirects=False,
            )

        assert resp.status_code == 302
        assert "oauth_unverified_email" in resp.headers["location"]


# ─── 6. Duplicate email — account-linking protection ─────────────────────────

class TestOAuthAccountLinking:
    @pytest.mark.asyncio
    async def test_existing_password_account_not_silently_linked(self, client, db):
        """
        If a password account exists with the same email, Google OAuth must REJECT
        with oauth_email_exists — it must NOT silently take over the account.
        """
        email = "existing-password@example.com"
        await _cleanup_user(db, email)

        # Create a password-based account
        user = User(
            email=email,
            name="Password User",
            password_hash=hash_password("Password123!"),
            is_verified=True,
        )
        db.add(user)
        await db.commit()

        userinfo = _make_userinfo(sub="google-new-sub", email=email)
        token_resp, userinfo_resp = _mock_google_success(userinfo)

        try:
            with patch("app.routers.oauth.settings") as mock_settings, \
                 patch("app.routers.oauth.cache_get", new=AsyncMock(return_value="1")), \
                 patch("app.routers.oauth.cache_delete", new=AsyncMock()), \
                 patch("httpx.AsyncClient") as mock_httpx:
                mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
                mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
                mock_settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/callback"
                mock_settings.FRONTEND_URL = "http://localhost:3000"
                mock_settings.REQUIRE_EMAIL_VERIFICATION = False

                ctx1 = AsyncMock()
                ctx1.__aenter__ = AsyncMock(return_value=ctx1)
                ctx1.__aexit__ = AsyncMock(return_value=False)
                ctx1.post = AsyncMock(return_value=token_resp)

                ctx2 = AsyncMock()
                ctx2.__aenter__ = AsyncMock(return_value=ctx2)
                ctx2.__aexit__ = AsyncMock(return_value=False)
                ctx2.get = AsyncMock(return_value=userinfo_resp)

                mock_httpx.side_effect = [ctx1, ctx2]

                resp = await client.get(
                    "/api/auth/google/callback?code=good-code&state=valid-state",
                    follow_redirects=False,
                )

            assert resp.status_code == 302
            assert "oauth_email_exists" in resp.headers["location"]

            # Verify the password account was NOT modified
            await db.refresh(user)
            assert user.google_id is None, "Password account must not be linked to Google"
        finally:
            await _cleanup_user(db, email)

    @pytest.mark.asyncio
    async def test_existing_google_account_logs_in(self, client, db):
        """
        A user who previously linked their Google account should be able to log in
        successfully and get a SentinelScan JWT.
        """
        email = "google-returning@example.com"
        await _cleanup_user(db, email)

        # Create an existing Google-linked account
        user = User(
            email=email,
            name="Google User",
            google_id="google-returning-sub",
            is_verified=True,
        )
        db.add(user)
        await db.commit()

        userinfo = _make_userinfo(sub="google-returning-sub", email=email)
        token_resp, userinfo_resp = _mock_google_success(userinfo)

        try:
            with patch("app.routers.oauth.settings") as mock_settings, \
                 patch("app.routers.oauth.cache_get", new=AsyncMock(return_value="1")), \
                 patch("app.routers.oauth.cache_delete", new=AsyncMock()), \
                 patch("httpx.AsyncClient") as mock_httpx:
                mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
                mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
                mock_settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/callback"
                mock_settings.FRONTEND_URL = "http://localhost:3000"
                mock_settings.REQUIRE_EMAIL_VERIFICATION = True
                mock_settings.REFRESH_TOKEN_EXPIRE_DAYS = 7
                mock_settings.ENVIRONMENT = "development"

                ctx1 = AsyncMock()
                ctx1.__aenter__ = AsyncMock(return_value=ctx1)
                ctx1.__aexit__ = AsyncMock(return_value=False)
                ctx1.post = AsyncMock(return_value=token_resp)

                ctx2 = AsyncMock()
                ctx2.__aenter__ = AsyncMock(return_value=ctx2)
                ctx2.__aexit__ = AsyncMock(return_value=False)
                ctx2.get = AsyncMock(return_value=userinfo_resp)

                mock_httpx.side_effect = [ctx1, ctx2]

                resp = await client.get(
                    "/api/auth/google/callback?code=good-code&state=valid-state",
                    follow_redirects=False,
                )

            # Expect redirect to /auth/callback with access_token in fragment
            assert resp.status_code == 302
            location = resp.headers["location"]
            assert "/auth/callback" in location
            assert "access_token=" in location
            # Refresh token must NOT be in the URL
            assert "refresh_token" not in location
        finally:
            await _cleanup_user(db, email)


# ─── 7. New Google user — account creation ────────────────────────────────────

class TestOAuthNewUser:
    @pytest.mark.asyncio
    async def test_new_google_user_creates_account(self, client, db):
        """A first-time Google user gets a new account and a valid JWT redirect."""
        email = "google-brand-new@example.com"
        await _cleanup_user(db, email)

        userinfo = _make_userinfo(sub="google-new-user-sub", email=email)
        token_resp, userinfo_resp = _mock_google_success(userinfo)

        try:
            with patch("app.routers.oauth.settings") as mock_settings, \
                 patch("app.routers.oauth.cache_get", new=AsyncMock(return_value="1")), \
                 patch("app.routers.oauth.cache_delete", new=AsyncMock()), \
                 patch("httpx.AsyncClient") as mock_httpx:
                mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
                mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
                mock_settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/callback"
                mock_settings.FRONTEND_URL = "http://localhost:3000"
                mock_settings.REQUIRE_EMAIL_VERIFICATION = False
                mock_settings.REFRESH_TOKEN_EXPIRE_DAYS = 7
                mock_settings.ENVIRONMENT = "development"

                ctx1 = AsyncMock()
                ctx1.__aenter__ = AsyncMock(return_value=ctx1)
                ctx1.__aexit__ = AsyncMock(return_value=False)
                ctx1.post = AsyncMock(return_value=token_resp)

                ctx2 = AsyncMock()
                ctx2.__aenter__ = AsyncMock(return_value=ctx2)
                ctx2.__aexit__ = AsyncMock(return_value=False)
                ctx2.get = AsyncMock(return_value=userinfo_resp)

                mock_httpx.side_effect = [ctx1, ctx2]

                resp = await client.get(
                    "/api/auth/google/callback?code=good-code&state=valid-state",
                    follow_redirects=False,
                )

            assert resp.status_code == 302
            location = resp.headers["location"]
            assert "/auth/callback" in location
            assert "access_token=" in location

            # Verify user was actually created in DB
            result = await db.execute(select(User).where(User.email == email))
            new_user = result.scalar_one_or_none()
            assert new_user is not None
            assert new_user.google_id == "google-new-user-sub"
            assert new_user.password_hash is None  # Google-only account
        finally:
            await _cleanup_user(db, email)


# ─── 8. SentinelScan JWT issuance ─────────────────────────────────────────────

class TestOAuthJWTIssuance:
    @pytest.mark.asyncio
    async def test_redirect_fragment_contains_access_token_not_refresh(self, client, db):
        """
        The /auth/callback redirect fragment must contain access_token ONLY.
        The refresh_token must be delivered exclusively as an HttpOnly cookie.
        """
        email = "jwt-test@example.com"
        await _cleanup_user(db, email)

        user = User(
            email=email,
            name="JWT Test",
            google_id="google-jwt-sub",
            is_verified=True,
        )
        db.add(user)
        await db.commit()

        userinfo = _make_userinfo(sub="google-jwt-sub", email=email)
        token_resp, userinfo_resp = _mock_google_success(userinfo)

        try:
            with patch("app.routers.oauth.settings") as mock_settings, \
                 patch("app.routers.oauth.cache_get", new=AsyncMock(return_value="1")), \
                 patch("app.routers.oauth.cache_delete", new=AsyncMock()), \
                 patch("httpx.AsyncClient") as mock_httpx:
                mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
                mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
                mock_settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/callback"
                mock_settings.FRONTEND_URL = "http://localhost:3000"
                mock_settings.REQUIRE_EMAIL_VERIFICATION = True
                mock_settings.REFRESH_TOKEN_EXPIRE_DAYS = 7
                mock_settings.ENVIRONMENT = "development"

                ctx1 = AsyncMock()
                ctx1.__aenter__ = AsyncMock(return_value=ctx1)
                ctx1.__aexit__ = AsyncMock(return_value=False)
                ctx1.post = AsyncMock(return_value=token_resp)

                ctx2 = AsyncMock()
                ctx2.__aenter__ = AsyncMock(return_value=ctx2)
                ctx2.__aexit__ = AsyncMock(return_value=False)
                ctx2.get = AsyncMock(return_value=userinfo_resp)

                mock_httpx.side_effect = [ctx1, ctx2]

                resp = await client.get(
                    "/api/auth/google/callback?code=good-code&state=valid-state",
                    follow_redirects=False,
                )

            assert resp.status_code == 302
            location = resp.headers["location"]

            # access_token must be in the fragment
            assert "#access_token=" in location

            # refresh_token must NOT appear in the URL at all
            assert "refresh_token" not in location
        finally:
            await _cleanup_user(db, email)

    @pytest.mark.asyncio
    async def test_httponly_refresh_cookie_is_set(self, client, db):
        """The HttpOnly refresh_token cookie must be set on the callback response."""
        email = "cookie-test@example.com"
        await _cleanup_user(db, email)

        user = User(
            email=email,
            name="Cookie Test",
            google_id="google-cookie-sub",
            is_verified=True,
        )
        db.add(user)
        await db.commit()

        userinfo = _make_userinfo(sub="google-cookie-sub", email=email)
        token_resp, userinfo_resp = _mock_google_success(userinfo)

        try:
            with patch("app.routers.oauth.settings") as mock_settings, \
                 patch("app.routers.oauth.cache_get", new=AsyncMock(return_value="1")), \
                 patch("app.routers.oauth.cache_delete", new=AsyncMock()), \
                 patch("httpx.AsyncClient") as mock_httpx:
                mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
                mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
                mock_settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/callback"
                mock_settings.FRONTEND_URL = "http://localhost:3000"
                mock_settings.REQUIRE_EMAIL_VERIFICATION = True
                mock_settings.REFRESH_TOKEN_EXPIRE_DAYS = 7
                mock_settings.ENVIRONMENT = "development"  # No Secure flag in dev

                ctx1 = AsyncMock()
                ctx1.__aenter__ = AsyncMock(return_value=ctx1)
                ctx1.__aexit__ = AsyncMock(return_value=False)
                ctx1.post = AsyncMock(return_value=token_resp)

                ctx2 = AsyncMock()
                ctx2.__aenter__ = AsyncMock(return_value=ctx2)
                ctx2.__aexit__ = AsyncMock(return_value=False)
                ctx2.get = AsyncMock(return_value=userinfo_resp)

                mock_httpx.side_effect = [ctx1, ctx2]

                resp = await client.get(
                    "/api/auth/google/callback?code=good-code&state=valid-state",
                    follow_redirects=False,
                )

            # Cookie must be set
            set_cookie = resp.headers.get("set-cookie", "")
            assert "refresh_token=" in set_cookie
            assert "HttpOnly" in set_cookie
            assert "Path=/api/auth" in set_cookie
        finally:
            await _cleanup_user(db, email)


# ─── 9. OAuth state is single-use ─────────────────────────────────────────────

class TestOAuthStateIsSingleUse:
    @pytest.mark.asyncio
    async def test_state_is_deleted_after_use(self, client):
        """
        cache_delete must be called exactly once for the state key,
        regardless of whether the rest of the callback succeeds or fails.
        This ensures state tokens cannot be replayed.
        """
        mock_cache_delete = AsyncMock()

        with patch("app.routers.oauth.settings") as mock_settings, \
             patch("app.routers.oauth.cache_get", new=AsyncMock(return_value="1")), \
             patch("app.routers.oauth.cache_delete", new=mock_cache_delete), \
             patch("httpx.AsyncClient") as mock_httpx:
            mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
            mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
            mock_settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/callback"
            mock_settings.FRONTEND_URL = "http://localhost:3000"
            mock_settings.REQUIRE_EMAIL_VERIFICATION = True

            # Force token exchange to fail after state is consumed
            bad_resp = MagicMock(spec=HttpxResponse)
            bad_resp.status_code = 503
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=ctx)
            ctx.__aexit__ = AsyncMock(return_value=False)
            ctx.post = AsyncMock(return_value=bad_resp)
            mock_httpx.return_value = ctx

            await client.get(
                "/api/auth/google/callback?code=some-code&state=valid-state",
                follow_redirects=False,
            )

        # State must have been consumed (deleted) exactly once
        mock_cache_delete.assert_called_once()


# ─── 10. Missing Google identity fields ───────────────────────────────────────

class TestOAuthMissingIdentityFields:
    @pytest.mark.asyncio
    async def test_missing_sub_redirects_oauth_missing_info(self, client):
        """Google returning no 'sub' field → oauth_missing_info."""
        userinfo_no_sub = _make_userinfo()
        userinfo_no_sub.pop("sub")

        token_resp = MagicMock(spec=HttpxResponse)
        token_resp.status_code = 200
        token_resp.json.return_value = {"access_token": "google-at-mock"}

        userinfo_resp = MagicMock(spec=HttpxResponse)
        userinfo_resp.status_code = 200
        userinfo_resp.json.return_value = userinfo_no_sub

        with patch("app.routers.oauth.settings") as mock_settings, \
             patch("app.routers.oauth.cache_get", new=AsyncMock(return_value="1")), \
             patch("app.routers.oauth.cache_delete", new=AsyncMock()), \
             patch("httpx.AsyncClient") as mock_httpx:
            mock_settings.GOOGLE_CLIENT_ID = "test-client-id"
            mock_settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
            mock_settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/callback"
            mock_settings.FRONTEND_URL = "http://localhost:3000"
            mock_settings.REQUIRE_EMAIL_VERIFICATION = True

            ctx1 = AsyncMock()
            ctx1.__aenter__ = AsyncMock(return_value=ctx1)
            ctx1.__aexit__ = AsyncMock(return_value=False)
            ctx1.post = AsyncMock(return_value=token_resp)

            ctx2 = AsyncMock()
            ctx2.__aenter__ = AsyncMock(return_value=ctx2)
            ctx2.__aexit__ = AsyncMock(return_value=False)
            ctx2.get = AsyncMock(return_value=userinfo_resp)

            mock_httpx.side_effect = [ctx1, ctx2]

            resp = await client.get(
                "/api/auth/google/callback?code=good-code&state=valid-state",
                follow_redirects=False,
            )

        assert resp.status_code == 302
        assert "oauth_missing_info" in resp.headers["location"]
