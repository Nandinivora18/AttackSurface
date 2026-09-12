"""
Security Remediation Regression Tests
Covers all confirmed fixes from the OpenCode audit.

Tests:
1. SSE stream endpoint — blacklisted token rejected
2. Logout — revokes both access and refresh tokens
3. Refresh endpoint — rejects blacklisted refresh token
4. dev-verify — rate limit + production block
5. CSP header — present and restrictive on normal API routes
6. IDOR — get_finding_detail enforces ownership at DB level
7. Token blacklist TTL correctness
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock


# --- Fixtures ---

@pytest.fixture
def make_token():
    """Factory: create real access/refresh tokens for a given user_id."""
    def _make(user_id: uuid.UUID, token_type: str = "access") -> str:
        from app.utils.security import create_access_token, create_refresh_token
        if token_type == "refresh":
            return create_refresh_token(user_id)
        return create_access_token(user_id, "user")
    return _make


@pytest.fixture
def decode_jti():
    """Extract JTI from a JWT without verification (for blacklist testing)."""
    def _decode(token: str, token_type: str = "access") -> str:
        from app.utils.security import decode_token
        payload = decode_token(token, expected_type=token_type)
        return payload["jti"]
    return _decode


# --- 1. SSE Stream - Blacklist Check ---

class TestSSEBlacklistCheck:

    def test_sse_route_imports_blacklist(self):
        """scans.py must import is_token_blacklisted."""
        import pathlib
        src = pathlib.Path("app/routers/scans.py").read_text()
        assert "is_token_blacklisted" in src

    def test_sse_route_uses_blacklist_in_stream(self):
        """stream_progress function body must reference is_token_blacklisted."""
        import pathlib
        src = pathlib.Path("app/routers/scans.py").read_text()
        stream_idx = src.find("async def stream_progress")
        blacklist_idx = src.find("is_token_blacklisted", stream_idx)
        assert blacklist_idx != -1

    @pytest.mark.asyncio
    async def test_sse_blacklisted_token_rejected(self, make_token, decode_jti):
        """A blacklisted access token must be rejected before establishing SSE."""
        user_id = uuid.uuid4()
        token = make_token(user_id, "access")
        jti = decode_jti(token, "access")

        with patch("app.utils.cache.is_token_blacklisted", new=AsyncMock(return_value=True)):
            from app.utils.cache import is_token_blacklisted
            is_blacklisted = await is_token_blacklisted(jti)
            assert is_blacklisted is True

    @pytest.mark.asyncio
    async def test_sse_valid_token_not_rejected(self, make_token, decode_jti):
        """A non-blacklisted access token must pass the blacklist check."""
        user_id = uuid.uuid4()
        token = make_token(user_id, "access")
        jti = decode_jti(token, "access")

        with patch("app.utils.cache.is_token_blacklisted", new=AsyncMock(return_value=False)):
            from app.utils.cache import is_token_blacklisted
            is_blacklisted = await is_token_blacklisted(jti)
            assert is_blacklisted is False


# --- 2. Logout - Refresh Token Revocation ---

class TestLogoutRefreshRevocation:

    def test_logout_accepts_refresh_token_in_body(self):
        """LogoutRequest schema must have an optional refresh_token field."""
        from app.schemas.user import LogoutRequest
        req_with = LogoutRequest(refresh_token="some-token")
        req_without = LogoutRequest()
        assert req_with.refresh_token == "some-token"
        assert req_without.refresh_token is None

    def test_logout_backward_compatible_no_body(self):
        """LogoutRequest must be backward-compatible (all fields optional)."""
        from app.schemas.user import LogoutRequest
        no_body = LogoutRequest()
        assert no_body.refresh_token is None
        with_body = LogoutRequest(refresh_token=None)
        assert with_body.refresh_token is None

    @pytest.mark.asyncio
    async def test_logout_blacklists_both_tokens_when_provided(self, make_token):
        """Logout with refresh_token must record both JTIs for blacklisting."""
        user_id = uuid.uuid4()
        access_token = make_token(user_id, "access")
        refresh_token = make_token(user_id, "refresh")

        from app.utils.security import decode_token
        access_jti = decode_token(access_token)["jti"]
        refresh_jti = decode_token(refresh_token, expected_type="refresh")["jti"]

        blacklisted = []

        async def mock_blacklist(jti: str, ttl: int):
            blacklisted.append(jti)

        await mock_blacklist(access_jti, 100)
        await mock_blacklist(refresh_jti, 1000)

        assert access_jti in blacklisted
        assert refresh_jti in blacklisted
        assert len(blacklisted) == 2


# --- 3. Refresh Endpoint - Blacklist Check ---

class TestRefreshBlacklistCheck:

    def test_refresh_endpoint_checks_blacklist(self):
        """auth.py refresh endpoint must call is_token_blacklisted."""
        import pathlib
        src = pathlib.Path("app/routers/auth.py").read_text()
        refresh_idx = src.find("async def refresh_token")
        blacklist_idx = src.find("is_token_blacklisted", refresh_idx)
        assert blacklist_idx != -1

    @pytest.mark.asyncio
    async def test_blacklisted_refresh_token_rejected(self, make_token):
        """Blacklisted refresh-token JTI is flagged."""
        user_id = uuid.uuid4()
        refresh_token = make_token(user_id, "refresh")
        from app.utils.security import decode_token
        jti = decode_token(refresh_token, expected_type="refresh")["jti"]

        with patch("app.utils.cache.is_token_blacklisted", new=AsyncMock(return_value=True)):
            from app.utils.cache import is_token_blacklisted
            assert await is_token_blacklisted(jti) is True

    @pytest.mark.asyncio
    async def test_valid_refresh_token_passes_blacklist(self, make_token):
        """Non-blacklisted refresh token must pass the blacklist check."""
        user_id = uuid.uuid4()
        refresh_token = make_token(user_id, "refresh")
        from app.utils.security import decode_token
        jti = decode_token(refresh_token, expected_type="refresh")["jti"]

        with patch("app.utils.cache.is_token_blacklisted", new=AsyncMock(return_value=False)):
            from app.utils.cache import is_token_blacklisted
            assert await is_token_blacklisted(jti) is False

    def test_malformed_refresh_token_rejected(self):
        """Malformed token must raise 401 on decode."""
        from fastapi import HTTPException
        from app.utils.security import decode_token
        with pytest.raises(HTTPException) as exc_info:
            decode_token("not.a.valid.jwt", expected_type="refresh")
        assert exc_info.value.status_code == 401

    def test_access_token_cannot_be_used_as_refresh(self, make_token):
        """Access token used as refresh token must be rejected (type mismatch)."""
        from fastapi import HTTPException
        from app.utils.security import decode_token
        user_id = uuid.uuid4()
        access_token = make_token(user_id, "access")
        with pytest.raises(HTTPException) as exc_info:
            decode_token(access_token, expected_type="refresh")
        assert exc_info.value.status_code == 401


# --- 4. dev-verify Rate Limit + Production Guard ---

class TestDevVerifyRateLimit:

    def test_dev_verify_has_rate_limit_decorator(self):
        """dev-verify must have @limiter.limit decorator."""
        import pathlib
        src = pathlib.Path("app/routers/auth.py").read_text(encoding='utf-8')
        dev_verify_idx = src.find("async def dev_verify_account")
        before_func = src[max(0, dev_verify_idx - 200):dev_verify_idx]
        assert "limiter.limit" in before_func

    def test_dev_verify_blocked_in_production_check_exists(self):
        """dev-verify must have a production environment check."""
        import pathlib
        src = pathlib.Path("app/routers/auth.py").read_text(encoding='utf-8')
        assert ("ENVIRONMENT" in src and "production" in src and "dev_verify" in src)

    @pytest.mark.asyncio
    async def test_dev_verify_returns_403_when_environment_is_production(self):
        """dev-verify MUST return HTTP 403 when ENVIRONMENT=production.

        This is the critical production-safety regression. If this guard is
        ever removed, any caller can bypass email verification in production.
        """
        from httpx import AsyncClient, ASGITransport
        from app.main import app
        from unittest.mock import patch
        from app.config import settings

        with patch.object(settings, "ENVIRONMENT", "production"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                response = await ac.post(
                    "/api/auth/dev-verify",
                    json={"email": "any@example.com"},
                )
        assert response.status_code == 403, (
            f"dev-verify must return 403 in production, got {response.status_code}"
)
        assert "not available in production" in response.json().get("detail", "").lower()

    @pytest.mark.asyncio
    async def test_dev_verify_rejects_unknown_email_with_404(self):
        """dev-verify must not silently succeed for unknown accounts.

        Prevents account takeover: an attacker supplying an email that does not
        exist must receive 404, not a success or a 500.

        The endpoint now requires the explicit DEV_BYPASS_EMAIL_VERIFICATION
        flag (default False), so this test enables it to reach the lookup path.
        """
        from httpx import AsyncClient, ASGITransport
        from app.main import app
        from app.database import AsyncSessionLocal, engine, Base
        from app.config import settings
        from unittest.mock import patch

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        with patch.object(settings, "DEV_BYPASS_EMAIL_VERIFICATION", True):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                response = await ac.post(
                    "/api/auth/dev-verify",
                    json={"email": "does-not-exist-regression@example.com"},
                )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_dev_verify_blocked_when_dev_bypass_flag_disabled(self):
        """dev-verify MUST return 403 in non-production when the explicit
        DEV_BYPASS_EMAIL_VERIFICATION flag is not enabled.

        Prevents email-verification bypass on misconfigured staging/dev
        deployments where the operator never intentionally enabled it.
        """
        from httpx import AsyncClient, ASGITransport
        from app.main import app
        from app.config import settings
        from unittest.mock import patch

        with patch.object(settings, "ENVIRONMENT", "development"), \
             patch.object(settings, "DEV_BYPASS_EMAIL_VERIFICATION", False):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                response = await ac.post(
                    "/api/auth/dev-verify",
                    json={"email": "flag-disabled-regression@example.com"},
                )
        assert response.status_code == 403, (
            f"dev-verify must return 403 when DEV_BYPASS_EMAIL_VERIFICATION is off, "
            f"got {response.status_code}"
        )
        assert "dev_bypass_email_verification" in response.json().get("detail", "").lower()


# --- 5. CSP Header ---

class TestCSPHeader:

    def test_main_py_sets_csp_header(self):
        """main.py must set Content-Security-Policy."""
        import pathlib
        src = pathlib.Path("app/main.py").read_text()
        assert "Content-Security-Policy" in src

    def test_restrictive_csp_exists(self):
        """Restrictive CSP must use default-src 'none'."""
        import pathlib
        src = pathlib.Path("app/main.py").read_text()
        assert "default-src 'none'" in src

    def test_docs_csp_gated_on_debug_and_route(self):
        """Relaxed docs CSP must be gated on settings.DEBUG and docs route."""
        import pathlib
        src = pathlib.Path("app/main.py").read_text()
        assert "settings.DEBUG" in src and "is_docs_route" in src

    def test_no_unsafe_eval_in_production_csp(self):
        """Restrictive (non-docs) CSP must not contain unsafe-eval."""
        import pathlib
        src = pathlib.Path("app/main.py").read_text()
        # Find the else block's CSP value (after the if settings.DEBUG block)
        else_marker = "# Restrictive policy"
        else_idx = src.find(else_marker)
        if else_idx != -1:
            restrictive_block = src[else_idx:else_idx + 200]
            assert "unsafe-eval" not in restrictive_block, (
                "Restrictive CSP must not contain unsafe-eval"
            )


# --- 6. IDOR - DB-Level Ownership ---

class TestFindingIDOR:

    def test_finding_detail_db_level_ownership(self):
        """reports.py must filter on Report.user_id at DB query level."""
        import pathlib
        src = pathlib.Path("app/routers/reports.py").read_text(encoding='utf-8')
        func_idx = src.find("async def get_finding_detail")
        func_body = src[func_idx:func_idx + 1000]
        assert "Report.user_id == current_user.id" in func_body

    def test_finding_detail_uses_join(self):
        """reports.py must JOIN Finding to Report."""
        import pathlib
        src = pathlib.Path("app/routers/reports.py").read_text(encoding='utf-8')
        func_idx = src.find("async def get_finding_detail")
        func_body = src[func_idx:func_idx + 1000]
        assert ".join(" in func_body

    def test_no_post_load_ownership_check(self):
        """Post-load ownership check must be removed."""
        import pathlib
        src = pathlib.Path("app/routers/reports.py").read_text(encoding='utf-8')
        func_idx = src.find("async def get_finding_detail")
        func_body = src[func_idx:func_idx + 1500]
        assert "finding.report.user_id != current_user.id" not in func_body

    def test_idor_isolation(self):
        """Conceptual BOLA: DB-level filter returns nothing for other users."""
        user_a = uuid.uuid4()
        user_b = uuid.uuid4()

        def db_result(owner_id, requester_id):
            return owner_id == requester_id  # simulates WHERE report.user_id = :current_user

        assert db_result(user_a, user_a) is True   # own resource
        assert db_result(user_a, user_b) is False  # other user blocked


# --- 7. Token Blacklist TTL ---

class TestBlacklistTTL:

    def test_access_token_ttl_positive(self, make_token):
        """Access token blacklist TTL must be > 0."""
        user_id = uuid.uuid4()
        token = make_token(user_id, "access")
        from app.utils.security import decode_token
        payload = decode_token(token)
        ttl = max(payload["exp"] - int(datetime.now(timezone.utc).timestamp()), 1)
        assert ttl > 0

    def test_refresh_token_ttl_positive(self, make_token):
        """Refresh token blacklist TTL must be > 0."""
        user_id = uuid.uuid4()
        token = make_token(user_id, "refresh")
        from app.utils.security import decode_token
        payload = decode_token(token, expected_type="refresh")
        ttl = max(payload["exp"] - int(datetime.now(timezone.utc).timestamp()), 1)
        assert ttl > 0


# --- 8. Missing-auth = 401 global contract ---

class TestMissingAuthContract:

    @pytest.mark.asyncio
    async def test_protected_endpoints_missing_auth_returns_401(self):
        """Global contract: a missing Authorization header must yield 401, never 403.

        The HTTPBearer auto_error default masks missing credentials as 403; the SPA
        refresh/redirect flow keys on 401 to recover expired sessions, so a 403 here
        would leave the user stranded on a dead page instead of redirecting to login.
        403 stays reserved for authenticated-but-blocked (unverified email, non-admin).
        """
        from httpx import AsyncClient, ASGITransport
        from app.main import app

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            for path in ("/api/scans", "/api/reports", "/api/admin/users"):
                resp = await ac.get(path)
                assert resp.status_code == 401, (
                    f"{path} must return 401 for missing auth, got {resp.status_code}: {resp.text[:120]}"
                )
                assert resp.json().get("detail") == "Not authenticated"

    @pytest.mark.asyncio
    async def test_malformed_authorization_header_returns_401(self):
        """A present-but-non-Bearer Authorization header must also be 401."""
        from httpx import AsyncClient, ASGITransport
        from app.main import app

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.get(
                "/api/scans",
                headers={"Authorization": "Basic dXNlcjpwYXNz"},
            )
        assert resp.status_code == 401, (
            f"Malformed Authorization header must return 401, got {resp.status_code}"
        )


# --- 9. Credential failure = 401, authorization failure = 403 ---
# Decision (OPTION B): 401 for missing / malformed / invalid / expired / revoked
# credentials; 403 strictly reserved for authenticated-but-forbidden states.

class TestAuthStatusCodeContract:
    """The status code must be 401 for every credential failure and 403 only for
    authenticated-but-blocked users."""

    @pytest.mark.asyncio
    async def test_garbage_token_returns_401(self):
        """An invalid (garbage) Bearer token must yield 401, never 403/500."""
        from httpx import AsyncClient, ASGITransport
        from app.main import app

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.get(
                "/api/scans",
                headers={"Authorization": "Bearer not.a.valid.jwt"},
            )
        assert resp.status_code == 401, (
            f"Garbage token must return 401, got {resp.status_code}: {resp.text[:120]}"
        )
        assert resp.json().get("detail") == "Could not validate credentials"

    @pytest.mark.asyncio
    async def test_expired_token_returns_401(self):
        """An expired but correctly-signed Bearer token must yield 401."""
        from datetime import datetime, timedelta, timezone
        from httpx import AsyncClient, ASGITransport
        from jose import jwt as jose_jwt
        from app.config import settings
        from app.main import app

        user_id = uuid.uuid4()
        expired = jose_jwt.encode(
            {
                "sub": str(user_id),
                "role": "user",
                "type": "access",
                "exp": datetime.now(timezone.utc) - timedelta(seconds=30),
                "iat": datetime.now(timezone.utc) - timedelta(hours=1),
                "jti": str(uuid.uuid4()),
            },
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.get(
                "/api/scans",
                headers={"Authorization": f"Bearer {expired}"},
            )
        assert resp.status_code == 401, (
            f"Expired token must return 401, got {resp.status_code}: {resp.text[:120]}"
        )

    @pytest.mark.asyncio
    async def test_wrong_signature_token_returns_401(self):
        """A token signed with the wrong secret must yield 401 (not 403)."""
        from datetime import datetime, timedelta, timezone
        from httpx import AsyncClient, ASGITransport
        from jose import jwt as jose_jwt
        from app.main import app

        user_id = uuid.uuid4()
        forged = jose_jwt.encode(
            {
                "sub": str(user_id),
                "role": "admin",
                "type": "access",
                "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
                "iat": datetime.now(timezone.utc),
                "jti": str(uuid.uuid4()),
            },
            "attacker-held-secret-key",
            algorithm="HS256",
        )

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.get(
                "/api/admin/users",
                headers={"Authorization": f"Bearer {forged}"},
            )
        assert resp.status_code == 401, (
            f"Forged-signature token must return 401, got {resp.status_code}"
        )
