import pytest
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.user import User
from app.config import settings
from app.utils.security import hash_password
from app.main import app
from app.database import get_db

import pytest_asyncio

from sqlalchemy import select, text

# Redis key pattern used by the production resend-verification per-email rate limiter.
# We delete it in the fixture setup/teardown so tests are isolated from prior runs.
_RESEND_RL_KEY = "rate_limit:resend_verify:unverified@example.com"
_RESEND_RL_KEY_NOBODY = "rate_limit:resend_verify:nobody@example.com"


async def _flush_resend_rl_key() -> None:
    """Delete the resend-verification rate-limit Redis key for the test email."""
    try:
        from app.utils.cache import get_redis
        r = await get_redis()
        if r:
            await r.delete(_RESEND_RL_KEY)
            await r.delete(_RESEND_RL_KEY_NOBODY)
    except Exception:
        pass  # Redis may not be running in CI; the endpoint falls back gracefully

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
async def unverified_user(db: AsyncSession):
    # Clear any leftover resend-verification rate-limit Redis state for this
    # test email BEFORE the test runs, so the test is isolated from prior runs.
    await _flush_resend_rl_key()

    # Cleanup previous DB row if any
    existing = await db.execute(select(User).where(User.email == "unverified@example.com"))
    eu = existing.scalar_one_or_none()
    if eu:
        await db.delete(eu)
        await db.commit()
        
    user = User(
        email="unverified@example.com",
        name="Unverified User",
        password_hash=hash_password("Password123!"),
        is_verified=False,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    yield user
    # DB cleanup
    await db.delete(user)
    await db.commit()
    # Redis cleanup — remove the rate-limit key so subsequent test runs start clean.
    await _flush_resend_rl_key()

@pytest_asyncio.fixture
async def verified_user(db: AsyncSession):
    # Cleanup previous if any
    existing = await db.execute(select(User).where(User.email == "verified@example.com"))
    eu = existing.scalar_one_or_none()
    if eu:
        await db.delete(eu)
        await db.commit()

    user = User(
        email="verified@example.com",
        name="Verified User",
        password_hash=hash_password("Password123!"),
        is_verified=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    yield user
    await db.delete(user)
    await db.commit()


@pytest.mark.asyncio
async def test_unverified_login_blocked(client: AsyncClient, unverified_user: User):
    response = await client.post(
        "/api/auth/login",
        json={"email": "unverified@example.com", "password": "Password123!"}
    )
    assert response.status_code == 403
    data = response.json()
    assert data["code"] == "EMAIL_NOT_VERIFIED"
    assert "Email not verified" in data["detail"]

@pytest.mark.asyncio
async def test_verified_login_success(client: AsyncClient, verified_user: User):
    response = await client.post(
        "/api/auth/login",
        json={"email": "verified@example.com", "password": "Password123!"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

@pytest.mark.asyncio
async def test_resend_verification_anti_enumeration(client: AsyncClient, unverified_user: User, db: AsyncSession):
    # Valid existing unverified user
    response = await client.post(
        "/api/auth/resend-verification",
        json={"email": "unverified@example.com"}
    )
    assert response.status_code == 200
    assert "If an unverified account exists" in response.json()["message"]

    # Ensure token was generated
    await db.refresh(unverified_user)
    assert unverified_user.email_verification_token is not None
    assert unverified_user.email_verification_expires is not None

    # Invalid non-existing user
    response2 = await client.post(
        "/api/auth/resend-verification",
        json={"email": "nobody@example.com"}
    )
    assert response2.status_code == 200
    assert "If an unverified account exists" in response2.json()["message"]

@pytest.mark.asyncio
async def test_startup_config_validation():
    """Production settings must enforce REQUIRE_EMAIL_VERIFICATION."""
    from pydantic import ValidationError
    from app.config import Settings

    # Use a valid strong key — the SECRET_KEY check must pass
    # so we can test the REQUIRE_EMAIL_VERIFICATION check
    strong_key = "a" * 40  # 40 chars, not in weak set

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY=strong_key,
            REQUIRE_EMAIL_VERIFICATION=False,
            DEBUG=False,
        )
    assert "REQUIRE_EMAIL_VERIFICATION cannot be False in production environment" in str(exc_info.value)


@pytest.mark.asyncio
async def test_production_rejects_weak_secret_key():
    """Production must reject known placeholder/weak SECRET_KEY values."""
    from pydantic import ValidationError
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="change-this-in-production-at-least-32-characters-long",
            REQUIRE_EMAIL_VERIFICATION=True,
            DEBUG=False,
        )
    assert "FATAL: SECRET_KEY" in str(exc_info.value)


@pytest.mark.asyncio
async def test_production_rejects_short_secret_key():
    """Production must reject SECRET_KEY shorter than 32 chars."""
    from pydantic import ValidationError
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="tooshort",
            REQUIRE_EMAIL_VERIFICATION=True,
            DEBUG=False,
        )
    assert "SECRET_KEY is too short" in str(exc_info.value)


@pytest.mark.asyncio
async def test_production_rejects_dev_bypass_email_verification():
    """DEV_BYPASS_EMAIL_VERIFICATION must be forbidden in production."""
    from pydantic import ValidationError
    from app.config import Settings

    strong_key = "b" * 40

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY=strong_key,
            REQUIRE_EMAIL_VERIFICATION=True,
            DEBUG=False,
            DEV_BYPASS_EMAIL_VERIFICATION=True,
        )
    assert "DEV_BYPASS_EMAIL_VERIFICATION" in str(exc_info.value)


@pytest.mark.asyncio
async def test_development_allows_weak_key():
    """Development environment should not reject weak SECRET_KEY."""
    from app.config import Settings

    # Should NOT raise in development
    cfg = Settings(
        ENVIRONMENT="development",
        SECRET_KEY="weak",
        REQUIRE_EMAIL_VERIFICATION=True,
        DEBUG=True,
    )
    assert cfg.ENVIRONMENT == "development"
