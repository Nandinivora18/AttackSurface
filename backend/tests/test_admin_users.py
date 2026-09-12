import pytest
import uuid
import bcrypt
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from jose import jwt

from app.models.user import User, UserRole
from app.models.misc import AuditLog
from app.utils.security import hash_password, create_access_token
from app.main import app
from app.config import settings
from app.database import AsyncSessionLocal, engine, Base
from app.routers.auth import limiter
import pytest_asyncio


@pytest.fixture(autouse=True)
def disable_auth_rate_limit():
    prev = limiter.enabled
    limiter.enabled = False
    yield
    limiter.enabled = prev


@pytest_asyncio.fixture
async def db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def admin_user(db: AsyncSession):
    # Ensure clean state
    await db.execute(delete(User).where(User.email == "admin_test@sentinelscan.io"))
    await db.commit()

    admin = User(
        email="admin_test@sentinelscan.io",
        name="Admin Test",
        password_hash=hash_password("AdminSecurePass123!"),
        role=UserRole.admin,
        is_verified=True,
    )
    db.add(admin)
    await db.commit()
    await db.refresh(admin)
    yield admin

    # Cleanup
    await db.execute(delete(AuditLog).where(AuditLog.user_id == admin.id))
    await db.execute(delete(User).where(User.id == admin.id))
    await db.commit()


@pytest_asyncio.fixture
async def normal_user(db: AsyncSession):
    # Ensure clean state
    await db.execute(delete(User).where(User.email == "normal_test@sentinelscan.io"))
    await db.commit()

    user = User(
        email="normal_test@sentinelscan.io",
        name="Normal User",
        password_hash=hash_password("UserSecurePass123!"),
        role=UserRole.user,
        is_verified=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    yield user

    # Cleanup
    await db.execute(delete(AuditLog).where(AuditLog.user_id == user.id))
    await db.execute(delete(User).where(User.id == user.id))
    await db.commit()


# ============================================================================
# 1. Registration RBAC Tests
# ============================================================================

@pytest.mark.asyncio
async def test_registration_defaults_to_user_role(client: AsyncClient, db: AsyncSession):
    test_id = uuid.uuid4().hex[:6]
    test_email = f"user_role_{test_id}@sentinelscan.io"
    res = await client.post(
        "/api/auth/register",
        json={"name": "Normal Registered User", "email": test_email, "password": "Password123!Secure"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["role"] == "user"

    # Confirm in database
    created_id = uuid.UUID(data["id"])
    async with AsyncSessionLocal() as session:
        u = (await session.execute(select(User).where(User.id == created_id))).scalar_one_or_none()
        assert u is not None
        assert u.role == UserRole.user

        # Cleanup
        await session.execute(delete(AuditLog).where(AuditLog.user_id == created_id))
        await session.execute(delete(User).where(User.id == created_id))
        await session.commit()


@pytest.mark.asyncio
async def test_registration_prevents_client_role_escalation(client: AsyncClient, db: AsyncSession):
    """Clients attempting to submit role='admin' in signup payload must NOT become admin."""
    test_id = uuid.uuid4().hex[:6]
    test_email = f"attacker_role_{test_id}@sentinelscan.io"
    res = await client.post(
        "/api/auth/register",
        json={
            "name": "Privilege Escalation Attempt",
            "email": test_email,
            "password": "Password123!Secure",
            "role": "admin",  # Malicious attempt
        },
    )
    assert res.status_code == 201
    data = res.json()
    assert data["role"] == "user", "Role MUST NOT be admin!"

    # Verify directly in database
    created_id = uuid.UUID(data["id"])
    async with AsyncSessionLocal() as session:
        u = (await session.execute(select(User).where(User.id == created_id))).scalar_one_or_none()
        assert u is not None
        assert u.role == UserRole.user, "Database role MUST remain UserRole.user!"

        # Cleanup
        await session.execute(delete(AuditLog).where(AuditLog.user_id == created_id))
        await session.execute(delete(User).where(User.id == created_id))
        await session.commit()


# ============================================================================
# 2. Login RBAC Tests
# ============================================================================

@pytest.mark.asyncio
async def test_admin_login_returns_admin_role(client: AsyncClient, admin_user: User):
    res = await client.post(
        "/api/auth/login",
        json={"email": admin_user.email, "password": "AdminSecurePass123!"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["role"] == "admin"


@pytest.mark.asyncio
async def test_normal_user_login_returns_user_role(client: AsyncClient, normal_user: User):
    res = await client.post(
        "/api/auth/login",
        json={"email": normal_user.email, "password": "UserSecurePass123!"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["role"] == "user"


# ============================================================================
# 3. Endpoint Access Control (Admin vs Normal vs Unauthenticated)
# ============================================================================

@pytest.mark.asyncio
async def test_admin_can_access_all_admin_endpoints(client: AsyncClient, admin_user: User):
    token = create_access_token(admin_user.id, role="admin")
    headers = {"Authorization": f"Bearer {token}"}

    endpoints = [
        "/api/admin/users",
        "/api/admin/stats",
        "/api/admin/scans",
        "/api/admin/logs",
        "/api/admin/health",
    ]
    for ep in endpoints:
        res = await client.get(ep, headers=headers)
        assert res.status_code == 200, f"Expected 200 on {ep}, got {res.status_code}"


@pytest.mark.asyncio
async def test_normal_user_denied_all_admin_endpoints(client: AsyncClient, normal_user: User):
    token = create_access_token(normal_user.id, role="user")
    headers = {"Authorization": f"Bearer {token}"}

    endpoints = [
        "/api/admin/users",
        "/api/admin/stats",
        "/api/admin/scans",
        "/api/admin/logs",
        "/api/admin/health",
    ]
    for ep in endpoints:
        res = await client.get(ep, headers=headers)
        assert res.status_code == 403, f"Expected 403 Forbidden on {ep}, got {res.status_code}"
        assert "Admin access required" in res.json().get("detail", "")


@pytest.mark.asyncio
async def test_unauthenticated_user_receives_401(client: AsyncClient):
    endpoints = [
        "/api/admin/users",
        "/api/admin/stats",
        "/api/admin/scans",
        "/api/admin/logs",
        "/api/admin/health",
    ]
    for ep in endpoints:
        res = await client.get(ep)
        assert res.status_code == 401, f"Expected 401 Unauthorized on {ep}, got {res.status_code}"


# ============================================================================
# 4. Role Tampering & Cryptographic Authority Tests
# ============================================================================

@pytest.mark.asyncio
async def test_role_tampering_fails(client: AsyncClient, normal_user: User):
    """An attacker tampering with token claims to add role='admin' must be rejected."""
    # 1. Modifying signature/token with role='admin' but wrong key
    tampered_token = jwt.encode(
        {"sub": str(normal_user.id), "role": "admin", "type": "access"},
        "fake-secret-key-attacker-guess",
        algorithm="HS256",
    )
    res = await client.get("/api/admin/users", headers={"Authorization": f"Bearer {tampered_token}"})
    assert res.status_code == 401, "Tampered signature MUST be rejected with 401"

    # 2. Token signed with real secret but claiming role='admin' for a user whose DB role is 'user'
    # Server verifies against database record in get_admin_user: current_user.role != UserRole.admin
    signed_with_admin_claim = create_access_token(normal_user.id, role="admin")
    res2 = await client.get("/api/admin/users", headers={"Authorization": f"Bearer {signed_with_admin_claim}"})
    assert res2.status_code == 403, "Server MUST check DB record and reject non-admin with 403"
    assert "Admin access required" in res2.json().get("detail", "")


# ============================================================================
# 5. Database Data & Safe Metadata Exposure Tests
# ============================================================================

@pytest.mark.asyncio
async def test_database_persistence_and_no_hash_exposure(client: AsyncClient, admin_user: User, normal_user: User):
    token = create_access_token(admin_user.id, role="admin")
    response = await client.get("/api/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    users = response.json()

    for u in users:
        assert "password" not in u
        assert "password_hash" not in u
        assert "email_verification_token" not in u
        assert "password_reset_token" not in u
        assert "password_storage" in u
        assert "auth_provider" in u
        assert "id" in u
        assert "email" in u
        assert "name" in u
        assert "role" in u
        assert "is_verified" in u
        assert "created_at" in u


@pytest.mark.asyncio
async def test_signup_user_appears_in_admin_list_and_can_login(client: AsyncClient, admin_user: User, db: AsyncSession):
    test_id = uuid.uuid4().hex[:6]
    test_email = f"inspect_test_{test_id}@sentinelscan.io"
    test_password = "Password123!Secure"

    res_signup = await client.post(
        "/api/auth/register",
        json={"name": f"Inspect User {test_id}", "email": test_email, "password": test_password},
    )
    assert res_signup.status_code == 201
    created_id = res_signup.json()["id"]

    async with AsyncSessionLocal() as session:
        u = (await session.execute(select(User).where(User.id == uuid.UUID(created_id)))).scalar_one_or_none()
        if u and not u.is_verified:
            u.is_verified = True
            await session.commit()

    admin_token = create_access_token(admin_user.id, role="admin")
    res_admin = await client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_admin.status_code == 200
    users_list = res_admin.json()
    new_user_row = next((u for u in users_list if u["id"] == created_id), None)
    assert new_user_row is not None
    assert new_user_row["email"] == test_email
    assert new_user_row["role"] == "user"
    assert new_user_row["password_storage"].startswith("$2b$12$")
    assert "password_hash" not in new_user_row

    res_login = await client.post(
        "/api/auth/login",
        json={"email": test_email, "password": test_password},
    )
    assert res_login.status_code == 200
    assert "access_token" in res_login.json()
    assert res_login.json()["user"]["role"] == "user"

    async with AsyncSessionLocal() as session:
        await session.execute(delete(AuditLog).where(AuditLog.user_id == uuid.UUID(created_id)))
        await session.execute(delete(User).where(User.id == uuid.UUID(created_id)))
        await session.commit()


# ============================================================================
# 6. Separate Admin Portal Login Endpoint Verification
# ============================================================================

@pytest.mark.asyncio
async def test_admin_portal_login_success_for_admin(client: AsyncClient, admin_user: User):
    """Admin signing in via /admin/login (portal='admin') succeeds with role='admin'."""
    res = await client.post(
        "/api/auth/login",
        json={"email": admin_user.email, "password": "AdminSecurePass123!", "portal": "admin"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["role"] == "admin"


@pytest.mark.asyncio
async def test_admin_portal_login_rejected_for_normal_user(client: AsyncClient, normal_user: User):
    """Normal user attempting to sign in via /admin/login (portal='admin') is rejected with 403."""
    res = await client.post(
        "/api/auth/login",
        json={"email": normal_user.email, "password": "UserSecurePass123!", "portal": "admin"},
    )
    assert res.status_code == 403
    assert "Administrator access required" in res.json().get("detail", "")
    assert "access_token" not in res.json()


@pytest.mark.asyncio
async def test_normal_login_with_admin_account_returns_admin_role(client: AsyncClient, admin_user: User):
    """Admin signing in via /login returns role='admin' without privilege downgrade."""
    res = await client.post(
        "/api/auth/login",
        json={"email": admin_user.email, "password": "AdminSecurePass123!"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["user"]["role"] == "admin"


# ============================================================================
# 7. Admin User Deletion and Audit Logging
# ============================================================================

@pytest.mark.asyncio
async def test_admin_delete_user_generates_audit_log(client: AsyncClient, admin_user: User, db: AsyncSession):
    """Deleting a user via admin endpoint must record an AuditLog entry."""
    # Create a victim user to delete
    victim = User(
        email=f"victim_{uuid.uuid4().hex[:6]}@sentinelscan.io",
        name="Victim User",
        password_hash=hash_password("VictimPass123!"),
        role=UserRole.user,
        is_verified=True,
    )
    db.add(victim)
    await db.commit()
    await db.refresh(victim)
    victim_id = victim.id

    admin_token = create_access_token(admin_user.id, admin_user.role.value)

    res = await client.delete(
        f"/api/admin/users/{victim_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 204

    # Verify user is deleted
    check_user = await db.execute(select(User).where(User.id == victim_id))
    assert check_user.scalar_one_or_none() is None

    # Verify AuditLog record was created
    log_res = await db.execute(
        select(AuditLog).where(
            AuditLog.action == "user_deleted",
            AuditLog.resource == "users",
            AuditLog.resource_id == victim_id,
        )
    )
    log_entry = log_res.scalar_one_or_none()
    assert log_entry is not None
    assert log_entry.user_id == admin_user.id

    # Cleanup audit log
    await db.execute(delete(AuditLog).where(AuditLog.id == log_entry.id))
    await db.commit()


@pytest.mark.asyncio
async def test_normal_user_cannot_delete_users(client: AsyncClient, normal_user: User, db: AsyncSession):
    """Non-admin user cannot delete accounts via /api/admin/users."""
    user_token = create_access_token(normal_user.id, normal_user.role.value)
    dummy_id = uuid.uuid4()
    res = await client.delete(
        f"/api/admin/users/{dummy_id}",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 403


