"""
Tests for Active Safety Boundaries and Consent Verification
===========================================================
Validates:
- Consent enforcement for safe_active and authenticated_safe_active modes
- Passive scan mode exemption from active consent
- Schema validation for allowed scan modes
- Auth credential sanitization and safety boundary enforcement
"""
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pydantic import ValidationError
from fastapi import HTTPException

from app.schemas.scan import ScanCreate
from app.routers.scans import create_scan


def _mock_db():
    active_res = MagicMock()
    active_res.scalars.return_value.all.return_value = []
    count_res = MagicMock()
    count_res.scalar.return_value = 0
    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[active_res, count_res])
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


def _mock_arq():
    mock_pool = AsyncMock()
    mock_pool.enqueue_job = AsyncMock(return_value=MagicMock())
    return mock_pool


@pytest.mark.asyncio
async def test_passive_mode_no_consent_allowed():
    """Passive mode does not require explicit authorization consent."""
    db = _mock_db()
    current_user = MagicMock(id=uuid.uuid4())
    payload = ScanCreate(
        url="https://example.com",
        scan_mode="passive",
        consent_acknowledged=False,
    )

    with patch("app.routers.scans._is_ssrf_safe_url", new=AsyncMock(return_value=(True, ""))):
        with patch("app.routers.scans._get_arq_pool", new=AsyncMock(return_value=_mock_arq())):
            scan = await create_scan(payload, db=db, current_user=current_user)
            assert scan.url == "https://example.com"
            assert scan.scan_mode == "passive"


@pytest.mark.asyncio
async def test_safe_active_mode_requires_consent():
    """Safe active mode without consent must raise HTTP 400."""
    db = _mock_db()
    current_user = MagicMock(id=uuid.uuid4())
    payload = ScanCreate(
        url="https://example.com",
        scan_mode="safe_active",
        consent_acknowledged=False,
    )

    with patch("app.routers.scans._is_ssrf_safe_url", new=AsyncMock(return_value=(True, ""))):
        with pytest.raises(HTTPException) as exc_info:
            await create_scan(payload, db=db, current_user=current_user)

    assert exc_info.value.status_code == 400
    assert "Active assessment requires explicit authorization and consent acknowledgement" in exc_info.value.detail


@pytest.mark.asyncio
async def test_safe_active_mode_with_consent_allowed():
    """Safe active mode with consent must be accepted."""
    db = _mock_db()
    current_user = MagicMock(id=uuid.uuid4())
    payload = ScanCreate(
        url="https://example.com",
        scan_mode="safe_active",
        consent_acknowledged=True,
    )

    with patch("app.routers.scans._is_ssrf_safe_url", new=AsyncMock(return_value=(True, ""))):
        with patch("app.routers.scans._get_arq_pool", new=AsyncMock(return_value=_mock_arq())):
            scan = await create_scan(payload, db=db, current_user=current_user)
            assert scan.scan_mode == "safe_active"


@pytest.mark.asyncio
async def test_authenticated_safe_active_requires_consent():
    """Authenticated safe active mode without consent must raise HTTP 400."""
    db = _mock_db()
    current_user = MagicMock(id=uuid.uuid4())
    payload = ScanCreate(
        url="https://example.com",
        scan_mode="authenticated_safe_active",
        consent_acknowledged=False,
    )

    with patch("app.routers.scans._is_ssrf_safe_url", new=AsyncMock(return_value=(True, ""))):
        with pytest.raises(HTTPException) as exc_info:
            await create_scan(payload, db=db, current_user=current_user)

    assert exc_info.value.status_code == 400


def test_invalid_scan_mode_rejected_by_schema():
    """Unsupported or aggressive scan modes must be rejected at validation."""
    with pytest.raises(ValidationError):
        ScanCreate(
            url="https://example.com",
            scan_mode="destructive_attack",
            consent_acknowledged=True,
        )


@pytest.mark.asyncio
async def test_auth_credential_sanitization_in_scan():
    """Credentials in auth_context must be sanitized for storage in DB."""
    db = _mock_db()
    current_user = MagicMock(id=uuid.uuid4())
    payload = ScanCreate(
        url="https://example.com",
        scan_mode="authenticated_safe_active",
        consent_acknowledged=True,
        auth_context={
            "username": "tester",
            "password": "SuperSecretPassword123!",
            "token": "secret_bearer_token",
        },
    )

    with patch("app.routers.scans._is_ssrf_safe_url", new=AsyncMock(return_value=(True, ""))):
        with patch("app.routers.scans._get_arq_pool", new=AsyncMock(return_value=_mock_arq())):
            scan = await create_scan(payload, db=db, current_user=current_user)
            assert scan.scope_config["auth_context"]["username"] == "tester"
            assert "password" not in scan.scope_config["auth_context"]
            assert "secret" not in scan.scope_config["auth_context"]



@pytest.mark.asyncio
async def test_case_variant_credential_sanitization():
    """Case variations like 'Password', 'admin_password', 'client_secret' must be stripped."""
    db = _mock_db()
    current_user = MagicMock(id=uuid.uuid4())
    payload = ScanCreate(
        url="https://example.com",
        scan_mode="authenticated_safe_active",
        consent_acknowledged=True,
        auth_context={
            "identity_label": "qa_user",
            "Password": "Secret123Password",
            "admin_password": "AnotherPassword",
            "CLIENT_SECRET": "oauth-client-secret",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----",
            "auth_type": "bearer",
        },
    )

    with patch("app.routers.scans._is_ssrf_safe_url", new=AsyncMock(return_value=(True, ""))):
        with patch("app.routers.scans._get_arq_pool", new=AsyncMock(return_value=_mock_arq())):
            scan = await create_scan(payload, db=db, current_user=current_user)
            stored_auth = scan.scope_config["auth_context"]
            assert stored_auth["identity_label"] == "qa_user"
            assert stored_auth["auth_type"] == "bearer"
            assert "Password" not in stored_auth
            assert "admin_password" not in stored_auth
            assert "CLIENT_SECRET" not in stored_auth
            assert "private_key" not in stored_auth

