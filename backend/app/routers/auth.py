import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Cookie
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models.user import User, UserRole
from app.models.misc import AuditLog
from app.schemas.user import (
    UserCreate, UserLogin, UserResponse, TokenResponse,
    ForgotPassword, ResetPassword, RefreshTokenRequest,
    ResendVerification, LogoutRequest,
)
from app.utils.security import (
    hash_password, verify_password, generate_token, hash_token,
    create_access_token, create_refresh_token, decode_token,
)
from app.utils.cache import blacklist_token, get_redis, is_token_blacklisted
from app.services.email_service import send_verification_email, send_password_reset_email
from app.config import settings
from app.exceptions import SentinelException
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["Authentication"])
limiter = Limiter(key_func=get_remote_address, key_style="endpoint")


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0] if forwarded else request.client.host if request.client else "unknown"


async def _log_audit(db: AsyncSession, user_id: uuid.UUID | None, action: str, ip: str, metadata: dict = None):
    log = AuditLog(user_id=user_id, action=action, ip_address=ip, metadata_=metadata or {})
    db.add(log)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(f"{settings.RATE_LIMIT_AUTH_PER_MINUTE}/minute")
async def register(payload: UserCreate, request: Request, db: AsyncSession = Depends(get_db)):
    email_normalized = payload.email.strip().lower()
    existing = await db.execute(select(User).where(User.email == email_normalized))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    smtp_configured = bool(settings.SMTP_USER and settings.SMTP_PASSWORD)

    # Determine effective verification requirement.
    # FAIL-CLOSED: If REQUIRE_EMAIL_VERIFICATION=True, we NEVER auto-verify just because SMTP is missing.
    # The only valid bypass is the explicit DEV_BYPASS_EMAIL_VERIFICATION flag (forbidden in production).
    if settings.REQUIRE_EMAIL_VERIFICATION:
        if settings.DEV_BYPASS_EMAIL_VERIFICATION:
            # Explicit dev bypass: skip verification, auto-verify
            require_verification = False
            logger.warning(
                "DEV_BYPASS_EMAIL_VERIFICATION=True: auto-verifying account for %s (dev only)",
                email_normalized,
            )
        else:
            # Verification required regardless of SMTP state
            require_verification = True
    else:
        require_verification = False

    verification_token = None
    token_hash = None
    expires = None

    if require_verification:
        verification_token = generate_token(32)
        token_hash = hash_token(verification_token)
        expires = datetime.now(timezone.utc) + timedelta(hours=24)

    user = User(
        email=email_normalized,
        name=payload.name,
        password_hash=hash_password(payload.password),
        role=UserRole.user,  # Explicitly enforce normal user role for all public registrations
        email_verification_token=token_hash,
        email_verification_expires=expires,
        is_verified=not require_verification,  # False when verification required
    )
    db.add(user)
    await db.flush()
    await _log_audit(db, user.id, "user.register", _get_client_ip(request))
    await db.commit()
    await db.refresh(user)

    if require_verification:
        if smtp_configured:
            # Best-effort: send verification email. If it fails, account stays unverified.
            sent = await send_verification_email(user.email, user.name, verification_token)
            if not sent:
                logger.warning(
                    "Verification email failed to send for %s — account remains unverified",
                    email_normalized,
                )
        else:
            # SMTP not configured: account stays unverified. Admin must configure SMTP
            # or use DEV_BYPASS_EMAIL_VERIFICATION for local development.
            logger.warning(
                "SMTP not configured: verification email not sent for %s — account stays unverified. "
                "Configure SMTP credentials or set DEV_BYPASS_EMAIL_VERIFICATION=true for local dev.",
                email_normalized,
            )

    return user



@router.post("/login", response_model=TokenResponse)
@limiter.limit(f"{settings.RATE_LIMIT_AUTH_PER_MINUTE}/minute")
async def login(payload: UserLogin, request: Request, db: AsyncSession = Depends(get_db)):
    email_normalized = payload.email.strip().lower()
    result = await db.execute(select(User).where(User.email == email_normalized))
    user = result.scalar_one_or_none()

    if not user or not user.password_hash or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not user.is_verified:
        raise SentinelException(
            detail="Email not verified. Please check your inbox.",
            code="EMAIL_NOT_VERIFIED",
            status_code=status.HTTP_403_FORBIDDEN
        )

    if payload.portal == "admin" and user.role != UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required. Standard user accounts cannot authenticate via the admin portal."
        )

    user.last_login = datetime.now(timezone.utc)
    await _log_audit(db, user.id, "user.login", _get_client_ip(request))
    await db.commit()
    await db.refresh(user)

    access_token = create_access_token(user.id, user.role.value)
    refresh_token = create_refresh_token(user.id)

    # Set the refresh token as an HttpOnly cookie so it is never accessible
    # to JavaScript. This protects against XSS-based token theft.
    #   - HttpOnly: inaccessible to document.cookie / JS
    #   - Secure:   only sent over HTTPS (enforced in production)
    #   - SameSite=Lax: blocks CSRF for cross-site navigations while allowing
    #                   normal same-origin requests and OAuth redirects
    #   - Max-Age: matches REFRESH_TOKEN_EXPIRE_DAYS (7 days by default)
    response = Response()
    cookie_kwargs: dict = {
        "key": "refresh_token",
        "value": refresh_token,
        "httponly": True,
        "samesite": "lax",
        "max_age": settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        "path": "/api/auth",  # Scoped to auth routes only — never sent to scanner/report endpoints
    }
    if settings.ENVIRONMENT == "production":
        cookie_kwargs["secure"] = True
    response.set_cookie(**cookie_kwargs)

    token_data = TokenResponse(
        access_token=access_token,
        user=UserResponse.model_validate(user),
    )
    # Include refresh_token in body for non-browser clients / tests.
    # Browser clients should use the cookie and ignore this field.
    token_data.refresh_token = refresh_token

    from fastapi.responses import JSONResponse
    json_response = JSONResponse(content=token_data.model_dump(mode="json"))
    json_response.headers["set-cookie"] = response.headers["set-cookie"]
    return json_response


@router.post("/resend-verification")
@limiter.limit("10/15minutes") # IP-based limit
async def resend_verification(payload: ResendVerification, request: Request, db: AsyncSession = Depends(get_db)):
    email_normalized = payload.email.strip().lower()
    
    # Per-email limit: 3 per 15 minutes using Redis
    redis_key = f"rate_limit:resend_verify:{email_normalized}"
    try:
        r = await get_redis()
        if r:
            count = await r.incr(redis_key)
            if count == 1:
                await r.expire(redis_key, 900)
            if count > 3:
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many resend attempts")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        logger.warning(f"Redis rate limiting failed: {e}")

    # Anti-enumeration response
    success_response = {"message": "If an unverified account exists for this email, a verification email has been sent."}

    # Short transaction: load user, update token, commit — release lock quickly
    result = await db.execute(
        select(User)
        .where(User.email == email_normalized)
        .with_for_update()
    )
    user = result.scalar_one_or_none()

    if not user or user.is_verified:
        return success_response

    new_token = generate_token(32)
    user.email_verification_token = hash_token(new_token)
    user.email_verification_expires = datetime.now(timezone.utc) + timedelta(hours=24)
    user_name = user.name
    user_email = user.email
    await db.commit()

    smtp_configured = bool(settings.SMTP_USER and settings.SMTP_PASSWORD)
    if smtp_configured:
        try:
            await send_verification_email(user_email, user_name, new_token)
        except Exception as e:
            logger.error(f"Failed to send verification email for {user_email}: {e}")

    return success_response


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("30/minute")
async def refresh_token(
    request: Request,
    payload: RefreshTokenRequest = None,
    db: AsyncSession = Depends(get_db),
    rt_cookie: Optional[str] = Cookie(default=None, alias="refresh_token"),
):
    """
    Issue new access + refresh token pair.

    Token source priority:
      1. HttpOnly cookie ("refresh_token") — preferred for browser clients
      2. Request body ("refresh_token" field) — backward compat for non-browser clients

    Returns the new access token in the JSON body and sets a new HttpOnly
    cookie for the refresh token.
    """
    # Resolve the refresh token: cookie takes priority over body
    raw_token = rt_cookie or (payload.refresh_token if payload else None)
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided (cookie or body)",
        )

    token_payload = decode_token(raw_token, expected_type="refresh")
    try:
        user_id = uuid.UUID(token_payload["sub"])
    except (ValueError, TypeError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    # ── Blacklist check: reject if refresh token JTI has been revoked ────── #
    jti = token_payload.get("jti", "")
    if jti and await is_token_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    if not user.is_verified:
        raise SentinelException(
            detail="Email not verified. Please check your inbox.",
            code="EMAIL_NOT_VERIFIED",
            status_code=status.HTTP_403_FORBIDDEN
        )

    access_token = create_access_token(user.id, user.role.value)
    new_refresh = create_refresh_token(user.id)

    # ── Blacklist the OLD refresh token so it cannot be reused ──────── #
    # This closes the token-reuse window: if the old token is intercepted
    # after rotation it will be rejected by is_token_blacklisted().
    if jti:
        try:
            old_exp = token_payload.get("exp", 0)
            old_now = int(datetime.now(timezone.utc).timestamp())
            old_ttl = max(old_exp - old_now, 1)
            await blacklist_token(jti, old_ttl)
        except Exception as _bl_err:
            # Non-fatal: log but do not block the rotation.
            # In production this should alert (Redis unavailable means
            # old refresh tokens cannot be revoked).
            logger.warning(
                "REFRESH_ROTATE_BLACKLIST_FAILED jti=%s: %s "
                "(old token not revoked — monitor Redis connectivity)",
                jti, _bl_err,
            )

    # Rotate cookie
    cookie_kwargs: dict = {
        "key": "refresh_token",
        "value": new_refresh,
        "httponly": True,
        "samesite": "lax",
        "max_age": settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        "path": "/api/auth",
    }
    if settings.ENVIRONMENT == "production":
        cookie_kwargs["secure"] = True

    token_data = TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh,  # Also in body for non-browser clients
        user=UserResponse.model_validate(user),
    )
    from fastapi.responses import JSONResponse
    json_response = JSONResponse(content=token_data.model_dump(mode="json"))
    response_obj = Response()
    response_obj.set_cookie(**cookie_kwargs)
    json_response.headers["set-cookie"] = response_obj.headers["set-cookie"]
    return json_response


@router.get("/verify-email/{token}")
@limiter.limit("10/minute")
async def verify_email(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    token_hash = hash_token(token)
    result = await db.execute(select(User).where(User.email_verification_token == token_hash))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")

    # Normalise naive SQLite datetimes to UTC before comparison (Postgres stores
    # tz-aware timestamps; SQLite stores naive — this guard keeps both working).
    if user.email_verification_expires:
        expires_at = user.email_verification_expires
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification token has expired")

    user.is_verified = True
    user.email_verification_token = None
    user.email_verification_expires = None
    await db.commit()
    return {"message": "Email verified successfully. You can now log in."}


class _DevVerifyRequest(BaseModel):
    email: str


@router.post("/dev-verify")
@limiter.limit("10/minute")
async def dev_verify_account(request: Request, body: _DevVerifyRequest, db: AsyncSession = Depends(get_db)):
    """DEV ONLY: instantly verify any user by email (accepts JSON body — never a query param).

    Requires BOTH:
    - ENVIRONMENT != "production", AND
    - DEV_BYPASS_EMAIL_VERIFICATION = True (the explicit dev bypass flag).

    Without the explicit flag, this endpoint refuses (403). This prevents
    email-verification bypass on misconfigured staging/dev deployments where
    the operator never intentionally enabled the bypass.
    """
    if settings.ENVIRONMENT == "production":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not available in production")
    if not settings.DEV_BYPASS_EMAIL_VERIFICATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not available: DEV_BYPASS_EMAIL_VERIFICATION is not enabled",
        )

    email = body.email.strip().lower()
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="email is required")
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.is_verified = True
    user.email_verification_token = None
    user.email_verification_expires = None
    await db.commit()
    return {"message": f"User {email} is now verified. You can log in."}


@router.post("/forgot-password")
@limiter.limit("3/minute")
async def forgot_password(payload: ForgotPassword, request: Request, db: AsyncSession = Depends(get_db)):
    email_normalized = payload.email.strip().lower()
    result = await db.execute(select(User).where(User.email == email_normalized))
    user = result.scalar_one_or_none()

    if user and user.password_hash:
        reset_token = generate_token(32)
        user.password_reset_token = hash_token(reset_token)
        user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        await db.commit()
        await send_password_reset_email(user.email, user.name, reset_token)

    return {"message": "If an account with that email exists, a reset link has been sent."}


@router.post("/reset-password")
@limiter.limit("5/minute")
async def reset_password(payload: ResetPassword, request: Request, db: AsyncSession = Depends(get_db)):
    token_hash = hash_token(payload.token)
    result = await db.execute(
        select(User).where(
            User.password_reset_token == token_hash,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

    # Normalise naive SQLite datetimes to UTC before comparison.
    if user.password_reset_expires:
        reset_expires = user.password_reset_expires
        if reset_expires.tzinfo is None:
            reset_expires = reset_expires.replace(tzinfo=timezone.utc)
        if reset_expires < datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

    user.password_hash = hash_password(payload.new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    await db.commit()
    return {"message": "Password reset successfully. You can now log in."}


@router.post("/logout")
@limiter.limit("20/minute")
async def logout(
    request: Request,
    body: LogoutRequest = None,
    rt_cookie: Optional[str] = Cookie(default=None, alias="refresh_token"),
):
    """
    Revoke the current access token by blacklisting its JTI.

    Also revokes the refresh token — reads from HttpOnly cookie first,
    then from request body as a fallback for non-browser clients.

    Clears the refresh_token cookie on successful logout.

    Production behaviour:
    - If Redis is available: tokens are persistently blacklisted, returns 200
    - If Redis is unavailable: returns 503, tokens NOT revoked
      (client must not treat this as a successful logout)

    Development behaviour:
    - If Redis unavailable: falls back to in-memory blacklist with a warning,
      returns 200 with a warning field
    """
    from app.utils.cache import RedisBlacklistError

    # ── Refresh-token revocation ──────────────────────────────────── #
    # MUST run regardless of whether an access token was presented: a browser
    # whose access JWT has already expired (30-min TTL) still holds a valid
    # 7-day refresh token in the HttpOnly cookie, and it is exactly the
    # credential that needs revoking here. Cookie takes priority over body;
    # body is accepted for non-browser clients.
    async def _revoke_refresh_token(refresh_raw: str) -> None:
        try:
            rt_payload = decode_token(refresh_raw, expected_type="refresh")
            rt_jti = rt_payload.get("jti")
            if rt_jti:
                rt_exp = rt_payload.get("exp", 0)
                now_ts = int(datetime.now(timezone.utc).timestamp())
                rt_ttl = max(rt_exp - now_ts, 1)
                await blacklist_token(rt_jti, rt_ttl)
                logger.info("Refresh token revoked on logout (JTI redacted)")
        except RedisBlacklistError as e:
            # Production: Redis unavailable — cannot guarantee revocation.
            # Fail closed consistently with the access-token path.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "message": "Logout failed: token revocation service unavailable.",
                    "reason": "Redis is required for persistent token revocation in production. "
                              "Your session token has NOT been invalidated. "
                              "Restore Redis connectivity and retry.",
                    "code": "TOKEN_REVOCATION_UNAVAILABLE",
                },
            )
        except Exception:
            # Malformed / already-expired refresh token — nothing to revoke
            logger.debug("Refresh token revocation skipped (invalid/expired token)")

    refresh_raw = rt_cookie or (body.refresh_token if body else None)
    if refresh_raw:
        await _revoke_refresh_token(refresh_raw)

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        # No access token to revoke; refresh token above already handled.
        response = Response(content='{"message": "Logged out successfully"}', media_type="application/json")
        response.delete_cookie(
            "refresh_token",
            path="/api/auth",
            httponly=True,
            samesite="lax",
            secure=(settings.ENVIRONMENT == "production"),
        )
        return response

    token = auth_header[7:]
    try:
        payload = decode_token(token)
        jti = payload.get("jti")
        if jti:
            exp = payload.get("exp", 0)
            now_ts = int(datetime.now(timezone.utc).timestamp())
            ttl = max(exp - now_ts, 1)
            try:
                await blacklist_token(jti, ttl)
            except RedisBlacklistError as e:
                # Production: Redis unavailable — cannot guarantee revocation
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail={
                        "message": "Logout failed: token revocation service unavailable.",
                        "reason": "Redis is required for persistent token revocation in production. "
                                  "Your session token has NOT been invalidated. "
                                  "Restore Redis connectivity and retry.",
                        "code": "TOKEN_REVOCATION_UNAVAILABLE",
                    },
                )
    except HTTPException:
        raise
    except Exception:
        # Token invalid/expired — nothing to revoke for access token
        pass

    # Clear the HttpOnly cookie regardless of whether revocation succeeded
    from fastapi.responses import JSONResponse
    json_response = JSONResponse(content={"message": "Logged out successfully"})
    json_response.delete_cookie(
        "refresh_token",
        path="/api/auth",
        httponly=True,
        samesite="lax",
        secure=(settings.ENVIRONMENT == "production"),
    )
    return json_response
