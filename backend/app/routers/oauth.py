"""
Google OAuth 2.0 / OpenID Connect Router
=========================================
Implements the authorization-code flow:

  GET  /api/auth/google           — redirect to Google consent screen
  GET  /api/auth/google/callback  — exchange code, create/login user, issue JWT

Security controls in this module:
  * OAuth state/CSRF: a cryptographically random 32-byte state token is stored
    in Redis (or dev-only in-memory fallback) for 10 minutes and validated on
    callback.  A mismatched or missing state returns the user to /login with an
    error — the request is not processed.
  * No Google tokens are stored: only the identity (sub, email, name, picture)
    is used; Google's access/refresh tokens are discarded after the userinfo
    fetch.
  * No credential logging: token-exchange error bodies are NOT logged (they may
    contain Google client secrets or access tokens).  Only the HTTP status code
    is logged on error paths.
  * Account-linking guard: if a password-based account already exists for the
    same email, Google login is rejected with a clear error.  Silent takeover of
    a password account is explicitly forbidden.
  * SentinelScan issues its OWN JWT access token + HttpOnly refresh-token cookie.
    Google's tokens are NOT used as SentinelScan authentication tokens.
  * email_verified is enforced: Google accounts with unverified emails are
    rejected when REQUIRE_EMAIL_VERIFICATION is enabled.
"""

import secrets
import time
import logging
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import get_db
from app.models.user import User
from app.schemas.user import UserResponse
from app.utils.security import create_access_token, create_refresh_token
from app.utils.cache import cache_set, cache_get, cache_delete
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
limiter = Limiter(key_func=get_remote_address, key_style="endpoint")

# Google OAuth endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

OAUTH_SCOPE = "openid email profile"

# OAuth state tokens live for this many seconds (10 minutes).
_STATE_TTL_SECONDS = 600
_STATE_KEY_PREFIX = "oauth:state:"

# In-memory fallback for OAuth state tokens when Redis is unavailable.
# Format: {state_token: expires_at_unix_float}
# This mirrors the _local_sse_tickets / _local_blacklist pattern in cache.py.
# Safe for development (single process); in production Redis is required.
_local_oauth_states: dict[str, float] = {}


def _prune_local_oauth_states() -> None:
    now = time.time()
    expired = [k for k, v in _local_oauth_states.items() if v < now]
    for k in expired:
        del _local_oauth_states[k]


async def _store_oauth_state(state: str) -> None:
    """Persist an OAuth state token in Redis (with in-memory fallback)."""
    key = f"{_STATE_KEY_PREFIX}{state}"
    try:
        await cache_set(key, "1", expire=_STATE_TTL_SECONDS)
        # Verify the write actually landed (silent Redis failures are the root cause
        # of state-not-found errors in development)
        stored = await cache_get(key)
        if stored:
            return  # Redis write confirmed
        logger.warning(
            "OAuth state Redis write unconfirmed for key %s — using in-memory fallback", key
        )
    except Exception as exc:
        logger.warning("OAuth state Redis write failed (%s) — using in-memory fallback", exc)

    # In-memory fallback (dev only pattern — same as SSE tickets in cache.py)
    _prune_local_oauth_states()
    _local_oauth_states[state] = time.time() + _STATE_TTL_SECONDS
    logger.info("OAuth state stored in-memory fallback (state length=%d)", len(state))


async def _consume_oauth_state(state: str) -> bool:
    """
    Verify and atomically consume an OAuth state token.
    Returns True if the state is valid and unused, False otherwise.
    Single-use: the state is deleted on first successful verification.
    """
    key = f"{_STATE_KEY_PREFIX}{state}"

    # Try Redis first
    try:
        stored = await cache_get(key)
        if stored:
            await cache_delete(key)
            logger.debug("OAuth state consumed from Redis")
            return True
    except Exception as exc:
        logger.warning("OAuth state Redis lookup failed (%s) — checking in-memory fallback", exc)

    # In-memory fallback
    _prune_local_oauth_states()
    expires_at = _local_oauth_states.pop(state, None)
    if expires_at is not None and expires_at > time.time():
        logger.debug("OAuth state consumed from in-memory fallback")
        return True

    return False


def _google_configured() -> bool:
    return bool(settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET)


def _error_redirect(error_code: str) -> RedirectResponse:
    """Redirect the user to the login page with a clear error code."""
    return RedirectResponse(
        url=f"{settings.FRONTEND_URL}/login?error={error_code}",
        status_code=302,
    )


def _build_cookie_kwargs(refresh_token: str) -> dict:
    """Build Set-Cookie kwargs matching the existing SentinelScan auth cookie policy."""
    kwargs: dict = {
        "key": "refresh_token",
        "value": refresh_token,
        "httponly": True,
        "samesite": "lax",
        "max_age": settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        "path": "/api/auth",  # Scoped to auth routes — never sent to scanner/report endpoints
    }
    if settings.ENVIRONMENT == "production":
        kwargs["secure"] = True
    return kwargs


@router.get("/google", summary="Initiate Google OAuth login")
@limiter.limit("20/minute")
async def google_login(request: Request):
    """
    Redirect the user to Google's OAuth consent screen.

    Generates a cryptographically random state token to prevent CSRF.
    The state is stored in Redis for 10 minutes; it is validated on callback.
    """
    if not _google_configured():
        # Return a redirect rather than 501 JSON so browser-initiated flows
        # get a usable error page instead of a JSON blob.
        return _error_redirect("oauth_not_configured")

    # Generate CSRF state token — never derived from user input
    state = secrets.token_urlsafe(32)
    await _store_oauth_state(state)

    params = (
        f"client_id={settings.GOOGLE_CLIENT_ID}"
        f"&redirect_uri={settings.GOOGLE_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope={OAUTH_SCOPE.replace(' ', '+')}"
        f"&state={state}"
        f"&access_type=offline"
        f"&prompt=select_account"
    )
    return RedirectResponse(url=f"{GOOGLE_AUTH_URL}?{params}", status_code=302)


@router.get("/google/callback", summary="Google OAuth callback — exchange code and issue JWT")
@limiter.limit("20/minute")
async def google_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Handle Google's redirect after the user consents (or cancels).

    Steps:
      1. Validate OAuth state (CSRF protection).
      2. Exchange authorization code for Google access token.
      3. Fetch Google userinfo via the access token.
      4. Enforce email_verified.
      5. Find existing user by google_id — or create a new one.
         If a password-based account exists with the same email: REJECT (no silent linking).
      6. Issue SentinelScan JWT access token + HttpOnly refresh-token cookie.
      7. Redirect to /auth/callback with the access token in the URL fragment.
         The refresh token is delivered ONLY via the HttpOnly cookie, never in the URL.
    """
    if not _google_configured():
        return _error_redirect("oauth_not_configured")

    # ── 1. Validate OAuth state (CSRF) ────────────────────────────────────────
    state = request.query_params.get("state")
    if not state:
        logger.warning("OAuth callback: missing state parameter")
        return _error_redirect("oauth_invalid_state")

    valid = await _consume_oauth_state(state)
    if not valid:
        logger.warning(
            "OAuth callback: invalid or expired state token (len=%d)", len(state)
        )
        return _error_redirect("oauth_invalid_state")

    # ── 2. Handle user-cancelled OAuth ────────────────────────────────────────
    error = request.query_params.get("error")
    if error:
        # User clicked "Cancel" on Google's consent screen — not a server error
        logger.info("OAuth callback: user cancelled consent (%s)", error)
        return _error_redirect("oauth_cancelled")

    code = request.query_params.get("code")
    if not code:
        logger.warning("OAuth callback: authorization code missing")
        return _error_redirect("oauth_failed")

    # ── 3. Exchange code for Google access token ───────────────────────────────
    # SECURITY: Never log token_resp.text — it may contain Google access/refresh
    # tokens and is subject to the same secrecy requirements as client_secret.
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            token_resp = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            )
    except httpx.TimeoutException:
        logger.error("OAuth callback: Google token exchange timed out")
        return _error_redirect("oauth_failed")
    except httpx.RequestError as exc:
        logger.error("OAuth callback: Google token exchange network error: %s", type(exc).__name__)
        return _error_redirect("oauth_failed")

    if token_resp.status_code != 200:
        # Log status code only — NOT the response body (may contain tokens)
        logger.error(
            "OAuth callback: Google token exchange failed with HTTP %d",
            token_resp.status_code,
        )
        return _error_redirect("oauth_failed")

    token_data = token_resp.json()
    google_access_token = token_data.get("access_token")
    if not google_access_token:
        logger.error("OAuth callback: no access_token in Google token response")
        return _error_redirect("oauth_failed")

    # ── 4. Fetch Google userinfo ───────────────────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            userinfo_resp = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {google_access_token}"},
            )
    except httpx.TimeoutException:
        logger.error("OAuth callback: Google userinfo fetch timed out")
        return _error_redirect("oauth_failed")
    except httpx.RequestError as exc:
        logger.error("OAuth callback: Google userinfo network error: %s", type(exc).__name__)
        return _error_redirect("oauth_failed")

    if userinfo_resp.status_code != 200:
        logger.error(
            "OAuth callback: Google userinfo failed with HTTP %d",
            userinfo_resp.status_code,
        )
        return _error_redirect("oauth_failed")

    userinfo = userinfo_resp.json()
    google_id = userinfo.get("sub")          # Stable Google user identifier
    email = userinfo.get("email")

    if not google_id or not email:
        logger.warning("OAuth callback: Google userinfo missing sub or email")
        return _error_redirect("oauth_missing_info")

    email = email.strip().lower()
    name = userinfo.get("name") or email.split("@")[0]
    avatar_url = userinfo.get("picture")

    # Google may return email_verified as a boolean or the string "true"
    raw_email_verified = userinfo.get("email_verified", False)
    email_verified = str(raw_email_verified).lower() == "true"

    # ── 5. Enforce email_verified ──────────────────────────────────────────────
    if settings.REQUIRE_EMAIL_VERIFICATION and not email_verified:
        logger.warning(
            "OAuth callback: Google account email not verified for google_id=%s", google_id
        )
        return _error_redirect("oauth_unverified_email")

    # ── 6. Find or create user ─────────────────────────────────────────────────
    # Look up by google_id ONLY first (most precise match).
    result = await db.execute(select(User).where(User.google_id == google_id))
    user = result.scalar_one_or_none()

    if user is None:
        # No Google-linked account found.  Check for a password account with the same email.
        result = await db.execute(select(User).where(User.email == email))
        email_user = result.scalar_one_or_none()

        if email_user is not None:
            # An account already exists with this email using password auth.
            #
            # SECURITY: We do NOT silently link Google to an existing password account.
            # Doing so would allow an attacker who controls a Google account with the
            # victim's email to take over their SentinelScan account without knowing
            # their password.
            #
            # Correct UX: reject with a clear error so the user can sign in with their
            # password and then optionally link Google from settings in a future feature.
            logger.info(
                "OAuth callback: email %s exists as password account — rejecting silent link",
                email,
            )
            return _error_redirect("oauth_email_exists")

        # Genuinely new user — create account
        user = User(
            email=email,
            name=name,
            google_id=google_id,
            avatar_url=avatar_url,
            # password_hash is intentionally None — Google-only account
            is_verified=email_verified or not settings.REQUIRE_EMAIL_VERIFICATION,
            last_login=datetime.now(timezone.utc),
        )
        db.add(user)

    else:
        # Existing Google-linked account — update mutable identity fields
        if avatar_url and not user.avatar_url:
            user.avatar_url = avatar_url
        if email_verified and not user.is_verified:
            user.is_verified = True
        user.last_login = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(user)

    if not user.is_verified:
        # Should not reach here (enforced above), but belt-and-suspenders
        return _error_redirect("oauth_unverified_email")

    # ── 7. Issue SentinelScan JWT + HttpOnly refresh cookie ───────────────────
    # We issue OUR OWN tokens.  Google's tokens are discarded after the userinfo
    # fetch and are never stored or returned to the browser.
    access_token = create_access_token(user.id, user.role.value)
    refresh_token = create_refresh_token(user.id)

    # The refresh token is delivered ONLY as an HttpOnly cookie — it is NEVER
    # placed in the URL fragment, query string, or JSON body for browser clients.
    # The fragment contains only the short-lived access token.
    response = RedirectResponse(
        url=f"{settings.FRONTEND_URL}/auth/callback#access_token={access_token}",
        status_code=302,
    )
    response.set_cookie(**_build_cookie_kwargs(refresh_token))
    return response
