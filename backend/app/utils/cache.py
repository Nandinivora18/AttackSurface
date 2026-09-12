import json
import logging
import secrets
import time
import redis.asyncio as aioredis
from typing import Optional
from app.config import settings
from app.utils.security import hash_token

logger = logging.getLogger(__name__)

_redis_client: Optional[aioredis.Redis] = None

# In-memory fallback token blacklist for when Redis is unavailable.
# WARNING: This is a DEVELOPMENT ONLY fallback.
# Entries are lost on process restart — revoked tokens will be re-accepted.
# In production, Redis is mandatory for token blacklisting.
# Entries: jti -> expire_at_unix_timestamp
_local_blacklist: dict[str, float] = {}


def _prune_local_blacklist() -> None:
    """Remove expired entries from the in-memory blacklist."""
    import time
    now = time.time()
    expired = [k for k, v in _local_blacklist.items() if v < now]
    for k in expired:
        del _local_blacklist[k]


async def get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis_client


async def _redis_available() -> bool:
    """Return True if Redis is reachable."""
    try:
        r = await get_redis()
        await r.ping()
        return True
    except Exception:
        return False


async def cache_set(key: str, value: str, expire: int = 3600) -> None:
    try:
        r = await get_redis()
        await r.set(key, value, ex=expire)
    except Exception:
        pass  # Redis is optional for caching — don't crash if unavailable


async def cache_get(key: str) -> Optional[str]:
    try:
        r = await get_redis()
        return await r.get(key)
    except Exception:
        return None


async def cache_delete(key: str) -> None:
    try:
        r = await get_redis()
        await r.delete(key)
    except Exception:
        pass


async def cache_exists(key: str) -> bool:
    try:
        r = await get_redis()
        return bool(await r.exists(key))
    except Exception:
        return False


async def blacklist_token(jti: str, expire_seconds: int) -> None:
    """
    Blacklist a JWT ID.

    In production: requires Redis — raises RedisBlacklistError if unavailable.
    In development: falls back to in-memory store with a warning.

    The caller should handle the production failure case appropriately
    (return 503 rather than silently claiming successful revocation).
    """
    import time
    redis_ok = await _redis_available()
    if redis_ok:
        await cache_set(f"blacklist:{jti}", "1", expire=expire_seconds)
        return

    # Redis unavailable — production must fail, development can fall back
    if settings.ENVIRONMENT == "production":
        raise RedisBlacklistError(
            "Token revocation failed: Redis is unavailable. "
            "In production, Redis is required for persistent token blacklisting. "
            "The logout operation cannot safely complete."
        )

    # Development fallback: in-memory blacklist
    _prune_local_blacklist()
    _local_blacklist[jti] = time.time() + expire_seconds
    logger.warning(
        "DEV FALLBACK: Redis unavailable — token JTI=%s blacklisted in-memory only. "
        "Tokens will be re-accepted after server restart. "
        "Start Redis to ensure persistent token revocation.",
        jti,
    )


async def is_token_blacklisted(jti: str) -> bool:
    """
    Check if a JWT ID has been blacklisted.

    In production: checks Redis only — returns False (safe) if Redis is unavailable,
    but this represents a security degradation that should be monitored.
    In development: checks Redis first, then in-memory fallback.
    """
    import time
    redis_ok = await _redis_available()

    if redis_ok:
        return await cache_exists(f"blacklist:{jti}")

    if settings.ENVIRONMENT == "production":
        # Redis is unavailable — we cannot verify blacklist.
        # Log this as a security event. We choose to NOT block requests here
        # (not revoke all tokens — that would break the service),
        # but this MUST be monitored. The /api/readiness endpoint surfaces this.
        logger.error(
            "SECURITY: Redis unavailable — cannot verify token blacklist for JTI=%s. "
            "Revoked tokens may be accepted. Restore Redis immediately.",
            jti,
        )
        return False  # Allow the request (fail-open for availability, fail-closed would require Redis)

    # Development: check in-memory fallback
    _prune_local_blacklist()
    expire_at = _local_blacklist.get(jti)
    if expire_at is not None and expire_at > time.time():
        return True
    return False


class RedisBlacklistError(Exception):
    """Raised when Redis is required for token blacklisting but is unavailable."""
    pass


# ─── SSE one-time tickets ──────────────────────────────────────────────────
# Short-lived, single-use, opaque credentials used to authenticate the SSE
# stream endpoint from a browser (EventSource cannot set Authorization headers).
#
# Security properties:
#   - Generated with secrets.token_urlsafe (cryptographically secure), never
#     derived from user_id / scan_id / timestamp / JWT contents.
#   - Only the SHA-256 hash of the ticket is persisted (Redis or the dev-only
#     in-memory fallback). The plaintext ticket is never stored server-side.
#   - Bound to both user_id and scan_id (resolved by the SSE endpoint).
#   - Consumed atomically via Redis GETDEL, so a ticket can be used at most once.
#   - Short TTL (settings.SSE_TICKET_TTL_SECONDS, 300s).
#
# Redis failure semantics (mirrors token blacklisting):
#   - production: issue fails closed (raises RedisBlacklistError → caller returns 503)
#   - development: in-memory fallback with an expiry timestamp

SSE_TICKET_PREFIX = "sse:ticket:"
# Dev-only fallback: sha256(ticket) -> {"payload": str, "expires_at": float}
_local_sse_tickets: dict[str, dict] = {}


def _prune_local_sse_tickets() -> None:
    expired = [k for k, v in _local_sse_tickets.items() if v["expires_at"] < time.time()]
    for k in expired:
        del _local_sse_tickets[k]


def _sse_ticket_key(ticket: str) -> str:
    return f"{SSE_TICKET_PREFIX}{hash_token(ticket)}"


async def issue_sse_ticket(
    user_id, scan_id, ttl: Optional[int] = None
) -> str:
    """Issue a short-lived, single-use, opaque SSE ticket.

    Returns the plaintext ticket (returned to the caller / browser). Only its
    SHA-256 hash is stored server-side, bound to the user+scan context.

    Production with Redis unavailable: raises RedisBlacklistError (fail-closed).
    """
    if ttl is None:
        ttl = settings.SSE_TICKET_TTL_SECONDS
    ticket = secrets.token_urlsafe(32)
    payload = json.dumps({"user_id": str(user_id), "scan_id": str(scan_id)})
    key = _sse_ticket_key(ticket)

    redis_ok = await _redis_available()
    if redis_ok:
        await cache_set(key, payload, expire=ttl)
        return ticket

    if settings.ENVIRONMENT == "production":
        raise RedisBlacklistError(
            "SSE ticket issuance failed: Redis is unavailable. "
            "In production, Redis is required for SSE ticket storage. "
            "The SSE connection cannot be safely established."
        )

    # Development fallback: in-memory ticket store
    _prune_local_sse_tickets()
    _local_sse_tickets[key] = {"payload": payload, "expires_at": time.time() + ttl}
    logger.warning(
        "DEV FALLBACK: Redis unavailable — SSE ticket stored in-memory only. "
        "Start Redis to ensure single-use enforcement across processes."
    )
    return ticket


async def consume_sse_ticket(ticket: str) -> Optional[dict]:
    """Atomically consume an SSE ticket.

    Returns the bound {"user_id", "scan_id"} context on first use, or None if
    the ticket is unknown, expired, or has already been consumed (reuse).
    """
    if not ticket:
        return None
    key = _sse_ticket_key(ticket)

    redis_ok = await _redis_available()
    if redis_ok:
        try:
            r = await get_redis()
            try:
                raw = await r.getdel(key)
            except Exception as e:
                if "unknown command" in str(e).lower():
                    # Atomic single-use GET and DEL for Redis < 6.2 (e.g. Redis 3.x/5.x on Windows)
                    lua_getdel = (
                        "local v = redis.call('GET', KEYS[1]); "
                        "if v then redis.call('DEL', KEYS[1]) end; "
                        "return v"
                    )
                    raw = await r.eval(lua_getdel, 1, key)
                else:
                    raise
        except Exception as e:
            logger.warning(f"SSE ticket consume failed: {e}")
            return None
        if raw:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            try:
                return json.loads(raw)
            except (TypeError, ValueError):
                return None
        return None

    if settings.ENVIRONMENT == "production":
        # Redis unavailable — cannot atomically consume/verify. Reject (fail-closed).
        logger.error(
            "SECURITY: Redis unavailable — cannot consume SSE ticket. "
            "SSE connections cannot be authenticated. Restore Redis immediately."
        )
        return None

    # Development fallback: in-memory ticket store
    _prune_local_sse_tickets()
    entry = _local_sse_tickets.pop(key, None)
    if entry is None:
        return None
    try:
        return json.loads(entry["payload"])
    except (TypeError, ValueError):
        return None


async def close_redis() -> None:
    global _redis_client
    if _redis_client:
        await _redis_client.aclose()
        _redis_client = None
