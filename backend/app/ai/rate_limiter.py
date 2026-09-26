"""
Per-User AI Rate Limiter — Ask Sentinel

Uses the existing Redis connection (same get_redis() utility used elsewhere)
with a sliding window counter keyed by user_id.

Key: ai:rate:{user_id}
Strategy: increment + EXPIRE on first request; decrement not needed (window expires)
Fails closed: if Redis is unavailable, check_ai_rate_limit raises
RateLimitUnavailableError so the caller rejects the request — an unenforced
per-user AI rate cap must never be silently bypassed during a Redis outage.
"""
import logging
import uuid
from typing import Tuple

from app.config import settings          # module-level: patchable as app.ai.rate_limiter.settings
from app.utils.cache import get_redis    # module-level: patchable as app.ai.rate_limiter.get_redis

logger = logging.getLogger(__name__)

_WINDOW_SECONDS = 3600  # 1-hour sliding window


class RateLimitUnavailableError(Exception):
    """
    Raised when the Redis-backed AI rate limiter cannot serve a decision.

    Callers must reject the request (fail-closed): silently allowing requests
    during a limiter outage would defeat the per-user AI rate limit entirely.
    """
    pass


async def check_ai_rate_limit(user_id: uuid.UUID) -> Tuple[bool, int]:
    """
    Check whether a user is within their AI request rate limit.

    Uses a simple fixed-window counter stored in Redis.
    Window resets every hour. The limit is configurable via settings.AI_RATE_LIMIT_PER_HOUR.

    Args:
        user_id: The authenticated user's UUID.

    Returns:
        (allowed: bool, requests_remaining: int)
        - allowed=True if the request should proceed
        - requests_remaining: how many more requests can be made in this window
          (0 when denied, negative values clamped to 0)

    Raises:
        RateLimitUnavailableError: if Redis is unavailable — the rate limit
          cannot be enforced, so the caller must reject the request.
    """
    key = f"ai:rate:{user_id}"
    limit = settings.AI_RATE_LIMIT_PER_HOUR

    try:
        redis = await get_redis()

        # Increment the counter; set expiry on first request in the window
        current = await redis.incr(key)
        if current == 1:
            # First request in this window — set the expiry
            await redis.expire(key, _WINDOW_SECONDS)

        remaining = max(0, limit - current)

        if current > limit:
            logger.info(
                "AI rate limit exceeded: user=%s count=%d limit=%d",
                user_id, current, limit,
            )
            return False, 0

        return True, remaining

    except RateLimitUnavailableError:
        raise
    except Exception as exc:
        logger.error(
            "AI rate limiter: Redis unavailable (%s) for user=%s — rejecting request (fail-closed)",
            type(exc).__name__, user_id,
        )
        raise RateLimitUnavailableError(
            "AI rate limiting service unavailable: Redis is required to enforce per-user AI rate limits."
        ) from exc


async def get_ai_usage(user_id: uuid.UUID) -> dict:
    """
    Return current AI usage stats for a user.
    Used for informational purposes in responses.

    Returns:
        {"requests_used": int, "limit": int, "window_seconds": int}
    """
    key = f"ai:rate:{user_id}"
    limit = settings.AI_RATE_LIMIT_PER_HOUR

    try:
        redis = await get_redis()
        current_str = await redis.get(key)
        current = int(current_str) if current_str else 0
    except Exception:
        current = 0

    return {
        "requests_used": current,
        "limit": limit,
        "window_seconds": _WINDOW_SECONDS,
    }
