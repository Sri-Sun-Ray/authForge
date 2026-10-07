"""Sliding-window rate limiting backed by Redis sorted sets.

One sorted set per bucket holds a member per request, scored by timestamp. Old entries
are trimmed, the new one is added, and the remaining count is compared with the limit —
a true sliding window, unlike fixed windows which let twice the limit through at a
window boundary.
"""

import logging
import secrets
import time
from dataclasses import dataclass

from redis.asyncio import Redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after_seconds: int = 0


async def check_rate_limit(
    redis: Redis, key: str, limit: int, window_seconds: int
) -> RateLimitResult:
    now = time.time()
    try:
        pipeline = redis.pipeline()
        pipeline.zremrangebyscore(key, 0, now - window_seconds)
        # Unique member per request: two requests in the same millisecond must both count
        pipeline.zadd(key, {f"{now}:{secrets.token_hex(4)}": now})
        pipeline.zcard(key)
        pipeline.expire(key, window_seconds)
        _, _, used, _ = await pipeline.execute()
    except RedisError:
        # Fail open: a Redis outage must not lock every user out of the product.
        # The trade-off is that rate limits lapse exactly when Redis is unhealthy.
        logger.warning("Rate limiter unavailable, allowing request", exc_info=True)
        return RateLimitResult(allowed=True)

    if used <= limit:
        return RateLimitResult(allowed=True)

    # Retry when the oldest request in the window falls out of it
    oldest = await redis.zrange(key, 0, 0, withscores=True)
    retry_after = window_seconds
    if oldest:
        retry_after = int(window_seconds - (now - oldest[0][1])) + 1
    return RateLimitResult(allowed=False, retry_after_seconds=max(retry_after, 1))
