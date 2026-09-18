"""Redis sliding-window rate limiter.

Milestone 4 — implement this yourself:
- Use a sorted set per key (e.g. "rl:login:ip:1.2.3.4"): ZREMRANGEBYSCORE to drop
  old entries, ZADD the current timestamp, ZCARD to count, EXPIRE the key.
- Run the commands in a pipeline (or a Lua script) so they are atomic.
- Expose a FastAPI dependency that raises HTTP 429 with a Retry-After header.
"""

from redis.asyncio import Redis


async def is_allowed(redis: Redis, key: str, limit: int, window_seconds: int) -> bool:
    raise NotImplementedError
