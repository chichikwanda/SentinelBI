"""Fixed-window counters in Redis, used to throttle password guessing and open sign-up.

Sign-in counts FAILED attempts per account (a success clears the counter), so a legitimate user
is never slowed down while guessing one account's password is capped. It is deliberately not keyed
by client address: browsers reach the API through the web container, so every user shares one
address and anyone could lock all of them out. The cost of keying by account is that someone can
lock a known account for one window by failing on purpose; the window is short and the owner is
told how long.

Redis errors fail OPEN (availability over throttling) and are logged: the ingest path already
answers 503 when Redis is down, and a login outage on top would not make the system safer.
"""

from __future__ import annotations

import hashlib
import logging

from redis.asyncio import Redis
from redis.exceptions import RedisError

log = logging.getLogger(__name__)


def _key(scope: str, subject: str) -> str:
    # hashed so e-mail addresses never appear in Redis keys
    return f"rl:{scope}:{hashlib.sha256(subject.lower().encode()).hexdigest()[:32]}"


async def seconds_until_allowed(redis: Redis, scope: str, subject: str, limit: int) -> int | None:
    """Seconds left in the current window if ``subject`` has used up ``limit`` hits, else None."""
    key = _key(scope, subject)
    try:
        used = await redis.get(key)
        if used is not None and int(used) >= limit:
            return max(int(await redis.ttl(key)), 1)
    except RedisError:
        log.warning("rate limit check skipped: Redis unavailable (scope=%s)", scope)
    return None


async def record_hit(redis: Redis, scope: str, subject: str, window_seconds: int) -> None:
    """Count one hit; the window starts at the first hit and is not extended by later ones."""
    key = _key(scope, subject)
    try:
        pipe = redis.pipeline(transaction=True)
        pipe.incr(key)
        pipe.expire(key, window_seconds, nx=True)
        await pipe.execute()
    except RedisError:
        log.warning("rate limit hit not recorded: Redis unavailable (scope=%s)", scope)


async def clear(redis: Redis, scope: str, subject: str) -> None:
    try:
        await redis.delete(_key(scope, subject))
    except RedisError:
        log.warning("rate limit counter not cleared: Redis unavailable (scope=%s)", scope)


def minutes(seconds: int) -> int:
    """Whole minutes, rounded up, for messages shown to people."""
    return max(1, -(-seconds // 60))
