"""Redis client factory (async, decoded strings)."""

from __future__ import annotations

from functools import lru_cache

from redis.asyncio import Redis

from app.core.config import get_settings


@lru_cache
def get_redis() -> Redis:
    settings = get_settings()
    return Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        # redis-py's own default is 5 s. A busy disk makes Redis stall on its append-only-file fsync
        # (seen here: "Asynchronous AOF fsync is taking too long", ingest answering 503). A stall of
        # a few seconds should delay a request, not fail it, so the wait is longer and explicit.
        socket_timeout=settings.redis_timeout_seconds,
        socket_connect_timeout=5,
        health_check_interval=30,
    )
