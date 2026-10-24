"""Redis Streams consumer: reads ``flows.raw`` in a consumer group and runs the pipeline."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import UTC, datetime

from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.heartbeat import beat
from app.core.logging import configure_logging
from app.core.redis import get_redis
from app.db.session import get_sessionmaker
from app.services.inference.predictor import Predictor
from app.services.inference.registry import PredictorHolder
from app.services.risk.aggregate import active_org_ids, snapshot_org
from app.workers.pipeline import Message, process_messages

log = logging.getLogger("worker")
_RECLAIM_EVERY_S = 15.0


async def ensure_group(redis: Redis, settings: Settings) -> None:
    try:
        # id="0": a worker started after the first ingest still sees everything queued so far
        await redis.xgroup_create(
            settings.stream_flows, settings.stream_group, id="0", mkstream=True
        )
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


def _as_messages(raw: object) -> list[Message]:
    """Flatten xreadgroup/xautoclaim replies into ``[(id, fields), ...]``."""
    out: list[Message] = []
    for _stream, entries in raw:  # type: ignore[attr-defined]
        out.extend((mid, fields) for mid, fields in entries)
    return out


async def consume_once(
    redis: Redis,
    sessionmaker: async_sessionmaker[AsyncSession],
    predictor: Predictor,
    settings: Settings,
    consumer: str,
    *,
    block_ms: int | None = None,
) -> int:
    """Read one batch (new messages), process and ack it. Returns messages handled."""
    raw = await redis.xreadgroup(
        settings.stream_group,
        consumer,
        {settings.stream_flows: ">"},
        count=settings.worker_batch_size,
        block=settings.worker_block_ms if block_ms is None else block_ms,
    )
    messages = _as_messages(raw) if raw else []
    return await _handle(redis, sessionmaker, predictor, settings, messages)


async def reclaim_once(
    redis: Redis,
    sessionmaker: async_sessionmaker[AsyncSession],
    predictor: Predictor,
    settings: Settings,
    consumer: str,
) -> int:
    """Take over messages another (crashed) consumer left pending for too long."""
    _next, entries, _deleted = await redis.xautoclaim(
        settings.stream_flows,
        settings.stream_group,
        consumer,
        min_idle_time=settings.worker_reclaim_idle_ms,
        start_id="0-0",
        count=settings.worker_batch_size,
    )
    messages = [(mid, fields) for mid, fields in entries if fields is not None]
    return await _handle(redis, sessionmaker, predictor, settings, messages)


async def _handle(
    redis: Redis,
    sessionmaker: async_sessionmaker[AsyncSession],
    predictor: Predictor,
    settings: Settings,
    messages: list[Message],
) -> int:
    if not messages:
        return 0
    started = time.perf_counter()
    result = await process_messages(
        messages, sessionmaker=sessionmaker, redis=redis, predictor=predictor, settings=settings
    )
    if result.acked:
        await redis.xack(settings.stream_flows, settings.stream_group, *result.acked)
    log.info(
        "batch msgs=%d inserted=%d dead=%d alerts=%d ms=%.0f",
        len(messages),
        result.inserted,
        result.dead,
        result.alerts_touched,
        (time.perf_counter() - started) * 1000,
    )
    return len(messages)


async def snapshot_risk(sessionmaker: async_sessionmaker[AsyncSession]) -> int:
    """Store a risk snapshot for every organisation with alerts in the last 24 h (trend charts)."""
    now = datetime.now(UTC)
    async with sessionmaker() as session:
        org_ids = await active_org_ids(session, now)
        for org_id in org_ids:
            await snapshot_org(session, org_id, now)
        await session.commit()
    return len(org_ids)


async def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    redis, sessionmaker = get_redis(), get_sessionmaker()
    holder = PredictorHolder(settings.model_refresh_seconds)
    await holder.refresh(sessionmaker, force=True)
    consumer = f"worker-{uuid.uuid4().hex[:8]}"
    await ensure_group(redis, settings)
    log.info("worker %s started, model=%s", consumer, holder.predictor.version)
    last_reclaim = 0.0
    last_snapshot = 0.0
    while True:
        beat()
        try:
            await holder.refresh(sessionmaker)
            await consume_once(redis, sessionmaker, holder.predictor, settings, consumer)
            if time.monotonic() - last_reclaim > _RECLAIM_EVERY_S:
                last_reclaim = time.monotonic()
                await reclaim_once(redis, sessionmaker, holder.predictor, settings, consumer)
            if time.monotonic() - last_snapshot > settings.risk_snapshot_seconds:
                last_snapshot = time.monotonic()
                await snapshot_risk(sessionmaker)
        except (RedisError, OSError):
            log.exception("redis/db unavailable; backing off")
            await asyncio.sleep(2)
        except Exception:
            log.exception("unexpected worker error; continuing")
            await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
