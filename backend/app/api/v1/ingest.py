"""Flow ingestion: authenticate by API key, validate, push to the Redis stream."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import get_settings
from app.core.deps import SourceDep
from app.core.redis import get_redis
from app.schemas.ingest import FlowBatch, IngestAccepted

log = logging.getLogger("ingest")
router = APIRouter(prefix="/ingest", tags=["ingest"])

RedisDep = Annotated[Redis, Depends(get_redis)]

IDEMPOTENCY_TTL_SECONDS = 3600

# Remember the batch's key and queue the whole batch in ONE atomic step inside Redis, or, when
# the key was already seen, queue nothing. A client that never saw the reply (a timeout, a dropped
# connection: the sensor retries on both) can then resend the identical batch without it being
# counted twice, even if the first attempt did reach Redis.
# KEYS: the key, the stream. ARGV: ttl, maxlen, org, src, then one flow's JSON per entry.
_QUEUE_ONCE = """
if redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[1]) == false then return 0 end
for i = 5, #ARGV do
  redis.call('XADD', KEYS[2], 'MAXLEN', '~', ARGV[2],
             '*', 'org', ARGV[3], 'src', ARGV[4], 'data', ARGV[i])
end
return #ARGV - 4
"""

# The client chooses the key; it only has to be unique per batch (the sensor sends a body hash).
IdempotencyKey = Annotated[
    str | None,
    Header(
        alias="Idempotency-Key",
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
        description="Optional. A batch resent with the same key is acknowledged, not queued again.",
    ),
]


@router.post(
    "/flows",
    response_model=IngestAccepted,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_flows(
    batch: FlowBatch,
    source: SourceDep,
    redis: RedisDep,
    idempotency_key: IdempotencyKey = None,
) -> IngestAccepted:
    settings = get_settings()
    if len(batch.flows) > settings.max_batch_flows:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"batch too large (max {settings.max_batch_flows} flows)",
        )
    now = datetime.now(UTC)
    records: list[str] = []
    for flow in batch.flows:
        record = flow.model_dump(mode="json")
        ts = flow.ts or now
        record["ts"] = (ts if ts.tzinfo else ts.replace(tzinfo=UTC)).astimezone(UTC).isoformat()
        records.append(json.dumps(record))
    org, src = str(source.org_id), str(source.id)
    try:
        if idempotency_key:
            queued = await redis.register_script(_QUEUE_ONCE)(
                keys=[f"idem:{src}:{idempotency_key}", settings.stream_flows],
                args=[IDEMPOTENCY_TTL_SECONDS, settings.stream_maxlen, org, src, *records],
            )
            if int(queued) == 0:
                return IngestAccepted(accepted=len(records), duplicate=True)
            return IngestAccepted(accepted=len(records))
        # MULTI/EXEC: the whole batch is queued or none of it. Without a key a retry after an
        # ambiguous failure can still repeat a batch that did get through; with one it cannot.
        pipe = redis.pipeline(transaction=True)
        for data in records:
            pipe.xadd(
                settings.stream_flows,
                {"org": org, "src": src, "data": data},
                maxlen=settings.stream_maxlen,
                approximate=True,
            )
        await pipe.execute()
    except RedisError as exc:
        log.error("ingest queue unavailable: %s", exc)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "ingest queue unavailable, retry later",
            headers={"Retry-After": "5"},
        ) from exc
    return IngestAccepted(accepted=len(batch.flows))
