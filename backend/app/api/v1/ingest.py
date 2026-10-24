"""Flow ingestion: authenticate by API key, validate, push to the Redis stream."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import get_settings
from app.core.deps import SourceDep
from app.core.redis import get_redis
from app.schemas.ingest import FlowBatch, IngestAccepted

log = logging.getLogger("ingest")
router = APIRouter(prefix="/ingest", tags=["ingest"])

RedisDep = Annotated[Redis, Depends(get_redis)]


@router.post("/flows", response_model=IngestAccepted, status_code=status.HTTP_202_ACCEPTED)
async def ingest_flows(batch: FlowBatch, source: SourceDep, redis: RedisDep) -> IngestAccepted:
    settings = get_settings()
    if len(batch.flows) > settings.max_batch_flows:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"batch too large (max {settings.max_batch_flows} flows)",
        )
    now = datetime.now(UTC)
    # MULTI/EXEC: the whole batch is queued or none of it, so a client retry after a 503
    # cannot duplicate the accepted half.
    pipe = redis.pipeline(transaction=True)
    for flow in batch.flows:
        record = flow.model_dump(mode="json")
        ts = flow.ts or now
        record["ts"] = (ts if ts.tzinfo else ts.replace(tzinfo=UTC)).astimezone(UTC).isoformat()
        pipe.xadd(
            settings.stream_flows,
            {"org": str(source.org_id), "src": str(source.id), "data": json.dumps(record)},
            maxlen=settings.stream_maxlen,
            approximate=True,
        )
    try:
        await pipe.execute()
    except RedisError as exc:
        log.error("ingest queue unavailable: %s", exc)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "ingest queue unavailable, retry later",
            headers={"Retry-After": "5"},
        ) from exc
    return IngestAccepted(accepted=len(batch.flows))
