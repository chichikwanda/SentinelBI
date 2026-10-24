"""Batch processing for the stream consumer: parse -> features -> predict -> persist -> alert.

``process_messages`` is independent of how messages are read, so tests drive it directly.
Persistence is idempotent (ADR-004): a redelivered message conflicts on
``(org_id, flow_ref, ts)`` and is skipped, and alerts are only built from newly inserted flows.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.enums import SourceStatus
from app.db.models import Source, flows, predictions
from app.schemas.ingest import FlowIn
from app.services.alerting import group_flagged, upsert_alert, window_count
from app.services.features.builder import records_to_frame, serving_features
from app.services.inference.predictor import Predictor, classify
from app.services.privacy import pseudonymize_ip
from sentinelbi_ml.features import BENIGN

log = logging.getLogger("worker.pipeline")

Message = tuple[str, dict[str, str]]
_CHUNK = 1000


@dataclass
class BatchResult:
    acked: list[str] = field(default_factory=list)
    inserted: int = 0
    dead: int = 0
    alerts_touched: int = 0


@dataclass
class _Parsed:
    msg_id: str
    org_id: uuid.UUID
    source_id: uuid.UUID
    flow: FlowIn


def _parse(messages: list[Message]) -> tuple[list[_Parsed], list[tuple[str, dict[str, str], str]]]:
    ok: list[_Parsed] = []
    bad: list[tuple[str, dict[str, str], str]] = []
    for msg_id, fields in messages:
        try:
            ok.append(
                _Parsed(
                    msg_id,
                    uuid.UUID(fields["org"]),
                    uuid.UUID(fields["src"]),
                    FlowIn.model_validate_json(fields["data"]),
                )
            )
        except Exception as exc:  # malformed message: dead-letter it, never block the stream
            bad.append((msg_id, fields, f"{type(exc).__name__}: {exc}"[:500]))
    return ok, bad


async def _dead_letter(
    redis: Redis, settings: Settings, bad: list[tuple[str, dict[str, str], str]]
) -> None:
    for msg_id, fields, error in bad:
        await redis.xadd(
            settings.stream_dead,
            {"id": msg_id, "error": error, "data": json.dumps(fields)[:2048]},
            maxlen=10_000,
            approximate=True,
        )
        log.warning("dead-lettered message %s: %s", msg_id, error)


async def _persist_and_alert(
    session: AsyncSession,
    redis: Redis,
    predictor: Predictor,
    settings: Settings,
    parsed: list[_Parsed],
) -> tuple[int, int]:
    now = datetime.now(UTC)
    key = settings.pseudonym_key.get_secret_value().encode()

    records: list[dict[str, Any]] = []
    for p in parsed:
        rec = p.flow.model_dump(mode="python")
        rec["src_ip"], rec["dst_ip"] = str(rec["src_ip"]), str(rec["dst_ip"])
        if settings.pseudonymize_ips:
            rec["src_ip"] = pseudonymize_ip(rec["src_ip"], p.org_id, key)
            rec["dst_ip"] = pseudonymize_ip(rec["dst_ip"], p.org_id, key)
        ts = p.flow.ts or now
        rec["ts"] = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
        records.append(rec)

    result = classify(predictor, serving_features(records_to_frame(records)))

    flow_rows = [
        {
            "ts": rec["ts"],
            "org_id": p.org_id,
            "source_id": p.source_id,
            "flow_ref": p.msg_id,
            "src_ip": rec["src_ip"],
            "dst_ip": rec["dst_ip"],
            "src_port": rec["src_port"],
            "dst_port": rec["dst_port"],
            "protocol": rec["protocol"],
            "tcp_flags": rec["tcp_flags"],
            "in_bytes": rec["in_bytes"],
            "out_bytes": rec["out_bytes"],
            "in_pkts": rec["in_pkts"],
            "out_pkts": rec["out_pkts"],
            "duration_ms": rec["duration_ms"],
            "extra": rec["extra"],
        }
        for p, rec in zip(parsed, records, strict=True)
    ]

    new_refs: set[str] = set()
    for i in range(0, len(flow_rows), _CHUNK):
        stmt = (
            pg_insert(flows)
            .values(flow_rows[i : i + _CHUNK])
            .on_conflict_do_nothing(index_elements=["org_id", "flow_ref", "ts"])
            .returning(flows.c.flow_ref)
        )
        new_refs.update(r[0] for r in await session.execute(stmt))

    pred_rows = [
        {
            "ts": row["ts"],
            "org_id": row["org_id"],
            "flow_ref": row["flow_ref"],
            "model_version": predictor.version,
            "label": label,
            "probability": float(prob),
        }
        for row, label, prob in zip(flow_rows, result.labels, result.confidence, strict=True)
        if row["flow_ref"] in new_refs
    ]
    for i in range(0, len(pred_rows), _CHUNK):
        await session.execute(
            pg_insert(predictions)
            .values(pred_rows[i : i + _CHUNK])
            .on_conflict_do_nothing(index_elements=["org_id", "flow_ref", "model_version", "ts"])
        )

    # Source health: arrival time, so the wizard can show "first flows received".
    for org_id, source_id in {(p.org_id, p.source_id) for p in parsed}:
        await session.execute(
            update(Source)
            .where(Source.id == source_id, Source.org_id == org_id)
            .values(last_seen=now, status=SourceStatus.ACTIVE.value)
        )

    source_ids = {p.source_id for p in parsed}
    crit_rows = await session.execute(
        select(Source.id, Source.criticality).where(Source.id.in_(source_ids))
    )
    crit: dict[uuid.UUID, int] = {row[0]: row[1] for row in crit_rows}
    flagged = [
        {
            **row,
            "label": label,
            "probability": float(prob),
            "bytes": (row["in_bytes"] or 0) + (row["out_bytes"] or 0),
        }
        for row, label, prob in zip(flow_rows, result.labels, result.confidence, strict=True)
        if row["flow_ref"] in new_refs
        and label != BENIGN
        and prob >= settings.alert_min_probability
    ]
    touched = 0
    for group in group_flagged(flagged, crit):
        in_window = await window_count(redis, group, settings)
        if in_window >= settings.alert_min_flows:
            await upsert_alert(
                session,
                group,
                model_version=predictor.version,
                in_window=in_window,
                now=now,
                settings=settings,
            )
            touched += 1
    return len(new_refs), touched


async def process_messages(
    messages: list[Message],
    *,
    sessionmaker: async_sessionmaker[AsyncSession],
    redis: Redis,
    predictor: Predictor,
    settings: Settings,
) -> BatchResult:
    """Process one batch. Returns the message ids that are safe to XACK."""
    result = BatchResult()
    parsed, bad = _parse(messages)
    if bad:
        await _dead_letter(redis, settings, bad)
        result.dead += len(bad)
        result.acked.extend(m[0] for m in bad)
    if not parsed:
        return result

    async def run(batch: list[_Parsed]) -> tuple[int, int]:
        async with sessionmaker() as session, session.begin():
            return await _persist_and_alert(session, redis, predictor, settings, batch)

    try:
        inserted, touched = await run(parsed)
        result.inserted += inserted
        result.alerts_touched += touched
        result.acked.extend(p.msg_id for p in parsed)
    except Exception:
        # One poison message must not wedge the stream: retry individually, dead-letter the culprit.
        log.exception("batch of %d failed; retrying message by message", len(parsed))
        for p in parsed:
            try:
                inserted, touched = await run([p])
                result.inserted += inserted
                result.alerts_touched += touched
            except Exception as exc:
                await _dead_letter(
                    redis,
                    settings,
                    [(p.msg_id, {"org": str(p.org_id)}, f"{type(exc).__name__}: {exc}"[:500])],
                )
                result.dead += 1
            result.acked.append(p.msg_id)
    return result
