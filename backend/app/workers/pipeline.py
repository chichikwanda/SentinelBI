"""Batch processing for the stream consumer: parse -> features -> predict -> persist -> alert.

``process_messages`` is independent of how messages are read, so tests drive it directly.
Persistence is idempotent (ADR-004): a redelivered message conflicts on
``(org_id, flow_ref, ts)`` and is skipped, and alerts are only built from newly inserted flows.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.enums import SourceStatus
from app.db.bulk import insert_ignoring_conflicts
from app.db.models import Source, flows, predictions
from app.schemas.ingest import FlowIn
from app.services.alerting import (
    add_window_totals,
    group_flagged,
    upsert_alert,
    window_counts,
)
from app.services.features.builder import records_to_frame, serving_features
from app.services.inference.predictor import Predictor, classify
from app.services.inventory import load_sources, observe_flows, quarantine_for_alert
from app.services.prescriptive.service import sync_recommendations
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
    # milliseconds spent per stage, summed over the batch (logged to show where time goes)
    stages: dict[str, float] = field(default_factory=dict)


@contextmanager
def _timed(stages: dict[str, float], name: str) -> Iterator[None]:
    started = time.perf_counter()
    try:
        yield
    finally:
        stages[name] = stages.get(name, 0.0) + (time.perf_counter() - started) * 1000


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
    stages: dict[str, float],
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

    with _timed(stages, "features"):
        feats = serving_features(records_to_frame(records))
    with _timed(stages, "predict"):
        result = classify(predictor, feats)

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
    # bulk.py explains why rows are sent as column arrays instead of an inlined VALUES list
    with _timed(stages, "flows"):
        for i in range(0, len(flow_rows), _CHUNK):
            new_refs.update(
                await insert_ignoring_conflicts(
                    session,
                    flows,
                    flow_rows[i : i + _CHUNK],
                    conflict=["org_id", "flow_ref", "ts"],
                    returning="flow_ref",
                )
            )

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
    with _timed(stages, "predictions"):
        for i in range(0, len(pred_rows), _CHUNK):
            await insert_ignoring_conflicts(
                session,
                predictions,
                pred_rows[i : i + _CHUNK],
                conflict=["org_id", "flow_ref", "model_version", "ts"],
            )

    # Source health: arrival time, so the wizard can show "first flows received".
    for org_id, source_id in {(p.org_id, p.source_id) for p in parsed}:
        await session.execute(
            update(Source)
            .where(Source.id == source_id, Source.org_id == org_id)
            .values(last_seen=now, status=SourceStatus.ACTIVE.value)
        )

    source_ids = {p.source_id for p in parsed}
    infos = await load_sources(session, source_ids, pseudonymized=settings.pseudonymize_ips)
    with _timed(stages, "inventory"):
        await observe_flows(
            session, [r for r in flow_rows if r["flow_ref"] in new_refs], infos, now=now
        )
    crit_rows = await session.execute(
        select(Source.id, Source.criticality).where(Source.id.in_(source_ids))
    )
    crit: dict[uuid.UUID, int] = {row[0]: row[1] for row in crit_rows}
    # the model's calibrated threshold applies, but never below the operator's configured floor
    threshold = max(
        settings.alert_min_probability, getattr(predictor, "alert_threshold", None) or 0.0
    )
    flagged = [
        {
            **row,
            "label": label,
            "probability": float(prob),
            "bytes": (row["in_bytes"] or 0) + (row["out_bytes"] or 0),
            "row_index": i,
        }
        for i, (row, label, prob) in enumerate(
            zip(flow_rows, result.labels, result.confidence, strict=True)
        )
        if row["flow_ref"] in new_refs and label != BENIGN and prob >= threshold
    ]
    # Totals for EVERY new flow per (org, source IP): the share gate below needs the denominator.
    totals = Counter((r["org_id"], r["src_ip"]) for r in flow_rows if r["flow_ref"] in new_refs)
    alert_started = time.perf_counter()
    window_totals = await add_window_totals(redis, dict(totals), settings)
    explain = getattr(predictor, "explain", None)
    classes = list(predictor.classes)

    touched = 0
    groups = list(group_flagged(flagged, crit))
    for group, in_window in zip(groups, await window_counts(redis, groups, settings), strict=True):
        total = max(window_totals.get((group.org_id, group.src_ip), in_window), in_window)
        if in_window >= settings.alert_min_flows and in_window / total >= settings.alert_min_share:
            top = None
            if callable(explain) and group.best_index is not None:
                top = explain(feats.iloc[[group.best_index]], classes.index(group.attack_class))
            alert = await upsert_alert(
                session,
                group,
                model_version=predictor.version,
                in_window=in_window,
                now=now,
                settings=settings,
                total_in_window=total,
                top_features=top,
            )
            await sync_recommendations(session, alert)
            info = infos.get(group.source_id)
            if info is not None:
                await quarantine_for_alert(session, alert, info, settings, now=now)
            touched += 1
    stages["alerts"] = stages.get("alerts", 0.0) + (time.perf_counter() - alert_started) * 1000
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
            return await _persist_and_alert(
                session, redis, predictor, settings, batch, result.stages
            )

    # A failed batch is first retried whole: transient database errors (a deadlock, a dropped
    # connection) usually clear, and the per-message fallback below costs one transaction per
    # message, which is slow for a large batch. The Redis window counters live outside the
    # transaction, so a retry can count the batch's flows twice: that can only make an alert fire
    # slightly early, never lose a flow.
    done = False
    for attempt in (1, 2):
        try:
            inserted, touched = await run(parsed)
        except Exception:
            log.exception("batch of %d failed (attempt %d of 2)", len(parsed), attempt)
            continue
        result.inserted += inserted
        result.alerts_touched += touched
        result.acked.extend(p.msg_id for p in parsed)
        done = True
        break
    if not done:
        # One poison message must not wedge the stream: retry individually, dead-letter the culprit.
        log.warning("retrying %d messages one by one", len(parsed))
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
