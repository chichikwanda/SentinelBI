"""Alert grouping, windowing and persistence.

Flagged flows are grouped per (org, source IP, attack class). A Redis counter per group over a
fixed window gates alert creation (a lone SYN-only flow is not a scan). Once the gate opens,
the group is merged into an existing open alert for the same (org, src_ip, class) seen within
``alert_merge_seconds`` or creates a new one. All reads/writes are scoped by ``org_id``.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.enums import AlertStatus
from app.db.models import Alert
from app.services.risk.scoring import event_risk, severity_for

EVIDENCE_SAMPLE = 20


@dataclass
class FlaggedGroup:
    org_id: uuid.UUID
    source_id: uuid.UUID
    src_ip: str
    attack_class: str
    criticality: int = 2
    n: int = 0
    max_probability: float = 0.0
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    dst_ips: set[str] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    bytes_total: int = 0
    flow_refs: list[str] = field(default_factory=list)


def group_flagged(
    rows: Iterable[dict[str, Any]], criticality: dict[uuid.UUID, int]
) -> list[FlaggedGroup]:
    """Group flagged flow rows. Each row needs: org_id, source_id, src_ip, dst_ip, dst_port,
    ts, flow_ref, label, probability, bytes."""
    groups: dict[tuple[uuid.UUID, str, str], FlaggedGroup] = {}
    for r in rows:
        key = (r["org_id"], r["src_ip"], r["label"])
        g = groups.get(key)
        if g is None:
            g = groups[key] = FlaggedGroup(
                org_id=r["org_id"],
                source_id=r["source_id"],
                src_ip=r["src_ip"],
                attack_class=r["label"],
                criticality=criticality.get(r["source_id"], 2),
            )
        g.n += 1
        g.max_probability = max(g.max_probability, float(r["probability"]))
        g.first_ts = r["ts"] if g.first_ts is None else min(g.first_ts, r["ts"])
        g.last_ts = r["ts"] if g.last_ts is None else max(g.last_ts, r["ts"])
        g.dst_ips.add(r["dst_ip"])
        g.dst_ports.add(int(r["dst_port"]))
        g.bytes_total += int(r["bytes"])
        if len(g.flow_refs) < EVIDENCE_SAMPLE:
            g.flow_refs.append(r["flow_ref"])
    return list(groups.values())


async def window_count(redis: Redis, group: FlaggedGroup, settings: Settings) -> int:
    """Add the group's flows to its fixed-window counter and return the running total."""
    key = f"win:{group.org_id}:{group.src_ip}:{group.attack_class}"
    pipe = redis.pipeline(transaction=True)
    pipe.incrby(key, group.n)
    pipe.expire(key, settings.alert_window_seconds, nx=True)
    result = await pipe.execute()
    return int(result[0])


def _merge_evidence(
    old: dict[str, Any], group: FlaggedGroup, model_version: str, in_window: int, settings: Settings
) -> dict[str, Any]:
    def union(prev: list[Any], new: Iterable[Any], limit: int) -> list[Any]:
        return sorted({*prev, *new}, key=str)[:limit]

    return {
        "model_version": model_version,
        "window_seconds": settings.alert_window_seconds,
        "flows_in_window": in_window,
        "bytes_total": int(old.get("bytes_total", 0)) + group.bytes_total,
        "dst_ips_sample": union(old.get("dst_ips_sample", []), group.dst_ips, EVIDENCE_SAMPLE),
        "dst_ports_sample": union(
            old.get("dst_ports_sample", []), group.dst_ports, EVIDENCE_SAMPLE
        ),
        "distinct_dst_ports_in_batch": len(group.dst_ports),
        "flow_refs_sample": (list(old.get("flow_refs_sample", [])) + group.flow_refs)[
            :EVIDENCE_SAMPLE
        ],
    }


async def upsert_alert(
    session: AsyncSession,
    group: FlaggedGroup,
    *,
    model_version: str,
    in_window: int,
    now: datetime,
    settings: Settings,
) -> Alert:
    assert group.first_ts is not None and group.last_ts is not None  # noqa: S101 - n >= 1
    # Serialise concurrent workers touching the same group.
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
        {"k": f"{group.org_id}:{group.src_ip}:{group.attack_class}"},
    )
    risk = 100.0 * event_risk(group.max_probability, group.attack_class, group.criticality)
    existing = (
        await session.execute(
            select(Alert)
            .where(
                Alert.org_id == group.org_id,
                Alert.src_ip == group.src_ip,
                Alert.attack_class == group.attack_class,
                Alert.status.in_([AlertStatus.NEW.value, AlertStatus.ACKNOWLEDGED.value]),
                Alert.last_seen >= now - timedelta(seconds=settings.alert_merge_seconds),
            )
            .order_by(Alert.last_seen.desc())
            .limit(1)
            .with_for_update()
        )
    ).scalar_one_or_none()

    if existing is None:
        alert = Alert(
            org_id=group.org_id,
            first_seen=group.first_ts,
            last_seen=group.last_ts,
            attack_class=group.attack_class,
            severity=severity_for(risk).value,
            risk_score=risk,
            # the gate may open on a later batch: include the earlier flows counted in the window
            count=max(group.n, in_window),
            src_ip=group.src_ip,
            dst_ip=next(iter(group.dst_ips)) if len(group.dst_ips) == 1 else None,
            evidence=_merge_evidence({}, group, model_version, in_window, settings),
            status=AlertStatus.NEW.value,
        )
        session.add(alert)
        await session.flush()
        return alert

    existing.count += group.n
    existing.first_seen = min(existing.first_seen, group.first_ts)
    existing.last_seen = max(existing.last_seen, group.last_ts)
    existing.risk_score = max(existing.risk_score, risk)
    existing.severity = severity_for(existing.risk_score).value
    if existing.dst_ip is not None and group.dst_ips != {str(existing.dst_ip)}:
        existing.dst_ip = None  # more than one target now
    existing.evidence = _merge_evidence(
        existing.evidence, group, model_version, in_window, settings
    )
    await session.flush()
    return existing
