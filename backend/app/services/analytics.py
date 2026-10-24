"""Descriptive analytics queries (all scoped by ``org_id``)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}


def protocol_name(number: int | None) -> str:
    return PROTOCOL_NAMES.get(number or -1, f"IP proto {number}")


def bucket_minutes(window_minutes: int) -> int:
    """Pick a bucket so a chart has roughly 60-180 points."""
    if window_minutes <= 180:
        return 1
    if window_minutes <= 900:
        return 5
    if window_minutes <= 4320:
        return 30
    return 120


async def timeseries(
    session: AsyncSession, org_id: uuid.UUID, minutes: int, now: datetime
) -> dict[str, Any]:
    step = bucket_minutes(minutes)
    since = now - timedelta(minutes=minutes)
    flows_rows = await session.execute(
        text(
            "SELECT time_bucket(make_interval(mins => :step), ts) AS bucket, count(*) AS flows, "
            "coalesce(sum(coalesce(in_bytes,0) + coalesce(out_bytes,0)), 0) AS bytes "
            "FROM flows WHERE org_id = :org AND ts >= :since GROUP BY 1"
        ),
        {"step": step, "org": org_id, "since": since},
    )
    alert_rows = await session.execute(
        text(
            "SELECT time_bucket(make_interval(mins => :step), first_seen) AS bucket, "
            "count(*) AS alerts "
            "FROM alerts WHERE org_id = :org AND first_seen >= :since GROUP BY 1"
        ),
        {"step": step, "org": org_id, "since": since},
    )
    flows = {r.bucket: (int(r.flows), int(r.bytes)) for r in flows_rows}
    alerts = {r.bucket: int(r.alerts) for r in alert_rows}

    # continuous series (empty buckets as zeros) so charts do not interpolate over gaps
    step_td = timedelta(minutes=step)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    start = epoch + ((since - epoch) // step_td) * step_td
    points: list[dict[str, Any]] = []
    t = start
    while t <= now:
        f, b = flows.get(t, (0, 0))
        points.append({"t": t.isoformat(), "flows": f, "bytes": b, "alerts": alerts.get(t, 0)})
        t += step_td
    return {"bucket_minutes": step, "minutes": minutes, "points": points}


async def top_talkers(
    session: AsyncSession, org_id: uuid.UUID, minutes: int, limit: int, now: datetime
) -> list[dict[str, Any]]:
    rows = await session.execute(
        text(
            "SELECT host(src_ip) AS ip, count(*) AS flows, "
            "coalesce(sum(coalesce(in_bytes,0) + coalesce(out_bytes,0)), 0) AS bytes "
            "FROM flows WHERE org_id = :org AND ts >= :since AND src_ip IS NOT NULL "
            "GROUP BY 1 ORDER BY bytes DESC LIMIT :limit"
        ),
        {"org": org_id, "since": now - timedelta(minutes=minutes), "limit": limit},
    )
    return [{"ip": r.ip, "flows": int(r.flows), "bytes": int(r.bytes)} for r in rows]


async def protocol_mix(
    session: AsyncSession, org_id: uuid.UUID, minutes: int, now: datetime
) -> list[dict[str, Any]]:
    rows = await session.execute(
        text(
            "SELECT protocol, count(*) AS flows, "
            "coalesce(sum(coalesce(in_bytes,0) + coalesce(out_bytes,0)), 0) AS bytes "
            "FROM flows WHERE org_id = :org AND ts >= :since GROUP BY 1 ORDER BY flows DESC"
        ),
        {"org": org_id, "since": now - timedelta(minutes=minutes)},
    )
    return [
        {"protocol": protocol_name(r.protocol), "flows": int(r.flows), "bytes": int(r.bytes)}
        for r in rows
    ]
