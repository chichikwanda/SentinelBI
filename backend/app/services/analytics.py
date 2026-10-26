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


# ---------------------------------------------------------------------------------------------
# Data volume per monitored host
# ---------------------------------------------------------------------------------------------
# ``in_bytes`` runs client -> server and ``out_bytes`` server -> client. From one host's point of
# view, what it SENT is ``in_bytes`` when it is the flow's source and ``out_bytes`` when it is the
# destination (and the other way round for what it RECEIVED). Each flow therefore appears twice,
# once per endpoint; a flow between two monitored hosts counts for both of them, as it should.
_SIDES = (
    "SELECT f.src_ip AS ip, coalesce(f.in_bytes, 0) AS sent, coalesce(f.out_bytes, 0) AS received, "
    "f.ts AS ts FROM flows f WHERE f.org_id = :org AND f.ts >= :since "
    "UNION ALL "
    "SELECT f.dst_ip, coalesce(f.out_bytes, 0), coalesce(f.in_bytes, 0), f.ts "
    "FROM flows f WHERE f.org_id = :org AND f.ts >= :since"
)


def _monitored(source_id: uuid.UUID | None) -> str:
    """An address is monitored when it is inside one of the organisation's sources."""
    scope = " AND s.id = :source" if source_id else ""
    return (
        "EXISTS (SELECT 1 FROM sources s WHERE s.org_id = :org"  # noqa: S608 - constant fragments, bound values
        + scope
        + " AND (sides.ip <<= s.cidr OR sides.ip <<= ANY (s.extra_cidrs)))"
    )


def format_bytes(n: float) -> str:
    """Human-readable size with decimal units (what network tools and ISPs use)."""
    value = float(n)
    for unit in ("B", "kB", "MB", "GB"):
        if value < 1000:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} TB"


async def traffic_summary(
    session: AsyncSession, org_id: uuid.UUID, minutes: int, now: datetime
) -> dict[str, Any]:
    since = now - timedelta(minutes=minutes)
    total = (
        await session.execute(
            text(
                "SELECT count(*) AS flows, "
                "coalesce(sum(coalesce(in_bytes,0) + coalesce(out_bytes,0)), 0) AS bytes "
                "FROM flows WHERE org_id = :org AND ts >= :since"
            ),
            {"org": org_id, "since": since},
        )
    ).one()
    mon = (
        await session.execute(
            text(
                f"WITH sides AS ({_SIDES}) "  # noqa: S608 - constant fragments, bound values
                "SELECT coalesce(sum(sent), 0) AS sent, coalesce(sum(received), 0) AS received, "
                f"count(DISTINCT ip) AS hosts FROM sides WHERE {_monitored(None)}"
            ),
            {"org": org_id, "since": since},
        )
    ).one()
    return {
        "minutes": minutes,
        "flows": int(total.flows),
        "total_bytes": int(total.bytes),
        "monitored_hosts": int(mon.hosts),
        "monitored_sent_bytes": int(mon.sent),
        "monitored_received_bytes": int(mon.received),
    }


async def host_volumes(
    session: AsyncSession,
    org_id: uuid.UUID,
    minutes: int,
    limit: int,
    now: datetime,
    source_id: uuid.UUID | None = None,
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {
        "org": org_id,
        "since": now - timedelta(minutes=minutes),
        "limit": limit,
    }
    if source_id:
        params["source"] = source_id
    rows = await session.execute(
        text(
            f"WITH sides AS ({_SIDES}) "  # noqa: S608 - constant fragments, bound values
            "SELECT host(ip) AS ip, sum(sent) AS sent, sum(received) AS received, "
            "count(*) AS flows, max(ts) AS last_seen "
            f"FROM sides WHERE {_monitored(source_id)} "
            "GROUP BY ip ORDER BY sum(sent) + sum(received) DESC LIMIT :limit"
        ),
        params,
    )
    return [
        {
            "ip": r.ip,
            "sent_bytes": int(r.sent),
            "received_bytes": int(r.received),
            "total_bytes": int(r.sent) + int(r.received),
            "flows": int(r.flows),
            "last_seen": r.last_seen.isoformat(),
        }
        for r in rows
    ]


SERVICE_NAMES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP submission", 993: "IMAPS", 995: "POP3S",
    1433: "SQL Server",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP (alt)",
    8443: "HTTPS (alt)",
}  # fmt: skip


def service_label(port: int | None, protocol: int | None) -> str:
    if protocol in (1, 58):
        return "ICMP"
    if not port:
        return "other"
    name = SERVICE_NAMES.get(port)
    return f"{name} ({port})" if name else f"port {port}"


async def host_detail(
    session: AsyncSession, org_id: uuid.UUID, ip: str, minutes: int, now: datetime
) -> dict[str, Any]:
    """Everything about one address: totals, sent/received over time, top peers and services."""
    step = bucket_minutes(minutes)
    since = now - timedelta(minutes=minutes)
    params = {"org": org_id, "since": since, "ip": ip, "step": step}
    me = "CAST(:ip AS inet)"
    involved = (
        f"org_id = :org AND ts >= :since AND (src_ip = {me} OR dst_ip = {me}) AND src_ip <> dst_ip"
    )
    sent = f"CASE WHEN src_ip = {me} THEN coalesce(in_bytes,0) ELSE coalesce(out_bytes,0) END"
    received = f"CASE WHEN src_ip = {me} THEN coalesce(out_bytes,0) ELSE coalesce(in_bytes,0) END"

    series = {
        r.bucket: (int(r.sent), int(r.received), int(r.flows))
        for r in await session.execute(
            text(
                "SELECT time_bucket(make_interval(mins => :step), ts) AS bucket, "  # noqa: S608 - constant fragments, bound values
                f"sum({sent}) AS sent, sum({received}) AS received, count(*) AS flows "
                f"FROM flows WHERE {involved} GROUP BY 1"
            ),
            params,
        )
    }
    step_td = timedelta(minutes=step)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    t = epoch + ((since - epoch) // step_td) * step_td
    points: list[dict[str, Any]] = []
    while t <= now:
        s, r, n = series.get(t, (0, 0, 0))
        points.append({"t": t.isoformat(), "sent": s, "received": r, "flows": n})
        t += step_td

    peers = await session.execute(
        text(
            f"SELECT host(CASE WHEN src_ip = {me} THEN dst_ip ELSE src_ip END) AS peer, "  # noqa: S608 - constant fragments, bound values
            "sum(coalesce(in_bytes,0) + coalesce(out_bytes,0)) AS bytes, count(*) AS flows "
            f"FROM flows WHERE {involved} GROUP BY 1 ORDER BY bytes DESC LIMIT 10"
        ),
        params,
    )
    services = await session.execute(
        text(
            "SELECT dst_port AS port, protocol, "  # noqa: S608 - constant fragments, bound values
            "sum(coalesce(in_bytes,0) + coalesce(out_bytes,0)) AS bytes, count(*) AS flows "
            f"FROM flows WHERE {involved} GROUP BY 1, 2 ORDER BY bytes DESC LIMIT 10"
        ),
        params,
    )
    total_sent = sum(p["sent"] for p in points)
    total_received = sum(p["received"] for p in points)
    return {
        "ip": ip,
        "minutes": minutes,
        "bucket_minutes": step,
        "sent_bytes": total_sent,
        "received_bytes": total_received,
        "total_bytes": total_sent + total_received,
        "flows": sum(p["flows"] for p in points),
        "points": points,
        "peers": [{"ip": r.peer, "bytes": int(r.bytes), "flows": int(r.flows)} for r in peers],
        "services": [
            {
                "service": service_label(r.port, r.protocol),
                "protocol": protocol_name(r.protocol),
                "bytes": int(r.bytes),
                "flows": int(r.flows),
            }
            for r in services
        ],
    }
