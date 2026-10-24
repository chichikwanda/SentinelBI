"""Router -> collector -> Redis -> worker -> alert, with hand-built NetFlow packets.

Exercises the real collector handler (allow-list, parser, normaliser, stream write) against the
real worker and database. Only the UDP socket is skipped: packets are handed to ``handle``.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import httpx
from conftest import Tenant, add_source, register_org
from redis.asyncio import Redis
from test_worker import drain

from allowlist import ExporterAllowlist, SourceRef
from app.core.config import Settings
from collector import Collector
from netflow_packets import Rec, v5_packet, v9_packet
from pairing import FlowPairer


def allowlist_for(*pairs: tuple[Tenant, str]) -> ExporterAllowlist:
    return ExporterAllowlist(
        [SourceRef(t.source["id"], t.org_id, ipaddress.ip_network(cidr)) for t, cidr in pairs]
    )


def scan_records(n: int) -> list[Rec]:
    return [Rec("203.0.113.50", "10.20.0.10", 50000 + i, 1 + i) for i in range(n)]


async def test_netflow_v5_scan_becomes_an_alert_for_the_exporters_org(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    router = "203.0.113.10"
    tenant = await register_org(client, "NetFlow Org")
    await add_source(client, tenant, cidr=router, method="netflow")
    collector = Collector(allowlist_for((tenant, f"{router}/32")), redis, pairer=FlowPairer(0))

    pushed = await collector.handle(v5_packet(scan_records(10)), router)
    assert pushed == 10
    assert collector.stats.flows_out == 10

    await drain(redis, sessionmaker, settings)
    (alert,) = (await client.get("/api/v1/alerts", headers=tenant.headers)).json()
    assert alert["attack_class"] == "Recon/Scan"
    assert alert["src_ip"] == "203.0.113.50"
    assert alert["count"] == 10

    health = (
        await client.get(f"/api/v1/sources/{tenant.source['id']}/health", headers=tenant.headers)
    ).json()
    assert health["first_flows_received"] is True
    assert health["flows_total"] == 10


async def test_netflow_v9_flows_reach_the_stream(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    router = "203.0.113.11"
    tenant = await register_org(client, "NetFlow v9 Org")
    await add_source(client, tenant, cidr=router, method="netflow")
    collector = Collector(allowlist_for((tenant, f"{router}/32")), redis, pairer=FlowPairer(0))

    assert await collector.handle(v9_packet(scan_records(6)), router) == 6
    await drain(redis, sessionmaker, settings)
    (alert,) = (await client.get("/api/v1/alerts", headers=tenant.headers)).json()
    assert alert["attack_class"] == "Recon/Scan"


async def test_unknown_exporter_is_dropped_and_nothing_is_queued(
    client: httpx.AsyncClient, redis: Redis, settings: Settings
) -> None:
    tenant = await register_org(client, "Known Org")
    await add_source(client, tenant, cidr="203.0.113.12", method="netflow")
    collector = Collector(allowlist_for((tenant, "203.0.113.12/32")), redis, pairer=FlowPairer(0))

    assert await collector.handle(v5_packet(scan_records(10)), "192.0.2.99") == 0
    assert collector.stats.dropped_unknown == 1
    assert await redis.xlen(settings.stream_flows) == 0


async def test_ambiguous_exporter_is_dropped_not_guessed(
    client: httpx.AsyncClient, redis: Redis, settings: Settings
) -> None:
    a, b = await register_org(client, "Org A"), await register_org(client, "Org B")
    await add_source(client, a, cidr="192.168.50.0/24", method="netflow")
    await add_source(client, b, cidr="192.168.50.0/24", method="netflow")
    collector = Collector(
        allowlist_for((a, "192.168.50.0/24"), (b, "192.168.50.0/24")), redis, pairer=FlowPairer(0)
    )

    assert await collector.handle(v5_packet(scan_records(10)), "192.168.50.1") == 0
    assert await redis.xlen(settings.stream_flows) == 0


async def test_garbage_datagram_from_a_known_exporter_is_survivable(
    client: httpx.AsyncClient, redis: Redis, settings: Settings
) -> None:
    router = "203.0.113.13"
    tenant = await register_org(client, "Garbage Org")
    await add_source(client, tenant, cidr=router, method="netflow")
    collector = Collector(allowlist_for((tenant, f"{router}/32")), redis, pairer=FlowPairer(0))

    assert await collector.handle(b"\x00\x05garbage", router) == 0
    assert await collector.handle(b"", router) == 0
    assert collector.stats.parse_errors == 2
    assert await redis.xlen(settings.stream_flows) == 0


async def test_reverse_netflow_records_are_paired_into_one_bidirectional_flow(
    client: httpx.AsyncClient, redis: Redis, settings: Settings
) -> None:
    """ADR-015: the model is trained on bidirectional flows, so the collector merges a record
    with its reverse partner and flushes records that never get one."""
    import json

    router = "203.0.113.14"
    tenant = await register_org(client, "Pairing Org")
    await add_source(client, tenant, cidr=router, method="netflow")
    collector = Collector(
        allowlist_for((tenant, f"{router}/32")), redis, pairer=FlowPairer(hold_seconds=30)
    )

    fwd = Rec(
        "10.20.0.5",
        "198.51.100.7",
        51000,
        443,
        flags=27,
        pkts=3,
        octets=300,
        first=99_000,
        last=99_400,
    )
    rev = Rec(
        "198.51.100.7",
        "10.20.0.5",
        443,
        51000,
        flags=27,
        pkts=7,
        octets=9000,
        first=99_050,
        last=99_450,
    )
    assert await collector.handle(v5_packet([fwd]), router) == 0  # held, waiting for its reply
    assert await redis.xlen(settings.stream_flows) == 0
    assert await collector.handle(v5_packet([rev]), router) == 1  # merged and written

    ((_, fields),) = await redis.xrange(settings.stream_flows)
    flow = json.loads(fields["data"])
    assert (flow["src_ip"], flow["dst_port"]) == ("10.20.0.5", 443)  # client side is the source
    assert (flow["in_pkts"], flow["in_bytes"]) == (3, 300)
    assert (flow["out_pkts"], flow["out_bytes"]) == (7, 9000)

    # a record that never gets a partner is flushed unchanged
    assert await collector.handle(v5_packet(scan_records(2)), router) == 0
    assert await collector.flush_pending(force=True) == 2
    assert await redis.xlen(settings.stream_flows) == 3
