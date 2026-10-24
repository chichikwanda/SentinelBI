"""The worker: stream -> features -> placeholder predictor -> flows/predictions/alerts."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from conftest import Tenant, flood_flows, scan_flows
from redis.asyncio import Redis
from sqlalchemy import text

from app.core.config import Settings
from app.services.inference.placeholder import PLACEHOLDER_VERSION, PlaceholderPredictor
from app.workers.pipeline import process_messages
from app.workers.stream_consumer import consume_once, ensure_group

PREDICTOR = PlaceholderPredictor()


async def ingest(client: httpx.AsyncClient, tenant: Tenant, flows: list[dict[str, Any]]) -> None:
    resp = await client.post(
        "/api/v1/ingest/flows", json={"flows": flows}, headers=tenant.api_headers
    )
    assert resp.status_code == 202, resp.text


async def drain(redis: Redis, sessionmaker: Any, settings: Settings) -> int:
    await ensure_group(redis, settings)
    total = 0
    while n := await consume_once(
        redis, sessionmaker, PREDICTOR, settings, "test-consumer", block_ms=50
    ):
        total += n
    return total


async def scalar(sessionmaker: Any, sql: str, **params: Any) -> Any:
    async with sessionmaker() as s:
        return (await s.execute(text(sql), params)).scalar_one()


async def alerts_for(client: httpx.AsyncClient, tenant: Tenant) -> list[dict[str, Any]]:
    resp = await client.get("/api/v1/alerts", headers=tenant.headers)
    assert resp.status_code == 200
    return resp.json()  # type: ignore[no-any-return]


async def test_scan_traffic_is_persisted_classified_and_alerted(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    sessionmaker: Any,
    settings: Settings,
    flow_factory: Any,
) -> None:
    await ingest(client, tenant, scan_flows(12) + [flow_factory() for _ in range(5)])
    assert await drain(redis, sessionmaker, settings) == 17

    assert (
        await scalar(sessionmaker, "SELECT count(*) FROM flows WHERE org_id = :o", o=tenant.org_id)
        == 17
    )
    assert (
        await scalar(
            sessionmaker,
            "SELECT count(*) FROM predictions WHERE org_id = :o AND model_version = :v AND label = 'Recon/Scan'",
            o=tenant.org_id,
            v=PLACEHOLDER_VERSION,
        )
        == 12
    )

    alerts = await alerts_for(client, tenant)
    assert len(alerts) == 1  # the 5 benign flows raise nothing
    alert = alerts[0]
    assert alert["attack_class"] == "Recon/Scan"
    assert alert["src_ip"] == "203.0.113.50"
    assert alert["count"] == 12
    assert alert["status"] == "new"
    # 0.85 (placeholder probability) x 0.3 (Recon impact) x 1.0 (criticality 2) = 25.5 -> Medium
    assert alert["risk_score"] == 25.5 or abs(alert["risk_score"] - 25.5) < 1e-6
    assert alert["severity"] == "Medium"
    assert alert["evidence"]["model_version"] == PLACEHOLDER_VERSION
    assert alert["evidence"]["distinct_dst_ports_in_batch"] == 12

    health = (
        await client.get(f"/api/v1/sources/{tenant.source['id']}/health", headers=tenant.headers)
    ).json()
    assert health["state"] == "receiving"
    assert health["first_flows_received"] is True
    assert health["flows_total"] == 17


async def test_flood_is_classified_as_dos(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    await ingest(client, tenant, flood_flows(6))
    await drain(redis, sessionmaker, settings)
    (alert,) = await alerts_for(client, tenant)
    assert alert["attack_class"] == "DoS/DDoS"
    assert alert["severity"] == "High"  # 0.9 x 0.6 = 54


async def test_benign_traffic_raises_no_alert(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    sessionmaker: Any,
    settings: Settings,
    flow_factory: Any,
) -> None:
    await ingest(client, tenant, [flow_factory(src_port=40000 + i) for i in range(30)])
    await drain(redis, sessionmaker, settings)
    assert (
        await scalar(sessionmaker, "SELECT count(*) FROM flows WHERE org_id = :o", o=tenant.org_id)
        == 30
    )
    assert await alerts_for(client, tenant) == []


async def test_alert_waits_for_enough_flagged_flows_across_batches(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    assert settings.alert_min_flows == 5
    await ingest(client, tenant, scan_flows(3))
    await drain(redis, sessionmaker, settings)
    assert await alerts_for(client, tenant) == []  # a few failed connections are not a scan

    await ingest(client, tenant, scan_flows(3))
    await drain(redis, sessionmaker, settings)
    (alert,) = await alerts_for(client, tenant)
    assert alert["count"] == 6  # includes the earlier batch counted in the window

    await ingest(client, tenant, scan_flows(4))
    await drain(redis, sessionmaker, settings)
    (merged,) = await alerts_for(client, tenant)  # merged into the open alert, not duplicated
    assert merged["id"] == alert["id"]
    assert merged["count"] == 10


async def test_redelivery_is_idempotent(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    await ingest(client, tenant, scan_flows(8))
    await ensure_group(redis, settings)
    raw = await redis.xreadgroup(
        settings.stream_group, "c1", {settings.stream_flows: ">"}, count=100, block=50
    )
    messages = [(mid, fields) for mid, fields in raw[0][1]]

    kwargs = {
        "sessionmaker": sessionmaker,
        "redis": redis,
        "predictor": PREDICTOR,
        "settings": settings,
    }
    first = await process_messages(messages, **kwargs)
    second = await process_messages(
        messages, **kwargs
    )  # same ids delivered again (crash before XACK)

    assert first.inserted == 8
    assert second.inserted == 0
    assert (
        await scalar(sessionmaker, "SELECT count(*) FROM flows WHERE org_id = :o", o=tenant.org_id)
        == 8
    )
    assert (
        await scalar(
            sessionmaker, "SELECT count(*) FROM predictions WHERE org_id = :o", o=tenant.org_id
        )
        == 8
    )
    (alert,) = await alerts_for(client, tenant)
    assert alert["count"] == 8  # not doubled


async def test_malformed_message_is_dead_lettered_without_blocking_the_rest(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    await ingest(client, tenant, scan_flows(6))
    await redis.xadd(
        settings.stream_flows,
        {"org": tenant.org_id, "src": tenant.source["id"], "data": "{not json"},
    )
    await redis.xadd(settings.stream_flows, {"org": "not-a-uuid", "src": "x", "data": "{}"})

    assert await drain(redis, sessionmaker, settings) == 8
    assert (
        await scalar(sessionmaker, "SELECT count(*) FROM flows WHERE org_id = :o", o=tenant.org_id)
        == 6
    )
    assert await redis.xlen(settings.stream_dead) == 2
    pending = await redis.xpending(settings.stream_flows, settings.stream_group)
    assert pending["pending"] == 0  # everything acked, nothing stuck


async def test_poison_message_that_fails_in_the_database_is_isolated(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    await ingest(client, tenant, scan_flows(6))
    poison = {
        "src_ip": "203.0.113.50",
        "dst_ip": "10.20.0.10",
        "src_port": 1,
        "dst_port": 2,
        "protocol": 6,
        "tcp_flags": 2,
        "in_bytes": 10**30,
        "out_bytes": 0,
        "in_pkts": 1,
        "out_pkts": 0,
        "duration_ms": 0,
        "ts": datetime.now(UTC).isoformat(),
    }
    await redis.xadd(
        settings.stream_flows,
        {"org": tenant.org_id, "src": tenant.source["id"], "data": json.dumps(poison)},
    )
    await drain(redis, sessionmaker, settings)

    assert (
        await scalar(sessionmaker, "SELECT count(*) FROM flows WHERE org_id = :o", o=tenant.org_id)
        == 6
    )
    assert await redis.xlen(settings.stream_dead) == 1
    assert (await redis.xpending(settings.stream_flows, settings.stream_group))["pending"] == 0


async def test_pseudonymization_masks_internal_addresses_only(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    sessionmaker: Any,
    settings: Settings,
    flow_factory: Any,
) -> None:
    masked = settings.model_copy(update={"pseudonymize_ips": True})
    await ingest(client, tenant, [flow_factory(src_ip="10.20.0.50", dst_ip="198.51.100.20")])
    await drain(redis, sessionmaker, masked)

    src, dst = await _row(
        sessionmaker,
        "SELECT host(src_ip), host(dst_ip) FROM flows WHERE org_id = :o",
        o=tenant.org_id,
    )
    assert src != "10.20.0.50" and src.startswith(("24", "25"))  # 240.0.0.0/4 pseudonym range
    assert dst == "198.51.100.20"  # public addresses are untouched


async def _row(sessionmaker: Any, sql: str, **params: Any) -> tuple[Any, ...]:
    async with sessionmaker() as s:
        return tuple((await s.execute(text(sql), params)).one())


async def test_unknown_org_uuid_in_stream_does_not_create_data_for_others(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    ghost_org = str(uuid.uuid4())
    await redis.xadd(
        settings.stream_flows,
        {
            "org": ghost_org,
            "src": str(uuid.uuid4()),
            "data": json.dumps({**scan_flows(1)[0], "ts": datetime.now(UTC).isoformat()}),
        },
    )
    await drain(redis, sessionmaker, settings)
    assert (
        await scalar(sessionmaker, "SELECT count(*) FROM flows WHERE org_id = :o", o=tenant.org_id)
        == 0
    )
