"""Tenant isolation (design rule 1): nothing leaks across organisations."""

from __future__ import annotations

import uuid
from typing import Any

import httpx
from conftest import Tenant, add_source, register_org, scan_flows
from redis.asyncio import Redis
from sqlalchemy import text
from test_worker import drain, ingest

from app.core.config import Settings


async def _two_tenants_with_alerts(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> tuple[Tenant, Tenant, dict[str, Any], dict[str, Any]]:
    a, b = await register_org(client, "Org A"), await register_org(client, "Org B")
    # identical private CIDR on purpose: tenants commonly share RFC1918 ranges
    await add_source(client, a, cidr="10.20.0.0/24", name="A-HQ")
    await add_source(client, b, cidr="10.20.0.0/24", name="B-HQ")
    await ingest(client, a, scan_flows(7))
    await ingest(client, b, scan_flows(9, src="203.0.113.99"))
    await drain(redis, sessionmaker, settings)
    (alert_a,) = (await client.get("/api/v1/alerts", headers=a.headers)).json()
    (alert_b,) = (await client.get("/api/v1/alerts", headers=b.headers)).json()
    return a, b, alert_a, alert_b


async def test_alerts_are_scoped_to_the_callers_org(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    a, b, alert_a, alert_b = await _two_tenants_with_alerts(client, redis, sessionmaker, settings)

    assert alert_a["src_ip"] == "203.0.113.50" and alert_a["count"] == 7
    assert alert_b["src_ip"] == "203.0.113.99" and alert_b["count"] == 9

    # direct access to the other tenant's alert: 404 (existence is not revealed)
    assert (
        await client.get(f"/api/v1/alerts/{alert_b['id']}", headers=a.headers)
    ).status_code == 404
    assert (
        await client.get(f"/api/v1/alerts/{alert_a['id']}", headers=b.headers)
    ).status_code == 404
    patch = await client.patch(
        f"/api/v1/alerts/{alert_b['id']}", json={"status": "resolved"}, headers=a.headers
    )
    assert patch.status_code == 404
    still = (await client.get(f"/api/v1/alerts/{alert_b['id']}", headers=b.headers)).json()
    assert still["status"] == "new"  # untouched


async def test_sources_and_health_are_scoped(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    a, b, _, _ = await _two_tenants_with_alerts(client, redis, sessionmaker, settings)

    listed_a = (await client.get("/api/v1/sources", headers=a.headers)).json()
    assert [s["id"] for s in listed_a] == [a.source["id"]]

    assert (
        await client.get(f"/api/v1/sources/{b.source['id']}", headers=a.headers)
    ).status_code == 404
    assert (
        await client.get(f"/api/v1/sources/{b.source['id']}/health", headers=a.headers)
    ).status_code == 404
    random_id = uuid.uuid4()
    assert (await client.get(f"/api/v1/sources/{random_id}", headers=a.headers)).status_code == 404

    # A's health counts only A's flows even though both orgs share the same CIDR
    health_a = (
        await client.get(f"/api/v1/sources/{a.source['id']}/health", headers=a.headers)
    ).json()
    assert health_a["flows_total"] == 7


async def test_each_orgs_flows_are_stored_under_its_own_org_id(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    a, b, _, _ = await _two_tenants_with_alerts(client, redis, sessionmaker, settings)
    async with sessionmaker() as s:
        rows = (
            await s.execute(
                text(
                    "SELECT org_id::text, source_id::text, count(*) FROM flows WHERE org_id IN (:a, :b) GROUP BY org_id, source_id"
                ),
                {"a": a.org_id, "b": b.org_id},
            )
        ).all()
    assert {(r[0], r[1]): r[2] for r in rows} == {
        (a.org_id, a.source["id"]): 7,
        (b.org_id, b.source["id"]): 9,
    }


async def test_alerts_from_different_orgs_never_merge(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    """Same attacker IP + class in two orgs must produce two separate alerts."""
    a, b = await register_org(client, "Org A"), await register_org(client, "Org B")
    await add_source(client, a)
    await add_source(client, b)
    await ingest(client, a, scan_flows(6, src="203.0.113.50"))
    await ingest(client, b, scan_flows(6, src="203.0.113.50"))
    await drain(redis, sessionmaker, settings)
    (alert_a,) = (await client.get("/api/v1/alerts", headers=a.headers)).json()
    (alert_b,) = (await client.get("/api/v1/alerts", headers=b.headers)).json()
    assert alert_a["id"] != alert_b["id"]
    assert alert_a["count"] == alert_b["count"] == 6


async def test_api_key_of_one_org_cannot_write_into_another(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    a, b = await register_org(client, "Org A"), await register_org(client, "Org B")
    await add_source(client, a)
    await add_source(client, b)
    await ingest(client, a, scan_flows(6))
    await drain(redis, sessionmaker, settings)
    async with sessionmaker() as s:
        count_b = (
            await s.execute(text("SELECT count(*) FROM flows WHERE org_id = :o"), {"o": b.org_id})
        ).scalar_one()
    assert count_b == 0
    assert (await client.get("/api/v1/alerts", headers=b.headers)).json() == []


async def test_users_listing_is_scoped(client: httpx.AsyncClient) -> None:
    a, b = await register_org(client, "Org A"), await register_org(client, "Org B")
    emails_a = {u["email"] for u in (await client.get("/api/v1/users", headers=a.headers)).json()}
    assert emails_a == {a.email}
    assert b.email not in emails_a
