"""Recommendations, overview, traffic, risk and the alert share gate (all fast, real DB)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from conftest import Tenant, add_source, register_org, scan_flows
from redis.asyncio import Redis
from test_worker import alerts_for, drain, ingest

from app.core.config import Settings
from app.services.risk.aggregate import AssetRisk, decay_factor, snapshot_org


async def make_scan_alert(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings,
    n: int = 12, dst: str = "10.20.0.10",
) -> dict[str, Any]:  # fmt: skip
    await ingest(client, tenant, scan_flows(n, dst=dst))
    await drain(redis, sessionmaker, settings)
    (alert,) = await alerts_for(client, tenant)
    return alert


async def test_alert_gets_ranked_recommendations_with_resolved_references(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    alert = await make_scan_alert(client, tenant, redis, sessionmaker, settings)
    resp = await client.get(
        f"/api/v1/recommendations?alert_id={alert['id']}", headers=tenant.headers
    )
    recs = resp.json()
    assert len(recs) >= 3
    assert [r["rank"] for r in recs] == sorted((r["rank"] for r in recs), reverse=True)
    assert all(r["alert"]["id"] == alert["id"] for r in recs)

    mitre = {
        (ref["id"], ref["title"])
        for r in recs
        for ref in r["references"]
        if ref["framework"] == "mitre"
    }
    assert ("M1056", "Pre-compromise") in mitre  # title resolved from the STIX-generated mapping
    assert any(ref["url"] for r in recs for ref in r["references"] if ref["framework"] == "mitre")


async def test_recommendation_persistence_is_idempotent_across_alert_updates(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    alert = await make_scan_alert(client, tenant, redis, sessionmaker, settings)
    first = (
        await client.get(f"/api/v1/recommendations?alert_id={alert['id']}", headers=tenant.headers)
    ).json()
    await ingest(client, tenant, scan_flows(8))  # merges into the same alert and re-syncs rules
    await drain(redis, sessionmaker, settings)
    second = (
        await client.get(f"/api/v1/recommendations?alert_id={alert['id']}", headers=tenant.headers)
    ).json()
    assert {r["id"] for r in first} <= {r["id"] for r in second}
    assert len(second) == len({r["rule_id"] + r["action"] for r in second})  # no duplicates


async def test_recommendation_status_workflow_and_permissions(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    admin = await register_org(client, "Recs Org")
    await add_source(client, admin)
    await make_scan_alert(client, admin, redis, sessionmaker, settings)
    (rec, *_rest) = (await client.get("/api/v1/recommendations", headers=admin.headers)).json()

    done = await client.patch(
        f"/api/v1/recommendations/{rec['id']}", json={"status": "done"}, headers=admin.headers
    )
    assert done.status_code == 200 and done.json()["status"] == "done"
    todo = (await client.get("/api/v1/recommendations?status=open", headers=admin.headers)).json()
    assert rec["id"] not in {r["id"] for r in todo}
    assert (
        await client.patch(
            f"/api/v1/recommendations/{rec['id']}", json={"status": "bogus"}, headers=admin.headers
        )
    ).status_code == 422

    # a viewer cannot change status; another organisation cannot even see it
    from conftest import PASSWORD, unique_email

    email = unique_email("viewer")
    await client.post(
        "/api/v1/users",
        json={"email": email, "password": PASSWORD, "role": "viewer"},
        headers=admin.headers,
    )
    token = (
        await client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    ).json()["access_token"]
    viewer = {"Authorization": f"Bearer {token}"}
    assert (
        await client.patch(
            f"/api/v1/recommendations/{rec['id']}", json={"status": "open"}, headers=viewer
        )
    ).status_code == 403
    other = await register_org(client, "Other Org")
    assert (
        await client.patch(
            f"/api/v1/recommendations/{rec['id']}", json={"status": "open"}, headers=other.headers
        )
    ).status_code == 404
    assert (await client.get("/api/v1/recommendations", headers=other.headers)).json() == []


async def test_overview_kpis_and_tenant_isolation(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    await make_scan_alert(client, tenant, redis, sessionmaker, settings)
    ov = (await client.get("/api/v1/overview", headers=tenant.headers)).json()
    assert ov["flows_24h"] == 12
    assert ov["open_alerts"] == 1 and ov["open_by_severity"]["Medium"] == 1
    assert ov["risk"]["score"] > 0 and ov["risk"]["severity"] in {
        "Low",
        "Medium",
        "High",
        "Critical",
    }
    assert ov["sources_total"] == 1 and ov["sources_receiving"] == 1
    assert ov["top_attackers"][0]["ip"] == "203.0.113.50"

    other = await register_org(client, "Empty Org")
    empty = (await client.get("/api/v1/overview", headers=other.headers)).json()
    assert empty["flows_24h"] == 0 and empty["open_alerts"] == 0 and empty["top_attackers"] == []
    assert empty["risk"]["score"] == 0


async def test_traffic_endpoints(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    sessionmaker: Any,
    settings: Settings,
    flow_factory: Any,
) -> None:
    await ingest(
        client,
        tenant,
        [flow_factory(src_ip="10.20.0.50", in_bytes=5000) for _ in range(3)] + scan_flows(6),
    )
    await drain(redis, sessionmaker, settings)

    series = (
        await client.get("/api/v1/traffic/timeseries?minutes=60", headers=tenant.headers)
    ).json()
    assert series["bucket_minutes"] == 1
    assert sum(p["flows"] for p in series["points"]) == 9
    assert sum(p["alerts"] for p in series["points"]) == 1
    assert datetime.fromisoformat(series["points"][-1]["t"]) <= datetime.now(UTC)

    talkers = (
        await client.get("/api/v1/traffic/top-talkers?minutes=60&limit=5", headers=tenant.headers)
    ).json()
    assert talkers[0]["ip"] == "10.20.0.50" and talkers[0]["bytes"] == 3 * (5000 + 5400)
    protocols = (
        await client.get("/api/v1/traffic/protocols?minutes=60", headers=tenant.headers)
    ).json()
    assert protocols == [{"protocol": "TCP", "flows": 9, "bytes": protocols[0]["bytes"]}]
    assert (
        await client.get("/api/v1/traffic/timeseries?minutes=1", headers=tenant.headers)
    ).status_code == 422


async def test_asset_risk_attaches_alerts_to_registered_assets(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    t = await register_org(client, "Asset Org")
    await add_source(
        client, t, cidr="10.20.0.10", method="http", criticality=3
    )  # single host => an asset
    await ingest(client, t, scan_flows(12, dst="10.20.0.10"))
    await drain(redis, sessionmaker, settings)

    risk = (await client.get("/api/v1/risk/assets", headers=t.headers)).json()
    (asset,) = risk["assets"]
    assert asset["ip"] == "10.20.0.10" and asset["registered"] and asset["criticality"] == 3
    assert asset["open_alerts"] == 1 and asset["score"] > 0
    assert risk["score"] == asset["score"]  # the single asset is the whole organisation

    # an alert for an address that is not a registered asset still counts, as "unassigned"
    await ingest(client, t, scan_flows(12, src="198.51.100.200", dst="10.20.0.99"))
    await drain(redis, sessionmaker, settings)
    labels = {
        a["label"]: a
        for a in (await client.get("/api/v1/risk/assets", headers=t.headers)).json()["assets"]
    }
    assert any(not a["registered"] for a in labels.values())


async def test_risk_snapshots_feed_the_trend(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    await make_scan_alert(client, tenant, redis, sessionmaker, settings)
    async with sessionmaker() as s:
        await snapshot_org(s, __import__("uuid").UUID(tenant.org_id), datetime.now(UTC))
        await s.commit()
    trend = (await client.get("/api/v1/risk/trend?hours=1", headers=tenant.headers)).json()
    assert len(trend["points"]) >= 2  # the stored snapshot plus the live value
    assert all(0 <= p["score"] <= 100 for p in trend["points"])


def test_risk_math() -> None:
    assert decay_factor(0, 6) == 1.0
    assert decay_factor(6, 6) == 0.5
    assert decay_factor(12, 6) == 0.25
    node = AssetRisk(None, "x", None, 2, False)
    node.add(0.5)
    assert round(node.score, 1) == 50.0
    node.add(0.5)  # 1 - (0.5 * 0.5)
    assert round(node.score, 1) == 75.0
    node.add(2.0)  # inputs are clamped to [0, 1]
    assert node.score == 100.0


async def test_busy_benign_host_with_a_few_flagged_flows_raises_no_alert(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    sessionmaker: Any,
    settings: Settings,
    flow_factory: Any,
) -> None:
    """The share gate: 6 scan-like flows among 100 normal ones from the same host is ~6%,
    far below alert_min_share (20%), so a ~1% false-positive rate cannot raise alerts."""
    busy = "10.20.0.77"
    normal = [flow_factory(src_ip=busy, src_port=40000 + i) for i in range(100)]
    await ingest(client, tenant, normal + scan_flows(6, src=busy))
    await drain(redis, sessionmaker, settings)
    assert await alerts_for(client, tenant) == []

    # the same count from a source that does nothing else is an alert
    await ingest(client, tenant, scan_flows(6, src="203.0.113.60"))
    await drain(redis, sessionmaker, settings)
    (alert,) = await alerts_for(client, tenant)
    assert alert["src_ip"] == "203.0.113.60"
    assert alert["evidence"]["all_flows_in_window"] == 6
