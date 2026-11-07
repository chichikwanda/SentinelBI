"""Devices on a network, the baseline of peer networks, and the quarantine queue."""

from __future__ import annotations

from typing import Any

import httpx
from conftest import Tenant, add_source, flood_flows, register_org
from redis.asyncio import Redis
from sqlalchemy import text
from test_worker import drain, ingest

from app.core.config import Settings

DISCOVER = "/api/v1/sensor/devices"


async def sensor_network(client: httpx.AsyncClient) -> Tenant:
    tenant = await register_org(client)
    await add_source(client, tenant, cidr="10.20.0.0/24", method="sensor", name="Office")
    return tenant


async def end_baseline(sessionmaker: Any) -> None:
    async with sessionmaker() as s:
        await s.execute(text("UPDATE sources SET baseline_until = now() - interval '1 minute'"))
        await s.commit()


async def get(client: httpx.AsyncClient, tenant: Tenant, path: str) -> Any:
    resp = await client.get(f"/api/v1/{path}", headers=tenant.headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_discovery_lists_the_devices_and_learns_them_as_the_baseline(
    client: httpx.AsyncClient,
) -> None:
    tenant = await sensor_network(client)
    resp = await client.put(
        DISCOVER,
        json={
            "devices": [
                {"ip": "10.20.0.1", "mac": "AA-BB-CC-00-00-01", "hostname": "router"},
                {"ip": "10.20.0.7", "mac": "aa:bb:cc:00:00:07"},
                {"ip": "192.168.9.9", "mac": "aa:bb:cc:00:00:09"},  # not on this network
                {"ip": "10.20.0.255"},  # a broadcast-style entry with no MAC is still stored
            ]
        },
        headers=tenant.api_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"stored": 3}
    devices = {d["ip"]: d for d in await get(client, tenant, "inventory/devices")}
    assert set(devices) == {"10.20.0.1", "10.20.0.7", "10.20.0.255"}
    assert devices["10.20.0.1"]["mac"] == "aa:bb:cc:00:00:01"
    assert devices["10.20.0.1"]["hostname"] == "router"
    assert {d["state"] for d in devices.values()} == {"known"}  # still learning


async def test_a_device_that_joins_after_the_baseline_waits_for_a_decision(
    client: httpx.AsyncClient, sessionmaker: Any
) -> None:
    tenant = await sensor_network(client)
    await client.put(DISCOVER, json={"devices": [{"ip": "10.20.0.1"}]}, headers=tenant.api_headers)
    await end_baseline(sessionmaker)
    await client.put(
        DISCOVER,
        json={"devices": [{"ip": "10.20.0.1"}, {"ip": "10.20.0.99", "mac": "de:ad:be:ef:00:99"}]},
        headers=tenant.api_headers,
    )
    by_ip = {d["ip"]: d for d in await get(client, tenant, "inventory/devices")}
    assert by_ip["10.20.0.1"]["state"] == "known"
    assert by_ip["10.20.0.99"]["state"] == "new"
    summary = await get(client, tenant, "inventory/summary")
    assert summary["devices_total"] == 2 and summary["devices_new"] == 1

    only_new = await get(client, tenant, "inventory/devices?state=new")
    assert [d["ip"] for d in only_new] == ["10.20.0.99"]

    decided = await client.post(
        f"/api/v1/inventory/devices/{by_ip['10.20.0.99']['id']}/decision",
        json={"action": "approve", "note": "the new printer"},
        headers=tenant.headers,
    )
    assert decided.status_code == 200, decided.text
    assert decided.json()["state"] == "trusted"
    assert decided.json()["state_by"] == tenant.email
    assert "the new printer" in decided.json()["state_reason"]


async def test_a_known_address_answering_from_a_new_mac_is_held(
    client: httpx.AsyncClient, sessionmaker: Any
) -> None:
    tenant = await sensor_network(client)
    one = {"ip": "10.20.0.5", "mac": "aa:bb:cc:00:00:05"}
    await client.put(DISCOVER, json={"devices": [one]}, headers=tenant.api_headers)
    await end_baseline(sessionmaker)
    await client.put(
        DISCOVER,
        json={"devices": [{"ip": "10.20.0.5", "mac": "de:ad:be:ef:00:05"}]},
        headers=tenant.api_headers,
    )
    (device,) = await get(client, tenant, "inventory/devices")
    assert device["state"] == "new"
    assert "MAC address changed" in device["state_reason"]
    assert device["mac"] == "de:ad:be:ef:00:05"


async def test_peer_networks_are_baselined_then_new_ones_are_flagged(
    client: httpx.AsyncClient,
    redis: Redis,
    sessionmaker: Any,
    settings: Settings,
    flow_factory: Any,
) -> None:
    tenant = await sensor_network(client)
    await ingest(client, tenant, [flow_factory(dst_ip="198.51.100.20")])
    await drain(redis, sessionmaker, settings)
    await end_baseline(sessionmaker)
    await ingest(
        client,
        tenant,
        [flow_factory(dst_ip="198.51.100.21", src_port=40001), flow_factory(dst_ip="203.0.113.9")],
    )
    await drain(redis, sessionmaker, settings)

    nets = {n["network"]: n for n in await get(client, tenant, "inventory/networks")}
    assert set(nets) == {"198.51.100.0/24", "203.0.113.0/24"}
    assert nets["198.51.100.0/24"]["state"] == "baseline" and nets["198.51.100.0/24"]["flows"] == 2
    assert nets["203.0.113.0/24"]["state"] == "new"
    assert [n["network"] for n in await get(client, tenant, "inventory/networks?state=new")] == [
        "203.0.113.0/24"
    ]
    # the sending host is a device of the network, found from its traffic alone
    assert {d["ip"] for d in await get(client, tenant, "inventory/devices")} == {"10.20.0.50"}


async def test_a_serious_alert_quarantines_the_network_it_came_from(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    tenant = await sensor_network(client)
    await ingest(client, tenant, flood_flows(6))
    await drain(redis, sessionmaker, settings)

    (item,) = await get(client, tenant, "inventory/quarantine")
    assert item["kind"] == "network" and item["target"] == "198.51.100.0/24"
    assert item["flagged_ips"] == ["198.51.100.77"]
    assert "DoS/DDoS" in item["reason"]
    assert any("198.51.100.0/24" in c for c in item["commands"]["windows"])
    assert any("iptables" in c and "FORWARD" in c for c in item["commands"]["gateway"])
    alert_id = (await get(client, tenant, "alerts"))[0]["id"]
    assert item["alert_id"] == alert_id

    # a person releases it; the same ongoing alert does not put it straight back
    released = await client.post(
        f"/api/v1/inventory/networks/{item['id']}/decision",
        json={"action": "approve"},
        headers=tenant.headers,
    )
    assert released.status_code == 200 and released.json()["state"] == "approved"
    await ingest(client, tenant, flood_flows(6))
    await drain(redis, sessionmaker, settings)
    assert await get(client, tenant, "inventory/quarantine") == []


async def test_an_attack_from_inside_the_network_quarantines_that_device(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    tenant = await sensor_network(client)
    await ingest(client, tenant, flood_flows(6, src="10.20.0.33", dst="203.0.113.5"))
    await drain(redis, sessionmaker, settings)
    (item,) = await get(client, tenant, "inventory/quarantine")
    assert item["kind"] == "device" and item["target"] == "10.20.0.33"
    (device,) = [
        d for d in await get(client, tenant, "inventory/devices") if d["ip"] == "10.20.0.33"
    ]
    assert device["state"] == "quarantined" and device["state_by"] == "system"


async def test_the_sensor_policy_says_to_discover_a_network_and_lists_what_is_held(
    client: httpx.AsyncClient,
) -> None:
    tenant = await sensor_network(client)
    resp = await client.get("/api/v1/sensor/policy", headers=tenant.api_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cidr"] == "10.20.0.0/24" and body["discover"] is True
    assert body["learning_until"] is not None and body["quarantined"] == []

    single = await register_org(client)
    await add_source(client, single, cidr="10.30.0.5", method="sensor", name="Laptop")
    one = await client.get("/api/v1/sensor/policy", headers=single.api_headers)
    assert one.json()["discover"] is False


async def test_decisions_and_lists_are_private_to_the_organisation(
    client: httpx.AsyncClient,
) -> None:
    mine, other = await sensor_network(client), await sensor_network(client)
    await client.put(DISCOVER, json={"devices": [{"ip": "10.20.0.8"}]}, headers=mine.api_headers)
    (device,) = await get(client, mine, "inventory/devices")
    assert await get(client, other, "inventory/devices") == []
    resp = await client.post(
        f"/api/v1/inventory/devices/{device['id']}/decision",
        json={"action": "quarantine"},
        headers=other.headers,
    )
    assert resp.status_code == 404


async def test_a_second_attacking_host_is_added_to_a_held_network(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    """Regression: the stored addresses came back as address objects and the new one was a string,
    which the database refused, so the batch failed and its messages were dead-lettered."""
    tenant = await sensor_network(client)
    await ingest(client, tenant, flood_flows(6))
    await drain(redis, sessionmaker, settings)
    await ingest(client, tenant, flood_flows(6, src="198.51.100.78"))
    await drain(redis, sessionmaker, settings)

    (item,) = await get(client, tenant, "inventory/quarantine")
    assert item["flagged_ips"] == ["198.51.100.77", "198.51.100.78"]
    assert await redis.xlen(settings.stream_dead) == 0
