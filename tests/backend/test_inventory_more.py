"""Inventory: vendors, a busy network, forgetting, and pseudonymised mode."""

from __future__ import annotations

from typing import Any

import httpx
from conftest import add_source, flood_flows, register_org
from redis.asyncio import Redis
from test_inventory import DISCOVER, get, sensor_network
from test_worker import drain, ingest

from app.core.config import Settings


async def test_devices_carry_their_vendor_and_a_random_mac_says_so(
    client: httpx.AsyncClient,
) -> None:
    tenant = await sensor_network(client)
    await client.put(
        DISCOVER,
        json={
            "devices": [
                {"ip": "10.20.0.1", "mac": "00:00:0c:12:34:56"},  # a Cisco prefix
                {"ip": "10.20.0.2", "mac": "da:a1:19:12:34:56"},  # locally administered bit set
                {"ip": "10.20.0.3"},
            ]
        },
        headers=tenant.api_headers,
    )
    by_ip = {d["ip"]: d["vendor"] for d in await get(client, tenant, "inventory/devices")}
    assert "cisco" in by_ip["10.20.0.1"].lower()
    assert by_ip["10.20.0.2"].startswith("Randomised")
    assert by_ip["10.20.0.3"] is None


async def test_a_busy_network_report_is_stored_whole_and_a_bigger_one_is_refused(
    client: httpx.AsyncClient,
) -> None:
    tenant = await register_org(client)
    await add_source(client, tenant, cidr="10.20.0.0/22", method="sensor", name="Campus")
    hosts = [
        {
            "ip": f"10.20.{i // 256}.{i % 256}",
            "mac": f"02:00:00:00:{i // 256:02x}:{i % 256:02x}",
        }
        for i in range(1024)
    ]
    resp = await client.put(DISCOVER, json={"devices": hosts}, headers=tenant.api_headers)
    assert resp.status_code == 200 and resp.json() == {"stored": 1024}
    too_many = await client.put(
        DISCOVER, json={"devices": [*hosts, {"ip": "10.20.3.250"}]}, headers=tenant.api_headers
    )
    assert too_many.status_code == 422
    page_one = await get(client, tenant, "inventory/devices?limit=1000")
    page_two = await get(client, tenant, "inventory/devices?limit=1000&offset=1000")
    assert len(page_one) == 1000 and len(page_two) == 24
    assert not {d["id"] for d in page_one} & {d["id"] for d in page_two}
    assert (await get(client, tenant, "inventory/summary"))["devices_total"] == 1024


async def test_an_administrator_can_forget_a_device_but_not_one_in_quarantine(
    client: httpx.AsyncClient,
) -> None:
    tenant = await sensor_network(client)
    await client.put(DISCOVER, json={"devices": [{"ip": "10.20.0.8"}]}, headers=tenant.api_headers)
    (device,) = await get(client, tenant, "inventory/devices")
    url = f"/api/v1/inventory/devices/{device['id']}"
    held = await client.post(
        f"{url}/decision", json={"action": "quarantine"}, headers=tenant.headers
    )
    assert held.status_code == 200
    assert (await client.delete(url, headers=tenant.headers)).status_code == 409
    await client.post(f"{url}/decision", json={"action": "approve"}, headers=tenant.headers)
    assert (await client.delete(url, headers=tenant.headers)).status_code == 204
    assert await get(client, tenant, "inventory/devices") == []
    other = await sensor_network(client)
    assert (await client.delete(url, headers=other.headers)).status_code == 404


async def test_with_pseudonymised_addresses_discovery_stores_no_real_address_or_name(
    client: httpx.AsyncClient, settings: Settings, monkeypatch: Any
) -> None:
    monkeypatch.setattr(settings, "pseudonymize_ips", True)
    tenant = await sensor_network(client)
    await client.put(
        DISCOVER,
        json={
            "devices": [{"ip": "10.20.0.5", "mac": "00:00:0c:12:34:56", "hostname": "ceo-laptop"}]
        },
        headers=tenant.api_headers,
    )
    (device,) = await get(client, tenant, "inventory/devices")
    assert device["ip"].startswith(("24", "25")) and device["ip"] != "10.20.0.5"
    assert device["hostname"] is None
    assert device["mac"].startswith("00:00:0c:") and device["mac"] != "00:00:0c:12:34:56"
    assert "cisco" in device["vendor"].lower()  # the vendor part is kept: it names no device


async def test_with_pseudonymised_addresses_an_inside_attacker_is_still_a_device(
    client: httpx.AsyncClient,
    redis: Redis,
    sessionmaker: Any,
    settings: Settings,
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(settings, "pseudonymize_ips", True)
    tenant = await sensor_network(client)
    await ingest(client, tenant, flood_flows(6, src="10.20.0.33", dst="203.0.113.5"))
    await drain(redis, sessionmaker, settings)
    (item,) = await get(client, tenant, "inventory/quarantine")
    assert item["kind"] == "device" and item["target"] != "10.20.0.33"
    assert item["target"].startswith(("24", "25"))
    nets = [n["network"] for n in await get(client, tenant, "inventory/networks")]
    assert nets == ["203.0.113.0/24"]  # outside networks are still real addresses
