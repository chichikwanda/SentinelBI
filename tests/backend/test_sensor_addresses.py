"""A sensor reports the other addresses of its machine (its IPv6 addresses), and the traffic views then
count them as the same monitored host."""

from __future__ import annotations

from typing import Any

import httpx
from conftest import Tenant, add_source, register_org
from redis.asyncio import Redis
from test_traffic_volume import NOW, get, send

import sensorkit as kit
from app.core.config import Settings

V6_SELF = "2001:db8:aa::5"
V6_SERVER = "2001:db8:bb::1"
PUT = "/api/v1/sensor/addresses"


def v6_exchange(self_ip: str = V6_SELF) -> list[kit.Frame]:
    """This machine opens a connection to a server: 2 packets out, 2 back, IPv6 headers (40 bytes)."""
    up = kit.tcp_segment(51000, 443, payload=300)
    down = kit.tcp_segment(443, 51000, payload=4000)
    return [
        (NOW, kit.ether(kit.ipv6_packet(self_ip, V6_SERVER, 6, up), ethertype=0x86DD)),
        (NOW + 0.01, kit.ether(kit.ipv6_packet(V6_SERVER, self_ip, 6, down), ethertype=0x86DD)),
    ]


async def sensor_tenant(client: httpx.AsyncClient) -> Tenant:
    tenant = await register_org(client)
    await add_source(client, tenant, cidr="10.20.0.5", method="sensor", name="My laptop")
    return tenant


async def test_announced_addresses_are_counted_as_the_same_monitored_host(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    tenant = await sensor_tenant(client)
    v4_out, _ = kit.tcp_session("10.20.0.5", "203.0.113.10", 50000, 443, NOW, up=100, down=200)
    await send(client, tenant, redis, sessionmaker, settings, v4_out + v6_exchange())

    # before the sensor says the IPv6 address is its own, only the registered IPv4 address counts
    assert {h["ip"] for h in await get(client, tenant, "traffic/hosts")} == {"10.20.0.5"}

    resp = await client.put(PUT, json={"addresses": [V6_SELF]}, headers=tenant.api_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"cidr": "10.20.0.5", "addresses": [V6_SELF]}

    hosts = {h["ip"]: h for h in await get(client, tenant, "traffic/hosts")}
    assert set(hosts) == {"10.20.0.5", V6_SELF}
    assert hosts[V6_SELF]["sent_bytes"] == 40 + 20 + 300  # IPv6 header + TCP header + payload
    assert hosts[V6_SELF]["received_bytes"] == 40 + 20 + 4000
    summary = await get(client, tenant, "traffic/summary")
    assert summary["monitored_hosts"] == 2
    detail = await get(client, tenant, f"traffic/hosts/{V6_SELF}")
    assert detail["total_bytes"] == 360 + 4060 and {p["ip"] for p in detail["peers"]} == {V6_SERVER}


async def test_the_source_lists_what_was_announced(
    client: httpx.AsyncClient,
) -> None:
    tenant = await sensor_tenant(client)
    assert (await get(client, tenant, "sources"))[0]["extra_cidrs"] == []
    await client.put(
        PUT, json={"addresses": [V6_SELF, "2001:db8:aa::6"]}, headers=tenant.api_headers
    )
    listed = (await get(client, tenant, "sources"))[0]
    assert listed["cidr"] == "10.20.0.5"
    assert listed["extra_cidrs"] == [
        V6_SELF,
        "2001:db8:aa::6",
    ]  # a single host is shown without /128


async def test_announcing_again_adds_new_addresses_and_ignores_known_ones(
    client: httpx.AsyncClient,
) -> None:
    tenant = await sensor_tenant(client)
    await client.put(PUT, json={"addresses": [V6_SELF]}, headers=tenant.api_headers)
    resp = await client.put(
        PUT,
        # the first is known, the second is the registered IPv4 address itself, the third is new
        json={"addresses": [V6_SELF.upper(), "10.20.0.5", "2001:db8:aa::7"]},
        headers=tenant.api_headers,
    )
    assert resp.json()["addresses"] == [V6_SELF, "2001:db8:aa::7"]


async def test_only_the_newest_addresses_are_kept_because_privacy_addresses_rotate(
    client: httpx.AsyncClient,
) -> None:
    from app.schemas.sources import MAX_EXTRA_CIDRS

    tenant = await sensor_tenant(client)
    sent = [f"2001:db8:aa::{n:x}" for n in range(1, 101)]  # 100 addresses over five requests
    for start in range(0, len(sent), 20):
        resp = await client.put(
            PUT, json={"addresses": sent[start : start + 20]}, headers=tenant.api_headers
        )
        assert resp.status_code == 200
    assert resp.json()["addresses"] == sent[-MAX_EXTRA_CIDRS:]  # the oldest were dropped


async def test_addresses_that_cannot_belong_to_a_host_are_refused(
    client: httpx.AsyncClient,
) -> None:
    tenant = await sensor_tenant(client)
    unspecified = "0.0.0.0"  # noqa: S104 - an address the server must refuse, not one we bind to
    for bad in (
        "fe80::1",
        "::1",
        "127.0.0.1",
        "ff02::1",
        unspecified,
        "not-an-ip",
        "2001:db8::/64",
    ):
        resp = await client.put(PUT, json={"addresses": [bad]}, headers=tenant.api_headers)
        assert resp.status_code == 422, bad
    too_many = [f"2001:db8:aa::{n + 1:x}" for n in range(33)]
    assert (
        await client.put(PUT, json={"addresses": too_many}, headers=tenant.api_headers)
    ).status_code == 422
    # a zone id on an otherwise fine address is dropped, not stored
    ok = await client.put(
        PUT, json={"addresses": ["2001:db8:aa::9%12"]}, headers=tenant.api_headers
    )
    assert ok.json()["addresses"] == ["2001:db8:aa::9"]


async def test_only_a_sensor_source_with_its_own_key_can_announce(
    client: httpx.AsyncClient,
) -> None:
    tenant = await sensor_tenant(client)
    body = {"addresses": [V6_SELF]}
    assert (await client.put(PUT, json=body)).status_code == 401
    assert (await client.put(PUT, json=body, headers={"X-API-Key": "sbi_nope"})).status_code == 401
    assert (
        await client.put(PUT, json=body, headers=tenant.headers)
    ).status_code == 401  # a JWT is no key
    router = await register_org(client, "Router Co")
    await add_source(client, router, cidr="10.30.0.0/24", method="http")
    other = await client.put(PUT, json=body, headers=router.api_headers)
    assert other.status_code == 409  # only a sensor reports the addresses of its own machine


async def test_another_organisation_does_not_gain_or_lose_anything(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    tenant = await sensor_tenant(client)
    await client.put(PUT, json={"addresses": [V6_SELF]}, headers=tenant.api_headers)
    stranger = await sensor_tenant(client)  # the same registered address, another organisation
    await send(client, stranger, redis, sessionmaker, settings, v6_exchange())
    assert (
        await get(client, stranger, "traffic/hosts") == []
    )  # V6_SELF was announced by the first only
    assert (await get(client, stranger, "sources"))[0]["extra_cidrs"] == []
