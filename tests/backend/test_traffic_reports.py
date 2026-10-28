"""Registered addresses that have gone quiet, sent/received per peer and service, and the report tables."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from conftest import Tenant, add_source, register_org
from redis.asyncio import Redis
from test_traffic_volume import drain, get, scenario, send

from app.core.config import Settings

PUT = "/api/v1/sensor/addresses"
V6 = "2001:db8:aa::5"


async def laptop_tenant(client: httpx.AsyncClient) -> Tenant:
    """A laptop registered by its address (a sensor), plus a branch PC that never reports."""
    tenant = await register_org(client)
    await add_source(client, tenant, cidr="10.20.0.77", method="http", name="Branch PC")
    await add_source(client, tenant, cidr="10.20.0.5", method="sensor", name="My laptop")
    return tenant


def rows_of(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text)))


async def fetch_csv(client: httpx.AsyncClient, tenant: Tenant, query: str) -> httpx.Response:
    return await client.get(f"/api/v1/reports/traffic.csv?{query}", headers=tenant.headers)


# ------------------------------------------------------------------ registered addresses
async def test_a_registered_address_is_listed_even_when_it_has_no_traffic(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    tenant = await laptop_tenant(client)
    assert await get(client, tenant, "traffic/hosts") == []  # the default list is traffic only

    idle = await get(client, tenant, "traffic/hosts?include_idle=true")
    assert {h["ip"]: h["source_name"] for h in idle} == {
        "10.20.0.5": "My laptop",
        "10.20.0.77": "Branch PC",
    }
    assert all(h["total_bytes"] == 0 and h["flows"] == 0 and h["last_seen"] is None for h in idle)
    assert all(h["source_id"] for h in idle)

    # once the laptop has traffic it moves to the top with its numbers, the quiet one stays listed
    frames, want = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    hosts = await get(client, tenant, "traffic/hosts?include_idle=true")
    assert [h["ip"] for h in hosts][:1] == ["10.20.0.5"] and hosts[-1]["ip"] == "10.20.0.77"
    assert hosts[0]["sent_bytes"] == want["outbound"].client_bytes + 58
    assert hosts[0]["last_seen"] and hosts[0]["source_name"] == "My laptop"
    assert hosts[-1]["total_bytes"] == 0 and hosts[-1]["last_seen"] is None


async def test_announced_addresses_are_listed_under_their_source_even_when_quiet(
    client: httpx.AsyncClient,
) -> None:
    tenant = await laptop_tenant(client)
    told = await client.put(PUT, json={"addresses": [V6]}, headers=tenant.api_headers)
    assert told.status_code == 200
    hosts = {h["ip"]: h for h in await get(client, tenant, "traffic/hosts?include_idle=true")}
    assert set(hosts) == {"10.20.0.5", "10.20.0.77", V6}
    assert hosts[V6]["source_name"] == "My laptop"


async def test_a_full_page_never_reports_a_busy_address_as_idle(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    """With limit=1 the second busy host is cut off; it must not come back as a made-up idle row."""
    tenant = await register_org(client)
    await add_source(client, tenant, cidr="10.20.0.9", method="http", name="Server")
    await add_source(client, tenant, cidr="10.20.0.5", method="sensor", name="My laptop")
    frames, _ = scenario()  # both 10.20.0.5 and 10.20.0.9 move data
    await send(client, tenant, redis, sessionmaker, settings, frames)
    page = await get(client, tenant, "traffic/hosts?include_idle=true&limit=1")
    assert [h["ip"] for h in page] == ["10.20.0.5"]
    both = await get(client, tenant, "traffic/hosts?include_idle=true&limit=2")
    assert {h["ip"] for h in both} == {"10.20.0.5", "10.20.0.9"}
    assert all(h["total_bytes"] > 0 for h in both)


async def test_idle_addresses_can_be_limited_to_one_source_and_never_cross_organisations(
    client: httpx.AsyncClient,
) -> None:
    tenant = await laptop_tenant(client)
    listed = await get(client, tenant, "sources")
    branch = next(s for s in listed if s["name"] == "Branch PC")
    only = await get(client, tenant, f"traffic/hosts?include_idle=true&source_id={branch['id']}")
    assert [h["ip"] for h in only] == ["10.20.0.77"]

    stranger = await register_org(client, "Other Co")
    await add_source(client, stranger, cidr="10.99.0.1", method="http", name="Theirs")
    theirs = await get(client, stranger, "traffic/hosts?include_idle=true")
    assert [h["ip"] for h in theirs] == ["10.99.0.1"]
    wrong = await client.get(
        f"/api/v1/traffic/hosts?include_idle=true&source_id={branch['id']}",
        headers=stranger.headers,
    )
    assert wrong.status_code == 200 and wrong.json() == []  # another organisation's source id


async def test_a_network_range_is_not_expanded_into_idle_rows(
    client: httpx.AsyncClient, tenant: Tenant
) -> None:
    assert await get(client, tenant, "traffic/hosts?include_idle=true") == []  # 10.20.0.0/24


# ------------------------------------------------------------------ sent and received
async def test_peers_and_services_say_what_was_sent_and_what_was_received(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    frames, want = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    d = await get(client, tenant, "traffic/hosts/10.20.0.5?minutes=60")

    out = want["outbound"]
    peers = {p["ip"]: p for p in d["peers"]}
    assert peers["203.0.113.10"]["sent_bytes"] == out.client_bytes
    assert peers["203.0.113.10"]["received_bytes"] == out.server_bytes
    assert peers["9.9.9.9"]["sent_bytes"] == 58 and peers["9.9.9.9"]["received_bytes"] == 118
    services = {s["service"]: s for s in d["services"]}
    assert services["HTTPS (443)"]["sent_bytes"] == out.client_bytes
    assert services["HTTPS (443)"]["received_bytes"] == out.server_bytes
    assert services["DNS (53)"]["received_bytes"] == 118

    for group in (d["peers"], d["services"]):
        for item in group:
            assert item["bytes"] == item["sent_bytes"] + item["received_bytes"]
        assert sum(i["sent_bytes"] for i in group) == d["sent_bytes"]  # nothing is lost or invented
        assert sum(i["received_bytes"] for i in group) == d["received_bytes"]


async def test_a_server_sent_is_what_it_answered_not_what_it_was_asked(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    frames, want = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    d = await get(client, tenant, "traffic/hosts/10.20.0.9?minutes=60")  # served an outsider
    (peer,) = d["peers"]
    assert peer["ip"] == "203.0.113.77"
    assert peer["sent_bytes"] == want["inbound"].server_bytes
    assert peer["received_bytes"] == want["inbound"].client_bytes
    (service,) = d["services"]
    assert service["service"] == "HTTP (alt) (8080)"
    assert service["sent_bytes"] == peer["sent_bytes"]


async def test_the_number_of_peers_and_services_listed_can_be_chosen(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    frames, _ = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    one = await get(client, tenant, "traffic/hosts/10.20.0.5?minutes=60&top=1")
    assert [p["ip"] for p in one["peers"]] == ["203.0.113.10"]  # the biggest
    assert len(one["services"]) == 1 and one["services"][0]["service"] == "HTTPS (443)"
    for bad in (0, 101):
        resp = await client.get(
            f"/api/v1/traffic/hosts/10.20.0.5?top={bad}", headers=tenant.headers
        )
        assert resp.status_code == 422


# ------------------------------------------------------------------ last seen, when the window is empty
async def test_an_empty_window_still_says_when_the_address_was_last_active(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    tenant = await laptop_tenant(client)
    when = datetime.now(UTC) - timedelta(days=2)
    flow = {
        "ts": when.isoformat(),
        "src_ip": "10.20.0.5",
        "dst_ip": "198.51.100.20",
        "src_port": 50000,
        "dst_port": 443,
        "protocol": 6,
        "in_bytes": 100,
        "out_bytes": 900,
        "in_pkts": 2,
        "out_pkts": 3,
        "duration_ms": 50,
    }
    resp = await client.post(
        "/api/v1/ingest/flows", json={"flows": [flow]}, headers=tenant.api_headers
    )
    assert resp.status_code == 202
    assert await drain(redis, sessionmaker, settings) == 1

    day = await get(client, tenant, "traffic/hosts/10.20.0.5?minutes=1440")
    assert day["flows"] == 0 and day["total_bytes"] == 0
    assert abs(datetime.fromisoformat(day["last_seen"]) - when) < timedelta(seconds=1)  # 2 days ago
    week = await get(client, tenant, "traffic/hosts/10.20.0.5?minutes=10080")
    assert week["flows"] == 1 and week["sent_bytes"] == 100 and week["received_bytes"] == 900
    assert week["last_seen"] == day["last_seen"]
    # an address that never appeared has nothing to report, and another organisation sees nothing
    assert (await get(client, tenant, "traffic/hosts/10.20.0.77"))["last_seen"] is None
    stranger = await register_org(client, "Other Co")
    assert (await get(client, stranger, "traffic/hosts/10.20.0.5"))["last_seen"] is None


# ------------------------------------------------------------------ the report tables
async def test_the_summary_table_lists_quiet_registered_addresses_with_zeros(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    tenant = await laptop_tenant(client)
    frames, want = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    resp = await fetch_csv(client, tenant, "hours=24")
    assert (
        resp.status_code == 200 and "sentinelbi-traffic.csv" in resp.headers["content-disposition"]
    )
    assert resp.text.splitlines()[0] == "ip,sent_bytes,received_bytes,total_bytes,flows,last_seen"
    rows = {r["ip"]: r for r in rows_of(resp.text)}
    assert int(rows["10.20.0.5"]["sent_bytes"]) == want["outbound"].client_bytes + 58
    assert rows["10.20.0.77"]["total_bytes"] == "0" and rows["10.20.0.77"]["last_seen"] == ""


async def test_a_report_can_be_limited_to_chosen_addresses(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    tenant = await laptop_tenant(client)
    frames, _ = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    one = rows_of((await fetch_csv(client, tenant, "hours=24&ip=10.20.0.77")).text)
    assert [r["ip"] for r in one] == ["10.20.0.77"]
    both = rows_of((await fetch_csv(client, tenant, "hours=24&ip=10.20.0.5&ip=10.20.0.77")).text)
    assert {r["ip"] for r in both} == {"10.20.0.5", "10.20.0.77"}

    # 10.20.0.9 also moved data, but it is not inside any registered source: it is not a monitored
    # host, so the summary table leaves it out, while an address asked for by name still gets its
    # detailed tables
    summary = rows_of((await fetch_csv(client, tenant, "hours=24&ip=10.20.0.9")).text)
    assert summary == []
    detail = rows_of((await fetch_csv(client, tenant, "hours=24&section=peers&ip=10.20.0.9")).text)
    assert {r["host"] for r in detail} == {"10.20.0.9"}


async def test_peer_service_and_timeline_tables_add_up_to_the_host_totals(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    frames, _ = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    d = await get(client, tenant, "traffic/hosts/10.20.0.5?minutes=1440")

    peers = await fetch_csv(client, tenant, "hours=24&section=peers&ip=10.20.0.5")
    assert "sentinelbi-traffic-peers.csv" in peers.headers["content-disposition"]
    assert peers.text.splitlines()[0] == "host,peer,sent_bytes,received_bytes,total_bytes,flows"
    prows = rows_of(peers.text)
    assert {r["peer"] for r in prows} == {"203.0.113.10", "9.9.9.9"}
    assert sum(int(r["sent_bytes"]) for r in prows) == d["sent_bytes"]
    assert sum(int(r["received_bytes"]) for r in prows) == d["received_bytes"]
    assert all(
        int(r["total_bytes"]) == int(r["sent_bytes"]) + int(r["received_bytes"]) for r in prows
    )

    services = await fetch_csv(client, tenant, "hours=24&section=services&ip=10.20.0.5")
    assert services.text.splitlines()[0] == (
        "host,service,protocol,sent_bytes,received_bytes,total_bytes,flows"
    )
    srows = rows_of(services.text)
    assert {(r["service"], r["protocol"]) for r in srows} == {
        ("HTTPS (443)", "TCP"),
        ("DNS (53)", "UDP"),
    }
    assert sum(int(r["sent_bytes"]) for r in srows) == d["sent_bytes"]

    timeline = await fetch_csv(client, tenant, "hours=24&section=timeline&ip=10.20.0.5")
    assert timeline.text.splitlines()[0] == "host,time,sent_bytes,received_bytes,flows"
    trows = rows_of(timeline.text)
    assert sum(int(r["sent_bytes"]) for r in trows) == d["sent_bytes"]
    assert sum(int(r["received_bytes"]) for r in trows) == d["received_bytes"]
    assert sum(int(r["flows"]) for r in trows) == d["flows"]


async def test_without_a_chosen_address_the_detailed_tables_cover_the_busiest_hosts(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    frames, _ = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    prows = rows_of((await fetch_csv(client, tenant, "section=peers")).text)
    assert {r["host"] for r in prows} == {"10.20.0.5", "10.20.0.9"}


async def test_report_requests_are_checked_and_isolated(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    frames, _ = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    for bad in (
        "ip=nope",
        "ip=10.20.0.5&ip=1.2.3.999",
        "section=everything",
        "hours=0",
        "hours=721",
    ):
        assert (await fetch_csv(client, tenant, bad)).status_code == 422, bad
    too_many = "&".join(f"ip=10.20.0.{n}" for n in range(1, 22))
    assert (await fetch_csv(client, tenant, too_many)).status_code == 422
    assert (await client.get("/api/v1/reports/traffic.csv")).status_code == 401

    stranger = await register_org(client, "Other Co")
    await add_source(client, stranger)  # the same address range, another organisation
    for section in ("peers", "services", "timeline"):
        text = (await fetch_csv(client, stranger, f"section={section}&ip=10.20.0.5")).text
        body = rows_of(text)
        # nothing of the first organisation: a timeline is all zeros, the other tables are empty
        assert all(int(r.get("sent_bytes", 0)) == 0 for r in body), section
        if section != "timeline":
            assert body == []


def test_traffic_tables_are_defined_for_every_section() -> None:
    from app.services.reports import TRAFFIC_SECTIONS, traffic_section_csv, traffic_section_rows

    assert set(TRAFFIC_SECTIONS) == {"hosts", "peers", "services", "timeline"}
    assert traffic_section_rows("peers", []) == []
    assert traffic_section_csv("peers", []).splitlines() == [",".join(TRAFFIC_SECTIONS["peers"])]
    sample = {
        "ip": "10.0.0.5",
        "points": [{"t": "2026-10-28T10:00:00+00:00", "sent": 5, "received": 9, "flows": 2}],
        "peers": [],
        "services": [],
    }
    (row,) = traffic_section_rows("timeline", [sample])
    assert row == {
        "host": "10.0.0.5",
        "time": "2026-10-28T10:00:00+00:00",
        "sent_bytes": 5,
        "received_bytes": 9,
        "flows": 2,
    }
