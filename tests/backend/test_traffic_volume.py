"""Data volume per monitored host: sensor -> ingest -> worker -> traffic API, byte for byte."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import httpx
from conftest import Tenant, add_source, register_org
from redis.asyncio import Redis

import sensorkit as kit
import sentinelbi_sensor as sensor
from app.core.config import Settings
from app.services.analytics import format_bytes, service_label
from app.services.inference.placeholder import PlaceholderPredictor
from app.services.reports import traffic_csv
from app.workers.stream_consumer import consume_once, ensure_group

REPO = Path(__file__).resolve().parents[2]
NOW = 1_800_000_000.0  # flows are stamped "now" by the server when the sensor says so; see send()


async def drain(redis: Redis, sessionmaker: Any, settings: Settings) -> int:
    await ensure_group(redis, settings)
    total = 0
    while n := await consume_once(
        redis, sessionmaker, PlaceholderPredictor(), settings, "test-consumer", block_ms=50
    ):
        total += n
    return total


def records_from(frames: list[kit.Frame]) -> list[dict[str, Any]]:
    """What the real sensor would report for these packets, with timestamps moved to the present."""
    import time

    table = sensor.FlowTable()
    shift = time.time() - frames[-1][0] - 5
    for ts, data in sorted(frames):
        pkt = sensor.parse_ethernet(data, ts + shift)
        assert pkt is not None
        table.add(pkt)
    return table.expire(time.time() + 1000)


async def send(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    sessionmaker: Any,
    settings: Settings,
    frames: list[kit.Frame],
) -> list[dict[str, Any]]:
    recs = records_from(frames)
    resp = await client.post(
        "/api/v1/ingest/flows", json={"flows": recs}, headers=tenant.api_headers
    )
    assert resp.status_code == 202, resp.text
    assert await drain(redis, sessionmaker, settings) == len(recs)
    return recs


async def get(client: httpx.AsyncClient, tenant: Tenant, path: str) -> Any:
    resp = await client.get(f"/api/v1/{path}", headers=tenant.headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def scenario() -> tuple[list[kit.Frame], dict[str, kit.Totals]]:
    """Host 10.20.0.5 (monitored) uploads and downloads; 10.20.0.9 (monitored) serves an outsider;
    both talk to an outside server on 443 and one of them also does DNS."""
    out, up_down = kit.tcp_session(
        "10.20.0.5", "203.0.113.10", 51000, 443, NOW, up=2000, down=50_000
    )
    inbound, served = kit.tcp_session(
        "203.0.113.77", "10.20.0.9", 40000, 8080, NOW + 1, up=700, down=9000
    )
    dns = [
        (
            NOW + 2,
            kit.ether(kit.ipv4_packet("10.20.0.5", "9.9.9.9", 17, kit.udp_datagram(40001, 53, 30))),
        ),
        (
            NOW + 2.02,
            kit.ether(kit.ipv4_packet("9.9.9.9", "10.20.0.5", 17, kit.udp_datagram(53, 40001, 90))),
        ),
    ]
    return out + inbound + dns, {"outbound": up_down, "inbound": served}


async def test_sent_and_received_are_counted_from_each_hosts_own_point_of_view(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    frames, want = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    hosts = {h["ip"]: h for h in await get(client, tenant, "traffic/hosts?minutes=1440")}

    assert set(hosts) == {"10.20.0.5", "10.20.0.9"}  # 203.0.113.x and 9.9.9.9 are not monitored
    a, b = hosts["10.20.0.5"], hosts["10.20.0.9"]
    dns_sent, dns_received = 20 + 8 + 30, 20 + 8 + 90
    # 10.20.0.5 was the client of the big transfer and of a DNS lookup
    assert a["sent_bytes"] == want["outbound"].client_bytes + dns_sent
    assert a["received_bytes"] == want["outbound"].server_bytes + dns_received
    # 10.20.0.9 was the SERVER of an inbound connection: its sent bytes are the flow's out_bytes
    assert b["sent_bytes"] == want["inbound"].server_bytes
    assert b["received_bytes"] == want["inbound"].client_bytes
    assert a["total_bytes"] == a["sent_bytes"] + a["received_bytes"]
    assert a["flows"] == 2 and b["flows"] == 1
    biggest_first = await get(client, tenant, "traffic/hosts")
    assert biggest_first[0]["ip"] == "10.20.0.5"


async def test_the_summary_adds_up(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    frames, _ = scenario()
    recs = await send(client, tenant, redis, sessionmaker, settings, frames)
    s = await get(client, tenant, "traffic/summary")
    assert s["flows"] == len(recs) == 3
    assert s["total_bytes"] == sum(r["in_bytes"] + r["out_bytes"] for r in recs)
    assert s["monitored_hosts"] == 2
    hosts = await get(client, tenant, "traffic/hosts")
    assert s["monitored_sent_bytes"] == sum(h["sent_bytes"] for h in hosts)
    assert s["monitored_received_bytes"] == sum(h["received_bytes"] for h in hosts)


async def test_one_host_in_detail(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    frames, want = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    d = await get(client, tenant, "traffic/hosts/10.20.0.5?minutes=60")
    hosts = {h["ip"]: h for h in await get(client, tenant, "traffic/hosts")}
    assert d["sent_bytes"] == hosts["10.20.0.5"]["sent_bytes"]
    assert d["received_bytes"] == hosts["10.20.0.5"]["received_bytes"]
    assert d["total_bytes"] == d["sent_bytes"] + d["received_bytes"] and d["flows"] == 2
    assert sum(p["sent"] for p in d["points"]) == d["sent_bytes"]  # the chart adds up to the totals
    assert [p["t"] for p in d["points"]] == sorted(p["t"] for p in d["points"])
    peers = {p["ip"]: p["bytes"] for p in d["peers"]}
    assert set(peers) == {"203.0.113.10", "9.9.9.9"}
    assert peers["203.0.113.10"] == want["outbound"].client_bytes + want["outbound"].server_bytes
    assert {s["service"] for s in d["services"]} == {"HTTPS (443)", "DNS (53)"}


async def test_unknown_or_invalid_hosts(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    quiet = await get(client, tenant, "traffic/hosts/10.20.0.77")  # monitored range, nothing seen
    assert quiet["total_bytes"] == 0 and quiet["peers"] == [] and quiet["services"] == []
    bad = await client.get("/api/v1/traffic/hosts/not-an-ip", headers=tenant.headers)
    assert bad.status_code == 422
    v6 = await get(client, tenant, "traffic/hosts/2001:db8::5")
    assert v6["ip"] == "2001:db8::5"


async def test_other_organisations_see_nothing(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    frames, _ = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    stranger = await register_org(client, "Other Co")
    await add_source(client, stranger)  # the same address range, but another organisation
    assert await get(client, stranger, "traffic/hosts") == []
    assert (await get(client, stranger, "traffic/summary"))["total_bytes"] == 0
    assert (await get(client, stranger, "traffic/hosts/10.20.0.5"))["total_bytes"] == 0


async def test_hosts_can_be_limited_to_one_source(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    frames, _ = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    first = tenant.source["id"]
    other = await client.post(
        "/api/v1/sources",
        json={"name": "Branch", "cidr": "10.30.0.0/24", "method": "http"},
        headers=tenant.headers,
    )
    assert other.status_code == 201
    only_first = await get(client, tenant, f"traffic/hosts?source_id={first}")
    only_other = await get(client, tenant, f"traffic/hosts?source_id={other.json()['id']}")
    assert {h["ip"] for h in only_first} == {"10.20.0.5", "10.20.0.9"} and only_other == []


async def test_reports_include_the_data_volume(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    frames, want = scenario()
    await send(client, tenant, redis, sessionmaker, settings, frames)
    resp = await client.get("/api/v1/reports/traffic.csv?hours=24", headers=tenant.headers)
    assert resp.status_code == 200 and "attachment" in resp.headers["content-disposition"]
    lines = resp.text.splitlines()
    assert lines[0] == "ip,sent_bytes,received_bytes,total_bytes,flows,last_seen"
    first = lines[1].split(",")
    assert first[0] == "10.20.0.5" and int(first[1]) == want["outbound"].client_bytes + 58
    pdf = await client.get("/api/v1/reports/summary.pdf", headers=tenant.headers)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")


def test_csv_and_size_helpers() -> None:
    row = {
        "ip": "10.0.0.1",
        "sent_bytes": 1,
        "received_bytes": 2,
        "total_bytes": 3,
        "flows": 1,
        "last_seen": "t",
    }
    assert traffic_csv([row]).splitlines() == [
        "ip,sent_bytes,received_bytes,total_bytes,flows,last_seen",
        "10.0.0.1,1,2,3,1,t",
    ]
    assert [format_bytes(n) for n in (0, 999, 1000, 1_500_000, 2_300_000_000, 4_100_000_000_000)] == [
        "0 B", "999 B", "1.0 kB", "1.5 MB", "2.3 GB", "4.1 TB",
    ]  # fmt: skip
    assert service_label(443, 6) == "HTTPS (443)" and service_label(40000, 6) == "port 40000"
    assert service_label(2048, 1) == "ICMP" and service_label(0, 6) == "other"


# ---------------------------------------------------------------------------- the sensor script
async def test_the_sensor_script_is_served_with_its_hash(
    client: httpx.AsyncClient, settings: Settings, monkeypatch: Any
) -> None:
    path = REPO / "sensor" / "sentinelbi_sensor.py"
    monkeypatch.setattr(settings, "sensor_script_path", str(path))
    resp = await client.get("/api/v1/sensor/sentinelbi_sensor.py")  # no sign-in: it is just code
    assert resp.status_code == 200 and resp.content == path.read_bytes()
    assert resp.headers["x-content-sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert "attachment" in resp.headers["content-disposition"]
    monkeypatch.setattr(settings, "sensor_script_path", str(REPO / "sensor" / "missing.py"))
    assert (await client.get("/api/v1/sensor/sentinelbi_sensor.py")).status_code == 404


async def test_registering_a_sensor_source_returns_real_commands(
    client: httpx.AsyncClient, settings: Settings, monkeypatch: Any
) -> None:
    path = REPO / "sensor" / "sentinelbi_sensor.py"
    monkeypatch.setattr(settings, "sensor_script_path", str(path))
    t = await register_org(client)
    resp = await client.post(
        "/api/v1/sources",
        json={"name": "My PC", "cidr": "10.181.2.111", "method": "sensor"},
        headers=t.headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["cidr"] == "10.181.2.111"  # a single host is shown without "/32", as when read back
    snippets = {s["id"]: s["content"] for s in body["setup"]["snippets"]}
    assert snippets["sensor-linux"].rstrip().endswith("--ip 10.181.2.111")
    assert set(snippets) == {
        "sensor-windows",
        "sensor-service",
        "sensor-linux",
        "sensor-docker",
        "sensor-demo",
    }
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    for name, text in snippets.items():
        assert (body["api_key"] in text and "10.181.2.111" in text) or name == "sensor-demo"
    assert digest in snippets["sensor-windows"] and digest in snippets["sensor-linux"]
    assert "--self-test" in snippets["sensor-linux"]
    assert "--cap-add=NET_RAW" in snippets["sensor-docker"]
    assert "--map-ip 10.20.0.5=10.181.2.111" in snippets["sensor-demo"]
    # the HTTP and NetFlow methods are unchanged
    http_src = await client.post(
        "/api/v1/sources",
        json={"name": "API", "cidr": "10.0.0.0/24", "method": "http"},
        headers=t.headers,
    )
    assert {s["id"] for s in http_src.json()["setup"]["snippets"]} == {"curl", "replay"}
