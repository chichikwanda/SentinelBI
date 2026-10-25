from __future__ import annotations

import hashlib

import httpx
import pytest
from conftest import PASSWORD, Tenant, add_source, register_org, unique_email
from sqlalchemy import text

from app.core.config import Settings


async def test_create_source_returns_key_once_and_stores_only_the_hash(
    client: httpx.AsyncClient, sessionmaker, settings: Settings
) -> None:
    t = await register_org(client)
    src = await add_source(client, t, cidr="10.20.0.0/24", method="http")

    key = src["api_key"]
    assert key.startswith("sbi_") and len(key) > 30
    assert src["status"] == "pending"
    assert src["cidr"] == "10.20.0.0/24"
    assert src["setup"]["collector_port"] == settings.collector_public_port
    curl = next(s for s in src["setup"]["snippets"] if s["id"] == "curl")
    assert key in curl["content"] and "/api/v1/ingest/flows" in curl["content"]

    async with sessionmaker() as s:
        stored = (
            await s.execute(
                text("SELECT api_key_hash FROM sources WHERE id = :i"), {"i": src["id"]}
            )
        ).scalar_one()
    assert stored == hashlib.sha256(key.encode()).hexdigest()
    assert key not in stored

    listed = await client.get("/api/v1/sources", headers=t.headers)
    assert listed.status_code == 200
    assert "api_key" not in listed.json()[0]  # never returned again
    assert "api_key_hash" not in listed.json()[0]


async def test_netflow_source_gets_router_snippets_with_collector_address(
    client: httpx.AsyncClient, settings: Settings
) -> None:
    t = await register_org(client)
    src = await add_source(client, t, cidr="203.0.113.10", method="netflow")
    by_id = {s["id"]: s["content"] for s in src["setup"]["snippets"]}
    assert {"mikrotik", "pfsense", "cisco"} <= set(by_id)
    assert (
        f"dst-address={settings.collector_public_host} port={settings.collector_public_port}"
        in by_id["mikrotik"]
    )
    assert src["cidr"] == "203.0.113.10"  # a bare IP stays a plain host address (no "/32")


async def test_single_host_source_creates_an_asset(client: httpx.AsyncClient, sessionmaker) -> None:
    t = await register_org(client)
    src = await add_source(client, t, cidr="203.0.113.10", method="netflow", criticality=3)
    async with sessionmaker() as s:
        rows = (
            await s.execute(
                text("SELECT host(ip), criticality, org_id::text FROM assets WHERE source_id = :i"),
                {"i": src["id"]},
            )
        ).all()
    assert rows == [("203.0.113.10", 3, t.org_id)]


@pytest.mark.parametrize(
    ("cidr", "method", "expected"),
    [
        ("not-an-ip", "http", 422),
        ("10.0.0.0/8", "http", 422),  # too broad
        ("0.0.0.0/0", "http", 422),
        ("10.0.0.0/24", "scan", 422),  # active scanning disabled (ADR-006)
        ("10.0.0.0/24", "syslog", 422),  # not implemented yet
        ("10.0.0.0/24", "carrier-pigeon", 422),
    ],
)
async def test_source_validation(
    client: httpx.AsyncClient, cidr: str, method: str, expected: int
) -> None:
    t = await register_org(client)
    resp = await client.post(
        "/api/v1/sources", json={"name": "HQ", "cidr": cidr, "method": method}, headers=t.headers
    )
    assert resp.status_code == expected


async def test_health_starts_waiting(client: httpx.AsyncClient, tenant: Tenant) -> None:
    resp = await client.get(f"/api/v1/sources/{tenant.source['id']}/health", headers=tenant.headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["state"] == "waiting"
    assert body["first_flows_received"] is False
    assert body["flows_total"] == 0


async def test_only_an_administrator_can_remove_a_source_and_only_in_their_own_organisation(
    client: httpx.AsyncClient,
) -> None:
    admin = await register_org(client)
    src = await add_source(client, admin)
    analyst = unique_email("analyst")
    created = await client.post(
        "/api/v1/users",
        json={"email": analyst, "password": PASSWORD, "role": "analyst"},
        headers=admin.headers,
    )
    assert created.status_code == 201
    login = await client.post("/api/v1/auth/login", json={"email": analyst, "password": PASSWORD})
    analyst_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    stranger = await register_org(client, "Other Co")

    url = f"/api/v1/sources/{src['id']}"
    assert (await client.delete(url, headers=analyst_headers)).status_code == 403  # not an admin
    assert (
        await client.delete(url, headers=stranger.headers)
    ).status_code == 404  # not theirs: no leak
    assert (await client.delete(url)).status_code == 401  # not signed in
    assert (
        len((await client.get("/api/v1/sources", headers=admin.headers)).json()) == 1
    )  # untouched
    assert (await client.delete(url, headers=admin.headers)).status_code == 204
    assert (await client.delete(url, headers=admin.headers)).status_code == 404  # already gone
