"""Settings changed from the web interface: who may, what is checked, and that it takes effect."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from conftest import PASSWORD, Tenant, register_org, unique_email
from sqlalchemy import text

from app.core.config import Settings
from app.services.runtime_settings import effective_settings


@pytest.fixture
async def admin(client: httpx.AsyncClient, settings: Settings) -> AsyncIterator[Tenant]:
    t = await register_org(client)
    settings.platform_admin_emails = t.email
    try:
        yield t
    finally:
        settings.platform_admin_emails = ""
        async with __import__("app.db.session", fromlist=["x"]).get_sessionmaker()() as s:
            await s.execute(text("DELETE FROM app_settings"))
            await s.commit()


async def test_everyone_can_read_but_only_platform_admins_can_edit(
    client: httpx.AsyncClient, settings: Settings
) -> None:
    t = await register_org(client)
    body = (await client.get("/api/v1/settings", headers=t.headers)).json()
    assert body["can_edit"] is False
    keys = {i["key"] for i in body["items"]}
    assert {"alert_min_flows", "retention_days", "allow_registration"} <= keys
    assert "secret_key" not in keys
    denied = await client.put(
        "/api/v1/settings", json={"values": {"alert_min_flows": 3}}, headers=t.headers
    )
    assert denied.status_code == 403


async def test_edit_takes_effect_and_can_be_reset(client: httpx.AsyncClient, admin: Tenant) -> None:
    r = await client.put(
        "/api/v1/settings",
        json={"values": {"alert_min_flows": 3, "auto_quarantine": False}},
        headers=admin.headers,
    )
    assert r.status_code == 200, r.text
    items = {i["key"]: i for i in r.json()["items"]}
    assert items["alert_min_flows"]["value"] == 3 and items["alert_min_flows"]["overridden"]
    assert r.json()["can_edit"] is True
    from app.db.session import get_sessionmaker

    async with get_sessionmaker()() as s:
        eff = await effective_settings(s)
    assert eff.alert_min_flows == 3 and eff.auto_quarantine is False
    reset = await client.delete("/api/v1/settings/alert_min_flows", headers=admin.headers)
    items = {i["key"]: i for i in reset.json()["items"]}
    assert not items["alert_min_flows"]["overridden"]


@pytest.mark.parametrize(
    "values",
    [
        {"alert_min_probability": 0.2},
        {"alert_min_flows": 2.5},
        {"alert_min_flows": True},
        {"quarantine_min_severity": "Severe"},
        {"retention_days": 0},
        {"platform_admin_emails": "not-an-email"},
        {"secret_key": "x"},
    ],
)
async def test_bad_values_are_refused(
    client: httpx.AsyncClient, admin: Tenant, values: dict[str, object]
) -> None:
    r = await client.put("/api/v1/settings", json={"values": values}, headers=admin.headers)
    assert r.status_code == 422, r.text


async def test_registration_can_be_switched_off_from_the_interface(
    client: httpx.AsyncClient, admin: Tenant
) -> None:
    await client.put(
        "/api/v1/settings", json={"values": {"allow_registration": False}}, headers=admin.headers
    )
    r = await client.post(
        "/api/v1/auth/register",
        json={"org_name": "Blocked Org", "email": unique_email(), "password": PASSWORD},
    )
    assert r.status_code == 403


async def test_retention_policy_is_changed_in_the_database(
    client: httpx.AsyncClient, admin: Tenant
) -> None:
    r = await client.put(
        "/api/v1/settings", json={"values": {"retention_days": 14}}, headers=admin.headers
    )
    assert r.status_code == 200, r.text
    from app.db.session import get_sessionmaker

    async with get_sessionmaker()() as s:
        days = (
            await s.execute(
                text(
                    "SELECT config->>'drop_after' FROM timescaledb_information.jobs "
                    "WHERE proc_name = 'policy_retention' AND hypertable_name = 'flows'"
                )
            )
        ).scalar()
    assert days is not None and days.startswith("14 days")
    await client.delete("/api/v1/settings/retention_days", headers=admin.headers)


async def test_added_platform_admin_may_edit(client: httpx.AsyncClient, admin: Tenant) -> None:
    other = await register_org(client, "Other")
    r = await client.put(
        "/api/v1/settings",
        json={"values": {"platform_admin_emails": other.email}},
        headers=admin.headers,
    )
    assert r.status_code == 200
    ok = await client.put(
        "/api/v1/settings", json={"values": {"alert_min_flows": 4}}, headers=other.headers
    )
    assert ok.status_code == 200


async def test_health_reports_database_queue_and_schema(
    client: httpx.AsyncClient, admin: Tenant
) -> None:
    h = (await client.get("/api/v1/settings/health", headers=admin.headers)).json()
    assert h["database"]["ok"] and h["queue"]["ok"]
    assert h["schema_version"] == "0009"
