"""The one-file Windows installer downloaded from the app."""

from __future__ import annotations

import hashlib
from pathlib import Path

import httpx
import pytest
from conftest import Tenant, add_source, register_org

from app.core.config import get_settings
from app.services.ingestion.installer import MARKER, build_windows_installer

URL = "/api/v1/sources/{}/installer"


def sensor_digest() -> str | None:
    script = Path(get_settings().sensor_script_path)
    return hashlib.sha256(script.read_bytes()).hexdigest() if script.exists() else None


async def sensor_source(client: httpx.AsyncClient, cidr: str = "192.168.1.0/24") -> Tenant:
    tenant = await register_org(client)
    await add_source(client, tenant, cidr=cidr, method="sensor", name="Office")
    return tenant


async def test_the_download_is_a_cmd_file_that_carries_a_fresh_key(
    client: httpx.AsyncClient,
) -> None:
    tenant = await sensor_source(client)
    old_key = tenant.source["api_key"]
    resp = await client.post(
        URL.format(tenant.source["id"]), json={"enforce": False}, headers=tenant.headers
    )
    assert resp.status_code == 200, resp.text
    assert 'filename="SentinelBI-sensor-setup.cmd"' in resp.headers["content-disposition"]
    assert resp.headers["cache-control"] == "no-store"
    text = resp.content.decode("utf-8")
    assert (
        text.startswith("@echo off\r\n") and MARKER in text and "\n" not in text.replace("\r\n", "")
    )
    assert "$Network = '192.168.1.0/24'" in text and "$Enforce = $false" in text

    key = next(line for line in text.split("\r\n") if line.startswith("$Key = ")).split("'")[1]
    assert key.startswith("sbi_") and key != old_key
    # the new key works, the old one was replaced
    assert (
        await client.get("/api/v1/sensor/policy", headers={"X-API-Key": key})
    ).status_code == 200
    assert (
        await client.get("/api/v1/sensor/policy", headers={"X-API-Key": old_key})
    ).status_code == 401


async def test_the_installer_pins_the_sensor_checksum_and_can_enable_enforcement(
    client: httpx.AsyncClient,
) -> None:
    tenant = await sensor_source(client)
    resp = await client.post(
        URL.format(tenant.source["id"]), json={"enforce": True}, headers=tenant.headers
    )
    text = resp.content.decode("utf-8")
    assert "$Enforce = $true" in text
    digest = sensor_digest()
    if digest:
        assert f"$ExpectedSha = '{digest}'" in text


async def test_only_a_sensor_source_in_your_own_organisation_has_an_installer(
    client: httpx.AsyncClient,
) -> None:
    tenant = await register_org(client)
    await add_source(client, tenant, cidr="10.20.0.0/24", method="http", name="API only")
    assert (
        await client.post(URL.format(tenant.source["id"]), json={}, headers=tenant.headers)
    ).status_code == 409
    mine, other = await sensor_source(client), await sensor_source(client)
    assert (
        await client.post(URL.format(mine.source["id"]), json={}, headers=other.headers)
    ).status_code == 404


def test_the_script_is_found_after_the_last_marker_not_the_one_in_the_batch_line() -> None:
    data = build_windows_installer(
        api_url="http://127.0.0.1:8000",
        api_key="sbi_abc",
        network="",
        enforce=False,
        sensor_sha256=None,
    ).decode("utf-8")
    assert data.count(MARKER) == 2  # once inside the batch's own command, once as the marker line
    assert "LastIndexOf('#PS-BEGIN')" in data
    script = data[data.rindex(MARKER) + len(MARKER) :]
    assert script.lstrip().startswith("$ErrorActionPreference") and MARKER not in script


def test_values_that_could_break_out_of_the_script_are_refused() -> None:
    good = {
        "api_url": "http://127.0.0.1:8000",
        "api_key": "sbi_abc-DEF_123",
        "network": "10.0.0.0/24",
        "enforce": False,
        "sensor_sha256": "ab" * 32,
    }
    assert build_windows_installer(**good)
    for field, bad in (
        ("api_url", "http://x'; Remove-Item C:\\ -Recurse; '"),
        ("api_key", "sbi_x'; calc; '"),
        ("network", "10.0.0.0/24'; calc"),
    ):
        with pytest.raises(ValueError):
            build_windows_installer(**{**good, field: bad})
