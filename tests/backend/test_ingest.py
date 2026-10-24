from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
from conftest import Tenant
from redis.asyncio import Redis

from app.core.config import Settings
from app.core.redis import get_redis
from app.main import app


async def test_valid_batch_is_accepted_and_queued_for_the_right_tenant(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    settings: Settings,
    flow_factory: Callable[..., dict[str, Any]],
) -> None:
    resp = await client.post(
        "/api/v1/ingest/flows",
        json={"flows": [flow_factory(), flow_factory(dst_port=80)]},
        headers=tenant.api_headers,
    )
    assert resp.status_code == 202
    assert resp.json() == {"accepted": 2}

    entries = await redis.xrange(settings.stream_flows)
    assert len(entries) == 2
    _id, fields = entries[0]
    assert fields["org"] == tenant.org_id
    assert fields["src"] == tenant.source["id"]
    record = json.loads(fields["data"])
    assert record["dst_ip"] == "198.51.100.20"
    assert record["ts"]  # ingest time is stamped when the client sends none


async def test_missing_or_invalid_api_key_is_rejected(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    settings: Settings,
    flow_factory: Callable[..., dict[str, Any]],
) -> None:
    body = {"flows": [flow_factory()]}
    assert (await client.post("/api/v1/ingest/flows", json=body)).status_code == 401
    bad = await client.post("/api/v1/ingest/flows", json=body, headers={"X-API-Key": "sbi_nope"})
    assert bad.status_code == 401
    # a user JWT is not an API key
    jwt_only = await client.post("/api/v1/ingest/flows", json=body, headers=tenant.headers)
    assert jwt_only.status_code == 401
    assert await redis.xlen(settings.stream_flows) == 0


async def test_payload_validation(
    client: httpx.AsyncClient, tenant: Tenant, flow_factory: Callable[..., dict[str, Any]]
) -> None:

    def post(flows: list[dict[str, Any]]) -> Any:
        return client.post(
            "/api/v1/ingest/flows", json={"flows": flows}, headers=tenant.api_headers
        )

    assert (await post([])).status_code == 422
    assert (await post([flow_factory(src_ip="999.1.1.1")])).status_code == 422
    assert (await post([flow_factory(dst_port=70000)])).status_code == 422
    assert (await post([flow_factory(in_bytes=-1)])).status_code == 422
    # no payload capture by design: unknown fields are refused, not stored
    assert (await post([flow_factory(payload="GET /secret")])).status_code == 422


async def test_oversized_batch_is_rejected(
    client: httpx.AsyncClient,
    tenant: Tenant,
    settings: Settings,
    monkeypatch,
    flow_factory: Callable[..., dict[str, Any]],  # type: ignore[no-untyped-def]
) -> None:
    monkeypatch.setattr(settings, "max_batch_flows", 3)
    resp = await client.post(
        "/api/v1/ingest/flows",
        json={"flows": [flow_factory() for _ in range(4)]},
        headers=tenant.api_headers,
    )
    assert resp.status_code == 413


async def test_queue_outage_returns_503_with_retry_after(
    client: httpx.AsyncClient, tenant: Tenant, flow_factory: Callable[..., dict[str, Any]]
) -> None:
    app.dependency_overrides[get_redis] = lambda: Redis.from_url(
        "redis://127.0.0.1:1", socket_connect_timeout=0.5
    )
    resp = await client.post(
        "/api/v1/ingest/flows", json={"flows": [flow_factory()]}, headers=tenant.api_headers
    )
    assert resp.status_code == 503
    assert resp.headers["retry-after"] == "5"
