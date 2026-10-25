from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import httpx
from conftest import Tenant, add_source, register_org
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


KEY = "9f2b4c1de8a74b0f9c3d5e6a7b8c9d01"


async def post(
    client: httpx.AsyncClient, tenant: Tenant, flows: list[dict[str, Any]], key: str | None
) -> httpx.Response:
    headers = {**tenant.api_headers, **({"Idempotency-Key": key} if key else {})}
    return await client.post("/api/v1/ingest/flows", json={"flows": flows}, headers=headers)


async def test_a_resent_batch_with_the_same_key_is_counted_once(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    settings: Settings,
    flow_factory: Callable[..., dict[str, Any]],
) -> None:
    flows = [flow_factory(src_port=50000 + i) for i in range(5)]
    first = await post(client, tenant, flows, KEY)
    assert first.status_code == 202 and first.json() == {"accepted": 5}  # unchanged for a new batch
    again = await post(
        client, tenant, flows, KEY
    )  # the client never saw the reply and sends it again
    assert again.status_code == 202 and again.json() == {"accepted": 5, "duplicate": True}
    assert await redis.xlen(settings.stream_flows) == 5  # queued once, not twice
    # a different batch (a different key) is new data
    third = await post(client, tenant, flows, KEY[:-1] + "x")
    assert third.json() == {"accepted": 5} and await redis.xlen(settings.stream_flows) == 10


async def test_without_a_key_nothing_changes(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    settings: Settings,
    flow_factory: Callable[..., dict[str, Any]],
) -> None:
    for _ in range(2):
        assert (await post(client, tenant, [flow_factory()], None)).json() == {"accepted": 1}
    assert (
        await redis.xlen(settings.stream_flows) == 2
    )  # clients that send no key keep the old behaviour


async def test_two_identical_requests_at_the_same_moment_queue_the_batch_once(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    settings: Settings,
    flow_factory: Callable[..., dict[str, Any]],
) -> None:
    flows = [flow_factory(src_port=40000 + i) for i in range(20)]
    results = await asyncio.gather(*(post(client, tenant, flows, KEY) for _ in range(6)))
    assert all(r.status_code == 202 for r in results)
    assert (
        sum(1 for r in results if r.json().get("duplicate")) == 5
    )  # exactly one of them was first
    assert await redis.xlen(settings.stream_flows) == 20


async def test_a_key_belongs_to_one_source(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    settings: Settings,
    flow_factory: Callable[..., dict[str, Any]],
) -> None:
    other = await register_org(client, "Other Co")
    await add_source(client, other)
    flows = [flow_factory()]
    assert (await post(client, tenant, flows, KEY)).json() == {"accepted": 1}
    assert (await post(client, other, flows, KEY)).json() == {
        "accepted": 1
    }  # same key, other source
    assert await redis.xlen(settings.stream_flows) == 2


async def test_malformed_keys_are_refused(
    client: httpx.AsyncClient, tenant: Tenant, flow_factory: Callable[..., dict[str, Any]]
) -> None:
    for bad in ("short", "x" * 129, "has spaces in it!!", "semi;colon;key"):
        r = await post(client, tenant, [flow_factory()], bad)
        assert r.status_code == 422, bad


async def test_a_redis_failure_is_a_503_and_the_resend_works_once_redis_is_back(
    client: httpx.AsyncClient,
    tenant: Tenant,
    redis: Redis,
    settings: Settings,
    flow_factory: Callable[..., dict[str, Any]],
) -> None:
    from redis.exceptions import ConnectionError as RedisConnectionError

    class Down:
        def register_script(self, *_: Any) -> Any:
            raise RedisConnectionError("redis is down")

    app.dependency_overrides[get_redis] = lambda: Down()
    flows = [flow_factory()]
    failed = await post(client, tenant, flows, KEY)
    assert failed.status_code == 503 and failed.headers["retry-after"] == "5"
    app.dependency_overrides.clear()
    retried = await post(
        client, tenant, flows, KEY
    )  # Redis is back: the same batch is accepted as new
    assert retried.json() == {"accepted": 1} and await redis.xlen(settings.stream_flows) == 1
