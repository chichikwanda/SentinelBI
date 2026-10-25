"""Sign-in lockout after repeated failures, and the cap on open sign-ups."""

from __future__ import annotations

import httpx
import pytest
from conftest import PASSWORD, register_org, unique_email
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.config import Settings
from app.core.ratelimit import _key, minutes
from app.core.redis import get_redis
from app.main import app

WRONG = "wrong-password-1"


async def login(client: httpx.AsyncClient, email: str, password: str) -> httpx.Response:
    return await client.post("/api/v1/auth/login", json={"email": email, "password": password})


@pytest.fixture
def three_failures(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "login_max_failures", 3)


@pytest.mark.usefixtures("three_failures")
async def test_account_is_locked_after_repeated_failures_even_for_the_right_password(
    client: httpx.AsyncClient,
) -> None:
    t = await register_org(client)
    for _ in range(3):
        assert (await login(client, t.email, WRONG)).status_code == 401
    locked = await login(client, t.email, PASSWORD)  # the correct password is refused too
    assert locked.status_code == 429
    assert int(locked.headers["Retry-After"]) > 0
    assert "Try again in" in locked.json()["detail"]


@pytest.mark.usefixtures("three_failures")
async def test_a_successful_sign_in_resets_the_counter(client: httpx.AsyncClient) -> None:
    t = await register_org(client)
    for _ in range(2):
        assert (await login(client, t.email, WRONG)).status_code == 401
    assert (await login(client, t.email, PASSWORD)).status_code == 200
    for _ in range(2):  # two more failures are allowed again: the earlier two were forgotten
        assert (await login(client, t.email, WRONG)).status_code == 401
    assert (await login(client, t.email, PASSWORD)).status_code == 200


@pytest.mark.usefixtures("three_failures")
async def test_locking_one_account_does_not_affect_another(client: httpx.AsyncClient) -> None:
    a, b = await register_org(client, "Org A"), await register_org(client, "Org B")
    for _ in range(3):
        await login(client, a.email, WRONG)
    assert (await login(client, a.email, PASSWORD)).status_code == 429
    assert (await login(client, b.email, PASSWORD)).status_code == 200


@pytest.mark.usefixtures("three_failures")
async def test_unknown_addresses_are_throttled_the_same_way(client: httpx.AsyncClient) -> None:
    ghost = unique_email(
        "ghost"
    )  # same behaviour, so the limiter does not reveal which accounts exist
    for _ in range(3):
        assert (await login(client, ghost, WRONG)).status_code == 401
    assert (await login(client, ghost, WRONG)).status_code == 429


@pytest.mark.usefixtures("three_failures")
async def test_window_starts_at_the_first_failure_and_is_not_extended(
    client: httpx.AsyncClient, redis: Redis, settings: Settings
) -> None:
    t = await register_org(client)
    await login(client, t.email, WRONG)
    key = _key("login-fail", t.email)
    first = await redis.ttl(key)
    assert 0 < first <= settings.login_lockout_seconds
    await redis.expire(key, 100)  # pretend time passed
    await login(client, t.email, WRONG)
    assert await redis.ttl(key) <= 100  # a later failure does not push the window out again


async def test_email_addresses_never_appear_in_redis_keys(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    t = await register_org(client)
    await login(client, t.email, WRONG)
    keys = [k async for k in redis.scan_iter("rl:*")]
    assert keys and all(t.email.split("@")[0] not in k for k in keys)


async def test_open_sign_up_is_capped_across_the_deployment(
    client: httpx.AsyncClient, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "register_max_per_hour", 2)
    for i in range(2):
        r = await client.post(
            "/api/v1/auth/register",
            json={"org_name": f"Org {i}", "email": unique_email(), "password": PASSWORD},
        )
        assert r.status_code == 201
    capped = await client.post(
        "/api/v1/auth/register",
        json={"org_name": "One too many", "email": unique_email(), "password": PASSWORD},
    )
    assert capped.status_code == 429
    assert "Retry-After" in capped.headers


class BrokenRedis:
    """Every call fails like a Redis that is down."""

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        def fail(*args: object, **kwargs: object) -> None:
            raise RedisConnectionError("redis is down")

        return fail


async def test_throttling_fails_open_when_redis_is_down(client: httpx.AsyncClient) -> None:
    t = await register_org(client)  # created while Redis still works
    app.dependency_overrides[get_redis] = lambda: BrokenRedis()
    assert (await login(client, t.email, PASSWORD)).status_code == 200
    assert (await login(client, t.email, WRONG)).status_code == 401  # still a plain failure, no 500


def test_minutes_rounds_up_for_people() -> None:
    assert [minutes(s) for s in (1, 60, 61, 900)] == [1, 1, 2, 15]


def test_redis_waits_longer_than_the_library_default_for_a_stalled_disk(settings: Settings) -> None:
    kwargs = get_redis().connection_pool.connection_kwargs
    assert settings.redis_timeout_seconds == 30.0
    assert kwargs.get("socket_timeout", kwargs.get("orig_socket_timeout")) == 30.0
