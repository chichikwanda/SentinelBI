"""Shared fixtures. Tests run against a real Postgres/TimescaleDB and Redis (no mocks for
the data path): a throwaway database ``sentinelbi_test`` is created and migrated once per
session, so the migration itself is exercised on every run.

Defaults target the compose services published on 127.0.0.1 (NOT "localhost": on Windows that
resolves to ::1 first and each connection stalls for ~2 minutes), so tests also run from the
host; inside the compose ``test`` service the env vars point at ``db`` / ``redis``.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from sqlalchemy.engine import make_url

_ADMIN_URL = os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://sentinel:dev-only-change-me@127.0.0.1:5432/postgres"
)
TEST_DB = "sentinelbi_test"

if sys.platform == "win32":  # psycopg async cannot use the default Proactor loop (host runs only)
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
os.environ["DATABASE_URL"] = (
    make_url(_ADMIN_URL).set(database=TEST_DB).render_as_string(hide_password=False)
)
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6379/1")
os.environ.setdefault("SECRET_KEY", "dev-only-test-secret-key-not-for-production-0123456789")
os.environ["ENV"] = "test"

import httpx  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from redis.asyncio import Redis  # noqa: E402

from app.core.config import Settings, get_settings  # noqa: E402
from app.core.redis import get_redis  # noqa: E402
from app.db.session import get_engine, get_sessionmaker  # noqa: E402
from app.main import app  # noqa: E402

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"


def _psycopg_dsn(url: str) -> str:
    return make_url(url).set(drivername="postgresql").render_as_string(hide_password=False)


def alembic_config(url: str | None = None) -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return cfg


def recreate_database(name: str) -> None:
    with psycopg.connect(_psycopg_dsn(_ADMIN_URL), autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.execute(f'CREATE DATABASE "{name}"')


@pytest.fixture(scope="session", autouse=True)
def _database() -> Iterator[None]:
    recreate_database(TEST_DB)
    command.upgrade(alembic_config(), "head")
    yield
    # engine disposal happens in the async fixture below; drop best-effort
    try:
        with psycopg.connect(_psycopg_dsn(_ADMIN_URL), autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)')
    except psycopg.Error:
        pass


@pytest.fixture(scope="session", autouse=True)
async def _dispose_engine() -> AsyncIterator[None]:
    yield
    await get_engine().dispose()
    await get_redis().aclose()


@pytest.fixture(autouse=True)
async def _clean_redis() -> None:
    """Redis db 1 is dedicated to tests; start every test with an empty stream/counters."""
    await get_redis().flushdb()


@pytest.fixture
def settings() -> Settings:
    return get_settings()


@pytest.fixture
async def redis() -> Redis:
    return get_redis()


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def sessionmaker() -> Any:
    return get_sessionmaker()


# --- builders ------------------------------------------------------------------------------

PASSWORD = "correct-horse-battery"


def unique_email(prefix: str = "user") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}@example.com"


class Tenant:
    """A registered organisation with its admin token and one source."""

    def __init__(self, org_id: str, email: str, token: str, source: dict[str, Any] | None = None):
        self.org_id = org_id
        self.email = email
        self.token = token
        self.source = source or {}

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    @property
    def api_headers(self) -> dict[str, str]:
        return {"X-API-Key": self.source["api_key"]}


async def register_org(client: httpx.AsyncClient, name: str = "Acme ICT") -> Tenant:
    email = unique_email("admin")
    resp = await client.post(
        "/api/v1/auth/register", json={"org_name": name, "email": email, "password": PASSWORD}
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    return Tenant(body["user"]["org_id"], email, body["access_token"])


async def add_source(
    client: httpx.AsyncClient,
    tenant: Tenant,
    *,
    cidr: str = "10.20.0.0/24",
    method: str = "http",
    name: str = "HQ",
    criticality: int = 2,
) -> dict[str, Any]:
    resp = await client.post(
        "/api/v1/sources",
        json={"name": name, "cidr": cidr, "method": method, "criticality": criticality},
        headers=tenant.headers,
    )
    assert resp.status_code == 201, resp.text
    tenant.source = resp.json()
    return tenant.source


@pytest.fixture
async def tenant(client: httpx.AsyncClient) -> Tenant:
    t = await register_org(client)
    await add_source(client, t)
    return t


@pytest.fixture
def flow_factory() -> Callable[..., dict[str, Any]]:
    def make(**overrides: Any) -> dict[str, Any]:
        flow = {
            "src_ip": "10.20.0.50",
            "dst_ip": "198.51.100.20",
            "src_port": 51514,
            "dst_port": 443,
            "protocol": 6,
            "tcp_flags": 27,
            "in_bytes": 1200,
            "out_bytes": 5400,
            "in_pkts": 10,
            "out_pkts": 12,
            "duration_ms": 850,
        }
        flow.update(overrides)
        return flow

    return make


def scan_flows(
    n: int, *, src: str = "203.0.113.50", dst: str = "10.20.0.10"
) -> list[dict[str, Any]]:
    """SYN-only single-packet flows to distinct ports (what the placeholder calls Recon/Scan)."""
    return [
        {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": 50000 + i,
            "dst_port": 1 + i,
            "protocol": 6,
            "tcp_flags": 2,
            "in_bytes": 44,
            "out_bytes": 0,
            "in_pkts": 1,
            "out_pkts": 0,
            "duration_ms": 0,
        }
        for i in range(n)
    ]


def flood_flows(
    n: int, *, src: str = "198.51.100.77", dst: str = "10.20.0.20"
) -> list[dict[str, Any]]:
    return [
        {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": 1024 + i,
            "dst_port": 80,
            "protocol": 17,
            "tcp_flags": 0,
            "in_bytes": 3000 * 60,
            "out_bytes": 0,
            "in_pkts": 3000,
            "out_pkts": 0,
            "duration_ms": 700,
        }
        for i in range(n)
    ]
