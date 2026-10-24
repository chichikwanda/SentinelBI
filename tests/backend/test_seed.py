from __future__ import annotations

from typing import Any

import httpx
import pytest
from sqlalchemy import text

from app.core.config import Settings
from app.db.seed import DEMO_DOMAIN, DEMO_ORG, seed
from app.services.inference.placeholder import PLACEHOLDER_VERSION


async def _counts(sessionmaker: Any) -> dict[str, int]:
    async with sessionmaker() as s:
        return {
            "orgs": (
                await s.execute(
                    text("SELECT count(*) FROM organizations WHERE name = :n"), {"n": DEMO_ORG}
                )
            ).scalar_one(),
            "users": (
                await s.execute(
                    text("SELECT count(*) FROM users WHERE email LIKE :d"),
                    {"d": f"%@{DEMO_DOMAIN}"},
                )
            ).scalar_one(),
            "assets": (
                await s.execute(
                    text(
                        "SELECT count(*) FROM assets a JOIN organizations o ON o.id = a.org_id WHERE o.name = :n"
                    ),
                    {"n": DEMO_ORG},
                )
            ).scalar_one(),
            "models": (
                await s.execute(
                    text("SELECT count(*) FROM model_registry WHERE version = :v AND active"),
                    {"v": PLACEHOLDER_VERSION},
                )
            ).scalar_one(),
        }


async def test_seed_is_idempotent_and_usable(
    client: httpx.AsyncClient, sessionmaker: Any, settings: Settings
) -> None:
    for _ in range(2):
        async with sessionmaker() as s:
            await seed(s)
    assert await _counts(sessionmaker) == {"orgs": 1, "users": 3, "assets": 3, "models": 1}

    login = await client.post(
        "/api/v1/auth/login",
        json={
            "email": f"admin@{DEMO_DOMAIN}",
            "password": settings.demo_password.get_secret_value(),
        },
    )
    assert login.status_code == 200
    assert login.json()["user"]["role"] == "admin"

    # the demo API key authenticates against the seeded source
    ingest = await client.post(
        "/api/v1/ingest/flows",
        json={"flows": [{"src_ip": "10.20.0.50", "dst_ip": "198.51.100.20", "protocol": 6}]},
        headers={"X-API-Key": settings.demo_api_key.get_secret_value()},
    )
    assert ingest.status_code == 202


async def test_placeholder_model_is_registered_without_metrics(sessionmaker: Any) -> None:
    async with sessionmaker() as s:
        await seed(s)
        row = (
            await s.execute(
                text("SELECT metrics::text, dataset, algo FROM model_registry WHERE version = :v"),
                {"v": PLACEHOLDER_VERSION},
            )
        ).one()
    assert row[0] == "{}"  # no fabricated metrics (design rule 7)
    assert row[1] is None
    assert "NOT a trained model" in row[2]


async def test_seed_refuses_to_run_in_prod(
    sessionmaker: Any, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "env", "prod")
    async with sessionmaker() as s:
        with pytest.raises(RuntimeError, match="prod"):
            await seed(s)


def test_prod_refuses_insecure_defaults() -> None:
    base = {
        "database_url": "postgresql+psycopg://x",
        "redis_url": "redis://x",
        "env": "prod",
        "secret_key": "dev-only-change-me-use-openssl-rand-hex-32",
        "seed_demo_data": False,  # do not inherit SEED_DEMO_DATA from the container env
        "pseudonym_key": "k" * 32,
    }
    with pytest.raises(ValueError, match="SECRET_KEY"):
        Settings(**base)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="PSEUDONYM_KEY"):
        Settings(**{**base, "secret_key": "s" * 40, "pseudonym_key": "dev-only-pseudonym-key"})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="SEED_DEMO_DATA"):
        Settings(**{**base, "secret_key": "s" * 40, "seed_demo_data": True})  # type: ignore[arg-type]
    ok = Settings(**{**base, "secret_key": "s" * 40})  # type: ignore[arg-type]
    assert ok.env == "prod"
