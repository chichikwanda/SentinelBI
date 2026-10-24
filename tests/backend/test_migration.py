"""The migration is the schema of record: it must match the ORM models and be reversible."""

from __future__ import annotations

from typing import Any

import psycopg
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from conftest import _ADMIN_URL, _psycopg_dsn, alembic_config, recreate_database
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

import app.db.models  # noqa: F401
from app.db.base import Base
from app.db.session import get_engine

EXPECTED_TABLES = {
    "organizations",
    "users",
    "sources",
    "assets",
    "flows",
    "predictions",
    "alerts",
    "recommendations",
    "risk_snapshots",
    "model_registry",
    "vulnerabilities",
    "evaluation_responses",
}


async def test_all_planned_tables_exist() -> None:
    async with get_engine().connect() as conn:
        tables = set(await conn.run_sync(lambda c: inspect(c).get_table_names()))
    assert tables >= EXPECTED_TABLES


async def test_flows_and_predictions_are_hypertables_with_retention() -> None:
    async with get_engine().connect() as conn:
        hypertables = {
            r[0]: r[1]
            for r in await conn.execute(
                text(
                    "SELECT hypertable_name, num_dimensions FROM timescaledb_information.hypertables"
                )
            )
        }
        retention = {
            r[0]
            for r in await conn.execute(
                text(
                    "SELECT hypertable_name FROM timescaledb_information.jobs WHERE proc_name = 'policy_retention'"
                )
            )
        }
    assert {"flows", "predictions"} <= set(hypertables)
    assert {"flows", "predictions"} <= retention


async def test_orm_metadata_matches_the_migrated_schema() -> None:
    def diff(sync_conn: Any) -> list[Any]:
        ctx = MigrationContext.configure(sync_conn, opts={"compare_type": True})
        return compare_metadata(ctx, Base.metadata)

    async with get_engine().connect() as conn:
        drift = await conn.run_sync(diff)
    # Expression indexes (`ts DESC`) are not reflected faithfully by Alembic: ignore those only.
    real = [d for d in drift if not _is_expression_index_noise(d)]
    assert real == [], f"ORM models and migration 0001 disagree: {real}"


def _is_expression_index_noise(d: Any) -> bool:
    if isinstance(d, tuple) and d and d[0] in {"add_index", "remove_index"}:
        name = getattr(d[1], "name", "")
        return (
            name.endswith("_ts")
            or name.endswith("_last_seen")
            or name == "ix_flows_org_id_src_ip_ts"
        )
    return False


def test_downgrade_then_upgrade_round_trips() -> None:
    name = "sentinelbi_migration_roundtrip"
    recreate_database(name)
    url = make_url(_ADMIN_URL).set(database=name).render_as_string(hide_password=False)
    import os

    previous = os.environ["DATABASE_URL"]
    from app.core.config import get_settings

    os.environ["DATABASE_URL"] = url
    get_settings.cache_clear()
    try:
        cfg = alembic_config()
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")
        engine = create_engine(url)
        with engine.connect() as conn:
            left = set(inspect(conn).get_table_names())
        engine.dispose()
        assert not (EXPECTED_TABLES & left)
        command.upgrade(cfg, "head")
    finally:
        os.environ["DATABASE_URL"] = previous
        get_settings.cache_clear()
        with psycopg.connect(_psycopg_dsn(_ADMIN_URL), autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
