"""Alembic environment. Synchronous psycopg engine; URL from the app settings."""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine, pool

import app.db.models  # noqa: F401  (registers tables on Base.metadata)
from app.core.config import get_settings
from app.db.base import Base

config = context.config
target_metadata = Base.metadata


def _include_object(object_, name, type_, reflected, compare_to):  # type: ignore[no-untyped-def]
    # TimescaleDB creates internal chunk/hypertable objects we do not model.
    return not (type_ == "table" and name is not None and name.startswith("_hyper_"))


def run_migrations_offline() -> None:
    context.configure(
        url=get_settings().database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        include_object=_include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(get_settings().database_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=_include_object,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
