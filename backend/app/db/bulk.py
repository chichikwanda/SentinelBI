"""Bulk insert that skips rows already stored, without rendering a huge SQL statement.

``INSERT ... VALUES (...), (...), ...`` with hundreds of rows makes SQLAlchemy and psycopg build and
parse a statement with thousands of placeholders on every batch; profiling the worker showed that
client-side work, not Postgres, was most of the insert time. Here each column travels as one array
parameter and the statement text is constant (``INSERT ... SELECT ... FROM unnest(...)``): measured
at 48 ms against 125 ms (executemany) and 267 ms (inline VALUES) for 500 flow rows.

Semantics match ``INSERT ... ON CONFLICT DO NOTHING``: rows that hit the unique index are skipped
and RETURNING reports only the rows actually inserted, which the pipeline relies on for idempotent
redelivery (ADR-004).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import Table, bindparam, column, func, select
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession


async def insert_ignoring_conflicts(
    session: AsyncSession,
    table: Table,
    rows: Sequence[dict[str, Any]],
    *,
    conflict: Sequence[str],
    returning: str | None = None,
) -> list[Any]:
    """Insert ``rows`` (all with the same keys); return ``returning`` for the rows inserted."""
    if not rows:
        return []
    cols = [c for c in table.c if c.name in rows[0]]
    arrays = [
        bindparam(c.name, [r[c.name] for r in rows], type_=ARRAY(c.type, dimensions=1))
        for c in cols
    ]
    source = (
        func.unnest(*arrays)
        .table_valued(*[column(c.name, c.type) for c in cols])
        .render_derived(name="rows")
    )
    stmt = (
        pg_insert(table)
        .from_select([c.name for c in cols], select(*source.c))
        .on_conflict_do_nothing(index_elements=list(conflict))
    )
    if returning is None:
        await session.execute(stmt)
        return []
    result = await session.execute(stmt.returning(table.c[returning]))
    return [r[0] for r in result]
