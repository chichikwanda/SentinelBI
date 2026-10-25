"""The bulk insert behaves like INSERT ... ON CONFLICT DO NOTHING, which the worker relies on (ADR-004)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from conftest import register_org
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db.bulk import insert_ignoring_conflicts
from app.db.models import flows, predictions

CONFLICT = ["org_id", "flow_ref", "ts"]
TS = datetime(2026, 10, 25, 12, 0, 0, 123456, tzinfo=UTC)


def row(tenant_org: str, ref: str, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ts": TS,
        "org_id": tenant_org,
        "source_id": None,
        "flow_ref": ref,
        "src_ip": "10.1.2.3",
        "dst_ip": "2001:db8::1",
        "src_port": 51000,
        "dst_port": None,  # NULLs inside the arrays must survive
        "protocol": 6,
        "tcp_flags": 27,
        "in_bytes": 2**40,  # needs BIGINT
        "out_bytes": 0,
        "in_pkts": 10,
        "out_pkts": 12,
        "duration_ms": 100,
        "extra": {"note": "a", "n": [1, 2]},
    }
    return {**base, **over}


async def test_values_round_trip_and_only_new_rows_are_reported(
    client: httpx.AsyncClient, sessionmaker: async_sessionmaker
) -> None:
    t = await register_org(client)
    rows = [row(t.org_id, "r1"), row(t.org_id, "r2", dst_port=443, extra={})]
    async with sessionmaker() as session, session.begin():
        first = await insert_ignoring_conflicts(
            session, flows, rows, conflict=CONFLICT, returning="flow_ref"
        )
        # the same two rows plus one new one: only the new one is inserted and reported
        again = await insert_ignoring_conflicts(
            session, flows, [*rows, row(t.org_id, "r3")], conflict=CONFLICT, returning="flow_ref"
        )
        stored = (
            await session.execute(
                select(flows).where(flows.c.org_id == t.org_id).order_by(flows.c.flow_ref)
            )
        ).all()
    assert sorted(first) == ["r1", "r2"]
    assert again == ["r3"]
    assert [r.flow_ref for r in stored] == ["r1", "r2", "r3"]  # no duplicates
    r1, r2 = stored[0], stored[1]
    assert str(r1.src_ip) == "10.1.2.3" and str(r1.dst_ip) == "2001:db8::1"
    assert r1.dst_port is None and r2.dst_port == 443
    assert r1.in_bytes == 2**40 and r1.out_bytes == 0
    assert r1.extra == {"note": "a", "n": [1, 2]} and r2.extra == {}
    assert r1.ts == TS and r1.source_id is None


async def test_the_same_flow_ref_in_two_organisations_is_kept_apart(
    client: httpx.AsyncClient, sessionmaker: async_sessionmaker
) -> None:
    a, b = await register_org(client, "Org A"), await register_org(client, "Org B")
    async with sessionmaker() as session, session.begin():
        await insert_ignoring_conflicts(
            session, flows, [row(a.org_id, "same")], conflict=CONFLICT, returning="flow_ref"
        )
        second = await insert_ignoring_conflicts(
            session, flows, [row(b.org_id, "same")], conflict=CONFLICT, returning="flow_ref"
        )
        count = (
            await session.execute(
                select(func.count()).select_from(flows).where(flows.c.flow_ref == "same")
            )
        ).scalar_one()
    assert second == ["same"] and count == 2


async def test_predictions_insert_without_returning(
    client: httpx.AsyncClient, sessionmaker: async_sessionmaker
) -> None:
    t = await register_org(client)
    pred = {
        "ts": TS,
        "org_id": t.org_id,
        "flow_ref": "r1",
        "model_version": "m1",
        "label": "DoS/DDoS",
        "probability": 0.93,
    }
    conflict = ["org_id", "flow_ref", "model_version", "ts"]
    async with sessionmaker() as session, session.begin():
        assert (
            await insert_ignoring_conflicts(session, predictions, [pred], conflict=conflict) == []
        )
        await insert_ignoring_conflicts(
            session, predictions, [pred], conflict=conflict
        )  # redelivery
        stored = (
            await session.execute(select(predictions).where(predictions.c.org_id == t.org_id))
        ).all()
    assert len(stored) == 1
    assert stored[0].label == "DoS/DDoS" and stored[0].probability == 0.93


async def test_empty_input_is_a_no_op(sessionmaker: async_sessionmaker) -> None:
    async with sessionmaker() as session, session.begin():
        assert (
            await insert_ignoring_conflicts(
                session, flows, [], conflict=CONFLICT, returning="flow_ref"
            )
            == []
        )
