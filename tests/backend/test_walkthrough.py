"""The walkthrough observation sheet: coded participants only, and a summary that is only what was recorded."""

from __future__ import annotations

import httpx
import pytest
from conftest import Tenant

from app.services import walkthrough as wt


def test_empty_sheet_gives_empty_tables() -> None:
    s = wt.summarise([], [])
    assert s["participants"] == [] and all(
        t["completed"] == 0 and t["mean_seconds"] is None for t in s["tasks"]
    )
    assert all(t["comment"] is None and t["participants"] == 0 for t in s["themes"])


def test_summary_counts_the_latest_record_per_participant() -> None:
    tasks = [
        {"participant": "P1", "task": "UAT1", "completed": False, "seconds": 90, "errors": 2},
        {"participant": "P1", "task": "UAT1", "completed": True, "seconds": 60, "errors": 0},
        {"participant": "P2", "task": "UAT1", "completed": True, "seconds": 40, "errors": 1},
    ]
    t1 = wt.summarise(tasks, [])["tasks"][0]
    assert (t1["participants"], t1["completed"], t1["mean_seconds"], t1["errors"]) == (2, 2, 50, 1)


async def test_record_and_read_back(client: httpx.AsyncClient, tenant: Tenant) -> None:
    ok = await client.post(
        "/api/v1/evaluation/walkthrough/tasks",
        json={"participant": "P1", "task": "UAT2", "completed": True, "seconds": 75, "errors": 1},
        headers=tenant.headers,
    )
    assert ok.status_code == 201, ok.text
    done = await client.post(
        "/api/v1/evaluation/walkthrough/comments",
        json={
            "participant": "P1",
            "theme": "clarity",
            "text": "The sources made the advice credible",
        },
        headers=tenant.headers,
    )
    body = done.json()
    assert body["participants"] == ["P1"]
    assert next(t for t in body["tasks"] if t["task"] == "UAT2")["mean_seconds"] == 75
    assert next(t for t in body["themes"] if t["theme"] == "clarity")["participants"] == 1
    assert (
        await client.get("/api/v1/evaluation/walkthrough", headers=tenant.headers)
    ).json() == body


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("tasks", {"participant": "Jane Doe", "task": "UAT1", "completed": True}),
        ("tasks", {"participant": "P1", "task": "UAT9", "completed": True}),
        ("comments", {"participant": "P1", "theme": "other", "text": "hello there"}),
        ("comments", {"participant": "a@b.com", "theme": "ease", "text": "hello there"}),
    ],
)
async def test_names_and_unknown_values_are_refused(
    client: httpx.AsyncClient, tenant: Tenant, path: str, body: dict[str, object]
) -> None:
    r = await client.post(
        f"/api/v1/evaluation/walkthrough/{path}", json=body, headers=tenant.headers
    )
    assert r.status_code == 422
