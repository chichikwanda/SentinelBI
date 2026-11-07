"""Rules editing from the web interface, backup listing and jobs, and the pipeline-lag measurement."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from conftest import Tenant, register_org
from redis.asyncio import Redis
from sqlalchemy import text

from app.core.config import Settings
from app.db.session import get_sessionmaker
from app.services import backup as bk
from app.services.prescriptive import overrides as ov
from app.services.prescriptive.engine import AlertContext, default_rules, recommend
from app.workers.pipeline import LAG_KEY, record_lag


@pytest.fixture
async def admin(client: httpx.AsyncClient, settings: Settings) -> AsyncIterator[Tenant]:
    t = await register_org(client)
    settings.platform_admin_emails = t.email
    async with get_sessionmaker()() as s:
        await s.execute(text("DELETE FROM app_settings; DELETE FROM training_jobs"))
        await s.commit()
    try:
        yield t
    finally:
        settings.platform_admin_emails = ""
        async with get_sessionmaker()() as s:
            await s.execute(text("DELETE FROM app_settings; DELETE FROM training_jobs"))
            await s.commit()


async def test_rules_are_listed_with_their_references(
    client: httpx.AsyncClient, admin: Tenant
) -> None:
    body = (await client.get("/api/v1/rules", headers=admin.headers)).json()
    assert body["can_edit"] is True and len(body["rules"]) == len(default_rules()) >= 25
    bf = next(r for r in body["rules"] if r["id"] == "RULE-BF-001")
    assert bf["enabled"] and bf["actions"][0]["refs"]


async def test_only_platform_admins_edit_rules(client: httpx.AsyncClient) -> None:
    t = await register_org(client)
    r = await client.put("/api/v1/rules/RULE-BF-001", json={"enabled": False}, headers=t.headers)
    assert r.status_code == 403


async def test_a_disabled_rule_stops_firing_and_can_be_restored(
    client: httpx.AsyncClient, admin: Tenant
) -> None:
    ctx = AlertContext("BruteForce", "High", 2, frozenset({22}))
    assert "RULE-BF-001" in {r.rule_id for r in recommend(ctx)}
    r = await client.put(
        "/api/v1/rules/RULE-BF-001", json={"enabled": False}, headers=admin.headers
    )
    assert r.status_code == 200
    async with get_sessionmaker()() as s:
        rules = await ov.effective_rules(s)
    assert "RULE-BF-001" not in {x.id for x in rules}
    assert "RULE-BF-001" not in {x.rule_id for x in recommend(ctx, rules)}
    await client.delete("/api/v1/rules/RULE-BF-001", headers=admin.headers)
    async with get_sessionmaker()() as s:
        assert "RULE-BF-001" in {x.id for x in await ov.effective_rules(s)}


async def test_action_text_priority_and_effort_can_be_edited_but_not_added(
    client: httpx.AsyncClient, admin: Tenant
) -> None:
    rule = next(r for r in default_rules() if r.id == "RULE-BF-001")
    edited = [
        {
            "action": "Lock accounts after five failed logins on the targeted service",
            "priority": 2,
            "effort": "low",
        }
        for _ in rule.recommend
    ]
    ok = await client.put(
        "/api/v1/rules/RULE-BF-001",
        json={"enabled": True, "actions": edited},
        headers=admin.headers,
    )
    assert ok.status_code == 200, ok.text
    async with get_sessionmaker()() as s:
        eff = next(r for r in await ov.effective_rules(s) if r.id == "RULE-BF-001")
    assert eff.recommend[0].priority == 2 and eff.recommend[0].action.startswith("Lock accounts")
    assert eff.recommend[0].refs == rule.recommend[0].refs  # the framework source never changes
    for bad in (
        edited[:1],  # removes actions
        [{"action": "short", "priority": 2, "effort": "low"}] * len(rule.recommend),
        [{"action": edited[0]["action"], "priority": 9, "effort": "low"}] * len(rule.recommend),
        [{"action": edited[0]["action"], "priority": 2, "effort": "huge"}] * len(rule.recommend),
    ):
        r = await client.put(
            "/api/v1/rules/RULE-BF-001",
            json={"enabled": True, "actions": bad},
            headers=admin.headers,
        )
        assert r.status_code == 422, r.text
    assert (
        await client.put("/api/v1/rules/NOPE", json={"enabled": False}, headers=admin.headers)
    ).status_code == 404


def test_backup_folders_are_listed_newest_first(tmp_path: Path) -> None:
    for name in ("20261101T100000Z", "20261105T100000Z"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "db.dump").write_bytes(b"x" * 10)
    (tmp_path / "not-a-backup").mkdir()
    (tmp_path / "20261106T100000Z").mkdir()  # no dump: not a backup
    listing = bk.list_backups(tmp_path)
    assert [b["name"] for b in listing] == ["20261105T100000Z", "20261101T100000Z"]
    assert bk.list_backups(tmp_path / "missing") == []


def test_a_tampered_backup_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "db.dump").write_bytes(b"original")
    (tmp_path / "SHA256SUMS").write_text(f"{bk.sha256(tmp_path / 'db.dump')}  db.dump\n")
    (tmp_path / "db.dump").write_bytes(b"changed")
    with pytest.raises(SystemExit, match="checksum mismatch"):
        bk.check(tmp_path)


async def test_backup_jobs_are_queued_checked_and_one_at_a_time(
    client: httpx.AsyncClient, admin: Tenant, settings: Settings, tmp_path: Path
) -> None:
    (tmp_path / "20261105T100000Z").mkdir()
    (tmp_path / "20261105T100000Z" / "db.dump").write_bytes(b"x")
    settings.backups_dir = str(tmp_path)
    try:
        assert (
            len((await client.get("/api/v1/training/backups", headers=admin.headers)).json()) == 1
        )
        assert (
            await client.post(
                "/api/v1/training/backups/check", json={"folder": "../etc"}, headers=admin.headers
            )
        ).status_code == 422
        assert (
            await client.post(
                "/api/v1/training/backups/check",
                json={"folder": "20260101T000000Z"},
                headers=admin.headers,
            )
        ).status_code == 404
        made = await client.post("/api/v1/training/backups", headers=admin.headers)
        assert made.status_code == 201 and made.json()["kind"] == "backup"
        again = await client.post(
            "/api/v1/training/backups/check",
            json={"folder": "20261105T100000Z"},
            headers=admin.headers,
        )
        assert again.status_code == 409  # one job at a time
    finally:
        settings.backups_dir = "/repo/backups"


async def test_pipeline_lag_is_recorded_and_reported(
    client: httpx.AsyncClient, admin: Tenant, redis: Redis
) -> None:
    class Msg:
        def __init__(self, age_ms: int) -> None:
            self.msg_id = f"{int(time.time() * 1000) - age_ms}-0"

    await record_lag(redis, [Msg(100), Msg(200), Msg(300)])  # type: ignore[list-item]
    assert await redis.llen(LAG_KEY) == 3  # type: ignore[misc]
    health = (await client.get("/api/v1/settings/health", headers=admin.headers)).json()
    lag = health["pipeline_lag"]
    assert (
        lag["samples"] == 3 and 150 <= lag["median_ms"] <= 600 and lag["p95_ms"] >= lag["median_ms"]
    )
