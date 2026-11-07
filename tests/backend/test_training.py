"""Training from the web interface: who may start it, what is checked, and how a job runs.

The real training takes many minutes and needs the datasets, so the subprocess is replaced by a
tiny stand-in command. Everything around it (queue, log, stages, registration, cancel) is real.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import Tenant, register_org
from sqlalchemy import text

from app.core.config import Settings
from app.db.models import TrainingJob
from app.db.session import get_sessionmaker
from app.services import training as tr
from app.workers import trainer


@pytest.fixture
async def admin(client: httpx.AsyncClient, settings: Settings) -> AsyncIterator[Tenant]:
    t = await register_org(client)
    settings.platform_admin_emails = t.email
    async with get_sessionmaker()() as s:
        await s.execute(text("DELETE FROM training_jobs"))
        await s.commit()
    try:
        yield t
    finally:
        settings.platform_admin_emails = ""
        async with get_sessionmaker()() as s:
            await s.execute(text("DELETE FROM training_jobs"))
            await s.commit()


async def test_only_platform_admins_may_use_training(client: httpx.AsyncClient) -> None:
    t = await register_org(client)
    for method, path in (
        ("GET", "/training/options"),
        ("GET", "/training/jobs"),
        ("POST", "/training/jobs"),
    ):
        r = await client.request(
            method, f"/api/v1{path}", headers=t.headers, json={} if method == "POST" else None
        )
        assert r.status_code == 403, (path, r.text)


async def test_options_list_algorithms_and_datasets(
    client: httpx.AsyncClient, admin: Tenant
) -> None:
    body = (await client.get("/api/v1/training/options", headers=admin.headers)).json()
    keys = {a["key"] for a in body["algorithms"]}
    assert {"dt", "rf", "lgbm", "xgb", "lr", "mlp"} <= keys
    assert {d["key"] for d in body["datasets"]} == set(tr.DATASET_KEYS)
    assert body["defaults"]["seed"] == 42 and body["busy"] is False


@pytest.mark.parametrize(
    "body",
    [
        {"models": ["gpt"]},
        {"datasets": ["nope"]},
        {"cv_folds": 1},
        {"benign_cap": 5},
        {"target_far": 0.9},
    ],
)
async def test_bad_requests_are_refused(
    client: httpx.AsyncClient, admin: Tenant, body: dict[str, Any]
) -> None:
    r = await client.post("/api/v1/training/jobs", json=body, headers=admin.headers)
    assert r.status_code == 422, r.text


async def test_missing_dataset_must_be_downloaded_first(
    client: httpx.AsyncClient, admin: Tenant, settings: Settings, tmp_path: Path
) -> None:
    settings.data_dir = str(tmp_path)
    try:
        r = await client.post("/api/v1/training/jobs", json={}, headers=admin.headers)
    finally:
        settings.data_dir = "/repo/data"
    assert r.status_code == 409 and "Download" in r.json()["detail"]


async def test_one_job_at_a_time_and_queued_jobs_can_be_cancelled(
    client: httpx.AsyncClient, admin: Tenant
) -> None:
    first = await client.post("/api/v1/training/jobs", json={"smoke": True}, headers=admin.headers)
    assert first.status_code == 201, first.text
    assert first.json()["status"] == "queued"
    second = await client.post(
        "/api/v1/training/downloads", json={"dataset": tr.DATASET_KEYS[0]}, headers=admin.headers
    )
    assert second.status_code == 409
    cancelled = await client.post(
        f"/api/v1/training/jobs/{first.json()['id']}/cancel", headers=admin.headers
    )
    assert cancelled.json()["status"] == "cancelled"
    again = await client.post(
        f"/api/v1/training/jobs/{first.json()['id']}/cancel", headers=admin.headers
    )
    assert again.status_code == 409
    assert (
        await client.post(
            "/api/v1/training/downloads", json={"dataset": "x"}, headers=admin.headers
        )
    ).status_code == 422


def test_command_is_built_from_validated_parameters(tmp_path: Path) -> None:
    p = tr.TrainParams(models=["rf", "mlp", "rf"], cv_folds=5, cross_dataset=False, smoke=True)
    cmd = tr.train_command(p, tmp_path / "raw", tmp_path / "models")
    assert cmd[cmd.index("--models") + 1] == "rf,mlp"  # de-duplicated, order kept
    assert "--cv-folds" in cmd and "--no-cross-dataset" in cmd and "--smoke" in cmd
    assert cmd[cmd.index("--benign-keep") + 1] == "nf-cse-cic-ids2018-v2=0.08"


def test_log_lines_become_stages_and_a_version() -> None:
    assert tr.stage_for("[10:00:01] training rf ...") == "Training models"
    assert tr.stage_for("[10:00:02] TEST (rf): macro-F1=0.6") == "Evaluating on the test split"
    assert tr.stage_for("some noise") is None
    assert (
        tr.exported_version("[10:09:00] exported ml/models/rf-nfmulti2-2026-ab12")
        == "rf-nfmulti2-2026-ab12"
    )
    assert tr.exported_version("[10:09:00] training rf") is None


async def _queue(kind: str = "train") -> TrainingJob:
    async with get_sessionmaker()() as s:
        job = TrainingJob(kind=kind, params={}, created_by="test")
        s.add(job)
        await s.commit()
        await s.refresh(job)
        return job


async def _reload(job_id: Any) -> TrainingJob:
    async with get_sessionmaker()() as s:
        row = await s.get(TrainingJob, job_id)
        assert row is not None
        return row


def _stub(monkeypatch: pytest.MonkeyPatch, code: str) -> list[str]:
    registered: list[str] = []

    async def fake_register(session: Any, version: str, activate: bool = False) -> None:
        registered.append(version)

    monkeypatch.setattr(trainer, "command_for", lambda job: [sys.executable, "-c", code])
    monkeypatch.setattr(trainer, "register_from_card", fake_register)
    monkeypatch.setattr(trainer, "FLUSH_EVERY_S", 0.1)
    monkeypatch.setattr(trainer, "POLL_S", 0.1)
    return registered


async def test_a_successful_run_logs_registers_and_records_the_model(
    admin: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    registered = _stub(
        monkeypatch,
        "print('[10:00:00] training rf ...'); print('[10:00:09] exported /m/rf-test-1')",
    )
    job = await _queue()
    claimed = await trainer.claim(get_sessionmaker())
    assert claimed is not None and claimed.id == job.id
    await trainer.run_job(get_sessionmaker(), claimed)
    done = await _reload(job.id)
    assert done.status == "succeeded" and done.result_version == "rf-test-1"
    assert registered == ["rf-test-1"] and "training rf" in done.log and done.finished_at


async def test_a_failing_run_is_reported_not_registered(
    admin: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    registered = _stub(monkeypatch, "import sys; print('boom'); sys.exit(3)")
    job = await _queue()
    claimed = await trainer.claim(get_sessionmaker())
    assert claimed is not None
    await trainer.run_job(get_sessionmaker(), claimed)
    done = await _reload(job.id)
    assert done.status == "failed" and "code 3" in (done.error or "") and not registered


async def test_a_run_that_exports_nothing_is_a_failure(
    admin: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub(monkeypatch, "print('[10:00:00] training rf ...')")
    job = await _queue()
    claimed = await trainer.claim(get_sessionmaker())
    assert claimed is not None
    await trainer.run_job(get_sessionmaker(), claimed)
    assert (await _reload(job.id)).status == "failed"


async def test_a_running_job_can_be_cancelled(
    admin: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub(
        monkeypatch, "import time; print('[10:00:00] training rf ...', flush=True); time.sleep(60)"
    )
    job = await _queue()
    claimed = await trainer.claim(get_sessionmaker())
    assert claimed is not None
    task = asyncio.create_task(trainer.run_job(get_sessionmaker(), claimed))
    await asyncio.sleep(0.5)
    async with get_sessionmaker()() as s:
        await s.execute(text("UPDATE training_jobs SET cancel_requested = true"))
        await s.commit()
    await asyncio.wait_for(task, timeout=20)
    assert (await _reload(job.id)).status == "cancelled"


async def test_jobs_left_running_by_a_dead_trainer_are_failed(admin: Tenant) -> None:
    job = await _queue()
    claimed = await trainer.claim(get_sessionmaker())
    assert claimed is not None
    await trainer.fail_orphans(get_sessionmaker())
    done = await _reload(job.id)
    assert done.status == "failed" and "restarted" in (done.error or "")
