"""Dataset downloads and model training from the web interface (platform administrators only).

The API only queues work; the ``trainer`` service does it. Training changes what every organisation
is scored with, so it is restricted like switching the active model.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ValidationError
from sqlalchemy import select

from app.api.v1.settings import require_platform_admin
from app.core.config import get_settings
from app.core.deps import PrincipalDep, SessionDep
from app.db.models import TrainingJob
from app.services import backup as bk
from app.services import training as tr

router = APIRouter(
    prefix="/training", tags=["training"], dependencies=[Depends(require_platform_admin)]
)


class JobOut(BaseModel):
    id: uuid.UUID
    kind: str
    status: str
    stage: str | None
    params: dict[str, Any]
    result_version: str | None
    error: str | None
    created_by: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class JobDetail(JobOut):
    log: str


def _out(job: TrainingJob) -> JobOut:
    return JobOut.model_validate(job, from_attributes=True)


@router.get("/options")
async def options(session: SessionDep) -> dict[str, Any]:
    root = Path(get_settings().data_dir) / "raw"
    busy = (
        await session.execute(
            select(TrainingJob.id).where(TrainingJob.status.in_(("queued", "running")))
        )
    ).first()
    return {
        "algorithms": tr.available_algorithms(),
        "datasets": tr.dataset_status(root),
        "defaults": tr.TrainParams().model_dump(),
        "busy": busy is not None,
    }


async def _enqueue(session: SessionDep, who: str, kind: str, params: dict[str, Any]) -> TrainingJob:
    active = (
        await session.execute(
            select(TrainingJob).where(TrainingJob.status.in_(("queued", "running"))).limit(1)
        )
    ).scalar_one_or_none()
    if active is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Another job is already queued or running; wait for it or cancel it first",
        )
    job = TrainingJob(kind=kind, params=params, created_by=who, status="queued")
    session.add(job)
    await session.commit()
    await session.refresh(job)
    return job


@router.post("/jobs", response_model=JobOut, status_code=status.HTTP_201_CREATED)
async def start_training(
    body: dict[str, Any], principal: PrincipalDep, session: SessionDep
) -> JobOut:
    try:
        params = tr.TrainParams.model_validate(body)
    except ValidationError as exc:
        msgs = "; ".join(
            f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors(include_url=False)
        )
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, msgs) from exc
    missing = [
        d["key"]
        for d in tr.dataset_status(Path(get_settings().data_dir) / "raw")
        if d["key"] in params.datasets and not d["ready"] and not params.smoke
    ]
    if missing:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Download and verify the dataset first: {', '.join(map(str, missing))}",
        )
    unavailable = {str(a["key"]) for a in tr.available_algorithms() if not a["available"]}
    wanted = sorted(unavailable & set(params.models))
    if wanted:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Not available in this installation: {', '.join(wanted)}",
        )
    return _out(await _enqueue(session, principal.email, "train", params.model_dump()))


@router.post("/downloads", response_model=JobOut, status_code=status.HTTP_201_CREATED)
async def start_download(
    body: dict[str, Any], principal: PrincipalDep, session: SessionDep
) -> JobOut:
    try:
        params = tr.DownloadParams.model_validate(body)
    except ValidationError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, f"dataset must be one of {tr.DATASET_KEYS}"
        ) from exc
    return _out(await _enqueue(session, principal.email, "download", params.model_dump()))


@router.get("/jobs", response_model=list[JobOut])
async def list_jobs(session: SessionDep) -> list[JobOut]:
    rows = await session.execute(
        select(TrainingJob).order_by(TrainingJob.created_at.desc()).limit(30)
    )
    return [_out(j) for j in rows.scalars()]


async def _job(session: SessionDep, job_id: uuid.UUID) -> TrainingJob:
    job = await session.get(TrainingJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such job")
    return job


@router.get("/jobs/{job_id}", response_model=JobDetail)
async def job_detail(job_id: uuid.UUID, session: SessionDep) -> JobDetail:
    job = await _job(session, job_id)
    return JobDetail.model_validate(job, from_attributes=True)


@router.post("/jobs/{job_id}/cancel", response_model=JobOut)
async def cancel_job(job_id: uuid.UUID, session: SessionDep) -> JobOut:
    job = await _job(session, job_id)
    if job.status == "queued":
        job.status, job.stage = "cancelled", "Cancelled"
    elif job.status == "running":
        job.cancel_requested = True  # the trainer stops the process within a few seconds
    else:
        raise HTTPException(status.HTTP_409_CONFLICT, f"The job is already {job.status}")
    await session.commit()
    await session.refresh(job)
    return _out(job)


@router.get("/backups")
async def backups() -> list[dict[str, object]]:
    return bk.list_backups(Path(get_settings().backups_dir))


@router.post("/backups", response_model=JobOut, status_code=status.HTTP_201_CREATED)
async def start_backup(principal: PrincipalDep, session: SessionDep) -> JobOut:
    return _out(await _enqueue(session, principal.email, "backup", {}))


@router.post("/backups/check", response_model=JobOut, status_code=status.HTTP_201_CREATED)
async def start_backup_check(
    body: dict[str, Any], principal: PrincipalDep, session: SessionDep
) -> JobOut:
    try:
        params = tr.CheckParams.model_validate(body)
    except ValidationError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Not a backup folder name"
        ) from exc
    if params.folder not in {
        str(b["name"]) for b in bk.list_backups(Path(get_settings().backups_dir))
    }:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such backup")
    return _out(await _enqueue(session, principal.email, "check", params.model_dump()))
