"""The trainer service: runs dataset downloads and model training queued from the web interface.

One job at a time. The work is done by the same code as ``make train`` (``sentinelbi_ml.train`` and
``sentinelbi_ml.download``), run as a subprocess so that a crash or a memory kill of a long
training cannot take the service down, and so that Cancel can stop it. The subprocess output is
appended to the job's log and the stage shown on the page follows it. When a training run exports
a model, it is registered (not activated: switching the live model stays a separate decision).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.heartbeat import beat
from app.core.logging import configure_logging
from app.db.models import TrainingJob
from app.db.session import get_sessionmaker
from app.services.inference.registry import register_from_card
from app.services.training import (
    CheckParams,
    DownloadParams,
    TrainParams,
    backup_command,
    check_backup_command,
    download_command,
    exported_version,
    stage_for,
    train_command,
)

log = logging.getLogger("trainer")
LOG_LIMIT = 60_000  # characters kept per job (the tail)
FLUSH_EVERY_S = 2.0
POLL_S = 3.0


def _tail(text: str) -> str:
    return text if len(text) <= LOG_LIMIT else "...\n" + text[-LOG_LIMIT:]


def command_for(job: TrainingJob) -> list[str]:
    """The command a job runs (a function so tests can stand in for the real, slow one)."""
    settings = get_settings()
    data_root = Path(settings.data_dir) / "raw"
    if job.kind == "backup":
        return backup_command()
    if job.kind == "check":
        return check_backup_command(CheckParams.model_validate(job.params).folder)
    if job.kind == "download":
        return download_command(DownloadParams.model_validate(job.params).dataset, data_root)
    return train_command(
        TrainParams.model_validate(job.params), data_root, Path(settings.models_dir)
    )


async def claim(sessionmaker: async_sessionmaker[AsyncSession]) -> TrainingJob | None:
    async with sessionmaker() as session:
        job = (
            await session.execute(
                select(TrainingJob)
                .where(TrainingJob.status == "queued")
                .order_by(TrainingJob.created_at)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
        ).scalar_one_or_none()
        if job is None:
            return None
        job.status, job.started_at, job.stage = "running", datetime.now(UTC), "Starting"
        await session.commit()
        await session.refresh(job)
        return job


async def _save(
    sessionmaker: async_sessionmaker[AsyncSession], job_id: object, **values: object
) -> bool:
    """Write progress; returns whether a cancel was requested."""
    async with sessionmaker() as session:
        await session.execute(update(TrainingJob).where(TrainingJob.id == job_id).values(**values))
        await session.commit()
        return bool(
            (
                await session.execute(
                    select(TrainingJob.cancel_requested).where(TrainingJob.id == job_id)
                )
            ).scalar()
        )


async def run_job(sessionmaker: async_sessionmaker[AsyncSession], job: TrainingJob) -> None:
    text, stage, version = "", "Starting", None
    status, error = "succeeded", None
    cancelled = False
    try:
        cmd = command_for(job)
        text = "$ " + " ".join(cmd) + "\n"
        env = {**os.environ, "PYTHONUNBUFFERED": "1"}
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
            cwd=str(Path(get_settings().data_dir).parent),
        )
        if proc.stdout is None:  # pragma: no cover - PIPE was requested
            raise RuntimeError("no output pipe")
        last_flush = time.monotonic()
        while True:
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), timeout=POLL_S)
            except TimeoutError:
                raw = None
            beat()
            if raw == b"":
                break
            if raw:
                line = raw.decode("utf-8", errors="replace").rstrip()
                text = _tail(text + line + "\n")
                stage = stage_for(line) or stage
                version = exported_version(line) or version
            if time.monotonic() - last_flush >= FLUSH_EVERY_S:
                last_flush = time.monotonic()
                if await _save(sessionmaker, job.id, log=text, stage=stage):
                    cancelled = True
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=15)
                    except TimeoutError:
                        proc.kill()
                    break
        code = await proc.wait()
        if cancelled:
            status = "cancelled"
        elif code != 0:
            status, error = "failed", f"the process exited with code {code} (see the log)"
        elif job.kind == "train":
            if version is None:
                status, error = "failed", "training finished but no model was exported"
            else:
                async with sessionmaker() as session:
                    await register_from_card(session, version, activate=False)
    except Exception as exc:
        log.exception("job %s failed", job.id)
        status, error = "failed", f"{type(exc).__name__}: {exc}"[:500]
    await _save(
        sessionmaker,
        job.id,
        status=status,
        error=error,
        log=text,
        stage={"succeeded": "Done", "cancelled": "Cancelled"}.get(status, stage),
        result_version=version
        if status == "succeeded" and job.kind in ("train", "backup")
        else None,
        finished_at=datetime.now(UTC),
    )
    log.info("job %s %s", job.id, status)


async def fail_orphans(sessionmaker: async_sessionmaker[AsyncSession]) -> None:
    """A job left 'running' by a previous trainer process cannot still be running."""
    async with sessionmaker() as session:
        await session.execute(
            update(TrainingJob)
            .where(TrainingJob.status == "running")
            .values(
                status="failed",
                error="the trainer restarted while this job was running",
                finished_at=datetime.now(UTC),
            )
        )
        await session.commit()


async def main() -> None:
    configure_logging(get_settings().log_level)
    sessionmaker = get_sessionmaker()
    await fail_orphans(sessionmaker)
    log.info("trainer started")
    while True:
        beat()
        try:
            job = await claim(sessionmaker)
            if job is None:
                await asyncio.sleep(POLL_S)
                continue
            await run_job(sessionmaker, job)
        except Exception:
            log.exception("trainer loop error; continuing")
            await asyncio.sleep(POLL_S)


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
