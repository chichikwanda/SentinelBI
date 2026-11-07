"""Settings and system health, for the web interface (so nothing needs a terminal)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select, text

from app.core.config import get_settings
from app.core.deps import PrincipalDep, SessionDep
from app.core.redis import get_redis
from app.db.models import AppSetting, ModelRegistry
from app.services import runtime_settings as rs
from app.workers.pipeline import LAG_KEY

router = APIRouter(prefix="/settings", tags=["settings"])
RedisDep = Annotated[Redis, Depends(get_redis)]


class SettingsOut(BaseModel):
    can_edit: bool
    items: list[dict[str, Any]]


class SettingsIn(BaseModel):
    values: dict[str, Any]


async def _can_edit(principal: PrincipalDep, session: SessionDep) -> bool:
    return principal.email.lower() in await rs.platform_admins(session)


async def _out(principal: PrincipalDep, session: SessionDep) -> SettingsOut:
    return SettingsOut(
        can_edit=await _can_edit(principal, session), items=await rs.describe(session)
    )


async def require_platform_admin(principal: PrincipalDep, session: SessionDep) -> None:
    if not await _can_edit(principal, session):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only platform administrators can change settings (see PLATFORM_ADMIN_EMAILS)",
        )


@router.get("", response_model=SettingsOut)
async def read_settings(principal: PrincipalDep, session: SessionDep) -> SettingsOut:
    return await _out(principal, session)


@router.put("", response_model=SettingsOut)
async def write_settings(
    body: SettingsIn, principal: PrincipalDep, session: SessionDep
) -> SettingsOut:
    await require_platform_admin(principal, session)
    cleaned: dict[str, Any] = {}
    for key, raw in body.values.items():
        item = rs.BY_KEY.get(key)
        if item is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown setting {key}")
        try:
            cleaned[key] = rs.clean(item, raw)
        except rs.SettingError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    for key, value in cleaned.items():
        row = await session.get(AppSetting, key)
        if row is None:
            session.add(AppSetting(key=key, value=value, updated_by=principal.email))
        else:
            row.value, row.updated_by, row.updated_at = value, principal.email, datetime.now(UTC)
    if rs.RETENTION_KEY in cleaned:
        await rs.set_retention(session, int(cleaned[rs.RETENTION_KEY]))
    await session.commit()
    return await _out(principal, session)


@router.delete("/{key}", response_model=SettingsOut)
async def reset_setting(key: str, principal: PrincipalDep, session: SessionDep) -> SettingsOut:
    """Go back to the environment's value."""
    await require_platform_admin(principal, session)
    if key not in rs.BY_KEY:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown setting")
    row = await session.get(AppSetting, key)
    if row is not None:
        await session.delete(row)
    if key == rs.RETENTION_KEY:
        await rs.set_retention(session, rs.RETENTION_DEFAULT)
    await session.commit()
    return await _out(principal, session)


async def _lag(redis: Redis) -> dict[str, Any]:
    """Queued-to-stored delay of the most recent flows (see workers.pipeline.record_lag)."""
    raw = await redis.lrange(LAG_KEY, 0, -1)
    lags = sorted(int(x) for x in raw)
    if not lags:
        return {"samples": 0}

    def pick(q: float) -> int:
        return lags[min(len(lags) - 1, int(q * len(lags)))]

    return {"samples": len(lags), "median_ms": pick(0.5), "p95_ms": pick(0.95), "max_ms": lags[-1]}


@router.get("/health")
async def system_health(_: PrincipalDep, session: SessionDep, redis: RedisDep) -> dict[str, Any]:
    """Is every part of the system alive? The same questions `docker compose ps` answers."""
    settings = get_settings()
    out: dict[str, Any] = {"checked_at": datetime.now(UTC).isoformat()}
    try:
        await session.execute(text("SELECT 1"))
        out["database"] = {"ok": True}
        version = (await session.execute(text("SELECT version_num FROM alembic_version"))).scalar()
        out["schema_version"] = version
        active = (
            await session.execute(select(ModelRegistry.version).where(ModelRegistry.active))
        ).scalar()
        out["active_model"] = active
        out["retention_days"] = await rs.effective_retention(session)
    except Exception as exc:
        out["database"] = {"ok": False, "error": type(exc).__name__}
    try:
        await redis.ping()
        depth = await redis.xlen(settings.stream_flows)
        dead = await redis.xlen(settings.stream_dead)
        workers: list[dict[str, Any]] = []
        try:
            for c in await redis.xinfo_consumers(settings.stream_flows, settings.stream_group):
                workers.append(
                    {
                        "name": c["name"],
                        "idle_seconds": round(c["idle"] / 1000),
                        "pending": c["pending"],
                    }
                )
        except RedisError:
            pass
        out["queue"] = {"ok": True, "waiting": depth, "dead_letters": dead, "workers": workers}
        out["pipeline_lag"] = await _lag(redis)
    except RedisError as exc:
        out["queue"] = {"ok": False, "error": type(exc).__name__}
    return out
