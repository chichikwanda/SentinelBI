"""Model registry: list versions with their measured metrics; switch the active model."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from app.core.config import get_settings
from app.core.deps import AdminDep, PrincipalDep, SessionDep
from app.db.models import ModelRegistry
from app.services.inference.artifact import ModelLoadError, read_card
from app.services.inference.placeholder import PLACEHOLDER_VERSION
from app.services.inference.registry import set_active

router = APIRouter(prefix="/models", tags=["models"])


class ModelOut(BaseModel):
    version: str
    algo: str
    dataset: str | None
    active: bool
    created_at: datetime
    features: list[str]
    metrics: dict[str, Any]


def _platform_admins() -> set[str]:
    return {e.strip().lower() for e in get_settings().platform_admin_emails.split(",") if e.strip()}


@router.get("", response_model=list[ModelOut])
async def list_models(_: PrincipalDep, session: SessionDep) -> list[ModelRegistry]:
    rows = await session.execute(select(ModelRegistry).order_by(ModelRegistry.created_at.desc()))
    return list(rows.scalars())


@router.post("/{version}/activate", response_model=ModelOut)
async def activate_model(version: str, admin: AdminDep, session: SessionDep) -> ModelRegistry:
    """Switch the PLATFORM-WIDE model. The registry is shared by every organisation, so this is
    restricted to the emails in PLATFORM_ADMIN_EMAILS, not to any organisation's admin."""
    if admin.email.lower() not in _platform_admins():
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only platform administrators can switch the model"
        )
    row = await session.get(ModelRegistry, version)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Model not registered")
    if version != PLACEHOLDER_VERSION:
        try:
            read_card(version)  # artifact present and feature-compatible?
        except ModelLoadError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    await set_active(session, version)
    await session.commit()
    await session.refresh(row)
    return row
