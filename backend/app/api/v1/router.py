"""Aggregates the v1 routers."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    alerts,
    assessment,
    auth,
    evaluation,
    ingest,
    inventory,
    models,
    overview,
    recommendations,
    reports,
    risk,
    rules,
    sensor,
    settings,
    sources,
    traffic,
    training,
    users,
)

api_router = APIRouter(prefix="/api/v1")
for module in (
    auth,
    users,
    sources,
    ingest,
    alerts,
    assessment,
    recommendations,
    overview,
    risk,
    models,
    evaluation,
    reports,
    traffic,
    inventory,
    sensor,
    settings,
    training,
    rules,
):
    api_router.include_router(module.router)
