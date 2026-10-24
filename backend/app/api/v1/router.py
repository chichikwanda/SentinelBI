"""Aggregates the v1 routers."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    alerts,
    auth,
    evaluation,
    ingest,
    models,
    overview,
    recommendations,
    reports,
    risk,
    sources,
    users,
)

api_router = APIRouter(prefix="/api/v1")
for module in (
    auth,
    users,
    sources,
    ingest,
    alerts,
    recommendations,
    overview,
    risk,
    models,
    evaluation,
    reports,
):
    api_router.include_router(module.router)
