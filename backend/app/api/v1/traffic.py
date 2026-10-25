"""Data volume per monitored host: totals, sent and received over time, top peers and services."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status

from app.core.deps import PrincipalDep, SessionDep
from app.services import analytics

router = APIRouter(prefix="/traffic", tags=["traffic"])

Minutes = Annotated[int, Query(ge=5, le=43200, description="look-back window in minutes")]


@router.get("/summary")
async def traffic_summary(
    principal: PrincipalDep, session: SessionDep, minutes: Minutes = 1440
) -> dict[str, Any]:
    """Total data moved, and how much the monitored hosts sent and received."""
    return await analytics.traffic_summary(session, principal.org_id, minutes, datetime.now(UTC))


@router.get("/hosts")
async def traffic_hosts(
    principal: PrincipalDep,
    session: SessionDep,
    minutes: Minutes = 1440,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    source_id: uuid.UUID | None = None,
) -> list[dict[str, Any]]:
    """Every monitored address (inside a registered source) with its sent/received bytes."""
    return await analytics.host_volumes(
        session, principal.org_id, minutes, limit, datetime.now(UTC), source_id
    )


@router.get("/hosts/{ip}")
async def traffic_host(
    ip: str, principal: PrincipalDep, session: SessionDep, minutes: Minutes = 1440
) -> dict[str, Any]:
    try:
        address = str(ipaddress.ip_address(ip.strip()))
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "not a valid IP address"
        ) from exc
    return await analytics.host_detail(
        session, principal.org_id, address, minutes, datetime.now(UTC)
    )
