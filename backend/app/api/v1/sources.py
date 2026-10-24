"""Register and inspect monitored sources."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.deps import AdminDep, PrincipalDep, SessionDep
from app.core.enums import SourceMethod, SourceStatus
from app.core.security import generate_api_key, hash_api_key
from app.db.models import Asset, Source, flows
from app.schemas.sources import (
    SetupOut,
    SnippetOut,
    SourceCreate,
    SourceCreated,
    SourceHealth,
    SourceOut,
)
from app.services.ingestion.snippets import build_setup_info

router = APIRouter(prefix="/sources", tags=["sources"])

# Methods that are implemented. 'scan' needs the ownership-attestation flow and audit log
# first (ADR-006); 'syslog' is a stretch goal.
_ENABLED_METHODS = {SourceMethod.NETFLOW, SourceMethod.SENSOR, SourceMethod.HTTP}
_RECEIVING_WINDOW = timedelta(seconds=60)


@router.post("", response_model=SourceCreated, status_code=status.HTTP_201_CREATED)
async def create_source(body: SourceCreate, admin: AdminDep, session: SessionDep) -> SourceCreated:
    if body.method not in _ENABLED_METHODS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Ingestion method '{body.method}' is not available yet",
        )
    api_key = generate_api_key()
    source = Source(
        org_id=admin.org_id,
        name=body.name,
        cidr=body.cidr,
        method=body.method.value,
        api_key_hash=hash_api_key(api_key),
        status=SourceStatus.PENDING.value,
        criticality=body.criticality,
    )
    session.add(source)
    await session.flush()
    net = ipaddress.ip_network(body.cidr)
    if net.num_addresses == 1:  # a single host is directly an asset
        session.add(
            Asset(
                org_id=admin.org_id,
                source_id=source.id,
                ip=str(net.network_address),
                criticality=body.criticality,
            )
        )
    await session.commit()

    setup = build_setup_info(body.method, api_key, get_settings())
    base = SourceOut.model_validate(source)
    return SourceCreated(
        **base.model_dump(),
        api_key=api_key,
        setup=SetupOut(
            collector_host=setup.collector_host,
            collector_port=setup.collector_port,
            api_url=setup.api_url,
            snippets=[SnippetOut(**vars(s)) for s in setup.snippets],
        ),
    )


@router.get("", response_model=list[SourceOut])
async def list_sources(principal: PrincipalDep, session: SessionDep) -> list[Source]:
    rows = await session.execute(
        select(Source).where(Source.org_id == principal.org_id).order_by(Source.created_at.desc())
    )
    return list(rows.scalars())


async def _get_scoped(session: SessionDep, org_id: uuid.UUID, source_id: uuid.UUID) -> Source:
    source = (
        await session.execute(select(Source).where(Source.id == source_id, Source.org_id == org_id))
    ).scalar_one_or_none()
    if source is None:  # 404, not 403: do not reveal that another tenant's id exists
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source not found")
    return source


@router.get("/{source_id}", response_model=SourceOut)
async def get_source(source_id: uuid.UUID, principal: PrincipalDep, session: SessionDep) -> Source:
    return await _get_scoped(session, principal.org_id, source_id)


@router.get("/{source_id}/health", response_model=SourceHealth)
async def source_health(
    source_id: uuid.UUID, principal: PrincipalDep, session: SessionDep
) -> SourceHealth:
    """Drives the wizard's 'first flows received' check."""
    source = await _get_scoped(session, principal.org_id, source_id)
    scope = (flows.c.org_id == principal.org_id, flows.c.source_id == source.id)
    total = await session.scalar(select(func.count()).select_from(flows).where(*scope))
    recent = await session.scalar(
        select(func.count())
        .select_from(flows)
        .where(*scope, flows.c.ts > datetime.now(UTC) - timedelta(minutes=1))
    )
    state: Literal["waiting", "receiving", "stale"]
    if source.last_seen is None:
        state = "waiting"
    elif datetime.now(UTC) - source.last_seen <= _RECEIVING_WINDOW:
        state = "receiving"
    else:
        state = "stale"
    return SourceHealth(
        source_id=source.id,
        state=state,
        first_flows_received=source.last_seen is not None,
        last_seen=source.last_seen,
        flows_total=total or 0,
        flows_last_minute=recent or 0,
    )
