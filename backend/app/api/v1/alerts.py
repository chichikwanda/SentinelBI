"""Alert queue (read) and lifecycle (acknowledge / false positive / resolve)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from app.core.deps import AnalystDep, PrincipalDep, SessionDep
from app.core.enums import AlertStatus
from app.db.models import Alert
from app.schemas.alerts import AlertOut, AlertPatch

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    principal: PrincipalDep,
    session: SessionDep,
    status_filter: Annotated[AlertStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Alert]:
    query = select(Alert).where(Alert.org_id == principal.org_id)
    if status_filter is not None:
        query = query.where(Alert.status == status_filter.value)
    rows = await session.execute(query.order_by(Alert.last_seen.desc()).limit(limit).offset(offset))
    return list(rows.scalars())


async def _get_scoped(session: SessionDep, org_id: uuid.UUID, alert_id: uuid.UUID) -> Alert:
    alert = (
        await session.execute(select(Alert).where(Alert.id == alert_id, Alert.org_id == org_id))
    ).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alert


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: uuid.UUID, principal: PrincipalDep, session: SessionDep) -> Alert:
    return await _get_scoped(session, principal.org_id, alert_id)


@router.patch("/{alert_id}", response_model=AlertOut)
async def patch_alert(
    alert_id: uuid.UUID, body: AlertPatch, principal: AnalystDep, session: SessionDep
) -> Alert:
    alert = await _get_scoped(session, principal.org_id, alert_id)
    if body.status is not None:
        alert.status = body.status.value
    if body.analyst_label is not None:
        alert.analyst_label = body.analyst_label
    await session.commit()
    return alert
