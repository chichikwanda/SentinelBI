"""Prescriptive output: ranked recommendations per alert, with their framework references."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select

from app.core.deps import AnalystDep, PrincipalDep, SessionDep
from app.core.enums import Severity
from app.db.models import Alert, Recommendation
from app.schemas.common import IpStr
from app.services.prescriptive.engine import rank_score, reference_index

router = APIRouter(prefix="/recommendations", tags=["recommendations"])

RecStatus = Literal["open", "in_progress", "done", "dismissed"]


class Reference(BaseModel):
    framework: Literal["mitre", "cis", "nist"]
    id: str
    title: str | None
    url: str | None = None


class AlertBrief(BaseModel):
    id: uuid.UUID
    attack_class: str
    severity: Severity
    src_ip: IpStr | None
    last_seen: datetime


class RecommendationOut(BaseModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    rule_id: str
    action: str
    priority: int
    effort: str | None
    status: RecStatus
    rank: float
    compliance_note: str | None
    references: list[Reference]
    alert: AlertBrief


class RecommendationPatch(BaseModel):
    status: RecStatus


def _references(refs: dict[str, Any]) -> list[Reference]:
    index = reference_index()
    out: list[Reference] = []
    for framework in ("mitre", "cis", "nist"):
        for ref_id in refs.get(framework, []) or []:
            item = index.get(framework, {}).get(str(ref_id), {})
            out.append(
                Reference(
                    framework=framework,
                    id=str(ref_id),
                    title=item.get("title"),
                    url=item.get("url"),
                )
            )
    return out


def _to_out(rec: Recommendation, alert: Alert) -> RecommendationOut:
    criticality = int((alert.evidence or {}).get("criticality", 2))  # type: ignore[call-overload]
    return RecommendationOut(
        id=rec.id,
        alert_id=rec.alert_id,
        rule_id=rec.rule_id,
        action=rec.action,
        priority=rec.priority,
        effort=rec.effort,
        status=rec.status,
        rank=round(rank_score(rec.priority, alert.severity, criticality), 2),
        compliance_note=rec.compliance_note,
        references=_references(rec.refs or {}),
        alert=AlertBrief(
            id=alert.id,
            attack_class=alert.attack_class,
            severity=Severity(alert.severity),
            src_ip=alert.src_ip,
            last_seen=alert.last_seen,
        ),
    )


@router.get("", response_model=list[RecommendationOut])
async def list_recommendations(
    principal: PrincipalDep,
    session: SessionDep,
    alert_id: uuid.UUID | None = None,
    status_filter: Annotated[RecStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[RecommendationOut]:
    query = (
        select(Recommendation, Alert)
        .join(Alert, Alert.id == Recommendation.alert_id)
        .where(Recommendation.org_id == principal.org_id, Alert.org_id == principal.org_id)
    )
    if alert_id is not None:
        query = query.where(Recommendation.alert_id == alert_id)
    if status_filter is not None:
        query = query.where(Recommendation.status == status_filter)
    else:
        # the global list is a to-do list: hide dismissed items unless explicitly asked for
        query = query.where(Recommendation.status != "dismissed") if alert_id is None else query
    rows = (await session.execute(query.order_by(Alert.last_seen.desc()).limit(1000))).all()
    out = [_to_out(rec, alert) for rec, alert in rows]
    out.sort(key=lambda r: (-r.rank, r.priority, r.action))
    return out[:limit]


@router.patch("/{rec_id}", response_model=RecommendationOut)
async def update_recommendation(
    rec_id: uuid.UUID, body: RecommendationPatch, principal: AnalystDep, session: SessionDep
) -> RecommendationOut:
    row = (
        await session.execute(
            select(Recommendation, Alert)
            .join(Alert, Alert.id == Recommendation.alert_id)
            .where(Recommendation.id == rec_id, Recommendation.org_id == principal.org_id)
        )
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Recommendation not found")
    rec, alert = row
    rec.status = body.status
    await session.commit()
    return _to_out(rec, alert)
