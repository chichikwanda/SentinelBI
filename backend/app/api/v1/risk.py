"""Risk views: per-asset scores and the organisation trend."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import text

from app.core.deps import PrincipalDep, SessionDep
from app.services.risk.aggregate import compute_org_risk
from app.services.risk.scoring import severity_for

router = APIRouter(prefix="/risk", tags=["risk"])


class AssetRiskOut(BaseModel):
    asset_id: uuid.UUID | None
    label: str
    ip: str | None
    criticality: int
    internet_facing: bool
    registered: bool
    score: float
    severity: str
    open_alerts: int


class RiskOut(BaseModel):
    score: float
    severity: str
    peak_asset: float
    assets: list[AssetRiskOut]


@router.get("/assets", response_model=RiskOut)
async def risk_assets(principal: PrincipalDep, session: SessionDep) -> RiskOut:
    risk = await compute_org_risk(session, principal.org_id, datetime.now(UTC))
    return RiskOut(
        score=risk.score,
        severity=risk.severity,
        peak_asset=risk.peak,
        assets=[
            AssetRiskOut(
                asset_id=a.asset_id,
                label=a.label,
                ip=a.ip,
                criticality=a.criticality,
                internet_facing=a.internet_facing,
                registered=a.registered,
                score=round(a.score, 1),
                severity=severity_for(a.score).value,
                open_alerts=a.alerts,
            )
            for a in risk.assets
        ],
    )


@router.get("/trend")
async def risk_trend(
    principal: PrincipalDep,
    session: SessionDep,
    hours: Annotated[int, Query(ge=1, le=168)] = 24,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    step = 5 if hours <= 24 else 30
    rows = await session.execute(
        text(
            "SELECT time_bucket(make_interval(mins => :step), ts) AS bucket, avg(score) AS score "
            "FROM risk_snapshots WHERE org_id = :org AND asset_id IS NULL AND ts >= :since "
            "GROUP BY 1 ORDER BY 1"
        ),
        {"step": step, "org": principal.org_id, "since": now - timedelta(hours=hours)},
    )
    points = [{"t": r.bucket.isoformat(), "score": round(float(r.score), 1)} for r in rows]
    current = await compute_org_risk(session, principal.org_id, now)
    points.append({"t": now.isoformat(), "score": current.score})
    return {"hours": hours, "bucket_minutes": step, "points": points}
