"""Dashboard KPIs and descriptive traffic analytics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import func, select, text

from app.core.deps import PrincipalDep, SessionDep
from app.core.enums import AlertStatus
from app.db.models import Alert, ModelRegistry, Source, flows
from app.services import analytics
from app.services.risk.aggregate import compute_org_risk

router = APIRouter(tags=["analytics"])

Minutes = Annotated[int, Query(ge=5, le=10080, description="look-back window in minutes")]
_OPEN = (AlertStatus.NEW.value, AlertStatus.ACKNOWLEDGED.value)


class RiskSummary(BaseModel):
    score: float
    severity: str
    peak_asset: float


class Attacker(BaseModel):
    ip: str
    alerts: int
    flows: int
    max_risk: float


class ModelInfo(BaseModel):
    version: str | None
    algo: str | None


class Overview(BaseModel):
    flows_24h: int
    open_alerts: int
    open_by_severity: dict[str, int]
    risk: RiskSummary
    sources_total: int
    sources_receiving: int
    top_attackers: list[Attacker]
    model: ModelInfo


@router.get("/overview", response_model=Overview)
async def overview(principal: PrincipalDep, session: SessionDep) -> Overview:
    org, now = principal.org_id, datetime.now(UTC)

    flows_24h = await session.scalar(
        select(func.count())
        .select_from(flows)
        .where(flows.c.org_id == org, flows.c.ts >= now - timedelta(hours=24))
    )
    by_sev = {
        sev: int(n)
        for sev, n in await session.execute(
            select(Alert.severity, func.count())
            .where(Alert.org_id == org, Alert.status.in_(_OPEN))
            .group_by(Alert.severity)
        )
    }
    total_sources = await session.scalar(
        select(func.count()).select_from(Source).where(Source.org_id == org)
    )
    receiving = await session.scalar(
        select(func.count())
        .select_from(Source)
        .where(Source.org_id == org, Source.last_seen >= now - timedelta(minutes=5))
    )
    attackers = await session.execute(
        text(
            "SELECT host(src_ip) AS ip, count(*) AS alerts, sum(count) AS flows, "
            "max(risk_score) AS max_risk "
            "FROM alerts WHERE org_id = :org AND status IN ('new', 'acknowledged') "
            "AND src_ip IS NOT NULL "
            "GROUP BY 1 ORDER BY max_risk DESC LIMIT 5"
        ),
        {"org": org},
    )
    active = (
        await session.execute(
            select(ModelRegistry.version, ModelRegistry.algo).where(ModelRegistry.active)
        )
    ).first()
    risk = await compute_org_risk(session, org, now)

    return Overview(
        flows_24h=flows_24h or 0,
        open_alerts=sum(by_sev.values()),
        open_by_severity={s: by_sev.get(s, 0) for s in ("Critical", "High", "Medium", "Low")},
        risk=RiskSummary(score=risk.score, severity=risk.severity, peak_asset=risk.peak),
        sources_total=total_sources or 0,
        sources_receiving=receiving or 0,
        top_attackers=[
            Attacker(
                ip=r.ip,
                alerts=int(r.alerts),
                flows=int(r.flows),
                max_risk=round(float(r.max_risk), 1),
            )
            for r in attackers
        ],
        model=ModelInfo(version=active[0] if active else None, algo=active[1] if active else None),
    )


@router.get("/traffic/timeseries")
async def traffic_timeseries(
    principal: PrincipalDep, session: SessionDep, minutes: Minutes = 60
) -> dict[str, Any]:
    return await analytics.timeseries(session, principal.org_id, minutes, datetime.now(UTC))


@router.get("/traffic/top-talkers")
async def traffic_top_talkers(
    principal: PrincipalDep,
    session: SessionDep,
    minutes: Minutes = 60,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> list[dict[str, Any]]:
    return await analytics.top_talkers(session, principal.org_id, minutes, limit, datetime.now(UTC))


@router.get("/traffic/protocols")
async def traffic_protocols(
    principal: PrincipalDep, session: SessionDep, minutes: Minutes = 60
) -> list[dict[str, Any]]:
    return await analytics.protocol_mix(session, principal.org_id, minutes, datetime.now(UTC))
