"""Exports: alerts as CSV, and a PDF security summary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Response
from sqlalchemy import func, select

from app.core.deps import PrincipalDep, SessionDep
from app.core.enums import AlertStatus
from app.db.models import Alert, ModelRegistry, Organization, Recommendation, flows
from app.services.prescriptive.engine import rank_score
from app.services.reports import alerts_csv, summary_pdf
from app.services.risk.aggregate import compute_org_risk

router = APIRouter(prefix="/reports", tags=["reports"])
_OPEN = (AlertStatus.NEW.value, AlertStatus.ACKNOWLEDGED.value)


@router.get("/alerts.csv")
async def alerts_export(principal: PrincipalDep, session: SessionDep) -> Response:
    alerts = (
        (
            await session.execute(
                select(Alert)
                .where(Alert.org_id == principal.org_id)
                .order_by(Alert.last_seen.desc())
                .limit(10000)
            )
        )
        .scalars()
        .all()
    )
    return Response(
        content=alerts_csv(list(alerts)),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="sentinelbi-alerts.csv"'},
    )


@router.get("/summary.pdf")
async def summary_export(principal: PrincipalDep, session: SessionDep) -> Response:
    org_id, now = principal.org_id, datetime.now(UTC)
    org = await session.get(Organization, org_id)
    risk = await compute_org_risk(session, org_id, now)
    by_sev = {
        s: int(n)
        for s, n in await session.execute(
            select(Alert.severity, func.count())
            .where(Alert.org_id == org_id, Alert.status.in_(_OPEN))
            .group_by(Alert.severity)
        )
    }
    flows_24h = await session.scalar(
        select(func.count())
        .select_from(flows)
        .where(flows.c.org_id == org_id, flows.c.ts >= now - timedelta(hours=24))
    )
    alerts = (
        (
            await session.execute(
                select(Alert)
                .where(Alert.org_id == org_id, Alert.status.in_(_OPEN))
                .order_by(Alert.risk_score.desc())
                .limit(15)
            )
        )
        .scalars()
        .all()
    )
    recs = (
        await session.execute(
            select(Recommendation).where(
                Recommendation.org_id == org_id,
                Recommendation.alert_id.in_([a.id for a in alerts]),
                Recommendation.status.in_(("open", "in_progress")),
            )
        )
    ).scalars()
    by_alert: dict[Any, list[Recommendation]] = {}
    for r in recs:
        by_alert.setdefault(r.alert_id, []).append(r)
    active = (
        await session.execute(select(ModelRegistry.version).where(ModelRegistry.active))
    ).scalar()

    rows = []
    for a in alerts:
        crit = int((a.evidence or {}).get("criticality", 2))  # type: ignore[call-overload]
        ranked = sorted(
            by_alert.get(a.id, []), key=lambda r: -rank_score(r.priority, a.severity, crit)
        )
        rows.append(
            {
                "severity": a.severity,
                "attack_class": a.attack_class,
                "src_ip": str(a.src_ip) if a.src_ip else None,
                "dst_ip": str(a.dst_ip) if a.dst_ip else None,
                "count": a.count,
                "risk": a.risk_score,
                "actions": [r.action for r in ranked[:3]],
            }
        )
    pdf = summary_pdf(
        {
            "org_name": org.name if org else "Organisation",
            "generated_at": now,
            "risk": {"score": risk.score, "severity": risk.severity},
            "open_by_severity": by_sev,
            "flows_24h": flows_24h or 0,
            "model_version": active or "none",
            "alerts": rows,
        }
    )
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="sentinelbi-summary.pdf"'},
    )
