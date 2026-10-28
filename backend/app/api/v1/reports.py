"""Exports: alerts as CSV, and a PDF security summary."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Response, status
from sqlalchemy import func, select

from app.core.deps import PrincipalDep, SessionDep
from app.core.enums import AlertStatus
from app.db.models import Alert, ModelRegistry, Organization, Recommendation, flows
from app.services import analytics
from app.services.prescriptive.engine import rank_score
from app.services.reports import (
    alerts_csv,
    summary_pdf,
    traffic_csv,
    traffic_section_csv,
    traffic_section_rows,
)
from app.services.risk.aggregate import compute_org_risk

router = APIRouter(prefix="/reports", tags=["reports"])
_OPEN = (AlertStatus.NEW.value, AlertStatus.ACKNOWLEDGED.value)
MAX_REPORT_HOSTS = 20


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


@router.get("/traffic.csv")
async def traffic_export(
    principal: PrincipalDep,
    session: SessionDep,
    hours: Annotated[int, Query(ge=1, le=720)] = 24,
    section: Annotated[
        Literal["hosts", "peers", "services", "timeline"],
        Query(description="which table: hosts (default), peers, services or timeline"),
    ] = "hosts",
    ip: Annotated[
        list[str] | None,
        Query(max_length=MAX_REPORT_HOSTS, description="limit the report to these addresses"),
    ] = None,
) -> Response:
    """Sent and received bytes over the last ``hours``, as the summary table (one row per
    monitored host, registered addresses included even when quiet) or, per host, as a detailed
    table of its peers, its services or its volume over time."""
    now, minutes = datetime.now(UTC), hours * 60
    wanted: list[str] = []
    for raw in ip or []:
        try:
            address = str(ipaddress.ip_address(raw.strip()))
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, f"{raw!r} is not a valid IP address"
            ) from exc
        if address not in wanted:
            wanted.append(address)
    hosts = await analytics.host_volumes(
        session, principal.org_id, minutes, 1000, now, include_idle=True
    )
    if wanted:
        hosts = [h for h in hosts if h["ip"] in wanted]
        known = {h["ip"] for h in hosts}  # an address with no row at all still gets its tables
        extra = [{"ip": a} for a in wanted if a not in known]
    else:
        hosts, extra = hosts[:MAX_REPORT_HOSTS] if section != "hosts" else hosts, []
    if section == "hosts":
        content = traffic_csv(hosts)
    else:
        details = [
            await analytics.host_detail(session, principal.org_id, h["ip"], minutes, now, top=100)
            for h in (*hosts, *extra)
        ]
        content = traffic_section_csv(section, traffic_section_rows(section, details))
    name = "traffic" if section == "hosts" else f"traffic-{section}"
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="sentinelbi-{name}.csv"'},
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
    traffic = await analytics.traffic_summary(session, org_id, 24 * 60, now)
    traffic["hosts"] = await analytics.host_volumes(session, org_id, 24 * 60, 10, now)

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
            "traffic": traffic,
        }
    )
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="sentinelbi-summary.pdf"'},
    )
