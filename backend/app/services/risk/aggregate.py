"""Asset and organisation risk (plan section 7), computed from open alerts.

    alert_risk  = alert.risk_score / 100                     (already P x impact x criticality)
    decayed     = alert_risk x 0.5 ** (age_hours / half_life)
    asset_risk  = 100 x (1 - prod(1 - decayed_i))            over the last 24 h
    org_risk    = criticality-weighted mean of asset_risk

Alerts are attached to a registered asset when its target (or, for an internal attacker,
its source) address equals the asset's address. Alerts that match no asset form a pseudo-asset
per source so they still count. Weights, half-life and the aggregation are PROVISIONAL (ADR-014).
Resolved and false-positive alerts are excluded, so working an alert lowers the score.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.enums import AlertStatus
from app.db.models import Alert, Asset, RiskSnapshot, Source
from app.services.risk.scoring import severity_for

WINDOW_HOURS = 24
_OPEN = (AlertStatus.NEW.value, AlertStatus.ACKNOWLEDGED.value)


@dataclass
class AssetRisk:
    asset_id: uuid.UUID | None
    label: str
    ip: str | None
    criticality: int
    internet_facing: bool
    score: float = 0.0
    alerts: int = 0
    registered: bool = True
    _survival: float = field(default=1.0, repr=False)  # prod(1 - r_i)

    def add(self, risk: float) -> None:
        self._survival *= 1.0 - max(0.0, min(1.0, risk))
        self.alerts += 1
        self.score = 100.0 * (1.0 - self._survival)


@dataclass
class OrgRisk:
    score: float
    severity: str
    peak: float
    assets: list[AssetRisk]


def decay_factor(age_hours: float, half_life_hours: float) -> float:
    return float(0.5 ** (max(age_hours, 0.0) / half_life_hours))


async def compute_org_risk(session: AsyncSession, org_id: uuid.UUID, now: datetime) -> OrgRisk:
    half_life = get_settings().risk_decay_half_life_hours
    since = now - timedelta(hours=WINDOW_HOURS)

    assets = (await session.execute(select(Asset).where(Asset.org_id == org_id))).scalars().all()
    by_ip: dict[str, AssetRisk] = {}
    nodes: list[AssetRisk] = []
    for a in assets:
        registered = AssetRisk(
            a.id, a.hostname or str(a.ip), str(a.ip), a.criticality, a.internet_facing
        )
        by_ip[str(a.ip)] = registered
        nodes.append(registered)

    name_rows = await session.execute(select(Source.id, Source.name).where(Source.org_id == org_id))
    source_names: dict[uuid.UUID, str] = {row[0]: row[1] for row in name_rows}
    alerts = (
        (
            await session.execute(
                select(Alert).where(
                    Alert.org_id == org_id, Alert.last_seen >= since, Alert.status.in_(_OPEN)
                )
            )
        )
        .scalars()
        .all()
    )
    pseudo: dict[uuid.UUID | None, AssetRisk] = {}
    for alert in alerts:
        age_h = (now - alert.last_seen).total_seconds() / 3600
        risk = alert.risk_score / 100.0 * decay_factor(age_h, half_life)
        node = by_ip.get(str(alert.dst_ip)) if alert.dst_ip is not None else None
        if node is None and alert.src_ip is not None:
            node = by_ip.get(str(alert.src_ip))
        if node is None:
            key = alert.source_id
            if key not in pseudo:
                raw_crit = (alert.evidence or {}).get("criticality", 2)
                crit = int(raw_crit) if isinstance(raw_crit, int | str) else 2
                label = (
                    f"Unassigned ({source_names.get(key, 'unknown source')})"
                    if key
                    else "Unassigned"
                )
                pseudo[key] = AssetRisk(None, label, None, crit, False, registered=False)
                nodes.append(pseudo[key])
            node = pseudo[key]
        node.add(risk)

    total_w = sum(n.criticality for n in nodes)
    score = sum(n.criticality * n.score for n in nodes) / total_w if total_w else 0.0
    peak = max((n.score for n in nodes), default=0.0)
    nodes.sort(key=lambda n: (-n.score, -n.criticality, n.label))
    return OrgRisk(round(score, 1), severity_for(score).value, round(peak, 1), nodes)


async def snapshot_org(session: AsyncSession, org_id: uuid.UUID, now: datetime) -> None:
    """Store the org score plus every asset with a non-zero score (for the trend charts)."""
    risk = await compute_org_risk(session, org_id, now)
    rows = [{"ts": now, "org_id": org_id, "asset_id": None, "score": risk.score}]
    rows += [
        {"ts": now, "org_id": org_id, "asset_id": n.asset_id, "score": n.score}
        for n in risk.assets
        if n.asset_id is not None and n.score > 0
    ]
    await session.execute(pg_insert(RiskSnapshot).values(rows))


async def active_org_ids(session: AsyncSession, now: datetime) -> list[uuid.UUID]:
    since = now - timedelta(hours=WINDOW_HOURS)
    rows = await session.execute(select(Alert.org_id).where(Alert.last_seen >= since).distinct())
    return [r[0] for r in rows]
