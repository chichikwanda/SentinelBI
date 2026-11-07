"""Persist the engine's recommendations for an alert (idempotent)."""

from __future__ import annotations

import uuid
from collections.abc import Mapping

from sqlalchemy import delete, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AlertStatus
from app.db.models import Alert, Recommendation
from app.services import assessment
from app.services.prescriptive import overrides
from app.services.prescriptive.engine import (
    AlertContext,
    recommend,
    recommend_from_profile,
)
from app.services.prescriptive.engine import Recommendation as Rec


def context_for(alert: Alert, maturity: Mapping[str, str] | None = None) -> AlertContext:
    evidence = alert.evidence or {}
    ports = evidence.get("dst_ports_sample", [])
    return AlertContext(
        attack_class=alert.attack_class,
        severity=alert.severity,
        criticality=int(evidence.get("criticality", 2)),  # type: ignore[call-overload]
        dst_ports=frozenset(int(p) for p in ports),  # type: ignore[attr-defined]
        maturity=dict(maturity or {}),
    )


def _rows(
    recs: list[Rec], org_id: uuid.UUID, alert_id: uuid.UUID | None
) -> list[dict[str, object]]:
    return [
        {
            "org_id": org_id,
            "alert_id": alert_id,
            "rule_id": r.rule_id,
            "rec_key": r.rec_key,
            "action": r.action,
            "priority": r.priority,
            "effort": r.effort,
            "refs": r.refs,
            "compliance_note": r.compliance_note,
        }
        for r in recs
    ]


async def sync_recommendations(
    session: AsyncSession, alert: Alert, maturity: Mapping[str, str] | None = None
) -> int:
    """Insert any recommendations the rules produce for the alert's current state.

    Safe to call on every alert update: ``(alert_id, rec_key)`` is unique, so existing rows
    (and any status an analyst already set on them) are left untouched while newly matching
    rules, for example one gated on a higher severity, are added.
    """
    if maturity is None:
        maturity = assessment.levels(await assessment.load_answers(session, alert.org_id))
    recs = recommend(context_for(alert, maturity), await overrides.effective_rules(session))
    if not recs:
        return 0
    rows = _rows(recs, alert.org_id, alert.id)
    result = await session.execute(
        pg_insert(Recommendation)
        .values(rows)
        .on_conflict_do_nothing(index_elements=["alert_id", "rec_key"])
        .returning(Recommendation.id)
    )
    return len(result.all())


async def sync_profile_recommendations(session: AsyncSession, org_id: uuid.UUID) -> int:
    """Recommendations that come from weak control areas alone. Open ones whose area has since
    improved are removed; ones a person has already acted on are kept."""
    levels = assessment.levels(await assessment.load_answers(session, org_id))
    recs = recommend_from_profile(levels, await overrides.effective_rules(session))
    keep = [r.rec_key for r in recs]
    await session.execute(
        delete(Recommendation).where(
            Recommendation.org_id == org_id,
            Recommendation.alert_id.is_(None),
            Recommendation.status == "open",
            Recommendation.rec_key.not_in(keep) if keep else text("true"),
        )
    )
    if not recs:
        return 0
    result = await session.execute(
        pg_insert(Recommendation)
        .values(_rows(recs, org_id, None))
        .on_conflict_do_nothing(
            index_elements=["org_id", "rec_key"], index_where=text("alert_id IS NULL")
        )
        .returning(Recommendation.id)
    )
    return len(result.all())


async def refresh_org_recommendations(session: AsyncSession, org_id: uuid.UUID) -> None:
    """After the self-assessment changes: re-run the rules for the open alerts and the profile."""
    levels = assessment.levels(await assessment.load_answers(session, org_id))
    alerts = (
        await session.execute(
            select(Alert).where(
                Alert.org_id == org_id,
                Alert.status.in_((AlertStatus.NEW.value, AlertStatus.ACKNOWLEDGED.value)),
            )
        )
    ).scalars()
    for alert in alerts:
        await sync_recommendations(session, alert, levels)
    await sync_profile_recommendations(session, org_id)
