"""Persist the engine's recommendations for an alert (idempotent)."""

from __future__ import annotations

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Alert, Recommendation
from app.services.prescriptive.engine import AlertContext, recommend


def context_for(alert: Alert) -> AlertContext:
    evidence = alert.evidence or {}
    ports = evidence.get("dst_ports_sample", [])
    return AlertContext(
        attack_class=alert.attack_class,
        severity=alert.severity,
        criticality=int(evidence.get("criticality", 2)),  # type: ignore[call-overload]
        dst_ports=frozenset(int(p) for p in ports),  # type: ignore[attr-defined]
    )


async def sync_recommendations(session: AsyncSession, alert: Alert) -> int:
    """Insert any recommendations the rules produce for the alert's current state.

    Safe to call on every alert update: ``(alert_id, rec_key)`` is unique, so existing rows
    (and any status an analyst already set on them) are left untouched while newly matching
    rules, for example one gated on a higher severity, are added.
    """
    recs = recommend(context_for(alert))
    if not recs:
        return 0
    rows = [
        {
            "org_id": alert.org_id,
            "alert_id": alert.id,
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
    result = await session.execute(
        pg_insert(Recommendation)
        .values(rows)
        .on_conflict_do_nothing(index_elements=["alert_id", "rec_key"])
        .returning(Recommendation.id)
    )
    return len(result.all())
