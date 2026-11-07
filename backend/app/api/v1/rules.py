"""The recommendation rules, viewable by everyone and editable by platform administrators."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status

from app.api.v1.settings import require_platform_admin
from app.core.deps import PrincipalDep, SessionDep
from app.services.prescriptive import overrides as ov
from app.services.prescriptive.engine import Rule, default_rules, reference_titles
from app.services.runtime_settings import platform_admins

router = APIRouter(prefix="/rules", tags=["rules"])


def _view(rule: Rule, override: dict[str, Any] | None) -> dict[str, Any]:
    o = override or {}
    edits = o.get("actions") or []
    titles = reference_titles()
    actions = []
    for i, a in enumerate(rule.recommend):
        e = edits[i] if i < len(edits) else None
        actions.append(
            {
                "action": e["action"] if e else a.action,
                "priority": e["priority"] if e else a.priority,
                "effort": e["effort"] if e else a.effort,
                "default": {"action": a.action, "priority": a.priority, "effort": a.effort},
                "refs": [
                    {"framework": fw, "id": rid, "title": titles.get(fw, {}).get(rid)}
                    for fw, ids in a.refs.model_dump().items()
                    for rid in ids
                ],
            }
        )
    w = rule.when
    return {
        "id": rule.id,
        "attack_class": w.attack_class,
        "min_severity": w.min_severity.value,
        "weak_area": w.weak_area,
        "max_level": w.max_level if w.weak_area else None,
        "profile_only": w.profile_only,
        "ports": w.dst_port_in,
        "enabled": o.get("enabled", True),
        "changed": bool(o),
        "actions": actions,
    }


@router.get("")
async def list_rules(principal: PrincipalDep, session: SessionDep) -> dict[str, Any]:
    overrides = await ov.load(session)
    return {
        "can_edit": principal.email.lower() in await platform_admins(session),
        "rules": [_view(r, overrides.get(r.id)) for r in default_rules()],
    }


@router.put("/{rule_id}")
async def edit_rule(
    rule_id: str, body: ov.RuleEdit, principal: PrincipalDep, session: SessionDep
) -> dict[str, Any]:
    await require_platform_admin(principal, session)
    rule = next((r for r in default_rules() if r.id == rule_id), None)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such rule")
    try:
        override = ov.validate(rule, body)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    data = await ov.load(session)
    data[rule_id] = override
    await ov.save(session, data, principal.email)
    await session.commit()
    return _view(rule, override)


@router.delete("/{rule_id}")
async def reset_rule(rule_id: str, principal: PrincipalDep, session: SessionDep) -> dict[str, Any]:
    await require_platform_admin(principal, session)
    rule = next((r for r in default_rules() if r.id == rule_id), None)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such rule")
    data = await ov.load(session)
    data.pop(rule_id, None)
    await ov.save(session, data, principal.email)
    await session.commit()
    return _view(rule, None)
