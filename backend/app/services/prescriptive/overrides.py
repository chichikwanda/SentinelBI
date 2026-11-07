"""Rule changes made from the web interface (Settings > Rules), kept in the database.

The YAML files stay the shipped default. An override can switch a rule off, or change the text,
priority and effort of its actions (never the references, the attack class or the conditions: those
carry the rule's meaning and its framework source). Overrides are validated with the same schema as
the files, so an edit cannot produce a rule the engine would reject.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AppSetting
from app.services.prescriptive.engine import Action, Rule, default_rules

KEY = "rule_overrides"


class ActionEdit(BaseModel):
    action: str
    priority: int
    effort: str


class RuleEdit(BaseModel):
    enabled: bool = True
    actions: list[ActionEdit] | None = None


async def load(session: AsyncSession) -> dict[str, dict[str, Any]]:
    row = await session.get(AppSetting, KEY)
    return dict(row.value) if row is not None and isinstance(row.value, dict) else {}


async def save(session: AsyncSession, data: dict[str, dict[str, Any]], who: str) -> None:
    row = await session.get(AppSetting, KEY)
    if row is None:
        session.add(AppSetting(key=KEY, value=data, updated_by=who))
    else:
        row.value, row.updated_by = data, who


def validate(rule: Rule, edit: RuleEdit) -> dict[str, Any]:
    """Return the override to store, or raise ``ValueError`` saying what is wrong."""
    out: dict[str, Any] = {"enabled": edit.enabled}
    if edit.actions is not None:
        if len(edit.actions) != len(rule.recommend):
            raise ValueError(
                f"{rule.id} has {len(rule.recommend)} actions; actions cannot be added or removed"
            )
        try:
            for a in edit.actions:
                Action.model_validate(
                    {"action": a.action, "priority": a.priority, "effort": a.effort}
                )
        except ValidationError as exc:
            raise ValueError("; ".join(e["msg"] for e in exc.errors(include_url=False))) from exc
        out["actions"] = [a.model_dump() for a in edit.actions]
    return out


def apply(rules: tuple[Rule, ...] | list[Rule], overrides: dict[str, dict[str, Any]]) -> list[Rule]:
    """The rules to use now: shipped rules with overrides applied and disabled ones removed."""
    out: list[Rule] = []
    for rule in rules:
        o = overrides.get(rule.id)
        if o is None:
            out.append(rule)
            continue
        if not o.get("enabled", True):
            continue
        edits = o.get("actions")
        if edits and len(edits) == len(rule.recommend):
            new = rule.model_copy(deep=True)
            for act, e in zip(new.recommend, edits, strict=True):
                act.action, act.priority, act.effort = e["action"], int(e["priority"]), e["effort"]
            out.append(new)
        else:
            out.append(rule)
    return out


async def effective_rules(session: AsyncSession) -> list[Rule]:
    return apply(default_rules(), await load(session))
