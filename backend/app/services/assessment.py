"""Self-assessment: the items, and how answers become a maturity level per control area.

    percent = 100 x sum(score x weight) / (2 x sum(weight))     over the ANSWERED items of the area
    level   = High if percent >= 80, Medium if >= 50, otherwise Low
    area with no answer yet = "Not assessed" (never guessed)

The governance items are shown separately as In place / Partly in place / Gap per item. They are
indicative decision support, not a finding of legal compliance.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AssessmentAnswer

ITEMS_FILE = Path(__file__).parent / "assessment_data" / "items.yaml"
GOVERNANCE_AREA = "Governance"
LEVELS = ["Low", "Medium", "High"]  # order matters: index = how strong
NOT_ASSESSED = "Not assessed"
STATUS = {0: "Gap", 1: "Partly in place", 2: "In place"}
DISCLAIMER = (
    "Indicative decision support only. It is not a finding of legal compliance: that remains a "
    "matter for the regulator and legal advisers."
)


@dataclass(frozen=True)
class Item:
    id: str
    area: str
    weight: int
    question: str
    source: str


@lru_cache
def items() -> tuple[Item, ...]:
    raw = yaml.safe_load(ITEMS_FILE.read_text(encoding="utf-8"))["items"]
    out = tuple(Item(**r) for r in raw)
    if len({i.id for i in out}) != len(out) or any(i.weight not in (1, 2) for i in out):
        raise ValueError("assessment items: duplicate id or weight outside 1..2")
    return out


def level_for(percent: float) -> str:
    return "High" if percent >= 80 else "Medium" if percent >= 50 else "Low"


def maturity(answers: dict[str, int]) -> dict[str, dict[str, Any]]:
    """Per control area (governance excluded): percent, level and how many items are answered."""
    areas: dict[str, dict[str, int]] = {}
    for it in items():
        if it.area == GOVERNANCE_AREA:
            continue
        a = areas.setdefault(it.area, {"items": 0, "answered": 0, "points": 0, "max": 0})
        a["items"] += 1
        if it.id in answers:
            a["answered"] += 1
            a["points"] += answers[it.id] * it.weight
            a["max"] += 2 * it.weight
    out: dict[str, dict[str, Any]] = {}
    for name, a in areas.items():
        counts = {"items": a["items"], "answered": a["answered"]}
        if a["answered"] == 0:
            out[name] = {"percent": None, "level": NOT_ASSESSED, **counts}
        else:
            pct = round(100 * a["points"] / a["max"], 1)
            out[name] = {"percent": pct, "level": level_for(pct), **counts}
    return out


def governance(answers: dict[str, int]) -> list[dict[str, Any]]:
    return [
        {
            "id": it.id,
            "question": it.question,
            "source": it.source,
            "status": STATUS[answers[it.id]] if it.id in answers else NOT_ASSESSED,
        }
        for it in items()
        if it.area == GOVERNANCE_AREA
    ]


def levels(answers: dict[str, int]) -> dict[str, str]:
    """area -> level, for the rule engine (areas not yet assessed are left out)."""
    return {k: v["level"] for k, v in maturity(answers).items() if v["level"] != NOT_ASSESSED}


async def load_answers(session: AsyncSession, org_id: uuid.UUID) -> dict[str, int]:
    rows = await session.execute(
        select(AssessmentAnswer.item_id, AssessmentAnswer.score).where(
            AssessmentAnswer.org_id == org_id
        )
    )
    return {item_id: int(score) for item_id, score in rows.all()}


def check_answers(answers: dict[str, int | None]) -> None:
    known = {i.id for i in items()}
    for item_id, score in answers.items():
        if item_id not in known:
            raise ValueError(f"unknown item {item_id}")
        if score is not None and score not in (0, 1, 2):
            raise ValueError(f"{item_id}: the answer must be 0 (No), 1 (Partly) or 2 (Yes)")


async def save_answers(
    session: AsyncSession, org_id: uuid.UUID, who: str, answers: dict[str, int | None]
) -> None:
    """Upsert answers; ``None`` clears one. Unknown items and scores outside 0..2 are refused."""
    check_answers(answers)
    for item_id, score in answers.items():
        if score is None:
            await session.execute(
                delete(AssessmentAnswer).where(
                    AssessmentAnswer.org_id == org_id, AssessmentAnswer.item_id == item_id
                )
            )
            continue
        await session.execute(
            pg_insert(AssessmentAnswer)
            .values(org_id=org_id, item_id=item_id, score=score, updated_by=who)
            .on_conflict_do_update(
                index_elements=["org_id", "item_id"],
                set_={"score": score, "updated_by": who, "updated_at": func.now()},
            )
        )
