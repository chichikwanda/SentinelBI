"""In-app SUS / TAM questionnaires, stored per user so results need no manual data entry."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.deps import AdminDep, PrincipalDep, SessionDep
from app.db.models import EvaluationResponse
from app.services import evaluation as ev

router = APIRouter(prefix="/evaluation", tags=["evaluation"])


class Answers(BaseModel):
    answers: list[int] = Field(min_length=1, max_length=50)


@router.get("/instruments")
async def instruments(_: PrincipalDep) -> dict[str, Any]:
    return {
        "sus": {"scale": [1, 5], "items": ev.SUS_ITEMS, "benchmark": ev.SUS_BENCHMARK},
        "tam": {
            "scale": [1, 7],
            "items": [{"construct": c, "text": t} for c, t in ev.TAM_ITEMS],
            "note": "Items adapted from Davis (1989).",
        },
    }


async def _store(
    session: SessionDep, principal: PrincipalDep, instrument: str, answers: list[int], result: Any
) -> None:
    session.add(
        EvaluationResponse(
            user_id=principal.user_id,
            org_id=principal.org_id,
            instrument=instrument,
            answers={"items": answers, "result": result},
        )
    )
    await session.commit()


@router.post("/sus", status_code=status.HTTP_201_CREATED)
async def submit_sus(
    body: Answers, principal: PrincipalDep, session: SessionDep
) -> dict[str, float]:
    try:
        score = ev.sus_score(body.answers)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await _store(session, principal, "SUS", body.answers, score)
    return {"score": score}


@router.post("/tam", status_code=status.HTTP_201_CREATED)
async def submit_tam(
    body: Answers, principal: PrincipalDep, session: SessionDep
) -> dict[str, float]:
    try:
        scores = ev.tam_scores(body.answers)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await _store(session, principal, "TAM", body.answers, scores)
    return scores


@router.get("/summary")
async def summary(admin: AdminDep, session: SessionDep) -> dict[str, Any]:
    """Aggregate for this organisation (latest response per user and instrument)."""
    rows = (
        await session.execute(
            select(EvaluationResponse)
            .where(EvaluationResponse.org_id == admin.org_id)
            .order_by(EvaluationResponse.submitted_at)
        )
    ).scalars()
    latest: dict[tuple[str, Any], list[int]] = {}
    for r in rows:
        latest[(r.instrument, r.user_id)] = [int(x) for x in cast(list[Any], r.answers["items"])]
    sus_rows = [v for (inst, _), v in latest.items() if inst == "SUS"]
    tam_rows = [v for (inst, _), v in latest.items() if inst == "TAM"]
    return ev.summarise(sus_rows, tam_rows)
