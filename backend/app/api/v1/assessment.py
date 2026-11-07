"""The self-assessment of security practices and the governance indicators.

Answers (No / Partly / Yes) become a maturity level per control area. The level feeds the
recommendation rules: a weak area makes a detected threat more urgent and can, on its own, add
recommendations to the Actions page. Governance items are shown as In place / Partly in place / Gap.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.core.deps import AnalystDep, PrincipalDep, SessionDep
from app.core.enums import Role
from app.services import assessment
from app.services.prescriptive.service import refresh_org_recommendations

router = APIRouter(prefix="/assessment", tags=["assessment"])


class AssessmentIn(BaseModel):
    answers: dict[str, int | None]


async def _view(principal: PrincipalDep, session: SessionDep) -> dict[str, Any]:
    answers = await assessment.load_answers(session, principal.org_id)
    return {
        "can_edit": principal.role in (Role.ADMIN, Role.ANALYST),
        "items": [
            {
                "id": i.id,
                "area": i.area,
                "question": i.question,
                "source": i.source,
                "weight": i.weight,
                "answer": answers.get(i.id),
            }
            for i in assessment.items()
        ],
        "maturity": assessment.maturity(answers),
        "governance": assessment.governance(answers),
        "disclaimer": assessment.DISCLAIMER,
    }


@router.get("")
async def read_assessment(principal: PrincipalDep, session: SessionDep) -> dict[str, Any]:
    return await _view(principal, session)


@router.put("")
async def write_assessment(
    body: AssessmentIn, principal: AnalystDep, session: SessionDep
) -> dict[str, Any]:
    try:
        await assessment.save_answers(session, principal.org_id, principal.email, body.answers)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await refresh_org_recommendations(session, principal.org_id)
    await session.commit()
    return await _view(principal, session)
