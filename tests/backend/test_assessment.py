"""Self-assessment, maturity levels, governance indicators and the threat-by-maturity rules."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from conftest import PASSWORD, Tenant, unique_email

from app.core.enums import Role
from app.db.models import Alert
from app.db.session import get_sessionmaker
from app.services import assessment
from app.services.prescriptive.engine import (
    AlertContext,
    load_rules,
    recommend,
    recommend_from_profile,
)

AREA = "Access control"


def _answers(area: str, score: int) -> dict[str, int]:
    return {i.id: score for i in assessment.items() if i.area == area}


def test_there_are_eighteen_items_four_of_them_governance() -> None:
    items = assessment.items()
    assert len(items) == 18
    assert sum(1 for i in items if i.area == assessment.GOVERNANCE_AREA) == 4
    assert {i.weight for i in items} <= {1, 2}


@pytest.mark.parametrize(("score", "level"), [(0, "Low"), (1, "Medium"), (2, "High")])
def test_levels_follow_the_80_and_50_percent_bands(score: int, level: str) -> None:
    m = assessment.maturity(_answers(AREA, score))
    assert m[AREA]["level"] == level
    assert m["Email security"]["level"] == assessment.NOT_ASSESSED  # never guessed


def test_weights_count_and_boundaries_are_inclusive() -> None:
    # AC1, AC2 weight 2; AC3, AC4 weight 1: Yes on both heavy items, No on the light ones = 4/6
    answers = {"AC1": 2, "AC2": 2, "AC3": 0, "AC4": 0}
    assert assessment.maturity(answers)[AREA]["percent"] == pytest.approx(66.7, abs=0.05)
    assert assessment.level_for(80.0) == "High" and assessment.level_for(50.0) == "Medium"
    assert assessment.level_for(49.9) == "Low"


def test_governance_status_is_per_item() -> None:
    g = {x["id"]: x["status"] for x in assessment.governance({"GV1": 2, "GV2": 1, "GV3": 0})}
    assert g == {"GV1": "In place", "GV2": "Partly in place", "GV3": "Gap", "GV4": "Not assessed"}


def test_all_fifteen_maturity_rules_load() -> None:
    mat = [r for r in load_rules() if r.when.weak_area]
    assert len(mat) == 15
    assert sum(1 for r in mat if r.when.profile_only) == 5


def test_threat_rules_fire_only_on_a_weak_assessed_area_and_low_raises_priority() -> None:
    def ids(maturity: dict[str, str]) -> dict[str, int]:
        ctx = AlertContext("BruteForce", "High", 2, frozenset({22}), maturity)
        return {r.rule_id: r.priority for r in recommend(ctx)}

    assert "RULE-MAT-002" not in ids({})  # not assessed: no guess
    assert "RULE-MAT-002" not in ids({"Network security": "High"})
    assert ids({"Network security": "Medium"})["RULE-MAT-002"] == 2
    assert ids({"Network security": "Low"})["RULE-MAT-002"] == 1  # one step more urgent


def test_profile_only_rules_need_no_alert() -> None:
    recs = recommend_from_profile({"Backup and recovery": "Medium", "Email security": "High"})
    assert {r.rule_id for r in recs} == {"RULE-MAT-013"}
    assert recommend_from_profile({}) == []


async def test_assessment_round_trip_and_validation(
    client: httpx.AsyncClient, tenant: Tenant
) -> None:
    first = (await client.get("/api/v1/assessment", headers=tenant.headers)).json()
    assert len(first["items"]) == 18 and first["can_edit"] is True
    assert all(v["level"] == "Not assessed" for v in first["maturity"].values())
    r = await client.put(
        "/api/v1/assessment", json={"answers": _answers(AREA, 0)}, headers=tenant.headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["maturity"][AREA]["level"] == "Low"
    for bad in ({"ZZ9": 1}, {"AC1": 5}):
        assert (
            await client.put("/api/v1/assessment", json={"answers": bad}, headers=tenant.headers)
        ).status_code == 422
    cleared = await client.put(
        "/api/v1/assessment",
        json={"answers": dict.fromkeys(_answers(AREA, 0))},
        headers=tenant.headers,
    )
    assert cleared.json()["maturity"][AREA]["level"] == assessment.NOT_ASSESSED


async def test_a_viewer_can_read_but_not_answer(client: httpx.AsyncClient, tenant: Tenant) -> None:
    email = unique_email("viewer")
    made = await client.post(
        "/api/v1/users",
        json={"email": email, "password": PASSWORD, "role": Role.VIEWER.value},
        headers=tenant.headers,
    )
    assert made.status_code == 201
    login = await client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await client.get("/api/v1/assessment", headers=headers)).status_code == 200
    denied = await client.put("/api/v1/assessment", json={"answers": {"AC1": 2}}, headers=headers)
    assert denied.status_code == 403


async def test_weak_areas_add_profile_actions_and_improving_removes_them(
    client: httpx.AsyncClient, tenant: Tenant
) -> None:
    await client.put(
        "/api/v1/assessment",
        json={"answers": _answers("Backup and recovery", 0)},
        headers=tenant.headers,
    )
    recs = (await client.get("/api/v1/recommendations", headers=tenant.headers)).json()
    profile = [r for r in recs if r["alert"] is None]
    assert [r["rule_id"] for r in profile] == ["RULE-MAT-013"]
    assert {x["framework"] for x in profile[0]["references"]} >= {"cis", "nist"}
    await client.put(
        "/api/v1/assessment",
        json={"answers": _answers("Backup and recovery", 2)},
        headers=tenant.headers,
    )
    recs = (await client.get("/api/v1/recommendations", headers=tenant.headers)).json()
    assert [r for r in recs if r["alert"] is None] == []


async def test_a_weak_area_adds_actions_to_an_alert_that_already_exists(
    client: httpx.AsyncClient, tenant: Tenant
) -> None:
    now = datetime.now(UTC)
    async with get_sessionmaker()() as s:
        alert = Alert(
            org_id=tenant.org_id,
            first_seen=now,
            last_seen=now,
            attack_class="BruteForce",
            severity="High",
            risk_score=60.0,
            count=9,
            evidence={"criticality": 2, "dst_ports_sample": [22]},
        )
        s.add(alert)
        await s.commit()
        alert_id = str(alert.id)
    await client.put(
        "/api/v1/assessment",
        json={"answers": _answers("Network security", 0)},
        headers=tenant.headers,
    )
    recs = (
        await client.get(f"/api/v1/recommendations?alert_id={alert_id}", headers=tenant.headers)
    ).json()
    assert "RULE-MAT-002" in {r["rule_id"] for r in recs}
