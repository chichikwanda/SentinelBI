"""SUS/TAM scoring and the CSV/PDF reports."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from conftest import PASSWORD, Tenant, add_source, register_org, scan_flows, unique_email
from redis.asyncio import Redis
from test_worker import drain, ingest

from app.core.config import Settings
from app.services import evaluation as ev
from app.services.reports import _cell


def test_sus_scoring_matches_the_standard_formula() -> None:
    best = [5, 1, 5, 1, 5, 1, 5, 1, 5, 1]  # strongly agree with positives, disagree with negatives
    worst = [1, 5, 1, 5, 1, 5, 1, 5, 1, 5]
    assert ev.sus_score(best) == 100.0
    assert ev.sus_score(worst) == 0.0
    assert ev.sus_score([3] * 10) == 50.0
    with pytest.raises(ValueError, match="SUS"):
        ev.sus_score([3] * 9)
    with pytest.raises(ValueError, match="SUS"):
        ev.sus_score([6] + [3] * 9)


def test_tam_constructs_and_reliability() -> None:
    answers = [7, 7, 7, 7, 4, 4, 4, 4, 1, 3]  # PU x4, PEOU x4, BI x2
    assert ev.tam_scores(answers) == {"PU": 7.0, "PEOU": 4.0, "BI": 2.0}
    assert ev.cronbach_alpha([[1, 1], [2, 2], [3, 3]]) == 1.0  # perfectly consistent items
    assert ev.cronbach_alpha([[1, 2]]) is None  # needs at least two respondents
    assert ev.cronbach_alpha([[3, 3], [3, 3]]) is None  # no variance


async def test_questionnaires_are_stored_and_summarised_per_organisation(
    client: httpx.AsyncClient,
) -> None:
    admin = await register_org(client, "Eval Org")
    ins = (await client.get("/api/v1/evaluation/instruments", headers=admin.headers)).json()
    assert len(ins["sus"]["items"]) == 10 and len(ins["tam"]["items"]) == 10

    r = await client.post(
        "/api/v1/evaluation/sus",
        json={"answers": [5, 1, 5, 1, 5, 1, 5, 1, 5, 1]},
        headers=admin.headers,
    )
    assert r.status_code == 201 and r.json() == {"score": 100.0}
    r = await client.post(
        "/api/v1/evaluation/tam", json={"answers": [6] * 10}, headers=admin.headers
    )
    assert r.status_code == 201 and r.json()["PU"] == 6.0
    bad = await client.post(
        "/api/v1/evaluation/sus", json={"answers": [9] * 10}, headers=admin.headers
    )
    assert bad.status_code == 422

    # a second user's response counts; a resubmission replaces the user's earlier one
    email = unique_email("analyst")
    await client.post(
        "/api/v1/users",
        json={"email": email, "password": PASSWORD, "role": "analyst"},
        headers=admin.headers,
    )
    token = (
        await client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    ).json()["access_token"]
    analyst = {"Authorization": f"Bearer {token}"}
    await client.post("/api/v1/evaluation/sus", json={"answers": [3] * 10}, headers=analyst)
    await client.post(
        "/api/v1/evaluation/sus", json={"answers": [1, 5, 1, 5, 1, 5, 1, 5, 1, 5]}, headers=analyst
    )  # latest wins

    summary = (await client.get("/api/v1/evaluation/summary", headers=admin.headers)).json()
    assert summary["sus"]["n"] == 2 and summary["sus"]["mean"] == 50.0  # (100 + 0) / 2
    assert summary["sus"]["above_benchmark"] is False
    assert (
        await client.get("/api/v1/evaluation/summary", headers=analyst)
    ).status_code == 403  # admin only

    other = await register_org(client, "Other Eval Org")
    assert (await client.get("/api/v1/evaluation/summary", headers=other.headers)).json()["sus"][
        "n"
    ] == 0


def test_csv_cells_cannot_inject_spreadsheet_formulas() -> None:
    assert _cell('=HYPERLINK("http://evil")') == '\'=HYPERLINK("http://evil")'
    assert _cell("+1+1") == "'+1+1" and _cell("-2") == "'-2" and _cell("@SUM(A1)") == "'@SUM(A1)"
    assert _cell("plain text") == "plain text" and _cell(None) == ""


async def _alert_for(
    client: httpx.AsyncClient, t: Tenant, redis: Redis, sm: Any, settings: Settings
) -> dict[str, Any]:
    await ingest(client, t, scan_flows(12))
    await drain(redis, sm, settings)
    return (await client.get("/api/v1/alerts", headers=t.headers)).json()[0]  # type: ignore[no-any-return]


async def test_csv_export_is_scoped_and_escaped(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    alert = await _alert_for(client, tenant, redis, sessionmaker, settings)
    await client.patch(
        f"/api/v1/alerts/{alert['id']}",
        json={"analyst_label": "=cmd|' /C calc'!A0"},
        headers=tenant.headers,
    )

    resp = await client.get("/api/v1/reports/alerts.csv", headers=tenant.headers)
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers["content-disposition"]
    lines = resp.text.strip().splitlines()
    assert lines[0].split(",")[:5] == ["id", "first_seen", "last_seen", "attack_class", "severity"]
    assert len(lines) == 2 and "203.0.113.50" in lines[1]
    assert "'=cmd" in lines[1] and ",=cmd" not in lines[1]  # formula neutralised

    other = await register_org(client, "No Alerts Org")
    assert (
        len(
            (await client.get("/api/v1/reports/alerts.csv", headers=other.headers))
            .text.strip()
            .splitlines()
        )
        == 1
    )


async def test_pdf_summary_is_a_pdf_for_the_callers_org(
    client: httpx.AsyncClient, tenant: Tenant, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    await _alert_for(client, tenant, redis, sessionmaker, settings)
    resp = await client.get("/api/v1/reports/summary.pdf", headers=tenant.headers)
    assert resp.status_code == 200 and resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF") and len(resp.content) > 1500
    assert (await client.get("/api/v1/reports/summary.pdf")).status_code == 401

    other = await register_org(
        client, "Quiet Org"
    )  # an org with nothing to report still gets a valid PDF
    quiet = await client.get("/api/v1/reports/summary.pdf", headers=other.headers)
    assert quiet.status_code == 200 and quiet.content.startswith(b"%PDF")
    _ = add_source  # imported for symmetry with other test modules
