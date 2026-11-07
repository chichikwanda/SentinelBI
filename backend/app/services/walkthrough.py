"""Observation sheet for the practitioner walkthrough (the user acceptance tasks UAT1 to UAT5).

The researcher records, per participant code and task, whether the task was completed unaided, how
long it took and how many errors were seen, and, separately, participants' comments tagged with a
theme. Participants are identified by code only (P1, P2, ...), never by name. The summary is what
Tables 5.11 and 5.12 of the dissertation report: nothing is estimated, an empty sheet gives empty
tables.
"""

from __future__ import annotations

import re
import statistics
from typing import Any

TASKS: dict[str, str] = {
    "UAT1": "Find the highest-priority action",
    "UAT2": "Explain why it is recommended",
    "UAT3": "Identify the most detected threat and its confidence",
    "UAT4": "Say which governance obligations are not met",
    "UAT5": "Compare two assets",
}
THEMES: dict[str, str] = {
    "usefulness": "Perceived usefulness",
    "ease": "Ease of use without training",
    "clarity": "Clarity of explanations and sources",
    "improvement": "Suggested improvements",
}
CODE = re.compile(r"^P\d{1,3}$")


def valid_code(code: str) -> bool:
    return bool(CODE.match(code))


def summarise(tasks: list[dict[str, Any]], comments: list[dict[str, Any]]) -> dict[str, Any]:
    """Task rows and comment rows of the sheet in, the two summary tables out."""
    participants = sorted({t["participant"] for t in tasks} | {c["participant"] for c in comments})
    out_tasks = []
    for task_id, label in TASKS.items():
        rows = [t for t in tasks if t["task"] == task_id]
        # one row per participant counts: the latest record of a participant replaces an earlier one
        latest = {r["participant"]: r for r in rows}
        done = sum(1 for r in latest.values() if r["completed"])
        times = [r["seconds"] for r in latest.values() if r["seconds"] is not None]
        out_tasks.append(
            {
                "task": task_id,
                "description": label,
                "participants": len(latest),
                "completed": done,
                "mean_seconds": round(statistics.fmean(times)) if times else None,
                "errors": sum(r["errors"] for r in latest.values()),
            }
        )
    out_themes = []
    for key, label in THEMES.items():
        rows = [c for c in comments if c["theme"] == key]
        out_themes.append(
            {
                "theme": key,
                "label": label,
                "participants": len({c["participant"] for c in rows}),
                "comment": rows[-1]["text"] if rows else None,
            }
        )
    return {"participants": participants, "tasks": out_tasks, "themes": out_themes}
