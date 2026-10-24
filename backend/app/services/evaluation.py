"""SUS and TAM questionnaires (objective 5): items, scoring and reliability.

SUS: Brooke (1996), the standard 10 items, 1-5 agreement scale; score 0-100, benchmark 68.
TAM: items adapted from Davis (1989) to this system; 1-7 agreement scale, reported as the mean
of each construct (PU, PEOU, BI) with Cronbach's alpha once there are enough respondents.
"""

from __future__ import annotations

import statistics
from typing import Any

SUS_BENCHMARK = 68.0

SUS_ITEMS = [
    "I think that I would like to use this system frequently.",
    "I found the system unnecessarily complex.",
    "I thought the system was easy to use.",
    "I think that I would need the support of a technical person to be able to use this system.",
    "I found the various functions in this system were well integrated.",
    "I thought there was too much inconsistency in this system.",
    "I would imagine that most people would learn to use this system very quickly.",
    "I found the system very cumbersome to use.",
    "I felt very confident using the system.",
    "I needed to learn a lot of things before I could get going with this system.",
]

# (construct, text)
TAM_ITEMS: list[tuple[str, str]] = [
    ("PU", "Using this system would help me detect security threats on my network more quickly."),
    (
        "PU",
        "Using this system would improve my ability to decide what to do about a security risk.",
    ),
    ("PU", "Using this system would make my organisation's network more secure."),
    ("PU", "I would find this system useful in my work."),
    ("PEOU", "Learning to operate this system would be easy for me."),
    ("PEOU", "I would find it easy to get this system to do what I want it to do."),
    ("PEOU", "The alerts and recommendations in this system are clear and understandable."),
    ("PEOU", "I would find this system easy to use."),
    ("BI", "I intend to use a system like this regularly if it were available."),
    ("BI", "I would recommend this system to other organisations like mine."),
]


def sus_score(answers: list[int]) -> float:
    """Odd items contribute (answer - 1), even items (5 - answer); the sum is scaled by 2.5."""
    if len(answers) != 10 or any(not 1 <= a <= 5 for a in answers):
        raise ValueError("SUS needs 10 answers between 1 and 5")
    total = sum((a - 1) if i % 2 == 0 else (5 - a) for i, a in enumerate(answers))
    return total * 2.5


def tam_scores(answers: list[int]) -> dict[str, float]:
    if len(answers) != len(TAM_ITEMS) or any(not 1 <= a <= 7 for a in answers):
        raise ValueError(f"TAM needs {len(TAM_ITEMS)} answers between 1 and 7")
    out: dict[str, list[int]] = {}
    for (construct, _), a in zip(TAM_ITEMS, answers, strict=True):
        out.setdefault(construct, []).append(a)
    return {k: round(sum(v) / len(v), 2) for k, v in out.items()}


def cronbach_alpha(rows: list[list[int]]) -> float | None:
    """rows = respondents x items. None when it cannot be computed (n < 2 or no variance)."""
    n, k = len(rows), len(rows[0]) if rows else 0
    if n < 2 or k < 2:
        return None
    item_vars = [statistics.variance([r[j] for r in rows]) for j in range(k)]
    total_var = statistics.variance([sum(r) for r in rows])
    if total_var == 0:
        return None
    return round(k / (k - 1) * (1 - sum(item_vars) / total_var), 3)


def summarise(sus_rows: list[list[int]], tam_rows: list[list[int]]) -> dict[str, Any]:
    scores = [sus_score(r) for r in sus_rows]
    pu_idx = [i for i, (c, _) in enumerate(TAM_ITEMS) if c == "PU"]
    peou_idx = [i for i, (c, _) in enumerate(TAM_ITEMS) if c == "PEOU"]
    tam = [tam_scores(r) for r in tam_rows]
    return {
        "sus": {
            "n": len(scores),
            "mean": round(statistics.fmean(scores), 1) if scores else None,
            "sd": round(statistics.stdev(scores), 1) if len(scores) > 1 else None,
            "benchmark": SUS_BENCHMARK,
            "above_benchmark": (statistics.fmean(scores) > SUS_BENCHMARK) if scores else None,
        },
        "tam": {
            "n": len(tam),
            "means": {
                c: round(statistics.fmean(t[c] for t in tam), 2) for c in ("PU", "PEOU", "BI")
            }
            if tam
            else None,
            "cronbach_alpha": {
                "PU": cronbach_alpha([[r[i] for i in pu_idx] for r in tam_rows]),
                "PEOU": cronbach_alpha([[r[i] for i in peou_idx] for r in tam_rows]),
            },
        },
    }
