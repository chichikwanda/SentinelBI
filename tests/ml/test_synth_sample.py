"""The committed synthetic sample must stay reproducible from its generator."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from sentinelbi_ml.features import CANONICAL_TO_RAW, RAW_TO_CANONICAL
from sentinelbi_ml.synth_sample import COLUMNS, render_csv

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "samples" / "synthetic_flows.csv"


def test_committed_sample_matches_generator() -> None:
    assert SAMPLE.read_text(encoding="utf-8") == render_csv(), (
        "data/samples/synthetic_flows.csv is stale: run "
        "`python -m sentinelbi_ml.synth_sample --out data/samples/synthetic_flows.csv`"
    )


def test_generator_is_deterministic() -> None:
    assert render_csv() == render_csv()


def test_sample_composition() -> None:
    rows = list(csv.DictReader(io.StringIO(render_csv())))
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["Attack"]] = counts.get(r["Attack"], 0) + 1
    assert counts == {"Benign": 600, "Recon/Scan": 80, "DoS/DDoS": 25}


def test_columns_cover_the_canonical_mapping() -> None:
    assert set(CANONICAL_TO_RAW.values()) <= set(COLUMNS)
    assert set(RAW_TO_CANONICAL) == set(CANONICAL_TO_RAW.values())
