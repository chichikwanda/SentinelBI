"""Design rule 2: training and serving build the SAME feature vector from the same input.

Training path: raw NetFlow-style dataset rows -> ``build_features`` (what ``train.py`` calls).
Serving path : the same rows -> CSV-replay mapping -> API schema (``FlowIn``) -> stream JSON ->
               worker frame -> ``serving_features``.
Both must agree exactly, for the committed synthetic sample and for awkward edge cases.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.schemas.ingest import FlowIn
from app.services.features.builder import records_to_frame, serving_features
from app.services.ingestion.csv_replay import row_to_flow
from sentinelbi_ml.features import (
    CORE_FEATURES,
    FEATURE_INPUT_COLUMNS,
    build_features,
    port_bucket,
)

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "samples" / "synthetic_flows.csv"

EDGE_ROWS = [
    # zero duration, zero packets, max ports: guards divide-by-zero / inf handling
    {
        "IPV4_SRC_ADDR": "10.0.0.1",
        "L4_SRC_PORT": "0",
        "IPV4_DST_ADDR": "10.0.0.2",
        "L4_DST_PORT": "65535",
        "PROTOCOL": "6",
        "TCP_FLAGS": "0",
        "IN_BYTES": "0",
        "OUT_BYTES": "0",
        "IN_PKTS": "0",
        "OUT_PKTS": "0",
        "FLOW_DURATION_MILLISECONDS": "0",
    },
    {
        "IPV4_SRC_ADDR": "10.0.0.1",
        "L4_SRC_PORT": "1023",
        "IPV4_DST_ADDR": "10.0.0.2",
        "L4_DST_PORT": "1024",
        "PROTOCOL": "17",
        "TCP_FLAGS": "27",
        "IN_BYTES": "4294967296",
        "OUT_BYTES": "1",
        "IN_PKTS": "3",
        "OUT_PKTS": "0",
        "FLOW_DURATION_MILLISECONDS": "1",
    },
    # blanks (CSV exports often leave empty cells)
    {
        "IPV4_SRC_ADDR": "10.0.0.1",
        "L4_SRC_PORT": "",
        "IPV4_DST_ADDR": "10.0.0.2",
        "L4_DST_PORT": "",
        "PROTOCOL": "1",
        "TCP_FLAGS": "",
        "IN_BYTES": "",
        "OUT_BYTES": "",
        "IN_PKTS": "",
        "OUT_PKTS": "",
        "FLOW_DURATION_MILLISECONDS": "",
    },
]


def _training_frame(rows: list[dict[str, str]]) -> pd.DataFrame:
    """Raw dataset rows as a training script would load them (numeric dtypes, NaN for blanks)."""
    df = pd.DataFrame(rows)
    for col in FEATURE_INPUT_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def _serving_frame(rows: list[dict[str, str]]) -> pd.DataFrame:
    """Same rows through replay mapping -> API schema -> stream JSON -> worker frame."""
    records = []
    for row in rows:
        flow = FlowIn.model_validate(row_to_flow(row))
        wire = json.loads(flow.model_dump_json())  # what ingest writes to Redis
        parsed = FlowIn.model_validate_json(json.dumps(wire))  # what the worker reads back
        records.append(parsed.model_dump(mode="python"))
    return serving_features(records_to_frame(records))


def _read_sample() -> list[dict[str, str]]:
    with SAMPLE.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_sample_is_present_and_nonempty() -> None:
    assert len(_read_sample()) > 100


def test_training_and_serving_vectors_are_identical_on_the_sample() -> None:
    rows = _read_sample()
    train = build_features(_training_frame(rows))
    serve = _serving_frame(rows)
    assert list(train.columns) == list(serve.columns) == CORE_FEATURES
    pd.testing.assert_frame_equal(
        train.reset_index(drop=True), serve.reset_index(drop=True), check_exact=True
    )


def test_training_and_serving_vectors_are_identical_on_edge_cases() -> None:
    train = build_features(_training_frame(EDGE_ROWS))
    serve = _serving_frame(EDGE_ROWS)
    pd.testing.assert_frame_equal(
        train.reset_index(drop=True), serve.reset_index(drop=True), check_exact=True
    )
    assert np.isfinite(serve.to_numpy()).all()  # no inf/NaN ever reaches a model


def test_features_are_deterministic_and_row_independent() -> None:
    df = _training_frame(_read_sample())
    once = build_features(df)
    twice = build_features(df.copy())
    pd.testing.assert_frame_equal(once, twice, check_exact=True)
    # a row's vector must not depend on which other rows are in the batch
    pd.testing.assert_frame_equal(
        build_features(df.iloc[[5]]).reset_index(drop=True),
        once.iloc[[5]].reset_index(drop=True),
        check_exact=True,
    )


def test_missing_input_columns_fail_loudly() -> None:
    df = _training_frame(EDGE_ROWS).drop(columns=["IN_PKTS"])
    with pytest.raises(ValueError, match="IN_PKTS"):
        build_features(df)


def test_port_buckets() -> None:
    buckets = port_bucket(pd.Series([0, 1, 1023, 1024, 49151, 49152, 65535]))
    assert buckets.tolist() == [0, 1, 1, 2, 2, 3, 3]
