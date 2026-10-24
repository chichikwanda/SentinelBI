"""Serving-side feature construction.

Turns canonical flow records (the stream/DB schema) into the model input vector by renaming
to the raw NetFlow-style columns and calling the SAME ``build_features`` that training uses.
No feature logic lives here by design: see ``ml/src/features.py``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import pandas as pd

from sentinelbi_ml.features import build_features, canonical_to_raw

CANONICAL_COLUMNS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "tcp_flags",
    "in_bytes",
    "out_bytes",
    "in_pkts",
    "out_pkts",
    "duration_ms",
]


def records_to_frame(records: Iterable[Mapping[str, Any]]) -> pd.DataFrame:
    df = pd.DataFrame(list(records))
    for col in CANONICAL_COLUMNS:
        if col not in df.columns:
            df[col] = 0
    return df


def serving_features(df: pd.DataFrame) -> pd.DataFrame:
    features: pd.DataFrame = build_features(canonical_to_raw(df))
    return features
