"""Load, label-map, de-duplicate and split NF-UNSW-NB15-v2 (Phase 2).

Facts about the data that this module relies on were checked against the real files (see
data/DATASETS.md): 2,390,275 bidirectional flows, 43 features plus ``Label`` (0/1) and
``Attack`` (class name), and NO timestamp column, so no time-aware split is possible.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from sentinelbi_ml.features import BENIGN, FEATURE_INPUT_COLUMNS

DATASET_KEY = "nf-unsw-nb15-v2"

# UNSW-NB15 attack family -> common SentinelBI taxonomy (plan section 5.1).
# BruteForce has no examples in this dataset, so a model trained on it cannot predict it.
ATTACK_TO_CLASS: dict[str, str] = {
    "Benign": BENIGN,
    "DoS": "DoS/DDoS",
    "Reconnaissance": "Recon/Scan",
    "Backdoor": "Botnet/Backdoor",
    "Analysis": "WebAttack",  # host description: "threats that target web applications"
    "Fuzzers": "Exploit/Other",
    "Exploits": "Exploit/Other",
    "Generic": "Exploit/Other",
    "Shellcode": "Exploit/Other",
    "Worms": "Exploit/Other",
}


def find_csv(raw_root: Path) -> Path:
    matches = sorted((raw_root / DATASET_KEY).rglob("NF-UNSW-NB15-v2.csv"))
    if not matches:
        raise FileNotFoundError(
            f"NF-UNSW-NB15-v2.csv not found under {raw_root / DATASET_KEY}; run "
            f"`python -I -m sentinelbi_ml.download {DATASET_KEY}` first"
        )
    return matches[0]


def load_raw(
    csv_path: Path, limit: int | None = None, extra_columns: tuple[str, ...] = ()
) -> pd.DataFrame:
    """Read the columns the core feature set needs plus the labels. ``row`` is the 0-based
    data-row number in the CSV, kept so that held-out rows can be traced back later."""
    df = pd.read_csv(
        csv_path,
        # IP addresses are NOT loaded for training (identifier leakage); only the demo-sample
        # extractor opts in through ``extra_columns``.
        usecols=[*FEATURE_INPUT_COLUMNS, "Label", "Attack", *extra_columns],
        nrows=limit,
    )
    df["row"] = np.arange(len(df), dtype=np.int64)
    return df


def map_labels(df: pd.DataFrame) -> pd.DataFrame:
    unknown = sorted(set(df["Attack"].unique()) - set(ATTACK_TO_CLASS))
    if unknown:
        raise ValueError(f"unmapped attack classes (extend ATTACK_TO_CLASS): {unknown}")
    out = df.copy()
    out["label"] = out["Attack"].map(ATTACK_TO_CLASS)
    # sanity: the dataset's own binary label must agree with the mapped class
    inconsistent = int(((out["Label"] == 0) != (out["label"] == BENIGN)).sum())
    if inconsistent:
        raise ValueError(f"{inconsistent} rows disagree between Label and Attack")
    return out


def dedupe(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, int]]:
    """Drop rows identical in every model input AND label. Without this, copies of the same
    flow land in both train and test and inflate scores."""
    before = len(df)
    out = df.drop_duplicates(subset=[*FEATURE_INPUT_COLUMNS, "label"]).reset_index(drop=True)
    return out, {
        "rows_before": before,
        "rows_after": len(out),
        "duplicates_removed": before - len(out),
    }


def eda_summary(raw: pd.DataFrame, mapped: pd.DataFrame, deduped: pd.DataFrame) -> dict[str, Any]:
    num = mapped[FEATURE_INPUT_COLUMNS]
    return {
        "rows": len(raw),
        "attack_counts": {k: int(v) for k, v in raw["Attack"].value_counts().items()},
        "class_counts_mapped": {k: int(v) for k, v in mapped["label"].value_counts().items()},
        "class_counts_after_dedupe": {
            k: int(v) for k, v in deduped["label"].value_counts().items()
        },
        "duplicate_rate_by_class": {
            k: round(1 - int(deduped["label"].eq(k).sum()) / int(mapped["label"].eq(k).sum()), 4)
            for k in mapped["label"].unique()
        },
        "missing_values": {c: int(v) for c, v in num.isna().sum().items() if v},
        "feature_ranges": {
            c: {
                "min": float(num[c].min()),
                "median": float(num[c].median()),
                "p99": float(num[c].quantile(0.99)),
                "max": float(num[c].max()),
            }
            for c in FEATURE_INPUT_COLUMNS
        },
        "classes_without_examples": ["BruteForce"],
    }


def stratified_split(
    y: np.ndarray, seed: int, fractions: tuple[float, float, float] = (0.70, 0.15, 0.15)
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Index arrays (train, validation, test), stratified on ``y``. Random, not time-based
    (the dataset has no timestamps), which is optimistic: see the model card limitations."""
    from sklearn.model_selection import train_test_split

    idx = np.arange(len(y))
    train, rest = train_test_split(idx, train_size=fractions[0], stratify=y, random_state=seed)
    val_share = fractions[1] / (fractions[1] + fractions[2])
    val, test = train_test_split(rest, train_size=val_share, stratify=y[rest], random_state=seed)
    return train, val, test
