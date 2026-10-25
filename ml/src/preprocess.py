"""Load, label-map, de-duplicate and split the NF-v2 NetFlow datasets (Phase 2).

Facts about the data that this module relies on were checked against the real files (see
data/DATASETS.md): bidirectional flows, 43 features plus ``Label`` (0/1) and ``Attack`` (class
name), and NO timestamp column, so no time-aware split is possible.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from sentinelbi_ml.features import BENIGN, FEATURE_INPUT_COLUMNS

DEFAULT_DATASET = "nf-unsw-nb15-v2"


# --- label mapping to the project taxonomy (plan section 5.1) --------------------------------------
# UNSW-NB15 attack family -> taxonomy. BruteForce has no examples in this dataset.
UNSW_MAP: dict[str, str] = {
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


def cse_cic_class(name: str) -> str | None:
    """CSE-CIC-IDS2018 attack name -> taxonomy, or None if the name is not recognised.

    Rules (case-insensitive, so 'DDOS'/'DDoS' both work): DoS/DDoS families -> DoS/DDoS;
    FTP/SSH brute force -> BruteForce; web attacks (web-login brute force, XSS, SQL injection) ->
    WebAttack; Bot -> Botnet/Backdoor; Infiltration -> Exploit/Other.
    """
    n = name.strip().lower()
    if n == "benign":
        return BENIGN
    if n.startswith(("ddos", "dos")):
        return "DoS/DDoS"
    # Same grouping as the host's published table (checked: SSH + FTP brute force = its
    # "BruteForce" 120,912; Brute Force -Web + -XSS + SQL Injection = its "Web Attacks" 3,502).
    if n in {"bruteforce", "ftp-bruteforce", "ssh-bruteforce"}:
        return "BruteForce"
    if n in {"web attacks", "web attack", "brute force -web", "brute force -xss", "sql injection"}:
        return "WebAttack"
    if n == "bot":
        return "Botnet/Backdoor"
    if n.startswith("infil"):  # the dataset spells it 'Infilteration'
        return "Exploit/Other"
    return None


@dataclass(frozen=True)
class DatasetSpec:
    key: str
    name: str
    csv_name: str
    classify: Callable[[str], str | None]


SPECS: dict[str, DatasetSpec] = {
    "nf-unsw-nb15-v2": DatasetSpec(
        "nf-unsw-nb15-v2", "NF-UNSW-NB15-v2", "NF-UNSW-NB15-v2.csv", UNSW_MAP.get
    ),
    "nf-cse-cic-ids2018-v2": DatasetSpec(
        "nf-cse-cic-ids2018-v2", "NF-CSE-CIC-IDS2018-v2", "NF-CSE-CIC-IDS2018-v2.csv", cse_cic_class
    ),
}

# kept for callers that import the original name
ATTACK_TO_CLASS = UNSW_MAP


def find_csv(raw_root: Path, key: str = DEFAULT_DATASET) -> Path:
    spec = SPECS[key]
    matches = sorted((raw_root / key).rglob(spec.csv_name))
    if not matches:
        raise FileNotFoundError(
            f"{spec.csv_name} not found under {raw_root / key}; run "
            f"`python -I -m sentinelbi_ml.download {key}` first"
        )
    return matches[0]


def sha256_file(path: Path, chunk: int = 1 << 24) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            digest.update(block)
    return digest.hexdigest()


def verify_sha256(path: Path, expected: str) -> None:
    """Refuse a dataset file whose bytes differ from the SHA-256 recorded when it was downloaded.

    The checksum in a model card is only a claim about the training data if the file is checked
    against it. A damaged file (bit rot, a bad disk or memory module) otherwise trains silently."""
    actual = sha256_file(path)
    if actual != expected:
        raise ValueError(
            f"{path.name} does not match its recorded SHA-256 ({actual[:16]}... != {expected[:16]}...): "
            "the file is damaged. Re-extract it with `python -I -m sentinelbi_ml.download <key> "
            "--out data/raw --reextract`, and if it keeps happening suspect the disk or RAM."
        )


def load_raw(
    csv_path: Path,
    limit: int | None = None,
    extra_columns: tuple[str, ...] = (),
    benign_keep: float = 1.0,
    seed: int = 0,
) -> pd.DataFrame:
    """Read the columns the core feature set needs plus the labels.

    ``row`` is the 0-based data-row number in the CSV (kept so held-out rows can be traced back).
    With ``benign_keep < 1`` the file is read in chunks, EVERY attack row is kept and benign rows
    are sampled with that probability, so multi-GB files fit in memory.
    """
    cols = [*FEATURE_INPUT_COLUMNS, "Label", "Attack", *extra_columns]
    # IP addresses are NOT loaded for training (identifier leakage); only the demo-sample
    # extractor opts in through ``extra_columns``.
    if benign_keep >= 1.0:
        df = pd.read_csv(csv_path, usecols=cols, nrows=limit)
        df["row"] = np.arange(len(df), dtype=np.int64)
        return df

    rng = np.random.default_rng(seed)
    parts: list[pd.DataFrame] = []
    offset = 0
    for chunk in pd.read_csv(csv_path, usecols=cols, chunksize=1_000_000, nrows=limit):
        chunk["row"] = np.arange(offset, offset + len(chunk), dtype=np.int64)
        offset += len(chunk)
        keep = (chunk["Label"] != 0) | (rng.random(len(chunk)) < benign_keep)
        parts.append(chunk[keep])
    return pd.concat(parts, ignore_index=True)


def load_rows(csv_path: Path, rows: set[int], extra_columns: tuple[str, ...] = ()) -> pd.DataFrame:
    """Read only the given 0-based data rows (chunked), with the optional extra columns."""
    cols = [*FEATURE_INPUT_COLUMNS, "Label", "Attack", *extra_columns]
    parts: list[pd.DataFrame] = []
    offset = 0
    for chunk in pd.read_csv(csv_path, usecols=cols, chunksize=1_000_000):
        idx = np.arange(offset, offset + len(chunk), dtype=np.int64)
        mask = (
            np.isin(idx, np.fromiter(rows, dtype=np.int64)) if rows else np.zeros(len(chunk), bool)
        )
        sel = chunk[mask].copy()
        sel["row"] = idx[mask]
        parts.append(sel)
        offset += len(chunk)
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=[*cols, "row"])


def map_labels(df: pd.DataFrame, spec: DatasetSpec | None = None) -> pd.DataFrame:
    spec = spec or SPECS[DEFAULT_DATASET]
    mapping = {a: spec.classify(a) for a in df["Attack"].unique()}
    unknown = sorted(a for a, c in mapping.items() if c is None)
    if unknown:
        raise ValueError(f"{spec.name}: unmapped attack classes (extend the mapping): {unknown}")
    out = df.copy()
    out["label"] = out["Attack"].map(mapping)
    # sanity: the dataset's own binary label must agree with the mapped class
    inconsistent = int(((out["Label"] == 0) != (out["label"] == BENIGN)).sum())
    if inconsistent:
        raise ValueError(f"{spec.name}: {inconsistent} rows disagree between Label and Attack")
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
        "rows_read": len(raw),
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
    }


def stratified_split(
    strata: np.ndarray, seed: int, fractions: tuple[float, float, float] = (0.70, 0.15, 0.15)
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Index arrays (train, validation, test), stratified on ``strata`` (label, and dataset when
    several are combined). Random, not time-based (the datasets have no timestamps), which is
    optimistic: see the model card limitations."""
    from sklearn.model_selection import train_test_split

    idx = np.arange(len(strata))
    train, rest = train_test_split(idx, train_size=fractions[0], stratify=strata, random_state=seed)
    val_share = fractions[1] / (fractions[1] + fractions[2])
    val, test = train_test_split(
        rest, train_size=val_share, stratify=strata[rest], random_state=seed
    )
    return train, val, test
