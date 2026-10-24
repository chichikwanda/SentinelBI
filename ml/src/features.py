"""Single source of truth for flow features: used by training AND serving.

Everything that turns a flow record into a model input vector lives here. The API
worker imports this module (``sentinelbi_ml.features``); ``train.py`` imports the same
one. ``tests/backend/test_feature_parity.py`` proves both paths give identical vectors.

NOTE (unverified until Phase 2): the raw column names below follow the NetFlow-v2
(NF-*-v2) naming given in the project plan. They must be checked against the real CSV
headers when the datasets are downloaded. That is a one-place change: ``CANONICAL_TO_RAW``.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# --- label taxonomy (plan section 5.1) ---------------------------------------------
BENIGN = "Benign"
CLASSES: list[str] = [
    BENIGN,
    "DoS/DDoS",
    "Recon/Scan",
    "BruteForce",
    "Botnet/Backdoor",
    "WebAttack",
    "Exploit/Other",
]

# --- schema mapping ------------------------------------------------------------------
# canonical flow field (API / stream / DB)  ->  raw NetFlow-style column (datasets, training)
CANONICAL_TO_RAW: dict[str, str] = {
    "src_ip": "IPV4_SRC_ADDR",
    "src_port": "L4_SRC_PORT",
    "dst_ip": "IPV4_DST_ADDR",
    "dst_port": "L4_DST_PORT",
    "protocol": "PROTOCOL",
    "tcp_flags": "TCP_FLAGS",
    "in_bytes": "IN_BYTES",
    "out_bytes": "OUT_BYTES",
    "in_pkts": "IN_PKTS",
    "out_pkts": "OUT_PKTS",
    "duration_ms": "FLOW_DURATION_MILLISECONDS",
}
RAW_TO_CANONICAL: dict[str, str] = {v: k for k, v in CANONICAL_TO_RAW.items()}

# Epoch-millisecond flow start. Optional in datasets; becomes the canonical `ts`.
RAW_TS_COLUMN = "FLOW_START_MILLISECONDS"

# Raw columns that feed the features (identifiers such as IPs are NOT inputs: leakage).
FEATURE_INPUT_COLUMNS: list[str] = [
    "PROTOCOL",
    "L4_SRC_PORT",
    "L4_DST_PORT",
    "TCP_FLAGS",
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
    "FLOW_DURATION_MILLISECONDS",
]

# --- features the router can export (the "core NetFlow" set) --------------------------
CORE_FEATURES: list[str] = [
    "PROTOCOL",
    "L4_SRC_PORT_BUCKET",
    "L4_DST_PORT_BUCKET",
    "TCP_FLAGS",
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
    "FLOW_DURATION_MS",
    "BYTES_PER_PKT_IN",
    "BYTES_PER_PKT_OUT",
    "BYTES_PER_SEC",
    "PKTS_PER_SEC",
    "IN_OUT_BYTE_RATIO",
]


def port_bucket(port: pd.Series) -> pd.Series:
    """0 = port 0, 1 = well-known (1-1023), 2 = registered (1024-49151), 3 = ephemeral."""
    p = port.to_numpy(dtype="float64")
    out = np.select([p <= 0, p < 1024, p < 49152], [0, 1, 2], default=3)
    return pd.Series(out, index=port.index, dtype="float64")


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Deterministically map raw NetFlow-style rows to ``CORE_FEATURES``.

    Pure function of its input: no fitted state, so training and serving cannot drift.
    Scaling / log transforms are fitted on the training split only and live in the
    exported sklearn pipeline, not here.
    """
    missing = [c for c in FEATURE_INPUT_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"missing raw columns for feature building: {missing}")

    raw = df[FEATURE_INPUT_COLUMNS].apply(pd.to_numeric, errors="coerce").astype("float64")
    raw = raw.fillna(0.0).clip(lower=0.0)

    dur_s = np.maximum(raw["FLOW_DURATION_MILLISECONDS"], 1.0) / 1000.0
    total_bytes = raw["IN_BYTES"] + raw["OUT_BYTES"]
    total_pkts = raw["IN_PKTS"] + raw["OUT_PKTS"]

    out = pd.DataFrame(index=df.index)
    out["PROTOCOL"] = raw["PROTOCOL"]
    out["L4_SRC_PORT_BUCKET"] = port_bucket(raw["L4_SRC_PORT"])
    out["L4_DST_PORT_BUCKET"] = port_bucket(raw["L4_DST_PORT"])
    out["TCP_FLAGS"] = raw["TCP_FLAGS"]
    out["IN_BYTES"] = raw["IN_BYTES"]
    out["OUT_BYTES"] = raw["OUT_BYTES"]
    out["IN_PKTS"] = raw["IN_PKTS"]
    out["OUT_PKTS"] = raw["OUT_PKTS"]
    out["FLOW_DURATION_MS"] = raw["FLOW_DURATION_MILLISECONDS"]
    out["BYTES_PER_PKT_IN"] = raw["IN_BYTES"] / np.maximum(raw["IN_PKTS"], 1.0)
    out["BYTES_PER_PKT_OUT"] = raw["OUT_BYTES"] / np.maximum(raw["OUT_PKTS"], 1.0)
    out["BYTES_PER_SEC"] = total_bytes / dur_s
    out["PKTS_PER_SEC"] = total_pkts / dur_s
    out["IN_OUT_BYTE_RATIO"] = raw["IN_BYTES"] / (raw["OUT_BYTES"] + 1.0)

    out = out.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return out[CORE_FEATURES].astype("float64")


def canonical_to_raw(df: pd.DataFrame) -> pd.DataFrame:
    """Rename canonical flow fields (API/stream/DB) to the raw NetFlow-style columns."""
    return df.rename(columns=CANONICAL_TO_RAW)


def raw_to_canonical(df: pd.DataFrame) -> pd.DataFrame:
    """Rename raw dataset columns to canonical flow fields, keeping only mapped columns."""
    keep = [c for c in df.columns if c in RAW_TO_CANONICAL]
    return df[keep].rename(columns=RAW_TO_CANONICAL)
