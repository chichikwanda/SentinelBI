"""Metrics for model comparison (Phase 2). Accuracy is reported but is NOT the headline metric:
with ~96% benign traffic it is nearly meaningless; use macro-F1, per-class F1 and false alarms."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from sentinelbi_ml.features import BENIGN


def evaluate(y_true: np.ndarray, proba: np.ndarray, classes: list[str]) -> dict[str, Any]:
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
        roc_auc_score,
    )

    y_pred = proba.argmax(axis=1)
    labels = list(range(len(classes)))
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    macro = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="macro", zero_division=0
    )
    weighted = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="weighted", zero_division=0
    )
    benign = classes.index(BENIGN)
    is_benign_true = y_true == benign
    is_benign_pred = y_pred == benign
    try:
        auc = float(roc_auc_score(y_true, proba, multi_class="ovr", average="macro", labels=labels))
    except ValueError:  # a class missing from y_true
        auc = float("nan")
    return {
        "n": len(y_true),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(macro[0]),
        "recall_macro": float(macro[1]),
        "f1_macro": float(macro[2]),
        "precision_weighted": float(weighted[0]),
        "recall_weighted": float(weighted[1]),
        "f1_weighted": float(weighted[2]),
        "roc_auc_ovr_macro": auc,
        # share of benign flows flagged as some attack
        "false_alarm_rate": float(
            (is_benign_true & ~is_benign_pred).sum() / max(is_benign_true.sum(), 1)
        ),
        # share of attack flows flagged as some attack (any class)
        "attack_detection_rate": float(
            ((~is_benign_true) & (~is_benign_pred)).sum() / max((~is_benign_true).sum(), 1)
        ),
        "per_class": {
            c: {
                "precision": float(p[i]),
                "recall": float(r[i]),
                "f1": float(f[i]),
                "support": int(s[i]),
            }
            for i, c in enumerate(classes)
        },
        "confusion_matrix": {
            "labels": classes,
            "rows_true_cols_pred": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        },
    }


def latency_ms(model: Any, x: pd.DataFrame, batch: int = 500, repeats: int = 20) -> float:
    """Median wall-clock milliseconds to score one micro-batch (plan target: < 50 ms / 500 flows)."""
    sample = x.iloc[:batch]
    model.predict_proba(sample)  # warm-up
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        model.predict_proba(sample)
        times.append((time.perf_counter() - t0) * 1000)
    return float(np.median(times))


def _flag_stats(
    proba: np.ndarray, y_true: np.ndarray, ds: np.ndarray, classes: list[str], t: float
) -> dict[str, Any]:
    """Flow-level alerting at probability threshold ``t``: a flow is FLAGGED when its predicted
    class is an attack class and that class's probability is >= t (exactly the serving rule)."""
    benign_id = classes.index(BENIGN)
    flagged = (proba.argmax(axis=1) != benign_id) & (proba.max(axis=1) >= t)
    is_benign = y_true == benign_id
    far_by_ds = {
        str(k): float(flagged[is_benign & (ds == k)].mean())
        if (is_benign & (ds == k)).any()
        else 0.0
        for k in np.unique(ds)
    }
    recall_by_ds = {
        str(k): float(flagged[~is_benign & (ds == k)].mean())
        if (~is_benign & (ds == k)).any()
        else 0.0
        for k in np.unique(ds)
    }
    return {
        "threshold": round(float(t), 3),
        "false_alarm_rate": float(flagged[is_benign].mean()),
        "attack_recall": float(flagged[~is_benign].mean()),
        "far_by_dataset": far_by_ds,
        "far_max": max(far_by_ds.values()),
        "attack_recall_by_dataset": recall_by_ds,
    }


def calibrate_threshold(
    proba: np.ndarray,
    y_true: np.ndarray,
    ds: np.ndarray,
    classes: list[str],
    target_far: float = 0.02,
) -> dict[str, Any]:
    """Pick the alert threshold on VALIDATION data. Rule fixed in advance: the smallest threshold
    in 0.50..0.99 whose false-alarm rate is <= ``target_far`` on EVERY dataset. If none reaches
    the target, take 0.99 and say so. The cost (lost attack recall) is reported alongside."""
    grid = [round(float(t), 2) for t in np.arange(0.50, 1.0, 0.01)]
    curve = [_flag_stats(proba, y_true, ds, classes, t) for t in grid]
    chosen = next((c for c in curve if c["far_max"] <= target_far), None)
    return {
        "rule": f"smallest threshold in 0.50-0.99 with false-alarm rate <= {target_far:.0%} on every dataset",
        "target_far": target_far,
        "target_met": chosen is not None,
        "chosen": chosen or curve[-1],
        "curve": [c for c in curve if round(c["threshold"] * 100) % 5 == 0],
    }


def at_threshold(
    proba: np.ndarray, y_true: np.ndarray, ds: np.ndarray, classes: list[str], t: float
) -> dict[str, Any]:
    return _flag_stats(proba, y_true, ds, classes, t)


# Hand-made flows that resemble everyday traffic. NOT a benchmark and not a metric: it only shows
# how a model treats ordinary-looking traffic, which the held-out splits of a lab dataset cannot.
_PROBE_BASE = {
    "src_ip": "10.0.0.5", "dst_ip": "198.51.100.20", "src_port": 51514, "protocol": 6, "tcp_flags": 27,
}  # fmt: skip
PROBES: dict[str, dict[str, Any]] = {
    "https browse (small)": dict(dst_port=443, in_bytes=1200, out_bytes=5400, in_pkts=10, out_pkts=12, duration_ms=850),
    "https browse (large)": dict(dst_port=443, in_bytes=40000, out_bytes=900000, in_pkts=300, out_pkts=700, duration_ms=9000),
    "http page": dict(dst_port=80, in_bytes=600, out_bytes=15000, in_pkts=6, out_pkts=14, duration_ms=300),
    "ssh session": dict(dst_port=22, in_bytes=5000, out_bytes=7000, in_pkts=40, out_pkts=40, duration_ms=60000),
    "smtp mail": dict(dst_port=25, in_bytes=3000, out_bytes=400, in_pkts=12, out_pkts=10, duration_ms=1200),
    "dns query": dict(dst_port=53, protocol=17, tcp_flags=0, in_bytes=70, out_bytes=200, in_pkts=1, out_pkts=1, duration_ms=20),
    "udp stream": dict(dst_port=5004, protocol=17, tcp_flags=0, in_bytes=500000, out_bytes=0, in_pkts=400, out_pkts=0, duration_ms=8000),
    "icmp ping": dict(dst_port=0, src_port=0, protocol=1, tcp_flags=0, in_bytes=84, out_bytes=84, in_pkts=1, out_pkts=1, duration_ms=1),
}  # fmt: skip


def probe_everyday_traffic(
    predict_proba: Callable[[pd.DataFrame], np.ndarray], classes: list[str]
) -> dict[str, Any]:
    """Classify the hand-made everyday flows; report how many were called Benign."""
    from sentinelbi_ml.features import build_features, canonical_to_raw

    frame = pd.DataFrame([{**_PROBE_BASE, **v} for v in PROBES.values()])
    proba = predict_proba(build_features(canonical_to_raw(frame)))
    rows = [
        {"flow": name, "label": classes[int(i)], "probability": round(float(p), 3)}
        for name, i, p in zip(PROBES, proba.argmax(axis=1), proba.max(axis=1), strict=True)
    ]
    benign = sum(r["label"] == BENIGN for r in rows)
    return {
        "note": "hand-made flows, NOT a benchmark",
        "benign": benign,
        "total": len(rows),
        "flows": rows,
    }


def bench_artifact(model_dir: Path, data_root: Path) -> dict[str, Any]:
    """Measure serving-path latency of an exported model: single-threaded (as the worker runs
    it), 500 held-out test flows, median of 30 runs. Updates the model card in place."""
    import json
    import os
    import platform

    import joblib

    from sentinelbi_ml.features import CORE_FEATURES, build_features
    from sentinelbi_ml.preprocess import DEFAULT_DATASET, find_csv, load_rows

    card = json.loads((model_dir / "model_card.json").read_text(encoding="utf-8"))
    est = joblib.load(model_dir / card["artifact"])
    if "n_jobs" in est.get_params():
        est.set_params(n_jobs=1)
    npz = model_dir / "test_rows.npz"
    if npz.exists():  # multi-dataset export: benchmark on the first dataset's test rows
        rows_by_key = np.load(npz)
        key = next(iter(rows_by_key.files))
        rows = rows_by_key[key][:500]
    else:  # single-dataset export (original format)
        key, rows = DEFAULT_DATASET, np.load(model_dir / "test_rows.npy")[:500]
    raw = load_rows(find_csv(data_root, key), set(rows.tolist()))
    x = build_features(raw)[CORE_FEATURES]
    ms = latency_ms(est, x, batch=500, repeats=30)
    card["latency_ms_training_run"] = card.get("latency_ms_per_500_flows")
    card["latency_ms_per_500_flows"] = round(ms, 2)
    card["latency_conditions"] = (
        f"serving path: n_jobs=1, 500 held-out test flows, median of 30 runs, "
        f"{platform.system()} {platform.machine()}, {os.cpu_count()} logical CPUs, "
        f"measured on an otherwise idle machine"
    )
    (model_dir / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    return {"latency_ms_per_500_flows": round(ms, 2), "plan_target_ms": 50}


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Benchmark an exported model on the serving path")
    ap.add_argument("model_dir", type=Path)
    ap.add_argument("--data-root", type=Path, default=Path("data/raw"))
    args = ap.parse_args()
    print(bench_artifact(args.model_dir, args.data_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
