"""Metrics for model comparison (Phase 2). Accuracy is reported but is NOT the headline metric:
with ~96% benign traffic it is nearly meaningless; use macro-F1, per-class F1 and false alarms."""

from __future__ import annotations

import time
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


def bench_artifact(model_dir: Path, data_root: Path) -> dict[str, Any]:
    """Measure serving-path latency of an exported model: single-threaded (as the worker runs
    it), 500 held-out test flows, median of 30 runs. Updates the model card in place."""
    import json
    import os
    import platform

    import joblib

    from sentinelbi_ml.features import CORE_FEATURES, build_features
    from sentinelbi_ml.preprocess import find_csv, load_raw

    card = json.loads((model_dir / "model_card.json").read_text(encoding="utf-8"))
    est = joblib.load(model_dir / card["artifact"])
    if "n_jobs" in est.get_params():
        est.set_params(n_jobs=1)
    rows = np.load(model_dir / "test_rows.npy")[:500]
    raw = load_raw(find_csv(data_root))
    x = build_features(raw.iloc[rows])[CORE_FEATURES]
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
