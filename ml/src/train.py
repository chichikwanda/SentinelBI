"""Train and compare models on NF-UNSW-NB15-v2 (Phase 2, lean MVP version).

    uv run --project ml --extra train python -I -m sentinelbi_ml.train

Compares Logistic Regression (baseline), Decision Tree, Random Forest, LightGBM and XGBoost on
the SHARED core feature set (``sentinelbi_ml.features.build_features``), selects the best on the
VALIDATION split by macro-F1, and reports the TEST split once, for the selected model only.

Deliberately NOT done here (deferred, see docs/DECISIONS.md): k-fold cross-validation,
hyper-parameter search, cross-dataset generalisation, significance tests, an MLP.
Nothing in the output is invented: every number comes from this run and is written to
``metrics.json`` / ``model_card.json`` next to the exported artifact.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from sentinelbi_ml.evaluate import evaluate, latency_ms
from sentinelbi_ml.export import export_model
from sentinelbi_ml.features import CORE_FEATURES, build_features
from sentinelbi_ml.preprocess import (
    DATASET_KEY,
    dedupe,
    eda_summary,
    find_csv,
    load_raw,
    map_labels,
    stratified_split,
)

ALL_MODELS = ["lr", "dt", "rf", "lgbm", "xgb"]


def make_model(key: str, seed: int, n_jobs: int) -> Any:
    if key == "lr":
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import FunctionTransformer, StandardScaler

        # features are non-negative and heavy-tailed: log1p, then standardise (fit on train only)
        return Pipeline(
            [
                ("log1p", FunctionTransformer(np.log1p, validate=False)),
                ("scale", StandardScaler()),
                ("clf", LogisticRegression(max_iter=300, class_weight="balanced")),
            ]
        )
    if key == "dt":
        from sklearn.tree import DecisionTreeClassifier

        return DecisionTreeClassifier(
            max_depth=24, min_samples_leaf=2, class_weight="balanced", random_state=seed
        )
    if key == "rf":
        from sklearn.ensemble import RandomForestClassifier

        return RandomForestClassifier(
            n_estimators=120,
            max_depth=24,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            n_jobs=n_jobs,
            random_state=seed,
        )
    if key == "lgbm":
        from lightgbm import LGBMClassifier

        return LGBMClassifier(
            n_estimators=300,
            learning_rate=0.1,
            num_leaves=63,
            class_weight="balanced",
            n_jobs=n_jobs,
            random_state=seed,
            verbose=-1,
        )
    if key == "xgb":
        from xgboost import XGBClassifier

        return XGBClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.1,
            tree_method="hist",
            n_jobs=n_jobs,
            random_state=seed,
            eval_metric="mlogloss",
        )
    raise ValueError(key)


def fit(key: str, model: Any, x: pd.DataFrame, y: np.ndarray) -> float:
    started = time.perf_counter()
    if key == "xgb":
        from sklearn.utils.class_weight import compute_sample_weight

        model.fit(x, y, sample_weight=compute_sample_weight("balanced", y))
    else:
        model.fit(x, y)
    return time.perf_counter() - started


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-root", type=Path, default=Path("data/raw"))
    ap.add_argument("--out", type=Path, default=Path("ml/models"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument(
        "--benign-cap", type=int, default=400_000, help="max benign rows in TRAIN (speed)"
    )
    ap.add_argument(
        "--limit", type=int, default=None, help="read only the first N rows (smoke test)"
    )
    ap.add_argument("--models", default=",".join(ALL_MODELS))
    ap.add_argument("--n-jobs", type=int, default=4)
    ap.add_argument("--no-export", action="store_true", help="evaluate only; write nothing")
    ap.add_argument(
        "--smoke",
        action="store_true",
        help="quick pipeline check: all attack rows + 60k benign rows (NOT for reported results)",
    )
    args = ap.parse_args(argv)

    from sklearn.preprocessing import LabelEncoder

    csv = find_csv(args.data_root)
    manifest = json.loads(
        (args.data_root / DATASET_KEY / "MANIFEST.json").read_text(encoding="utf-8")
    )
    csv_sha = next(
        v["sha256"] for k, v in manifest["files"].items() if k.endswith("NF-UNSW-NB15-v2.csv")
    )

    log(f"loading {csv} (limit={args.limit})")
    raw = load_raw(csv, args.limit)
    mapped = map_labels(raw)
    if args.smoke:
        benign_rows = mapped[mapped["label"] == "Benign"].sample(60_000, random_state=args.seed)
        mapped = pd.concat([mapped[mapped["label"] != "Benign"], benign_rows]).sort_values("row")
        raw = raw.loc[mapped.index]
        log("SMOKE MODE: subsampled data; metrics are not valid results")
    deduped, dedupe_stats = dedupe(mapped)
    eda = eda_summary(raw, mapped, deduped)
    log(
        f"rows={len(raw):,} after dedupe={len(deduped):,}  classes={eda['class_counts_after_dedupe']}"
    )

    # features come from the SHARED module: the exact function the serving path calls
    x_all = build_features(deduped)
    le = LabelEncoder().fit(deduped["label"])
    classes = [str(c) for c in le.classes_]
    y_all = le.transform(deduped["label"])

    tr, va, te = stratified_split(y_all, args.seed)
    benign_id = classes.index("Benign")
    rng = np.random.default_rng(args.seed)
    benign_tr = tr[y_all[tr] == benign_id]
    if len(benign_tr) > args.benign_cap:  # undersample benign inside the TRAIN split only
        keep = rng.choice(benign_tr, size=args.benign_cap, replace=False)
        tr = np.sort(np.concatenate([tr[y_all[tr] != benign_id], keep]))
    log(
        f"split train={len(tr):,} (benign capped at {args.benign_cap:,}) val={len(va):,} test={len(te):,}"
    )

    x_tr, y_tr = x_all.iloc[tr], y_all[tr]
    x_va, y_va = x_all.iloc[va], y_all[va]
    x_te, y_te = x_all.iloc[te], y_all[te]

    results: dict[str, Any] = {}
    fitted: dict[str, Any] = {}
    for key in [m for m in args.models.split(",") if m]:
        model = make_model(key, args.seed, args.n_jobs)
        log(f"training {key} ...")
        seconds = fit(key, model, x_tr, y_tr)
        m = evaluate(y_va, model.predict_proba(x_va), classes)
        m["train_seconds"] = round(seconds, 1)
        m["latency_ms_per_500_flows"] = round(latency_ms(model, x_va), 2)
        results[key], fitted[key] = m, model
        log(
            f"  {key}: val macro-F1={m['f1_macro']:.4f} acc={m['accuracy']:.4f} "
            f"false-alarm={m['false_alarm_rate']:.4f} attack-recall={m['attack_detection_rate']:.4f} "
            f"train={seconds:.0f}s latency={m['latency_ms_per_500_flows']}ms"
        )

    best = max(results, key=lambda k: results[k]["f1_macro"])
    log(f"selected on validation macro-F1: {best}")
    test_metrics = evaluate(y_te, fitted[best].predict_proba(x_te), classes)  # test touched ONCE
    log(
        f"TEST ({best}): macro-F1={test_metrics['f1_macro']:.4f} acc={test_metrics['accuracy']:.4f} "
        f"false-alarm={test_metrics['false_alarm_rate']:.4f} "
        f"attack-recall={test_metrics['attack_detection_rate']:.4f}"
    )
    for c, v in test_metrics["per_class"].items():
        log(
            f"    {c:16s} P={v['precision']:.3f} R={v['recall']:.3f} F1={v['f1']:.3f} n={v['support']}"
        )

    if args.no_export:
        log("--no-export: nothing written")
        return 0

    gain = None
    est = fitted[best]
    if hasattr(est, "feature_importances_"):
        gain = {f: float(g) for f, g in zip(CORE_FEATURES, est.feature_importances_, strict=True)}
    out = export_model(
        out_root=args.out,
        algo=best,
        estimator=est,
        classes=classes,
        metrics={
            "validation": {
                k: {kk: vv for kk, vv in v.items() if kk != "confusion_matrix"}
                for k, v in results.items()
            },
            "test": test_metrics,
            "latency_ms": results[best]["latency_ms_per_500_flows"],
            "eda": eda,
            "dedupe": dedupe_stats,
        },
        dataset={
            "name": "NF-UNSW-NB15-v2",
            "source": manifest["source_page"],
            "csv_sha256": csv_sha,
            "licence_text_from_host": manifest["licence_text_from_host"],
            "citation": manifest["citation"],
            "rows_used": len(raw),
        },
        training={
            "seed": args.seed,
            "benign_cap_train": args.benign_cap,
            "splits": {"train": len(tr), "validation": len(va), "test": len(te)},
            "selection": "validation macro-F1",
            "models_compared": sorted(results),
            "not_done": [
                "k-fold cross-validation",
                "hyper-parameter search",
                "cross-dataset generalisation",
                "statistical significance tests",
                "MLP",
            ],
        },
        test_rows=deduped["row"].to_numpy()[te],
        feature_gain=gain,
    )
    log(f"exported {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
