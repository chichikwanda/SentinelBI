"""Train and compare models on the NF-v2 NetFlow datasets (Phase 2, lean MVP version).

    uv run --project ml --extra train python -I -m sentinelbi_ml.train \\
        --datasets nf-unsw-nb15-v2,nf-cse-cic-ids2018-v2

Compares models on the SHARED core feature set (``sentinelbi_ml.features.build_features``),
selects the best on the VALIDATION split by macro-F1 (rule fixed in advance), and reports the
TEST split once, for the selected model only. With two or more datasets it also measures how the
selected algorithm does on a dataset it was NOT trained on (leave-one-dataset-out), which is the
check that speaks to dataset shift.

Deliberately NOT done here (deferred, see docs/DECISIONS.md): k-fold cross-validation,
hyper-parameter search, significance tests, an MLP. Nothing in the output is invented: every
number comes from this run and is written to ``metrics.json`` / ``model_card.json`` next to the
exported artifact.
"""

from __future__ import annotations

import argparse
import gc
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from sentinelbi_ml.evaluate import (
    at_threshold,
    calibrate_threshold,
    evaluate,
    latency_ms,
    probe_everyday_traffic,
)
from sentinelbi_ml.export import amend_card, export_model
from sentinelbi_ml.features import BENIGN, CORE_FEATURES, build_features
from sentinelbi_ml.preprocess import (
    SPECS,
    dedupe,
    eda_summary,
    find_csv,
    load_raw,
    map_labels,
    stratified_split,
    verify_sha256,
)

ALL_MODELS = ["lr", "dt", "rf", "lgbm", "xgb"]
DEFAULT_MODELS = ["dt", "rf", "lgbm"]
# the large dataset is read in chunks keeping EVERY attack row and only a share of benign rows
DEFAULT_BENIGN_KEEP = {"nf-cse-cic-ids2018-v2": 0.08}


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


def load_dataset(key: str, args: argparse.Namespace) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Load, label-map and de-duplicate one dataset. Returns (rows, info for the card)."""
    spec = SPECS[key]
    csv = find_csv(args.data_root, key)
    manifest = json.loads((args.data_root / key / "MANIFEST.json").read_text(encoding="utf-8"))
    csv_sha = next(v["sha256"] for k, v in manifest["files"].items() if k.endswith(spec.csv_name))
    if not args.smoke:
        log(f"verifying SHA-256 of {csv.name} ...")
        verify_sha256(csv, csv_sha)
    keep = args.benign_keep.get(key, 1.0)
    log(f"loading {key} from {csv} (benign kept: {keep:.0%}, limit={args.limit})")
    raw = load_raw(csv, args.limit, benign_keep=keep, seed=args.seed)
    mapped = map_labels(raw, spec)
    if args.smoke:
        attacks = mapped[mapped["label"] != BENIGN]
        attacks = attacks.sample(min(len(attacks), 150_000), random_state=args.seed)
        benign = mapped[mapped["label"] == BENIGN].sample(
            min(60_000, int((mapped["label"] == BENIGN).sum())), random_state=args.seed
        )
        mapped = pd.concat([attacks, benign]).sort_values("row")
        raw = raw.loc[mapped.index]
        log("SMOKE MODE: subsampled data; metrics are not valid results")
    deduped, dedupe_stats = dedupe(mapped)
    deduped["dataset"] = key
    eda = eda_summary(raw, mapped, deduped)
    log(
        f"  {key}: rows read={len(raw):,} after dedupe={len(deduped):,} {eda['class_counts_after_dedupe']}"
    )
    info = {
        "key": key,
        "name": spec.name,
        "source": manifest["source_page"],
        "csv_sha256": csv_sha,
        "licence_text_from_host": manifest["licence_text_from_host"],
        "citation": manifest["citation"],
        "rows_read": len(raw),
        "benign_keep_fraction": keep,
        "dedupe": dedupe_stats,
        "eda": eda,
    }
    return deduped, info


def cap_training_rows(
    tr: np.ndarray, labels: np.ndarray, benign_cap: int, class_cap: int, rng: np.random.Generator
) -> np.ndarray:
    """Down-sample large classes inside the TRAIN split only (never validation/test)."""
    kept = []
    for label in np.unique(labels[tr]):
        idx = tr[labels[tr] == label]
        cap = benign_cap if label == BENIGN else class_cap
        kept.append(rng.choice(idx, size=cap, replace=False) if len(idx) > cap else idx)
    return np.sort(np.concatenate(kept))


def parse_keep(values: list[str]) -> dict[str, float]:
    out = dict(DEFAULT_BENIGN_KEEP)
    for v in values:
        key, _, frac = v.partition("=")
        out[key] = float(frac)
    return out


def summarise(m: dict[str, Any]) -> dict[str, Any]:
    keys = ("n", "accuracy", "f1_macro", "false_alarm_rate", "attack_detection_rate")
    out = {k: m[k] for k in keys}
    out["per_class_f1"] = {c: v["f1"] for c, v in m["per_class"].items() if v["support"] > 0}
    return out


@dataclass
class Prepared:
    keys: list[str]
    infos: list[dict[str, Any]]
    meta: pd.DataFrame  # row, dataset, label only: raw columns are dropped to save memory
    x_all: pd.DataFrame
    y_all: np.ndarray
    classes: list[str]
    ds_arr: np.ndarray
    tr: np.ndarray
    va: np.ndarray
    te: np.ndarray


def prepare(args: argparse.Namespace) -> Prepared:
    """Load, label-map, de-duplicate, featurise and split. Deterministic for a given ``args``
    (seeded sampling and split)."""
    from sklearn.preprocessing import LabelEncoder

    keys = [k for k in args.datasets.split(",") if k]
    loaded = [load_dataset(k, args) for k in keys]
    data = pd.concat([d for d, _ in loaded], ignore_index=True)
    infos = [i for _, i in loaded]
    del loaded
    log(f"combined: {len(data):,} rows; classes {data['label'].value_counts().to_dict()}")

    # features come from the SHARED module: the exact function the serving path calls
    x_all = build_features(data)
    le = LabelEncoder().fit(data["label"])
    classes = [str(c) for c in le.classes_]
    y_all = le.transform(data["label"])
    label_arr = data["label"].to_numpy()
    ds_arr = data["dataset"].to_numpy()
    meta = data[["row", "dataset", "label"]].copy()
    del data  # the raw columns are no longer needed: keeping them nearly doubles memory use
    gc.collect()

    strata = np.char.add(np.char.add(label_arr.astype(str), "|"), ds_arr.astype(str))
    tr, va, te = stratified_split(strata, args.seed)
    rng = np.random.default_rng(args.seed)
    tr = cap_training_rows(tr, label_arr, args.benign_cap, args.class_cap, rng)
    log(
        f"split train={len(tr):,} (benign cap {args.benign_cap:,}, class cap {args.class_cap:,}) "
        f"val={len(va):,} test={len(te):,}"
    )
    return Prepared(keys, infos, meta, x_all, y_all, classes, ds_arr, tr, va, te)


def run_cross_dataset(p: Prepared, best: str, args: argparse.Namespace) -> dict[str, Any]:
    """Leave-one-dataset-out: refit the selected algorithm on one dataset, score the other's test
    split. Failures are recorded, never raised: this check must not be able to lose a model."""
    cross: dict[str, Any] = {}
    for a in p.keys:
        for b in p.keys:
            if a == b:
                continue
            name = f"{a} -> {b}"
            try:
                sel_a = p.tr[p.ds_arr[p.tr] == a]
                model = make_model(best, args.seed, max(1, args.n_jobs // 2))
                log(
                    f"cross-dataset: train {best} on {a} only ({len(sel_a):,} rows), test on {b} ..."
                )
                fit(best, model, p.x_all.iloc[sel_a], p.y_all[sel_a])
                sel_b = p.te[p.ds_arr[p.te] == b]
                proba = model.predict_proba(p.x_all.iloc[sel_b])
                # the model may lack classes the other dataset has: pad to the full class list
                full = np.zeros((len(sel_b), len(p.classes)))
                full[:, np.asarray(model.classes_, dtype=int)] = proba
                res = summarise(evaluate(p.y_all[sel_b], full, p.classes))
                cross[name] = res
                log(
                    f"  {name}: macro-F1={res['f1_macro']:.3f} false-alarm={res['false_alarm_rate']:.4f} "
                    f"attack-recall={res['attack_detection_rate']:.4f}"
                )
            except Exception as exc:
                cross[name] = {"error": f"{type(exc).__name__}: {exc}"[:300]}
                log(f"  {name}: FAILED ({type(exc).__name__}: {str(exc)[:120]})")
    return cross


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-root", type=Path, default=Path("data/raw"))
    ap.add_argument("--out", type=Path, default=Path("ml/models"))
    ap.add_argument("--datasets", default="nf-unsw-nb15-v2,nf-cse-cic-ids2018-v2")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--benign-cap", type=int, default=400_000, help="max benign rows in TRAIN")
    ap.add_argument(
        "--class-cap", type=int, default=150_000, help="max rows per attack class in TRAIN"
    )
    ap.add_argument(
        "--benign-keep",
        action="append",
        default=[],
        metavar="DATASET=FRACTION",
        help="share of benign rows to keep while reading a large dataset",
    )
    ap.add_argument("--limit", type=int, default=None, help="read only the first N rows (smoke)")
    ap.add_argument("--models", default=",".join(DEFAULT_MODELS))
    ap.add_argument("--n-jobs", type=int, default=3)
    ap.add_argument(
        "--target-far", type=float, default=0.02, help="false-alarm target for the alert threshold"
    )
    ap.add_argument("--no-cross-dataset", action="store_true")
    ap.add_argument("--no-export", action="store_true", help="evaluate only; write nothing")
    ap.add_argument("--smoke", action="store_true", help="quick pipeline check (NOT valid results)")
    args = ap.parse_args(argv)
    args.benign_keep = parse_keep(args.benign_keep)

    p = prepare(args)
    keys, infos, x_all, y_all = p.keys, p.infos, p.x_all, p.y_all
    classes, ds_arr, tr, va, te = p.classes, p.ds_arr, p.tr, p.va, p.te
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
        results[key], fitted[key] = m, model
        log(
            f"  {key}: val macro-F1={m['f1_macro']:.4f} acc={m['accuracy']:.4f} "
            f"false-alarm={m['false_alarm_rate']:.4f} attack-recall={m['attack_detection_rate']:.4f} "
            f"train={seconds:.0f}s"
        )

    best = max(results, key=lambda k: results[k]["f1_macro"])
    log(f"selected on validation macro-F1: {best}")
    est = fitted[best]

    # alert threshold: chosen on VALIDATION only (rule fixed in advance), then reported on test
    proba_va = est.predict_proba(x_va)
    calib = calibrate_threshold(proba_va, y_va, ds_arr[va], classes, args.target_far)
    t_star = calib["chosen"]["threshold"]
    log(
        f"alert threshold {t_star} ({'target met' if calib['target_met'] else 'TARGET NOT MET'}): "
        f"validation false-alarm max/dataset={calib['chosen']['far_max']:.4f} "
        f"attack-recall={calib['chosen']['attack_recall']:.4f}"
    )

    proba_te = est.predict_proba(x_te)
    test_metrics = evaluate(y_te, proba_te, classes)  # the test split is touched ONCE
    test_at_t = at_threshold(proba_te, y_te, ds_arr[te], classes, t_star)
    log(
        f"TEST ({best}): macro-F1={test_metrics['f1_macro']:.4f} acc={test_metrics['accuracy']:.4f} "
        f"argmax false-alarm={test_metrics['false_alarm_rate']:.4f} "
        f"attack-recall={test_metrics['attack_detection_rate']:.4f}"
    )
    log(
        f"TEST at alert threshold {t_star}: false-alarm={test_at_t['false_alarm_rate']:.4f} "
        f"{test_at_t['far_by_dataset']} attack-recall={test_at_t['attack_recall']:.4f} "
        f"{test_at_t['attack_recall_by_dataset']}"
    )
    for c, v in test_metrics["per_class"].items():
        log(
            f"    {c:16s} P={v['precision']:.3f} R={v['recall']:.3f} F1={v['f1']:.3f} n={v['support']}"
        )

    # the same test predictions, split by dataset (no extra look at the data)
    per_dataset: dict[str, Any] = {}
    for k in keys:
        mask = ds_arr[te] == k
        per_dataset[k] = summarise(evaluate(y_te[mask], proba_te[mask], classes))
        d = per_dataset[k]
        log(
            f"  test on {k}: macro-F1={d['f1_macro']:.3f} false-alarm={d['false_alarm_rate']:.4f} "
            f"attack-recall={d['attack_detection_rate']:.4f}"
        )

    probe = probe_everyday_traffic(est.predict_proba, classes)
    log(f"everyday-traffic probe: {probe['benign']} of {probe['total']} called Benign")
    for r in probe["flows"]:
        log(f"    {r['flow']:22s} -> {r['label']:16s} p={r['probability']}")

    if args.no_export:
        log("--no-export: nothing written")
        return 0

    gain = None
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
            "per_dataset_test": per_dataset,
            "cross_dataset": {},  # filled in below; the optional check cannot lose the model
            "latency_ms": round(latency_ms(est, x_va), 2),
            "eda": {i["key"]: i["eda"] for i in infos},
            "dedupe": {i["key"]: i["dedupe"] for i in infos},
        },
        datasets=[{k: v for k, v in i.items() if k not in {"eda"}} for i in infos],
        training={
            "seed": args.seed,
            "benign_cap_train": args.benign_cap,
            "class_cap_train": args.class_cap,
            "splits": {"train": len(tr), "validation": len(va), "test": len(te)},
            "selection": "validation macro-F1",
            "models_compared": sorted(results),
            "not_done": [
                "k-fold cross-validation",
                "hyper-parameter search",
                "statistical significance tests",
                "MLP",
                "evaluation on real SME traffic",
            ],
        },
        test_rows={k: p.meta["row"].to_numpy()[te][ds_arr[te] == k] for k in keys},
        feature_gain=gain,
        probe=probe,
        alert_threshold={
            "value": t_star,
            "calibration": calib,
            "test": test_at_t,
        },
    )
    log(f"exported {out}")

    if len(keys) > 1 and not args.no_cross_dataset:
        amend_card(out, cross_dataset=run_cross_dataset(p, best, args))
        log("cross-dataset results added to the model card")
    return 0


if __name__ == "__main__":
    sys.exit(main())
