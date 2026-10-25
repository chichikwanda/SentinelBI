"""Export the chosen model with a model card (Phase 2).

Layout: ``ml/models/<version>/{model.joblib, model_card.json, metrics.json, test_rows.npz}``.
``test_rows.npz`` holds, per dataset key, the CSV data-row numbers of the held-out test split.
The card records the SHA-256 of the artifact; the serving side verifies it before loading
(joblib files are pickles, so only load artifacts you produced yourself).
"""

from __future__ import annotations

import hashlib
import json
import platform
import time
from pathlib import Path
from typing import Any

import numpy as np

from sentinelbi_ml.features import BENIGN, CLASSES, CORE_FEATURES, FEATURE_SPEC_VERSION


def limitations(
    datasets: list[dict[str, Any]], classes: list[str], probe: dict[str, Any] | None
) -> list[str]:
    """Limitations text for the card. Everything data-dependent is computed from this run."""
    names = " + ".join(d["name"] for d in datasets)
    out = [
        f"Trained on {names} only (lab testbeds). Not validated on any real SME traffic.",
        "Random stratified split: the datasets have no timestamps, so a time-aware split was "
        "impossible. Flows from the same attack session can appear in train and test, so scores "
        "are optimistic.",
        "Duplicate flows (identical inputs and label) were removed before splitting; large classes "
        "were down-sampled in the TRAINING split only.",
        "Trained on bidirectional flows (IN and OUT counters). Router NetFlow v5/v9 records are "
        "unidirectional; the collector pairs reverse-direction records before scoring (ADR-015).",
    ]
    missing = [c for c in CLASSES if c != BENIGN and c not in classes]
    if missing:
        out.append(
            f"No training examples for {', '.join(missing)}, so the model cannot predict them."
        )
    if len(datasets) == 1:
        out.append("Only one dataset was used, so no cross-dataset generalisation was measured.")
    if probe:
        out.append(
            f"Informal probe ({probe['note']}): {probe['benign']} of {probe['total']} everyday-traffic "
            "flows (HTTPS, HTTP, SSH, SMTP, DNS, UDP stream, ICMP) were labelled Benign; the rest were "
            "called attacks. Treat alerts on ordinary-looking traffic with suspicion and calibrate on "
            "a consented pilot capture before trusting them."
        )
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def export_model(
    *,
    out_root: Path,
    algo: str,
    estimator: Any,
    classes: list[str],
    metrics: dict[str, Any],
    datasets: list[dict[str, Any]],
    training: dict[str, Any],
    test_rows: dict[str, np.ndarray],
    feature_gain: dict[str, float] | None = None,
    probe: dict[str, Any] | None = None,
    alert_threshold: dict[str, Any] | None = None,
) -> Path:
    import joblib

    stamp = time.strftime("%Y%m%d", time.gmtime())
    tmp = out_root / f"_incoming-{algo}"
    tmp.mkdir(parents=True, exist_ok=True)
    artifact = tmp / "model.joblib"
    joblib.dump(estimator, artifact, compress=3)
    digest = sha256_file(artifact)
    tag = (
        "nfunsw2"
        if len(datasets) == 1 and datasets[0]["key"] == "nf-unsw-nb15-v2"
        else f"nfmulti{len(datasets)}"
    )
    version = f"{algo}-{tag}-{stamp}-{digest[:8]}"

    card = {
        "version": version,
        "algo": algo,
        "features": CORE_FEATURES,
        "feature_spec_version": FEATURE_SPEC_VERSION,
        "classes": classes,
        "artifact": "model.joblib",
        "artifact_sha256": digest,
        "artifact_bytes": artifact.stat().st_size,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": {"name": " + ".join(d["name"] for d in datasets), "sources": datasets},
        "training": training,
        "metrics": {
            "validation_selection": metrics.get("validation"),
            "test": metrics.get("test"),
            "per_dataset_test": metrics.get("per_dataset_test"),
            "cross_dataset": metrics.get("cross_dataset"),
        },
        "latency_ms_per_500_flows": metrics.get("latency_ms"),
        "feature_gain": feature_gain,
        "informal_probe": probe,
        "alert_threshold": alert_threshold,
        "limitations": limitations(datasets, classes, probe),
        "environment": {"python": platform.python_version()},
    }
    final = out_root / version
    if final.exists():
        raise FileExistsError(f"{final} already exists")
    tmp.rename(final)
    (final / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    (final / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    np.savez(final / "test_rows.npz", **{k: np.sort(v) for k, v in test_rows.items()})
    return final


def amend_card(model_dir: Path, **metric_fields: Any) -> None:
    """Add results that finish after the model was exported (e.g. the optional cross-dataset check)
    to ``metrics.json`` and the card, so a late failure can never lose the exported model."""
    card_path = model_dir / "model_card.json"
    card = json.loads(card_path.read_text(encoding="utf-8"))
    card["metrics"].update(metric_fields)
    card_path.write_text(json.dumps(card, indent=2), encoding="utf-8")
    metrics_path = model_dir / "metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    metrics.update(metric_fields)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")


def main() -> int:
    print("sentinelbi_ml.export is called by train.py; run `python -m sentinelbi_ml.train`.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
