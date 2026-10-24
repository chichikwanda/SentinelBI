"""Export the chosen model with a model card (Phase 2).

Layout: ``ml/models/<version>/{model.joblib, model_card.json, metrics.json, test_rows.npy}``.
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

from sentinelbi_ml.features import CORE_FEATURES

LIMITATIONS = [
    "Trained on NF-UNSW-NB15-v2 only (a 2015 lab testbed). No cross-dataset generalisation test has been run yet.",
    "Random stratified split: the dataset has no timestamps, so a time-aware split was impossible. "
    "Flows from the same attack session can appear in train and test, so scores are optimistic.",
    "Duplicate flows (identical inputs and label) were removed before splitting; benign traffic was "
    "down-sampled in the training split only.",
    "The BruteForce class has no examples in this dataset, so the model cannot predict it.",
    "Trained on bidirectional flows (IN and OUT counters). Router NetFlow v5/v9 records are "
    "unidirectional; the collector pairs reverse-direction records before scoring (ADR-015).",
    "Not validated on any real SME traffic.",
    "Dataset shift is likely to cause false alarms on real networks. Informal probe (hand-made flows, NOT a benchmark): typical HTTPS, HTTP, SMTP, DNS, UDP-stream and ICMP flows were all labelled Exploit/Other with probability 0.34-0.81, and only an SSH flow was Benign. The benign traffic in the training data comes from one lab testbed; train on more diverse data and calibrate on a consented pilot capture before trusting alerts.",
]


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
    dataset: dict[str, Any],
    training: dict[str, Any],
    test_rows: np.ndarray,
    feature_gain: dict[str, float] | None = None,
) -> Path:
    import joblib

    stamp = time.strftime("%Y%m%d", time.gmtime())
    tmp = out_root / f"_incoming-{algo}"
    tmp.mkdir(parents=True, exist_ok=True)
    artifact = tmp / "model.joblib"
    joblib.dump(estimator, artifact, compress=3)
    digest = sha256_file(artifact)
    version = f"{algo}-nfunsw2-{stamp}-{digest[:8]}"

    card = {
        "version": version,
        "algo": algo,
        "features": CORE_FEATURES,
        "classes": classes,
        "artifact": "model.joblib",
        "artifact_sha256": digest,
        "artifact_bytes": artifact.stat().st_size,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": dataset,
        "training": training,
        "metrics": {"validation_selection": metrics.get("validation"), "test": metrics.get("test")},
        "latency_ms_per_500_flows": metrics.get("latency_ms"),
        "feature_gain": feature_gain,
        "limitations": LIMITATIONS,
        "environment": {"python": platform.python_version()},
    }
    final = out_root / version
    if final.exists():
        raise FileExistsError(f"{final} already exists")
    tmp.rename(final)
    (final / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    (final / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    np.save(final / "test_rows.npy", np.sort(test_rows))
    return final


def main() -> int:
    print("sentinelbi_ml.export is called by train.py; run `python -m sentinelbi_ml.train`.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
