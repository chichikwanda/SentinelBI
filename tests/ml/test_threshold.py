"""Alert-threshold calibration (chosen on validation only) and late card amendments."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from sentinelbi_ml.evaluate import at_threshold, calibrate_threshold
from sentinelbi_ml.export import amend_card

CLASSES = ["Benign", "DoS/DDoS"]


def build(false_attack_p: dict[str, float]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Per dataset: 100 benign flows (10 of them mispredicted as attack with the given probability)
    and 100 attack flows predicted as attack with probability 0.97."""
    proba, y, ds = [], [], []
    for name, p_attack in false_attack_p.items():
        for i in range(100):
            p = p_attack if i < 10 else 0.01
            proba.append([1 - p, p])
            y.append(0)
            ds.append(name)
        for _ in range(100):
            proba.append([0.03, 0.97])
            y.append(1)
            ds.append(name)
    return np.array(proba), np.array(y), np.array(ds)


def test_threshold_is_the_smallest_that_meets_the_target_on_every_dataset() -> None:
    proba, y, ds = build({"a": 0.60, "b": 0.95})
    cal = calibrate_threshold(proba, y, ds, CLASSES, target_far=0.02)
    chosen = cal["chosen"]
    assert cal["target_met"] is True
    assert chosen["threshold"] == 0.96  # dataset b's false alarms sit at 0.95
    assert chosen["far_max"] == 0.0
    assert chosen["attack_recall"] == 1.0  # the 0.97 attacks survive the stricter threshold
    # the stricter dataset decides: at 0.70 dataset a is clean but b still raises 10% false alarms
    at_070 = at_threshold(proba, y, ds, CLASSES, 0.70)
    assert at_070["far_by_dataset"] == {"a": 0.0, "b": 0.10}


def test_cost_is_visible_when_attacks_are_less_confident_than_false_alarms() -> None:
    proba, y, ds = build({"a": 0.60, "b": 0.99})
    cal = calibrate_threshold(proba, y, ds, CLASSES, target_far=0.02)
    assert cal["chosen"]["threshold"] == 0.99 or cal["chosen"]["attack_recall"] < 1.0
    assert cal["chosen"]["attack_recall"] == 0.0  # at 0.99 even the real attacks (0.97) are lost


def test_unreachable_target_is_reported_not_hidden() -> None:
    proba, y, ds = build({"a": 0.999})
    cal = calibrate_threshold(proba, y, ds, CLASSES, target_far=0.02)
    assert cal["target_met"] is False
    assert cal["chosen"]["threshold"] == 0.99  # falls back to the top of the grid
    assert cal["chosen"]["far_max"] > 0.02
    assert "every dataset" in cal["rule"]


def test_curve_is_summarised_for_the_card() -> None:
    proba, y, ds = build({"a": 0.6})
    cal = calibrate_threshold(proba, y, ds, CLASSES)
    thresholds = [c["threshold"] for c in cal["curve"]]
    assert thresholds == [0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95]


def test_amend_card_updates_card_and_metrics_together(tmp_path: Path) -> None:
    (tmp_path / "model_card.json").write_text(
        json.dumps({"metrics": {"test": {"f1": 1}}}), encoding="utf-8"
    )
    (tmp_path / "metrics.json").write_text(json.dumps({"test": {"f1": 1}}), encoding="utf-8")
    amend_card(tmp_path, cross_dataset={"a -> b": {"f1_macro": 0.2}})
    card = json.loads((tmp_path / "model_card.json").read_text(encoding="utf-8"))
    metrics = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    assert card["metrics"]["cross_dataset"] == {"a -> b": {"f1_macro": 0.2}}
    assert metrics["cross_dataset"] == {"a -> b": {"f1_macro": 0.2}}
    assert card["metrics"]["test"] == {"f1": 1}  # existing results are untouched
