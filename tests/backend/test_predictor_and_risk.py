"""Predictor interface contract + provisional risk scoring."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from app.core.enums import Severity
from app.services.features.builder import records_to_frame, serving_features
from app.services.inference.model_loader import load_predictor
from app.services.inference.placeholder import PLACEHOLDER_VERSION, PlaceholderPredictor
from app.services.inference.predictor import classify
from app.services.risk.scoring import event_risk, severity_for
from sentinelbi_ml.features import BENIGN, CLASSES, CORE_FEATURES


def _features(**flow: int) -> pd.DataFrame:
    base = {
        "src_ip": "10.0.0.1", "dst_ip": "198.51.100.1", "src_port": 40000, "dst_port": 443,
        "protocol": 6, "tcp_flags": 27, "in_bytes": 1000, "out_bytes": 4000,
        "in_pkts": 10, "out_pkts": 12, "duration_ms": 800,
    }  # fmt: skip
    base.update(flow)
    return serving_features(records_to_frame([base]))


def test_loader_returns_the_placeholder_until_a_model_exists() -> None:
    predictor = load_predictor()
    assert isinstance(predictor, PlaceholderPredictor)
    assert predictor.version == PLACEHOLDER_VERSION


def test_proba_shape_and_normalisation_over_a_mixed_batch() -> None:
    frames = pd.concat(
        [_features(), _features(tcp_flags=2, in_pkts=1, out_pkts=0, in_bytes=44, out_bytes=0, duration_ms=0),
         _features(protocol=17, in_pkts=3000, in_bytes=180000, out_pkts=0, out_bytes=0)],
        ignore_index=True,
    )  # fmt: skip
    predictor = PlaceholderPredictor()
    proba = predictor.predict_proba(frames)
    assert proba.shape == (3, len(CLASSES))
    assert list(predictor.classes) == CLASSES
    np.testing.assert_allclose(proba.sum(axis=1), 1.0)
    assert classify(predictor, frames).labels == [BENIGN, "Recon/Scan", "DoS/DDoS"]


def test_classify_rejects_a_misshapen_predictor() -> None:
    class Broken:
        version = "broken"
        classes = ("a", "b")

        def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
            return np.zeros((len(features), 3))

    with pytest.raises(ValueError, match="shape"):
        classify(Broken(), _features())


def test_predictor_only_sees_the_shared_feature_columns() -> None:
    assert list(_features().columns) == CORE_FEATURES


def test_event_risk_formula_and_clipping() -> None:
    # 0.85 x 0.3 (Recon) x 1.0 (medium criticality)
    assert event_risk(0.85, "Recon/Scan") == pytest.approx(0.255)
    # high-criticality assets raise the score, low lower it
    assert event_risk(0.9, "DoS/DDoS", criticality=3) > event_risk(0.9, "DoS/DDoS", criticality=1)
    assert event_risk(1.0, "Botnet/Backdoor", criticality=3, exposure_factor=2.0) == 1.0  # clipped
    assert event_risk(0.0, "DoS/DDoS") == 0.0
    assert event_risk(0.5, "SomethingNew") == pytest.approx(0.25)  # unknown class: default weight


@pytest.mark.parametrize(
    ("score", "severity"),
    [(0, Severity.LOW), (24.9, Severity.LOW), (25, Severity.MEDIUM), (49.9, Severity.MEDIUM),
     (50, Severity.HIGH), (74.9, Severity.HIGH), (75, Severity.CRITICAL), (100, Severity.CRITICAL)],
)  # fmt: skip
def test_severity_bands_match_the_plan(score: float, severity: Severity) -> None:
    assert severity_for(score) is severity
