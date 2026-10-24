"""Load a trained model produced by ``sentinelbi_ml.train`` and expose it as a ``Predictor``.

An artifact directory holds ``model.joblib`` + ``model_card.json``. Before unpickling, the
artifact's SHA-256 is compared with the card (joblib files are pickles: never load one you did
not produce yourself), and the card's feature list must equal the serving feature set exactly,
so a model trained on different features can never be silently fed the wrong columns.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from app.core.config import get_settings
from sentinelbi_ml.features import CORE_FEATURES

log = logging.getLogger("inference.artifact")


class ModelLoadError(RuntimeError):
    pass


def model_dir(version: str) -> Path:
    root = Path(get_settings().models_dir).resolve()
    path = (root / version).resolve()
    if root not in path.parents:  # version comes from the DB/API: never allow path tricks
        raise ModelLoadError(f"invalid model version {version!r}")
    return path


def read_card(version: str) -> dict[str, Any]:
    card_path = model_dir(version) / "model_card.json"
    try:
        card = json.loads(card_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ModelLoadError(f"model card not found for {version}: {card_path}") from exc
    if card.get("version") != version:
        raise ModelLoadError(f"model card version mismatch for {version}")
    if card.get("features") != CORE_FEATURES:
        raise ModelLoadError(
            f"model {version} was trained on different features than this build serves "
            f"({card.get('features')} != {CORE_FEATURES})"
        )
    return card  # type: ignore[no-any-return]


class ArtifactPredictor:
    """Wraps a fitted scikit-learn-compatible classifier (Pipeline, tree ensemble, LightGBM...)."""

    def __init__(self, version: str, estimator: Any, classes: Sequence[str]) -> None:
        self.version = version
        self.classes: Sequence[str] = tuple(classes)
        self._estimator = estimator

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        return np.asarray(self._estimator.predict_proba(features[CORE_FEATURES]))

    def explain(
        self, features: pd.DataFrame, class_index: int, top: int = 5
    ) -> list[dict[str, Any]] | None:
        """Per-prediction feature contributions (SHAP values) for one row and one class, or
        ``None`` when the model family has no native support. LightGBM and XGBoost compute
        exact tree-SHAP themselves, so the heavy ``shap`` package is not needed."""
        row = features[CORE_FEATURES].iloc[[0]]
        n_feat = len(CORE_FEATURES)
        module = type(self._estimator).__module__
        try:
            if module.startswith("lightgbm"):
                contrib = np.asarray(self._estimator.predict(row, pred_contrib=True))[0]
                part = contrib[class_index * (n_feat + 1) : (class_index + 1) * (n_feat + 1)]
            elif module.startswith("xgboost"):
                import xgboost as xgb

                contrib = self._estimator.get_booster().predict(
                    xgb.DMatrix(row), pred_contribs=True
                )
                part = np.asarray(contrib)[0][class_index]
            else:
                return None
        except Exception:
            log.exception("could not compute contributions")
            return None
        values = part[:n_feat]  # last entry is the bias term
        order = np.argsort(-np.abs(values))[:top]
        return [
            {
                "feature": CORE_FEATURES[i],
                "value": float(row.iloc[0, i]),
                "contribution": round(float(values[i]), 4),
            }
            for i in order
        ]


def load_artifact_predictor(version: str) -> ArtifactPredictor:
    import joblib

    card = read_card(version)
    path = model_dir(version) / card["artifact"]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != card["artifact_sha256"]:
        raise ModelLoadError(f"artifact checksum mismatch for {version}: refusing to load")
    estimator = joblib.load(path)
    if hasattr(estimator, "set_params") and "n_jobs" in estimator.get_params():
        estimator.set_params(n_jobs=1)  # threads cost more than they save on 500-row batches
    log.info("loaded model %s (%s)", version, card["algo"])
    return ArtifactPredictor(version, estimator, card["classes"])
