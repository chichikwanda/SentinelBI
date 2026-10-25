"""The predictor interface the worker depends on.

The real model (Phase 2) must implement this same protocol, so swapping the placeholder for
a trained model changes one factory function (``model_loader.load_predictor``), not the worker.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

import numpy as np
import pandas as pd


class Predictor(Protocol):
    version: str
    classes: Sequence[str]

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        """Return an ``(n_rows, len(classes))`` matrix whose rows sum to 1.

        ``features`` is the output of ``sentinelbi_ml.features.build_features``.
        """
        ...

    # Optional: ``alert_threshold: float | None`` (calibrated minimum probability for an alert).
    # Optional: predictors that can explain a single prediction also provide
    #   explain(features_one_row, class_index, top=5) -> list[{feature, value, contribution}] | None
    # (the worker looks it up with getattr, so the placeholder does not need it).


@dataclass(frozen=True)
class Classified:
    labels: list[str]
    confidence: np.ndarray  # probability of the predicted label, shape (n,)
    proba: np.ndarray  # (n, k)


def classify(predictor: Predictor, features: pd.DataFrame) -> Classified:
    proba = predictor.predict_proba(features)
    if proba.shape != (len(features), len(predictor.classes)):
        raise ValueError(
            f"predictor returned shape {proba.shape}, expected "
            f"({len(features)}, {len(predictor.classes)})"
        )
    idx = proba.argmax(axis=1)
    classes = list(predictor.classes)
    return Classified(
        labels=[classes[i] for i in idx],
        confidence=proba[np.arange(len(idx)), idx],
        proba=proba,
    )
