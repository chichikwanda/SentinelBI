"""Predictor selection lives in ``registry``; this module keeps the original entry point.

``load_predictor()`` returns the placeholder; the worker uses ``PredictorHolder`` (registry.py),
which swaps in the registry's active trained model and falls back to the placeholder if no
model is active or its artifact cannot be loaded.
"""

from __future__ import annotations

from app.services.inference.placeholder import PlaceholderPredictor
from app.services.inference.predictor import Predictor


def load_predictor() -> Predictor:
    return PlaceholderPredictor()
