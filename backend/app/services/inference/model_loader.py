"""Chooses the predictor the worker uses.

Phase 2 replaces the body with: read the active ``model_registry`` row, load the exported
pipeline + ``model_card.json``, verify its feature list equals ``CORE_FEATURES`` (or the
sensor feature set), and return a ``Predictor`` wrapping it. Until a trained model exists the
placeholder is returned.
"""

from __future__ import annotations

from app.services.inference.placeholder import PlaceholderPredictor
from app.services.inference.predictor import Predictor


def load_predictor() -> Predictor:
    return PlaceholderPredictor()
