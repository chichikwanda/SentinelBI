"""PLACEHOLDER classifier: fixed rules, NOT a trained model (ADR-012).

It exists so the whole pipeline (ingest -> features -> predict -> alert) can be exercised end
to end before Phase 2 produces a real model. It makes no accuracy claim and is registered in
``model_registry`` with empty metrics. It sees only the shared feature vector, exactly like
the real model will.

Rules (all on ``CORE_FEATURES``):
  * DoS/DDoS  : >= 100 inbound packets AND >= 1000 packets/second
  * Recon/Scan: TCP, SYN-only flags (2), <= 2 inbound packets, no reply
  * otherwise : Benign
Per-flow rules cannot tell a scan from a few failed connections; the worker therefore needs
several flagged flows from one source inside a window before it raises an alert.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
import pandas as pd

from sentinelbi_ml.features import CLASSES

PLACEHOLDER_VERSION = "placeholder-heuristic-v0"
_TCP = 6
_SYN_ONLY = 2


class PlaceholderPredictor:
    version = PLACEHOLDER_VERSION
    classes: Sequence[str] = tuple(CLASSES)

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        n = len(features)
        proba = np.zeros((n, len(self.classes)), dtype="float64")
        idx = {c: i for i, c in enumerate(self.classes)}

        in_pkts = features["IN_PKTS"].to_numpy()
        out_pkts = features["OUT_PKTS"].to_numpy()
        pps = features["PKTS_PER_SEC"].to_numpy()
        proto = features["PROTOCOL"].to_numpy()
        flags = features["TCP_FLAGS"].to_numpy()

        dos = (in_pkts >= 100) & (pps >= 1000)
        scan = (~dos) & (proto == _TCP) & (flags == _SYN_ONLY) & (in_pkts <= 2) & (out_pkts == 0)
        benign = ~(dos | scan)

        proba[dos, idx["DoS/DDoS"]] = 0.90
        proba[dos, idx["Benign"]] = 0.10
        proba[scan, idx["Recon/Scan"]] = 0.85
        proba[scan, idx["Benign"]] = 0.15
        proba[benign, idx["Benign"]] = 1.0
        return proba
