"""Real model artifacts: loading, integrity checks, registry, hot-swap, and worker serving.

The models here are tiny (trained inside the test on the synthetic sample) so the suite stays
fast; the real 29 MB model is exercised by the stack, not by pytest.
"""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import joblib
import numpy as np
import pandas as pd
import pytest
from conftest import Tenant, add_source, register_org, scan_flows
from redis.asyncio import Redis
from test_worker import alerts_for, ingest

from app.core.config import Settings
from app.db.seed import seed
from app.services.inference.artifact import ModelLoadError, load_artifact_predictor, read_card
from app.services.inference.placeholder import PLACEHOLDER_VERSION
from app.services.inference.predictor import classify
from app.services.inference.registry import PredictorHolder, register_from_card, set_active
from sentinelbi_ml.features import CORE_FEATURES, FEATURE_SPEC_VERSION, build_features

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "samples" / "synthetic_flows.csv"


def _training_frame() -> tuple[pd.DataFrame, np.ndarray, list[str]]:
    with SAMPLE.open(newline="", encoding="utf-8") as fh:
        df = pd.DataFrame(list(csv.DictReader(fh)))
    for col in df.columns.difference(["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "Attack"]):
        df[col] = pd.to_numeric(df[col])
    classes = sorted(df["Attack"].unique())
    y = df["Attack"].map({c: i for i, c in enumerate(classes)}).to_numpy()
    return build_features(df), y, classes


def make_artifact(root: Path, kind: str = "dt") -> str:
    """Train a tiny model on the synthetic sample and write model.joblib + model_card.json."""
    x, y, classes = _training_frame()
    if kind == "lgbm":
        from lightgbm import LGBMClassifier

        est: Any = LGBMClassifier(
            n_estimators=15, num_leaves=7, min_child_samples=3, verbose=-1, random_state=0
        )
    else:
        from sklearn.tree import DecisionTreeClassifier

        est = DecisionTreeClassifier(max_depth=6, random_state=0)
    est.fit(x, y)
    tmp = root / f"_{kind}"
    tmp.mkdir(parents=True)
    joblib.dump(est, tmp / "model.joblib")
    digest = hashlib.sha256((tmp / "model.joblib").read_bytes()).hexdigest()
    version = f"{kind}-test-{digest[:8]}"
    (root / version).mkdir()
    (tmp / "model.joblib").rename(root / version / "model.joblib")
    card = {
        "version": version, "algo": kind, "features": CORE_FEATURES, "classes": classes,
        "feature_spec_version": FEATURE_SPEC_VERSION,
        "artifact": "model.joblib", "artifact_sha256": digest, "artifact_bytes": 1,
        "dataset": {"name": "synthetic sample (test)", "csv_sha256": "0" * 64},
        "training": {}, "metrics": {"test": {"f1_macro": 1.0}, "validation_selection": {}},
        "limitations": ["test artifact"],
    }  # fmt: skip
    (root / version / "model_card.json").write_text(json.dumps(card), encoding="utf-8")
    return version


@pytest.fixture
def models_dir(tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(settings, "models_dir", str(tmp_path))
    return tmp_path


def test_artifact_loads_and_predicts_with_the_serving_interface(models_dir: Path) -> None:
    version = make_artifact(models_dir)
    predictor = load_artifact_predictor(version)
    x, y, classes = _training_frame()
    assert predictor.version == version and list(predictor.classes) == classes
    result = classify(predictor, x)
    assert (
        np.array(result.labels) == np.array(classes)[y]
    ).mean() > 0.95  # fits its own training data
    np.testing.assert_allclose(result.proba.sum(axis=1), 1.0)


def test_tampered_artifact_is_refused(models_dir: Path) -> None:
    version = make_artifact(models_dir)
    with (models_dir / version / "model.joblib").open("ab") as fh:
        fh.write(b"tamper")
    with pytest.raises(ModelLoadError, match="checksum"):
        load_artifact_predictor(version)


def test_model_trained_on_other_features_is_refused(models_dir: Path) -> None:
    version = make_artifact(models_dir)
    card_path = models_dir / version / "model_card.json"
    card = json.loads(card_path.read_text(encoding="utf-8"))
    card["features"] = [*CORE_FEATURES[:-1], "SOMETHING_ELSE"]
    card_path.write_text(json.dumps(card), encoding="utf-8")
    with pytest.raises(ModelLoadError, match="different features"):
        read_card(version)


@pytest.mark.parametrize("spec", [None, FEATURE_SPEC_VERSION - 1, FEATURE_SPEC_VERSION + 1])
def test_model_trained_with_another_feature_spec_is_refused(
    models_dir: Path, spec: int | None
) -> None:
    version = make_artifact(models_dir)
    card_path = models_dir / version / "model_card.json"
    card = json.loads(card_path.read_text(encoding="utf-8"))
    card.pop("feature_spec_version")  # None: a card from before the field existed (= spec v1)
    if spec is not None:
        card["feature_spec_version"] = spec
    card_path.write_text(json.dumps(card), encoding="utf-8")
    with pytest.raises(ModelLoadError, match="feature spec"):
        read_card(version)


@pytest.mark.parametrize("bad", ["../escape", "..", "a/../../b"])
def test_version_cannot_escape_the_models_directory(models_dir: Path, bad: str) -> None:
    with pytest.raises(ModelLoadError):
        read_card(bad)


def test_boosted_trees_explain_predictions_natively(models_dir: Path) -> None:
    version = make_artifact(models_dir, "lgbm")
    predictor = load_artifact_predictor(version)
    x, _y, classes = _training_frame()
    scan_row = x[(x["TCP_FLAGS"] == 2) & (x["IN_PKTS"] == 1)].iloc[[0]]
    top = predictor.explain(scan_row, classes.index("Recon/Scan"), top=5)
    assert top is not None and len(top) == 5
    assert {t["feature"] for t in top} <= set(CORE_FEATURES)
    assert [abs(t["contribution"]) for t in top] == sorted(
        (abs(t["contribution"]) for t in top), reverse=True
    )


def test_models_without_native_explanations_return_none(models_dir: Path) -> None:
    predictor = load_artifact_predictor(make_artifact(models_dir, "dt"))
    x, _y, _classes = _training_frame()
    assert predictor.explain(x.iloc[[0]], 0) is None


async def test_register_activate_and_hot_swap(
    client: httpx.AsyncClient, sessionmaker: Any, settings: Settings, models_dir: Path
) -> None:
    version = make_artifact(models_dir)
    async with sessionmaker() as s:
        await seed(s)  # registers + activates the placeholder
        row = await register_from_card(s, version, activate=False)
        assert row.metrics["test"]["f1_macro"] == 1.0 and row.active is False

    holder = PredictorHolder(refresh_seconds=0)
    await holder.refresh(sessionmaker, force=True)
    assert holder.predictor.version == PLACEHOLDER_VERSION  # placeholder is still active

    admin = await register_org(client, "Platform Org")
    # an organisation admin may NOT switch the platform-wide model...
    denied = await client.post(f"/api/v1/models/{version}/activate", headers=admin.headers)
    assert denied.status_code == 403
    # ...a configured platform administrator may
    settings.platform_admin_emails = f"someone@else.test, {admin.email.upper()}"
    try:
        assert (
            await client.post("/api/v1/models/nope/activate", headers=admin.headers)
        ).status_code == 404
        ok = await client.post(f"/api/v1/models/{version}/activate", headers=admin.headers)
        assert ok.status_code == 200 and ok.json()["active"] is True
    finally:
        settings.platform_admin_emails = ""

    await holder.refresh(sessionmaker, force=True)
    assert holder.predictor.version == version  # the worker swapped without a restart
    listed = (await client.get("/api/v1/models", headers=admin.headers)).json()
    assert sum(m["active"] for m in listed) == 1

    # a broken artifact must not crash the worker: it keeps serving the previous good model
    broken = make_artifact(models_dir, "lgbm")
    async with sessionmaker() as s:
        await register_from_card(s, broken)
    (models_dir / broken / "model.joblib").write_bytes(b"corrupt")
    async with sessionmaker() as s:
        await set_active(s, broken)
        await s.commit()
    await holder.refresh(sessionmaker, force=True)
    assert holder.predictor.version == version  # unchanged: the corrupt artifact was refused

    async with (
        sessionmaker() as s
    ):  # and the registry can always be pointed back at the placeholder
        await set_active(s, PLACEHOLDER_VERSION)
        await s.commit()
    await holder.refresh(sessionmaker, force=True)
    assert holder.predictor.version == PLACEHOLDER_VERSION


async def test_activating_a_model_whose_artifact_is_missing_is_a_conflict(
    client: httpx.AsyncClient, sessionmaker: Any, settings: Settings, models_dir: Path
) -> None:
    version = make_artifact(models_dir)
    async with sessionmaker() as s:
        await register_from_card(s, version)
    (models_dir / version / "model_card.json").unlink()
    admin = await register_org(client, "Conflict Org")
    settings.platform_admin_emails = admin.email
    try:
        resp = await client.post(f"/api/v1/models/{version}/activate", headers=admin.headers)
    finally:
        settings.platform_admin_emails = ""
    assert resp.status_code == 409


async def test_worker_serves_a_real_artifact_end_to_end(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings, models_dir: Path
) -> None:
    version = make_artifact(models_dir, "lgbm")
    predictor = load_artifact_predictor(version)
    t: Tenant = await register_org(client, "Model Org")
    await add_source(client, t)
    await ingest(client, t, scan_flows(12))

    from app.workers.stream_consumer import consume_once, ensure_group

    await ensure_group(redis, settings)
    while await consume_once(redis, sessionmaker, predictor, settings, "model-test", block_ms=50):
        pass
    (alert,) = await alerts_for(client, t)
    assert alert["attack_class"] == "Recon/Scan"
    assert alert["evidence"]["model_version"] == version
    top = alert["evidence"]["top_features"]  # boosted trees explain each alert
    assert top and top[0]["feature"] in CORE_FEATURES


async def test_sync_registers_models_and_only_replaces_the_placeholder(
    sessionmaker: Any, models_dir: Path
) -> None:
    from app.services.inference.registry import active_version, sync_models

    async with sessionmaker() as s:
        await seed(s)  # placeholder active
    older = make_artifact(models_dir, "dt")
    async with sessionmaker() as s:
        result = await sync_models(s)
        assert result["registered"] == [older] and result["activated"] == older
        assert await active_version(s) == older

    # a model that arrives later is registered, but does not override the current choice
    newer = make_artifact(models_dir, "lgbm")
    async with sessionmaker() as s:
        result = await sync_models(s)
        assert newer in result["registered"] and result["activated"] is None
        assert await active_version(s) == older


class StubPredictor:
    """Constant-confidence predictor: every flow is 'Recon/Scan' with probability ``p``."""

    version = "stub-threshold"
    classes = ("Benign", "Recon/Scan")

    def __init__(self, p: float, alert_threshold: float | None) -> None:
        self._p = p
        self.alert_threshold = alert_threshold

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        return np.tile([1 - self._p, self._p], (len(features), 1))


async def _flag_with(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings, predictor: Any
) -> int:
    from app.workers.stream_consumer import consume_once, ensure_group

    t = await register_org(client, "Threshold Org")
    await add_source(client, t)
    await ingest(client, t, scan_flows(12))
    await ensure_group(redis, settings)
    while await consume_once(redis, sessionmaker, predictor, settings, "thr-test", block_ms=50):
        pass
    return len(await alerts_for(client, t))


async def test_models_calibrated_threshold_decides_whether_flagged_flows_alert(
    client: httpx.AsyncClient, redis: Redis, sessionmaker: Any, settings: Settings
) -> None:
    assert settings.alert_min_probability == 0.7
    # no calibrated threshold: the configured floor (0.7) applies, so p=0.9 alerts
    assert await _flag_with(client, redis, sessionmaker, settings, StubPredictor(0.9, None)) == 1
    # a calibrated threshold above the model's confidence suppresses the alert
    assert await _flag_with(client, redis, sessionmaker, settings, StubPredictor(0.9, 0.95)) == 0
    # a calibrated threshold below the floor never loosens the operator's setting
    assert await _flag_with(client, redis, sessionmaker, settings, StubPredictor(0.65, 0.5)) == 0
    # confident enough for both
    assert await _flag_with(client, redis, sessionmaker, settings, StubPredictor(0.97, 0.95)) == 1


def test_artifact_predictor_reads_the_threshold_from_the_card(models_dir: Path) -> None:
    version = make_artifact(models_dir)
    assert load_artifact_predictor(version).alert_threshold is None  # card has none

    card_path = models_dir / version / "model_card.json"
    card = json.loads(card_path.read_text(encoding="utf-8"))
    card["alert_threshold"] = {"value": 0.93}
    card_path.write_text(json.dumps(card), encoding="utf-8")
    assert load_artifact_predictor(version).alert_threshold == 0.93
