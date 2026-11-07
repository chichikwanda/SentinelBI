"""Training from the web interface: what may be asked for, the command that runs it, and how the
trainer's log lines become a stage the page can show.

The training code itself stays in ``ml/src/train.py`` (one implementation, also used by
``make train``). The ``trainer`` service runs it as a subprocess; nothing here fits a model.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from sentinelbi_ml.download import DATASETS

DATASET_KEYS = sorted(DATASETS)
ALGORITHMS: dict[str, dict[str, str]] = {
    "dt": {"label": "Decision Tree", "module": "sklearn"},
    "rf": {"label": "Random Forest", "module": "sklearn"},
    "lgbm": {"label": "LightGBM", "module": "lightgbm"},
    "xgb": {"label": "XGBoost", "module": "xgboost"},
    "lr": {"label": "Logistic Regression", "module": "sklearn"},
    "mlp": {"label": "Neural network (MLP)", "module": "sklearn"},
}
DEFAULT_ALGORITHMS = ["dt", "rf", "lgbm"]
DEFAULT_KEEP = {"nf-cse-cic-ids2018-v2": 0.08}


def available_algorithms() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for key, info in ALGORITHMS.items():
        ok = importlib.util.find_spec(info["module"]) is not None
        out.append(
            {
                "key": key,
                "label": info["label"],
                "available": ok,
                "default": key in DEFAULT_ALGORITHMS,
                "note": ""
                if ok
                else f"the {info['module']} package is not installed in this image",
            }
        )
    return out


class TrainParams(BaseModel):
    datasets: list[str] = Field(default_factory=lambda: list(DATASET_KEYS), min_length=1)
    models: list[str] = Field(default_factory=lambda: list(DEFAULT_ALGORITHMS), min_length=1)
    seed: int = Field(42, ge=0, le=1_000_000)
    benign_cap: int = Field(400_000, ge=1_000, le=5_000_000)
    class_cap: int = Field(150_000, ge=1_000, le=5_000_000)
    benign_keep: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_KEEP))
    target_far: float = Field(0.02, ge=0.001, le=0.2)
    cv_folds: int = Field(0, ge=0, le=10)
    n_jobs: int = Field(3, ge=1, le=8)
    cross_dataset: bool = True
    smoke: bool = False

    @field_validator("datasets")
    @classmethod
    def _known_datasets(cls, v: list[str]) -> list[str]:
        bad = [k for k in v if k not in DATASETS]
        if bad:
            raise ValueError(f"unknown dataset {', '.join(bad)}")
        return list(dict.fromkeys(v))

    @field_validator("models")
    @classmethod
    def _known_models(cls, v: list[str]) -> list[str]:
        bad = [k for k in v if k not in ALGORITHMS]
        if bad:
            raise ValueError(f"unknown algorithm {', '.join(bad)}")
        return list(dict.fromkeys(v))

    @field_validator("benign_keep")
    @classmethod
    def _keep(cls, v: dict[str, float]) -> dict[str, float]:
        for k, frac in v.items():
            if k not in DATASETS:
                raise ValueError(f"unknown dataset {k}")
            if not 0.01 <= frac <= 1.0:
                raise ValueError("the benign share to keep must be between 0.01 and 1")
        return v

    @field_validator("cv_folds")
    @classmethod
    def _folds(cls, v: int) -> int:
        if v == 1:
            raise ValueError("cross-validation needs at least 2 folds (or 0 for off)")
        return v


class CheckParams(BaseModel):
    folder: str = Field(pattern=r"^\d{8}T\d{6}Z$")


class DownloadParams(BaseModel):
    dataset: Literal[*DATASET_KEYS]  # type: ignore[valid-type]


def train_command(p: TrainParams, data_root: Path, out_root: Path) -> list[str]:
    cmd = [
        sys.executable, "-I", "-m", "sentinelbi_ml.train",
        "--data-root", str(data_root),
        "--out", str(out_root),
        "--datasets", ",".join(p.datasets),
        "--models", ",".join(p.models),
        "--seed", str(p.seed),
        "--benign-cap", str(p.benign_cap),
        "--class-cap", str(p.class_cap),
        "--target-far", str(p.target_far),
        "--n-jobs", str(p.n_jobs),
    ]  # fmt: skip
    for key, frac in p.benign_keep.items():
        if key in p.datasets:
            cmd += ["--benign-keep", f"{key}={frac}"]
    if p.cv_folds:
        cmd += ["--cv-folds", str(p.cv_folds)]
    if not p.cross_dataset:
        cmd.append("--no-cross-dataset")
    if p.smoke:
        cmd.append("--smoke")
    return cmd


def backup_command() -> list[str]:
    return [sys.executable, "-I", "-m", "app.services.backup", "create"]


def check_backup_command(folder: str) -> list[str]:
    return [sys.executable, "-I", "-m", "app.services.backup", "check", folder]


def download_command(dataset: str, data_root: Path) -> list[str]:
    return [sys.executable, "-I", "-m", "sentinelbi_ml.download", dataset, "--out", str(data_root)]


# (prefix of the log message, stage shown on the page), checked in order
_STAGES: list[tuple[str, str]] = [
    ("dumping", "Dumping the database"),
    ("copying", "Copying models"),
    ("checksum", "Checking the checksum"),
    ("dump is readable", "Checking the dump"),
    ("restored", "Trial restore"),
    ("verifying", "Checking dataset files"),
    ("loading", "Loading data"),
    ("combined", "Preparing features"),
    ("split", "Splitting"),
    ("training", "Training models"),
    ("selected", "Choosing the model"),
    ("alert threshold", "Calibrating the alert threshold"),
    ("TEST", "Evaluating on the test split"),
    ("everyday-traffic", "Probing everyday traffic"),
    ("exported", "Saved"),
    ("cross-dataset", "Checking dataset shift"),
]
_BACKUP = re.compile(r"^backup\s+(\d{8}T\d{6}Z)$")
_LINE = re.compile(r"^\[\d\d:\d\d:\d\d\]\s*(.*)$")
_EXPORTED = re.compile(r"exported\s+(\S.*)$")


def stage_for(line: str) -> str | None:
    m = _LINE.match(line.strip())
    msg = m.group(1).strip() if m else line.strip()
    for prefix, stage in _STAGES:
        if msg.startswith(prefix):
            return stage
    return None


def exported_version(line: str) -> str | None:
    m = _LINE.match(line.strip())
    msg = m.group(1).strip() if m else line.strip()
    found = _EXPORTED.match(msg)
    if found:
        return Path(found.group(1).strip()).name
    made = _BACKUP.match(msg)
    return made.group(1) if made else None


def dataset_status(data_root: Path) -> list[dict[str, object]]:
    """Which datasets are on disk and verified (a MANIFEST.json plus the CSV)."""
    out: list[dict[str, object]] = []
    for key, ds in DATASETS.items():
        folder = data_root / key
        manifest = folder / "MANIFEST.json"
        csvs = sorted(folder.rglob("*.csv")) if folder.is_dir() else []
        out.append(
            {
                "key": key,
                "ready": manifest.is_file() and bool(csvs),
                "bytes": sum(c.stat().st_size for c in csvs),
                "citation": ds.citation,
                "source": ds.landing_page,
            }
        )
    return out
