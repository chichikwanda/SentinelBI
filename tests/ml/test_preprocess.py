"""Multi-dataset preprocessing, training caps, the everyday-traffic probe and card text."""

from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from sentinelbi_ml.evaluate import PROBES, probe_everyday_traffic
from sentinelbi_ml.export import limitations
from sentinelbi_ml.features import CLASSES, FEATURE_INPUT_COLUMNS
from sentinelbi_ml.preprocess import (
    SPECS,
    cse_cic_class,
    dedupe,
    load_raw,
    load_rows,
    map_labels,
    stratified_split,
    verify_sha256,
)
from sentinelbi_ml.train import cap_training_rows


def write_csv(path: Path, attacks: list[str]) -> Path:
    """A tiny NF-v2-shaped CSV: one row per entry of ``attacks`` (distinct inputs per row)."""
    rows = []
    for i, attack in enumerate(attacks):
        row = dict.fromkeys(FEATURE_INPUT_COLUMNS, i + 1)
        row.update(
            Label=0 if attack == "Benign" else 1, Attack=attack, IPV4_SRC_ADDR=f"10.0.0.{i % 250}"
        )
        rows.append(row)
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Benign", "Benign"),
        ("Bot", "Botnet/Backdoor"),
        ("DDoS attacks-LOIC-HTTP", "DoS/DDoS"),
        ("DDOS attack-HOIC", "DoS/DDoS"),
        ("DDOS attack-LOIC-UDP", "DoS/DDoS"),
        ("DoS attacks-Hulk", "DoS/DDoS"),
        ("DoS attacks-SlowHTTPTest", "DoS/DDoS"),
        ("FTP-BruteForce", "BruteForce"),
        ("SSH-Bruteforce", "BruteForce"),
        ("Brute Force -Web", "WebAttack"),  # host groups it under "Web Attacks"
        ("Brute Force -XSS", "WebAttack"),
        ("SQL Injection", "WebAttack"),
        ("Infilteration", "Exploit/Other"),
        # the parent categories the host actually publishes for the v2 file
        ("BruteForce", "BruteForce"),
        ("DoS", "DoS/DDoS"),
        ("DDoS", "DoS/DDoS"),
        ("Infiltration", "Exploit/Other"),
        ("Web Attacks", "WebAttack"),
    ],
)
def test_cse_cic_label_mapping(name: str, expected: str) -> None:
    assert cse_cic_class(name) == expected
    assert expected in CLASSES


def test_unknown_attack_names_fail_loudly_instead_of_being_dropped(tmp_path: Path) -> None:
    df = load_raw(write_csv(tmp_path / "d.csv", ["Benign", "Mystery Attack"]))
    with pytest.raises(ValueError, match="Mystery Attack"):
        map_labels(df, SPECS["nf-cse-cic-ids2018-v2"])


def test_disagreeing_binary_label_is_rejected(tmp_path: Path) -> None:
    df = load_raw(write_csv(tmp_path / "d.csv", ["Benign", "DoS"]))
    df.loc[0, "Label"] = 1  # claims "attack" for a Benign row
    with pytest.raises(ValueError, match="disagree"):
        map_labels(df)


def test_chunked_loader_keeps_every_attack_and_samples_benign(tmp_path: Path) -> None:
    csv = write_csv(tmp_path / "d.csv", ["Benign"] * 400 + ["DoS"] * 25 + ["Reconnaissance"] * 10)
    everything = load_raw(csv, benign_keep=1.0)
    assert len(everything) == 435
    sampled = load_raw(csv, benign_keep=0.25, seed=1)
    assert (sampled["Label"] != 0).sum() == 35  # no attack row is ever dropped
    assert 50 < (sampled["Label"] == 0).sum() < 150  # roughly a quarter of 400 benign rows
    assert load_raw(csv, benign_keep=0.0)["Label"].eq(1).all()
    # row numbers still point at the original CSV rows even after sampling
    assert (sampled["row"].to_numpy() == (sampled["IN_BYTES"].to_numpy() - 1)).all()


def test_load_rows_returns_exactly_the_requested_rows_with_ips(tmp_path: Path) -> None:
    csv = write_csv(tmp_path / "d.csv", ["Benign", "DoS", "Benign", "Reconnaissance", "Benign"])
    got = load_rows(csv, {1, 3}, extra_columns=("IPV4_SRC_ADDR",))
    assert sorted(got["row"]) == [1, 3]
    assert set(got["Attack"]) == {"DoS", "Reconnaissance"}
    assert "IPV4_SRC_ADDR" in got.columns
    assert "IPV4_SRC_ADDR" not in load_raw(csv).columns  # IPs stay out of training data by default


def test_dedupe_ignores_identical_flows_with_the_same_label(tmp_path: Path) -> None:
    df = load_raw(write_csv(tmp_path / "d.csv", ["Benign", "Benign", "DoS"]))
    df.loc[1, FEATURE_INPUT_COLUMNS] = df.loc[
        0, FEATURE_INPUT_COLUMNS
    ].to_numpy()  # exact duplicate
    out, stats = dedupe(map_labels(df))
    assert stats == {"rows_before": 3, "rows_after": 2, "duplicates_removed": 1}
    assert len(out) == 2


def test_split_is_stratified_over_label_and_dataset() -> None:
    strata = np.array(["a|x"] * 700 + ["a|y"] * 100 + ["b|x"] * 200)
    tr, va, te = stratified_split(strata, seed=3)
    assert len(tr) + len(va) + len(te) == 1000
    assert not (set(tr) & set(va)) and not (set(tr) & set(te)) and not (set(va) & set(te))
    for part in (tr, va, te):  # every stratum is present in every split
        assert set(strata[part]) == {"a|x", "a|y", "b|x"}


def test_training_caps_only_shrink_large_classes() -> None:
    labels = np.array(["Benign"] * 1000 + ["DoS/DDoS"] * 300 + ["BruteForce"] * 40)
    tr = np.arange(len(labels))
    kept = cap_training_rows(tr, labels, benign_cap=100, class_cap=60, rng=np.random.default_rng(0))
    counts = pd.Series(labels[kept]).value_counts().to_dict()
    assert counts == {"Benign": 100, "DoS/DDoS": 60, "BruteForce": 40}
    assert list(kept) == sorted(kept)


def test_probe_reports_how_many_everyday_flows_were_called_benign() -> None:
    classes = ["Benign", "Exploit/Other"]

    def all_benign(x: pd.DataFrame) -> np.ndarray:
        return np.tile([0.9, 0.1], (len(x), 1))

    def all_attack(x: pd.DataFrame) -> np.ndarray:
        return np.tile([0.2, 0.8], (len(x), 1))

    ok = probe_everyday_traffic(all_benign, classes)
    bad = probe_everyday_traffic(all_attack, classes)
    assert ok["total"] == bad["total"] == len(PROBES)
    assert ok["benign"] == len(PROBES) and bad["benign"] == 0
    assert {r["flow"] for r in ok["flows"]} == set(PROBES)
    assert "NOT a benchmark" in ok["note"]


def test_card_limitations_are_computed_from_the_run_not_hardcoded() -> None:
    probe = {"note": "hand-made flows, NOT a benchmark", "benign": 2, "total": 8}
    one = limitations([{"name": "NF-UNSW-NB15-v2"}], ["Benign", "DoS/DDoS"], probe)
    text = " ".join(one)
    assert "BruteForce" in text  # no training examples for it
    assert "no cross-dataset generalisation" in text  # a single dataset was used
    assert "2 of 8" in text

    many = limitations([{"name": "A"}, {"name": "B"}], list(CLASSES), None)
    joined = " ".join(many)
    assert "A + B" in joined
    assert "cross-dataset" not in joined and "No training examples" not in joined
    assert "Informal probe" not in joined  # no probe was run


def test_a_damaged_dataset_file_is_refused(tmp_path: Path) -> None:
    data = b"IPV4_SRC_ADDR,IN_BYTES" + bytes([10]) + b"10.0.0.1,100" + bytes([10])
    f = tmp_path / "flows.csv"
    f.write_bytes(data)
    verify_sha256(f, hashlib.sha256(data).hexdigest())  # intact: no error
    # one flipped bit (0x2c ',' becomes 0x0c): the damage seen on this project's dev machine
    f.write_bytes(data.replace(b",", bytes([0x0C]), 1))
    with pytest.raises(ValueError, match="damaged"):
        verify_sha256(f, hashlib.sha256(data).hexdigest())
