"""Write a demo replay CSV drawn ONLY from a model's held-out test rows.

    python -I -m sentinelbi_ml.sample ml/models/<version> --out data/processed/demo_sample.csv

The output is a subset of NF-UNSW-NB15-v2 (licence: academic research use after citing
Sarhan et al. 2022), so it is written under data/processed/ (gitignored) and never committed.
It is enriched with attacks (the real dataset is ~96% benign) so a demo has something to show;
that is a presentation choice, not a performance claim. Rows come from the test split, so the
model has not been trained on them. Ground-truth columns are kept in the file but ignored by
the replay tool.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from sentinelbi_ml.features import CANONICAL_TO_RAW
from sentinelbi_ml.preprocess import DEFAULT_DATASET, SPECS, find_csv, load_rows, map_labels


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("model_dir", type=Path)
    ap.add_argument("--data-root", type=Path, default=Path("data/raw"))
    ap.add_argument("--out", type=Path, default=Path("data/processed/demo_sample.csv"))
    ap.add_argument("--benign", type=int, default=2000)
    ap.add_argument("--per-attack-class", type=int, default=250)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)

    card = json.loads((args.model_dir / "model_card.json").read_text(encoding="utf-8"))
    npz = args.model_dir / "test_rows.npz"
    if npz.exists():  # one array of held-out CSV row numbers per dataset
        loaded = np.load(npz)
        test_rows = {k: loaded[k] for k in loaded.files}
    else:  # original single-dataset export
        test_rows = {DEFAULT_DATASET: np.load(args.model_dir / "test_rows.npy")}

    rng = np.random.default_rng(args.seed)
    parts = []
    for key, rows in test_rows.items():
        raw = load_rows(
            find_csv(args.data_root, key), set(rows.tolist()), ("IPV4_SRC_ADDR", "IPV4_DST_ADDR")
        )
        test = map_labels(raw, SPECS[key])
        for label, group in test.groupby("label"):
            want = args.benign if label == "Benign" else args.per_attack_class
            take = min(want // len(test_rows) if label == "Benign" else want, len(group))
            parts.append(group.iloc[rng.choice(len(group), size=take, replace=False)])
            print(f"  {key:24s} {label:16s} {take:5d} of {len(group):,} test flows")
    sample = pd.concat(parts).sample(frac=1.0, random_state=args.seed)

    cols = [*CANONICAL_TO_RAW.values(), "Label", "Attack"]
    # restore the dataset's own column order for the columns we kept; add L7 etc. is unnecessary
    args.out.parent.mkdir(parents=True, exist_ok=True)
    sample[cols].to_csv(args.out, index=False, lineterminator="\n")
    print(f"wrote {args.out} ({len(sample):,} flows) from model {card['version']} test split")
    return 0


if __name__ == "__main__":
    sys.exit(main())
