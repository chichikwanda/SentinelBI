"""Generate a small SYNTHETIC NetFlow-style CSV for pipeline demos and tests.

This is NOT a research dataset and must never be used for model training or evaluation
claims (design rule 7). It exists so the ingest -> worker -> alert path can be demonstrated
without a router or the real datasets (those arrive in Phase 2).

The traffic is deterministic (fixed seed). Addresses use private ranges and the documentation
ranges 203.0.113.0/24 and 198.51.100.0/24 (RFC 5737), so nothing refers to a real host.

    python -m sentinelbi_ml.synth_sample --out data/samples/synthetic_flows.csv
"""

from __future__ import annotations

import argparse
import csv
import io
import random
from pathlib import Path

from sentinelbi_ml.features import CANONICAL_TO_RAW

SEED = 20261024
COLUMNS = [*CANONICAL_TO_RAW.values(), "Label", "Attack"]
_INTERNAL = [f"10.20.0.{i}" for i in (10, 20, 50, 51, 52, 53, 54, 55)]
_EXTERNAL_SERVERS = ["198.51.100.10", "198.51.100.20", "198.51.100.30", "203.0.113.200"]
_SCANNER = "203.0.113.50"
_FLOODER = "198.51.100.77"
_TCP, _UDP = 6, 17


def _row(
    src: str,
    sp: int,
    dst: str,
    dp: int,
    proto: int,
    flags: int,
    ib: int,
    ob: int,
    ipk: int,
    opk: int,
    dur: int,
    label: int,
    attack: str,
) -> list[object]:
    return [src, sp, dst, dp, proto, flags, ib, ob, ipk, opk, dur, label, attack]


def generate_rows() -> list[list[object]]:
    rng = random.Random(SEED)
    rows: list[list[object]] = []

    for _ in range(600):  # benign web/mail/DNS-like traffic
        host = rng.choice(_INTERNAL)
        if rng.random() < 0.25:  # DNS
            rows.append(
                _row(
                    host,
                    rng.randint(40000, 60000),
                    "198.51.100.53",
                    53,
                    _UDP,
                    0,
                    rng.randint(60, 90),
                    rng.randint(90, 400),
                    1,
                    1,
                    rng.randint(5, 80),
                    0,
                    "Benign",
                )
            )
        else:
            ipk, opk = rng.randint(4, 60), rng.randint(4, 80)
            rows.append(
                _row(
                    host,
                    rng.randint(40000, 60000),
                    rng.choice(_EXTERNAL_SERVERS),
                    rng.choice([443, 443, 443, 80, 993, 587]),
                    _TCP,
                    27,
                    ipk * rng.randint(60, 700),
                    opk * rng.randint(100, 1400),
                    ipk,
                    opk,
                    rng.randint(50, 6000),
                    0,
                    "Benign",
                )
            )

    ports = rng.sample(range(1, 1025), 80)  # SYN scan against the mail server
    for p in ports:
        rows.append(
            _row(
                _SCANNER,
                rng.randint(40000, 60000),
                "10.20.0.10",
                p,
                _TCP,
                2,
                rng.choice([40, 44, 48, 60]),
                0,
                1,
                0,
                0,
                1,
                "Recon/Scan",
            )
        )

    for _ in range(25):  # UDP flood against the web server
        pk = rng.randint(2000, 5000)
        rows.append(
            _row(
                _FLOODER,
                rng.randint(1024, 65000),
                "10.20.0.20",
                80,
                _UDP,
                0,
                pk * 60,
                0,
                pk,
                0,
                rng.randint(500, 900),
                1,
                "DoS/DDoS",
            )
        )

    rng.shuffle(rows)
    return rows


def render_csv() -> str:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(COLUMNS)
    writer.writerows(generate_rows())
    return buf.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("data/samples/synthetic_flows.csv"))
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_csv(), newline="\n")
    print(f"wrote {args.out} ({len(generate_rows())} synthetic flows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
