"""Replay a NetFlow-style CSV through the ingest API (demos, load tests, dataset replays).

    python -m app.services.ingestion.csv_replay --file data/samples/synthetic_flows.csv \
        --api-url http://localhost:8000 --api-key sbi_...

Reads the raw NetFlow-style column names (see ``sentinelbi_ml.features.CANONICAL_TO_RAW``),
maps them to the canonical flow record with the same mapping the features module defines,
and posts batches to ``POST /api/v1/ingest/flows``. Unknown columns (labels etc.) are ignored,
so ground truth never reaches the platform. By default no timestamp is sent, so the server
stamps ingest time and replayed flows show up as live traffic.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import sys
import time
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import httpx

from sentinelbi_ml.features import RAW_TO_CANONICAL, RAW_TS_COLUMN

REQUIRED_COLUMNS = ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "PROTOCOL"]
_ADDRESS_FIELDS = {"src_ip", "dst_ip"}


def _to_int(value: str | None) -> int:
    if value is None or value.strip() == "":
        return 0
    return int(float(value))


def row_to_flow(row: Mapping[str, str], keep_timestamps: bool = False) -> dict[str, Any]:
    """Map one CSV row (raw column names) to the canonical ingest record."""
    flow: dict[str, Any] = {}
    for raw, canonical in RAW_TO_CANONICAL.items():
        if raw not in row:
            continue
        flow[canonical] = row[raw].strip() if canonical in _ADDRESS_FIELDS else _to_int(row[raw])
    if keep_timestamps and row.get(RAW_TS_COLUMN):
        flow["ts"] = _to_int(row[RAW_TS_COLUMN]) / 1000.0  # epoch ms -> epoch seconds
    return flow


def read_flows(
    path: Path, *, limit: int | None = None, keep_timestamps: bool = False
) -> Iterator[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise SystemExit(f"{path}: missing required columns {missing}")
        for i, row in enumerate(reader):
            if limit is not None and i >= limit:
                return
            yield row_to_flow(row, keep_timestamps)


async def post_flows(
    client: httpx.AsyncClient,
    flows: Iterator[dict[str, Any]],
    *,
    api_key: str,
    batch_size: int = 500,
    rate: float = 0.0,
) -> tuple[int, int]:
    """POST flows in batches. ``rate`` caps flows/second (0 = as fast as possible)."""
    sent = batches = 0
    batch: list[dict[str, Any]] = []

    async def flush() -> None:
        nonlocal sent, batches
        started = time.perf_counter()
        resp = await client.post(
            "/api/v1/ingest/flows", json={"flows": batch}, headers={"X-API-Key": api_key}
        )
        if resp.status_code != 202:
            raise SystemExit(f"ingest failed: HTTP {resp.status_code}: {resp.text[:300]}")
        sent += len(batch)
        batches += 1
        if rate > 0:
            await asyncio.sleep(max(0.0, len(batch) / rate - (time.perf_counter() - started)))
        batch.clear()

    for flow in flows:
        batch.append(flow)
        if len(batch) >= batch_size:
            await flush()
    if batch:
        await flush()
    return sent, batches


async def _amain(args: argparse.Namespace) -> int:
    flows = read_flows(args.file, limit=args.limit, keep_timestamps=args.keep_timestamps)
    started = time.perf_counter()
    async with httpx.AsyncClient(base_url=args.api_url.rstrip("/"), timeout=30) as client:
        sent, batches = await post_flows(
            client, flows, api_key=args.api_key, batch_size=args.batch_size, rate=args.rate
        )
    print(f"posted {sent} flows in {batches} batches ({time.perf_counter() - started:.1f}s)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Replay a NetFlow-style CSV through the ingest API")
    p.add_argument("--file", type=Path, required=True)
    p.add_argument("--api-url", default="http://localhost:8000")
    p.add_argument("--api-key", required=True)
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--limit", type=int, default=None, help="only the first N rows")
    p.add_argument("--rate", type=float, default=0.0, help="max flows/second (0 = unlimited)")
    p.add_argument("--keep-timestamps", action="store_true", help="send the CSV's own start times")
    return asyncio.run(_amain(p.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
