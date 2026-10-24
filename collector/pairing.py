"""Pair reverse-direction NetFlow records into bidirectional flows (ADR-015).

Routers export ONE record per direction; the training data (NF-UNSW-NB15-v2, built with nProbe)
has both directions in one flow (IN_* = client to server, OUT_* = server to client). Feeding
unidirectional records to a model trained on bidirectional ones would be train/serve skew, so
the collector merges a record with its reverse counterpart seen within ``hold_seconds``.
A record that finds no partner in time is emitted unchanged (out_* = 0).

Pairing is keyed per source (tenant context), so two organisations can never be merged.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

Key = tuple[str, int, str, int, str, int]  # (context, proto, src_ip, src_port, dst_ip, dst_port)


@dataclass(frozen=True)
class Item:
    """A flow ready to be written to the stream, with the tenant context it belongs to."""

    org_id: str
    source_id: str
    record: dict[str, Any]


@dataclass
class _Pending:
    org_id: str
    source_id: str
    record: dict[str, Any]
    start: datetime
    held_at: float


def _start(rec: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(rec["ts"])


def _merge(a: _Pending, b: _Pending) -> dict[str, Any]:
    """Merge two opposite-direction records. The initiator (client) is the earlier record;
    on a tie, the side whose destination port is lower (the service port) is the client."""
    if (a.start, a.record["dst_port"]) <= (b.start, b.record["dst_port"]):
        client, server = a, b
    else:
        client, server = b, a
    c, s = client.record, server.record
    end = max(
        client.start + timedelta(milliseconds=c["duration_ms"]),
        server.start + timedelta(milliseconds=s["duration_ms"]),
    )
    start = min(client.start, server.start)
    merged = dict(c)
    merged.update(
        ts=start.isoformat(),
        out_bytes=s["in_bytes"],
        out_pkts=s["in_pkts"],
        tcp_flags=int(c["tcp_flags"]) | int(s["tcp_flags"]),
        duration_ms=int((end - start).total_seconds() * 1000),
    )
    return merged


class FlowPairer:
    def __init__(
        self,
        hold_seconds: float = 10.0,
        max_pending: int = 100_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.hold_seconds = hold_seconds
        self.max_pending = max_pending
        self._clock = clock
        self._pending: OrderedDict[Key, _Pending] = OrderedDict()
        self.paired = 0
        self.unpaired = 0

    def __len__(self) -> int:
        return len(self._pending)

    @staticmethod
    def _keys(ctx: str, rec: dict[str, Any]) -> tuple[Key, Key]:
        fwd = (ctx, rec["protocol"], rec["src_ip"], rec["src_port"], rec["dst_ip"], rec["dst_port"])
        rev = (ctx, rec["protocol"], rec["dst_ip"], rec["dst_port"], rec["src_ip"], rec["src_port"])
        return fwd, rev

    def add(self, org_id: str, source_id: str, rec: dict[str, Any]) -> list[Item]:
        """Offer a record; returns the flows that are ready to emit right now."""
        if self.hold_seconds <= 0:
            self.unpaired += 1
            return [Item(org_id, source_id, rec)]
        fwd, rev = self._keys(source_id, rec)
        out: list[Item] = []
        partner = self._pending.pop(rev, None)
        if partner is not None:
            self.paired += 1
            merged = _merge(partner, _Pending(org_id, source_id, rec, _start(rec), 0.0))
            return [Item(org_id, source_id, merged)]
        stale = self._pending.pop(fwd, None)  # same direction again (active-timeout split)
        if stale is not None:
            out.append(self._emit(stale))
        self._pending[fwd] = _Pending(org_id, source_id, rec, _start(rec), self._clock())
        while len(self._pending) > self.max_pending:  # memory bound: evict the oldest unpaired
            _, oldest = self._pending.popitem(last=False)
            out.append(self._emit(oldest))
        return out

    def _emit(self, p: _Pending) -> Item:
        self.unpaired += 1
        return Item(p.org_id, p.source_id, p.record)

    def flush_expired(self, force: bool = False) -> list[Item]:
        """Emit records that waited ``hold_seconds`` without a partner (all if ``force``)."""
        now = self._clock()
        out: list[Item] = []
        while self._pending:
            key, p = next(iter(self._pending.items()))
            if not force and now - p.held_at < self.hold_seconds:
                break
            del self._pending[key]
            out.append(self._emit(p))
        return out
