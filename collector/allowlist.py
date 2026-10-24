"""Exporter allow-list: only registered sources may send NetFlow (design rule 4).

An exporter is accepted only when its address falls inside the CIDR of EXACTLY ONE registered
``netflow`` source. Zero matches = unknown exporter; several matches = ambiguous (two tenants
registered overlapping ranges, e.g. the same RFC 1918 network). Both are dropped, because
guessing could put one tenant's traffic into another's account. See ADR-005.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal

import psycopg

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class SourceRef:
    source_id: str
    org_id: str
    network: IPNetwork


@dataclass(frozen=True)
class Resolution:
    source: SourceRef | None
    reason: Literal["ok", "unknown", "ambiguous", "invalid-address"]


class ExporterAllowlist:
    def __init__(self, sources: list[SourceRef] | None = None) -> None:
        self._sources: list[SourceRef] = list(sources or [])

    def replace(self, sources: list[SourceRef]) -> None:
        self._sources = list(sources)  # atomic swap; readers never see a half-built list

    def __len__(self) -> int:
        return len(self._sources)

    def resolve(self, exporter_ip: str) -> Resolution:
        try:
            addr = ipaddress.ip_address(exporter_ip)
        except ValueError:
            return Resolution(None, "invalid-address")
        matches = [
            s for s in self._sources if addr.version == s.network.version and addr in s.network
        ]
        if not matches:
            return Resolution(None, "unknown")
        if len(matches) > 1:
            return Resolution(None, "ambiguous")
        return Resolution(matches[0], "ok")


def load_sources(dsn: str) -> list[SourceRef]:
    """Read the registered NetFlow sources (sync; call via ``asyncio.to_thread``)."""
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        rows = conn.execute(
            "SELECT id::text, org_id::text, cidr::text FROM sources WHERE method = 'netflow'"
        ).fetchall()
    return [SourceRef(r[0], r[1], ipaddress.ip_network(r[2])) for r in rows]
