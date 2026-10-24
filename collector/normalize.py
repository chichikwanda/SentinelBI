"""Map parsed NetFlow v5/v9/IPFIX records to the canonical flow record (same shape as the
HTTP ingest API: see backend ``FlowIn``).

NetFlow records are normally UNIDIRECTIONAL (one direction per record), so ``out_*`` stays 0
unless the exporter supplies output counters. The NF-v2 training datasets are bidirectional;
pairing reverse records is an open item before the real model goes live (ADR-015).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

_UPTIME_WRAP = 2**32

_SRC = ("IPV4_SRC_ADDR", "IPV6_SRC_ADDR", "sourceIPv4Address", "sourceIPv6Address")
_DST = ("IPV4_DST_ADDR", "IPV6_DST_ADDR", "destinationIPv4Address", "destinationIPv6Address")
_SPORT = ("L4_SRC_PORT", "SRC_PORT", "sourceTransportPort")
_DPORT = ("L4_DST_PORT", "DST_PORT", "destinationTransportPort")
_PROTO = ("PROTOCOL", "PROTO", "protocolIdentifier")
_FLAGS = ("TCP_FLAGS", "tcpControlBits")
_IN_BYTES = ("IN_BYTES", "IN_OCTETS", "octetDeltaCount")
_IN_PKTS = ("IN_PKTS", "IN_PACKETS", "packetDeltaCount")
_OUT_BYTES = ("OUT_BYTES",)
_OUT_PKTS = ("OUT_PKTS",)


def _first(data: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in data and data[k] is not None:
            return data[k]
    return None


def _addr(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _int(value: Any) -> int:
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def _epoch_ms(value: Any) -> int | None:
    if isinstance(value, datetime):
        return int(value.timestamp() * 1000)
    if isinstance(value, int | float):
        return int(value)
    return None


def normalize_flow(
    data: Mapping[str, Any], *, export_unix_s: int, uptime_ms: int | None
) -> dict[str, Any] | None:
    """Return a canonical flow dict, or ``None`` if the record has no usable addresses."""
    src, dst = _addr(_first(data, _SRC)), _addr(_first(data, _DST))
    if src is None or dst is None:
        return None

    start_ms: int | None = None
    duration_ms = 0
    first, last = data.get("FIRST_SWITCHED"), data.get("LAST_SWITCHED")
    if first is not None and last is not None and uptime_ms is not None:
        # sysUpTime-relative timestamps: convert via the packet's export time, handling wrap
        start_ms = export_unix_s * 1000 - ((uptime_ms - _int(first)) % _UPTIME_WRAP)
        duration_ms = (_int(last) - _int(first)) % _UPTIME_WRAP
    else:
        s, e = (
            _epoch_ms(data.get("flowStartMilliseconds")),
            _epoch_ms(data.get("flowEndMilliseconds")),
        )
        if s is not None:
            start_ms = s
            duration_ms = max(0, (e - s) if e is not None else 0)
    if start_ms is None:
        start_ms = export_unix_s * 1000

    return {
        "ts": datetime.fromtimestamp(start_ms / 1000, tz=UTC).isoformat(),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": _int(_first(data, _SPORT)),
        "dst_port": _int(_first(data, _DPORT)),
        "protocol": _int(_first(data, _PROTO)),
        "tcp_flags": _int(_first(data, _FLAGS)),
        "in_bytes": _int(_first(data, _IN_BYTES)),
        "out_bytes": _int(_first(data, _OUT_BYTES)),
        "in_pkts": _int(_first(data, _IN_PKTS)),
        "out_pkts": _int(_first(data, _OUT_PKTS)),
        "duration_ms": duration_ms,
    }


def normalize_packet(packet: Any) -> list[dict[str, Any]]:
    """Normalise every flow of a parsed export packet (``netflow.parse_packet`` result)."""
    header = packet.header
    export_unix_s = _int(getattr(header, "timestamp", getattr(header, "export_time", 0)))
    uptime = getattr(header, "uptime", None)
    out: list[dict[str, Any]] = []
    for flow in packet.flows:
        record = normalize_flow(
            flow.data,
            export_unix_s=export_unix_s,
            uptime_ms=_int(uptime) if uptime is not None else None,
        )
        if record is not None:
            out.append(record)
    return out
