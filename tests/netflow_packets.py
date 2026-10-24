"""Hand-built NetFlow v5 / v9 export packets for tests (no router needed)."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass


@dataclass
class Rec:
    src: str
    dst: str
    sport: int
    dport: int
    proto: int = 6
    flags: int = 2
    pkts: int = 1
    octets: int = 44
    first: int = 99_000  # sysUpTime ms
    last: int = 99_000


def v5_packet(
    records: list[Rec], *, uptime: int = 100_000, unix_secs: int = 1_760_000_000
) -> bytes:
    header = struct.pack("!HHIIIIBBH", 5, len(records), uptime, unix_secs, 0, 1, 0, 0, 0)
    body = b"".join(
        struct.pack(
            "!4s4s4sHHIIIIHHxBBBHHBBxx",
            socket.inet_aton(r.src),
            socket.inet_aton(r.dst),
            socket.inet_aton("0.0.0.0"),  # noqa: S104 - next hop field, not a bind
            1,
            2,
            r.pkts,
            r.octets,
            r.first,
            r.last,
            r.sport,
            r.dport,
            r.flags,
            r.proto,
            0,
            0,
            0,
            24,
            24,
        )
        for r in records
    )
    return header + body


# v9 template 256: field type ids from RFC 3954
_V9_FIELDS = [
    (8, 4),  # IPV4_SRC_ADDR
    (12, 4),  # IPV4_DST_ADDR
    (7, 2),  # L4_SRC_PORT
    (11, 2),  # L4_DST_PORT
    (4, 1),  # PROTOCOL
    (6, 1),  # TCP_FLAGS
    (2, 4),  # IN_PKTS
    (1, 4),  # IN_BYTES
    (22, 4),  # FIRST_SWITCHED
    (21, 4),  # LAST_SWITCHED
]


def _pad4(b: bytes) -> bytes:
    return b + b"\x00" * (-len(b) % 4)


def v9_template_flowset(template_id: int = 256) -> bytes:
    rec = struct.pack("!HH", template_id, len(_V9_FIELDS)) + b"".join(
        struct.pack("!HH", t, ln) for t, ln in _V9_FIELDS
    )
    body = _pad4(rec)
    return struct.pack("!HH", 0, 4 + len(body)) + body


def v9_data_flowset(records: list[Rec], template_id: int = 256) -> bytes:
    body = b"".join(
        struct.pack(
            "!4s4sHHBBIIII",
            socket.inet_aton(r.src),
            socket.inet_aton(r.dst),
            r.sport,
            r.dport,
            r.proto,
            r.flags,
            r.pkts,
            r.octets,
            r.first,
            r.last,
        )
        for r in records
    )
    body = _pad4(body)
    return struct.pack("!HH", template_id, 4 + len(body)) + body


def v9_packet(
    records: list[Rec],
    *,
    with_template: bool = True,
    uptime: int = 100_000,
    unix_secs: int = 1_760_000_000,
) -> bytes:
    flowsets = (v9_template_flowset() if with_template else b"") + v9_data_flowset(records)
    count = len(records) + (1 if with_template else 0)
    header = struct.pack("!HHIIII", 9, count, uptime, unix_secs, 1, 0)
    return header + flowsets
