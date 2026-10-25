"""Builders for synthetic packets and pcap files, shared by the sensor and backend tests."""

from __future__ import annotations

import socket
import struct
from pathlib import Path

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
Frame = tuple[float, bytes] | tuple[float, bytes, int]  # (time, bytes[, real length if truncated])


def tcp_segment(sport: int, dport: int, flags: int = ACK, payload: int = 0) -> bytes:
    """A TCP header (no options) followed by ``payload`` zero bytes."""
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + bytes(
        payload
    )


def udp_datagram(sport: int, dport: int, payload: int = 0) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + payload, 0) + bytes(payload)


def icmp_message(kind: int, code: int = 0, payload: int = 0) -> bytes:
    return struct.pack("!BBHI", kind, code, 0, 0) + bytes(payload)


def ipv4_packet(
    src: str, dst: str, proto: int, l4: bytes, *, total: int | None = None, frag: int = 0
) -> bytes:
    length = 20 + len(l4) if total is None else total
    head = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, length, 0, frag, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )  # fmt: skip
    return head + l4


def ipv6_packet(src: str, dst: str, next_header: int, l4: bytes, *, ext: bytes = b"") -> bytes:
    head = struct.pack(
        "!IHBB16s16s", 6 << 28, len(ext) + len(l4), next_header if not ext else 0, 64,
        socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst),
    )  # fmt: skip
    return head + ext + l4


def ether(ip: bytes, *, ethertype: int = 0x0800, vlan: int | None = None, pad_to: int = 0) -> bytes:
    macs = bytes.fromhex("020000000002020000000001")
    if vlan is None:
        frame = macs + struct.pack("!H", ethertype) + ip
    else:
        frame = macs + struct.pack("!HHH", 0x8100, vlan, ethertype) + ip
    return frame + bytes(max(0, pad_to - len(frame)))  # Ethernet pads short frames


def pcap_bytes(
    frames: list[Frame], *, linktype: int = 1, big: bool = False, nano: bool = False
) -> bytes:
    order = ">" if big else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    scale = 1_000_000_000 if nano else 1_000_000
    for frame in frames:
        ts, data = frame[0], frame[1]
        wire = frame[2] if len(frame) > 2 else len(data)  # type: ignore[misc]
        sec = int(ts)
        out += struct.pack(order + "IIII", sec, int((ts - sec) * scale), len(data), wire) + data
    return out


def write_pcap(path: Path, frames: list[Frame], **kwargs: object) -> Path:
    path.write_bytes(pcap_bytes(frames, **kwargs))  # type: ignore[arg-type]
    return path


class Totals:
    """What a flow built from a generated session should report (IP-level bytes, as NetFlow counts)."""

    def __init__(self) -> None:
        self.client_bytes = self.server_bytes = self.client_pkts = self.server_pkts = 0


def tcp_session(
    client: str,
    server: str,
    cport: int,
    sport: int,
    start: float,
    *,
    up: int,
    down: int,
    mss: int = 1400,
    gap: float = 0.01,
    close: bool = True,
    snap: int | None = None,
) -> tuple[list[Frame], Totals]:
    """A TCP conversation: handshake, ``up`` payload bytes client->server, ``down`` back, FIN/FIN."""
    frames: list[Frame] = []
    t = Totals()
    clock = start

    def send(from_client: bool, flags: int, payload: int = 0) -> None:
        nonlocal clock
        src, dst = (client, server) if from_client else (server, client)
        a, b = (cport, sport) if from_client else (sport, cport)
        seg = tcp_segment(a, b, flags, payload)
        frame = ether(ipv4_packet(src, dst, 6, seg))
        # snap: keep only the first bytes of each packet, like a header-only capture, and record the real size
        frames.append((clock, frame[:snap], len(frame)) if snap else (clock, frame))
        size = 20 + len(seg)
        if from_client:
            t.client_bytes, t.client_pkts = t.client_bytes + size, t.client_pkts + 1
        else:
            t.server_bytes, t.server_pkts = t.server_bytes + size, t.server_pkts + 1
        clock += gap

    send(True, SYN)
    send(False, SYN | ACK)
    send(True, ACK)
    for sent in range(0, up, mss):
        send(True, ACK | PSH, min(mss, up - sent))
    for sent in range(0, down, mss):
        send(False, ACK | PSH, min(mss, down - sent))
    if close:
        send(True, FIN | ACK)
        send(False, FIN | ACK)
        send(True, ACK)
    return frames, t
