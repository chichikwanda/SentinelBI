#!/usr/bin/env python3
"""SentinelBI sensor: turns the packet headers seen on this machine into flow records.

Use it when you cannot (or do not want to) configure NetFlow on a router: run it on the host you
want to watch, or on a gateway or mirror port that sees the traffic, tell it which IP address or
network to watch, and it posts flow records (addresses, ports, protocol, byte and packet counts,
timing) to your SentinelBI server.

Privacy: only packet HEADERS are read. Payload bytes are never stored, logged or sent, and the
record format has no field that could carry them. Run it only on hosts and networks you administer.

Needs Python 3.9+ and nothing else (standard library only).
  Linux:    sudo python3 sentinelbi_sensor.py ...          (or CAP_NET_RAW)
  Windows:  python sentinelbi_sensor.py ...                (from an Administrator terminal; IPv4 only)
  Any OS:   --read-pcap capture.pcap                       (replay a classic .pcap file, no privileges)

Quick check that capture works on this machine:  python3 sentinelbi_sensor.py --self-test
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import functools
import ipaddress
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Iterable, Iterator, List, NamedTuple, Optional, Set, Tuple

VERSION = "0.1.0"

TCP, UDP, ICMP, ICMPV6 = 6, 17, 1, 58
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


# --------------------------------------------------------------------------------------------
# Packet headers -> Packet (no payload is ever kept)
# --------------------------------------------------------------------------------------------
class Packet(NamedTuple):
    ts: float
    proto: int
    src: str
    dst: str
    sport: int
    dport: int
    flags: int  # TCP flag bits of this packet (0 for other protocols)
    length: int  # bytes at the IP layer, as NetFlow counts them


def _l4(proto: int, buf: bytes, off: int) -> Tuple[int, int, int]:
    """(src port, dst port, TCP flags). ICMP puts type*256+code in the destination port, which is
    how NetFlow v9 (and so the training data) records it."""
    if proto == TCP and len(buf) >= off + 14:
        sport, dport = struct.unpack_from("!HH", buf, off)
        return sport, dport, buf[off + 13]
    if proto == UDP and len(buf) >= off + 4:
        sport, dport = struct.unpack_from("!HH", buf, off)
        return sport, dport, 0
    if proto in (ICMP, ICMPV6) and len(buf) >= off + 2:
        return 0, buf[off] * 256 + buf[off + 1], 0
    return 0, 0, 0


def parse_ip(buf: bytes, ts: float, off: int = 0, wire: Optional[int] = None) -> Optional[Packet]:
    """Parse an IPv4 or IPv6 header starting at ``off``. Returns None for anything malformed.

    ``wire`` is the packet's real size (the capture copies only the headers out of the kernel)."""
    avail = len(buf) - off
    real = (wire - off) if wire else avail
    if avail < 20:
        return None
    version = buf[off] >> 4
    if version == 4:
        ihl = (buf[off] & 0x0F) * 4
        if ihl < 20 or avail < ihl:
            return None
        total = struct.unpack_from("!H", buf, off + 2)[0]
        # the header's length ignores Ethernet padding; 0 appears on offloaded (TSO) transmit
        length = total if total >= ihl else real
        frag = struct.unpack_from("!H", buf, off + 6)[0]
        proto = buf[off + 9]
        src = socket.inet_ntoa(buf[off + 12 : off + 16])
        dst = socket.inet_ntoa(buf[off + 16 : off + 20])
        sport, dport, flags = (0, 0, 0) if frag & 0x1FFF else _l4(proto, buf, off + ihl)
        return Packet(ts, proto, src, dst, sport, dport, flags, length)
    if version == 6:
        if avail < 40:
            return None
        payload_len = struct.unpack_from("!H", buf, off + 4)[0]
        nxt = buf[off + 6]
        src = socket.inet_ntop(socket.AF_INET6, buf[off + 8 : off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, buf[off + 24 : off + 40])
        pos = off + 40
        fragment = False
        for _ in range(8):  # skip extension headers
            if nxt in (0, 43, 60) and len(buf) >= pos + 2:
                nxt, pos = buf[pos], pos + (buf[pos + 1] + 1) * 8
            elif nxt == 44 and len(buf) >= pos + 8:
                fragment = bool(struct.unpack_from("!H", buf, pos + 2)[0] & 0xFFF8)
                nxt, pos = buf[pos], pos + 8
            else:
                break
        sport, dport, flags = (0, 0, 0) if fragment else _l4(nxt, buf, pos)
        return Packet(ts, nxt, src, dst, sport, dport, flags, 40 + payload_len)
    return None


def parse_ethernet(frame: bytes, ts: float, wire: Optional[int] = None) -> Optional[Packet]:
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    off = 14
    while ethertype in (0x8100, 0x88A8) and len(frame) >= off + 4:  # VLAN tags
        ethertype = struct.unpack_from("!H", frame, off + 2)[0]
        off += 4
    if ethertype in (0x0800, 0x86DD):
        return parse_ip(frame, ts, off, wire)
    return None


# --------------------------------------------------------------------------------------------
# Which packets to keep
# --------------------------------------------------------------------------------------------
class Matcher:
    """Keeps packets with an endpoint in the watched networks, and drops the sensor's own reports."""

    def __init__(self, networks: Iterable[str], excluded: Iterable[Tuple[str, int]] = ()) -> None:
        self.networks = [
            ipaddress.ip_network(n.strip(), strict=False) for n in networks if n.strip()
        ]
        self.excluded: Set[Tuple[str, int]] = set(excluded)

        @functools.lru_cache(maxsize=65536)
        def inside(ip: str) -> bool:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self.networks if net.version == addr.version)

        self._inside = inside

    def wanted(self, p: Packet) -> bool:
        if (p.src, p.sport) in self.excluded or (p.dst, p.dport) in self.excluded:
            return False
        if not self.networks:
            return True
        return self._inside(p.src) or self._inside(p.dst)


# --------------------------------------------------------------------------------------------
# Packets -> bidirectional flows
# --------------------------------------------------------------------------------------------
Endpoint = Tuple[str, int]


class _Flow:
    __slots__ = (
        "c_bytes",
        "c_pkts",
        "client",
        "closing",
        "fin_c",
        "fin_s",
        "first",
        "flags",
        "last",
        "proto",
        "s_bytes",
        "s_pkts",
        "server",
    )  # fmt: skip

    def __init__(self, proto: int, client: Endpoint, server: Endpoint, ts: float) -> None:
        self.proto, self.client, self.server = proto, client, server
        self.first = self.last = ts
        self.c_bytes = self.s_bytes = self.c_pkts = self.s_pkts = 0
        self.flags = 0
        self.fin_c = self.fin_s = self.closing = False


def _sender_is_client(p: Packet) -> bool:
    """Who opened the flow? The first packet's sender, unless it is plainly a server's reply."""
    if p.proto == TCP and p.flags & SYN:
        return not p.flags & ACK  # SYN opens; SYN+ACK is the server answering
    if p.proto in (TCP, UDP):  # capture began mid-conversation: a well-known port is the server
        return not (p.sport < 1024 <= p.dport)
    return True


class FlowTable:
    """Aggregates packets into flows. ``in_*`` is client->server, ``out_*`` is server->client, the
    same convention as the NetFlow v9 datasets the model was trained on."""

    def __init__(
        self,
        idle: float = 15.0,
        active: float = 60.0,
        linger: float = 1.0,
        max_flows: int = 100_000,
    ) -> None:
        self.idle, self.active, self.linger, self.max_flows = idle, active, linger, max_flows
        self._flows: Dict[tuple, _Flow] = {}

    def __len__(self) -> int:
        return len(self._flows)

    def add(self, p: Packet) -> List[dict]:
        """Count a packet. Returns records that had to be exported to make room (normally none)."""
        icmp = p.proto in (ICMP, ICMPV6)
        # ICMP carries type and code where ports would be, so a request and its reply would not
        # match: key them on the addresses alone and report the first packet's type/code
        a = (p.src, 0 if icmp else p.sport)
        b = (p.dst, 0 if icmp else p.dport)
        key = (p.proto, a, b) if a <= b else (p.proto, b, a)
        flow = self._flows.get(key)
        if flow is None:
            if _sender_is_client(p):
                client, server = (p.src, 0 if icmp else p.sport), (p.dst, p.dport)
            else:
                client, server = (p.dst, 0 if icmp else p.dport), (p.src, p.sport)
            flow = self._flows[key] = _Flow(p.proto, client, server, p.ts)
        from_client = a[0] == flow.client[0] and (icmp or a[1] == flow.client[1])
        if from_client:
            flow.c_bytes += p.length
            flow.c_pkts += 1
        else:
            flow.s_bytes += p.length
            flow.s_pkts += 1
        flow.flags |= p.flags
        flow.last = p.ts
        if p.proto == TCP:
            if p.flags & RST:
                flow.closing = True
            if p.flags & FIN:
                if from_client:
                    flow.fin_c = True
                else:
                    flow.fin_s = True
                flow.closing = flow.closing or (flow.fin_c and flow.fin_s)
        if len(self._flows) > self.max_flows:  # a scan or flood: export the oldest tenth now
            oldest = sorted(self._flows.items(), key=lambda kv: kv[1].last)[: self.max_flows // 10]
            return [r for k, f in oldest if (r := self._take(k, f))]
        return []

    def _take(self, key: tuple, flow: _Flow) -> Optional[dict]:
        self._flows.pop(key, None)
        return record(flow) if flow.c_pkts + flow.s_pkts else None

    def expire(self, now: float, force: bool = False) -> List[dict]:
        out: List[dict] = []
        for key, flow in list(self._flows.items()):
            idle_for = now - flow.last
            if force or idle_for >= self.idle or (flow.closing and idle_for >= self.linger):
                rec = self._take(key, flow)
                if rec:
                    out.append(rec)
            elif now - flow.first >= self.active and flow.c_pkts + flow.s_pkts:
                out.append(record(flow))  # long flow: report what we have so far and keep counting
                flow.first = flow.last
                flow.c_bytes = flow.s_bytes = flow.c_pkts = flow.s_pkts = 0
                flow.flags = 0
        return out


def record(flow: _Flow) -> dict:
    """One flow in the platform's canonical ingest format (see backend FlowIn)."""
    return {
        "ts": datetime.fromtimestamp(flow.first, tz=timezone.utc).isoformat(),
        "src_ip": flow.client[0],
        "dst_ip": flow.server[0],
        "src_port": flow.client[1],
        "dst_port": flow.server[1],
        "protocol": flow.proto,
        "tcp_flags": flow.flags,
        "in_bytes": flow.c_bytes,
        "out_bytes": flow.s_bytes,
        "in_pkts": flow.c_pkts,
        "out_pkts": flow.s_pkts,
        "duration_ms": max(0, int((flow.last - flow.first) * 1000)),
    }


# --------------------------------------------------------------------------------------------
# Where packets come from
# --------------------------------------------------------------------------------------------
# (timestamp, header bytes, "eth" | "ip", real packet length); None = idle tick
Raw = Optional[Tuple[float, bytes, str, int]]
HEADER_BYTES = 256  # enough for Ethernet + IP + TCP with options; payload is never copied


SOL_PACKET, PACKET_STATISTICS, SO_RCVBUFFORCE = 263, 6, 33


class LinuxCapture:
    """AF_PACKET capture. Only the first HEADER_BYTES of each packet are copied out of the kernel;
    MSG_TRUNC still reports the real length, so byte counts are exact."""

    def __init__(self, iface: Optional[str]) -> None:
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # type: ignore[attr-defined]
        # A packet socket is charged for whole packets (offloading makes them up to 64 KB), so the
        # default ~200 KB buffer overflows in a burst and the kernel silently drops our copies.
        # SO_RCVBUFFORCE (needs CAP_NET_ADMIN, which root has) lifts the cap; otherwise the best
        # SO_RCVBUF the system allows. Whatever is still lost is counted in ``drops``.
        for option in (SO_RCVBUFFORCE, socket.SO_RCVBUF):
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, option, 32 * 1024 * 1024)
                break
            except OSError:
                continue
        if iface:
            self.sock.bind((iface, 0))
        self.sock.settimeout(1.0)
        self.drops = 0

    def _count_drops(self) -> None:
        with contextlib.suppress(OSError):  # reading the statistics resets them, so add them up
            self.drops += struct.unpack(
                "II", self.sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            )[1]

    def __iter__(self) -> Iterator[Raw]:
        buf = bytearray(HEADER_BYTES)
        seen = 0
        try:
            while True:
                try:
                    size, meta = self.sock.recvfrom_into(buf, HEADER_BYTES, socket.MSG_TRUNC)
                except socket.timeout:
                    self._count_drops()
                    yield None
                    continue
                if meta[0] == "lo":  # loopback shows every packet twice and is not network traffic
                    continue
                seen += 1
                if seen % 2000 == 0:
                    self._count_drops()
                yield time.time(), bytes(buf[: min(size, HEADER_BYTES)]), "eth", size
        finally:
            self._count_drops()
            self.sock.close()


def default_local_ip() -> str:
    """The address of the interface that reaches the internet (nothing is sent)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        return str(probe.getsockname()[0])
    finally:
        probe.close()


def windows_source(local_ip: str) -> Iterator[Raw]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind((local_ip, 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # type: ignore[attr-defined]
    sock.settimeout(1.0)
    try:
        while True:
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                yield None
                continue
            yield time.time(), data[:HEADER_BYTES], "ip", len(data)
    finally:
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  # type: ignore[attr-defined]
        finally:
            sock.close()


def pcap_source(path: str, header_only: bool = False) -> Iterator[Raw]:
    """Read a classic libpcap file (Ethernet, raw IP or Linux 'cooked' captures).

    With ``header_only`` the packet bytes are skipped and only timestamps are produced."""
    with open(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            raise ValueError("not a pcap file (too short)")
        magic = head[:4]
        if magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError(
                "this is a pcapng file; convert it first: editcap -F pcap in.pcapng out.pcap"
            )
        endian = {
            b"\xd4\xc3\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\x3c\x4d": ">",
        }.get(magic)
        if endian is None:
            raise ValueError("not a pcap file (unknown magic number)")
        nanos = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        link = struct.unpack(endian + "I", head[20:24])[0]
        kinds = {1: ("eth", 0), 101: ("ip", 0), 113: ("ip", 16)}
        if link not in kinds:
            raise ValueError(
                f"unsupported pcap link type {link} (supported: Ethernet, raw IP, Linux cooked)"
            )
        kind, skip = kinds[link]
        while True:
            hdr = fh.read(16)
            if len(hdr) < 16:
                return
            sec, frac, caplen, wire = struct.unpack(endian + "IIII", hdr)
            if header_only:
                fh.seek(caplen, 1)
                data = b""
            else:
                data = fh.read(caplen)
                if len(data) < caplen:
                    return
            ts = sec + frac / (1e9 if nanos else 1e6)
            yield ts, data[skip:], kind, max(wire, caplen) - skip


def parse_raw(raw: Tuple[float, bytes, str, int]) -> Optional[Packet]:
    ts, data, kind, wire = raw
    try:
        return parse_ethernet(data, ts, wire) if kind == "eth" else parse_ip(data, ts, 0, wire)
    except (struct.error, ValueError, OSError):  # malformed packets are skipped, never fatal
        return None


# --------------------------------------------------------------------------------------------
# Sending flows to SentinelBI (own thread, so capture is never blocked by the network)
# --------------------------------------------------------------------------------------------
class Exporter:
    def __init__(
        self, api_url: str, api_key: str, batch: int = 500, max_pending: int = 50_000
    ) -> None:
        if not api_url.lower().startswith(("http://", "https://")):
            raise ValueError("--api-url must start with http:// or https://")
        self.url = api_url.rstrip("/") + "/api/v1/ingest/flows"
        self.key, self.batch = api_key, batch
        self.pending: collections.deque = collections.deque(maxlen=max_pending)
        self.sent = self.dropped = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="exporter", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def submit(self, records: List[dict]) -> None:
        with self._lock:
            overflow = len(self.pending) + len(records) - (self.pending.maxlen or 0)
            if overflow > 0:  # the server has been unreachable for a long time: oldest go first
                self.dropped += overflow
            self.pending.extend(records)

    def post(self, records: List[dict]) -> bool:
        body = json.dumps({"flows": records}).encode()
        req = urllib.request.Request(  # noqa: S310 - the scheme is checked in __init__
            self.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self.key,
                "User-Agent": f"sentinelbi-sensor/{VERSION}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - same URL, scheme checked
                return resp.status == 202
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                log(f"the server rejected the API key (HTTP {exc.code}); check --api-key")
            elif exc.code in (400, 413, 422):  # this batch will never be accepted: do not retry it
                log(
                    f"the server refused a batch of {len(records)} flows (HTTP {exc.code}); dropping it"
                )
                return True
            else:
                log(f"server answered HTTP {exc.code}; will retry")
            return False
        except (urllib.error.URLError, OSError) as exc:
            log(f"cannot reach {self.url}: {getattr(exc, 'reason', exc)}; will retry")
            return False

    def flush_once(self) -> bool:
        with self._lock:
            batch = [self.pending.popleft() for _ in range(min(self.batch, len(self.pending)))]
        if not batch:
            return True
        if self.post(batch):
            self.sent += len(batch)
            return True
        with self._lock:  # put it back at the front, in order
            self.pending.extendleft(reversed(batch))
        return False

    def _loop(self) -> None:
        wait = 1.0
        while not self._stop.is_set():
            ok = self.flush_once()
            wait = 1.0 if ok else min(wait * 2, 30.0)
            if ok and self.pending:
                continue
            self._stop.wait(wait)

    def close(self, drain_seconds: float = 10.0) -> None:
        """Stop, then make a last bounded attempt to deliver what is left."""
        self._stop.set()
        self._thread.join(timeout=15)
        deadline = time.time() + drain_seconds
        while self.pending and time.time() < deadline and self.flush_once():
            pass


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------------
def endpoints_of(api_url: str) -> Set[Tuple[str, int]]:
    """The server's own address(es), so the sensor's reports are not counted as traffic."""
    from urllib.parse import urlparse

    parsed = urlparse(api_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        return {
            (str(info[4][0]), port)
            for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        }
    except OSError:
        return set()


def open_live(args: argparse.Namespace) -> Iterator[Raw]:
    if sys.platform.startswith("linux"):
        return LinuxCapture(args.iface)
    if sys.platform == "win32":
        local = args.interface_ip
        if not local:
            hosts = [n for n in (args.ip or []) if "/" not in n and ":" not in n]
            local = hosts[0] if len(hosts) == 1 and _is_local(hosts[0]) else default_local_ip()
        return windows_source(local)
    raise SystemExit(
        "this OS is not supported for live capture; use --read-pcap with a capture file"
    )


def _is_local(ip: str) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def off_route_warning(networks: List[str]) -> Optional[str]:
    """A single address that belongs to this machine but is not the one internet traffic leaves from
    (typically a virtual adapter: Hyper-V, WSL, Docker) would match almost nothing. Say so."""
    try:
        default = default_local_ip()
    except OSError:
        return None  # no route at all: nothing sensible to compare with
    for item in networks:
        try:
            net = ipaddress.ip_network(item.strip(), strict=False)
        except ValueError:
            continue
        if net.version == 4 and net.num_addresses == 1:
            address = str(net.network_address)
            if address != default and _is_local(address):
                return (
                    f"{address} is an address of this machine, but not the one your internet traffic uses "
                    f"({default}, from the default route). Only traffic to or from {address} is reported, "
                    f"so ordinary browsing will not appear. To watch this machine's traffic use --ip {default} "
                    "(Windows: it is the adapter with a Default Gateway in ipconfig, not a vEthernet one)."
                )
    return None


def has_global_ipv6() -> bool:
    """True when this machine has a routable IPv6 address (so much of its traffic may be IPv6)."""
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
    except OSError:
        return False
    return any(not str(i[4][0]).lower().startswith(("fe80", "::1")) for i in infos)


def ipv6_notice() -> Optional[str]:
    """Windows capture reads IPv4 only; on a dual-stack machine most browsing can be IPv6."""
    if sys.platform != "win32" or not has_global_ipv6():
        return None
    return (
        "this machine also has IPv6, and the Windows sensor reads IPv4 only. Traffic that uses IPv6 "
        "(often most web browsing, and QUIC) is NOT counted, so volumes here are a lower bound. "
        "Linux captures both. IPv4 traffic, for example `ping -4 1.1.1.1`, is counted."
    )


def capture_diagnosis(
    seen: int, kept: int, networks: List[str], on_windows: bool, ipv6: bool
) -> Optional[str]:
    """Why nothing is being reported, said once after the first ten quiet seconds."""
    if seen == 0:
        why = (
            "this machine may be idle, capture may be on the wrong interface (Linux: --iface NAME; "
            "Windows: --interface-ip ADDRESS)"
        )
        if on_windows and ipv6:
            why += ", or its traffic is IPv6, which the Windows sensor cannot read"
        return f"no packets were seen in the first 10 seconds: {why}. Try `ping -4 1.1.1.1` to generate IPv4 traffic."
    if kept == 0 and networks:
        return (
            f"packets are arriving ({seen} so far) but none involve {', '.join(networks)}. "
            "Check that address is the one this traffic really uses (ipconfig on Windows, "
            "ip route get 1.1.1.1 on Linux)."
        )
    return None


def privilege_hint() -> str:
    if sys.platform == "win32":
        return "live capture needs an Administrator terminal"
    return "live capture needs root (sudo) or the NET_RAW capability (docker run --cap-add=NET_RAW)"


def self_test(args: argparse.Namespace) -> int:
    """Send one datagram to a documentation address and check the capture sees it leave."""
    target = "192.0.2.1"  # TEST-NET-1: never routed to a real host
    try:
        source = open_live(args)
        iterator = iter(source)
        next(iterator)  # opens the socket (and fails here if privileges are missing)
    except PermissionError:
        log(f"cannot open the capture socket: {privilege_hint()}")
        return 2
    except OSError as exc:
        log(f"cannot open the capture socket: {exc} ({privilege_hint()})")
        return 2
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.sendto(b"sentinelbi-self-test", (target, 9))
        probe.close()
    except OSError as exc:
        log(f"cannot send the test packet ({exc}); is this machine connected to a network?")
        return 2
    deadline = time.time() + 3.0
    for raw in iterator:
        if raw is not None:
            pkt = parse_raw(raw)
            if pkt and pkt.dst == target and pkt.proto == UDP:
                log(
                    f"capture works: saw this machine's outgoing packet ({pkt.length} bytes) to {target}"
                )
                return 0
        if time.time() > deadline:
            break
    log(
        "capture opened, but this machine's own outgoing packet was not seen. Try --iface <name> (Linux) "
        "or --interface-ip <this machine's address> (Windows), or run from an Administrator/root terminal."
    )
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinelbi_sensor",
        description="Report flow records (headers only, never payloads) to a SentinelBI server.",
    )
    p.add_argument(
        "--api-url",
        default=os.environ.get("SENTINELBI_API_URL"),
        help="e.g. http://192.0.2.10:8000",
    )
    p.add_argument(
        "--api-key", default=os.environ.get("SENTINELBI_API_KEY"), help="the source's API key"
    )
    p.add_argument(
        "--ip",
        action="append",
        help="IP address or network to watch; repeat or comma-separate. Omit to report everything seen",
    )
    p.add_argument("--iface", help="Linux: capture on this interface only (default: all except lo)")
    p.add_argument(
        "--interface-ip",
        help="Windows: local address of the interface to capture on (default: the one with the default route)",
    )
    p.add_argument(
        "--read-pcap", metavar="FILE", help="read a classic .pcap file instead of capturing live"
    )
    p.add_argument(
        "--shift-to-now",
        action="store_true",
        help="with --read-pcap: move timestamps so the capture ends now",
    )
    p.add_argument(
        "--map-ip",
        action="append",
        metavar="FROM=TO",
        help="with --read-pcap: rewrite an address (e.g. to pretend a recorded host is yours)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="print flow records as JSON lines instead of sending them",
    )
    p.add_argument(
        "--self-test",
        action="store_true",
        help="check that capture works on this machine, then exit",
    )
    p.add_argument(
        "--idle-timeout",
        type=float,
        default=15.0,
        help="seconds without packets before a flow is reported (default 15)",
    )
    p.add_argument(
        "--active-timeout",
        type=float,
        default=60.0,
        help="report long flows at least this often (default 60)",
    )
    p.add_argument(
        "--stats-interval",
        type=float,
        default=30.0,
        help="seconds between status lines (default 30)",
    )
    p.add_argument("--version", action="version", version=f"sentinelbi-sensor {VERSION}")
    return p


_END = object()


def run(args: argparse.Namespace) -> int:
    networks = [n for item in (args.ip or []) for n in item.split(",") if n.strip()]
    try:
        matcher = Matcher(networks)
    except ValueError as exc:
        log(f"--ip: {exc}")
        return 2
    if args.self_test:
        return self_test(args)
    remap: Dict[str, str] = {}
    for pair in args.map_ip or []:
        old, _, new = pair.partition("=")
        try:
            remap[str(ipaddress.ip_address(old.strip()))] = str(ipaddress.ip_address(new.strip()))
        except ValueError:
            log(f"--map-ip expects FROM=TO with two IP addresses, got {pair!r}")
            return 2
    exporter: Optional[Exporter] = None
    if not args.dry_run:
        if not args.api_url or not args.api_key:
            log("--api-url and --api-key are required (or use --dry-run)")
            return 2
        matcher.excluded = endpoints_of(args.api_url)  # do not count our own reports
        exporter = Exporter(args.api_url, args.api_key)

    table = FlowTable(idle=args.idle_timeout, active=args.active_timeout)
    offline = bool(args.read_pcap)
    shift = 0.0
    try:
        if offline:
            if args.shift_to_now:
                ends = [raw[0] for raw in pcap_source(args.read_pcap, header_only=True) if raw]
                shift = time.time() - max(ends) if ends else 0.0
            source = pcap_source(args.read_pcap)
        else:
            source = open_live(args)
        iterator = iter(source)
        first = next(iterator, _END)  # surfaces permission problems before we say we are running
    except FileNotFoundError:
        log(f"no such file: {args.read_pcap}")
        return 2
    except ValueError as exc:
        log(str(exc))
        return 2
    except PermissionError:
        log(f"cannot open the capture socket: {privilege_hint()}")
        return 2
    except OSError as exc:
        log(f"cannot start capture: {exc} ({privilege_hint()})")
        return 2

    if exporter:
        exporter.start()
    stop = threading.Event()
    if not offline:
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, lambda *_: stop.set())
        log(
            f"sensor {VERSION} capturing; watching {', '.join(networks) or 'all traffic'}; Ctrl+C to stop"
        )
        warning = off_route_warning(networks)
        if warning:
            log(f"WARNING: {warning}")
        notice = ipv6_notice()
        if notice:
            log(f"NOTE: {notice}")

    counts = {"seen": 0, "kept": 0, "flows": 0}
    started_at = time.time()
    diagnosed = False

    def emit(records: List[dict]) -> None:
        counts["flows"] += len(records)
        if args.dry_run:
            for rec in records:
                print(json.dumps(rec), flush=True)
        elif exporter and records:
            exporter.submit(records)

    items: Iterable[Raw] = [] if first is _END else _chain(first, iterator)  # type: ignore[arg-type]
    clock = last_expire = last_stats = 0.0
    last_stats = time.time()
    try:
        for raw in items:
            if stop.is_set():
                break
            if raw is not None:
                counts["seen"] += 1
                if shift:
                    raw = (raw[0] + shift, raw[1], raw[2], raw[3])
                pkt = parse_raw(raw)
                if pkt is not None and remap:
                    pkt = pkt._replace(
                        src=remap.get(pkt.src, pkt.src), dst=remap.get(pkt.dst, pkt.dst)
                    )
                if pkt is not None and matcher.wanted(pkt):
                    counts["kept"] += 1
                    emit(table.add(pkt))
                clock = max(clock, raw[0])
            if not offline:
                clock = time.time()  # live: the wall clock drives expiry, even when it is quiet
            if clock - last_expire >= 1.0:
                last_expire = clock
                emit(table.expire(clock))
            if not offline and not diagnosed and time.time() - started_at >= 10.0:
                diagnosed = (
                    True  # once: say why nothing is being reported, instead of staying silent
                )
                hint = capture_diagnosis(
                    counts["seen"],
                    counts["kept"],
                    networks,
                    sys.platform == "win32",
                    has_global_ipv6(),
                )
                if hint:
                    log(f"WARNING: {hint}")
            if not offline and time.time() - last_stats >= args.stats_interval:
                last_stats = time.time()
                waiting = len(exporter.pending) if exporter else 0
                lost = getattr(source, "drops", 0)
                log(
                    f"packets seen={counts['seen']} kept={counts['kept']} active flows={len(table)} "
                    f"reported={counts['flows']} waiting to send={waiting}"
                    + (
                        f"; KERNEL DROPPED {lost} packets (byte counts are a lower bound)"
                        if lost
                        else ""
                    )
                )
    except PermissionError:
        log(f"capture failed: {privilege_hint()}")
        return 2
    except OSError as exc:
        log(f"capture stopped: {exc}")
        return 1
    finally:
        emit(table.expire(clock or time.time(), force=True))
        if exporter:
            exporter.close()
            lost = len(exporter.pending)
            log(
                f"stopped; sent {exporter.sent} flow records"
                + (f", {lost} could not be delivered" if lost else "")
                + (
                    f", {exporter.dropped} dropped while the server was unreachable"
                    if exporter.dropped
                    else ""
                )
            )
        dropped = getattr(source, "drops", 0)
        if dropped:
            log(
                f"WARNING: the kernel dropped {dropped} packets before they were read, so byte counts "
                "are a lower bound. Run as root (or add --cap-add=NET_ADMIN in Docker) to enlarge the "
                "capture buffer, or capture on one interface with --iface."
            )
    return 0


def _chain(first: Raw, rest: Iterator[Raw]) -> Iterator[Raw]:
    yield first
    yield from rest


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
