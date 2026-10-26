"""The sensor: header parsing, flow building, capture-file reading, delivery and the command line."""

from __future__ import annotations

import hashlib
import json
import random
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

import sensorkit as kit
import sentinelbi_sensor as s
from app.schemas.ingest import FlowIn
from sensorkit import ACK, FIN, PSH, RST, SYN

SENSOR = Path(__file__).resolve().parents[2] / "sensor" / "sentinelbi_sensor.py"
T0 = 1_700_000_000.0


def pkt(**over: Any) -> s.Packet:
    base: dict[str, Any] = {
        "ts": T0, "proto": 6, "src": "10.0.0.5", "dst": "198.51.100.7",
        "sport": 51000, "dport": 443, "flags": ACK, "length": 100,
    }  # fmt: skip
    return s.Packet(**{**base, **over})


# ---------------------------------------------------------------------------------- parsing
def test_ipv4_tcp_fields_and_ip_level_length() -> None:
    seg = kit.tcp_segment(51000, 443, SYN | ACK, payload=100)
    p = s.parse_ethernet(kit.ether(kit.ipv4_packet("10.0.0.5", "198.51.100.7", 6, seg)), T0)
    assert p == s.Packet(T0, 6, "10.0.0.5", "198.51.100.7", 51000, 443, SYN | ACK, 20 + 20 + 100)


def test_ethernet_padding_does_not_count_as_bytes() -> None:
    ack = kit.ipv4_packet("10.0.0.5", "198.51.100.7", 6, kit.tcp_segment(1, 2))  # 40 bytes
    padded = s.parse_ethernet(kit.ether(ack, pad_to=64), T0)
    assert padded is not None and padded.length == 40


def test_vlan_tagged_frames_are_parsed() -> None:
    ip = kit.ipv4_packet("10.0.0.5", "10.0.0.6", 17, kit.udp_datagram(5353, 53, 20))
    p = s.parse_ethernet(kit.ether(ip, vlan=42), T0)
    assert p is not None and (p.sport, p.dport, p.length) == (5353, 53, 20 + 8 + 20)


def test_udp_and_icmp() -> None:
    udp = s.parse_ip(
        kit.ipv4_packet("10.0.0.5", "9.9.9.9", 17, kit.udp_datagram(40000, 53, 30)), T0
    )
    assert udp is not None and (udp.proto, udp.sport, udp.dport, udp.length) == (17, 40000, 53, 58)
    echo = s.parse_ip(kit.ipv4_packet("10.0.0.5", "9.9.9.9", 1, kit.icmp_message(8, 0, 56)), T0)
    assert echo is not None and echo.dport == 8 * 256  # type*256+code, as NetFlow v9 records it


def test_ipv6_with_an_extension_header() -> None:
    hop_by_hop = bytes([6, 0]) + bytes(6)  # next header = TCP, length 8 bytes
    seg = kit.tcp_segment(50000, 443, ACK, payload=10)
    raw = kit.ipv6_packet("2001:db8::5", "2001:db8::7", 6, seg, ext=hop_by_hop)
    p = s.parse_ip(raw, T0)
    assert p is not None
    assert (p.src, p.dst, p.proto, p.sport, p.dport) == (
        "2001:db8::5",
        "2001:db8::7",
        6,
        50000,
        443,
    )
    assert p.length == 40 + 8 + 20 + 10


def test_later_fragments_have_no_ports() -> None:
    raw = kit.ipv4_packet("10.0.0.5", "10.0.0.6", 17, bytes(64), frag=185)  # offset 185*8
    p = s.parse_ip(raw, T0)
    assert p is not None and (p.sport, p.dport, p.length) == (0, 0, 84)


def test_offloaded_transmit_packets_with_length_zero_use_the_captured_size() -> None:
    raw = kit.ipv4_packet("10.0.0.5", "10.0.0.6", 6, kit.tcp_segment(1, 2, payload=3000), total=0)
    p = s.parse_ip(raw, T0)
    assert p is not None and p.length == len(raw)


def test_only_headers_are_needed_when_the_real_length_is_known() -> None:
    # the live capture copies HEADER_BYTES per packet and learns the real size from MSG_TRUNC
    big = kit.ether(
        kit.ipv4_packet("10.0.0.5", "10.0.0.6", 6, kit.tcp_segment(1, 2, payload=60_000), total=0)
    )
    head = big[: s.HEADER_BYTES]
    p = s.parse_ethernet(head, T0, wire=len(big))
    assert p is not None and p.length == len(big) - 14  # an offloaded 60 kB packet, counted in full
    assert (p.sport, p.dport) == (1, 2)


def test_truncated_capture_reports_the_wire_length() -> None:
    raw = kit.ipv4_packet("10.0.0.5", "10.0.0.6", 6, kit.tcp_segment(1, 2), total=1500)
    p = s.parse_ip(raw, T0)
    assert p is not None and p.length == 1500


def test_garbage_never_raises() -> None:
    rng = random.Random(7)
    for _ in range(3000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 90)))
        s.parse_raw((T0, blob, "eth", len(blob)))
        s.parse_raw((T0, blob, "ip", len(blob)))
    assert s.parse_ip(b"\x45" + bytes(10), T0) is None  # too short
    assert s.parse_ip(bytes([0x42]) + bytes(40), T0) is None  # IP version 4 with ihl 8 bytes
    assert s.parse_ethernet(kit.ether(b"x" * 30, ethertype=0x0806), T0) is None  # ARP


# ---------------------------------------------------------------------------------- matching
def test_matcher_keeps_traffic_of_watched_networks_only() -> None:
    m = s.Matcher(["10.0.0.5", "192.168.1.0/24", "2001:db8::/32"])
    assert m.wanted(pkt(src="10.0.0.5", dst="1.1.1.1"))
    assert m.wanted(pkt(src="1.1.1.1", dst="192.168.1.77"))
    assert m.wanted(pkt(src="2001:db8::1", dst="2001:4860::1"))
    assert not m.wanted(pkt(src="10.0.0.6", dst="1.1.1.1"))
    assert s.Matcher([]).wanted(pkt(src="1.2.3.4", dst="5.6.7.8"))  # no filter: everything


def test_matcher_drops_the_sensors_own_reports() -> None:
    m = s.Matcher(["10.0.0.5"], excluded={("198.51.100.7", 8000)})
    assert not m.wanted(pkt(dst="198.51.100.7", dport=8000))
    assert not m.wanted(pkt(src="198.51.100.7", sport=8000, dst="10.0.0.5"))
    assert m.wanted(pkt(dst="198.51.100.7", dport=443))


def test_the_api_address_is_excluded() -> None:
    assert ("127.0.0.1", 8000) in s.endpoints_of("http://127.0.0.1:8000")


def test_bad_network_is_rejected() -> None:
    with pytest.raises(ValueError):
        s.Matcher(["not-an-ip"])


# ---------------------------------------------------------------------------------- flows
def feed(table: s.FlowTable, frames: list[kit.Frame]) -> list[dict]:
    out: list[dict] = []
    for ts, data in frames:
        p = s.parse_ethernet(data, ts)
        assert p is not None
        out += table.add(p)
    return out


def test_a_tcp_session_becomes_one_bidirectional_flow_with_exact_byte_counts() -> None:
    frames, want = kit.tcp_session("10.0.0.5", "198.51.100.7", 51000, 443, T0, up=3000, down=12_000)
    table = s.FlowTable()
    feed(table, frames)
    (rec,) = table.expire(frames[-1][0] + 2.0)  # both FINs seen: reported after the short linger
    assert (rec["src_ip"], rec["dst_ip"], rec["src_port"], rec["dst_port"]) == (
        "10.0.0.5", "198.51.100.7", 51000, 443,
    )  # fmt: skip
    assert (rec["in_bytes"], rec["out_bytes"]) == (want.client_bytes, want.server_bytes)
    assert (rec["in_pkts"], rec["out_pkts"]) == (want.client_pkts, want.server_pkts)
    assert rec["tcp_flags"] == SYN | ACK | PSH | FIN
    assert rec["protocol"] == 6 and rec["duration_ms"] == int((frames[-1][0] - T0) * 1000)
    assert rec["ts"].startswith("2023-11-14")
    assert len(table) == 0


def test_records_are_valid_ingest_records() -> None:
    frames, _ = kit.tcp_session("10.0.0.5", "198.51.100.7", 51000, 443, T0, up=100, down=100)
    table = s.FlowTable()
    feed(table, frames)
    for rec in table.expire(T0 + 100):
        FlowIn.model_validate(rec)  # the platform's own schema (extra fields are forbidden there)


def test_a_server_reply_seen_first_does_not_make_the_server_the_client() -> None:
    table = s.FlowTable()
    table.add(
        pkt(src="198.51.100.7", sport=443, dst="10.0.0.5", dport=51000, flags=SYN | ACK, length=60)
    )
    table.add(pkt(ts=T0 + 0.01, flags=ACK, length=52))
    (rec,) = table.expire(T0 + 100)
    assert (rec["src_ip"], rec["dst_ip"], rec["dst_port"]) == ("10.0.0.5", "198.51.100.7", 443)
    assert (rec["in_bytes"], rec["out_bytes"]) == (52, 60)


def test_udp_captured_mid_conversation_treats_the_well_known_port_as_the_server() -> None:
    table = s.FlowTable()
    table.add(
        pkt(proto=17, src="9.9.9.9", sport=53, dst="10.0.0.5", dport=40000, length=120, flags=0)
    )
    table.add(
        pkt(
            proto=17,
            ts=T0 + 0.1,
            src="10.0.0.5",
            sport=40000,
            dst="9.9.9.9",
            dport=53,
            length=70,
            flags=0,
        )
    )
    (rec,) = table.expire(T0 + 100)
    assert (rec["src_ip"], rec["dst_port"], rec["in_bytes"], rec["out_bytes"]) == (
        "10.0.0.5",
        53,
        70,
        120,
    )


def test_icmp_echo_request_and_reply_are_one_flow() -> None:
    table = s.FlowTable()
    table.add(
        pkt(proto=1, src="10.0.0.5", sport=0, dst="9.9.9.9", dport=8 * 256, flags=0, length=84)
    )
    table.add(
        pkt(
            proto=1,
            ts=T0 + 0.02,
            src="9.9.9.9",
            sport=0,
            dst="10.0.0.5",
            dport=0,
            flags=0,
            length=84,
        )
    )
    (rec,) = table.expire(T0 + 100)
    assert (rec["in_pkts"], rec["out_pkts"], rec["dst_port"], rec["src_port"]) == (1, 1, 2048, 0)


def test_two_conversations_between_the_same_hosts_stay_separate() -> None:
    table = s.FlowTable()
    table.add(pkt(sport=50001))
    table.add(pkt(sport=50002))
    assert len(table.expire(T0 + 100)) == 2


def test_idle_flows_are_reported_only_after_the_idle_timeout() -> None:
    table = s.FlowTable(idle=15)
    table.add(pkt())
    assert table.expire(T0 + 14.9) == []
    assert len(table.expire(T0 + 15.0)) == 1
    assert table.expire(T0 + 60) == []


def test_reset_closes_a_flow_quickly() -> None:
    table = s.FlowTable(idle=15, linger=1)
    table.add(pkt())
    table.add(
        pkt(ts=T0 + 0.5, src="198.51.100.7", sport=443, dst="10.0.0.5", dport=51000, flags=RST)
    )
    assert len(table.expire(T0 + 2.0)) == 1


def test_long_flows_are_reported_in_pieces_without_losing_a_byte_or_the_direction() -> None:
    table = s.FlowTable(idle=15, active=60)
    records: list[dict] = []
    for i in range(130):  # one packet each way per second for 130 s
        t = T0 + i
        table.add(pkt(ts=t, length=100))
        table.add(
            pkt(ts=t + 0.5, src="198.51.100.7", sport=443, dst="10.0.0.5", dport=51000, length=1000)
        )
        records += table.expire(t + 0.9)
    records += table.expire(T0 + 1000)
    assert len(records) >= 3
    assert {r["src_ip"] for r in records} == {
        "10.0.0.5"
    }  # the client stays the client in every piece
    assert sum(r["in_bytes"] for r in records) == 130 * 100
    assert sum(r["out_bytes"] for r in records) == 130 * 1000


def test_a_flood_cannot_grow_the_table_without_limit() -> None:
    table = s.FlowTable(max_flows=100)
    exported = 0
    for i in range(1000):
        exported += len(table.add(pkt(ts=T0 + i * 0.001, sport=1000 + i)))
    assert len(table) <= 101
    assert exported > 0


# ---------------------------------------------------------------------------------- pcap files
def read(path: Path, **kw: Any) -> list[s.Packet | None]:
    return [s.parse_raw(r) for r in s.pcap_source(str(path), **kw) if r is not None]


def one_frame() -> list[kit.Frame]:
    return [
        (
            T0 + 0.25,
            kit.ether(kit.ipv4_packet("10.0.0.5", "9.9.9.9", 17, kit.udp_datagram(1, 53, 10))),
        )
    ]


@pytest.mark.parametrize("big", [False, True])
@pytest.mark.parametrize("nano", [False, True])
def test_pcap_variants_are_read(tmp_path: Path, big: bool, nano: bool) -> None:
    path = kit.write_pcap(tmp_path / "x.pcap", one_frame(), big=big, nano=nano)
    (p,) = read(path)
    assert p is not None and abs(p.ts - (T0 + 0.25)) < 1e-6 and p.dport == 53


def test_raw_ip_and_linux_cooked_captures_are_read(tmp_path: Path) -> None:
    ip = kit.ipv4_packet("10.0.0.5", "9.9.9.9", 17, kit.udp_datagram(1, 53, 10))
    raw = kit.write_pcap(tmp_path / "raw.pcap", [(T0, ip)], linktype=101)
    cooked = kit.write_pcap(
        tmp_path / "cooked.pcap", [(T0, bytes(14) + b"\x08\x00" + ip)], linktype=113
    )
    assert [p.dport for p in read(raw) if p] == [53]
    assert [p.dport for p in read(cooked) if p] == [53]


def test_header_only_reading_gives_timestamps_without_packet_bytes(tmp_path: Path) -> None:
    frames = [*one_frame(), (T0 + 9.0, one_frame()[0][1])]
    path = kit.write_pcap(tmp_path / "x.pcap", frames)
    stamps = [raw[0] for raw in s.pcap_source(str(path), header_only=True) if raw]
    assert stamps == [T0 + 0.25, T0 + 9.0]


def test_unreadable_captures_are_explained(tmp_path: Path) -> None:
    ng = tmp_path / "x.pcapng"
    ng.write_bytes(b"\x0a\x0d\x0d\x0a" + bytes(40))
    with pytest.raises(ValueError, match="pcapng"):
        list(s.pcap_source(str(ng)))
    junk = tmp_path / "junk"
    junk.write_bytes(b"hello world, this is not a capture file")
    with pytest.raises(ValueError, match="magic"):
        list(s.pcap_source(str(junk)))
    wifi = kit.write_pcap(tmp_path / "wifi.pcap", one_frame(), linktype=127)
    with pytest.raises(ValueError, match="link type"):
        list(s.pcap_source(str(wifi)))


def test_a_truncated_capture_file_yields_what_it_has(tmp_path: Path) -> None:
    data = kit.pcap_bytes(one_frame() * 3)
    path = tmp_path / "cut.pcap"
    path.write_bytes(data[:-10])
    assert len(list(s.pcap_source(str(path)))) == 2


# ---------------------------------------------------------------------------------- command line
def demo_pcap(tmp_path: Path) -> Path:
    web, w_totals = kit.tcp_session(
        "10.20.0.5", "203.0.113.10", 51000, 443, T0, up=2_000, down=50_000
    )
    other, _ = kit.tcp_session("10.20.0.9", "203.0.113.10", 52000, 443, T0 + 1, up=500, down=500)
    dns = [
        (
            T0 + 2,
            kit.ether(kit.ipv4_packet("10.20.0.5", "9.9.9.9", 17, kit.udp_datagram(40000, 53, 30))),
        ),
        (
            T0 + 2.02,
            kit.ether(kit.ipv4_packet("9.9.9.9", "10.20.0.5", 17, kit.udp_datagram(53, 40000, 90))),
        ),
    ]
    frames = sorted(web + other + dns, key=lambda f: f[0])
    kit.write_pcap(tmp_path / "demo.pcap", frames)
    demo_pcap.totals = w_totals  # type: ignore[attr-defined]
    return tmp_path / "demo.pcap"


def test_dry_run_prints_the_flows_of_the_watched_ip_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = demo_pcap(tmp_path)
    assert s.main(["--read-pcap", str(path), "--dry-run", "--ip", "10.20.0.5"]) == 0
    recs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert sorted(r["protocol"] for r in recs) == [
        6,
        17,
    ]  # the other host's session is not reported
    tcp = next(r for r in recs if r["protocol"] == 6)
    want = demo_pcap.totals  # type: ignore[attr-defined]
    assert (tcp["in_bytes"], tcp["out_bytes"]) == (want.client_bytes, want.server_bytes)
    dns = next(r for r in recs if r["protocol"] == 17)
    assert (dns["dst_port"], dns["in_bytes"], dns["out_bytes"]) == (53, 58, 118)


def test_shift_to_now_moves_an_old_capture_to_the_present(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = demo_pcap(tmp_path)
    s.main(["--read-pcap", str(path), "--dry-run", "--shift-to-now"])
    recs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    from datetime import datetime

    ages = [time.time() - datetime.fromisoformat(r["ts"]).timestamp() for r in recs]
    assert all(0 <= a < 30 for a in ages)  # a 2023 capture now looks like it just happened


def test_map_ip_moves_a_recorded_host_onto_your_address(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = demo_pcap(tmp_path)
    assert (
        s.main(
            [
                "--read-pcap",
                str(path),
                "--dry-run",
                "--map-ip",
                "10.20.0.5=10.181.2.111",
                "--ip",
                "10.181.2.111",
            ]
        )
        == 0
    )
    recs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(recs) == 2 and {r["src_ip"] for r in recs} == {"10.181.2.111"}
    assert s.main(["--read-pcap", str(path), "--dry-run", "--map-ip", "nonsense"]) == 2


def test_the_script_runs_standalone_and_reports_errors_plainly(tmp_path: Path) -> None:
    path = demo_pcap(tmp_path)
    ok = subprocess.run(
        [sys.executable, "-I", str(SENSOR), "--read-pcap", str(path), "--dry-run"],
        capture_output=True, text=True, timeout=60,
    )  # fmt: skip
    assert ok.returncode == 0 and len(ok.stdout.splitlines()) == 3
    missing = subprocess.run(
        [sys.executable, "-I", str(SENSOR), "--read-pcap", str(tmp_path / "nope.pcap"), "--dry-run"],
        capture_output=True, text=True, timeout=60,
    )  # fmt: skip
    assert missing.returncode == 2 and "no such file" in missing.stderr
    no_key = subprocess.run(
        [sys.executable, "-I", str(SENSOR), "--read-pcap", str(path)],
        capture_output=True, text=True, timeout=60,
    )  # fmt: skip
    assert no_key.returncode == 2 and "--api-key" in no_key.stderr
    bad_ip = subprocess.run(
        [sys.executable, "-I", str(SENSOR), "--read-pcap", str(path), "--dry-run", "--ip", "nonsense"],
        capture_output=True, text=True, timeout=60,
    )  # fmt: skip
    assert bad_ip.returncode == 2 and "--ip" in bad_ip.stderr


def test_no_payload_bytes_can_reach_a_record() -> None:
    # a recognisable payload goes in; no field of the record may carry it
    marker = b"SECRET-PASSWORD-1234"
    seg = kit.tcp_segment(51000, 80, ACK | PSH) + marker
    frame = kit.ether(kit.ipv4_packet("10.0.0.5", "198.51.100.7", 6, seg))
    table = s.FlowTable()
    table.add(s.parse_ethernet(frame, T0))  # type: ignore[arg-type]
    (rec,) = table.expire(T0 + 100)
    assert marker.decode() not in json.dumps(rec)
    assert set(rec) == set(FlowIn.model_fields) - {"extra"}  # only counters and addresses
    assert rec["in_bytes"] == 20 + 20 + len(marker)  # the payload is counted, never kept


# ---------------------------------------------------------------------------------- delivery
class Receiver:
    """A tiny HTTP server that answers with scripted status codes and records what it was sent."""

    def __init__(self, statuses: list[int]) -> None:
        self.statuses, self.requests = list(statuses), []
        self.reply: dict = {"accepted": 1}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.requests.append(
                    (self.path, {k.lower(): v for k, v in self.headers.items()}, json.loads(body))
                )
                code = outer.statuses.pop(0) if outer.statuses else 202
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(outer.reply).encode())

            do_PUT = do_POST  # the address announcement is a PUT

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()


@pytest.fixture
def receiver() -> Any:
    made: list[Receiver] = []

    def make(*statuses: int) -> Receiver:
        r = Receiver(list(statuses))
        made.append(r)
        return r

    yield make
    for r in made:
        r.close()


REC = {"src_ip": "10.0.0.5", "dst_ip": "9.9.9.9", "protocol": 17}


def test_flows_are_posted_with_the_api_key(receiver: Any) -> None:
    r = receiver(202)
    ex = s.Exporter(r.url, "sbi_key_123")
    ex.submit([REC, REC])
    assert ex.flush_once() is True
    path, headers, body = r.requests[0]
    assert path == "/api/v1/ingest/flows"
    assert headers["x-api-key"] == "sbi_key_123" and body == {"flows": [REC, REC]}
    assert ex.sent == 2 and not ex.pending


def test_every_batch_carries_a_key_that_is_the_same_when_the_batch_is_resent(receiver: Any) -> None:
    r = receiver(503, 202)  # the first attempt fails, the resend succeeds
    ex = s.Exporter(r.url, "k", batch=3)
    ex.submit([{**REC, "n": i} for i in range(3)])
    assert ex.flush_once() is False and ex.flush_once() is True
    (_, first_headers, first_body), (_, second_headers, second_body) = r.requests
    assert first_body == second_body  # the same records went out both times
    key = first_headers["idempotency-key"]
    assert key == second_headers["idempotency-key"]  # so the server can recognise the resend
    assert key == hashlib.sha256(json.dumps(first_body).encode()).hexdigest()
    ex.submit([{**REC, "n": 99}])
    assert ex.flush_once() is True
    assert r.requests[2][1]["idempotency-key"] != key  # a different batch is a different key


def test_a_batch_the_server_had_already_is_counted_and_reported(
    receiver: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    r = receiver()
    r.reply = {"accepted": 1, "duplicate": True}
    ex = s.Exporter(r.url, "k")
    ex.submit([REC])
    assert (
        ex.flush_once() is True and ex.duplicates == 1 and not ex.pending
    )  # delivered, not retried
    r.reply = {"accepted": 1}
    ex.submit([{**REC, "n": 2}])
    assert ex.flush_once() is True and ex.duplicates == 1


def test_a_failed_post_is_retried_in_order_with_nothing_lost(receiver: Any) -> None:
    r = receiver(503, 202)
    ex = s.Exporter(r.url, "k", batch=2)
    ex.submit([{**REC, "n": i} for i in range(5)])
    assert ex.flush_once() is False  # server busy: the batch goes back to the front
    assert [x["n"] for x in ex.pending] == [0, 1, 2, 3, 4]
    assert ex.flush_once() is True
    assert [f["n"] for f in r.requests[-1][2]["flows"]] == [0, 1]


def test_unreachable_server_is_retried_not_fatal() -> None:
    ex = s.Exporter("http://127.0.0.1:9", "k")  # nothing listens on the discard port
    ex.submit([REC])
    assert ex.flush_once() is False and len(ex.pending) == 1


def test_a_rejected_key_is_not_silently_swallowed(
    receiver: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    r = receiver(401)
    ex = s.Exporter(r.url, "wrong")
    ex.submit([REC])
    assert ex.flush_once() is False and len(ex.pending) == 1
    assert "rejected the API key" in capsys.readouterr().err


def test_a_batch_the_server_will_never_accept_is_dropped_not_retried_forever(receiver: Any) -> None:
    r = receiver(422)
    ex = s.Exporter(r.url, "k")
    ex.submit([REC])
    assert ex.flush_once() is True and not ex.pending


def test_the_backlog_is_bounded_while_the_server_is_down() -> None:
    ex = s.Exporter("http://127.0.0.1:9", "k", max_pending=10)
    ex.submit([{**REC, "n": i} for i in range(25)])
    assert len(ex.pending) == 10 and ex.dropped == 15
    assert [x["n"] for x in ex.pending] == list(range(15, 25))  # the oldest were dropped


def test_end_to_end_with_the_cli(tmp_path: Path, receiver: Any) -> None:
    r = receiver()
    path = demo_pcap(tmp_path)
    code = s.main(
        ["--read-pcap", str(path), "--api-url", r.url, "--api-key", "kk", "--ip", "10.20.0.5"]
    )
    assert code == 0
    flows = [f for _, _, body in r.requests for f in body["flows"]]
    assert sorted(f["protocol"] for f in flows) == [6, 17]
    assert all(h["x-api-key"] == "kk" for _, h, _ in r.requests)


def test_watching_an_address_that_is_not_the_internet_facing_one_is_flagged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # e.g. a Hyper-V or WSL virtual adapter: it belongs to this machine but browsing never uses it
    monkeypatch.setattr(s, "default_local_ip", lambda: "10.181.2.111")
    monkeypatch.setattr(s, "_is_local", lambda ip: ip in {"10.181.2.111", "172.18.16.1"})
    warning = s.off_route_warning(["172.18.16.1"])
    assert warning and "10.181.2.111" in warning and "--ip 10.181.2.111" in warning
    assert s.off_route_warning(["172.18.16.1/32"])  # the /32 form of the same host
    assert s.off_route_warning(["10.181.2.111"]) is None  # the right address: no warning
    assert (
        s.off_route_warning(["203.0.113.50"]) is None
    )  # not this machine: a gateway or mirror use
    assert s.off_route_warning(["172.18.0.0/16"]) is None  # a network is deliberate
    assert s.off_route_warning(["not-an-ip"]) is None
    monkeypatch.setattr(s, "default_local_ip", lambda: (_ for _ in ()).throw(OSError("no route")))
    assert s.off_route_warning(["172.18.16.1"]) is None  # offline: nothing to compare with


def test_silence_is_explained_instead_of_left_unexplained() -> None:
    quiet = s.capture_diagnosis(0, 0, ["10.0.0.5"], ipv4_only=False, ipv6=False)
    assert quiet and "no packets" in quiet and "--iface" in quiet and "IPv6" not in quiet
    win = s.capture_diagnosis(0, 0, ["10.0.0.5"], ipv4_only=True, ipv6=True)
    assert win and "IPv6" in win and "Npcap" in win and "ping -4" in win
    elsewhere = s.capture_diagnosis(500, 0, ["10.0.0.5"], ipv4_only=False, ipv6=False)
    assert elsewhere and "none involve 10.0.0.5" in elsewhere
    assert s.capture_diagnosis(500, 12, ["10.0.0.5"], ipv4_only=True, ipv6=True) is None  # working
    assert s.capture_diagnosis(500, 0, [], ipv4_only=False, ipv6=False) is None  # no filter given


def test_the_ipv4_only_limit_is_stated_only_where_it_applies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(s, "has_global_ipv6", lambda: True)
    monkeypatch.setattr(s.sys, "platform", "win32")
    notice = s.ipv6_notice(sees_ipv6=False)  # the raw-socket fallback
    assert notice and "IPv4 only" in notice and "lower bound" in notice and "Npcap" in notice
    assert s.ipv6_notice(sees_ipv6=True) is None  # Npcap capture sees both families
    monkeypatch.setattr(s.sys, "platform", "linux")
    assert s.ipv6_notice(sees_ipv6=False) is None  # not a Windows limitation
    monkeypatch.setattr(s.sys, "platform", "win32")
    monkeypatch.setattr(s, "has_global_ipv6", lambda: False)
    assert s.ipv6_notice(sees_ipv6=False) is None  # an IPv4-only machine has nothing to warn about


# ---------------------------------------------------------------------------------- libpcap / Npcap
def sockaddr4(ip: str) -> bytes:
    fam = socket.AF_INET.to_bytes(2, sys.byteorder)
    return fam + b"\x00\x00" + socket.inet_aton(ip) + bytes(8)


def sockaddr6(ip: str, family: int = socket.AF_INET6) -> bytes:
    return (
        family.to_bytes(2, sys.byteorder)
        + bytes(2)
        + bytes(4)
        + socket.inet_pton(socket.AF_INET6, ip)
        + bytes(4)
    )


def test_addresses_are_read_out_of_c_socket_structures() -> None:
    assert s.sockaddr_ip(sockaddr4("10.181.2.111")) == "10.181.2.111"
    assert s.sockaddr_ip(sockaddr6("2001:db8::7")) == "2001:db8::7"
    assert s.sockaddr_ip(sockaddr6("2001:db8::7", family=23)) == "2001:db8::7"  # Windows' AF_INET6
    assert (
        s.sockaddr_ip(bytes([16, 2]) + bytes(2) + socket.inet_aton("1.2.3.4") + bytes(8), bsd=True)
        == "1.2.3.4"
    )
    assert s.sockaddr_ip(b"\x00\x01") is None  # too short
    assert s.sockaddr_ip(bytes(24)) is None  # an unknown family


def test_link_layers_say_where_the_ip_header_starts() -> None:
    assert s.link_layer(1) == ("eth", 0)
    assert s.link_layer(0) == ("ip", 4) and s.link_layer(108) == ("ip", 4)  # BSD loopback header
    assert s.link_layer(113) == ("ip", 16)  # Linux cooked
    assert s.link_layer(12) == ("ip", 0) and s.link_layer(101) == ("ip", 0)
    assert s.link_layer(105) is None  # Wi-Fi monitor mode: not supported


DEVICES = [
    (r"\Device\NPF_{AAA}", "Intel(R) Wi-Fi 6 AX201", ["fe80::1", "2a00:1:2::5", "10.181.2.111"]),
    (r"\Device\NPF_{BBB}", "Hyper-V Virtual Ethernet Adapter (Default Switch)", ["172.18.16.1"]),
    (r"\Device\NPF_Loopback", "Adapter for loopback traffic capture", ["127.0.0.1"]),
]


def test_the_capture_device_is_chosen_by_address_or_by_name() -> None:
    assert s.choose_device(DEVICES, ["10.181.2.111"], None).endswith("{AAA}")
    assert s.choose_device(DEVICES, ["172.18.16.1", "10.181.2.111"], None).endswith(
        "{BBB}"
    )  # first match wins
    assert s.choose_device(DEVICES, ["2A00:0001:0002:0000:0000:0000:0000:0005"], None).endswith(
        "{AAA}"
    )  # IPv6, any spelling
    assert s.choose_device(DEVICES, [], r"\Device\NPF_{BBB}").endswith("{BBB}")  # exact name
    assert s.choose_device(DEVICES, [], "wi-fi").endswith("{AAA}")  # a part of the description
    with pytest.raises(OSError, match="matches 2"):
        s.choose_device(
            DEVICES, [], "adapter"
        )  # ambiguous: "Hyper-V ... Adapter" and "Adapter for loopback"
    with pytest.raises(OSError, match="--list-devices"):
        s.choose_device(DEVICES, ["192.0.2.9"], None)  # nothing owns that address: say what exists


class FakeLib:
    """Stands in for libpcap: a scripted list of (timestamp, bytes, real length) and a timeout (None)."""

    def __init__(self, items: list[Any], dlt: int = 1) -> None:
        self.items, self.dlt, self.closed, self.drop_count = list(items), dlt, False, 0

    def open(self, device: str, snaplen: int, promiscuous: bool, timeout_ms: int) -> int:
        self.opened = (device, snaplen, promiscuous, timeout_ms)
        return 7

    def datalink(self, handle: int) -> int:
        return self.dlt

    def next(self, handle: int) -> Any:
        if not self.items:
            raise OSError("end of script")
        return self.items.pop(0)

    def drops(self, handle: int) -> int:
        return self.drop_count

    def close(self, handle: int) -> None:
        self.closed = True


def test_a_pcap_capture_turns_library_packets_into_the_sensors_raw_tuples() -> None:
    v6 = kit.ether(
        kit.ipv6_packet(
            "2a00:1:2::5", "2606:4700::1", 6, kit.tcp_segment(50000, 443, ACK, payload=10)
        ),
        ethertype=0x86DD,
    )
    lib = FakeLib(
        [(T0, v6[:80], len(v6) + 1400), None]
    )  # headers copied, 1400 more bytes on the wire
    cap = s.PcapCapture(lib, "dev0", promiscuous=True)
    assert lib.opened == ("dev0", s.HEADER_BYTES, True, 500) and cap.sees_ipv6
    stream = iter(cap)
    ts, data, kind, wire = next(stream)
    assert (ts, kind, wire) == (T0, "eth", len(v6) + 1400) and data == v6[:80]
    pkt = s.parse_raw((ts, data, kind, wire))
    assert pkt and (pkt.src, pkt.dst, pkt.dport) == ("2a00:1:2::5", "2606:4700::1", 443)
    assert (
        pkt.length == 40 + 20 + 10
    )  # IPv6 reports its own payload length: the wire padding is not counted
    lib.drop_count = 9
    assert next(stream) is None and cap.drops == 9  # an idle read: counted drops are refreshed
    with pytest.raises(
        OSError
    ):  # the scripted capture ends with an error, as a failing device would
        next(stream)
    assert lib.closed  # and the handle is always released


def test_loopback_style_link_types_skip_their_header() -> None:
    ip = kit.ipv4_packet("10.0.0.5", "10.0.0.6", 17, kit.udp_datagram(1, 2, 20))
    cap = s.PcapCapture(FakeLib([(T0, bytes(4) + ip, len(ip) + 4)], dlt=0), "lo0")
    ts, data, kind, wire = next(iter(cap))
    assert kind == "ip" and data == ip and wire == len(ip)
    p = s.parse_raw((ts, data, kind, wire))
    assert p and p.length == len(ip)


def test_an_unsupported_link_type_is_refused_clearly() -> None:
    lib = FakeLib([], dlt=105)
    with pytest.raises(OSError, match="unsupported link type 105"):
        s.PcapCapture(lib, "wlan-monitor")
    assert lib.closed


def args_for(argv: list[str]) -> Any:
    return s.build_parser().parse_args(argv)


def test_pcap_is_the_default_on_windows_and_falls_back_to_the_raw_socket_when_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(s.sys, "platform", "win32")
    monkeypatch.setattr(s, "default_local_ip", lambda: "10.181.2.111")

    def missing() -> Any:
        raise s.PcapUnavailable("Npcap is not installed. Install it from https://npcap.com")

    monkeypatch.setattr(s.PcapLib, "load", staticmethod(missing))
    cap = s.open_live(args_for(["--ip", "10.181.2.111"]))
    assert isinstance(cap, s.WindowsRawCapture) and not cap.sees_ipv6
    assert "Falling back to the Windows raw socket" in capsys.readouterr().err

    lib = FakeLib([])
    lib.devices = lambda: DEVICES  # type: ignore[attr-defined]
    monkeypatch.setattr(s.PcapLib, "load", staticmethod(lambda: lib))
    cap2 = s.open_live(args_for(["--ip", "10.181.2.111"]))
    assert isinstance(cap2, s.PcapCapture) and cap2.device.endswith("{AAA}") and cap2.sees_ipv6


def test_asking_for_pcap_explicitly_never_falls_back_silently(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def missing() -> Any:
        raise s.PcapUnavailable("libpcap is not installed")

    monkeypatch.setattr(s.PcapLib, "load", staticmethod(missing))
    with pytest.raises(SystemExit) as exit_info:
        s.open_live(args_for(["--backend", "pcap", "--ip", "10.0.0.5"]))
    assert exit_info.value.code == 2 and "libpcap is not installed" in capsys.readouterr().err


def test_linux_keeps_its_native_capture_unless_pcap_is_requested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(s.sys, "platform", "linux")
    made: list[str] = []
    monkeypatch.setattr(s, "LinuxCapture", lambda iface: made.append(f"native:{iface}") or "native")
    assert s.open_live(args_for(["--iface", "eth0"])) == "native" and made == ["native:eth0"]


def test_the_wanted_addresses_put_the_watched_host_before_the_default_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(s, "default_local_ip", lambda: "10.181.2.111")
    wanted = s.wanted_addresses(
        args_for(["--ip", "172.18.16.1,10.0.0.0/24,2a00:1:2::5", "--interface-ip", "192.168.9.9"])
    )
    assert wanted == [
        "192.168.9.9",
        "172.18.16.1",
        "2a00:1:2::5",
        "10.181.2.111",
    ]  # a /24 is not a host


def test_list_devices_prints_them_or_explains_why_not(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    lib = FakeLib([])
    lib.devices = lambda: DEVICES  # type: ignore[attr-defined]
    monkeypatch.setattr(s.PcapLib, "load", staticmethod(lambda: lib))
    assert s.main(["--list-devices"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 3 and "10.181.2.111" in out[0] and "Default Switch" in out[1]

    def missing() -> Any:
        raise s.PcapUnavailable("Npcap is not installed")

    monkeypatch.setattr(s.PcapLib, "load", staticmethod(missing))
    assert s.main(["--list-devices"]) == 2


def _pkt(src: str, dst: str) -> s.Packet:
    return pkt(src=src, dst=dst, sport=40000, dport=80)


def test_a_probe_is_counted_by_direction_whatever_the_ipv6_spelling() -> None:
    local, remote = "2a00:1:2::5", "2606:4700::1"
    packets = [
        _pkt("2A00:0001:0002:0000:0000:0000:0000:0005", remote),  # sent (a different spelling)
        _pkt(local, remote),
        _pkt(remote, local),
        _pkt("10.0.0.5", "1.1.1.1"),  # unrelated traffic is not counted
    ]
    assert s.count_probe(packets, local, remote) == (2, 1)
    assert s.count_probe([], local, remote) == (0, 0)


class ScriptedCapture:
    """A fake live capture: after the self-test it 'sees' whichever families it is told to."""

    def __init__(self, sees: dict[str, bool], sees_ipv6: bool = True, delay: float = 0.0) -> None:
        self.sees, self.sees_ipv6, self.name = sees, sees_ipv6, "scripted capture"
        # libpcap/Npcap hand packets over in batches, so they can arrive well after the request
        self.delay, self.probe_started = delay, 0.0

    def __iter__(self) -> Any:
        yield None  # the capture opens
        while True:
            if time.time() < self.probe_started + self.delay:
                time.sleep(0.02)
                yield None
                continue
            for label, (src, dst) in {
                "v4": ("10.0.0.5", "93.184.1.1"),
                "v6": ("2a00:1:2::5", "2606::1"),
            }.items():
                if self.sees[label]:
                    yield (
                        T0,
                        kit.ether(kit.ipv4_packet(src, dst, 6, kit.tcp_segment(40000, 80)))
                        if label == "v4"
                        else kit.ether(
                            kit.ipv6_packet(src, dst, 6, kit.tcp_segment(40000, 80)),
                            ethertype=0x86DD,
                        ),
                        "eth",
                        60,
                    )
                    yield (
                        T0,
                        kit.ether(kit.ipv4_packet(dst, src, 6, kit.tcp_segment(80, 40000)))
                        if label == "v4"
                        else kit.ether(
                            kit.ipv6_packet(dst, src, 6, kit.tcp_segment(80, 40000)),
                            ethertype=0x86DD,
                        ),
                        "eth",
                        60,
                    )
            yield None


def run_check(monkeypatch: pytest.MonkeyPatch, capture: Any, drain: float = 0.05) -> int:
    monkeypatch.setattr(s, "self_test", lambda a: 0)
    monkeypatch.setattr(s, "open_live", lambda a: capture)
    endpoints = {
        socket.AF_INET: ("10.0.0.5", "93.184.1.1"),
        socket.AF_INET6: ("2a00:1:2::5", "2606::1"),
    }

    def fake_probe(family: int, result: dict) -> None:
        capture.probe_started = time.time()
        result["local"], result["remote"] = endpoints[family]
        result["ok"] = True

    monkeypatch.setattr(s, "probe_family", fake_probe)
    monkeypatch.setattr(s, "CHECK_DRAIN_SECONDS", drain)
    return s.main(["--check"])


def test_check_reports_a_capture_that_sees_both_families(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_check(monkeypatch, ScriptedCapture({"v4": True, "v6": True})) == 0
    err = capsys.readouterr().err
    assert "IPv4: OK" in err and "IPv6: OK" in err and "sees every address family" in err


def test_check_tells_a_windows_user_to_install_npcap_when_ipv6_is_invisible(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = ScriptedCapture({"v4": True, "v6": False}, sees_ipv6=False)
    assert run_check(monkeypatch, capture) == 1
    err = capsys.readouterr().err
    assert "IPv4: OK" in err and "IPv6: NOT SEEN" in err and "install Npcap" in err


def test_check_does_not_blame_the_capture_when_a_family_cannot_be_tested(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(s, "self_test", lambda a: 0)
    monkeypatch.setattr(s, "open_live", lambda a: ScriptedCapture({"v4": True, "v6": False}))

    def probe(family: int, result: dict) -> None:
        if family == socket.AF_INET:
            result.update(local="10.0.0.5", remote="93.184.1.1", ok=True)
        else:
            result["error"] = "Network is unreachable"  # a machine with no IPv6 route

    monkeypatch.setattr(s, "probe_family", probe)
    monkeypatch.setattr(s, "CHECK_DRAIN_SECONDS", 0.05)
    assert s.main(["--check"]) == 0
    err = capsys.readouterr().err
    assert "IPv6: not testable here" in err and "NOT SEEN" not in err


def test_check_keeps_listening_after_a_quick_request_for_packets_that_arrive_in_batches(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found on a real Windows laptop with Npcap: the IPv6 request finished in well under a second, the
    packets reached the program 0.5 s later, and the check had already given up and reported NOT SEEN."""
    capture = ScriptedCapture({"v4": True, "v6": True}, delay=1.2)
    assert run_check(monkeypatch, capture, drain=2.0) == 0
    err = capsys.readouterr().err
    assert "IPv4: OK" in err and "IPv6: OK" in err
    # and a capture that really is blind still fails once the listening time is up
    assert run_check(monkeypatch, ScriptedCapture({"v4": True, "v6": False}, delay=1.2), 2.0) == 1


def test_check_stops_at_a_failed_self_test(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(s, "self_test", lambda a: 2)
    assert s.main(["--check"]) == 2


# ------------------------------------------------------ the other addresses of the watched machine
ADAPTER = [
    "10.20.0.5",
    "fe80::1234:5678:9abc:def0%12",  # link-local: never added
    "2001:db8:aa:1:3d2e:9f4b:70c1:5a6e",
    "2001:DB8:AA:1::1DA",  # a different spelling of a global address
    "169.254.7.7",  # link-local
    "::1",
]


def test_the_other_addresses_of_the_adapter_that_owns_a_watched_address_are_found() -> None:
    assert s.sibling_addresses(ADAPTER, ["10.20.0.5"]) == [
        "2001:db8:aa:1:3d2e:9f4b:70c1:5a6e",
        "2001:db8:aa:1::1da",
    ]


def test_nothing_is_added_unless_a_single_address_of_this_adapter_was_asked_for() -> None:
    assert s.sibling_addresses(ADAPTER, []) == []  # no --ip: everything is watched anyway
    assert s.sibling_addresses(ADAPTER, ["10.20.0.0/24"]) == []  # a range is not "this machine"
    assert s.sibling_addresses(ADAPTER, ["192.0.2.9"]) == []  # that address is on another adapter
    assert s.sibling_addresses(ADAPTER, ["not an address"]) == []


def test_addresses_that_are_already_watched_are_not_added_again() -> None:
    assert s.sibling_addresses(ADAPTER, ["10.20.0.5", "2001:db8:aa:1::/64"]) == []
    one_left = s.sibling_addresses(ADAPTER, ["10.20.0.5", "2001:db8:aa:1:3d2e:9f4b:70c1:5a6e"])
    assert one_left == ["2001:db8:aa:1::1da"]


def test_a_matcher_forgets_what_it_decided_before_an_address_was_added() -> None:
    m = s.Matcher(["10.0.0.5"])
    v6 = pkt(src="2a00:1:2::5", dst="2606:4700::1")
    assert not m.wanted(v6)  # decided, and remembered
    m.add_networks(["2a00:1:2::5"])
    assert m.wanted(v6)
    m.add_networks(["2a00:1:2::5"])  # adding the same again changes nothing
    assert len(m.networks) == 2


def test_the_watcher_hands_over_each_new_address_once_as_privacy_addresses_rotate() -> None:
    class Source:
        addresses = ["10.0.0.5", "2a00:1:2::5"]

        def local_addresses(self) -> list[str]:
            return list(self.addresses)

    source = Source()
    watcher = s.AddressWatcher(source, lambda: ["10.0.0.5"])
    assert watcher.available
    watcher.scan()
    assert watcher.take() == ["2a00:1:2::5"] and watcher.take() == []
    watcher.scan()
    assert watcher.take() == []  # nothing changed
    source.addresses.append("2a00:1:2::6")  # a new temporary address appears
    watcher.scan()
    assert watcher.take() == ["2a00:1:2::6"]
    assert not s.AddressWatcher(object(), lambda: []).available  # e.g. a capture file


def test_a_failed_look_at_the_adapter_changes_nothing() -> None:
    class Broken:
        def local_addresses(self) -> list[str]:
            raise OSError("adapter list unavailable")

    watcher = s.AddressWatcher(Broken(), lambda: ["10.0.0.5"])
    watcher.scan()
    assert watcher.take() == []


def test_a_pcap_capture_lists_the_addresses_of_its_own_device() -> None:
    lib = FakeLib([])
    lib.devices = lambda: DEVICES  # type: ignore[attr-defined]
    cap = s.PcapCapture(lib, DEVICES[0][0])
    assert cap.local_addresses() == ["fe80::1", "2a00:1:2::5", "10.181.2.111"]
    gone = s.PcapCapture(lib, "unplugged")
    assert gone.local_addresses() == []


def wait_for(condition: Any, seconds: float = 5.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if condition():
            return True
        time.sleep(0.02)
    return False


def test_the_server_is_told_about_the_other_addresses_in_requests_of_at_most_32(
    receiver: Any,
) -> None:
    r = receiver()
    ex = s.Exporter(r.url, "sbi_key_123")
    addresses = [f"2001:db8:aa::{n:x}" for n in range(1, 41)]
    ex.announce(addresses)
    assert wait_for(lambda: len(r.requests) == 2)
    paths = {path for path, _, _ in r.requests}
    assert paths == {"/api/v1/sensor/addresses"}
    sent = [a for _, headers, body in r.requests for a in body["addresses"]]
    assert sorted(sent) == sorted(addresses)
    assert all(len(body["addresses"]) <= 32 for _, _, body in r.requests)
    assert all(headers["x-api-key"] == "sbi_key_123" for _, headers, _ in r.requests)


def test_an_older_server_is_told_about_politely_and_not_retried(
    receiver: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    r = receiver(404)
    ex = s.Exporter(r.url, "k")
    assert ex._announce(["2001:db8::1"]) is False
    assert len(r.requests) == 1  # a 404 is final
    assert "older and does not take" in capsys.readouterr().err


def test_a_failed_announcement_is_retried_then_gives_up(
    receiver: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    r = receiver(503, 503, 202)
    ex = s.Exporter(r.url, "k")
    monkeypatch.setattr(ex._stop, "wait", lambda timeout=None: False)  # do not really wait
    assert ex._announce(["2001:db8::1"]) is True and len(r.requests) == 3
    r2 = receiver(503, 503, 503, 503, 503)
    ex2 = s.Exporter(r2.url, "k")
    monkeypatch.setattr(ex2._stop, "wait", lambda timeout=None: False)
    assert ex2._announce(["2001:db8::1"]) is False and len(r2.requests) == 4
    assert "could not tell the server" in capsys.readouterr().err
    gone = s.Exporter("http://127.0.0.1:9", "k")  # nothing listens there
    monkeypatch.setattr(gone._stop, "wait", lambda timeout=None: False)
    assert gone._announce(["2001:db8::1"]) is False


class AdapterCapture:
    """A fake live capture on an adapter that has an IPv4 address and, once asked, IPv6 addresses."""

    sees_ipv6, name, drops = True, "fake adapter capture", 0

    def __init__(self, frames: list[Any], addresses: list[str]) -> None:
        self.frames, self.addresses = frames, addresses

    def local_addresses(self) -> list[str]:
        return list(self.addresses)

    def __iter__(self) -> Any:
        yield from self.frames


def run_live(monkeypatch: pytest.MonkeyPatch, capture: Any, argv: list[str]) -> int:
    monkeypatch.setattr(s, "open_live", lambda a: capture)
    monkeypatch.setattr(s.signal, "signal", lambda *a: None)  # not the test runner's handlers
    monkeypatch.setattr(s, "off_route_warning", lambda n: None)
    monkeypatch.setattr(s, "has_global_ipv6", lambda: False)
    return s.main(argv)


def machine_frames() -> list[Any]:
    """The machine talks to a server over IPv4 and over IPv6 (one packet each way)."""
    out = []
    now = time.time()
    for src, dst, sport, v6 in (
        ("10.0.0.5", "93.184.216.34", 50001, False),
        ("2001:db8:aa::5", "2606:2800::1", 50002, True),
    ):
        for a, b, p, q in ((src, dst, sport, 443), (dst, src, 443, sport)):
            l4 = kit.tcp_segment(p, q, payload=100)
            ip = kit.ipv6_packet(a, b, 6, l4) if v6 else kit.ipv4_packet(a, b, 6, l4)
            out.append(
                (now, kit.ether(ip, ethertype=0x86DD if v6 else 0x0800), "eth", 14 + len(ip))
            )
    return out


def test_giving_one_ipv4_address_also_watches_and_announces_the_adapters_ipv6_addresses(
    receiver: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    r = receiver()
    capture = AdapterCapture(machine_frames(), ["10.0.0.5", "fe80::1", "2001:db8:aa::5"])
    argv = ["--api-url", r.url, "--api-key", "sbi_k", "--ip", "10.0.0.5", "--idle-timeout", "3"]
    assert run_live(monkeypatch, capture, argv) == 0

    err = capsys.readouterr().err
    assert "also watching the other addresses of this adapter: 2001:db8:aa::5" in err
    flows = [f for path, _, body in r.requests if path.endswith("/flows") for f in body["flows"]]
    assert {(f["src_ip"], f["dst_ip"]) for f in flows} == {
        ("10.0.0.5", "93.184.216.34"),
        ("2001:db8:aa::5", "2606:2800::1"),  # the IPv6 flow is kept too
    }
    assert wait_for(lambda: any(path.endswith("/sensor/addresses") for path, _, _ in r.requests))
    (told,) = [body for path, _, body in r.requests if path.endswith("/sensor/addresses")]
    assert told == {"addresses": ["2001:db8:aa::5"]}


def test_a_dry_run_watches_the_other_addresses_but_tells_nobody(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = AdapterCapture(machine_frames(), ["10.0.0.5", "2001:db8:aa::5"])
    assert run_live(monkeypatch, capture, ["--dry-run", "--ip", "10.0.0.5"]) == 0
    out = capsys.readouterr()
    assert "2001:db8:aa::5" in out.err
    assert '"src_ip": "2001:db8:aa::5"' in out.out


def test_without_a_way_to_list_addresses_the_user_is_told_how_to_include_ipv6(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Native:  # e.g. the Linux packet socket: it sees IPv6 but cannot list the adapter's addresses
        sees_ipv6, name, drops = True, "native capture", 0

        def __iter__(self) -> Any:
            yield from machine_frames()

    monkeypatch.setattr(s, "open_live", lambda a: Native())
    monkeypatch.setattr(s.signal, "signal", lambda *a: None)
    monkeypatch.setattr(s, "off_route_warning", lambda n: None)
    monkeypatch.setattr(s, "has_global_ipv6", lambda: True)
    assert s.main(["--dry-run", "--ip", "10.0.0.5"]) == 0
    assert "also has IPv6 addresses" in capsys.readouterr().err
    assert s.main(["--dry-run", "--ip", "10.0.0.0/24"]) == 0  # a range: not a single machine
    assert "also has IPv6 addresses" not in capsys.readouterr().err


def test_the_sensor_stays_runnable_on_python_3_9() -> None:
    """It runs on whatever Python the monitored machine has. The grammar check catches new syntax;
    the name check catches standard-library names added later (ruff's autofix once swapped
    ``timezone.utc`` for ``datetime.UTC``, which needs Python 3.11, and nothing noticed)."""
    import ast

    source = SENSOR.read_text(encoding="utf-8")
    tree = ast.parse(source, feature_version=(3, 9))
    imported = {
        (node.module, alias.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert ("datetime", "UTC") not in imported
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        is_zip = isinstance(call.func, ast.Name) and call.func.id == "zip"
        assert not (is_zip and any(k.arg == "strict" for k in call.keywords)), (
            "zip(strict=) is 3.10+"
        )
    assert "int | None" not in source.replace('"', "")  # runtime unions need 3.10
