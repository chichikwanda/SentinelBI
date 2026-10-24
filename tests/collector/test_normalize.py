from __future__ import annotations

from datetime import UTC, datetime

import netflow

from netflow_packets import Rec, v5_packet, v9_packet
from normalize import normalize_flow, normalize_packet

TEMPLATES = {"netflow": {}, "ipfix": {}}


def fresh() -> dict[str, dict]:  # type: ignore[type-arg]
    return {"netflow": {}, "ipfix": {}}


def test_v5_record_maps_to_canonical_flow() -> None:
    pkt = v5_packet(
        [
            Rec(
                "10.20.0.5",
                "198.51.100.7",
                51000,
                443,
                proto=6,
                flags=2,
                pkts=3,
                octets=180,
                first=99_000,
                last=99_400,
            )
        ],
        uptime=100_000,
        unix_secs=1_760_000_000,
    )
    (flow,) = normalize_packet(netflow.parse_packet(pkt, fresh()))
    assert flow["src_ip"] == "10.20.0.5"
    assert flow["dst_ip"] == "198.51.100.7"
    assert (flow["src_port"], flow["dst_port"], flow["protocol"], flow["tcp_flags"]) == (
        51000,
        443,
        6,
        2,
    )
    assert (flow["in_pkts"], flow["in_bytes"]) == (3, 180)
    assert (flow["out_pkts"], flow["out_bytes"]) == (0, 0)  # unidirectional record (ADR-015)
    assert flow["duration_ms"] == 400
    # started 1000 ms before the export time (uptime 100000 - first 99000)
    assert datetime.fromisoformat(flow["ts"]) == datetime.fromtimestamp(1_760_000_000 - 1, tz=UTC)


def test_v5_multiple_records() -> None:
    recs = [Rec("10.0.0.1", "198.51.100.7", 40000 + i, 1 + i) for i in range(5)]
    flows = normalize_packet(netflow.parse_packet(v5_packet(recs), fresh()))
    assert [f["dst_port"] for f in flows] == [1, 2, 3, 4, 5]


def test_sysuptime_wraparound_does_not_produce_negative_duration() -> None:
    # exporter uptime counter wrapped between flow start and end
    flow = normalize_flow(
        {
            "IPV4_SRC_ADDR": 1,
            "IPV4_DST_ADDR": 2,
            "FIRST_SWITCHED": 2**32 - 100,
            "LAST_SWITCHED": 300,
        },
        export_unix_s=1_760_000_000,
        uptime_ms=500,
    )
    assert flow is not None
    assert flow["duration_ms"] == 400


def test_v9_needs_its_template_then_parses() -> None:
    templates = fresh()
    recs = [Rec("10.20.0.9", "203.0.113.20", 50505, 22, proto=6, flags=2, pkts=1, octets=60)]
    (flow,) = normalize_packet(netflow.parse_packet(v9_packet(recs, with_template=True), templates))
    assert (flow["src_ip"], flow["dst_ip"], flow["dst_port"]) == ("10.20.0.9", "203.0.113.20", 22)
    assert (flow["in_pkts"], flow["in_bytes"], flow["tcp_flags"]) == (1, 60, 2)

    # a later data-only packet reuses the cached template
    (again,) = normalize_packet(
        netflow.parse_packet(v9_packet(recs, with_template=False), templates)
    )
    assert again["dst_port"] == 22


def test_record_without_addresses_is_skipped() -> None:
    assert normalize_flow({"IN_BYTES": 10}, export_unix_s=1, uptime_ms=None) is None


def test_ipfix_style_field_names_are_understood() -> None:
    flow = normalize_flow(
        {
            "sourceIPv4Address": "10.1.1.1",
            "destinationIPv4Address": "198.51.100.9",
            "sourceTransportPort": 1234,
            "destinationTransportPort": 53,
            "protocolIdentifier": 17,
            "octetDeltaCount": 90,
            "packetDeltaCount": 1,
            "flowStartMilliseconds": 1_760_000_000_000,
            "flowEndMilliseconds": 1_760_000_000_250,
        },
        export_unix_s=1_760_000_005,
        uptime_ms=None,
    )
    assert flow is not None
    assert (flow["protocol"], flow["dst_port"], flow["in_bytes"], flow["duration_ms"]) == (
        17,
        53,
        90,
        250,
    )
    assert datetime.fromisoformat(flow["ts"]) == datetime.fromtimestamp(1_760_000_000, tz=UTC)
