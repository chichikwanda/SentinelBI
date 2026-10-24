from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from pairing import FlowPairer

T0 = datetime(2026, 10, 24, 12, 0, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def rec(
    src: str, sport: int, dst: str, dport: int, *, secs: float = 0, **kw: Any
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ts": (T0 + timedelta(seconds=secs)).isoformat(),
        "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport, "protocol": 6,
        "tcp_flags": 0, "in_bytes": 100, "out_bytes": 0, "in_pkts": 2, "out_pkts": 0, "duration_ms": 500,
    }  # fmt: skip
    base.update(kw)
    return base


def test_reverse_records_merge_into_one_bidirectional_flow() -> None:
    p = FlowPairer(hold_seconds=10, clock=Clock())
    client = rec("10.0.0.5", 51000, "198.51.100.7", 443, tcp_flags=2, in_bytes=300, in_pkts=3)
    server = rec(
        "198.51.100.7",
        443,
        "10.0.0.5",
        51000,
        secs=0.1,
        tcp_flags=18,
        in_bytes=9000,
        in_pkts=7,
        duration_ms=800,
    )
    assert p.add("org", "src", client) == []
    (item,) = p.add("org", "src", server)
    m = item.record
    assert (m["src_ip"], m["dst_ip"], m["src_port"], m["dst_port"]) == (
        "10.0.0.5",
        "198.51.100.7",
        51000,
        443,
    )
    assert (m["in_bytes"], m["in_pkts"]) == (300, 3)  # client -> server
    assert (m["out_bytes"], m["out_pkts"]) == (9000, 7)  # server -> client
    assert m["tcp_flags"] == 2 | 18
    assert m["duration_ms"] == 900  # from the client's start to the server's end (0.1 s + 800 ms)
    assert len(p) == 0
    assert p.paired == 1


def test_arrival_order_does_not_decide_who_the_client_is() -> None:
    p = FlowPairer(hold_seconds=10, clock=Clock())
    server = rec("198.51.100.7", 443, "10.0.0.5", 51000, secs=0.1, in_bytes=9000)
    client = rec("10.0.0.5", 51000, "198.51.100.7", 443, secs=0.0, in_bytes=300)
    assert p.add("org", "src", server) == []  # the reply is exported first
    (item,) = p.add("org", "src", client)
    assert item.record["src_ip"] == "10.0.0.5"
    assert (item.record["in_bytes"], item.record["out_bytes"]) == (300, 9000)


def test_equal_start_times_use_the_lower_destination_port_as_server() -> None:
    p = FlowPairer(hold_seconds=10, clock=Clock())
    a = rec("10.0.0.5", 51000, "198.51.100.7", 443, in_bytes=300)
    b = rec("198.51.100.7", 443, "10.0.0.5", 51000, in_bytes=9000)
    p.add("org", "src", b)
    (item,) = p.add("org", "src", a)
    assert item.record["dst_port"] == 443


def test_unpaired_records_are_emitted_unchanged_after_the_hold() -> None:
    clock = Clock()
    p = FlowPairer(hold_seconds=10, clock=clock)
    r = rec("203.0.113.50", 50000, "10.0.0.10", 22, tcp_flags=2, in_pkts=1)
    assert p.add("org", "src", r) == []
    clock.now = 9.0
    assert p.flush_expired() == []
    clock.now = 10.5
    (item,) = p.flush_expired()
    assert item.record == r and item.record["out_pkts"] == 0
    assert p.unpaired == 1 and len(p) == 0


def test_sources_never_pair_with_each_other() -> None:
    p = FlowPairer(hold_seconds=10, clock=Clock())
    fwd = rec("10.0.0.5", 51000, "198.51.100.7", 443)
    rev = rec("198.51.100.7", 443, "10.0.0.5", 51000)
    assert p.add("orgA", "srcA", fwd) == []
    assert p.add("orgB", "srcB", rev) == []  # same 5-tuple, different tenant: stays separate
    assert len(p) == 2 and p.paired == 0


def test_same_direction_repeat_flushes_the_older_record() -> None:
    p = FlowPairer(hold_seconds=10, clock=Clock())
    first = rec("10.0.0.5", 51000, "198.51.100.7", 443, secs=0)
    second = rec("10.0.0.5", 51000, "198.51.100.7", 443, secs=60)
    assert p.add("org", "src", first) == []
    (flushed,) = p.add("org", "src", second)
    assert flushed.record == first
    assert len(p) == 1


def test_pending_table_is_bounded() -> None:
    p = FlowPairer(hold_seconds=10, max_pending=3, clock=Clock())
    emitted = []
    for i in range(5):
        emitted += p.add("org", "src", rec("10.0.0.5", 40000 + i, "198.51.100.7", 80))
    assert len(p) == 3
    assert [e.record["src_port"] for e in emitted] == [40000, 40001]  # oldest evicted first


def test_zero_hold_disables_pairing() -> None:
    p = FlowPairer(hold_seconds=0, clock=Clock())
    r = rec("10.0.0.5", 51000, "198.51.100.7", 443)
    assert [i.record for i in p.add("org", "src", r)] == [r]
    assert len(p) == 0


def test_force_flush_empties_the_table() -> None:
    p = FlowPairer(hold_seconds=10, clock=Clock())
    for i in range(4):
        p.add("org", "src", rec("10.0.0.5", 40000 + i, "198.51.100.7", 80))
    assert len(p.flush_expired(force=True)) == 4 and len(p) == 0
