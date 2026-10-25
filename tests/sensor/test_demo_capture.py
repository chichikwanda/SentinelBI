"""The bundled demo capture: in sync with its generator, and no byte lost between packets and flows."""

from __future__ import annotations

import collections
import importlib.util
import json
from pathlib import Path

import pytest

import sentinelbi_sensor as s

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "data" / "samples" / "sensor_demo.pcap"


def test_the_committed_file_is_what_the_generator_produces(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location(
        "make_demo", ROOT / "scripts" / "make_sensor_demo_pcap.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    import sensorkit as kit

    fresh = kit.write_pcap(tmp_path / "fresh.pcap", module.build())
    assert fresh.read_bytes() == DEMO.read_bytes(), "run: python scripts/make_sensor_demo_pcap.py"


def test_every_byte_in_the_capture_ends_up_in_a_flow_record(
    capsys: pytest.CaptureFixture[str],
) -> None:
    packets = [p for raw in s.pcap_source(str(DEMO)) if raw and (p := s.parse_raw(raw))]
    assert len(packets) > 8000
    assert s.main(["--read-pcap", str(DEMO), "--dry-run"]) == 0
    recs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert sum(r["in_bytes"] + r["out_bytes"] for r in recs) == sum(p.length for p in packets)
    assert sum(r["in_pkts"] + r["out_pkts"] for r in recs) == len(packets)


def test_it_tells_the_story_the_generator_describes(capsys: pytest.CaptureFixture[str]) -> None:
    assert s.main(["--read-pcap", str(DEMO), "--dry-run", "--ip", "10.20.0.0/24"]) == 0
    recs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    sent: collections.Counter[str] = collections.Counter()
    received: collections.Counter[str] = collections.Counter()
    for r in recs:
        for ip, up, down in (
            (r["src_ip"], r["in_bytes"], r["out_bytes"]),
            (r["dst_ip"], r["out_bytes"], r["in_bytes"]),
        ):
            sent[ip] += up
            received[ip] += down
    assert (
        received["10.20.0.5"] > 20_000_000 and 2_500_000 < sent["10.20.0.5"] < 4_000_000
    )  # laptop
    assert sent["10.20.0.9"] > 2_000_000 and received["10.20.0.9"] < 500_000  # a server
    scan = [r for r in recs if r["src_ip"] == "198.51.100.200"]
    assert len(scan) == 50 and {r["dst_ip"] for r in scan} == {"10.20.0.5"}
    video = [r for r in recs if r["dst_ip"] == "198.51.100.7" and r["out_bytes"] > 100_000]
    assert len({r["src_port"] for r in video}) < len(
        video
    )  # the long download was reported in pieces
