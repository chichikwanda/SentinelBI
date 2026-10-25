"""Generate data/samples/sensor_demo.pcap: SYNTHETIC traffic for trying the sensor without capture rights.

Nothing in it was recorded from a real network. It describes eight minutes in a small office:

  10.20.0.5   a laptop: browsing, a 6 MB video download, DNS lookups, pings, a 3 MB backup upload
  10.20.0.9   a small server: inbound web requests, outbound mail, one long SSH session
  198.51.100.200  an outsider who port-scans 10.20.0.5 (50 ports) near the end

Only the first 64 bytes of each packet are stored, with the real size recorded, so a few megabytes of
"downloads" take a few hundred kilobytes on disk. The script is deterministic: running it again gives
the same file (a test checks that the committed file matches).

    python scripts/make_sensor_demo_pcap.py [output.pcap]
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import sensorkit as kit  # noqa: E402

START = 1_800_000_000.0  # arbitrary: the sensor's --shift-to-now moves it to the present
SNAP = 64
LAPTOP, SERVER, SCANNER = "10.20.0.5", "10.20.0.9", "198.51.100.200"
CDNS = ["203.0.113.10", "203.0.113.20", "203.0.113.30", "198.51.100.7"]


def build() -> list[kit.Frame]:
    rng = random.Random(2026)
    frames: list[kit.Frame] = []

    def add(session: tuple[list[kit.Frame], kit.Totals]) -> None:
        frames.extend(session[0])

    port = 50_000

    def next_port() -> int:
        nonlocal port
        port += 1
        return port

    # the laptop browses: a page every ~12 s, 20 kB to 900 kB each
    for i in range(36):
        add(kit.tcp_session(
            LAPTOP, rng.choice(CDNS), next_port(), 443, START + i * 12 + rng.random() * 5,
            up=rng.randrange(600, 4000), down=rng.randrange(20_000, 900_000), mss=4000, snap=SNAP,
        ))  # fmt: skip
    # a 6 MB video download that runs for about 90 seconds (so a long flow is reported in pieces)
    add(
        kit.tcp_session(
            LAPTOP,
            "198.51.100.7",
            next_port(),
            443,
            START + 150,
            up=3000,
            down=6_000_000,
            mss=4000,
            gap=0.06,
            snap=SNAP,
        )
    )
    # a 3 MB backup upload to a cloud service
    add(
        kit.tcp_session(
            LAPTOP,
            "203.0.113.99",
            next_port(),
            443,
            START + 330,
            up=3_000_000,
            down=4000,
            mss=4000,
            gap=0.02,
            snap=SNAP,
        )
    )
    # DNS lookups every ~15 s
    for i in range(30):
        t = START + i * 15 + rng.random()
        sport = next_port()
        q, a = 28 + rng.randrange(0, 20), 80 + rng.randrange(0, 120)
        frames.append(
            (t, kit.ether(kit.ipv4_packet(LAPTOP, "9.9.9.9", 17, kit.udp_datagram(sport, 53, q))))
        )
        frames.append(
            (
                t + 0.03,
                kit.ether(kit.ipv4_packet("9.9.9.9", LAPTOP, 17, kit.udp_datagram(53, sport, a))),
            )
        )
    # ten pings
    for i in range(10):
        t = START + 200 + i
        frames.append(
            (t, kit.ether(kit.ipv4_packet(LAPTOP, "8.8.8.8", 1, kit.icmp_message(8, 0, 56))))
        )
        frames.append(
            (t + 0.02, kit.ether(kit.ipv4_packet("8.8.8.8", LAPTOP, 1, kit.icmp_message(0, 0, 56))))
        )

    # the server: inbound web requests from the internet, outbound mail, an admin's SSH session
    for i in range(40):
        add(kit.tcp_session(
            f"203.0.113.{100 + i % 30}", SERVER, next_port(), 8080, START + i * 11 + rng.random() * 4,
            up=rng.randrange(300, 1500), down=rng.randrange(2_000, 120_000), mss=4000, snap=SNAP,
        ))  # fmt: skip
    for i in range(5):
        add(
            kit.tcp_session(
                SERVER,
                "192.0.2.25",
                next_port(),
                25,
                START + 60 + i * 80,
                up=rng.randrange(5_000, 60_000),
                down=600,
                snap=SNAP,
            )
        )
    add(
        kit.tcp_session(
            "198.51.100.50",
            SERVER,
            next_port(),
            22,
            START + 20,
            up=40_000,
            down=90_000,
            mss=500,
            gap=2.5,
            snap=SNAP,
        )
    )

    # the outsider scans 50 ports on the laptop within a few seconds; closed ports answer with a reset
    for i, dport in enumerate(range(20, 70)):
        t = START + 420 + i * 0.08
        sport = next_port()
        syn = kit.tcp_segment(sport, dport, kit.SYN)
        rst = kit.tcp_segment(dport, sport, kit.RST | kit.ACK)
        frames.append((t, kit.ether(kit.ipv4_packet(SCANNER, LAPTOP, 6, syn))))
        frames.append((t + 0.001, kit.ether(kit.ipv4_packet(LAPTOP, SCANNER, 6, rst))))

    frames.sort(key=lambda f: f[0])
    # anything not already truncated is tiny (DNS, ICMP, scan packets): keep it whole
    return frames


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "samples" / "sensor_demo.pcap"
    frames = build()
    kit.write_pcap(out, frames)
    wire = sum(f[2] if len(f) > 2 else len(f[1]) for f in frames)  # type: ignore[misc]
    print(
        f"wrote {out} ({out.stat().st_size / 1000:.0f} kB on disk): {len(frames)} packets, {wire / 1e6:.1f} MB on the wire"
    )


if __name__ == "__main__":
    main()
