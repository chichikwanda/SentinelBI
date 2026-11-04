"""Device discovery: reading the neighbour table, staying inside the network, ignoring its own probes."""

from __future__ import annotations

import ipaddress

import sentinelbi_sensor as s

WINDOWS_ARP = """
Interface: 192.168.1.6 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-00-11-22     dynamic
  192.168.1.20          AA-BB-CC-00-11-33     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
"""

LINUX_NEIGH = """
192.168.1.1 dev eth0 lladdr aa:bb:cc:00:11:22 REACHABLE
192.168.1.30 dev eth0  FAILED
fe80::1 dev eth0 lladdr aa:bb:cc:00:11:22 router STALE
"""


def test_a_windows_arp_table_gives_the_real_devices_only() -> None:
    assert s.parse_neighbours(WINDOWS_ARP) == {
        "192.168.1.1": "aa:bb:cc:00:11:22",
        "192.168.1.20": "aa:bb:cc:00:11:33",
    }


def test_a_linux_neighbour_table_skips_entries_without_a_hardware_address() -> None:
    found = s.parse_neighbours(LINUX_NEIGH)
    assert found["192.168.1.1"] == "aa:bb:cc:00:11:22"
    assert "192.168.1.30" not in found


def test_discovery_keeps_only_the_registered_network_and_adds_this_machine(monkeypatch) -> None:
    monkeypatch.setattr(s, "poke", lambda hosts, wait=2.0: None)
    monkeypatch.setattr(s, "reverse_names", lambda addresses, budget=8.0: {"192.168.1.1": "router"})
    monkeypatch.setattr(
        s,
        "read_neighbours",
        lambda: {"192.168.1.1": "aa:bb:cc:00:11:22", "10.9.9.9": "aa:bb:cc:00:99:99"},
    )
    found = s.discover(ipaddress.ip_network("192.168.1.0/24"), ["192.168.1.6", "10.0.0.2"])
    assert found == [
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:11:22", "hostname": "router"},
        {"ip": "192.168.1.6", "mac": None, "hostname": None},
    ]


def test_a_big_network_is_cut_off_and_an_ipv6_one_is_not_swept() -> None:
    assert len(s.sweep_hosts(ipaddress.ip_network("10.0.0.0/16"))) == s.MAX_SWEEP
    assert s.sweep_hosts(ipaddress.ip_network("2001:db8::/48")) == []


def test_the_sensors_own_probes_are_not_counted_as_traffic() -> None:
    matcher = s.Matcher(["192.168.1.0/24"])
    probe = s.Packet(0.0, s.UDP, "192.168.1.6", "192.168.1.20", 51000, s.DISCOVERY_PORT, 0, 29)
    web = s.Packet(0.0, s.UDP, "192.168.1.6", "192.168.1.20", 51000, 443, 0, 29)
    assert not matcher.wanted(probe) and matcher.wanted(web)


def test_the_loop_reports_what_it_found_and_notes_new_quarantines(monkeypatch) -> None:
    calls: list[tuple[str, str, object]] = []

    class FakeExporter:
        def call(self, method: str, path: str, body: object = None) -> object:
            calls.append((method, path, body))
            if path == "/sensor/policy":
                return {
                    "cidr": "192.168.1.0/24",
                    "discover": True,
                    "discover_interval_seconds": 120,
                    "quarantined": ["203.0.113.0/24"],
                }
            return {"stored": 1}

    monkeypatch.setattr(
        s, "discover", lambda network, own: [{"ip": "192.168.1.1", "mac": None, "hostname": None}]
    )
    import threading

    loop = s.DiscoveryLoop(FakeExporter(), threading.Event(), None, None, lambda: [])  # type: ignore[arg-type]
    assert loop.once() == 120.0
    assert [c[:2] for c in calls] == [("GET", "/sensor/policy"), ("PUT", "/sensor/devices")]
    assert loop.held == {"203.0.113.0/24"}
