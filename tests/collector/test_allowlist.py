from __future__ import annotations

import ipaddress

from allowlist import ExporterAllowlist, SourceRef


def src(source_id: str, org: str, cidr: str) -> SourceRef:
    return SourceRef(source_id, org, ipaddress.ip_network(cidr))


def test_exporter_inside_one_registered_range_is_accepted() -> None:
    al = ExporterAllowlist([src("s1", "o1", "203.0.113.0/29"), src("s2", "o2", "198.51.100.0/24")])
    res = al.resolve("203.0.113.5")
    assert res.reason == "ok"
    assert res.source is not None
    assert (res.source.source_id, res.source.org_id) == ("s1", "o1")


def test_unknown_exporter_is_dropped() -> None:
    al = ExporterAllowlist([src("s1", "o1", "203.0.113.0/29")])
    res = al.resolve("192.0.2.77")
    assert res.source is None
    assert res.reason == "unknown"


def test_empty_allowlist_drops_everything() -> None:
    assert ExporterAllowlist().resolve("203.0.113.5").source is None


def test_overlapping_registrations_are_ambiguous_and_dropped() -> None:
    """Two tenants registered the same private range: never guess whose traffic it is."""
    al = ExporterAllowlist(
        [src("s1", "orgA", "192.168.1.0/24"), src("s2", "orgB", "192.168.1.0/24")]
    )
    res = al.resolve("192.168.1.1")
    assert res.source is None
    assert res.reason == "ambiguous"


def test_ip_versions_do_not_cross_match() -> None:
    al = ExporterAllowlist([src("s1", "o1", "2001:db8::/32")])
    assert al.resolve("2001:db8::1").reason == "ok"
    assert al.resolve("203.0.113.5").reason == "unknown"


def test_garbage_address_is_rejected() -> None:
    assert (
        ExporterAllowlist([src("s1", "o1", "10.0.0.0/8")]).resolve("not-an-ip").reason
        == "invalid-address"
    )


def test_replace_swaps_the_list() -> None:
    al = ExporterAllowlist([src("s1", "o1", "203.0.113.0/29")])
    al.replace([src("s2", "o2", "198.51.100.0/24")])
    assert al.resolve("203.0.113.5").source is None
    assert al.resolve("198.51.100.9").source is not None
    assert len(al) == 1
