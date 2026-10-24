from __future__ import annotations

import ipaddress
import uuid

from app.services.privacy import pseudonymize_ip

KEY = b"unit-test-key"
ORG_A, ORG_B = uuid.uuid4(), uuid.uuid4()


def test_internal_addresses_are_replaced_deterministically() -> None:
    first = pseudonymize_ip("10.20.0.50", ORG_A, KEY)
    assert first != "10.20.0.50"
    assert first == pseudonymize_ip("10.20.0.50", ORG_A, KEY)  # stable: grouping still works
    assert ipaddress.ip_address(first) in ipaddress.ip_network("240.0.0.0/4")  # reserved range


def test_pseudonyms_differ_per_org_and_per_key() -> None:
    assert pseudonymize_ip("10.20.0.50", ORG_A, KEY) != pseudonymize_ip("10.20.0.50", ORG_B, KEY)
    assert pseudonymize_ip("10.20.0.50", ORG_A, KEY) != pseudonymize_ip(
        "10.20.0.50", ORG_A, b"other-key"
    )


def test_distinct_hosts_stay_distinct() -> None:
    masked = {pseudonymize_ip(f"192.168.1.{i}", ORG_A, KEY) for i in range(1, 255)}
    assert len(masked) == 254


def test_public_addresses_are_untouched() -> None:
    assert pseudonymize_ip("198.51.100.20", ORG_A, KEY) == "198.51.100.20"
    assert pseudonymize_ip("8.8.8.8", ORG_A, KEY) == "8.8.8.8"


def test_ipv6_internal_addresses() -> None:
    masked = pseudonymize_ip("fd12:3456::1", ORG_A, KEY)
    assert masked != "fd12:3456::1"
    assert ipaddress.ip_address(masked) in ipaddress.ip_network("fd00::/8")
    assert pseudonymize_ip("2001:4860:4860::8888", ORG_A, KEY) == "2001:4860:4860::8888"
