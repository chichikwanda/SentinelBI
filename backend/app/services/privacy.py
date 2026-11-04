"""IP pseudonymisation (design rule 6).

Internal addresses (RFC 1918, CGNAT, loopback, link-local, ULA) are replaced by a keyed,
per-organisation, deterministic pseudonym, so grouping and joins still work but the real host
address is not stored. Public addresses are left alone: they are the attackers/destinations
analysts need.
Pseudonyms land in reserved ranges (240.0.0.0/4, fd00::/8) so they cannot be mistaken for
real hosts. Collisions are possible (28 bits for IPv4): fine for SME-sized networks.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import uuid

# Explicit list on purpose: Python's ``is_private`` also covers the RFC 5737 documentation
# ranges (192.0.2/24, 198.51.100/24, 203.0.113/24), which are not "internal hosts".
_INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
]


def is_internal(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr.version == n.version and addr in n for n in _INTERNAL_NETWORKS)


def pseudonymize_ip(ip: str, org_id: uuid.UUID, key: bytes) -> str:
    addr = ipaddress.ip_address(ip)
    if not is_internal(addr):
        return ip
    digest = hmac.new(key + org_id.bytes, addr.packed, hashlib.sha256).digest()
    if addr.version == 4:
        value = (int.from_bytes(digest[:4], "big") & 0x0FFFFFFF) | 0xF0000000
        return str(ipaddress.IPv4Address(value))
    return str(ipaddress.IPv6Address(b"\xfd" + digest[:15]))


def pseudonymize_mac(mac: str, org_id: uuid.UUID, key: bytes) -> str:
    """Keep the vendor part (the first three bytes name a manufacturer, not a device) and replace
    the device part with a keyed, per-organisation hash. The same card always maps to the same
    pseudonym, so a changed MAC is still noticed."""
    digits = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    digest = hmac.new(key + org_id.bytes, bytes.fromhex(digits), hashlib.sha256).digest()
    tail = digest[:3].hex()
    full = digits[:6] + tail
    return ":".join(full[i : i + 2] for i in range(0, 12, 2))
