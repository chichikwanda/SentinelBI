"""Shared schema helpers."""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any

from pydantic import BeforeValidator


def _ip_to_str(value: Any) -> Any:
    """Postgres INET/CIDR columns come back as ipaddress objects; expose plain strings.

    Hosts drop the /32 or /128 mask; networks keep their prefix length.
    """
    if isinstance(value, ipaddress.IPv4Interface | ipaddress.IPv6Interface):
        return str(value.ip) if value.network.prefixlen == value.max_prefixlen else str(value)
    if isinstance(value, ipaddress.IPv4Address | ipaddress.IPv6Address):
        return str(value)
    if isinstance(value, ipaddress.IPv4Network | ipaddress.IPv6Network):
        return str(value)
    return value


IpStr = Annotated[str, BeforeValidator(_ip_to_str)]
