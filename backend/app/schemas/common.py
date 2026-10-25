"""Shared schema helpers."""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any

from pydantic import BeforeValidator


def host_form(cidr: str) -> str:
    """'10.0.0.5/32' (or '/128') is just the host: show it without the mask."""
    return cidr.rsplit("/", 1)[0] if cidr.endswith(("/32", "/128")) else cidr


def _ip_to_str(value: Any) -> Any:
    """Postgres INET/CIDR columns come back as ipaddress objects; expose plain strings.

    A single host (/32 or /128) drops the mask whichever way it arrives; real networks keep it.
    """
    if isinstance(value, ipaddress.IPv4Interface | ipaddress.IPv6Interface):
        return str(value.ip) if value.network.prefixlen == value.max_prefixlen else str(value)
    if isinstance(value, ipaddress.IPv4Address | ipaddress.IPv6Address):
        return str(value)
    if isinstance(value, ipaddress.IPv4Network | ipaddress.IPv6Network):
        return str(value.network_address) if value.prefixlen == value.max_prefixlen else str(value)
    if isinstance(value, str):
        return host_form(value)
    return value


IpStr = Annotated[str, BeforeValidator(_ip_to_str)]
