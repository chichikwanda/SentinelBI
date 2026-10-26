"""Source (monitored network) schemas."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import SourceMethod
from app.schemas.common import IpStr

MIN_PREFIX_V4 = 16  # reject absurdly broad ranges (an SME never owns a /8)
MIN_PREFIX_V6 = 48


class SourceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    cidr: str = Field(
        description="IP or CIDR the organisation owns, e.g. 203.0.113.10 or 10.0.0.0/24"
    )
    method: SourceMethod = SourceMethod.NETFLOW
    criticality: int = Field(default=2, ge=1, le=3, description="1 low, 2 medium, 3 high")

    @field_validator("cidr")
    @classmethod
    def _normalise_cidr(cls, v: str) -> str:
        try:
            net = ipaddress.ip_network(v.strip(), strict=False)
        except ValueError as exc:
            raise ValueError("not a valid IP address or CIDR") from exc
        floor = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
        if net.prefixlen < floor:
            raise ValueError(f"range too broad: use /{floor} or narrower")
        return str(net)


class SourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    cidr: IpStr
    extra_cidrs: list[IpStr] = Field(default_factory=list)
    method: SourceMethod
    status: str
    criticality: int
    last_seen: datetime | None
    created_at: datetime


MAX_ANNOUNCED_ADDRESSES = 32  # per request
MAX_EXTRA_CIDRS = 64  # kept per source, newest last (IPv6 privacy addresses rotate daily)


class SourceAddresses(BaseModel):
    cidr: str
    addresses: list[str]


class SensorAddresses(BaseModel):
    """The other addresses of the machine a sensor runs on (see ``Source.extra_cidrs``)."""

    addresses: list[str] = Field(max_length=MAX_ANNOUNCED_ADDRESSES)

    @field_validator("addresses")
    @classmethod
    def _single_public_addresses(cls, values: list[str]) -> list[str]:
        out: list[str] = []
        for raw in values:
            try:
                ip = ipaddress.ip_address(
                    raw.strip().split("%", 1)[0]
                )  # drop a zone id (fe80::1%12)
            except ValueError as exc:
                raise ValueError(f"{raw!r} is not an IP address") from exc
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                raise ValueError(f"{ip} is not an address of a host on a network")
            if str(ip) not in out:
                out.append(str(ip))
        return out


class SnippetOut(BaseModel):
    id: str
    title: str
    language: str
    content: str


class SetupOut(BaseModel):
    collector_host: str
    collector_port: int
    api_url: str
    snippets: list[SnippetOut]


class SourceCreated(SourceOut):
    api_key: str = Field(description="Shown once. Only its SHA-256 hash is stored.")
    setup: SetupOut


class SourceHealth(BaseModel):
    source_id: uuid.UUID
    state: Literal["waiting", "receiving", "stale"]
    first_flows_received: bool
    last_seen: datetime | None
    flows_total: int
    flows_last_minute: int
