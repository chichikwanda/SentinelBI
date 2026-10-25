"""Flow ingestion schemas (the canonical flow record)."""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FlowIn(BaseModel):
    """One flow in canonical form. No payload fields exist by design (rule 6)."""

    model_config = ConfigDict(extra="forbid")

    ts: datetime | None = Field(default=None, description="Flow start; defaults to ingest time")
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=0, ge=0, le=65535)
    protocol: int = Field(ge=0, le=255)
    tcp_flags: int = Field(default=0, ge=0, le=0xFFFF)
    in_bytes: int = Field(default=0, ge=0)
    out_bytes: int = Field(default=0, ge=0)
    in_pkts: int = Field(default=0, ge=0)
    out_pkts: int = Field(default=0, ge=0)
    duration_ms: int = Field(default=0, ge=0)
    extra: dict[str, Any] | None = None


class FlowBatch(BaseModel):
    flows: list[FlowIn] = Field(min_length=1)


class IngestAccepted(BaseModel):
    accepted: int
    # present (true) only when this exact batch had already been received: a resend, not new data
    duplicate: bool | None = None
