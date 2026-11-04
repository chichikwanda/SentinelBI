"""Schemas for devices, peer networks, the quarantine queue and the sensor's discovery reports."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field

from app.schemas.common import IpStr
from app.services.oui import vendor_for


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    ip: IpStr
    mac: str | None
    hostname: str | None
    state: str
    first_seen: datetime
    last_seen: datetime
    state_reason: str | None
    state_changed_at: datetime
    state_by: str
    alert_id: uuid.UUID | None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def vendor(self) -> str | None:
        """Who made the network card, from the MAC's first three bytes."""
        return vendor_for(self.mac)


class NetworkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    network: IpStr
    flows: int
    bytes: int
    flagged_ips: list[IpStr]
    state: str
    first_seen: datetime
    last_seen: datetime
    state_reason: str | None
    state_changed_at: datetime
    state_by: str
    alert_id: uuid.UUID | None


class Decision(BaseModel):
    action: Literal["approve", "quarantine"]
    note: str | None = Field(default=None, max_length=300)


class InventorySummary(BaseModel):
    devices_total: int
    devices_new: int
    devices_quarantined: int
    networks_total: int
    networks_new: int
    networks_quarantined: int


class QuarantineItem(BaseModel):
    kind: Literal["device", "network"]
    id: uuid.UUID
    source_id: uuid.UUID
    target: str
    flagged_ips: list[str]
    reason: str | None
    since: datetime
    alert_id: uuid.UUID | None
    commands: dict[str, list[str]]


class DiscoveredDevice(BaseModel):
    ip: str = Field(max_length=64)
    mac: str | None = Field(default=None, max_length=32)
    hostname: str | None = Field(default=None, max_length=253)


class DiscoveryReport(BaseModel):
    devices: list[DiscoveredDevice] = Field(max_length=1024)


class DiscoveryAccepted(BaseModel):
    stored: int


class SensorPolicy(BaseModel):
    """What a sensor should do, decided by the server: the network to discover, and what is held."""

    cidr: str
    discover: bool
    discover_interval_seconds: int
    learning_until: datetime | None
    quarantined: list[str]
