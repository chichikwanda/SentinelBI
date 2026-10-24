"""Alert schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.core.enums import AlertStatus, Severity
from app.schemas.common import IpStr


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    attack_class: str
    severity: Severity
    risk_score: float
    count: int
    src_ip: IpStr | None
    dst_ip: IpStr | None
    first_seen: datetime
    last_seen: datetime
    status: AlertStatus
    analyst_label: str | None
    evidence: dict[str, Any]


class AlertPatch(BaseModel):
    status: AlertStatus | None = None
    analyst_label: str | None = None
