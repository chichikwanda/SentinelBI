"""What a registered network contains (devices) and who talks to it (peer networks)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import DeviceState, NetworkState, sql_in
from app.db.base import Base


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint(f"state IN ({sql_in(DeviceState)})", name="state"),
        UniqueConstraint("org_id", "source_id", "ip", name="uq_devices_org_source_ip"),
        Index("ix_devices_org_id_state", "org_id", "state"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    mac: Mapped[str | None] = mapped_column(Text)
    hostname: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state_reason: Mapped[str | None] = mapped_column(Text)
    state_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # "system", or the email of the person who decided
    state_by: Mapped[str] = mapped_column(Text, nullable=False, default="system")
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL")
    )


class PeerNetwork(Base):
    __tablename__ = "peer_networks"
    __table_args__ = (
        CheckConstraint(f"state IN ({sql_in(NetworkState)})", name="state"),
        UniqueConstraint("org_id", "source_id", "network", name="uq_peer_networks_org_source_net"),
        Index("ix_peer_networks_org_id_state", "org_id", "state"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    network: Mapped[str] = mapped_column(CIDR, nullable=False)
    flows: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # the individual addresses inside the network that were flagged
    flagged_ips: Mapped[list[str]] = mapped_column(
        ARRAY(INET), nullable=False, default=list, server_default=text("'{}'")
    )
    state: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state_reason: Mapped[str | None] = mapped_column(Text)
    state_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state_by: Mapped[str] = mapped_column(Text, nullable=False, default="system")
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL")
    )
