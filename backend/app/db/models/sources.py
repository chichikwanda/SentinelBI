"""Monitored sources (registered by IP/CIDR) and the assets inside them."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    SmallInteger,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import SourceMethod, SourceStatus, sql_in
from app.db.base import Base


class Source(Base):
    __tablename__ = "sources"
    __table_args__ = (
        CheckConstraint(f"method IN ({sql_in(SourceMethod)})", name="method"),
        CheckConstraint("criticality BETWEEN 1 AND 3", name="criticality"),
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
    name: Mapped[str] = mapped_column(Text, nullable=False)
    cidr: Mapped[str] = mapped_column(CIDR, nullable=False)
    # Further addresses of the same machine, reported by its sensor (the IPv6 addresses of the
    # adapter whose IPv4 address was registered). Counted as monitored alongside ``cidr``.
    extra_cidrs: Mapped[list[str]] = mapped_column(
        ARRAY(CIDR), nullable=False, default=list, server_default=text("'{}'::cidr[]")
    )
    method: Mapped[str] = mapped_column(Text, nullable=False)
    # SHA-256 of the API key; the plaintext is shown once at creation (ADR-010).
    api_key_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default=SourceStatus.PENDING.value)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Until this moment the source is learning what is normal; later arrivals are "new".
    baseline_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Deviation from the plan (ADR-007): default criticality for assets in this source.
    criticality: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=2, server_default=text("2")
    )


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (CheckConstraint("criticality BETWEEN 1 AND 3", name="criticality"),)

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
    source_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sources.id", ondelete="CASCADE"), index=True
    )
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    hostname: Mapped[str | None] = mapped_column(Text)
    criticality: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=2, server_default=text("2")
    )
    internet_facing: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
