"""Risk history, model registry, vulnerability catalogue and evaluation (SUS/TAM) answers."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    SmallInteger,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RiskSnapshot(Base):
    __tablename__ = "risk_snapshots"
    __table_args__ = (Index("ix_risk_snapshots_org_id_ts", "org_id", text("ts DESC")),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # NULL asset_id = organisation-level score.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE")
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)


class ModelRegistry(Base):
    """Platform-wide (not tenant-scoped): models are trained once and shared."""

    __tablename__ = "model_registry"
    __table_args__ = (
        # at most one active model
        Index("uq_model_registry_active", "active", unique=True, postgresql_where=text("active")),
    )

    version: Mapped[str] = mapped_column(Text, primary_key=True)
    algo: Mapped[str] = mapped_column(Text, nullable=False)
    metrics: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    features: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    dataset: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Vulnerability(Base):
    """Global CVE/KEV/EPSS catalogue (populated by the enrichment jobs, later phase)."""

    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    cvss: Mapped[float | None] = mapped_column(Float)
    epss: Mapped[float | None] = mapped_column(Float)
    in_kev: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    data: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )


class EvaluationResponse(Base):
    __tablename__ = "evaluation_responses"
    __table_args__ = (CheckConstraint("instrument IN ('SUS', 'TAM')", name="instrument"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Deviation (ADR-013): org_id added so every tenant table can be scoped directly.
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    instrument: Mapped[str] = mapped_column(Text, nullable=False)
    answers: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AppSetting(Base):
    """A platform-wide setting changed from the web interface. The environment value is the default;
    a row here overrides it (see ``app.services.runtime_settings``)."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[object] = mapped_column(JSONB, nullable=False)
    updated_by: Mapped[str] = mapped_column(Text, nullable=False, default="system")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class TrainingJob(Base):
    """A dataset download or a model training run, queued from the web interface and run by the
    ``trainer`` service. Platform-wide (models are shared by every organisation)."""

    __tablename__ = "training_jobs"
    __table_args__ = (
        CheckConstraint("kind IN ('train', 'download', 'backup', 'check')", name="kind"),
        CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')", name="status"
        ),
        Index("ix_training_jobs_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)  # "train" | "download"
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued")
    params: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    stage: Mapped[str | None] = mapped_column(Text)
    log: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    result_version: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    cancel_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    created_by: Mapped[str] = mapped_column(Text, nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AssessmentAnswer(Base):
    """One organisation's answer to one self-assessment item: 0 = No, 1 = Partly, 2 = Yes."""

    __tablename__ = "assessment_answers"
    __table_args__ = (CheckConstraint("score BETWEEN 0 AND 2", name="score"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    item_id: Mapped[str] = mapped_column(Text, primary_key=True)
    score: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    updated_by: Mapped[str] = mapped_column(Text, nullable=False, default="system")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
