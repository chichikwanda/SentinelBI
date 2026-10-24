"""Time-series tables (TimescaleDB hypertables, created in the migration).

Defined as Core ``Table`` objects: they have no primary key (hypertable unique indexes must
include the partition column ``ts``) and are written in bulk, so the ORM adds nothing.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Float,
    Identity,
    Index,
    Integer,
    SmallInteger,
    Table,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID

from app.db.base import Base

flows = Table(
    "flows",
    Base.metadata,
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("org_id", UUID(as_uuid=True), nullable=False),
    Column("source_id", UUID(as_uuid=True)),
    # Deviation (ADR-004): stream message id; makes persistence idempotent.
    Column("flow_ref", Text, nullable=False),
    Column("src_ip", INET),
    Column("dst_ip", INET),
    Column("src_port", Integer),
    Column("dst_port", Integer),
    Column("protocol", SmallInteger),
    Column("tcp_flags", Integer),
    Column("in_bytes", BigInteger),
    Column("out_bytes", BigInteger),
    Column("in_pkts", BigInteger),
    Column("out_pkts", BigInteger),
    Column("duration_ms", BigInteger),
    Column("extra", JSONB),
    Index("ix_flows_org_id_ts", "org_id", text("ts DESC")),
    Index("ix_flows_org_id_src_ip_ts", "org_id", "src_ip", text("ts DESC")),
    Index("uq_flows_org_id_flow_ref_ts", "org_id", "flow_ref", "ts", unique=True),
)

predictions = Table(
    "predictions",
    Base.metadata,
    Column("id", BigInteger, Identity(), nullable=False),
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("org_id", UUID(as_uuid=True), nullable=False),
    Column("flow_ref", Text, nullable=False),
    Column("model_version", Text, nullable=False),
    Column("label", Text, nullable=False),
    Column("probability", Float, nullable=False),
    Column("shap_top", JSONB),
    Index("ix_predictions_org_id_ts", "org_id", text("ts DESC")),
    Index(
        "uq_predictions_org_id_flow_ref_model_version_ts",
        "org_id",
        "flow_ref",
        "model_version",
        "ts",
        unique=True,
    ),
)
