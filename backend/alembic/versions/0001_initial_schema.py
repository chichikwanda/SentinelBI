"""initial schema (plan section 9) + TimescaleDB hypertables

Revision ID: 0001
Revises:
Create Date: 2026-10-24

Deviations from the plan's DDL are recorded in docs/DECISIONS.md (ADR-004, 007, 008, 013):
flows.flow_ref, sources.criticality, predictions as a hypertable, org_id on recommendations
and evaluation_responses.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

UUID = pg.UUID(as_uuid=True)
NOW = sa.text("now()")
GEN_UUID = sa.text("gen_random_uuid()")
EMPTY_OBJ = sa.text("'{}'::jsonb")


def _id() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column("id", UUID, server_default=GEN_UUID, nullable=False)


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")

    # --- tenancy -------------------------------------------------------------------
    op.create_table(
        "organizations",
        _id(),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organizations")),
    )
    op.create_table(
        "users",
        _id(),
        sa.Column("org_id", UUID, nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.CheckConstraint("role IN ('admin', 'analyst', 'viewer')", name=op.f("ck_users_role")),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_users_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )
    op.create_index(op.f("ix_users_org_id"), "users", ["org_id"])

    # --- sources & assets ------------------------------------------------------------
    op.create_table(
        "sources",
        _id(),
        sa.Column("org_id", UUID, nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("cidr", pg.CIDR(), nullable=False),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column("api_key_hash", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.Column("criticality", sa.SmallInteger(), server_default=sa.text("2"), nullable=False),
        sa.CheckConstraint(
            "method IN ('netflow', 'sensor', 'http', 'syslog', 'scan')",
            name=op.f("ck_sources_method"),
        ),
        sa.CheckConstraint("criticality BETWEEN 1 AND 3", name=op.f("ck_sources_criticality")),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_sources_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sources")),
        sa.UniqueConstraint("api_key_hash", name=op.f("uq_sources_api_key_hash")),
    )
    op.create_index(op.f("ix_sources_org_id"), "sources", ["org_id"])

    op.create_table(
        "assets",
        _id(),
        sa.Column("org_id", UUID, nullable=False),
        sa.Column("source_id", UUID, nullable=True),
        sa.Column("ip", pg.INET(), nullable=False),
        sa.Column("hostname", sa.Text(), nullable=True),
        sa.Column("criticality", sa.SmallInteger(), server_default=sa.text("2"), nullable=False),
        sa.Column("internet_facing", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.CheckConstraint("criticality BETWEEN 1 AND 3", name=op.f("ck_assets_criticality")),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_assets_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name=op.f("fk_assets_source_id_sources"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
    )
    op.create_index(op.f("ix_assets_org_id"), "assets", ["org_id"])
    op.create_index(op.f("ix_assets_source_id"), "assets", ["source_id"])

    # --- flows (hypertable) --------------------------------------------------------------
    op.create_table(
        "flows",
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("org_id", UUID, nullable=False),
        sa.Column("source_id", UUID, nullable=True),
        sa.Column("flow_ref", sa.Text(), nullable=False),
        sa.Column("src_ip", pg.INET(), nullable=True),
        sa.Column("dst_ip", pg.INET(), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.SmallInteger(), nullable=True),
        sa.Column("tcp_flags", sa.Integer(), nullable=True),
        sa.Column("in_bytes", sa.BigInteger(), nullable=True),
        sa.Column("out_bytes", sa.BigInteger(), nullable=True),
        sa.Column("in_pkts", sa.BigInteger(), nullable=True),
        sa.Column("out_pkts", sa.BigInteger(), nullable=True),
        sa.Column("duration_ms", sa.BigInteger(), nullable=True),
        sa.Column("extra", pg.JSONB(), nullable=True),
    )
    op.create_index("ix_flows_org_id_ts", "flows", ["org_id", sa.text("ts DESC")])
    op.create_index("ix_flows_org_id_src_ip_ts", "flows", ["org_id", "src_ip", sa.text("ts DESC")])
    op.create_index(
        "uq_flows_org_id_flow_ref_ts", "flows", ["org_id", "flow_ref", "ts"], unique=True
    )
    # 1-day chunks so the 30-day retention policy drops data at day granularity (ADR-008)
    # create_default_indexes=FALSE: every query is org-scoped, so our (org_id, ts DESC) index
    # serves reads; Timescale's extra standalone ts index would only slow ingest.
    op.execute(
        "SELECT create_hypertable('flows', 'ts', chunk_time_interval => INTERVAL '1 day', "
        "create_default_indexes => FALSE)"
    )
    op.execute("SELECT add_retention_policy('flows', INTERVAL '30 days')")

    # --- predictions (hypertable) ------------------------------------------------------------
    op.create_table(
        "predictions",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("org_id", UUID, nullable=False),
        sa.Column("flow_ref", sa.Text(), nullable=False),
        sa.Column("model_version", sa.Text(), nullable=False),
        sa.Column("label", sa.Text(), nullable=False),
        sa.Column("probability", sa.Float(), nullable=False),
        sa.Column("shap_top", pg.JSONB(), nullable=True),
    )
    op.create_index("ix_predictions_org_id_ts", "predictions", ["org_id", sa.text("ts DESC")])
    op.create_index(
        "uq_predictions_org_id_flow_ref_model_version_ts",
        "predictions",
        ["org_id", "flow_ref", "model_version", "ts"],
        unique=True,
    )
    op.execute(
        "SELECT create_hypertable('predictions', 'ts', chunk_time_interval => INTERVAL '1 day', "
        "create_default_indexes => FALSE)"
    )
    op.execute("SELECT add_retention_policy('predictions', INTERVAL '30 days')")

    # --- alerts & recommendations ------------------------------------------------------------
    op.create_table(
        "alerts",
        _id(),
        sa.Column("org_id", UUID, nullable=False),
        sa.Column("asset_id", UUID, nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attack_class", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("src_ip", pg.INET(), nullable=True),
        sa.Column("dst_ip", pg.INET(), nullable=True),
        sa.Column("evidence", pg.JSONB(), server_default=EMPTY_OBJ, nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'new'"), nullable=False),
        sa.Column("analyst_label", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "status IN ('new', 'acknowledged', 'false_positive', 'resolved')",
            name=op.f("ck_alerts_status"),
        ),
        sa.CheckConstraint(
            "severity IN ('Low', 'Medium', 'High', 'Critical')", name=op.f("ck_alerts_severity")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_alerts_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name=op.f("fk_alerts_asset_id_assets"), ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
    )
    op.create_index(op.f("ix_alerts_org_id"), "alerts", ["org_id"])
    op.create_index(
        "ix_alerts_org_id_status_last_seen",
        "alerts",
        ["org_id", "status", sa.text("last_seen DESC")],
    )
    op.create_index(
        "ix_alerts_org_id_src_ip_attack_class", "alerts", ["org_id", "src_ip", "attack_class"]
    )

    op.create_table(
        "recommendations",
        _id(),
        sa.Column("org_id", UUID, nullable=False),
        sa.Column("alert_id", UUID, nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("priority", sa.SmallInteger(), nullable=False),
        sa.Column("effort", sa.Text(), nullable=True),
        sa.Column("refs", pg.JSONB(), server_default=EMPTY_OBJ, nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'open'"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_recommendations_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_recommendations_alert_id_alerts"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_recommendations")),
    )
    op.create_index(op.f("ix_recommendations_org_id"), "recommendations", ["org_id"])
    op.create_index(op.f("ix_recommendations_alert_id"), "recommendations", ["alert_id"])

    # --- risk, registry, vulnerabilities, evaluation -----------------------------------------
    op.create_table(
        "risk_snapshots",
        _id(),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("org_id", UUID, nullable=False),
        sa.Column("asset_id", UUID, nullable=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_risk_snapshots_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_risk_snapshots_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_snapshots")),
    )
    op.create_index("ix_risk_snapshots_org_id_ts", "risk_snapshots", ["org_id", sa.text("ts DESC")])

    op.create_table(
        "model_registry",
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("algo", sa.Text(), nullable=False),
        sa.Column("metrics", pg.JSONB(), server_default=EMPTY_OBJ, nullable=False),
        sa.Column("features", pg.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("dataset", sa.Text(), nullable=True),
        sa.Column("active", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.PrimaryKeyConstraint("version", name=op.f("pk_model_registry")),
    )
    op.create_index(
        "uq_model_registry_active",
        "model_registry",
        ["active"],
        unique=True,
        postgresql_where=sa.text("active"),
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("in_kev", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("data", pg.JSONB(), server_default=EMPTY_OBJ, nullable=False),
        sa.PrimaryKeyConstraint("cve_id", name=op.f("pk_vulnerabilities")),
    )

    op.create_table(
        "evaluation_responses",
        _id(),
        sa.Column("user_id", UUID, nullable=False),
        sa.Column("org_id", UUID, nullable=False),
        sa.Column("instrument", sa.Text(), nullable=False),
        sa.Column("answers", pg.JSONB(), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.CheckConstraint(
            "instrument IN ('SUS', 'TAM')", name=op.f("ck_evaluation_responses_instrument")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_evaluation_responses_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name=op.f("fk_evaluation_responses_org_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evaluation_responses")),
    )
    op.create_index(op.f("ix_evaluation_responses_user_id"), "evaluation_responses", ["user_id"])
    op.create_index(op.f("ix_evaluation_responses_org_id"), "evaluation_responses", ["org_id"])


def downgrade() -> None:
    for table in (
        "evaluation_responses",
        "vulnerabilities",
        "model_registry",
        "risk_snapshots",
        "recommendations",
        "alerts",
        "predictions",
        "flows",
        "assets",
        "sources",
        "users",
        "organizations",
    ):
        op.drop_table(table)
