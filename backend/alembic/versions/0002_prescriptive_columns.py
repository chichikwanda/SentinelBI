"""recommendations: rec_key + compliance_note; alerts: source_id

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-24

rec_key makes recommendation persistence idempotent (unique per alert); alerts.source_id lets
dashboards attribute an alert to a source without parsing evidence.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "recommendations",
        sa.Column("rec_key", sa.Text(), nullable=False, server_default=sa.text("''")),
    )
    op.alter_column("recommendations", "rec_key", server_default=None)
    op.add_column("recommendations", sa.Column("compliance_note", sa.Text(), nullable=True))
    op.create_index(
        "uq_recommendations_alert_id_rec_key",
        "recommendations",
        ["alert_id", "rec_key"],
        unique=True,
    )

    op.add_column("alerts", sa.Column("source_id", pg.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        op.f("fk_alerts_source_id_sources"),
        "alerts",
        "sources",
        ["source_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(op.f("ix_alerts_source_id"), "alerts", ["source_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_alerts_source_id"), table_name="alerts")
    op.drop_constraint(op.f("fk_alerts_source_id_sources"), "alerts", type_="foreignkey")
    op.drop_column("alerts", "source_id")
    op.drop_index("uq_recommendations_alert_id_rec_key", table_name="recommendations")
    op.drop_column("recommendations", "compliance_note")
    op.drop_column("recommendations", "rec_key")
