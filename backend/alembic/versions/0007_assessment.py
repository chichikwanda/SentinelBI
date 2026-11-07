"""self-assessment answers; recommendations that come from the assessment alone

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-07

``assessment_answers`` holds an organisation's answers (0 No, 1 Partly, 2 Yes). A recommendation may
now have no alert: it then comes from a weak control area alone (a "profile-only" rule).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assessment_answers",
        sa.Column(
            "org_id",
            pg.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("item_id", sa.Text(), primary_key=True),
        sa.Column("score", sa.SmallInteger(), nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=False, server_default="system"),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("score BETWEEN 0 AND 2", name=op.f("ck_assessment_answers_score")),
    )
    op.alter_column(
        "recommendations", "alert_id", existing_type=pg.UUID(as_uuid=True), nullable=True
    )
    op.create_index(
        "uq_recommendations_profile",
        "recommendations",
        ["org_id", "rec_key"],
        unique=True,
        postgresql_where=sa.text("alert_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_recommendations_profile", table_name="recommendations")
    op.execute("DELETE FROM recommendations WHERE alert_id IS NULL")
    op.alter_column(
        "recommendations", "alert_id", existing_type=pg.UUID(as_uuid=True), nullable=False
    )
    op.drop_table("assessment_answers")
