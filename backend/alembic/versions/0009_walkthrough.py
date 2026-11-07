"""walkthrough_records: the observation sheet of the practitioner walkthrough

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "walkthrough_records",
        sa.Column(
            "id",
            pg.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "org_id",
            pg.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("participant", sa.Text(), nullable=False),
        sa.Column("task", sa.Text()),
        sa.Column("completed", sa.Boolean()),
        sa.Column("seconds", sa.Integer()),
        sa.Column("errors", sa.Integer()),
        sa.Column("theme", sa.Text()),
        sa.Column("text", sa.Text()),
        sa.Column("recorded_by", sa.Text(), nullable=False, server_default="system"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("kind IN ('task', 'comment')", name=op.f("ck_walkthrough_records_kind")),
    )
    op.create_index(
        "ix_walkthrough_records_org_id_created_at", "walkthrough_records", ["org_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_table("walkthrough_records")
