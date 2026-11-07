"""training_jobs: dataset downloads and model training queued from the web interface

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "training_jobs",
        sa.Column(
            "id",
            pg.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="queued"),
        sa.Column("params", pg.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("stage", sa.Text()),
        sa.Column("log", sa.Text(), nullable=False, server_default=""),
        sa.Column("result_version", sa.Text()),
        sa.Column("error", sa.Text()),
        sa.Column(
            "cancel_requested", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("created_by", sa.Text(), nullable=False, server_default="system"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("kind IN ('train', 'download')", name=op.f("ck_training_jobs_kind")),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')",
            name=op.f("ck_training_jobs_status"),
        ),
    )
    op.create_index("ix_training_jobs_created_at", "training_jobs", ["created_at"])


def downgrade() -> None:
    op.drop_table("training_jobs")
