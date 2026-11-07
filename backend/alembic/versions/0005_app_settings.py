"""app_settings: platform settings changed from the web interface

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-07

The environment (.env) stays the default; a row here overrides one setting without a restart.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column("key", sa.Text(), primary_key=True),
        sa.Column("value", pg.JSONB(), nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=False, server_default="system"),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )


def downgrade() -> None:
    op.drop_table("app_settings")
