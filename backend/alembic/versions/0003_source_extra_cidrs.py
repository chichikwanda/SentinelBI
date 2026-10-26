"""sources.extra_cidrs: further addresses that belong to a source

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-26

A machine watched by the sensor is usually dual-stack: the IPv4 address the user typed and the IPv6
addresses of the same adapter, which change over time. The sensor reports the latter here so that the
traffic views count them as the same monitored machine.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "sources",
        sa.Column(
            "extra_cidrs",
            pg.ARRAY(pg.CIDR()),
            nullable=False,
            server_default=sa.text("'{}'::cidr[]"),
        ),
    )


def downgrade() -> None:
    op.drop_column("sources", "extra_cidrs")
