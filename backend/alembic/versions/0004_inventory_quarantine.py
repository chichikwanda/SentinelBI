"""devices, peer networks, baseline window

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-04

A source learns what is normal (``baseline_until``). ``devices`` lists every machine seen on a
registered network (found by the sensor's discovery or in its traffic); ``peer_networks`` lists the
networks (a /24 or /48) that talk to it. Anything first seen after the baseline is ``new`` and waits
for a person; a suspicious alert moves the address it came from to ``quarantined``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def _common() -> list[sa.Column]:
    return [
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
            index=True,
        ),
        sa.Column(
            "source_id",
            pg.UUID(as_uuid=True),
            sa.ForeignKey("sources.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state_reason", sa.Text()),
        sa.Column("state_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state_by", sa.Text(), nullable=False, server_default="system"),
        sa.Column(
            "alert_id",
            pg.UUID(as_uuid=True),
            sa.ForeignKey("alerts.id", ondelete="SET NULL"),
        ),
    ]


def upgrade() -> None:
    op.add_column("sources", sa.Column("baseline_until", sa.DateTime(timezone=True)))
    # sources that already exist learn afresh, so nothing they already talk to is suddenly "new"
    op.execute("UPDATE sources SET baseline_until = now() + interval '7 days'")

    op.create_table(
        "devices",
        *_common(),
        sa.Column("ip", pg.INET(), nullable=False),
        sa.Column("mac", sa.Text()),
        sa.Column("hostname", sa.Text()),
        sa.Column("state", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "state IN ('known', 'new', 'trusted', 'quarantined')", name="ck_devices_state"
        ),
        sa.UniqueConstraint("org_id", "source_id", "ip", name="uq_devices_org_source_ip"),
    )
    op.create_index("ix_devices_org_id_state", "devices", ["org_id", "state"])

    op.create_table(
        "peer_networks",
        *_common(),
        sa.Column("network", pg.CIDR(), nullable=False),
        sa.Column("flows", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "flagged_ips", pg.ARRAY(pg.INET()), nullable=False, server_default=sa.text("'{}'")
        ),
        sa.Column("state", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "state IN ('baseline', 'new', 'approved', 'quarantined')", name="ck_peer_networks_state"
        ),
        sa.UniqueConstraint(
            "org_id", "source_id", "network", name="uq_peer_networks_org_source_net"
        ),
    )
    op.create_index("ix_peer_networks_org_id_state", "peer_networks", ["org_id", "state"])


def downgrade() -> None:
    op.drop_table("peer_networks")
    op.drop_table("devices")
    op.drop_column("sources", "baseline_until")
