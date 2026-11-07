"""training_jobs also runs backups and backup checks

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-07
"""

from __future__ import annotations

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_training_jobs_kind"), "training_jobs", type_="check")
    op.create_check_constraint(
        op.f("ck_training_jobs_kind"),
        "training_jobs",
        "kind IN ('train', 'download', 'backup', 'check')",
    )


def downgrade() -> None:
    op.execute("DELETE FROM training_jobs WHERE kind IN ('backup', 'check')")
    op.drop_constraint(op.f("ck_training_jobs_kind"), "training_jobs", type_="check")
    op.create_check_constraint(
        op.f("ck_training_jobs_kind"), "training_jobs", "kind IN ('train', 'download')"
    )
