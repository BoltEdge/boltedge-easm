"""make monitor_alert.monitor_id nullable and add source columns

Revision ID: d4e5f6a7b8c9
Revises: c1d2e3f4a5b6
Create Date: 2026-04-30 14:00:00.000000

Manually-escalated alerts (from a finding or a LookUp Tool result) have no
underlying monitor, so monitor_id becomes nullable. The source column
distinguishes how the alert was created.
"""
from alembic import op
import sqlalchemy as sa


revision = "d4e5f6a7b8c9"
down_revision = "c1d2e3f4a5b6"
branch_labels = None
depends_on = None


def upgrade():
    # Make monitor_id nullable
    op.alter_column(
        "monitor_alert",
        "monitor_id",
        existing_type=sa.Integer(),
        nullable=True,
    )

    # Add new source columns
    op.add_column(
        "monitor_alert",
        sa.Column("source", sa.String(20), nullable=False, server_default="monitor"),
    )
    op.add_column("monitor_alert", sa.Column("source_tool", sa.String(50), nullable=True))
    op.add_column("monitor_alert", sa.Column("source_target", sa.String(500), nullable=True))

    op.create_index("ix_monitor_alert_source", "monitor_alert", ["source"])


def downgrade():
    op.drop_index("ix_monitor_alert_source", table_name="monitor_alert")
    op.drop_column("monitor_alert", "source_target")
    op.drop_column("monitor_alert", "source_tool")
    op.drop_column("monitor_alert", "source")

    # Re-tighten monitor_id (only safe if no orphan rows exist)
    op.alter_column(
        "monitor_alert",
        "monitor_id",
        existing_type=sa.Integer(),
        nullable=False,
    )
