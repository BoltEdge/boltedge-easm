"""add scan_job.initiator

Revision ID: p4f5a6b7c8d9
Revises: o3e4f5a6b7c8
Create Date: 2026-05-11 11:00:00.000000

Adds a non-nullable string column tracking who/what created each scan
job: "manual" (default — user clicked Scan now), "monitor" (monitoring
scheduler re-scanned an asset), or "scheduled" (a ScanSchedule fired).

Backfills existing rows from schedule_id: rows with schedule_id IS NOT
NULL get "scheduled", everything else stays "manual". Monitor-triggered
historical scans aren't distinguishable from manual ones via schema
alone, so they fall to "manual" — that's accepted; only new rows will
correctly carry "monitor".
"""
from alembic import op
import sqlalchemy as sa


revision = "p4f5a6b7c8d9"
down_revision = "o3e4f5a6b7c8"
branch_labels = None
depends_on = None


def upgrade():
    # Add nullable first so the column exists; backfill; then enforce NOT NULL.
    op.add_column(
        "scan_job",
        sa.Column("initiator", sa.String(length=20), nullable=True),
    )
    op.execute(
        "UPDATE scan_job "
        "SET initiator = CASE WHEN schedule_id IS NOT NULL THEN 'scheduled' ELSE 'manual' END"
    )
    op.alter_column("scan_job", "initiator", nullable=False, server_default="manual")


def downgrade():
    op.drop_column("scan_job", "initiator")
