"""monitor_alert.resolution_reason

Revision ID: l0b1c2d3e4f5
Revises: k9a0b1c2d3e4
Create Date: 2026-05-08 10:30:00.000000

Captures why an alert was resolved. Previously the only resolution
context was `resolved_by` (user) + `resolved_at` (timestamp), with no
free-text field for "why". The Suppress-similar flow on the alert
detail panel now passes the tuning rule's reason through to the
resolve call so the alert row carries it directly — no need to chase
the matching tuning rule to understand why an alert was closed.

Nullable: most alerts will continue to be resolved with no explicit
reason (the Resolve button doesn't currently prompt for one), and
historical rows can't be backfilled.
"""
from alembic import op
import sqlalchemy as sa


revision = 'l0b1c2d3e4f5'
down_revision = 'k9a0b1c2d3e4'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'monitor_alert',
        sa.Column('resolution_reason', sa.Text(), nullable=True),
    )


def downgrade():
    op.drop_column('monitor_alert', 'resolution_reason')
