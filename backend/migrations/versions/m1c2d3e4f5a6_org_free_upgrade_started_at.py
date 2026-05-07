"""organization.free_upgrade_started_at

Revision ID: m1c2d3e4f5a6
Revises: l0b1c2d3e4f5
Create Date: 2026-05-08 11:00:00.000000

Tracks when the most recent free upgrade started for each org.
plan_expires_at already carries the END of the grant; this column
records the START so the admin console can display "started X days
ago" without subtracting from expiry. NULL on existing rows — orgs
that have never taken a free upgrade since this column existed.
"""
from alembic import op
import sqlalchemy as sa


revision = 'm1c2d3e4f5a6'
down_revision = 'l0b1c2d3e4f5'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'organization',
        sa.Column('free_upgrade_started_at', sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_column('organization', 'free_upgrade_started_at')
