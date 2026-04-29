"""add source column to quick_scan_log

Revision ID: c1d2e3f4a5b6
Revises: b1c2d3e4f5a6
Create Date: 2026-04-29 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'c1d2e3f4a5b6'
down_revision = 'b1c2d3e4f5a6'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'quick_scan_log',
        sa.Column('source', sa.String(20), nullable=False, server_default='scan'),
    )


def downgrade():
    op.drop_column('quick_scan_log', 'source')
