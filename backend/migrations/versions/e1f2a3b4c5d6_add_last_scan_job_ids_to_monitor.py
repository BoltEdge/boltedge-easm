"""add last_scan_job_ids to monitor

Revision ID: e1f2a3b4c5d6
Revises: d2e3f4a5b6c7
Create Date: 2026-04-30

"""
from alembic import op
import sqlalchemy as sa

revision = 'e1f2a3b4c5d6'
down_revision = 'd2e3f4a5b6c7'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('monitor', sa.Column('last_scan_job_ids', sa.JSON(), nullable=True))


def downgrade():
    op.drop_column('monitor', 'last_scan_job_ids')
