"""health_check_result table

Revision ID: n2d3e4f5a6b7
Revises: m1c2d3e4f5a6
Create Date: 2026-05-08 12:00:00.000000

Single-row-per-(kind, name) snapshot of every health probe — engines,
analyzers, discovery modules, scheduler heartbeats, external APIs,
system probes. The /admin/health endpoint and `flask health` CLI both
read from this table; the 6-hourly probe scheduler upserts rows.
"""
from alembic import op
import sqlalchemy as sa


revision = 'n2d3e4f5a6b7'
down_revision = 'm1c2d3e4f5a6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'health_check_result',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('kind', sa.String(length=40), nullable=False),
        sa.Column('name', sa.String(length=80), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('check_metadata', sa.JSON(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('last_checked_at', sa.DateTime(), nullable=False),
        sa.Column('last_healthy_at', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('kind', 'name', name='uq_health_kind_name'),
    )
    op.create_index(
        'ix_health_check_result_kind',
        'health_check_result',
        ['kind'],
    )


def downgrade():
    op.drop_index('ix_health_check_result_kind', table_name='health_check_result')
    op.drop_table('health_check_result')
