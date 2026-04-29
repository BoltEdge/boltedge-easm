"""add quick_scan_log and blocked_ip tables

Revision ID: b1c2d3e4f5a6
Revises: a1b2c3d4e5f6
Create Date: 2026-04-29 17:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'b1c2d3e4f5a6'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'quick_scan_log',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('target', sa.String(255), nullable=False),
        sa.Column('asset_type', sa.String(10), nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='pending'),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('finding_counts', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.String(500), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_quick_scan_log_ip_address', 'quick_scan_log', ['ip_address'])
    op.create_index('ix_quick_scan_log_target', 'quick_scan_log', ['target'])
    op.create_index('ix_quick_scan_log_created_at', 'quick_scan_log', ['created_at'])

    op.create_table(
        'blocked_ip',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('reason', sa.String(500), nullable=True),
        sa.Column('blocked_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['blocked_by'], ['user.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('ip_address', name='uq_blocked_ip_address'),
    )
    op.create_index('ix_blocked_ip_ip_address', 'blocked_ip', ['ip_address'], unique=True)


def downgrade():
    op.drop_index('ix_blocked_ip_ip_address', table_name='blocked_ip')
    op.drop_table('blocked_ip')
    op.drop_index('ix_quick_scan_log_created_at', table_name='quick_scan_log')
    op.drop_index('ix_quick_scan_log_target', table_name='quick_scan_log')
    op.drop_index('ix_quick_scan_log_ip_address', table_name='quick_scan_log')
    op.drop_table('quick_scan_log')
