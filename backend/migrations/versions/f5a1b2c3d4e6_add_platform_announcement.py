"""add platform_announcement table

Revision ID: f5a1b2c3d4e6
Revises: e4f9a2b3c1d6
Create Date: 2026-04-29 15:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'f5a1b2c3d4e6'
down_revision = 'e4f9a2b3c1d6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'platform_announcement',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('body', sa.Text(), nullable=True),
        sa.Column('kind', sa.String(20), nullable=False, server_default='info'),
        sa.Column('target_org_id', sa.Integer(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.ForeignKeyConstraint(['created_by'], ['user.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['target_org_id'], ['organization.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_platform_announcement_target_org_id', 'platform_announcement', ['target_org_id'])


def downgrade():
    op.drop_index('ix_platform_announcement_target_org_id', table_name='platform_announcement')
    op.drop_table('platform_announcement')
