"""add target user and link url to platform announcement

Revision ID: c7d9e2a3f4b5
Revises: 06fc508c2770
Create Date: 2026-05-01 09:30:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'c7d9e2a3f4b5'
down_revision = '06fc508c2770'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('platform_announcement') as batch_op:
        batch_op.add_column(sa.Column('target_user_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('link_url', sa.String(length=500), nullable=True))
        batch_op.create_index(
            'ix_platform_announcement_target_user_id',
            ['target_user_id'],
        )
        batch_op.create_foreign_key(
            'fk_platform_announcement_target_user_id',
            'user',
            ['target_user_id'],
            ['id'],
            ondelete='CASCADE',
        )


def downgrade():
    with op.batch_alter_table('platform_announcement') as batch_op:
        batch_op.drop_constraint(
            'fk_platform_announcement_target_user_id',
            type_='foreignkey',
        )
        batch_op.drop_index('ix_platform_announcement_target_user_id')
        batch_op.drop_column('link_url')
        batch_op.drop_column('target_user_id')
