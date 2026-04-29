"""add oauth fields to user

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
Create Date: 2026-04-29
"""
from alembic import op
import sqlalchemy as sa

revision = 'd2e3f4a5b6c7'
down_revision = 'c1d2e3f4a5b6'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column('user', 'password_hash', nullable=True)
    op.add_column('user', sa.Column('oauth_provider', sa.String(50), nullable=True))
    op.add_column('user', sa.Column('oauth_provider_id', sa.String(255), nullable=True))
    op.add_column('user', sa.Column('avatar_url', sa.String(500), nullable=True))
    op.create_index('ix_user_oauth', 'user', ['oauth_provider', 'oauth_provider_id'])


def downgrade():
    op.drop_index('ix_user_oauth', table_name='user')
    op.drop_column('user', 'avatar_url')
    op.drop_column('user', 'oauth_provider_id')
    op.drop_column('user', 'oauth_provider')
    op.alter_column('user', 'password_hash', nullable=False)
