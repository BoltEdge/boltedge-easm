"""add is_suspended to user and organization

Revision ID: d3e8f1a2b4c5
Revises: ca154b33506a
Create Date: 2026-04-29 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'd3e8f1a2b4c5'
down_revision = 'ca154b33506a'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_suspended', sa.Boolean(), nullable=False, server_default='false'))

    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_suspended', sa.Boolean(), nullable=False, server_default='false'))


def downgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.drop_column('is_suspended')

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('is_suspended')
