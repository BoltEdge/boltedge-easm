"""add limit_overrides to organization

Revision ID: e4f9a2b3c1d6
Revises: d3e8f1a2b4c5
Create Date: 2026-04-29 14:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'e4f9a2b3c1d6'
down_revision = 'd3e8f1a2b4c5'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.add_column(sa.Column('limit_overrides', sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.drop_column('limit_overrides')
