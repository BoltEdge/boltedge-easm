"""make audit_log.organization_id nullable

Revision ID: a1b2c3d4e5f6
Revises: f5a1b2c3d4e6
Create Date: 2026-04-29 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'a1b2c3d4e5f6'
down_revision = 'f5a1b2c3d4e6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.alter_column('organization_id',
                              existing_type=sa.Integer(),
                              nullable=True)


def downgrade():
    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.alter_column('organization_id',
                              existing_type=sa.Integer(),
                              nullable=False)
