"""add email verification fields to user

Revision ID: d8e0f1a2b3c4
Revises: c7d9e2a3f4b5
Create Date: 2026-05-01 11:00:00.000000

Existing users are backfilled as verified so the new login gate
doesn't lock anyone out. Only newly-registered users will need to
verify going forward.
"""
from alembic import op
import sqlalchemy as sa


revision = 'd8e0f1a2b3c4'
down_revision = 'c7d9e2a3f4b5'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user') as batch_op:
        batch_op.add_column(sa.Column(
            'email_verified',
            sa.Boolean(),
            nullable=False,
            server_default=sa.text('FALSE'),
        ))
        batch_op.add_column(sa.Column(
            'email_verification_sent_at',
            sa.DateTime(),
            nullable=True,
        ))

    # Backfill: mark every pre-existing user as verified.
    op.execute("UPDATE \"user\" SET email_verified = TRUE")


def downgrade():
    with op.batch_alter_table('user') as batch_op:
        batch_op.drop_column('email_verification_sent_at')
        batch_op.drop_column('email_verified')
