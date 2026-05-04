"""add welcome_email_sent_at to user

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-05-04 11:00:00.000000

Tracks the one-and-only send of the welcome email per user, so we can
both defer it (until after verification + first login) and never send
it twice — even if the surrounding code paths fire more than once.

Backfill: existing users who were created before the welcome email
existed are stamped with their `created_at` so we don't surprise
anyone with a "welcome to Nano EASM" email a year after they signed
up. New users get NULL → next welcome trigger sends.
"""
from alembic import op
import sqlalchemy as sa


revision = 'd5e6f7a8b9c0'
down_revision = 'c4d5e6f7a8b9'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user') as batch:
        batch.add_column(sa.Column('welcome_email_sent_at', sa.DateTime(), nullable=True))

    # Backfill: stamp existing users with their created_at so we don't
    # spam ancient accounts with a "welcome" the next time they log in.
    # Anyone created from this point on starts NULL → eligible.
    op.execute("""
        UPDATE "user"
        SET welcome_email_sent_at = created_at
        WHERE created_at IS NOT NULL;
    """)


def downgrade():
    with op.batch_alter_table('user') as batch:
        batch.drop_column('welcome_email_sent_at')
