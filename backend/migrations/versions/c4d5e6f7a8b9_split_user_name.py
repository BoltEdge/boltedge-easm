"""split user.name into first_name + last_name

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-05-04 09:00:00.000000

Adds nullable `first_name` and `last_name` columns to `user`. The
existing `name` column stays — it remains the canonical display name
(populated as first + last on new signups, kept verbatim for OAuth
signups whose IdP returns a full name).

Backfill: for existing rows that have a `name` set, split on the
first space — first token → first_name, rest → last_name. Single-word
names go entirely into first_name with last_name left null. Best-effort;
users can correct it from their profile.
"""
from alembic import op
import sqlalchemy as sa


revision = 'c4d5e6f7a8b9'
down_revision = 'b3c4d5e6f7a8'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user') as batch:
        batch.add_column(sa.Column('first_name', sa.String(length=60), nullable=True))
        batch.add_column(sa.Column('last_name', sa.String(length=60), nullable=True))

    # Backfill existing rows. Best-effort split on first space.
    # Postgres SUBSTRING + STRPOS handles single-word names cleanly:
    # if there's no space, last_name stays null and the whole thing
    # ends up in first_name.
    op.execute("""
        UPDATE "user"
        SET first_name = CASE
                WHEN POSITION(' ' IN TRIM(name)) > 0
                  THEN SUBSTRING(TRIM(name) FROM 1 FOR POSITION(' ' IN TRIM(name)) - 1)
                ELSE TRIM(name)
            END,
            last_name = CASE
                WHEN POSITION(' ' IN TRIM(name)) > 0
                  THEN TRIM(SUBSTRING(TRIM(name) FROM POSITION(' ' IN TRIM(name)) + 1))
                ELSE NULL
            END
        WHERE name IS NOT NULL AND TRIM(name) <> '';
    """)


def downgrade():
    with op.batch_alter_table('user') as batch:
        batch.drop_column('last_name')
        batch.drop_column('first_name')
