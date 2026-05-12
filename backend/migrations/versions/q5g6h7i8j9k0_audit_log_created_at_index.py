"""audit_log.created_at index

Revision ID: q5g6h7i8j9k0
Revises: e903d172a1a7
Create Date: 2026-05-12 15:30:00.000000

Adds an index on audit_log.created_at to make the recent-events queries
fast. Without this index, queries like
    SELECT ... FROM audit_log WHERE created_at >= ?
    ORDER BY created_at DESC LIMIT 50
do a full table scan and can time out at 10 s on prod (audit_log grows
unbounded; even ~100k rows is enough to hit the timeout).

The index also speeds up the existing /admin/audit-log filter pages.
CONCURRENTLY can't be used inside a transaction, so this migration uses
the default (locks the table briefly — should be < 1 s for typical
audit_log sizes).

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'q5g6h7i8j9k0'
down_revision = 'e903d172a1a7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        op.f('ix_audit_log_created_at'),
        'audit_log',
        ['created_at'],
        unique=False,
    )


def downgrade():
    op.drop_index(
        op.f('ix_audit_log_created_at'),
        table_name='audit_log',
    )
