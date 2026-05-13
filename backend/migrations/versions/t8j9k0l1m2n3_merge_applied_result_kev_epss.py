"""merge applied_result and kev_epss heads

Both 9ae2385fda17 (pending_action.applied_result) and s7i8j9k0l1m2
(KEV/EPSS threat intel) chained off r6h7i8j9k0l1, leaving alembic
with two heads. This is a no-op merge that reconciles the chain so
`flask db upgrade` and `flask db stamp head` work again.

Revision ID: t8j9k0l1m2n3
Revises: 9ae2385fda17, s7i8j9k0l1m2
Create Date: 2026-05-14
"""
from alembic import op  # noqa: F401


revision = "t8j9k0l1m2n3"
down_revision = ("9ae2385fda17", "s7i8j9k0l1m2")
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
