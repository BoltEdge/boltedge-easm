"""add is_root_admin column to user

Revision ID: i7e8f9a0b1c2
Revises: h6d7e8f9a0b1
Create Date: 2026-05-05 16:00:00.000000

Adds the root-admin tier — a superadmin-superset that is protected
from destructive actions by non-root admins. Implementation:

  - user.is_root_admin (bool, default false, NOT NULL)
  - granted/revoked only via `flask grant-root-admin <email>` /
    `flask revoke-root-admin <email>` (no UI, same model as
    is_superadmin)
  - existing superadmin endpoints add a target-side guard:
    if target.is_root_admin and not actor.is_root_admin → 403

No data backfill — admins must explicitly elevate the founding /
operator account(s) post-deploy.
"""
from alembic import op
import sqlalchemy as sa


revision = 'i7e8f9a0b1c2'
down_revision = 'h6d7e8f9a0b1'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'user',
        sa.Column(
            'is_root_admin',
            sa.Boolean(),
            nullable=False,
            server_default=sa.text('false'),
        ),
    )


def downgrade():
    op.drop_column('user', 'is_root_admin')
