"""add audit-log webhook forwarding

Revision ID: f4b5c6d7e8f9
Revises: f3a4b5c6d7e8
Create Date: 2026-05-04 17:00:00.000000

Adds the per-org audit-webhook config (URL, secret, category filter,
kill-switch) on the `organization` table and a new
`audit_webhook_delivery` table that records every forwarding attempt
so operators can debug failed deliveries without scraping app logs.

The feature is plan-gated (`audit_log: True` — Gold + Custom) and
disabled by default; the column defaults make every existing org
inherit the off state without a backfill.
"""
from alembic import op
import sqlalchemy as sa


revision = 'f4b5c6d7e8f9'
down_revision = 'f3a4b5c6d7e8'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('organization') as batch:
        batch.add_column(sa.Column('audit_webhook_url', sa.String(length=500), nullable=True))
        batch.add_column(sa.Column('audit_webhook_secret', sa.String(length=100), nullable=True))
        batch.add_column(sa.Column('audit_webhook_categories', sa.JSON(), nullable=True))
        batch.add_column(sa.Column(
            'audit_webhook_enabled',
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ))

    op.create_table(
        'audit_webhook_delivery',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('audit_log_id', sa.Integer(), nullable=True),
        sa.Column('event_id', sa.String(length=50), nullable=False),
        sa.Column('delivery_url', sa.String(length=500), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending'),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.String(length=1000), nullable=True),
        sa.Column('attempted_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ['organization_id'], ['organization.id'], ondelete='CASCADE',
        ),
    )
    op.create_index(
        'ix_audit_webhook_delivery_organization_id',
        'audit_webhook_delivery',
        ['organization_id'],
    )
    op.create_index(
        'ix_audit_webhook_delivery_audit_log_id',
        'audit_webhook_delivery',
        ['audit_log_id'],
    )
    op.create_index(
        'ix_audit_webhook_delivery_event_id',
        'audit_webhook_delivery',
        ['event_id'],
        unique=True,
    )
    op.create_index(
        'ix_audit_webhook_delivery_attempted_at',
        'audit_webhook_delivery',
        ['attempted_at'],
    )


def downgrade():
    op.drop_index('ix_audit_webhook_delivery_attempted_at', table_name='audit_webhook_delivery')
    op.drop_index('ix_audit_webhook_delivery_event_id', table_name='audit_webhook_delivery')
    op.drop_index('ix_audit_webhook_delivery_audit_log_id', table_name='audit_webhook_delivery')
    op.drop_index('ix_audit_webhook_delivery_organization_id', table_name='audit_webhook_delivery')
    op.drop_table('audit_webhook_delivery')

    with op.batch_alter_table('organization') as batch:
        batch.drop_column('audit_webhook_enabled')
        batch.drop_column('audit_webhook_categories')
        batch.drop_column('audit_webhook_secret')
        batch.drop_column('audit_webhook_url')
