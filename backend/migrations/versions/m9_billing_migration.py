"""add billing fields and trial_history table

Revision ID: m9_billing_migration
Revises: m8_monitoring_migration
Create Date: 2026-02-10
"""
from alembic import op
import sqlalchemy as sa

revision = 'm9_billing_migration'
down_revision = 'm8_monitoring'
branch_labels = None
depends_on = None


def upgrade():
    # ── Add new columns to organization table ──
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.add_column(sa.Column('plan_status', sa.String(30), nullable=False, server_default='active'))
        batch_op.add_column(sa.Column('trial_ends_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('billing_cycle', sa.String(20), nullable=True))
        batch_op.add_column(sa.Column('stripe_customer_id', sa.String(255), nullable=True))
        batch_op.add_column(sa.Column('stripe_subscription_id', sa.String(255), nullable=True))

    # ── Create trial_history table ──
    op.create_table(
        'trial_history',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('organization_id', sa.Integer(), sa.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False),
        sa.Column('plan', sa.String(50), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('ended_at', sa.DateTime(), nullable=True),
        sa.Column('trial_days', sa.Integer(), nullable=False),
        sa.Column('outcome', sa.String(20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('organization_id', 'plan', name='uq_trial_history_org_plan'),
    )
    op.create_index('ix_trial_history_organization_id', 'trial_history', ['organization_id'])

    # ── Update default asset_limit from 10 to 2 for free plan ──
    # (Only affects the column default, not existing rows)


def downgrade():
    op.drop_index('ix_trial_history_organization_id', table_name='trial_history')
    op.drop_table('trial_history')

    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.drop_column('stripe_subscription_id')
        batch_op.drop_column('stripe_customer_id')
        batch_op.drop_column('billing_cycle')
        batch_op.drop_column('trial_ends_at')
        batch_op.drop_column('plan_status')