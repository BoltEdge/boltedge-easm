"""add stripe billing support

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
Create Date: 2026-05-03 14:00:00.000000

Phase 1 of the Stripe integration. Adds:

  1. Five new columns on `organization` to track Stripe subscription state.
     All nullable — existing rows are unaffected. When ENABLE_BILLING=false
     these stay null forever; when billing is enabled, they're kept in
     sync by the webhook handler in app/billing/stripe_webhook.py.

  2. `stripe_event` — idempotency log so a redelivered webhook event
     never gets processed twice.

  3. `billing_event` — user-visible audit trail (subscription created,
     payment succeeded/failed, plan changed, refund issued, ...).
     Surfaces in the /settings/billing page in Phase 2.

Safe to apply on a live DB. No data migration required.
"""
from alembic import op
import sqlalchemy as sa


revision = 'b3c4d5e6f7a8'
down_revision = 'a2b3c4d5e6f7'
branch_labels = None
depends_on = None


def upgrade():
    # ── 1. Extend organization with Stripe state ──────────────────────
    with op.batch_alter_table('organization') as batch:
        batch.add_column(sa.Column('stripe_subscription_status', sa.String(length=30), nullable=True))
        batch.add_column(sa.Column('current_period_start', sa.DateTime(), nullable=True))
        batch.add_column(sa.Column('current_period_end', sa.DateTime(), nullable=True))
        batch.add_column(sa.Column('cancel_at_period_end', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column('default_payment_method', sa.String(length=100), nullable=True))
        batch.add_column(sa.Column('billing_email', sa.String(length=255), nullable=True))

    # Existing stripe_customer_id / stripe_subscription_id columns are
    # already nullable; add indexes so webhook lookups are O(log n).
    op.create_index(
        'ix_organization_stripe_customer_id',
        'organization',
        ['stripe_customer_id'],
        unique=False,
    )
    op.create_index(
        'ix_organization_stripe_subscription_id',
        'organization',
        ['stripe_subscription_id'],
        unique=False,
    )

    # ── 2. stripe_event — webhook idempotency log ─────────────────────
    op.create_table(
        'stripe_event',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('stripe_id', sa.String(length=100), nullable=False),
        sa.Column('type', sa.String(length=100), nullable=False),
        sa.Column('received_at', sa.DateTime(), nullable=False),
        sa.Column('processed_at', sa.DateTime(), nullable=True),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('error', sa.Text(), nullable=True),
    )
    op.create_index(
        'ix_stripe_event_stripe_id',
        'stripe_event',
        ['stripe_id'],
        unique=True,
    )
    op.create_index(
        'ix_stripe_event_type',
        'stripe_event',
        ['type'],
        unique=False,
    )

    # ── 3. billing_event — user-visible billing audit trail ───────────
    op.create_table(
        'billing_event',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('public_id', sa.String(length=20), nullable=True),
        sa.Column(
            'organization_id',
            sa.Integer(),
            sa.ForeignKey('organization.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sa.Column('kind', sa.String(length=40), nullable=False),
        sa.Column('amount_cents', sa.Integer(), nullable=True),
        sa.Column('currency', sa.String(length=3), nullable=True),
        sa.Column('description', sa.String(length=500), nullable=True),
        sa.Column('stripe_object_id', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index(
        'ix_billing_event_public_id',
        'billing_event',
        ['public_id'],
        unique=True,
    )
    op.create_index(
        'ix_billing_event_organization_id',
        'billing_event',
        ['organization_id'],
        unique=False,
    )


def downgrade():
    op.drop_index('ix_billing_event_organization_id', table_name='billing_event')
    op.drop_index('ix_billing_event_public_id', table_name='billing_event')
    op.drop_table('billing_event')

    op.drop_index('ix_stripe_event_type', table_name='stripe_event')
    op.drop_index('ix_stripe_event_stripe_id', table_name='stripe_event')
    op.drop_table('stripe_event')

    op.drop_index('ix_organization_stripe_subscription_id', table_name='organization')
    op.drop_index('ix_organization_stripe_customer_id', table_name='organization')

    with op.batch_alter_table('organization') as batch:
        batch.drop_column('billing_email')
        batch.drop_column('default_payment_method')
        batch.drop_column('cancel_at_period_end')
        batch.drop_column('current_period_end')
        batch.drop_column('current_period_start')
        batch.drop_column('stripe_subscription_status')
