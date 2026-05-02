"""add contact_request table

Revision ID: f1a2b3c4d5e6
Revises: e9f0a1b2c3d4
Create Date: 2026-05-02 10:30:00.000000

Stores inbound enquiries submitted via the public contact form on the
landing page, terms page, and API docs. Replaces the previous
`mailto:contact@nanoasm.com` link so admins can triage in-app instead
of digging through an inbox.

The reply itself goes out via Resend (the same provider used for
verification emails). Reply text and admin notes live on the row.
"""
from alembic import op
import sqlalchemy as sa


revision = 'f1a2b3c4d5e6'
down_revision = 'e9f0a1b2c3d4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'contact_request',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('public_id', sa.String(length=20), nullable=True),

        # Submitter
        sa.Column('name',    sa.String(length=120), nullable=False),
        sa.Column('email',   sa.String(length=255), nullable=False),
        sa.Column('subject', sa.String(length=200), nullable=True),
        sa.Column('message', sa.Text(),             nullable=False),

        # Origin (helps with abuse / spam triage)
        sa.Column('ip_address', sa.String(length=45),  nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('referer',    sa.String(length=500), nullable=True),

        # Status: open | in_progress | replied | closed | spam
        sa.Column('status', sa.String(length=20), nullable=False, server_default='open'),

        # Reply tracking
        sa.Column(
            'replied_by',
            sa.Integer(),
            sa.ForeignKey('user.id', ondelete='SET NULL'),
            nullable=True,
        ),
        sa.Column('replied_at',    sa.DateTime(),       nullable=True),
        sa.Column('reply_subject', sa.String(length=200), nullable=True),
        sa.Column('reply_message', sa.Text(),             nullable=True),

        # Internal notes — never sent to the user
        sa.Column('admin_notes', sa.Text(), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )

    op.create_index('ix_contact_request_email',      'contact_request', ['email'])
    op.create_index('ix_contact_request_ip_address', 'contact_request', ['ip_address'])
    op.create_index('ix_contact_request_status',     'contact_request', ['status'])
    op.create_index('ix_contact_request_created_at', 'contact_request', ['created_at'])
    op.create_index('ix_contact_request_public_id',  'contact_request', ['public_id'], unique=True)


def downgrade():
    op.drop_index('ix_contact_request_public_id',  table_name='contact_request')
    op.drop_index('ix_contact_request_created_at', table_name='contact_request')
    op.drop_index('ix_contact_request_status',     table_name='contact_request')
    op.drop_index('ix_contact_request_ip_address', table_name='contact_request')
    op.drop_index('ix_contact_request_email',      table_name='contact_request')
    op.drop_table('contact_request')
