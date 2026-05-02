"""add request_type to contact_request

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-05-03 09:00:00.000000

Lets the contact form distinguish general support from trial / demo
requests so admins can triage and (later) auto-grant trials only to
the right kind of submission.
"""
from alembic import op
import sqlalchemy as sa


revision = 'a2b3c4d5e6f7'
down_revision = 'f1a2b3c4d5e6'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'contact_request',
        sa.Column(
            'request_type',
            sa.String(length=20),
            nullable=False,
            server_default='general',
        ),
    )
    op.create_index(
        'ix_contact_request_request_type',
        'contact_request',
        ['request_type'],
    )


def downgrade():
    op.drop_index('ix_contact_request_request_type', table_name='contact_request')
    op.drop_column('contact_request', 'request_type')
