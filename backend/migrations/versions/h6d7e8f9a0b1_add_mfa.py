"""add MFA columns to user + user_recovery_code table

Revision ID: h6d7e8f9a0b1
Revises: g5c6d7e8f9a0
Create Date: 2026-05-05 14:00:00.000000

Adds:
  - user.mfa_enabled (bool, default false, NOT NULL)
  - user.mfa_secret_ciphertext (text, nullable) — Fernet-encrypted TOTP secret
  - user.mfa_enrolled_at (timestamp, nullable)
  - user_recovery_code (id, user_id, code_hash, used_at, created_at)

Plaintext TOTP secrets and recovery codes are never written to the DB —
secrets are encrypted via app.auth.mfa_crypto.encrypt_secret, recovery
codes are hashed with werkzeug.security.generate_password_hash.

Backfill is intentionally absent: existing users have mfa_enabled=False
and no secret. Each user enrols themselves through /auth/mfa/enroll.
The mandatory-MFA enforcement (phase 5) provides a one-shot enrolment
flow on next login for users whose role/role-flag requires MFA.
"""
from alembic import op
import sqlalchemy as sa


revision = 'h6d7e8f9a0b1'
down_revision = 'g5c6d7e8f9a0'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'user',
        sa.Column(
            'mfa_enabled',
            sa.Boolean(),
            nullable=False,
            server_default=sa.text('false'),
        ),
    )
    op.add_column(
        'user',
        sa.Column('mfa_secret_ciphertext', sa.Text(), nullable=True),
    )
    op.add_column(
        'user',
        sa.Column('mfa_enrolled_at', sa.DateTime(), nullable=True),
    )

    op.create_table(
        'user_recovery_code',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column(
            'user_id',
            sa.Integer(),
            sa.ForeignKey('user.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sa.Column('code_hash', sa.String(length=255), nullable=False),
        sa.Column('used_at', sa.DateTime(), nullable=True),
        sa.Column(
            'created_at',
            sa.DateTime(),
            nullable=False,
            server_default=sa.text('CURRENT_TIMESTAMP'),
        ),
    )
    op.create_index(
        'ix_user_recovery_code_user_id',
        'user_recovery_code',
        ['user_id'],
    )


def downgrade():
    op.drop_index('ix_user_recovery_code_user_id', table_name='user_recovery_code')
    op.drop_table('user_recovery_code')
    op.drop_column('user', 'mfa_enrolled_at')
    op.drop_column('user', 'mfa_secret_ciphertext')
    op.drop_column('user', 'mfa_enabled')
