"""bulletproof email_verified default + reset broken rows

Revision ID: g5c6d7e8f9a0
Revises: f4b5c6d7e8f9
Create Date: 2026-05-05 12:00:00.000000

Two fixes for the recurring "new users marked verified before
clicking the link" bug:

1) Re-assert the column-level default to FALSE. The original
   d8e0f1a2b3c4 migration set this correctly, but if the column was
   ever ALTER'd manually (or a non-Alembic migration touched it),
   PostgreSQL could be auto-defaulting new rows to TRUE for any
   INSERT that didn't explicitly set the value. Idempotent ALTER
   regardless of the current state.

2) Reset email_verified back to FALSE for users who match the
   "shouldn't possibly be verified" pattern:

      - email_verified = TRUE                — currently marked verified
      AND oauth_provider IS NULL              — didn't sign up via Google/Microsoft
      AND email_verification_sent_at IS NULL  — never received a verify link
      AND welcome_email_sent_at IS NULL       — never logged in successfully
      AND user is NOT a member of any org via an invite

   That combination can only be reached by the bug — a legitimate
   email/password signup either has email_verification_sent_at set
   (we tried to send) or welcome_email_sent_at set (they verified +
   logged in). A legitimate invite signup has invited_by_user_id
   set on their organization_member row.

   The query is conservative on purpose. Anyone with a real
   verification path stays verified.
"""
from alembic import op
import sqlalchemy as sa


revision = 'g5c6d7e8f9a0'
down_revision = 'f4b5c6d7e8f9'
branch_labels = None
depends_on = None


def upgrade():
    # ── (1) Bulletproof the column default ──────────────────────────
    # ALTER COLUMN ... SET DEFAULT is idempotent — running it on a
    # column that already has the right default is a no-op.
    op.execute('ALTER TABLE "user" ALTER COLUMN email_verified SET DEFAULT FALSE')

    # ── (2) Reset users that match the bug pattern ──────────────────
    # We exclude any user who's an invite-acceptance signup by
    # checking organization_member.invited_by_user_id. Email/password
    # signups are the only path through register() that should ever
    # require verification.
    op.execute("""
        UPDATE "user" u
        SET email_verified = FALSE
        WHERE u.email_verified = TRUE
          AND u.oauth_provider IS NULL
          AND u.email_verification_sent_at IS NULL
          AND u.welcome_email_sent_at IS NULL
          AND NOT EXISTS (
            SELECT 1 FROM organization_member om
            WHERE om.user_id = u.id
              AND om.invited_by_user_id IS NOT NULL
          )
    """)


def downgrade():
    # The default reset is harmless — leave it as FALSE.
    # The data reset cannot be safely undone (we'd be re-marking
    # legitimate unverified users as verified). No-op.
    pass
