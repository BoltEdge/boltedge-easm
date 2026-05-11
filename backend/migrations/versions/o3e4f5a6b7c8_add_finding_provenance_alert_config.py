"""add finding provenance + alert config

Revision ID: o3e4f5a6b7c8
Revises: n2d3e4f5a6b7
Create Date: 2026-05-11 00:00:00.000000

Adds 4 nullable/default-friendly columns:
- Finding.previously_resolved_at: timestamp of FIRST resolution, never cleared
- User.prefs_json: per-user preferences blob (v1: showProvenanceTags)
- Organization.alert_on_recurrence: org-level monitor alert scope toggle
- Monitor.alert_on_recurrence_override: per-monitor override for org setting

Migration backfills previously_resolved_at from resolved_at for existing
resolved findings.
"""
from alembic import op
import sqlalchemy as sa


revision = 'o3e4f5a6b7c8'
down_revision = 'n2d3e4f5a6b7'
branch_labels = None
depends_on = None


def upgrade():
    # Add previously_resolved_at to finding. The index is created via an
    # explicit op.execute below so it's IF NOT EXISTS-safe (idempotent
    # across partial reruns). Do NOT also pass index=True on the Column
    # here — Alembic auto-creates the index in that case and we'd race
    # the explicit create.
    op.add_column(
        'finding',
        sa.Column('previously_resolved_at', sa.DateTime(), nullable=True),
    )

    # Add prefs_json to user
    op.add_column(
        'user',
        sa.Column('prefs_json', sa.JSON(), nullable=False, server_default='{}'),
    )

    # Add alert_on_recurrence to organization
    op.add_column(
        'organization',
        sa.Column('alert_on_recurrence', sa.Boolean(), nullable=False, server_default='0'),
    )

    # Add alert_on_recurrence_override to monitor
    op.add_column(
        'monitor',
        sa.Column('alert_on_recurrence_override', sa.Boolean(), nullable=True),
    )

    # Idempotent index create: a partial earlier run (or the previous
    # version of this file that had index=True on the Column) may have
    # already created this index. IF NOT EXISTS keeps reruns safe.
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_finding_previously_resolved_at "
        "ON finding (previously_resolved_at)"
    )

    # Backfill: every existing finding that has a resolved_at gets that
    # timestamp copied to previously_resolved_at, so the UI tags them
    # correctly on first page load after deploy. Findings that have
    # never been resolved stay NULL.
    op.execute(
        "UPDATE finding "
        "SET previously_resolved_at = resolved_at "
        "WHERE resolved_at IS NOT NULL"
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS ix_finding_previously_resolved_at")
    op.drop_column('finding', 'previously_resolved_at')
    op.drop_column('user', 'prefs_json')
    op.drop_column('organization', 'alert_on_recurrence')
    op.drop_column('monitor', 'alert_on_recurrence_override')
