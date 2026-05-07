"""add use_leak to scan_profile + backfill system profiles

Revision ID: j8f9a0b1c2d3
Revises: i7e8f9a0b1c2
Create Date: 2026-05-07 10:00:00.000000

Wires the previously-dormant LeakEngine into the scan pipeline. The
engine, analyzer, and templates have been built for a while, but the
scan profile schema had no toggle to switch them on, so leak findings
have never appeared on real scans.

This migration:
  - Adds scan_profile.use_leak (bool, default false, NOT NULL)
  - Backfills the existing system profiles:
      Quick:    use_leak = false  (kept fast — sub-60s budget)
      Standard: use_leak = true   (everyday profile — leak findings on)
      Deep:     use_leak = true
      Full:     use_leak = true

The orchestrator gates on this flag in _select_engines_for_asset.
GitHub-leak detection additionally requires the GITHUB_TOKEN env var;
when missing, the leak engine falls back to sensitive-path probing
only and skips GitHub Code Search gracefully.
"""
from alembic import op
import sqlalchemy as sa


revision = 'j8f9a0b1c2d3'
down_revision = 'i7e8f9a0b1c2'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'scan_profile',
        sa.Column('use_leak', sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    # Backfill: enable on Standard / Deep / Full system profiles. Quick
    # stays off so the "60s sanity check" budget isn't blown by extra
    # network probes.
    op.execute(
        """
        UPDATE scan_profile
        SET use_leak = TRUE
        WHERE is_system = TRUE
          AND name IN ('Standard Scan', 'Deep Scan', 'Full Scan')
        """
    )
    # Drop the server_default — going forward, application code sets the
    # value explicitly. Matches the pattern used by the other use_* columns.
    op.alter_column('scan_profile', 'use_leak', server_default=None)


def downgrade():
    op.drop_column('scan_profile', 'use_leak')
