"""lookalike_domain_detection

Adds the per-asset opt-in flag + self-rate-limit anchor for the
LookalikeEngine, a profile toggle for the engine, and seeds the
"Lookalike Scan" system profile.

Revision ID: u9k0l1m2n3o4
Revises: t8j9k0l1m2n3
Create Date: 2026-05-14
"""
from alembic import op
import sqlalchemy as sa


revision = "u9k0l1m2n3o4"
down_revision = "t8j9k0l1m2n3"
branch_labels = None
depends_on = None


def upgrade():
    # Asset.lookalike_watch / last_lookalike_scan_at
    op.add_column(
        "asset",
        sa.Column(
            "lookalike_watch",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.create_index(
        "ix_asset_lookalike_watch",
        "asset",
        ["lookalike_watch"],
    )
    op.add_column(
        "asset",
        sa.Column("last_lookalike_scan_at", sa.DateTime(), nullable=True),
    )

    # ScanProfile.use_lookalike
    op.add_column(
        "scan_profile",
        sa.Column(
            "use_lookalike",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

    # Seed the Lookalike Scan system profile. Inserted via raw SQL so the
    # migration is self-contained (no Python model imports). Idempotent
    # via the WHERE NOT EXISTS guard. shodan_include_* and timeout_seconds
    # are NOT NULL on the table with no server_default, so we set them
    # explicitly even though the engine never reads them on this profile.
    op.execute("""
        INSERT INTO scan_profile (
            name, description, is_system, is_default, is_active,
            use_shodan, use_nmap, use_nuclei, use_sslyze, use_leak,
            use_lookalike,
            shodan_include_history, shodan_include_cves, shodan_include_dns,
            timeout_seconds,
            created_at, updated_at
        )
        SELECT
            'Lookalike Scan',
            'Detects typosquats, homoglyph variants, TLD swaps, and IDN confusables for watched root domains. Runs weekly on a separate schedule from vulnerability scans.',
            true, false, true,
            false, false, false, false, false,
            true,
            false, false, false,
            300,
            NOW(), NOW()
        WHERE NOT EXISTS (
            SELECT 1 FROM scan_profile
            WHERE name = 'Lookalike Scan' AND is_system = true
        );
    """)


def downgrade():
    op.execute("""
        DELETE FROM scan_profile
        WHERE name = 'Lookalike Scan' AND is_system = true;
    """)
    op.drop_column("scan_profile", "use_lookalike")
    op.drop_column("asset", "last_lookalike_scan_at")
    op.drop_index("ix_asset_lookalike_watch", table_name="asset")
    op.drop_column("asset", "lookalike_watch")
