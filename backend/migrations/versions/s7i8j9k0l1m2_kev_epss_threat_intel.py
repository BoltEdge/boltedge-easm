"""kev_epss_threat_intel

Adds CISA KEV and FIRST.org EPSS caches plus three indexed columns on
the finding table that surface the enrichment for filter/sort use later.

Revision ID: s7i8j9k0l1m2
Revises: r6h7i8j9k0l1
Create Date: 2026-05-13
"""
from alembic import op
import sqlalchemy as sa


revision = "s7i8j9k0l1m2"
down_revision = "r6h7i8j9k0l1"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "kev_entry",
        sa.Column("cve_id", sa.String(20), primary_key=True),
        sa.Column("date_added", sa.Date(), nullable=False),
        sa.Column("vendor", sa.String(255), nullable=True),
        sa.Column("product", sa.String(255), nullable=True),
        sa.Column("vulnerability_name", sa.String(500), nullable=True),
        sa.Column(
            "known_ransomware",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("required_action", sa.Text(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("short_description", sa.Text(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_kev_entry_fetched_at", "kev_entry", ["fetched_at"])

    op.create_table(
        "epss_cache",
        sa.Column("cve_id", sa.String(20), primary_key=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("model_version", sa.String(20), nullable=True),
        sa.Column("fetched_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_epss_cache_fetched_at", "epss_cache", ["fetched_at"])

    op.add_column(
        "finding",
        sa.Column(
            "kev_listed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.create_index("ix_finding_kev_listed", "finding", ["kev_listed"])

    op.add_column("finding", sa.Column("epss_score", sa.Float(), nullable=True))
    op.create_index("ix_finding_epss_score", "finding", ["epss_score"])

    op.add_column(
        "finding",
        sa.Column("epss_percentile", sa.Float(), nullable=True),
    )


def downgrade():
    op.drop_index("ix_finding_epss_score", table_name="finding")
    op.drop_column("finding", "epss_percentile")
    op.drop_column("finding", "epss_score")
    op.drop_index("ix_finding_kev_listed", table_name="finding")
    op.drop_column("finding", "kev_listed")

    op.drop_index("ix_epss_cache_fetched_at", table_name="epss_cache")
    op.drop_table("epss_cache")
    op.drop_index("ix_kev_entry_fetched_at", table_name="kev_entry")
    op.drop_table("kev_entry")
