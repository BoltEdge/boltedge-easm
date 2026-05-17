"""site_mimic_watch

Adds mimic_baseline + ct_log_candidate tables for the Site Mimic Watch
feature (bundled with Lookalike monitoring; gated by MIMIC_ENABLED env
var and per-tier mimic_storage_mb plan limit).

Revision ID: w1m2n3o4p5q6
Revises: v0l1m2n3o4p5
Create Date: 2026-05-15
"""
from alembic import op
import sqlalchemy as sa


revision = "w1m2n3o4p5q6"
down_revision = "v0l1m2n3o4p5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mimic_baseline",
        sa.Column("asset_id", sa.Integer(),
                  sa.ForeignKey("asset.id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("structural_hash", sa.String(64), nullable=False),
        sa.Column("favicon_phash", sa.String(64), nullable=True),
        sa.Column("visual_phash", sa.String(64), nullable=False),
        sa.Column("key_strings_json", sa.JSON(), nullable=False),
        sa.Column("baseline_image_key", sa.String(255), nullable=True),
        sa.Column("captured_at", sa.DateTime(), nullable=False),
        sa.Column("last_refresh_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "ct_log_candidate",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("brand_keyword", sa.String(64), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("cert_id", sa.String(40), nullable=False),
        sa.Column("cert_logged_at", sa.DateTime(), nullable=True),
        sa.Column("discovered_at", sa.DateTime(), nullable=False),
        sa.Column("processed_at", sa.DateTime(), nullable=True),
        sa.Column("processed_status", sa.String(20), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("cert_id", "hostname",
                            name="uq_ct_log_candidate_cert_hostname"),
    )
    op.create_index("ix_ct_log_candidate_expires_at",
                    "ct_log_candidate", ["expires_at"])
    op.create_index("ix_ct_log_candidate_brand_unprocessed",
                    "ct_log_candidate", ["brand_keyword", "processed_at"])


def downgrade():
    op.drop_index("ix_ct_log_candidate_brand_unprocessed",
                  table_name="ct_log_candidate")
    op.drop_index("ix_ct_log_candidate_expires_at",
                  table_name="ct_log_candidate")
    op.drop_table("ct_log_candidate")
    op.drop_table("mimic_baseline")
