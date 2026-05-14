"""paste_cache

Rolling 7-day cache of public Pastebin pastes for the LeakEngine.
Populated by a background fetcher; cleaned hourly. No changes to any
other table.

Revision ID: v0l1m2n3o4p5
Revises: u9k0l1m2n3o4
Create Date: 2026-05-14
"""
from alembic import op
import sqlalchemy as sa


revision = "v0l1m2n3o4p5"
down_revision = "u9k0l1m2n3o4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "paste_cache",
        sa.Column("paste_key", sa.String(20), primary_key=True),
        sa.Column("paste_url", sa.String(255), nullable=False),
        sa.Column("title", sa.String(255), nullable=True),
        sa.Column("author", sa.String(100), nullable=True),
        sa.Column("syntax", sa.String(40), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("date_pasted", sa.DateTime(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_paste_cache_expires_at", "paste_cache", ["expires_at"])
    op.create_index("ix_paste_cache_fetched_at", "paste_cache", ["fetched_at"])


def downgrade():
    op.drop_index("ix_paste_cache_fetched_at", table_name="paste_cache")
    op.drop_index("ix_paste_cache_expires_at", table_name="paste_cache")
    op.drop_table("paste_cache")
