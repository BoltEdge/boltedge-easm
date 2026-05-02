"""add public_id to entity tables

Revision ID: e9f0a1b2c3d4
Revises: d8e0f1a2b3c4
Create Date: 2026-05-02 09:00:00.000000

Adds a stored, externally-visible identifier (public_id) to every
entity that's exposed via the API. Format:
    <2-letter prefix><zero-padded integer id, 4 digits min>
e.g. SC0042 for scan_job.id=42, AS0150 for asset.id=150.

Per-table migration is the same 3-step transactional dance:
  1. ADD COLUMN public_id VARCHAR(20)         -- nullable, no constraint yet
  2. UPDATE backfill from existing integer id
  3. CREATE UNIQUE INDEX ix_<table>_public_id

Column stays nullable at the DB level. The `after_insert` SQLAlchemy
event registered in app/utils/display_id.py populates public_id from
the just-assigned integer id, inside the same transaction. The unique
index still enforces no duplicate values across rows.

Fully reversible. No existing data is touched (only an additive column).
"""
from alembic import op
import sqlalchemy as sa


revision = 'e9f0a1b2c3d4'
down_revision = 'd8e0f1a2b3c4'
branch_labels = None
depends_on = None


# (table_name, prefix) — must stay aligned with PREFIX_BY_TABLE in
# app/utils/display_id.py
ENTITIES: list[tuple[str, str]] = [
    ("api_key",               "AK"),
    ("asset",                 "AS"),
    ("asset_group",           "GR"),
    ("audit_log",             "LG"),
    ("blocked_ip",            "BL"),
    ("discovery_job",         "DC"),
    ("finding",               "FN"),
    ("monitor",               "MO"),
    ("monitor_alert",         "AL"),
    ("organization",          "OR"),
    ("pending_invitation",    "IN"),
    ("platform_announcement", "AN"),
    ("quick_scan_log",        "QS"),
    ("report",                "RP"),
    ("scan_job",              "SC"),
    ("scan_profile",          "PR"),
    ("scan_schedule",         "SH"),
    ("user",                  "US"),
]


def _table_exists(conn, table_name: str) -> bool:
    inspector = sa.inspect(conn)
    return table_name in inspector.get_table_names()


def upgrade():
    bind = op.get_bind()

    for table, prefix in ENTITIES:
        if not _table_exists(bind, table):
            # Skip tables that aren't in this database — keeps the migration
            # robust against partial schemas (e.g. test envs).
            continue

        # 1. Add the column as nullable so the backfill can run.
        op.add_column(
            table,
            sa.Column("public_id", sa.String(length=20), nullable=True),
        )

        # 2. Backfill from existing integer id. LPAD to at least 4 digits.
        # Quote the table name so reserved words like "user" work.
        op.execute(
            f'UPDATE "{table}" '
            f"SET public_id = '{prefix}' || LPAD(id::text, 4, '0') "
            f"WHERE public_id IS NULL"
        )

        # 3. Unique index on the populated column. NOT NULL is enforced
        # at the application level via the after_insert event listener —
        # the column stays nullable so the listener has a window to fill
        # it inside the same transaction.
        op.create_index(
            f"ix_{table}_public_id",
            table,
            ["public_id"],
            unique=True,
        )


def downgrade():
    bind = op.get_bind()

    # Reverse order so we drop indexes before columns.
    for table, _prefix in reversed(ENTITIES):
        if not _table_exists(bind, table):
            continue

        try:
            op.drop_index(f"ix_{table}_public_id", table_name=table)
        except Exception:
            pass

        try:
            op.drop_column(table, "public_id")
        except Exception:
            pass
