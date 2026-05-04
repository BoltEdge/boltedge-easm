"""add criticality column to asset

Revision ID: e2f3a4b5c6d7
Revises: d5e6f7a8b9c0
Create Date: 2026-05-04 12:00:00.000000

Adds Asset.criticality (tier_1 / tier_2 / tier_3, default tier_2).
Used to weight findings in exposure-score rollups: tier_1 findings
count 1.5x, tier_2 1.0x, tier_3 0.5x.

Backfill: every existing asset gets tier_2 via the server_default,
which matches the prior implicit "all assets are equal" behaviour —
exposure scores stay numerically identical until a user reclassifies.
"""
from alembic import op
import sqlalchemy as sa


revision = 'e2f3a4b5c6d7'
down_revision = 'd5e6f7a8b9c0'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('asset') as batch:
        batch.add_column(sa.Column(
            'criticality',
            sa.String(length=10),
            nullable=False,
            server_default='tier_2',
        ))
        batch.create_index('ix_asset_criticality', ['criticality'])


def downgrade():
    with op.batch_alter_table('asset') as batch:
        batch.drop_index('ix_asset_criticality')
        batch.drop_column('criticality')
