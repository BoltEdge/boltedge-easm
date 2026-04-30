"""merge oauth and manual_alerts heads

Revision ID: bda233dcf660
Revises: d4e5f6a7b8c9, e1f2a3b4c5d6
Create Date: 2026-05-01 08:22:02.241683

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bda233dcf660'
down_revision = ('d4e5f6a7b8c9', 'e1f2a3b4c5d6')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
