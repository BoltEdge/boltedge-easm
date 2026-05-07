"""tuning_rule applied_count + last_applied_at

Revision ID: k9a0b1c2d3e4
Revises: j8f9a0b1c2d3
Create Date: 2026-05-08 09:00:00.000000

Adds visibility for tuning rules — how often each rule has actually
fired and the timestamp of its most recent application. The previous
state was that users could create suppression / downgrade rules and
have no signal at all about whether they were hitting anything,
which made the rule list impossible to maintain (over-broad rules
silenced findings the user wanted to see; over-narrow rules sat
inert).

`applied_count` increments any time a rule causes a non-allow action
(suppress, downgrade, upgrade, snooze) — not just suppression. The
column name reflects that breadth.

Counters are best-effort visibility, not authoritative audit. The
authoritative record of what alerts were generated lives in
monitor_alert; this column is a denormalised counter so the rules
list can show "applied N times" without a per-row aggregate query.
"""
from alembic import op
import sqlalchemy as sa


revision = 'k9a0b1c2d3e4'
down_revision = 'j8f9a0b1c2d3'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'tuning_rule',
        sa.Column('applied_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
    )
    op.add_column(
        'tuning_rule',
        sa.Column('last_applied_at', sa.DateTime(), nullable=True),
    )
    # Drop the server_default — going forward, application code sets
    # the value (always 0 on insert). Matches the pattern used elsewhere.
    op.alter_column('tuning_rule', 'applied_count', server_default=None)


def downgrade():
    op.drop_column('tuning_rule', 'last_applied_at')
    op.drop_column('tuning_rule', 'applied_count')
