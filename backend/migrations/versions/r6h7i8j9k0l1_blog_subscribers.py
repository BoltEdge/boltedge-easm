"""add blog_subscriber + blog_article_sent

Revision ID: r6h7i8j9k0l1
Revises: q5g6h7i8j9k0
Create Date: 2026-05-13 12:00:00.000000

Public, no-auth email subscription to the blog notification feed.
Single opt-in — the row goes in with is_active=True on signup. The
welcome email + the unsubscribe_token URL is the consent audit
mechanism. Re-subscribes reuse the same row (flips is_active back
on, rotates the unsubscribe_token).

blog_article_sent provides per-recipient send idempotency so the
admin can safely re-click the Send button on the same article
without double-mailing anyone.
"""
from alembic import op
import sqlalchemy as sa


revision = "r6h7i8j9k0l1"
down_revision = "q5g6h7i8j9k0"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "blog_subscriber",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("unsubscribe_token", sa.String(length=64), nullable=False),
        sa.Column("subscribed_at", sa.DateTime(), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("unsubscribed_at", sa.DateTime(), nullable=True),
        sa.Column("last_sent_at", sa.DateTime(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("source", sa.String(length=64), nullable=True),
        sa.Column("ip_at_signup", sa.String(length=45), nullable=True),
        sa.Column("user_agent_at_signup", sa.String(length=255), nullable=True),
        sa.UniqueConstraint("email", name="uq_blog_subscriber_email"),
        sa.UniqueConstraint("unsubscribe_token", name="uq_blog_subscriber_unsubscribe_token"),
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_blog_subscriber_email "
        "ON blog_subscriber (email)"
    )

    op.create_table(
        "blog_article_sent",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("article_slug", sa.String(length=120), nullable=False),
        sa.Column("subscriber_id", sa.Integer(), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("error_message", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(
            ["subscriber_id"], ["blog_subscriber.id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("article_slug", "subscriber_id",
                            name="uq_blog_article_sent_slug_subscriber"),
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_blog_article_sent_article_slug "
        "ON blog_article_sent (article_slug)"
    )


def downgrade():
    op.drop_table("blog_article_sent")
    op.drop_table("blog_subscriber")
