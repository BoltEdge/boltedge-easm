"""Blog subscription routes.

Public:
  POST /blog/subscribe
  GET  /blog/unsubscribe/<token>

Admin (superadmin-only):
  POST /admin/blog/send
  GET  /admin/blog/subscribers
  GET  /admin/blog/article-sent/<slug>

Prefixes intentionally omit /api/ — nginx strips that segment before
forwarding to Flask, so blueprints follow the same convention as every
other module here (auth_bp = /auth, billing_bp = /billing, etc.).

Single-opt-in semantics: subscribing creates an active row immediately
and the welcome email is sent right away. The welcome email's
unsubscribe link is the consent audit + accidental-signup escape hatch.

Per-IP rate limit: 3 subscribe attempts per hour per source IP, counted
from the audit fields on existing blog_subscriber rows. Simple and
sufficient given the Turnstile gate sits in front of this.
"""
from __future__ import annotations

import logging
import re
import secrets
from datetime import timedelta

from flask import Blueprint, current_app, jsonify, request

from app.extensions import db
from app.models import BlogSubscriber, BlogArticleSent, now_utc
from app.auth.decorators import require_superadmin
from app.utils.turnstile import verify_turnstile

from .emails import send_welcome_email, send_article_notification


logger = logging.getLogger(__name__)

blog_bp = Blueprint("blog", __name__, url_prefix="/blog")
blog_admin_bp = Blueprint("blog_admin", __name__, url_prefix="/admin/blog")


# Loose but effective email regex — RFC-5322 in full is a tarpit. This
# rejects obviously-broken values and accepts the rest; Resend rejects
# undeliverable addresses on send.
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_MAX_EMAIL_LEN = 254
_RATE_LIMIT_PER_HOUR = 3


def _client_ip() -> str:
    """Real client IP. ProxyFix is wired in app/__init__.py so
    request.remote_addr is already correct behind nginx."""
    return (request.remote_addr or "").strip()[:45]


def _user_agent() -> str:
    return (request.headers.get("User-Agent") or "").strip()[:255]


def _normalise_email(raw: str) -> str:
    return (raw or "").strip().lower()[:_MAX_EMAIL_LEN]


def _new_token() -> str:
    """64-char URL-safe random token — long enough to be unguessable,
    short enough to fit comfortably in an email link."""
    return secrets.token_urlsafe(48)[:64]


def _ip_rate_limited(ip: str) -> bool:
    """Returns True if this IP has signed up >= _RATE_LIMIT_PER_HOUR times
    in the last hour. Counted from BlogSubscriber.ip_at_signup +
    subscribed_at. Approximate (doesn't catch IP rotation) but enough."""
    if not ip:
        return False
    cutoff = now_utc() - timedelta(hours=1)
    recent = (
        BlogSubscriber.query
        .filter(BlogSubscriber.ip_at_signup == ip)
        .filter(BlogSubscriber.subscribed_at >= cutoff)
        .count()
    )
    return recent >= _RATE_LIMIT_PER_HOUR


# ─────────────────────────────────────────────────────────────────────
# Public
# ─────────────────────────────────────────────────────────────────────

@blog_bp.post("/subscribe")
def subscribe():
    body = request.get_json(silent=True) or {}
    email = _normalise_email(body.get("email") or "")
    source = (body.get("source") or "blog-index")[:64]

    if not email or not _EMAIL_RE.match(email):
        return jsonify(error="Please enter a valid email address."), 400

    # Turnstile gate — fail-open on Cloudflare outages by design.
    ok, msg = verify_turnstile(request)
    if not ok:
        return jsonify(error=msg or "Verification failed."), 400

    ip = _client_ip()
    if _ip_rate_limited(ip):
        return jsonify(
            error="Too many subscribe attempts from this network. Try again in an hour."
        ), 429

    existing = BlogSubscriber.query.filter_by(email=email).first()

    if existing:
        if existing.is_active:
            # Already subscribed — return success without re-sending the
            # welcome so we don't help an attacker spam someone's inbox.
            return jsonify(
                status="already-subscribed",
                message="You're already on the list.",
            ), 200
        # Re-subscribe: flip the row back to active, rotate the
        # unsubscribe_token so the old one is dead, send a fresh welcome.
        existing.is_active = True
        existing.unsubscribed_at = None
        existing.unsubscribe_token = _new_token()
        existing.subscribed_at = now_utc()
        existing.source = source
        existing.ip_at_signup = ip
        existing.user_agent_at_signup = _user_agent()
        db.session.commit()
        sent = send_welcome_email(email, existing.unsubscribe_token)
        return jsonify(
            status="resubscribed",
            message="Welcome back. Check your inbox for confirmation.",
            email_sent=sent,
        ), 200

    sub = BlogSubscriber(
        email=email,
        unsubscribe_token=_new_token(),
        is_active=True,
        source=source,
        ip_at_signup=ip,
        user_agent_at_signup=_user_agent(),
    )
    db.session.add(sub)
    db.session.commit()
    sent = send_welcome_email(email, sub.unsubscribe_token)
    return jsonify(
        status="subscribed",
        message="Subscribed. Check your inbox for confirmation.",
        email_sent=sent,
    ), 201


@blog_bp.get("/unsubscribe/<token>")
def unsubscribe(token: str):
    """One-click unsubscribe. Idempotent — if the row is already
    unsubscribed, return the same success response so a re-click doesn't
    look like an error to the user."""
    if not token or len(token) > 64:
        return jsonify(error="Invalid unsubscribe link."), 400

    sub = BlogSubscriber.query.filter_by(unsubscribe_token=token).first()
    if not sub:
        # Token mismatch — could be a stale link from a re-subscribe, or
        # a copy-paste mistake. Don't leak whether the email exists.
        return jsonify(
            status="unsubscribed",
            message="This subscription has been removed.",
        ), 200

    if sub.is_active:
        sub.is_active = False
        sub.unsubscribed_at = now_utc()
        db.session.commit()

    return jsonify(
        status="unsubscribed",
        message="You've been unsubscribed. We won't email you again.",
    ), 200


# ─────────────────────────────────────────────────────────────────────
# Admin (superadmin only)
# ─────────────────────────────────────────────────────────────────────

@blog_admin_bp.get("/subscribers")
@require_superadmin
def list_subscribers():
    """Paginated subscriber list. Active first, most-recent first within
    each group, capped at 500 per request to keep responses bounded."""
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(500, max(10, int(request.args.get("perPage", 50))))
    include_inactive = request.args.get("includeInactive") == "1"

    q = BlogSubscriber.query
    if not include_inactive:
        q = q.filter(BlogSubscriber.is_active.is_(True))
    q = q.order_by(BlogSubscriber.is_active.desc(), BlogSubscriber.subscribed_at.desc())

    total = q.count()
    rows = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify(
        total=total,
        page=page,
        perPage=per_page,
        active=BlogSubscriber.query.filter_by(is_active=True).count(),
        items=[
            {
                "id": s.id,
                "email": s.email,
                "isActive": s.is_active,
                "subscribedAt": s.subscribed_at.isoformat() + "Z" if s.subscribed_at else None,
                "unsubscribedAt": s.unsubscribed_at.isoformat() + "Z" if s.unsubscribed_at else None,
                "lastSentAt": s.last_sent_at.isoformat() + "Z" if s.last_sent_at else None,
                "source": s.source,
            }
            for s in rows
        ],
    ), 200


@blog_admin_bp.get("/article-sent/<slug>")
@require_superadmin
def article_sent_counts(slug: str):
    """How many subscribers have already received this article. Used by
    the admin send page to show 'already sent to N of M' before the
    operator clicks Send."""
    if not slug or len(slug) > 120:
        return jsonify(error="Invalid slug."), 400

    sent_count = BlogArticleSent.query.filter_by(article_slug=slug, success=True).count()
    failed_count = BlogArticleSent.query.filter_by(article_slug=slug, success=False).count()
    active_subs = BlogSubscriber.query.filter_by(is_active=True).count()
    not_yet_sent = max(0, active_subs - sent_count)
    return jsonify(
        slug=slug,
        sent=sent_count,
        failed=failed_count,
        activeSubscribers=active_subs,
        notYetSent=not_yet_sent,
    ), 200


@blog_admin_bp.post("/send")
@require_superadmin
def send_article():
    """Iterate active subscribers, email each one about the supplied
    article. Idempotent at the per-recipient level via BlogArticleSent's
    unique constraint — if a row exists for (slug, subscriber_id), we
    skip that subscriber.

    Body:
      slug         (str, required)
      title        (str, required)
      description  (str, required)
      readTime     (int, optional)

    The frontend supplies these — the backend doesn't need filesystem
    access to the markdown source. Keeps the seam clean.
    """
    body = request.get_json(silent=True) or {}
    slug = (body.get("slug") or "").strip()[:120]
    title = (body.get("title") or "").strip()
    description = (body.get("description") or "").strip()
    read_time = body.get("readTime")
    try:
        read_time = int(read_time) if read_time is not None else None
    except (TypeError, ValueError):
        read_time = None

    if not slug or not title or not description:
        return jsonify(error="slug, title, and description are required"), 400

    active_subs = BlogSubscriber.query.filter_by(is_active=True).all()
    if not active_subs:
        return jsonify(
            slug=slug,
            attempted=0,
            sent=0,
            skipped=0,
            failed=0,
            message="No active subscribers.",
        ), 200

    # Pull the set of subscriber_ids who already received this article,
    # in one query instead of an existence check per recipient.
    already_sent_ids = {
        row.subscriber_id
        for row in BlogArticleSent.query.filter_by(article_slug=slug).all()
    }

    sent = 0
    skipped = 0
    failed = 0
    now = now_utc()

    for sub in active_subs:
        if sub.id in already_sent_ids:
            skipped += 1
            continue
        ok = send_article_notification(
            email=sub.email,
            unsubscribe_token=sub.unsubscribe_token,
            article_title=title,
            article_description=description,
            article_slug=slug,
            read_time=read_time,
        )
        receipt = BlogArticleSent(
            article_slug=slug,
            subscriber_id=sub.id,
            sent_at=now,
            success=ok,
            error_message=None if ok else "Resend send returned False",
        )
        db.session.add(receipt)
        if ok:
            sub.last_sent_at = now
            sent += 1
        else:
            failed += 1
        # Flush each row so a per-recipient failure doesn't lose audit
        # rows for the recipients before it.
        db.session.commit()

    return jsonify(
        slug=slug,
        attempted=len(active_subs),
        sent=sent,
        skipped=skipped,
        failed=failed,
        message=(
            f"Sent {sent} email{'' if sent == 1 else 's'}"
            + (f", skipped {skipped} already-sent" if skipped else "")
            + (f", {failed} failed" if failed else "")
            + "."
        ),
    ), 200
