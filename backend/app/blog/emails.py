"""Blog subscription email templates + send helpers.

Two emails:
  · welcome — sent immediately on subscribe; serves as the single-opt-in
    consent confirmation. Contains a prominent unsubscribe link so an
    accidental subscribe is one click away from removal.
  · article-notification — sent when admin pushes a new article. Includes
    title, lede, link to read, and an unsubscribe footer.

All sends go through app.utils.email_shell.send_via_resend so the From
address, headers, and brand chrome are consistent with auth / billing
emails.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from app.utils.email_shell import (
    shell,
    send_via_resend,
    frontend_url,
    BRAND_TEAL,
    TEXT_DARK,
    TEXT_MUTED,
)


logger = logging.getLogger(__name__)


def _blog_from_address() -> str:
    """From line for blog emails. Falls back to a sensible default if the
    env var isn't set so local dev doesn't crash."""
    return os.environ.get("EMAIL_FROM_BLOG", "Nano EASM Blog <blog@nanoeasm.com>")


def _unsubscribe_url(token: str) -> str:
    return f"{frontend_url()}/resources/blog/unsubscribe/{token}"


def _read_article_url(slug: str) -> str:
    return f"{frontend_url()}/resources/blog/{slug}"


def _footer_html(unsubscribe_url: str) -> str:
    return (
        f'You\'re receiving this because you subscribed to the Nano EASM blog at '
        f'<a href="{frontend_url()}/resources/blog" style="color:{BRAND_TEAL};text-decoration:none;">'
        f'{frontend_url().replace("https://", "").replace("http://", "")}/resources/blog</a>. '
        f'<a href="{unsubscribe_url}" style="color:{TEXT_MUTED};text-decoration:underline;">'
        f'Unsubscribe</a> any time — one click, no questions.'
    )


def send_welcome_email(email: str, unsubscribe_token: str) -> bool:
    """Sent immediately when someone subscribes. The unsubscribe link is
    prominent — if a malicious actor signed someone else up, the wrong
    recipient can escape with a single click."""
    unsubscribe_url = _unsubscribe_url(unsubscribe_token)
    title = "You're subscribed to the Nano EASM blog"
    body = f"""
      <p style="font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:16px 0 0 0;">
        Welcome. You'll get an email from us when we publish a new article — usually one a week,
        sometimes less, never more than two.
      </p>
      <p style="font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:16px 0 0 0;">
        We write about Attack Surface Management, vulnerability discovery, exposure monitoring,
        and the practical work of staying ahead of an ever-expanding attack surface.
        Senior-engineer-to-peers tone. No marketing fluff.
      </p>
      <p style="font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:24px 0 8px 0;">
        Browse what's already published:
      </p>
      <p style="margin:0 0 24px 0;">
        <a href="{frontend_url()}/resources/blog"
           style="display:inline-block;background:{BRAND_TEAL};color:#ffffff;
                  text-decoration:none;padding:11px 20px;border-radius:8px;
                  font-size:14px;font-weight:600;">Open the blog</a>
      </p>
      <p style="font-size:13px;line-height:1.6;color:{TEXT_MUTED};margin:24px 0 0 0;">
        Didn't sign up? Someone else may have entered your address — sorry about that.
        <a href="{unsubscribe_url}" style="color:{BRAND_TEAL};text-decoration:underline;">Remove your address</a>
        in one click, no questions.
      </p>
    """
    html = shell(
        title=title,
        body_html=body,
        footer_html=_footer_html(unsubscribe_url),
    )
    return send_via_resend(
        to=email,
        subject="You're subscribed to the Nano EASM blog",
        html=html,
        from_addr=_blog_from_address(),
    )


def send_article_notification(
    *,
    email: str,
    unsubscribe_token: str,
    article_title: str,
    article_description: str,
    article_slug: str,
    read_time: Optional[int] = None,
) -> bool:
    """Sent when admin pushes an article to subscribers. One email per
    subscriber per article; idempotency enforced at the call site via
    BlogArticleSent."""
    unsubscribe_url = _unsubscribe_url(unsubscribe_token)
    read_url = _read_article_url(article_slug)
    read_time_label = f" · {read_time} min read" if read_time else ""

    title = "New from the Nano EASM blog"
    body = f"""
      <p style="font-size:13px;line-height:1.5;color:{TEXT_MUTED};
                text-transform:uppercase;letter-spacing:0.08em;font-weight:600;margin:16px 0 4px 0;">
        New article{read_time_label}
      </p>
      <h2 style="font-size:24px;font-weight:700;color:{TEXT_DARK};line-height:1.25;
                 margin:6px 0 16px 0;letter-spacing:-0.01em;">
        {article_title}
      </h2>
      <p style="font-size:15px;line-height:1.65;color:{TEXT_DARK};margin:0 0 24px 0;">
        {article_description}
      </p>
      <p style="margin:0 0 24px 0;">
        <a href="{read_url}"
           style="display:inline-block;background:{BRAND_TEAL};color:#ffffff;
                  text-decoration:none;padding:11px 22px;border-radius:8px;
                  font-size:14px;font-weight:600;">Read the article</a>
      </p>
    """
    html = shell(
        title=title,
        body_html=body,
        footer_html=_footer_html(unsubscribe_url),
    )
    return send_via_resend(
        to=email,
        subject=f"New on Nano EASM: {article_title}",
        html=html,
        from_addr=_blog_from_address(),
    )
