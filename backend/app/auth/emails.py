"""
Auth-flow transactional emails.

Three emails live here:
  - send_welcome_email(user, organization=None) — sent once per user
    after email verification, OAuth signup, or invite acceptance.
  - send_verification_email(user, verify_link) — confirms an email address.
  - send_password_reset_email(user, reset_link) — password recovery.

All three use the shared `email_shell` so the look matches the rest
of the brand (billing receipts, monitor alerts, future emails).

Failures are logged but never raised — caller is mid-flow and a
transient email outage shouldn't break verification, registration,
or password reset.
"""
from __future__ import annotations

import logging
from typing import Optional

from app.models import User, Organization
from app.utils.email_shell import (
    shell,
    send_via_resend,
    frontend_url,
    BRAND_TEAL,
    TEXT_DARK,
    TEXT_MUTED,
    BORDER,
)


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
# Welcome email — sent once per user
# ─────────────────────────────────────────────────────────────────────

def _quickstart_card(*, num: str, title: str, blurb: str, cta_text: str, cta_href: str) -> str:
    """One numbered "thing to try first" card used in the welcome email."""
    return f"""
    <table cellpadding="0" cellspacing="0" border="0" style="width:100%;margin:12px 0;background:#fff;border:1px solid {BORDER};border-radius:10px;border-collapse:separate;border-spacing:0;">
      <tr>
        <td style="padding:14px 16px;vertical-align:top;width:48px;">
          <div style="width:32px;height:32px;background:{BRAND_TEAL}15;color:{BRAND_TEAL};border-radius:8px;text-align:center;line-height:32px;font-weight:700;font-size:14px;">{num}</div>
        </td>
        <td style="padding:14px 16px 14px 0;vertical-align:top;">
          <div style="font-size:14px;font-weight:600;color:{TEXT_DARK};margin-bottom:4px;">{title}</div>
          <div style="font-size:13px;color:{TEXT_MUTED};line-height:1.55;margin-bottom:8px;">{blurb}</div>
          <a href="{cta_href}" style="font-size:13px;color:{BRAND_TEAL};text-decoration:none;font-weight:500;">{cta_text} &rarr;</a>
        </td>
      </tr>
    </table>"""


def send_welcome_email(user: User, organization: Optional[Organization] = None) -> bool:
    """
    Send the one-time welcome email to a newly active user.

    `organization` is optional — when present, the greeting acknowledges
    the workspace name. For invite-based signups (where a user joins an
    existing org), this gives the email a slightly more personal frame.
    """
    if not user.email:
        return False

    fe = frontend_url()
    name = (user.name or user.email.split("@")[0] or "there").strip()

    if organization and organization.name:
        intro = (
            f"<p style=\"font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:0 0 16px 0;\">"
            f"You&rsquo;ve joined <strong>{organization.name}</strong> on Nano EASM. "
            f"Here are three quick things to try first to get the most out of your workspace."
            f"</p>"
        )
    else:
        intro = (
            f"<p style=\"font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:0 0 16px 0;\">"
            f"Welcome aboard. Your account is ready &mdash; here are three quick "
            f"things to try first to get the most out of Nano EASM."
            f"</p>"
        )

    body = (
        intro
        + _quickstart_card(
            num="1",
            title="Add your first asset",
            blurb="Drop in a domain, IP, or cloud asset you own. Nano EASM will start mapping what's exposed within minutes.",
            cta_text="Add an asset",
            cta_href=f"{fe}/assets",
        )
        + _quickstart_card(
            num="2",
            title="Run a scan",
            blurb="Pick Quick, Standard, or Deep — see ports, services, certificates, and vulnerability findings on one screen.",
            cta_text="Start a scan",
            cta_href=f"{fe}/scan",
        )
        + _quickstart_card(
            num="3",
            title="Turn on monitoring",
            blurb="Get notified the moment something changes — a new port opens, a cert is about to expire, a finding shows up.",
            cta_text="Set up monitoring",
            cta_href=f"{fe}/monitoring",
        )
        + f"""
        <p style="font-size:13px;line-height:1.6;color:{TEXT_MUTED};margin:24px 0 8px 0;">
          Got more questions? Our <a href="{fe}/faq" style="color:{BRAND_TEAL};text-decoration:none;">FAQ</a> covers most of them &mdash; from what you&rsquo;re allowed to scan to how billing works.
        </p>
        <p style="font-size:13px;line-height:1.6;color:{TEXT_MUTED};margin:0;">
          Still stuck? Reply to this email &mdash; it goes straight to a real person at
          <a href="mailto:contact@nanoasm.com" style="color:{BRAND_TEAL};text-decoration:none;">contact@nanoasm.com</a>.
        </p>
        """
    )

    title = f"Welcome to Nano EASM, {name}"
    subject = "Welcome to Nano EASM"
    footer = (
        "Sent once when you joined Nano EASM. We&rsquo;ll only email you about scans you start, "
        "alerts you configure, and your account &mdash; never marketing without your consent."
    )
    html = shell(title=title, body_html=body, footer_html=footer)
    return send_via_resend(to=user.email, subject=subject, html=html)


# ─────────────────────────────────────────────────────────────────────
# Email verification
# ─────────────────────────────────────────────────────────────────────

def send_verification_email(user: User, verify_link: str) -> bool:
    """Confirm-your-email link, branded shell."""
    if not user.email:
        return False

    name = (user.name or user.email.split("@")[0] or "there").strip()

    body = f"""
    <p style="font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:0 0 16px 0;">
      Hi {name},
    </p>
    <p style="font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:0 0 16px 0;">
      Please confirm this is your email address so you can sign in to Nano EASM.
    </p>

    <div style="margin:24px 0;">
      <a href="{verify_link}" style="display:inline-block;background:{BRAND_TEAL};color:#fff;text-decoration:none;padding:11px 22px;border-radius:8px;font-weight:600;font-size:14px;">Verify my email</a>
    </div>

    <p style="font-size:13px;line-height:1.6;color:{TEXT_MUTED};margin:0 0 8px 0;">
      Or paste this link into your browser:
    </p>
    <p style="font-size:12px;line-height:1.55;color:{TEXT_DARK};margin:0;font-family:ui-monospace,SFMono-Regular,monospace;background:#f3f4f6;border:1px solid {BORDER};border-radius:6px;padding:8px 10px;word-break:break-all;">
      {verify_link}
    </p>

    <p style="font-size:13px;line-height:1.6;color:{TEXT_MUTED};margin:20px 0 0 0;">
      This link expires in 48 hours. If you didn&rsquo;t create a Nano EASM account, you can safely ignore this email.
    </p>
    """

    return send_via_resend(
        to=user.email,
        subject="Verify your Nano EASM email address",
        html=shell(title="Confirm your email address", body_html=body),
    )


# ─────────────────────────────────────────────────────────────────────
# Password reset
# ─────────────────────────────────────────────────────────────────────

def send_password_reset_email(user: User, reset_link: str) -> bool:
    """Password-reset link, branded shell."""
    if not user.email:
        return False

    name = (user.name or user.email.split("@")[0] or "there").strip()

    body = f"""
    <p style="font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:0 0 16px 0;">
      Hi {name},
    </p>
    <p style="font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:0 0 16px 0;">
      We received a request to reset the password on your Nano EASM account.
      Click the button below to choose a new one.
    </p>

    <div style="margin:24px 0;">
      <a href="{reset_link}" style="display:inline-block;background:{BRAND_TEAL};color:#fff;text-decoration:none;padding:11px 22px;border-radius:8px;font-weight:600;font-size:14px;">Set a new password</a>
    </div>

    <p style="font-size:13px;line-height:1.6;color:{TEXT_MUTED};margin:0 0 8px 0;">
      Or paste this link into your browser:
    </p>
    <p style="font-size:12px;line-height:1.55;color:{TEXT_DARK};margin:0;font-family:ui-monospace,SFMono-Regular,monospace;background:#f3f4f6;border:1px solid {BORDER};border-radius:6px;padding:8px 10px;word-break:break-all;">
      {reset_link}
    </p>

    <p style="font-size:13px;line-height:1.6;color:{TEXT_MUTED};margin:20px 0 0 0;">
      This link expires in 24 hours. If you didn&rsquo;t request a password reset, you can safely ignore this email &mdash; your existing password still works.
    </p>
    """

    return send_via_resend(
        to=user.email,
        subject="Reset your Nano EASM password",
        html=shell(title="Reset your password", body_html=body),
    )
