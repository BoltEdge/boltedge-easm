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


def _greeting_name(user: User) -> str:
    """
    Resolve a friendly first-name greeting for an email.

    Order of preference:
      1. `user.first_name` — explicit, set on every email/password
         signup since the first-name/last-name split.
      2. First word of `user.name` — legacy users registered before
         the split, plus OAuth signups whose IdP only returns a
         single full name.
      3. The local-part of `user.email` — last resort so we never
         greet "there".
    """
    if user.first_name and user.first_name.strip():
        return user.first_name.strip()
    if user.name and user.name.strip():
        return user.name.strip().split()[0]
    if user.email and "@" in user.email:
        return user.email.split("@", 1)[0]
    return "there"


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

    Idempotent: returns False without sending if `user.welcome_email_sent_at`
    is already populated. Stamps the timestamp + commits on a successful
    send so subsequent calls are no-ops. This is what lets us trigger
    welcome from multiple call sites (login, OAuth, invite) without
    risking duplicate emails.

    `organization` is optional — when present, the greeting acknowledges
    the workspace name. For invite-based signups (where a user joins an
    existing org), this gives the email a slightly more personal frame.
    """
    if not user.email:
        return False

    # Idempotency guard — once we've sent the welcome, never send again.
    if getattr(user, "welcome_email_sent_at", None) is not None:
        logger.info("Welcome email already sent for user %s; skipping.", user.id)
        return False

    fe = frontend_url()
    name = _greeting_name(user)

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
          <a href="mailto:support@nanoeasm.com" style="color:{BRAND_TEAL};text-decoration:none;">support@nanoeasm.com</a>.
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
    sent = send_via_resend(to=user.email, subject=subject, html=html)

    # Stamp timestamp on a successful send so future calls become
    # no-ops. We commit immediately rather than relying on the caller —
    # a missed commit here would mean a duplicate welcome on the next
    # trigger, which is worse than the (rare) wasted DB write.
    if sent:
        from datetime import datetime as _dt, timezone as _tz
        from app.extensions import db
        try:
            user.welcome_email_sent_at = _dt.now(_tz.utc).replace(tzinfo=None)
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception("Failed to stamp welcome_email_sent_at for user %s", user.id)

    return sent


# ─────────────────────────────────────────────────────────────────────
# Email verification
# ─────────────────────────────────────────────────────────────────────

def send_verification_email(user: User, verify_link: str) -> bool:
    """Confirm-your-email link, branded shell."""
    if not user.email:
        return False

    name = _greeting_name(user)

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

    name = _greeting_name(user)

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


# ─────────────────────────────────────────────────────────────────────
# Admin-initiated security notifications
# ─────────────────────────────────────────────────────────────────────

def send_mfa_reset_notice(user: User, *, by_admin: bool = True) -> bool:
    """
    Notify the user that their two-factor authentication has been
    disabled. Sent after an admin clicks "Reset MFA" on the user, or
    after the user themselves disables MFA from Settings → Security
    (with `by_admin=False`).

    The email does not contain a recovery link — disabling MFA is its
    own action; the user simply needs to know it happened so they can
    flag it if they didn't authorise it.
    """
    if not user.email:
        return False

    name = _greeting_name(user)
    fe = frontend_url()
    actor_phrase = (
        "a Nano EASM administrator" if by_admin
        else "you (or someone signed in as you)"
    )

    body = f"""
    <p style="font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:0 0 16px 0;">
      Hi {name},
    </p>
    <p style="font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:0 0 16px 0;">
      Two-factor authentication on your Nano EASM account was just <strong>disabled</strong> by {actor_phrase}.
      Your authenticator app and recovery key have been unlinked.
    </p>
    <p style="font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:0 0 16px 0;">
      Next time you sign in, you&rsquo;ll be asked to set up two-factor authentication again
      (if your role requires it).
    </p>

    <div style="margin:24px 0;padding:14px 16px;border-radius:8px;background:#fff7ed;border:1px solid #fed7aa;">
      <p style="margin:0 0 8px 0;font-size:14px;font-weight:600;color:#9a3412;">
        Didn&rsquo;t expect this?
      </p>
      <p style="margin:0;font-size:13px;line-height:1.55;color:#9a3412;">
        If you didn&rsquo;t request this change and don&rsquo;t recognise the action, contact
        <a href="mailto:support@nanoeasm.com" style="color:#9a3412;text-decoration:underline;">support@nanoeasm.com</a>
        immediately and consider changing your password.
      </p>
    </div>

    <p style="font-size:13px;line-height:1.6;color:{TEXT_MUTED};margin:20px 0 0 0;">
      You can re-enable two-factor authentication at any time from
      <a href="{fe}/settings/security" style="color:{BRAND_TEAL};">Settings &rarr; Security</a>.
    </p>
    """

    return send_via_resend(
        to=user.email,
        subject="Your Nano EASM two-factor authentication was disabled",
        html=shell(title="Two-factor authentication disabled", body_html=body),
    )


def send_password_reset_notice(user: User, *, by_admin: bool = True) -> bool:
    """
    Notify the user that someone initiated a password reset on their
    account. The actual reset *link* is delivered separately by
    `send_password_reset_email`; this function exists for the case
    where an admin took action and the user should know.

    Today, the admin password-reset endpoint already includes the
    "an admin initiated this" line in the reset-link email, so this
    helper is mostly a hook for future use (e.g. when password is
    changed via admin without a self-service flow).
    """
    if not user.email:
        return False

    name = _greeting_name(user)
    fe = frontend_url()
    actor_phrase = (
        "a Nano EASM administrator" if by_admin
        else "you (or someone signed in as you)"
    )

    body = f"""
    <p style="font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:0 0 16px 0;">
      Hi {name},
    </p>
    <p style="font-size:15px;line-height:1.6;color:{TEXT_DARK};margin:0 0 16px 0;">
      The password on your Nano EASM account was just <strong>changed</strong> by {actor_phrase}.
    </p>

    <div style="margin:24px 0;padding:14px 16px;border-radius:8px;background:#fff7ed;border:1px solid #fed7aa;">
      <p style="margin:0 0 8px 0;font-size:14px;font-weight:600;color:#9a3412;">
        Didn&rsquo;t expect this?
      </p>
      <p style="margin:0;font-size:13px;line-height:1.55;color:#9a3412;">
        If you didn&rsquo;t make this change, contact
        <a href="mailto:support@nanoeasm.com" style="color:#9a3412;text-decoration:underline;">support@nanoeasm.com</a>
        immediately.
      </p>
    </div>

    <p style="font-size:13px;line-height:1.6;color:{TEXT_MUTED};margin:20px 0 0 0;">
      You can sign in at
      <a href="{fe}/login" style="color:{BRAND_TEAL};">{fe}/login</a>.
    </p>
    """

    return send_via_resend(
        to=user.email,
        subject="Your Nano EASM password was changed",
        html=shell(title="Password changed", body_html=body),
    )
