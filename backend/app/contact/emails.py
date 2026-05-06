# =============================================================================
# File: app/contact/emails.py
# Description: Acknowledgement email sent to anyone who submits a
# ContactRequest — public contact form, demo request, or trial request.
#
# We send the same shape of email regardless of channel because the
# recipient's question is the same: "did you actually get my message?"
# Including the request number means if they reply / contact us
# elsewhere, we can pull the original up instantly.
#
# Failure mode: never raises. If Resend is down or RESEND_API_KEY is
# missing, we log and return — the surrounding flow (DB write, banner
# response) is unaffected. We'd rather drop one ack email than fail
# the whole request and confuse the user.
# =============================================================================

from __future__ import annotations

import logging
from typing import Optional

from app.utils.email_shell import (
    shell,
    send_via_resend,
    frontend_url,
    BRAND_TEAL as _BRAND_TEAL,
    TEXT_DARK as _TEXT_DARK,
    TEXT_MUTED as _TEXT_MUTED,
    BORDER as _BORDER,
)


logger = logging.getLogger(__name__)


# Friendly human label for each `request_type`. Drives the email
# subject and body copy. Unknown types fall back to the generic
# "message" wording.
_TYPE_COPY = {
    "general": {
        "title": "We received your message",
        "subject": "We received your message — Nano EASM",
        "lead": "Thanks for getting in touch with Nano EASM. Our team has received your message and will follow up shortly.",
    },
    "trial": {
        "title": "We received your trial request",
        "subject": "Your Nano EASM trial request has been received",
        "lead": "Thanks for requesting a free trial. Our team will review your request and email you with a decision — usually within one business day.",
    },
    "demo": {
        "title": "We received your demo request",
        "subject": "Your Nano EASM demo request has been received",
        "lead": "Thanks for asking for a guided demo. Our team will reach out shortly to schedule a time that suits you.",
    },
}


def send_acknowledgement_email(
    *,
    to_email: str,
    to_name: Optional[str],
    request_id: Optional[str],
    request_type: str,
    subject: Optional[str] = None,
    message_excerpt: Optional[str] = None,
) -> bool:
    """
    Send an acknowledgement email to whoever submitted a ContactRequest.

    Args:
        to_email:        recipient address (the submitter)
        to_name:         display name for the salutation; falls back to "there"
        request_id:      ContactRequest.public_id (e.g. "CR0042"). May be None
                         if it hasn't flushed yet — we still send something useful.
        request_type:    "general" | "trial" | "demo" — drives copy
        subject:         the user-supplied subject line (echoed back so they
                         see we have what they sent)
        message_excerpt: optional preview of their message, trimmed in caller

    Returns True on send, False on any failure (incl. missing API key).
    """
    if not to_email:
        return False

    copy = _TYPE_COPY.get(request_type) or _TYPE_COPY["general"]
    name = (to_name or "").strip() or "there"

    request_id_block = ""
    if request_id:
        request_id_block = f"""
        <p style="margin:0 0 14px 0;font-size:14px;color:{_TEXT_MUTED};line-height:1.6;">
          Reference number:
          <span style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:{_TEXT_DARK};font-weight:600;">
            {request_id}
          </span>
          — quote this if you reply to this email or contact us again.
        </p>
        """

    submitted_block = ""
    if subject or message_excerpt:
        rows = []
        if subject:
            rows.append(
                f'<tr><td style="padding:6px 12px 6px 0;color:{_TEXT_MUTED};vertical-align:top;font-size:13px;width:80px;">Subject</td>'
                f'<td style="padding:6px 0;color:{_TEXT_DARK};font-size:13px;">{_html_escape(subject)}</td></tr>'
            )
        if message_excerpt:
            rows.append(
                f'<tr><td style="padding:6px 12px 6px 0;color:{_TEXT_MUTED};vertical-align:top;font-size:13px;">Message</td>'
                f'<td style="padding:6px 0;color:{_TEXT_DARK};font-size:13px;white-space:pre-wrap;">{_html_escape(message_excerpt)}</td></tr>'
            )
        submitted_block = f"""
        <div style="margin:18px 0;padding:14px 16px;border:1px solid {_BORDER};border-radius:8px;background:#fff;">
          <p style="margin:0 0 8px 0;font-size:12px;color:{_TEXT_MUTED};text-transform:uppercase;letter-spacing:0.04em;font-weight:600;">What you sent</p>
          <table cellpadding="0" cellspacing="0" border="0" style="width:100%;">
            {''.join(rows)}
          </table>
        </div>
        """

    body_html = f"""
      <p style="margin:0 0 14px 0;font-size:15px;color:{_TEXT_DARK};line-height:1.6;">Hi {_html_escape(name)},</p>
      <p style="margin:0 0 14px 0;font-size:15px;color:{_TEXT_DARK};line-height:1.6;">{copy['lead']}</p>
      {request_id_block}
      {submitted_block}
      <p style="margin:18px 0 0 0;font-size:14px;color:{_TEXT_MUTED};line-height:1.6;">
        No action is needed from you right now. If your situation changes, just reply to this email.
      </p>
    """

    html = shell(
        title=copy["title"],
        body_html=body_html,
        footer_html=f'You\'re receiving this because someone submitted a request using this address at <a href="{frontend_url()}" style="color:{_BRAND_TEAL};text-decoration:none;">nanoeasm.com</a>.',
    )

    return send_via_resend(
        to=to_email,
        subject=copy["subject"],
        html=html,
    )


def _html_escape(s: str) -> str:
    """Tiny escape — we don't want a hostile name/subject HTML-injecting."""
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
