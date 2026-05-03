"""
Shared HTML shell for transactional emails.

All Nano EASM emails — auth, billing, monitoring, future ones — should
go through `shell()` so the look is consistent and changes (logo,
sign-off, footer style) only need to be made in one place.

Provides:
  - Brand colour constants (TEAL, DARK, TEXT, MUTED, BORDER, BG)
  - frontend_url()         — resolves the FRONTEND_URL env var with fallback
  - send_via_resend(...)   — consistent Resend wrapper (logs + never raises)
  - shell(title, body, …)  — the full email HTML wrapper
"""
from __future__ import annotations

import logging
import os
from typing import Optional


logger = logging.getLogger(__name__)


# ── Brand palette (kept in sync with frontend tailwind config) ───────
BRAND_TEAL = "#14b8a6"
BRAND_DARK = "#0a0f1e"
TEXT_DARK = "#1f2937"
TEXT_MUTED = "#6b7280"
BORDER = "#e5e7eb"
BG_LIGHT = "#f9fafb"


def frontend_url() -> str:
    """Resolve the canonical app URL from env, with a sensible fallback."""
    return os.environ.get("FRONTEND_URL", "https://nanoasm.com").rstrip("/")


# ── Sign-off block (universal, appears at the bottom of every email) ─

def _signoff_html() -> str:
    return f"""
    <div style="margin-top:32px;padding-top:24px;border-top:1px solid {BORDER};">
      <p style="font-size:14px;color:{TEXT_DARK};margin:0 0 14px 0;font-weight:600;line-height:1.5;">— The Nano EASM Team</p>
      <table cellpadding="0" cellspacing="0" border="0">
        <tr>
          <td style="padding-right:8px;vertical-align:middle;">
            <div style="width:24px;height:24px;background:{BRAND_DARK};border-radius:5px;text-align:center;line-height:24px;">
              <span style="color:{BRAND_TEAL};font-size:14px;font-weight:bold;">⚡</span>
            </div>
          </td>
          <td style="vertical-align:middle;">
            <a href="{frontend_url()}" style="color:{BRAND_TEAL};text-decoration:none;font-size:13px;font-weight:500;">nanoasm.com</a>
          </td>
        </tr>
      </table>
    </div>"""


# ── Header (logo + wordmark) ─────────────────────────────────────────

def _header_html() -> str:
    return f"""
    <div style="text-align:left;padding-bottom:24px;border-bottom:1px solid {BORDER};">
      <table cellpadding="0" cellspacing="0" border="0">
        <tr>
          <td style="padding-right:10px;vertical-align:middle;">
            <div style="width:32px;height:32px;background:{BRAND_DARK};border-radius:7px;text-align:center;line-height:32px;">
              <span style="color:{BRAND_TEAL};font-size:20px;font-weight:bold;">⚡</span>
            </div>
          </td>
          <td style="vertical-align:middle;">
            <span style="font-size:16px;font-weight:600;color:{TEXT_DARK};">Nano<span style="color:{BRAND_TEAL};">EASM</span></span>
          </td>
        </tr>
      </table>
    </div>"""


# ── Public: full email wrapper ───────────────────────────────────────

def shell(*, title: str, body_html: str, footer_html: str = "") -> str:
    """
    Wrap email content in the standard Nano EASM shell.

    Layout:
      [header — logo + wordmark]
      [h1 title]
      [body_html — caller's content]
      [universal sign-off — "Kind regards, The Nano EASM Team" + logo + URL]
      [footer_html — optional, per-email legal/disclaimer text]

    `footer_html` is rendered in muted small text. Use it for things
    like "manage billing · contact@nanoasm.com" lines specific to one
    email type. Leave empty if the sign-off is enough.
    """
    footer_block = ""
    if footer_html:
        footer_block = f"""
        <div style="margin-top:20px;padding-top:14px;border-top:1px solid {BORDER};font-size:12px;color:{TEXT_MUTED};line-height:1.6;">
          {footer_html}
        </div>"""

    return f"""<!doctype html>
<html>
<body style="margin:0;padding:0;background:{BG_LIGHT};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:{TEXT_DARK};">
  <div style="max-width:560px;margin:0 auto;padding:32px 16px;">
    {_header_html()}
    <h1 style="font-size:22px;font-weight:600;color:{TEXT_DARK};margin:24px 0 8px 0;letter-spacing:-0.01em;">{title}</h1>
    {body_html}
    {_signoff_html()}
    {footer_block}
  </div>
</body>
</html>"""


# ── Public: Resend send helper ───────────────────────────────────────

def send_via_resend(*, to: str, subject: str, html: str, from_addr: Optional[str] = None) -> bool:
    """
    Send an email through Resend. Never raises — caller is mid-flow
    and a transient email failure shouldn't fail the surrounding
    operation (registration, billing webhook, password reset, etc.).

    Returns True on success, False on any failure (including missing
    API key). All failures are logged with the recipient address but
    not the message body.
    """
    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    if not api_key:
        logger.warning("RESEND_API_KEY not set; skipping email to %s (subject: %s)", to, subject)
        return False

    sender = from_addr or os.environ.get("EMAIL_FROM") or "Nano EASM <no-reply@nanoasm.com>"

    try:
        import resend
        resend.api_key = api_key
        resend.Emails.send({
            "from": sender,
            "to": [to],
            "subject": subject,
            "html": html,
        })
        return True
    except Exception:
        logger.exception("Resend send failed for email to %s (subject: %s)", to, subject)
        return False
