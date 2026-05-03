"""
Transactional billing emails — sent via Resend in response to Stripe
webhook events.

Why we send our own emails instead of using Stripe's built-in receipts:
  1. Comes from `no-reply@nanoasm.com` (our domain, our trust signal)
     instead of `invoice+statements@stripe.com`.
  2. Branded layout matches the rest of the app's email design.
  3. We can fold in app-specific context (link to /settings/billing,
     plan label using our naming, etc.).

Important: when this module is in use, **disable Stripe's automatic
receipts** in Stripe Dashboard → Settings → Customer emails to avoid
duplicate emails to the customer.

Failure mode: every send is wrapped in a try/except. If Resend is down
or misconfigured, we log and return — the webhook handler then commits
the DB updates and acks the event to Stripe. We'd rather drop one
email than have Stripe retry the whole event (which could re-process
state changes).
"""
from __future__ import annotations

import logging
from typing import Optional

from app.models import Organization, OrganizationMember, User
from app.utils.email_shell import (
    shell,
    send_via_resend,
    frontend_url,
    BRAND_TEAL as _BRAND_TEAL,
    BRAND_DARK as _BRAND_DARK,
    TEXT_DARK as _TEXT_DARK,
    TEXT_MUTED as _TEXT_MUTED,
    BORDER as _BORDER,
    BG_LIGHT as _BG_LIGHT,
)


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
# Recipient resolution
# ─────────────────────────────────────────────────────────────────────

def _recipient_for(org: Organization) -> Optional[str]:
    """
    Pick a billing-email recipient for `org`. Order:
      1. org.billing_email (set in Stripe Customer → updated by webhook)
      2. The org's owner's email
      3. None — caller logs and skips
    """
    if org.billing_email:
        return org.billing_email

    owner_link = OrganizationMember.query.filter_by(
        organization_id=org.id, role="owner", is_active=True
    ).first()
    if owner_link:
        owner = User.query.get(owner_link.user_id)
        if owner and owner.email:
            return owner.email

    # Fallback: any active admin
    admin_link = OrganizationMember.query.filter_by(
        organization_id=org.id, role="admin", is_active=True
    ).first()
    if admin_link:
        admin = User.query.get(admin_link.user_id)
        if admin and admin.email:
            return admin.email

    return None


# Per-email footer for billing emails — points at /settings/billing
# so the recipient has a one-click path to update their card or view
# invoices. Reused by all three send functions below.
def _billing_footer() -> str:
    fe = frontend_url()
    return (
        f'This is an automated email from Nano EASM. You received it because you have an active subscription on this organisation.<br>'
        f'<a href="{fe}/settings/billing" style="color:{_BRAND_TEAL};text-decoration:none;">Manage billing</a>'
        f'&nbsp;·&nbsp;'
        f'<a href="mailto:contact@nanoasm.com" style="color:{_BRAND_TEAL};text-decoration:none;">contact@nanoasm.com</a>'
    )


def _format_money(amount_cents: int, currency: str) -> str:
    """e.g. 1900, 'usd' → '$19.00 USD'"""
    if amount_cents is None:
        return "—"
    sym = "$" if currency.lower() == "usd" else ""
    return f"{sym}{amount_cents / 100:,.2f} {currency.upper()}"


def _format_unix_date(ts: Optional[int]) -> str:
    """Format a Stripe unix timestamp as YYYY-MM-DD."""
    if not ts:
        return "—"
    from datetime import datetime, timezone
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")


# Most common ISO 3166-1 alpha-2 codes mapped to full country names. The
# Stripe Invoice object stores `country` as the 2-letter code; receipts
# read better with the full name. Codes we don't have fall back to the
# raw code (e.g. "ZA" → "ZA") which is still recognisable.
_COUNTRY_NAMES: dict[str, str] = {
    "US": "United States", "GB": "United Kingdom", "CA": "Canada",
    "AU": "Australia", "NZ": "New Zealand", "IE": "Ireland",
    "DE": "Germany", "FR": "France", "ES": "Spain", "IT": "Italy",
    "NL": "Netherlands", "BE": "Belgium", "PT": "Portugal",
    "SE": "Sweden", "NO": "Norway", "DK": "Denmark", "FI": "Finland",
    "AT": "Austria", "CH": "Switzerland", "PL": "Poland", "CZ": "Czechia",
    "RO": "Romania", "GR": "Greece", "HU": "Hungary",
    "JP": "Japan", "SG": "Singapore", "HK": "Hong Kong",
    "KR": "South Korea", "TW": "Taiwan",
    "IN": "India", "BR": "Brazil", "MX": "Mexico", "AR": "Argentina",
    "ZA": "South Africa", "AE": "United Arab Emirates", "IL": "Israel",
}


def _country_name(code: Optional[str]) -> str:
    if not code:
        return ""
    code = code.upper()
    return _COUNTRY_NAMES.get(code, code)


def _format_signed_money(cents: Optional[int], currency: str) -> str:
    """Render a money value with explicit sign — credits are negative."""
    if cents is None:
        return "—"
    sym = "$" if currency.lower() == "usd" else ""
    if cents < 0:
        return f"-{sym}{abs(cents) / 100:,.2f}"
    return f"{sym}{cents / 100:,.2f}"


def _line_items_html(invoice: dict) -> str:
    """
    Render the invoice's line items + subtotal/tax/total summary as
    a single table. Handles both:

      - Normal renewals — one line item, simple summary
      - Prorated changes — multiple line items, one or more negative
        (credits for unused time on old plan), positive for new plan
      - Stripe Tax — when active, the tax line has a real value;
        when off, it's hidden entirely

    Stripe gives us nicely-formatted descriptions like:
      "1 × Nano EASM Starter (at $19.00 / month)"
      "Unused time on Nano EASM Starter after 03 May 2026"
      "Remaining time on Nano EASM Pro after 03 May 2026"
    so we don't need to add period info separately.
    """
    lines = (invoice.get("lines") or {}).get("data") or []
    currency = (invoice.get("currency") or "usd").lower()
    subtotal = invoice.get("subtotal", 0) or 0
    total = invoice.get("total", subtotal) or 0
    # `tax` field is populated when Stripe Tax is active. Otherwise
    # `total - subtotal` is 0. Either way, hide the row when there's
    # no tax to show.
    tax = invoice.get("tax")
    if tax is None:
        tax = max(0, total - subtotal)

    rows = []
    for line in lines:
        desc = (line.get("description") or "—").strip()
        amount = line.get("amount", 0) or 0
        amount_color = _TEXT_DARK if amount >= 0 else _TEXT_MUTED
        rows.append(f"""
        <tr>
          <td style="padding:12px 16px;font-size:13px;color:{_TEXT_DARK};border-bottom:1px solid {_BORDER};line-height:1.5;">{desc}</td>
          <td style="padding:12px 16px;font-size:13px;color:{amount_color};text-align:right;border-bottom:1px solid {_BORDER};font-family:ui-monospace,monospace;white-space:nowrap;">{_format_signed_money(amount, currency)}</td>
        </tr>""")

    summary = []
    summary.append(f"""
    <tr>
      <td style="padding:10px 16px;font-size:13px;color:{_TEXT_MUTED};">Subtotal</td>
      <td style="padding:10px 16px;font-size:13px;color:{_TEXT_DARK};text-align:right;font-family:ui-monospace,monospace;white-space:nowrap;">{_format_signed_money(subtotal, currency)}</td>
    </tr>""")

    if tax and tax > 0:
        summary.append(f"""
        <tr>
          <td style="padding:10px 16px;font-size:13px;color:{_TEXT_MUTED};">Tax</td>
          <td style="padding:10px 16px;font-size:13px;color:{_TEXT_DARK};text-align:right;font-family:ui-monospace,monospace;white-space:nowrap;">{_format_signed_money(tax, currency)}</td>
        </tr>""")

    summary.append(f"""
    <tr>
      <td style="padding:14px 16px;font-size:14px;color:{_TEXT_DARK};font-weight:600;border-top:1px solid {_BORDER};">Total paid</td>
      <td style="padding:14px 16px;font-size:14px;color:{_TEXT_DARK};text-align:right;font-family:ui-monospace,monospace;font-weight:600;border-top:1px solid {_BORDER};white-space:nowrap;">{_format_signed_money(total, currency)} {currency.upper()}</td>
    </tr>""")

    return f"""
    <table cellpadding="0" cellspacing="0" border="0" style="width:100%;border:1px solid {_BORDER};border-radius:10px;margin:20px 0;background:#fff;border-collapse:separate;border-spacing:0;">
      <tr>
        <td style="padding:10px 16px;font-size:11px;color:{_TEXT_MUTED};text-transform:uppercase;letter-spacing:0.5px;font-weight:600;border-bottom:1px solid {_BORDER};">Description</td>
        <td style="padding:10px 16px;font-size:11px;color:{_TEXT_MUTED};text-transform:uppercase;letter-spacing:0.5px;font-weight:600;text-align:right;border-bottom:1px solid {_BORDER};">Amount</td>
      </tr>
      {''.join(rows)}
      {''.join(summary)}
    </table>"""


def _format_address_html(invoice: dict) -> str:
    """
    Build a "Billed to" block from the Stripe Invoice's customer details.
    Returns an empty string if no address is available — the receipt
    skips the block entirely rather than rendering blanks.

    The Stripe Invoice object holds:
      customer_name             — name on file
      customer_email            — email on file
      customer_address          — { line1, line2, city, postal_code, state, country }
      customer_tax_ids          — array of { type, value } (e.g. EU VAT)
    """
    name  = (invoice.get("customer_name") or "").strip()
    email = (invoice.get("customer_email") or "").strip()
    addr  = invoice.get("customer_address") or {}
    tax_ids = invoice.get("customer_tax_ids") or []

    # If there's literally no address data, skip the block.
    has_address = any(addr.get(k) for k in ("line1", "line2", "city", "postal_code", "state", "country"))
    if not (name or has_address):
        return ""

    parts: list[str] = []
    if name:
        parts.append(f'<div style="font-size:14px;color:{_TEXT_DARK};font-weight:500;">{name}</div>')

    line1 = (addr.get("line1") or "").strip()
    line2 = (addr.get("line2") or "").strip()
    city = (addr.get("city") or "").strip()
    state = (addr.get("state") or "").strip()
    postal = (addr.get("postal_code") or "").strip()
    country = _country_name(addr.get("country"))

    if line1:
        parts.append(f'<div style="font-size:13px;color:{_TEXT_MUTED};">{line1}</div>')
    if line2:
        parts.append(f'<div style="font-size:13px;color:{_TEXT_MUTED};">{line2}</div>')

    # "City, State Postal" all on one line, only what's filled.
    locality_bits = []
    if city: locality_bits.append(city)
    if state: locality_bits.append(state)
    locality = ", ".join(locality_bits)
    if postal: locality = f"{locality} {postal}".strip()
    if locality:
        parts.append(f'<div style="font-size:13px;color:{_TEXT_MUTED};">{locality}</div>')

    if country:
        parts.append(f'<div style="font-size:13px;color:{_TEXT_MUTED};">{country}</div>')

    if email:
        parts.append(f'<div style="font-size:13px;color:{_TEXT_MUTED};margin-top:6px;">{email}</div>')

    # Tax IDs (e.g. VAT, EIN) — important for B2B receipts in EU/UK.
    for tid in tax_ids:
        kind = (tid.get("type") or "").upper().replace("_", " ")
        value = tid.get("value") or ""
        if value:
            parts.append(f'<div style="font-size:12px;color:{_TEXT_MUTED};font-family:ui-monospace,monospace;margin-top:4px;">{kind}: {value}</div>')

    inner = "".join(parts)
    return f"""
    <div style="margin:20px 0;padding:14px 16px;background:{_BG_LIGHT};border:1px solid {_BORDER};border-radius:10px;">
      <div style="font-size:11px;color:{_TEXT_MUTED};text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;font-weight:600;">Billed to</div>
      {inner}
    </div>"""


# ─────────────────────────────────────────────────────────────────────
# Public API — called from webhook handlers
# ─────────────────────────────────────────────────────────────────────

def send_receipt_email(org: Organization, invoice: dict) -> bool:
    """
    Send a payment-success receipt to the org's billing contact.

    `invoice` is the Stripe Invoice object from the
    `invoice.payment_succeeded` webhook event.
    """
    to = _recipient_for(org)
    if not to:
        logger.warning("No billing recipient for org %s; skipping receipt", org.id)
        return False

    from app.billing.routes import PLAN_CONFIG
    plan_label = PLAN_CONFIG.get(org.plan, {}).get("label", org.plan)

    amount_cents = invoice.get("amount_paid", 0)
    currency = invoice.get("currency") or "usd"
    period_start = invoice.get("period_start") or invoice.get("status_transitions", {}).get("paid_at")
    period_end = invoice.get("period_end")
    invoice_number = invoice.get("number") or invoice.get("id", "")
    invoice_pdf = invoice.get("invoice_pdf") or invoice.get("hosted_invoice_url") or ""
    hosted_url = invoice.get("hosted_invoice_url") or ""

    fe = frontend_url()
    pdf_button = ""
    if invoice_pdf:
        pdf_button = f"""
        <div style="margin:24px 0;">
          <a href="{invoice_pdf}" style="display:inline-block;background:{_BRAND_TEAL};color:#fff;text-decoration:none;padding:11px 22px;border-radius:8px;font-weight:600;font-size:14px;">View invoice (PDF)</a>
          {f'&nbsp;<a href="{hosted_url}" style="color:{_BRAND_TEAL};text-decoration:none;font-size:14px;padding:11px 0;display:inline-block;">View online</a>' if hosted_url and hosted_url != invoice_pdf else ''}
        </div>"""

    address_block = _format_address_html(invoice)
    line_items_table = _line_items_html(invoice)

    # Detect proration so we can add a one-line explainer for users
    # who are confused by the multiple line items on a plan switch.
    has_proration = any(
        (l.get("proration") is True)
        for l in (invoice.get("lines") or {}).get("data") or []
    )
    proration_note = ""
    if has_proration:
        proration_note = f"""
        <p style="font-size:13px;line-height:1.6;color:{_TEXT_MUTED};margin:-8px 0 16px 0;font-style:italic;">
          You changed plans mid-cycle, so this invoice includes a credit for unused time on your previous plan
          and a prorated charge for the new one.
        </p>"""

    period_str = (
        f"{_format_unix_date(period_start)} → {_format_unix_date(period_end)}"
        if period_start and period_end else ""
    )

    body = f"""
    <p style="font-size:15px;line-height:1.6;color:{_TEXT_DARK};margin:0 0 16px 0;">
      Thank you for your subscription. Your payment was received and your account is up to date.
    </p>

    {address_block}

    {line_items_table}

    {proration_note}

    <div style="font-size:12px;color:{_TEXT_MUTED};line-height:1.6;margin:0 0 8px 0;">
      <span style="color:{_TEXT_MUTED};">Invoice </span>
      <span style="color:{_TEXT_DARK};font-family:ui-monospace,monospace;">{invoice_number}</span>
      {f'<span style="margin:0 6px;color:{_BORDER};">·</span>Billing period <span style="color:{_TEXT_DARK};">{period_str}</span>' if period_str else ''}
    </div>

    {pdf_button}

    <p style="font-size:14px;line-height:1.6;color:{_TEXT_MUTED};margin:16px 0 0 0;">
      Need to update your payment method or download past invoices? <a href="{fe}/settings/billing" style="color:{_BRAND_TEAL};text-decoration:none;">Manage your billing</a>.
    </p>
    """

    subject = f"Receipt — Nano EASM {plan_label} · {_format_money(amount_cents, currency).split(' ')[0]}"
    html = shell(title="Payment received", body_html=body, footer_html=_billing_footer())
    return send_via_resend(to=to, subject=subject, html=html)


def send_payment_failed_email(org: Organization, invoice: dict) -> bool:
    """
    Send a payment-failure notification to the org's billing contact.
    Sent from the `invoice.payment_failed` webhook.
    """
    to = _recipient_for(org)
    if not to:
        logger.warning("No billing recipient for org %s; skipping payment-failed email", org.id)
        return False

    from app.billing.routes import PLAN_CONFIG
    plan_label = PLAN_CONFIG.get(org.plan, {}).get("label", org.plan)

    amount_cents = invoice.get("amount_due", 0)
    currency = invoice.get("currency") or "usd"
    next_attempt = invoice.get("next_payment_attempt")
    fe = frontend_url()

    next_attempt_line = ""
    if next_attempt:
        next_attempt_line = f"""
        <p style="font-size:14px;line-height:1.6;color:{_TEXT_DARK};margin:8px 0 0 0;">
          We&rsquo;ll retry automatically on <strong>{_format_unix_date(next_attempt)}</strong>.
          To avoid an interruption, please update your payment method now.
        </p>"""

    body = f"""
    <p style="font-size:15px;line-height:1.6;color:{_TEXT_DARK};margin:0 0 16px 0;">
      We tried to charge your card for your Nano EASM {plan_label} subscription, but the payment didn&rsquo;t go through.
    </p>

    <table cellpadding="0" cellspacing="0" border="0" style="width:100%;border:1px solid {_BORDER};border-radius:10px;margin:20px 0;background:#fff;border-collapse:separate;border-spacing:0;">
      <tr>
        <td style="padding:14px 16px;font-size:13px;color:{_TEXT_MUTED};border-bottom:1px solid {_BORDER};">Plan</td>
        <td style="padding:14px 16px;font-size:14px;color:{_TEXT_DARK};text-align:right;border-bottom:1px solid {_BORDER};">Nano EASM {plan_label}</td>
      </tr>
      <tr>
        <td style="padding:14px 16px;font-size:13px;color:{_TEXT_MUTED};">Amount due</td>
        <td style="padding:14px 16px;font-size:14px;color:{_TEXT_DARK};text-align:right;font-family:ui-monospace,monospace;">{_format_money(amount_cents, currency)}</td>
      </tr>
    </table>

    <div style="margin:24px 0;">
      <a href="{fe}/settings/billing" style="display:inline-block;background:{_BRAND_TEAL};color:#fff;text-decoration:none;padding:11px 22px;border-radius:8px;font-weight:600;font-size:14px;">Update payment method</a>
    </div>

    {next_attempt_line}

    <p style="font-size:13px;line-height:1.6;color:{_TEXT_MUTED};margin:24px 0 0 0;">
      Common reasons for failed payments: expired card, insufficient funds, or your bank flagging the charge as unusual. Updating your payment method takes a minute and resolves nearly all cases.
    </p>
    """

    subject = "Payment failed — please update your card"
    html = shell(title="Your payment didn't go through", body_html=body, footer_html=_billing_footer())
    return send_via_resend(to=to, subject=subject, html=html)


def send_refund_email(org: Organization, charge: dict) -> bool:
    """
    Send a refund-issued notification. Sent from `charge.refunded`
    webhook when a refund is created — partial or full.

    `charge` is the Stripe Charge object. We pull the most recent
    refund from `charge.refunds.data[0]` for the per-event amount,
    falling back to `amount_refunded` (cumulative) if the array is
    empty for any reason.
    """
    to = _recipient_for(org)
    if not to:
        logger.warning("No billing recipient for org %s; skipping refund email", org.id)
        return False

    currency = charge.get("currency") or "usd"

    refunds_list = (charge.get("refunds") or {}).get("data") or []
    latest_refund = refunds_list[0] if refunds_list else {}
    refund_amount = latest_refund.get("amount") or charge.get("amount_refunded") or 0
    refund_id = latest_refund.get("id") or ""
    refund_reason = (latest_refund.get("reason") or "").replace("_", " ")
    receipt_url = charge.get("receipt_url") or ""

    fe = frontend_url()

    reason_line = ""
    if refund_reason:
        reason_line = f"""
        <tr>
          <td style="padding:14px 16px;font-size:13px;color:{_TEXT_MUTED};">Reason</td>
          <td style="padding:14px 16px;font-size:14px;color:{_TEXT_DARK};text-align:right;">{refund_reason.capitalize()}</td>
        </tr>"""

    receipt_button = ""
    if receipt_url:
        receipt_button = f"""
        <div style="margin:24px 0;">
          <a href="{receipt_url}" style="display:inline-block;color:{_BRAND_TEAL};text-decoration:none;padding:11px 0;font-weight:500;font-size:14px;">View original receipt →</a>
        </div>"""

    body = f"""
    <p style="font-size:15px;line-height:1.6;color:{_TEXT_DARK};margin:0 0 16px 0;">
      We&rsquo;ve issued a refund to your original payment method. The amount should appear in your account in <strong>5–10 business days</strong>, depending on your bank.
    </p>

    <table cellpadding="0" cellspacing="0" border="0" style="width:100%;border:1px solid {_BORDER};border-radius:10px;margin:20px 0;background:#fff;border-collapse:separate;border-spacing:0;">
      <tr>
        <td style="padding:14px 16px;font-size:13px;color:{_TEXT_MUTED};border-bottom:1px solid {_BORDER};">Refund amount</td>
        <td style="padding:14px 16px;font-size:14px;color:{_TEXT_DARK};text-align:right;border-bottom:1px solid {_BORDER};font-family:ui-monospace,monospace;">{_format_money(refund_amount, currency)}</td>
      </tr>
      {reason_line}
      <tr>
        <td style="padding:14px 16px;font-size:13px;color:{_TEXT_MUTED};">Refund reference</td>
        <td style="padding:14px 16px;font-size:13px;color:{_TEXT_DARK};text-align:right;font-family:ui-monospace,monospace;">{refund_id}</td>
      </tr>
    </table>

    {receipt_button}

    <p style="font-size:13px;line-height:1.6;color:{_TEXT_MUTED};margin:16px 0 0 0;">
      If you have questions about this refund, reply to this email or contact us at
      <a href="mailto:contact@nanoasm.com" style="color:{_BRAND_TEAL};text-decoration:none;">contact@nanoasm.com</a>.
      Your billing history is available in <a href="{fe}/settings/billing" style="color:{_BRAND_TEAL};text-decoration:none;">your account</a>.
    </p>
    """

    subject = f"Refund issued — {_format_money(refund_amount, currency).split(' ')[0]}"
    html = shell(title="Refund issued", body_html=body, footer_html=_billing_footer())
    return send_via_resend(to=to, subject=subject, html=html)
