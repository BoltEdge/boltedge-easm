"""Outbound email for the agent platform.

Two flows:
  1. send_digest_email — internal-only digests to the founder (auto-send,
     no approval gate; recipient is hard-coded to the configured founder
     email so a misconfigured agent cannot exfiltrate to anyone else).
  2. send_approved_draft — sends a draft post-approval to a customer-
     facing recipient. Implemented in Plan 2.

Sender domain is the agent platform's, separate from customer-facing
billing/auth emails. Token: RESEND_TOKEN_AGENTS env var (falls back to
RESEND_API_KEY if the agents-specific key is not set).
"""
from __future__ import annotations

import os

import markdown as md


def _markdown_to_html(text: str) -> str:
    return md.markdown(text, extensions=["fenced_code", "tables"])


class FakeResendClient:
    """Test stub — captures sent messages instead of dispatching."""

    def __init__(self):
        self.sent: list[dict] = []

    def send(self, *, to: str, subject: str, html: str, from_: str) -> None:
        self.sent.append(
            {"to": to, "subject": subject, "html": html, "from": from_}
        )


class RealResendClient:
    def __init__(self, api_key: str | None = None):
        import resend

        resend.api_key = api_key or os.environ.get(
            "RESEND_TOKEN_AGENTS"
        ) or os.environ["RESEND_API_KEY"]
        self._resend = resend

    def send(self, *, to: str, subject: str, html: str, from_: str) -> None:
        self._resend.Emails.send(
            {
                "from": from_,
                "to": [to] if isinstance(to, str) else to,
                "subject": subject,
                "html": html,
            }
        )


FROM_AGENTS: str = os.environ.get(
    "AGENTS_FROM_EMAIL", "agents@nanoeasm.com"
)


def send_digest_email(
    to: str,
    subject: str,
    markdown: str,
    client: FakeResendClient | RealResendClient | None = None,
) -> None:
    """Convert *markdown* to HTML and send a digest email via Resend.

    Args:
        to: Recipient email address.
        subject: Email subject line.
        markdown: Email body as Markdown — converted to HTML before sending.
        client: Injectable email client (defaults to :class:`RealResendClient`).
                Pass a :class:`FakeResendClient` in tests.
    """
    html = _markdown_to_html(markdown)
    c = client if client is not None else RealResendClient()
    c.send(to=to, subject=subject, html=html, from_=FROM_AGENTS)
