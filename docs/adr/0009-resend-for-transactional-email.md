# ADR 0009 — Resend for Transactional Email

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-05-05 |
| Deciders | Founder / sole engineer |
| Supersedes | – |
| Superseded by | – |

## Context

Nano EASM sends transactional email for:
- Email verification at signup.
- Password reset.
- MFA enrolment (planned).
- Trial-approved / trial-expiring / plan-changed.
- Free-tier expiry warnings (day 80, 87, 113, 117).
- Finding alerts (when configured by the customer).
- Stripe receipt / payment failure / refund (we send these from `nanoasm.com` rather than Stripe defaults, so the from-address is consistent).

Throughput is low (hundreds per day at current scale). Reliability and deliverability are critical — verification and password-reset are direct user paths.

We need:
- A simple Python SDK or HTTP API.
- Domain-authentication (SPF, DKIM, DMARC) on `nanoasm.com`.
- Reasonable inbox-placement reputation.
- Affordable at low volume.

## Decision

We use **Resend** as the transactional email provider.

- API key in env var `RESEND_API_KEY`.
- All sending goes through `app/billing/emails.py`.
- Domain is configured in Resend with DKIM keys; SPF and DMARC records on `nanoasm.com` are aligned.
- We do not use Resend templates — bodies are built in Python (Jinja2) so they live in the repo.

## Considered alternatives

| Alternative | Why rejected |
|---|---|
| **AWS SES** | Cheapest, but the operational onboarding is heavier (sandbox approval, bounce/complaint topic wiring, IAM). Worth it if we were already sending millions of emails; not worth it for hundreds. |
| **Postmark** | Excellent reputation and tooling. Slightly more expensive than Resend at our volume. Tied for second; Resend won on developer ergonomics. |
| **SendGrid** | Established. Heavy account / template UX. Recent reputation issues with deliverability. Not worth the trade. |
| **Mailgun** | Established. Mid-tier on dev ergonomics. Pricing tier mismatched with our volume. |
| **Self-hosted Postfix on EC2** | Deliverability is a full-time job. We do not have the scale to justify owning it; the inbox-placement risk is large. |

## Consequences

**Positive:**
- **Developer-friendly API** — a few lines per email, no template upload dance.
- **Domain authentication is straightforward** — Resend gives the DNS records, we add them to Route 53, done.
- **Affordable.** Free tier covers most of our development volume; first paid tier is $20/mo and easily covers production at current scale.
- **Templates live in the repo** — code review captures email body changes alongside the code that triggers them. Translations / branding tweaks are PRs, not console clicks.

**Negative:**
- **Vendor risk.** Resend is a young company. Outage = email send fails (queued for retry).
- **Less mature analytics** than SendGrid / Postmark. Open-rate and click-tracking are present but light. We don't currently rely on them.
- **No built-in suppression-list management** beyond the API; we have to track unsubscribe / bounce state in our own DB if we send marketing email later. (Today we send transactional only.)

## Implementation notes

- **Pre-fetch resistance:** every email link points to a landing page that requires a user click before POSTing the token. This protects against email security scanners (Microsoft Safe Links, Mimecast, Proofpoint, Gmail safe-browsing) that pre-fetch URLs and consume single-use tokens. This is a code-level discipline, not a Resend feature; documented in §06 Security §14.
- **Send model:** synchronous in the request handler with a 10s timeout. On failure, the email is enqueued in `outbound_email` for retry by a daily job. The user's action is **not** rolled back. (§07 Integrations §3.3)
- **Receipts and refunds** go through Resend, **not** Stripe's default mailer. This keeps the from-address at `nanoasm.com` for every customer-facing email. (§07 Integrations §3.5)

## References

- ADR 0010 — Stripe (corollary: Stripe events trigger Resend sends, not Stripe-default emails)
- §07 Integrations §3 — Resend integration detail
- §06 Security §14 — anti-pre-fetch design

---
