# 09 — Service Level Agreement (SLA)

| Field | Value |
|---|---|
| Document | 09 — SLA |
| Owner | Founder / sole engineer |
| Status | Draft |
| Effective from | (per-tier; see §1) |
| Last reviewed | 2026-05-05 |
| Related docs | `02-srs.md`, `08-backup-and-dr.md`, `10-dpa.md` (forthcoming), CLAUDE.md "Plan tiers and limits" |

---

## 1. Purpose and applicability

This SLA states the service availability, performance, and support commitments Nano EASM makes to customers. Commitments are **tier-dependent** — Free tier carries no SLA; paid tiers carry progressively stronger commitments.

| Plan | SLA applicable | Effective when |
|---|---|---|
| Free | No | – |
| Starter | Best-effort (no credits) | At signup |
| Professional | Yes (target only; no credits) | At signup |
| Enterprise Silver | Yes (with service credits) | At signup |
| Enterprise Gold | Yes (with stronger credits) | At signup |
| Custom | Negotiated per contract | At contract signature |

The Custom tier overrides this document where the contract specifies otherwise.

---

## 2. Definitions

| Term | Meaning |
|---|---|
| **Service** | The Nano EASM platform at `https://nanoasm.com`, including the web app and the REST API |
| **Available** | The Service responds to `GET /api/health` with `200 OK` within 5 seconds, AND a representative authenticated request completes successfully |
| **Downtime** | Continuous period during which the Service is not Available, as measured by external uptime monitoring |
| **Excluded Downtime** | Downtime attributable to causes listed in §6 |
| **Monthly Uptime %** | `(Total minutes in month – Downtime – Excluded Downtime) / (Total minutes in month – Excluded Downtime) × 100` |
| **Service Credit** | A pro-rated refund or extension applied to the affected billing period |
| **Severity** | Classification of an incident or support request (SEV-1 to SEV-4); see §4 |
| **Business hours** | 09:00 – 17:00 AEST, Monday – Friday, excluding Australian public holidays |
| **24×7** | All hours of all days |

---

## 3. Availability commitments

### 3.1 Monthly uptime targets

| Plan | Monthly uptime target | Service credit |
|---|---|---|
| Starter | 99.0% (target only) | None |
| Professional | 99.5% (target only) | None |
| Enterprise Silver | 99.9% | Yes — see §3.2 |
| Enterprise Gold | 99.95% | Yes — see §3.2 |
| Custom | Per contract | Per contract |

Targets reflect realistic single-region, single-host posture. Numbers tighten as the platform's deployment topology evolves (SAD §04 Deployment §10 scaling steps).

### 3.2 Service credits (Silver / Gold)

| Monthly Uptime % | Silver service credit | Gold service credit |
|---|---|---|
| < 99.95% but ≥ 99.9% | – | 10% of monthly fee |
| < 99.9% but ≥ 99.5% | 10% of monthly fee | 25% of monthly fee |
| < 99.5% but ≥ 99.0% | 25% of monthly fee | 50% of monthly fee |
| < 99.0% | 50% of monthly fee | 50% of monthly fee |

Credits are:
- **Capped at 50%** of the monthly fee for the affected month.
- **Customer-claimed** — the customer must request the credit within 30 days of the affected month (we do not auto-credit; the operational overhead would create false-positive credits at small scale).
- **Pro-rated** for annual customers based on monthly equivalent.
- **Sole and exclusive remedy** for any failure to meet the uptime target. Outside this credit, we do not pay damages for downtime.

### 3.3 How uptime is measured

- External uptime monitoring (UptimeRobot or equivalent) hits `/api/health` from a fixed external probe at 1-minute intervals.
- A failure is recorded when the probe receives a non-2xx response or no response within 30 seconds.
- Downtime is recorded as the continuous span of failed probes, rounded to the nearest minute.
- Customers may use their own monitoring; if a credit-affecting discrepancy arises, we use our records as the canonical source unless the customer demonstrates a clear collection error.

### 3.4 Status page

A status page (`status.nanoasm.com`, planned) reflects current and historical incidents. Until the status page is live, incidents are communicated by email to affected customers and via the in-app announcement banner.

---

## 4. Severity classification

The team classifies incidents and support requests on the same severity scale.

| Severity | Definition | Typical examples |
|---|---|---|
| **SEV-1** | Service unavailable, or critical security / data-integrity issue | Full outage; cross-tenant data leak; payment processing broken for > 1 hour |
| **SEV-2** | Major feature unavailable; significant degradation | Discovery jobs failing; finding alerts not firing; one role's permissions broken |
| **SEV-3** | Minor feature unavailable; intermittent issue | Single endpoint slow; cosmetic but disruptive UI bug; an integration's notifications not appearing |
| **SEV-4** | Question, request, or low-priority issue | "How do I configure X?"; feature request; non-blocking visual issue |

Customers may propose a severity; we may reclassify. Reclassification is communicated with reasoning.

---

## 5. Support commitments

### 5.1 Response and resolution targets

**Response time** = first substantive human response to a ticket. **Resolution target** = work-in-progress target; no commitment to fix within the window for SEV-3 / SEV-4.

| Plan | SEV-1 response | SEV-2 response | SEV-3 response | SEV-4 response | Channel | Hours |
|---|---|---|---|---|---|---|
| Starter | 1 business day | 2 business days | 5 business days | 5 business days | Email | Business hours |
| Professional | 4 business hours | 1 business day | 2 business days | 5 business days | Email | Business hours |
| Enterprise Silver | 1 hour | 4 business hours | 1 business day | 2 business days | Email + dedicated account contact | 24×7 (SEV-1/2), business hours otherwise |
| Enterprise Gold | 30 minutes | 1 hour | 4 business hours | 1 business day | Email + dedicated account contact + Slack-shared (if configured) | 24×7 (SEV-1/2/3), business hours SEV-4 |
| Custom | Per contract | Per contract | Per contract | Per contract | Per contract | Per contract |

Free tier customers receive **community-style** support — public docs, FAQ, and best-effort response with no commitment.

### 5.2 Resolution targets

We commit to **starting** work on a SEV-1 / SEV-2 within the response window and **continuing** to work it until resolved or downgraded. We do not commit to a fixed resolution wall-clock — some root causes (third-party outage, complex data issue) take time. The commitment is **diligent, continuous effort with regular updates**.

Update cadence during in-progress incidents:

| Severity | Update cadence |
|---|---|
| SEV-1 | Every 30 minutes |
| SEV-2 | Every 2 hours |
| SEV-3 | Daily |
| SEV-4 | At resolution |

### 5.3 Channels

- Primary: `support@nanoasm.com` (planned; today `contact@nanoasm.com`).
- Enterprise customers: dedicated account-team contact at signup.
- Security: `security@nanoasm.com` (planned) — see `05-security-policy.md` §10.

---

## 6. Excluded downtime

Time is **not** counted against the uptime target when downtime is caused by:

1. **Scheduled maintenance** — communicated ≥ 48 hours in advance, capped at 1 hour per month, scheduled outside business hours where possible.
2. **Force majeure** — natural disaster, pandemic, war, government action, internet-backbone outage.
3. **Third-party provider outage** affecting Nano EASM where we have no commercially reasonable mitigation — AWS regional outage, Stripe outage, Let's Encrypt CA outage, public DNS outage. We document the outage with a reference to the third-party's incident report.
4. **Customer-caused issues** — customer's own network, browser, account misconfiguration, or DNS pointing away from our service.
5. **Customer's misuse** — exceeding documented rate limits, abuse triggering rate-limit / block.
6. **Beta or labelled-experimental features** — features explicitly marked as beta carry no SLA.

The list of excluded events for any given month is published with the monthly uptime report on request.

---

## 7. Performance targets (informational, not credit-bearing)

These are operating targets, not commitments. We monitor and aim to keep:

| Metric | Target |
|---|---|
| API response p50 (read endpoints) | < 200 ms |
| API response p95 (read endpoints) | < 1 s |
| API response p95 (write endpoints) | < 2 s |
| Scan kickoff (HTTP 202 returned) | < 500 ms |
| Quick scan completion | < 30 s typical |
| Standard scan completion | < 5 min typical |
| Deep scan completion | < 30 min typical |
| Discovery job completion | < 5 min typical for a single root domain |
| Email send latency (verification, reset) | < 60 s end-to-end typical |

These targets are not enforced by service credit. They are stated so customers know what to expect and can flag deviation.

---

## 8. Maintenance

- **Routine deploys** are performed without prior notice. They cause a brief blip (5–15 s) and are not counted toward downtime if the blip is < 30 s.
- **Scheduled maintenance** with anticipated downtime > 30 s is announced ≥ 48 hours in advance via email and the in-app banner.
- **Emergency maintenance** for security or stability may bypass the notice period; we communicate as soon as practicable.

---

## 9. Customer obligations

For the SLA to apply, the customer must:

- Be on a paid tier in good standing (not suspended for non-payment, abuse, or ToS violation).
- Configure the service correctly (correct DNS resolution, correctly attributed root domains for discovery / scanning).
- Use supported browsers and SDKs (current major versions).
- Not exceed documented limits (`/api` rate limits, plan limits).
- Cooperate with reasonable requests during incident triage (provide reproduction steps, logs, timestamps).
- Submit credit claims within 30 days of the affected month, in writing, to the support channel.

Failure to meet these obligations may forfeit the SLA for the affected period.

---

## 10. What is not covered

The following are explicitly **out of scope** of this SLA:

- **Accuracy or completeness of scan results.** Discovery and scanning are best-effort; we do not warrant that all assets or findings will be detected. Coverage gaps in third-party data sources (Shodan, CT logs, public DNS) are not a service defect.
- **Findings interpretation.** A finding flagged by Nano EASM is informational; the customer's own analysis remains authoritative. False positives and false negatives are inherent to security scanning; we work to reduce them but do not commit to zero.
- **Compliance certification of customer's own systems.** The customer's compliance posture is theirs; our compliance-mapping reports are evidence input, not audit certification.
- **Third-party integrations' availability.** Slack, Jira, Stripe, Resend availability is each provider's commitment, not ours.
- **Customer's ability to respond to alerts** — we deliver them; what the customer does with them is their operational responsibility.

---

## 11. Service-credit claim process

To claim a service credit (Silver / Gold / Custom):

1. Email `support@nanoasm.com` within **30 days** of the end of the affected calendar month.
2. Include: the affected month, the customer's monitoring data showing the downtime (optional but accelerates), the credit amount being claimed.
3. We respond within 10 business days with: confirmed credit amount, or a substantiated rebuttal with our records.
4. Credits are applied to the next invoice, or as a refund for annually pre-paid customers.

Credits are applied to fees only — not taxes, not third-party costs, not professional services charges.

---

## 12. Data-loss commitment

Per `08-backup-and-dr.md`:

- **RPO**: 24 hours (we keep daily backups; in the worst case a customer loses up to 24 hours of activity).
- **RTO**: 4 hours for SEV-1 outages.

**These are operational targets, not contractual commitments.** They are provided here so customers know our recovery posture. The contractual commitment is the uptime SLA above; the data-loss bound is a customer-facing **expectation**, and the only contractual remedy for a data-loss incident is what general law / the DPA / the contract provides — not a service credit per minute of lost data.

---

## 13. Security incidents

Security incidents are handled per `05-security-policy.md` §10. The SLA addresses **availability**, not security. A security incident may also affect availability, in which case both apply.

For security incidents involving customer data, we commit to:

- Notify affected customers within **72 hours** of confirmation.
- Provide initial scope and remediation status.
- Follow up with full root-cause and remediation report within 30 days.

This is the customer-facing notification commitment; the regulatory clock under GDPR / state breach laws may be tighter for the customer themselves.

---

## 14. Modifications and review

- We may amend this SLA on **60 days written notice** to existing customers.
- Amendments that **materially reduce** commitments give the affected customer a 30-day window to terminate without penalty.
- The SLA in effect at the start of a billing period applies to that period.

---

## 15. References

- `02-srs.md` §5 (Non-Functional Requirements) — internal reliability requirements
- `08-backup-and-dr.md` §2 — RPO / RTO
- `05-security-policy.md` §10 — incident response
- `10-dpa.md` (forthcoming) — data-processing terms
- CLAUDE.md "Plan tiers and limits" — the plan structure this SLA tiers off

---

*End of 09 SLA.*
