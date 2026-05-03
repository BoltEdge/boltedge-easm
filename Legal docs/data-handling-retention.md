# Data Handling & Retention Policy

**Effective date:** 1 May 2026
**Last updated:** 1 May 2026

This document explains **where** we store data, **how long** we keep
it, **how** we protect it, and **what happens** when it needs to be
deleted. It is the operational companion to the [Privacy
Policy](./privacy-policy.md) and is incorporated into the [Terms of
Use](./terms-of-use.md). For Customer Data, the obligations in this
document are reflected in our standard Data Processing Agreement
(DPA) — see §13.

Capitalised terms have the meanings given in the Terms of Use.

---

## 1. Scope

This policy covers all personal data and Customer Data processed by
us in connection with the Service, including:

- account and organisation records,
- assets, scan results, findings, and monitor configurations
  ("Customer Data"),
- audit logs and security logs,
- billing records,
- quick-scan submissions from the unauthenticated tools,
- emails we send and their delivery metadata,
- backups and disaster-recovery snapshots.

It does **not** cover data held by third parties under their own
terms — for example, copies of receipts in your email client, or
data you exported from the Service to your own systems.

## 2. Data classification

We classify data into four categories. Each category has its own
retention rules, access rules, and deletion processes.

| Category | Examples | Sensitivity |
|----------|----------|-------------|
| **Account data** | Email, name, password hash, OAuth IDs, organisation membership | High |
| **Customer Data** | Assets, scan results, findings, monitor rules, integrations | Medium–High (varies by content) |
| **Operational data** | Audit logs, IP addresses, request logs, quick-scan logs | Medium |
| **Financial data** | Stripe customer/subscription IDs, invoices, billing events | High |

## 3. Where data is hosted

Although Nano EASM operates from Australia, the primary application
and database are hosted on **Amazon Web Services (AWS)** in the
**us-east-1 (United States — N. Virginia)** region. Hosting outside
Australia is a deliberate technical choice driven by sub-processor
availability and global low-latency for international customers; it
means personal data submitted to the Service is transferred outside
Australia, as described in §11 and in the [Privacy Policy](./privacy-policy.md) §7.

Specific data flows leave that region only as follows:

- **Stripe** processes payment events on its global infrastructure
  (US-headquartered, with EU/UK transfer mechanisms in place). We
  retain only metadata; card data never reaches our servers.
- **Resend** delivers transactional email from US infrastructure.
  Recipient address, subject, and HTML body are processed in
  transit and retained according to Resend's policies.
- **Google / Microsoft (OAuth)** authenticate users via their
  respective US-based identity services when OAuth sign-in is used.
- **Shodan** receives target identifiers (IP, domain) for asset
  intelligence enrichment and processes them on its US
  infrastructure.

The full sub-processor list is in the [Privacy Policy](./privacy-policy.md)
§6.1. International transfers are governed by the safeguards in §7
of that policy.

## 4. Retention periods

The following retention periods apply unless extended by legal
obligation (e.g. a court order or tax-record requirement) or
shortened by you exercising a deletion right.

| Data | Retention |
|------|-----------|
| Account record (User row) | Lifetime of the Account + 30 days after deletion request |
| Organisation record | Lifetime of the Organisation; on deletion, all linked records cascade-delete (assets, scans, findings, members, API keys, audit log rows for that organisation) |
| Customer Data (assets, scan results, findings, monitor configs) | Lifetime of the Organisation; deleted with the Organisation |
| Audit logs (in-app actions) | **12 months** rolling, then aggregated or deleted |
| Web request logs (server-level) | **30 days** rolling |
| Quick-scan logs (unauthenticated submissions) | **90 days** rolling for the abuse-tracking detail; aggregate counts retained indefinitely |
| Blocked IP list | Until manually removed by an administrator |
| Email content + delivery metadata | **30 days** with Resend (their default), then aggregated to delivery counters |
| Stripe webhook event log | **24 months** (kept for forensic analysis of billing disputes) |
| Billing events (subscription created, payment succeeded, refund issued, etc.) | **7 years** for tax and accounting compliance |
| Stripe customer + subscription record (held by Stripe) | Subject to Stripe's retention; we retain references for as long as needed for billing records |
| Database backups | **30 days** rolling, then overwritten on rotation |
| Disaster-recovery snapshots | Up to **90 days** depending on snapshot tier |

We may extend retention beyond these periods where:

- required by applicable law,
- needed to defend ourselves against an actual or threatened legal
  claim,
- required to investigate a security incident or abuse case.

In such cases, the data is preserved only for the specific purpose
and is deleted once that purpose ends.

## 5. Deletion processes

### 5.1 You delete your account or organisation

**Organisation deletion.** Owners can delete an Organisation from
Settings → Billing → Danger Zone. The deletion:

- removes the Organisation row and all rows that cascade from it
  (assets, scans, findings, monitors, schedules, API keys, audit
  log rows for the Org, billing events, members),
- happens immediately in the live database,
- is **propagated to backups within 30 days** (the rolling backup
  window), after which the data is no longer recoverable from
  backup,
- does not delete the User account itself if the User belongs to
  other Organisations.

**Account deletion.** A User who is not a member of any
Organisation can request account deletion via
**contact@nanoasm.com**. The deletion follows the same backup
window as Organisation deletion.

**Customer-Portal-driven cancellation** (cancelling a paid
subscription) does **not** delete data — it only cancels billing.
Use Organisation deletion to remove data.

### 5.2 You exercise a right to erasure (GDPR Article 17)

If you exercise a right to erasure under UK or EU data protection
law:

- We delete personal data that we can lawfully delete within **30
  days** of receiving a verified request.
- We retain data we are legally required to retain (e.g. invoices
  for tax records) and explain why in our response.
- We delete data from production immediately and from backups
  within the **30-day rolling backup window**.

Requests are submitted to **contact@nanoasm.com** as set out in the
[Privacy Policy](./privacy-policy.md) §9.

### 5.3 Automatic deletion (no request needed)

The following deletions happen automatically without you taking
action:

- Quick-scan log entries older than 90 days are purged daily.
- Audit log entries older than 12 months are purged or aggregated.
- Web request logs older than 30 days are rotated out.
- Stripe webhook event payloads older than 24 months are purged
  daily.
- Backups older than 30 days are overwritten on rotation.

## 6. Backups

We take regular backups of the application database to protect
against data loss. Backups are:

- **encrypted at rest** with AWS-managed keys,
- stored in the same AWS region as the primary database (with
  cross-region replication where the snapshot tier supports it),
- retained on a **30-day rolling window**, after which they are
  overwritten,
- restored from only when needed for disaster recovery.

When you delete data, that data is removed from the live database
immediately and **purged from backups within the 30-day rolling
window** as backups roll over. We do not perform on-demand purges
of historical backups, because doing so would compromise the
backup's integrity for disaster recovery — which is the same
trade-off that GDPR Article 17 explicitly permits ("disproportionate
effort" carve-out for backups).

If you have a compliance requirement for immediate purge from
backups, contact us at **contact@nanoasm.com** and we will discuss
options under a custom contract.

## 7. Encryption

- **In transit.** All connections to the Service are protected with
  **TLS 1.2 or above**. HTTP traffic is redirected to HTTPS. API
  endpoints reject non-TLS connections.
- **At rest.** The application database and backups are encrypted
  using AWS-managed encryption (AES-256 or equivalent).
- **Passwords.** User passwords are stored using a one-way
  cryptographic hash (currently bcrypt or equivalent) with per-user
  salt. We never store, log, or transmit plaintext passwords.
- **Secrets.** API keys and OAuth tokens we issue are stored as
  hashes where possible. Third-party API keys (e.g. for Slack
  webhooks, Jira) are stored encrypted at rest.
- **Card data.** We never receive, process, or store card data —
  Stripe handles it directly.

## 8. Access controls

- **Customer-side.** Access within an Organisation is governed by
  role-based access control (Owner / Admin / Analyst / Viewer).
  Users only see data within their Organisation.
- **Internal staff.** Access to production systems is restricted to
  named operations personnel on a least-privilege basis. Privileged
  actions (e.g. impersonation by a superadmin) are audit-logged.
- **Multi-factor authentication** is required for staff with
  production access.

## 9. Personnel

All staff with access to personal data:

- are bound by confidentiality obligations in their employment or
  contractor agreements,
- receive training on data protection and security expectations,
- have access revoked promptly on departure or change of role.

## 10. Sub-processors

The full list of sub-processors is in the [Privacy
Policy](./privacy-policy.md) §6.1. We:

- enter into data-protection agreements with sub-processors where
  required (e.g. Standard Contractual Clauses for international
  transfers),
- assess each sub-processor's security posture before engagement,
- maintain the right to terminate or replace a sub-processor that
  fails to meet our standards.

We will give you reasonable notice before adding or replacing a
sub-processor that handles Customer Data of customers on paid plans.

## 11. International transfers

Cross-border transfers of personal data are governed by the [Privacy
Policy](./privacy-policy.md) §7. We rely on transfer mechanisms
including Standard Contractual Clauses and the UK International
Data Transfer Addendum where applicable.

## 12. Security incident response

If we become aware of an actual or suspected breach of security
that affects your personal data or Customer Data, we will:

1. **Investigate** the scope and severity promptly.
2. **Contain** the incident and remediate the underlying cause.
3. **Notify** affected customers without undue delay where the
   breach is likely to result in serious harm or risk. Specifically:
   - Under the Australian **Notifiable Data Breaches (NDB) scheme**
     (Privacy Act 1988 Part IIIC), where there is a likely risk of
     **serious harm**, we notify affected individuals and the OAIC
     as soon as practicable.
   - Where UK or EU GDPR applies, we notify the relevant supervisory
     authority within **72 hours** of becoming aware.
4. **Notify** the relevant supervisory authority where required by
   law.
5. **Document** the incident for our records and for the customer's
   own breach-notification obligations.

Customers can report a suspected security incident to
**contact@nanoasm.com**. For vulnerability reports against the
Service itself, see the [Acceptable Use Policy](./acceptable-use-policy.md)
§6.

## 13. Data Processing Agreement (DPA)

Where we act as your processor for Customer Data — typically the
case for paid subscriptions — we will enter into a Data Processing
Agreement (DPA) with you on request.

Our standard DPA covers:

- subject matter, duration, and purpose of processing,
- categories of personal data and data subjects,
- confidentiality obligations,
- security measures (including the measures in this document),
- sub-processor handling and notice obligations,
- assistance with data-subject rights and breach notification,
- audit rights and certifications,
- international transfer mechanisms,
- termination and return/deletion of data.

To request a DPA, email **contact@nanoasm.com**.

## 14. Customer responsibilities

You are responsible for:

- ensuring you have a **lawful basis** to submit the personal data
  (including third-party PII) you put into the Service as Customer
  Data,
- communicating to your own data subjects that the data is being
  processed by Nano EASM as a sub-processor where relevant,
- managing access within your Organisation (granting and revoking
  team-member access promptly),
- exporting any Customer Data you wish to retain **before** you
  delete an Organisation — once deleted, recovery from backup is
  not possible after the 30-day backup window expires,
- providing accurate billing-address and tax-ID information so that
  invoicing and tax reporting are correct,
- following our [Acceptable Use Policy](./acceptable-use-policy.md)
  and [Security & Scanning Authorisation](./security-scanning-authorisation.md).

## 15. Changes to this policy

We may update this policy from time to time. Material changes —
including changes that materially affect retention periods or
sub-processors — will be communicated via the Service or by email
to account holders.

## 16. Contact

For questions about this policy, data subject rights, DPA requests,
or security incidents:

- Email: **contact@nanoasm.com**
- Web: https://nanoasm.com/#contact
