# Privacy Policy

**Effective date:** 1 May 2026
**Last updated:** 1 May 2026

---

## 1. Who we are

Nano EASM (**"we"**, **"us"**, **"our"**) operates the Service at
https://nanoasm.com — an External Attack Surface Management platform
that helps organisations discover, scan, monitor, and remediate
internet-facing assets.

For the personal data covered by this policy, **we are the data
controller** (or, under the **Australian Privacy Act 1988**, the
**APP entity**) unless stated otherwise.

- Operator: **Nano EASM** — based in Australia
- Contact for privacy matters: **contact@nanoasm.com**

We comply with the **Australian Privacy Principles (APPs)** under the
Privacy Act 1988 (Cth). For users in the United Kingdom or European
Economic Area, we also comply with the UK GDPR / EU GDPR. For
California residents, we observe the rights described in §9.

If we have appointed an Article 27 GDPR / UK GDPR representative,
their details will be made available on request from the contact above.

## 2. Scope of this policy

This Privacy Policy explains how we handle:

- **Personal data of account holders** (people who sign up to use the
  Service), where we are the data controller.
- **Personal data of Authorised Users** within an organisation
  (invited team members), where we are the data controller for the
  account itself but the organisation owner controls organisation-level
  decisions.
- **Visitors to nanoasm.com** and users of the unauthenticated
  quick-scan tools.

It does **not** describe how organisations using the Service handle
personal data they choose to submit as Customer Data (assets, scan
results, findings). For that data, the **organisation is the
controller** and we act as their **processor** under the Terms of Use.
If you are a data subject of an organisation's scan results and want
to exercise rights over that data, contact the organisation directly.

## 3. The information we collect

### 3.1 Information you provide directly

When you create an account or use the Service, you may give us:

- **Account information** — name, email address, password (stored as a
  cryptographic hash, never in plaintext), country, optional job title
  and company.
- **Organisation information** — organisation name, slug, industry,
  size, website, country.
- **Communications** — messages you send via the contact form,
  support emails, or in-product feedback (including subject, body,
  and any attachments).
- **Customer Data** — domains, subdomains, IP addresses, email
  addresses, cloud asset URLs, asset groups, scan profiles, scan
  schedules, monitoring rules, and integration configurations that
  you submit to the Service.
- **Billing information** — for paid plans, your billing email and
  any billing address collected during checkout. **Card data is
  collected and stored by our payment processor (Stripe) — we never
  see, store, or process your card number directly.** We retain
  metadata such as your Stripe customer ID, subscription status,
  invoice history references, and the last four digits of the
  payment-method brand for display purposes.

### 3.2 Information collected automatically

When you use the Service, we automatically collect:

- **Log data** — IP address, user agent, request paths, timestamps,
  HTTP status codes, and (for authenticated requests) the user and
  organisation involved. Used for security monitoring, abuse
  prevention, and debugging.
- **Audit log entries** — actions you perform inside the Service
  (e.g. scan started, asset added, plan changed) tied to your user
  ID, organisation ID, and source IP address.
- **Quick-scan submissions** — for users of the unauthenticated
  quick-scan tools, we log your IP address, user agent, the target
  you submitted, the request status (completed / blocked /
  rate-limited), and timing data. This is used for abuse prevention
  (rate limiting, IP blocking) and capacity planning.
- **Email delivery metadata** — when we send transactional email
  (verification, password reset, billing receipts, monitoring
  alerts), our email provider records delivery, bounce, and open
  status.

We do **not** use third-party analytics trackers, advertising
pixels, fingerprinting libraries, or behavioural tracking.

### 3.3 Information from third parties

If you sign in with Google or Microsoft (OAuth), we receive your
email address, name, and (where available) avatar URL from the
identity provider. We do not receive your password.

We do not buy, rent, or scrape personal data from data brokers.

### 3.4 Customer Data and third-party personal data

The Service performs reconnaissance and security scanning against
internet-facing assets that you authorise. Scan results and
discovered assets may include personal data of third parties (for
example, email addresses found in WHOIS records, on websites, or in
breach corpora that public scanners reference).

For this category of personal data:

- **You** (the organisation submitting the scan) are the data
  controller and are responsible for ensuring you have a lawful basis
  to process it.
- **We** are the data processor, processing it on your instructions
  to provide the Service.
- A Data Processing Agreement (DPA) governs this relationship for
  customers on paid plans. Contact us to request one.

## 4. How we use information

We use the personal data described above to:

- **Provide the Service** — authenticate you, run scans you initiate,
  store your assets and findings, deliver alerts, send transactional
  email, and provide customer support.
- **Bill paid plans** — manage subscriptions via Stripe, send
  receipts, and recover failed payments.
- **Secure the Service** — detect and prevent abuse, fraud, and
  unauthorised use; investigate security incidents.
- **Improve the Service** — diagnose bugs, analyse aggregate usage
  patterns, and develop new features. We do not use Customer Data
  to train models or improve features that benefit other customers.
- **Comply with legal obligations** — respond to lawful requests
  from public authorities, comply with tax and accounting
  requirements, and enforce our Terms of Use.

## 5. Legal bases for processing

We process personal data under one or more of the following bases,
depending on which jurisdiction's law applies to you:

- **Performance of a contract** — to provide the Service to you under
  the Terms of Use, including running scans, sending transactional
  email, and managing your subscription.
- **Legitimate interests / reasonable use** — to keep the Service
  secure (abuse prevention, fraud detection, audit logging), to
  communicate with you about your account, and to improve the
  Service. We have weighed these interests against your rights and
  freedoms.
- **Legal obligation** — to comply with laws that require us to
  retain or disclose data (e.g. tax, accounting, court orders, or
  notifiable data-breach reporting under the Privacy Act 1988).
- **Consent** — where we ask for it explicitly, for example for
  certain optional communications. You can withdraw consent at any
  time without affecting prior processing.

If you are in Australia, our processing is also conducted in
accordance with the **Australian Privacy Principles (APPs)** in
Schedule 1 of the Privacy Act 1988 (Cth). If you are in the UK or
EU, the four legal bases above map to the lawful-processing grounds
under Article 6 of the UK / EU GDPR.

## 6. Who we share information with

We share personal data only with the parties listed below, and only
to the extent necessary for the listed purpose. We do **not** sell
personal data, share it for cross-context behavioural advertising,
or rent it to third parties.

### 6.1 Sub-processors

We rely on the following providers to operate the Service:

| Provider | Purpose | Data categories | Region |
|----------|---------|-----------------|--------|
| Amazon Web Services (AWS) | Application + database hosting | All Service data | US (us-east-1) |
| Stripe, Inc. | Payments, subscription management, customer portal | Billing email, billing address (where collected), payment-method metadata, transaction history | US (with EU/UK transfer mechanisms) |
| Resend | Transactional email delivery (verification, password reset, billing receipts, monitoring alerts) | Recipient email, message content, delivery metadata | US |
| Google LLC | OAuth sign-in (when used) | Name, email, avatar URL | US |
| Microsoft Corporation | OAuth sign-in (when used) | Name, email, avatar URL | US |
| Shodan | Asset intelligence + scanning | Target IP/domain, scan parameters | US |

We require each sub-processor to provide appropriate safeguards for
the data they process and we have data-protection agreements in place
where required.

### 6.2 Legal disclosures

We may disclose personal data when required by law, court order, or
binding government request, or where necessary to protect our rights,
your rights, or public safety. Where legally permitted, we will
attempt to notify the affected user before disclosure.

### 6.3 Business transfers

If we are acquired or merge with another company, personal data may
be transferred to the successor entity, subject to the protections
of this policy. We will notify you of any such transfer.

## 7. International data transfers

Although Nano EASM is based in Australia, our application and
database are hosted on Amazon Web Services in the **United States
(us-east-1)** region, and several of our sub-processors are also
located in the US. This means personal data submitted to the
Service is transferred outside Australia for storage and
processing.

We rely on appropriate safeguards for these transfers, which may
include:

- For data subject to **Australian Privacy Principle 8**, taking
  reasonable steps to ensure overseas recipients handle data
  consistently with the APPs.
- For UK / EU data subjects, **Standard Contractual Clauses
  (SCCs)** and the **UK International Data Transfer Addendum**,
  with supplementary technical and organisational measures.
- Adequacy decisions where applicable (e.g. EU–US Data Privacy
  Framework, UK–US Data Bridge).

By using the Service, you acknowledge and consent to the transfer
of your personal data to the United States and the other
sub-processor jurisdictions listed in §6.1.

A copy of the safeguards we rely on for any specific transfer is
available on request from **contact@nanoasm.com**.

## 8. How long we keep data

We keep personal data for as long as it is needed for the purposes
described in this policy. Specific retention rules are set out in
[Data Handling & Retention](./data-handling-retention.md). At a high
level:

- **Account data** — retained while your account is active and for a
  reasonable wind-down period after deletion.
- **Customer Data** (assets, scans, findings) — retained for the
  lifetime of your organisation; deleted on organisation deletion
  with database cascade.
- **Audit logs and security logs** — retained for a defined window
  (typically 12 months) for security and compliance.
- **Quick-scan logs** — retained for abuse prevention.
- **Billing records** — retained as required by tax and accounting
  law (typically 6–7 years depending on jurisdiction).
- **Backups** — retained on a rolling schedule and overwritten on
  rotation.

When data is no longer needed, we delete or anonymise it.

## 9. Your rights

You have the following rights in relation to your personal data,
exercisable free of charge:

- **Access** — request a copy of the personal data we hold about you.
- **Correction** (or rectification) — ask us to correct inaccurate
  or out-of-date data.
- **Deletion** (or erasure / "right to be forgotten") — ask us to
  delete your data, subject to legal retention obligations.
- **Restriction** — ask us to restrict processing in certain
  circumstances.
- **Portability** — receive a machine-readable export of data you
  provided to us.
- **Object** — object to processing based on legitimate interests.
- **Withdraw consent** — where we rely on your consent, you can
  withdraw it at any time without affecting prior processing.

The exact name and scope of these rights depends on the law that
applies to you:

- **Australia.** Under the Privacy Act 1988 (Cth) and the
  Australian Privacy Principles, you can access, correct, and
  complain about the handling of your personal data. If you are
  unsatisfied with our response to a complaint, you may lodge a
  complaint with the [Office of the Australian Information
  Commissioner (OAIC)](https://www.oaic.gov.au/).
- **United Kingdom / European Economic Area.** Under UK GDPR / EU
  GDPR, you can lodge a complaint with the [UK Information
  Commissioner's Office (ICO)](https://ico.org.uk/) or your
  country's supervisory authority.
- **California (US).** Under the California Consumer Privacy Act
  (CCPA) and California Privacy Rights Act (CPRA), you have the
  right to know, delete, correct, and limit use of sensitive
  personal information. We do not sell or share personal
  information for cross-context behavioural advertising.

To exercise any of these rights, email **contact@nanoasm.com**. We
may need to verify your identity before fulfilling the request and
will respond within the timeframe required by applicable law
(generally 30 days under the Privacy Act 1988, one month under
UK / EU GDPR, 45 days under CCPA).

If you are a data subject of an organisation's scan results, please
contact that organisation directly — they are the controller of that
data.

## 10. Children's privacy

The Service is not directed at children. We do not knowingly collect
personal data from anyone under 18. If you believe we have collected
data from a minor, contact us at **contact@nanoasm.com** and we will
delete it.

## 11. Security

We use industry-standard technical and organisational measures to
protect personal data, including:

- TLS for all data in transit.
- Encryption for sensitive data at rest.
- Hashed (never plaintext) password storage.
- Role-based access control and least-privilege principles for
  internal access.
- Audit logging of administrative actions.
- Regular dependency updates and security patches.

No system is perfectly secure. If you discover a security
vulnerability in the Service, please report it responsibly via
**contact@nanoasm.com** — we appreciate coordinated disclosure.

## 12. Cookies and similar technologies

We use a small number of cookies and browser-storage items, all of
them strictly necessary for the Service to function. We do **not**
use analytics, advertising, or behavioural-tracking cookies.

| Type | Purpose | Duration |
|------|---------|----------|
| Session cookie | Authenticated session for logged-in users (HttpOnly, Secure, SameSite=Lax) | Until logout or session expiry |
| `ag_permissions` (localStorage) | Cached role-based permissions for fast UI rendering | Until logout or change |
| `asm_dismissed_announcements` (localStorage) | Tracks which platform announcements you dismissed | Until cleared |
| `asm_impersonate_return` / `asm_impersonating` (localStorage) | Used only by superadmins during user impersonation flows | Cleared on exit |

Because all cookies/storage we use are strictly necessary, we do not
display a cookie banner. If we add non-essential cookies in future
(e.g. analytics), we will update this policy and provide a consent
mechanism where required.

## 13. Changes to this policy

We may update this policy from time to time. Material changes will
be notified via the Service or by email to account holders, with
reasonable notice before the effective date. The "Last updated" date
at the top reflects the most recent revision.

## 14. Contact

For privacy questions, data subject requests, or to request a copy
of safeguards for international transfers:

- Email: **contact@nanoasm.com**
- Web: https://nanoasm.com/#contact
