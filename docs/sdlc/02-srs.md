# Nano EASM — Software Requirements Specification

## Document Control

| Field | Value |
|---|---|
| Document ID | SDLC-02 |
| Title | Nano EASM — Software Requirements Specification (SRS) |
| Version | 0.1 (Draft) |
| Status | Draft — pending sign-off |
| Owner | [TBD — founder name] |
| Author | [TBD — founder name] |
| Created | 2026-05-05 |
| Last reviewed | 2026-05-05 |
| Next review | +90 days |
| Supersedes | — |
| Related documents | 01 Vision & Charter, 03 SAD, 04 Threat Model, 05 Security Policy, 06 Test Strategy, 09 SLA, 10 DPA |

---

## 1. Introduction

### 1.1 Purpose

This Software Requirements Specification (SRS) defines the functional and non-functional requirements for **Nano EASM** — an External Attack Surface Management SaaS platform. It is the authoritative reference for what the system **shall do** and the constraints it **shall operate within**. It binds engineering, QA, support, and security work to a single shared definition of the product.

This document is read by:

- **Engineers** — to know what to build and what acceptance criteria define "done"
- **QA / UAT participants** — to derive test cases (the Test Strategy, doc 06, references SRS IDs directly)
- **Security reviewers / auditors** — to confirm the system implements the security capabilities it claims
- **Customers and prospects** under NDA — to evaluate functional fit
- **The author** — to keep their own thinking honest as the system evolves

### 1.2 Scope

The SRS covers the entire production Nano EASM system — multi-tenant SaaS, web application, public marketing site, public Quick Scan tool, hosted backend API, background job processing, scheduled jobs, payment processing integration, and the hidden superadmin console.

Out-of-scope items from the charter §5.2 are also out-of-scope here: authenticated/credentialed scanning, internal asset discovery, EDR functionality, mobile apps, customer-managed self-hosted deployments, threat intelligence publication.

The SRS does **not** specify implementation choices (programming languages, frameworks, deployment topology, library selection); those live in the Software Architecture Document (doc 03). Where a requirement implies a particular technology (e.g. "a webhook delivery shall use HTTPS"), that is a behavioural constraint, not an implementation directive.

### 1.3 Definitions, Acronyms, Abbreviations

The glossary in the Vision & Charter (§16) is authoritative. Module SRS files may extend it with module-specific terms; conflicting definitions are not permitted.

### 1.4 References

| Ref | Document | Where it lives |
|---|---|---|
| R-01 | Vision & Charter | `docs/sdlc/01-vision-and-charter.md` |
| R-02 | Software Architecture Document | `docs/sdlc/03-sad.md` (forthcoming) |
| R-03 | Threat Model | `docs/sdlc/04-threat-model.md` (forthcoming) |
| R-04 | Security Policy | `docs/sdlc/05-security-policy.md` (forthcoming) |
| R-05 | OWASP Application Security Verification Standard 4.0 | https://owasp.org/www-project-application-security-verification-standard/ |
| R-06 | CIS Controls v8 | https://www.cisecurity.org/controls/ |
| R-07 | NIST Cybersecurity Framework v2.0 | https://www.nist.gov/cyberframework |
| R-08 | PCI-DSS v4.0 | https://www.pcisecuritystandards.org/ |
| R-09 | Australian Privacy Act 1988 | https://www.oaic.gov.au/privacy/the-privacy-act |

### 1.5 Document Conventions

#### Requirement identifiers

Every functional requirement has a unique stable identifier of the form:

```
FR-<MODULE>-<NUM>
```

For example: `FR-AUTH-001`, `FR-SCAN-014`, `FR-BILL-007`.

Non-functional requirements are identified as:

```
NFR-<CATEGORY>-<NUM>
```

For example: `NFR-PERF-003`, `NFR-SEC-018`, `NFR-COMP-002`.

IDs are **stable for the life of the document**. If a requirement is removed or replaced, its ID is **retired** (never reused) and the change is recorded in the document control history. New requirements take the next available number; gaps in numbering are normal and not bugs.

#### Priority codes

Each requirement carries one of:

- **P0 — Must** — non-negotiable. The system fails its purpose if this is not satisfied. Includes anything that blocks revenue, breaks security, or violates a regulatory obligation.
- **P1 — Should** — strongly expected. Absence is a recognised gap that the roadmap commits to closing.
- **P2 — Could** — useful enhancement. Absence is acceptable indefinitely if not built.

#### Implementation status markers

Each requirement is annotated with its **current implementation status** so the SRS reflects reality, not aspiration:

- **[IMPLEMENTED]** — the requirement is satisfied by the current production codebase
- **[PARTIAL]** — partially implemented; the gap is described inline
- **[GAP: not implemented]** — specified but no production code yet
- **[BEYOND SPEC]** — the implementation does *more* than the requirement states; the additional capability is described inline (and may itself need a follow-up requirement to formalise)

The status marker is informational. The requirement itself is **prescriptive** — it states what the system shall do regardless of current implementation.

#### Requirement format

```
### FR-AUTH-001 — User registration via email + password

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]
**Source:** Charter §5.1

The system shall allow an unauthenticated visitor to create an account by
providing first name, last name, email address, password (≥8 characters),
and accepting the Terms of Use, Privacy Policy, and Acceptable Use Policy.

**Acceptance criteria:**
- AC-1 Registration with valid input creates a User row with `email_verified=false`
- AC-2 The system sends a verification email containing a tokenised link valid for 48 hours
- AC-3 The system creates a personal Organization with the registering user as Owner
- AC-4 The system returns the registering user to a "check your inbox" view; no session token is issued
- AC-5 Registration with an email already belonging to a verified account returns HTTP 409 with code `email already registered`
```

The acceptance criteria are written so each line is testable as a single check. They become the basis for unit, integration, and UAT test cases (Test Strategy, doc 06, links them by ID).

#### "Shall" vs "should"

Functional requirements use **"shall"** for prescriptive obligations and **"should"** sparingly for non-binding recommendations within a requirement. NFRs follow the same convention.

#### Module index

The SRS is split across this parent document and per-module files in `docs/sdlc/02-srs/`. Module identifiers are stable and listed in §4. Cross-references between modules use the requirement ID directly (e.g., "see `FR-AUTH-001`") so a reader doesn't need to know which file holds it.

---

## 2. Overall Description

### 2.1 Product Perspective

Nano EASM is a **net-new, standalone, multi-tenant SaaS** product. It is not a module of a larger system, not a self-hosted distribution, and not a wrapper around a third-party platform. It depends on several external services (Stripe, Resend, Shodan, AWS, Postgres) but those are operational dependencies, not parents in a system-of-systems hierarchy.

The product is reached by users via:

- A **public marketing website** at `https://nanoasm.com`
- A **web application** at the same origin under authenticated routes
- A **public Quick Scan tool** under the same origin, no authentication required
- A **REST API** under the same origin under `/api/...`, accessible via session token (web app) or API key (programmatic)
- **Outbound email** delivered by Resend, originating from `no-reply@nanoasm.com`
- **Outbound webhooks** delivered by the system to customer-configured endpoints
- **Inbound webhooks** received from Stripe (payment events)

### 2.2 Product Functions

A high-level summary of what Nano EASM does. Each of these is decomposed into module-level functional requirements in §4 / `02-srs/`.

- Discover externally-visible assets (subdomains, IPs, services, cloud resources) for a customer-supplied root domain
- Scan discovered assets for vulnerabilities, misconfigurations, exposed paths, leaked credentials, weak TLS, and missing security headers
- Score the exposure risk of an asset and an organisation as an aggregate
- Continuously monitor an organisation's assets and emit alerts when material change is detected
- Triage findings through a workflow (open → acknowledged → resolved / accepted-risk)
- Map findings to compliance frameworks (OWASP ASVS / CIS / NIST CSF / PCI-DSS as direct mappings; SOC 2 / ISO 27001 as cross-walked supports)
- Generate executive, technical, and compliance PDF reports
- Route findings and alerts to external systems (Slack, Jira, PagerDuty, email, generic webhook)
- Stream the audit log to a customer-configured webhook (Enterprise Gold and above)
- Manage organisations, users, roles, permissions, API keys, scheduled scans, and asset groups
- Administer the platform (superadmin only) — orgs, users, abuse, announcements, audit log, contact requests, platform health
- Process subscription payments via Stripe
- Enforce a 90-day Free-tier evaluation lifecycle with a 30-day grace period followed by hard data deletion
- Offer a public Quick Scan tool for top-of-funnel lead capture, rate-limited and abuse-protected
- Offer a Lookup workspace for ad-hoc investigations (cert lookup, DNS, WHOIS, header check, etc.)

### 2.3 User Classes and Characteristics

Operator personas (in-application roles) and buyer personas are defined in the Vision & Charter §6. Reproduced briefly here for SRS context:

| Class | Role | Authentication path | Frequency of use |
|---|---|---|---|
| Owner | Org founder | Email/password, Google OAuth, Microsoft OAuth | Weekly+ |
| Admin | Trusted operator | Email/password, OAuth, accepted invite | Daily |
| Analyst | Day-to-day triage | Email/password, OAuth, accepted invite | Daily |
| Viewer | Stakeholder | Email/password, OAuth, accepted invite | Weekly |
| Anonymous user | Unauthenticated | None | First-time visit + Quick Scan |
| Superadmin | Platform operator (Nano EASM staff) | Email/password (must also have superadmin flag granted via CLI) | Daily |
| API consumer | Programmatic | API key (`Authorization: Bearer ag_sk_...` or `X-API-Key`) | Continuous |
| External webhook receiver | Customer SIEM / chat / ticketing | None — the system is calling them | On-event |
| Stripe webhook sender | Payment processor calling the system | HMAC signature verified | On-event |

### 2.4 Operating Environment

The system shall operate in the following environment:

- **Hosting**: AWS, Sydney region (`ap-southeast-2`)
- **Compute**: a single Linux EC2 instance (currently t2.medium) running Docker Compose
- **Database**: PostgreSQL 16, single instance, co-resident on the same EC2 host
- **Reverse proxy**: nginx, terminating TLS, routing `/api/*` to backend container, `/*` to frontend container
- **Outbound email**: Resend
- **Payment processing**: Stripe
- **DNS provider**: [TBD — likely Cloudflare or Route 53]
- **Frontend client**: any modern evergreen browser (Chrome, Firefox, Edge, Safari — last two major versions of each)
- **Backend runtime**: Python 3.x with Flask + SQLAlchemy + APScheduler
- **Frontend runtime**: Node.js with Next.js standalone build, served by Node

Specific versions are recorded in the Software Architecture Document (doc 03). The SRS cares about the *capability* of the environment, not the version.

### 2.5 Design and Implementation Constraints

These are constraints inherited from the charter (Vision & Charter §10) that affect every requirement:

- **Single-region deployment** — no multi-region failover requirement
- **Single-instance database** — no requirement for horizontally distributed reads or sharding
- **In-process background jobs** — no requirement for an external queue (Celery, RQ, SQS) at current scale
- **Australian data residency by default** — non-AU data residency is not required and not offered
- **Currency is AUD** — multi-currency is not required
- **Browser-only frontend** — no native mobile apps; web app must be responsive
- **No SSO with enterprise identity providers** beyond Google and Microsoft consumer OAuth (SAML / OIDC for enterprise IdPs is out of scope)

### 2.6 Assumptions and Dependencies

Things assumed true when reading the requirements; if any becomes false, the affected requirements need re-evaluation.

| ID | Assumption | If false… |
|---|---|---|
| A-01 | Stripe is available as a payment processor in the customer's billing region | Affects all FR-BILL requirements; alternate processor needed |
| A-02 | Resend can deliver to the customer's email domain | Affects all FR-AUTH and FR-NOTIF email-bearing requirements |
| A-03 | Shodan API is available with a paid Corporate-tier subscription | Affects FR-DISC, FR-SCAN, FR-LOOKUP requirements that consume Shodan |
| A-04 | Customers have authorisation to scan the targets they submit | Liability shift via Acceptable Use Policy; legal exposure if false |
| A-05 | Customer browsers support modern web standards (ES2020+, CSS Grid, Service Worker) | Frontend degrades on older browsers; not supported |
| A-06 | PostgreSQL 16 backups (logical + physical) are operating successfully | Affects all data-retention and disaster-recovery NFRs |
| A-07 | The hosting AWS region is operational | Single-region deployment = single point of regional failure |
| A-08 | A new user has access to their email inbox before they can use the system | Affects FR-AUTH-002 onwards (verification gate) |

---

## 3. External Interface Requirements

### 3.1 User Interfaces

The system presents four primary user interfaces:

1. **Public marketing site** (`/`, `/pricing`, `/faq`, `/api-docs`, `/quick-scan`, legal pages) — unauthenticated, marketing-focused, conversion-optimised
2. **Authenticated web application** (`/dashboard`, `/assets`, `/discovery`, `/scan`, `/findings`, `/monitoring`, `/reports`, `/settings/*`) — the day-to-day operator UI
3. **Hidden superadmin console** (`/admin/*`) — accessible only to users with the superadmin flag; returns 404 to all others
4. **Public Quick Scan** (`/quick-scan`) — unauthenticated, single-target abuse-rate-limited

UI requirements relating to specific behaviours (e.g., "the system shall present a 'Resend verification' button after registration") live in the relevant module's functional requirements. Cross-cutting UX NFRs (responsiveness, accessibility, browser support) live in §5.3.

### 3.2 Hardware Interfaces

The system has no direct hardware interfaces. All input comes via HTTP from user-agent browsers or API clients. There is no requirement for serial, USB, sensor, camera, microphone, GPS, or any other hardware integration.

### 3.3 Software Interfaces

The system depends on the following external software interfaces. Each is documented in detail in the SAD (doc 03); the SRS lists them as requirements on which downstream FRs depend.

| Interface | Purpose | Direction | Protocol |
|---|---|---|---|
| **Stripe API** | Subscription creation, payment processing, customer portal, refunds | Outbound (to Stripe) + Inbound (Stripe webhook → us) | HTTPS REST, signed webhook |
| **Resend API** | Transactional email delivery | Outbound (to Resend) | HTTPS REST |
| **Shodan API** | Host intelligence, port scanning data, CVE enrichment | Outbound (to Shodan) | HTTPS REST |
| **GitHub API** | Leaked credential search | Outbound (to GitHub) | HTTPS REST |
| **Certificate Transparency log APIs** (e.g., crt.sh) | Subdomain discovery via certificate logs | Outbound | HTTPS REST |
| **Public DNS resolvers** | DNS resolution, record enumeration | Outbound | DNS/UDP, DoH/HTTPS |
| **Google OAuth 2.0** | OAuth sign-in/sign-up | Outbound + redirect | HTTPS OAuth2 |
| **Microsoft OAuth 2.0** | OAuth sign-in/sign-up | Outbound + redirect | HTTPS OAuth2 |
| **Customer-configured webhook receivers** | Notifications, audit log streaming, integrations | Outbound | HTTPS POST, optionally HMAC-signed |
| **Slack webhook URLs** | Notification delivery to Slack channels | Outbound | HTTPS POST |
| **Jira REST API** | Ticket creation | Outbound | HTTPS REST + Basic Auth (email + token) |
| **PagerDuty Events API v2** | Incident triggering | Outbound | HTTPS POST + routing key |
| **Custom SMTP** | Optional self-hosted alternative to Resend | Outbound | SMTP/STARTTLS |

### 3.4 Communications Interfaces

- All inbound HTTP traffic shall arrive over HTTPS (TLS 1.2 minimum, TLS 1.3 preferred) — see `NFR-SEC-003`
- All outbound HTTP traffic to external services shall be HTTPS — see `NFR-SEC-004`
- Webhook deliveries the system *originates* shall include a per-org HMAC signature header where the receiver supports it — see `NFR-SEC-018` and `FR-INT-*`
- Webhook deliveries the system *receives* (Stripe) shall be signature-verified before processing — see `NFR-SEC-019`
- Email shall be delivered via Resend or a customer-configured SMTP relay; direct SMTP from the application server is not used — see `FR-NOTIF-*`

---

## 4. Functional Requirements — Module Index

The functional requirements are split across the following module files in `docs/sdlc/02-srs/`. Each file contains the FRs for a single product module, written in the format defined in §1.5.

| Module | Module file | Status |
|---|---|---|
| 01 — Authentication & Account Lifecycle | `02-srs/01-authentication.md` | Drafted |
| 02 — Multi-tenancy & RBAC | `02-srs/02-rbac-multitenancy.md` | Drafted |
| 03 — Asset Management | `02-srs/03-asset-management.md` | Drafted |
| 04 — Asset Discovery | `02-srs/04-discovery.md` | Drafted |
| 05 — Scanning | `02-srs/05-scanning.md` | Drafted |
| 06 — Findings Management | `02-srs/06-findings.md` | Drafted |
| 07 — Continuous Monitoring | `02-srs/07-monitoring.md` | Drafted |
| 08 — Reports | `02-srs/08-reports.md` | Drafted |
| 09 — Integrations & Notifications | `02-srs/09-integrations.md` | Drafted |
| 10 — Billing & Subscriptions (incl. Free-tier lifecycle) | `02-srs/10-billing.md` | Drafted |
| 11 — Audit Log | `02-srs/11-audit-log.md` | Drafted |
| 12 — Lookup Tools | `02-srs/12-lookup-tools.md` | Drafted |
| 13 — Public Quick Scan | `02-srs/13-public-quick-scan.md` | Drafted |
| 14 — Settings (Org + User) | `02-srs/14-settings.md` | Drafted |
| 15 — Admin / Superadmin Console | `02-srs/15-admin-console.md` | Drafted |
| 16 — Audit Log Webhook Stream | `02-srs/16-audit-webhook.md` | Drafted |
| 17 — API & Programmatic Access | `02-srs/17-api-access.md` | Drafted |

Module file numbering is **stable** — `01-authentication.md` will always be authentication, even if a later module is removed.

---

## 5. Non-Functional Requirements

These NFRs apply to **the whole system** unless explicitly scoped to a module. Module files may add module-specific NFRs but cannot override these.

### 5.1 Performance

#### NFR-PERF-001 — API response latency (read endpoints)

**Priority:** P0 — Must
**Status:** [PARTIAL — no formal SLO measurement in place]

For authenticated read endpoints (list views, single-resource fetches, dashboard summaries), the system shall return a response within:

- **p50: ≤ 300 ms**
- **p95: ≤ 1.5 s**
- **p99: ≤ 5 s**

Measured at the application boundary (excluding browser render time, including database query time and network egress from the EC2 instance). [TBD — initial baseline measurement required.]

**Acceptance criteria:**
- AC-1 An automated load test against `/dashboard/summary`, `/findings`, `/assets`, `/scan-jobs` against a representative tenant (≥ 50 assets, ≥ 500 findings) hits the targets above
- AC-2 Latency metrics are exposed (logs minimum, dashboards preferred) for ongoing observation

#### NFR-PERF-002 — API response latency (write endpoints)

**Priority:** P0 — Must
**Status:** [PARTIAL]

For authenticated write endpoints that do not initiate a long-running task (CRUD on assets, groups, settings, members, etc.), the system shall return a response within:

- **p50: ≤ 500 ms**
- **p95: ≤ 2.5 s**

#### NFR-PERF-003 — Asynchronous job kickoff response

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Endpoints that initiate a long-running task (scan, discovery, report generation) shall:

- AC-1 Return HTTP 202 with the job's display ID within 1 s
- AC-2 Defer all heavy work to a background thread or scheduled job
- AC-3 Make subsequent status visible via the corresponding list / detail endpoint

#### NFR-PERF-004 — Scan completion time (Quick profile)

**Priority:** P1 — Should
**Status:** [PARTIAL — no formal measurement; observed values appear within target]

A Quick scan (Shodan host lookup, basic asset reconnaissance) against a single asset shall complete in **≤ 60 s** under normal external API conditions.

#### NFR-PERF-005 — Scan completion time (Standard profile)

**Priority:** P1 — Should
**Status:** [PARTIAL]

A Standard scan (Shodan + Nmap top-1000 ports + CVE enrichment) against a single asset shall complete in **≤ 10 minutes** under normal conditions.

#### NFR-PERF-006 — Scan completion time (Deep profile)

**Priority:** P1 — Should
**Status:** [PARTIAL]

A Deep scan (Shodan + Nmap 1–5000 ports + Nuclei templates) against a single asset shall complete in **≤ 30 minutes** under normal conditions.

#### NFR-PERF-007 — Scan completion time (Full profile)

**Priority:** P2 — Could
**Status:** [PARTIAL]

A Full scan (every engine, full port range) against a single asset shall complete in **≤ 60 minutes** under normal conditions. Acceptable to exceed this for very large estates; the user is informed of the long expected runtime in the UI before kickoff.

#### NFR-PERF-008 — Discovery job completion time

**Priority:** P1 — Should
**Status:** [PARTIAL]

A discovery job for a single root domain shall complete in **≤ 5 minutes** for a typical small/mid-size organisation (≤ 100 subdomains).

#### NFR-PERF-009 — PDF report generation time

**Priority:** P1 — Should
**Status:** [PARTIAL]

A PDF report (any template) for an organisation with ≤ 1000 findings shall be ready for download within **≤ 30 s** of request.

#### NFR-PERF-010 — Concurrent active tenants

**Priority:** P0 — Must
**Status:** [GAP: not formally load-tested]

The single-instance deployment shall sustain **at least 50 concurrent active tenants** with mixed read/write/scan traffic before degradation requires a vertical scale-up. [TBD — load test required.]

### 5.2 Security

These NFRs are the system-wide security floor. Module-specific security requirements (e.g., FR-AUTH-* rules around password policy) live with their module.

#### NFR-SEC-001 — Passwords stored as salted, key-derived hashes

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall never store user passwords in plaintext or in a reversible form. Stored credentials shall use a memory-hard or computationally-hard key derivation function with per-user salt and a work factor reviewed annually. The current implementation uses Werkzeug's `generate_password_hash` (PBKDF2-SHA256 by default). Any change to the algorithm must support reading existing hashes (lazy rehash on next login) without forcing a global password reset.

**Acceptance criteria:**
- AC-1 No `User.password_hash` value in the database matches its plaintext for any test value
- AC-2 The hash format includes the algorithm, work factor, salt, and digest
- AC-3 A password reset uses the same derivation parameters

#### NFR-SEC-002 — Minimum password complexity

**Priority:** P0 — Must
**Status:** [PARTIAL — only length enforced]

User-chosen passwords shall be at least 8 characters. The system shall not impose composition rules (mandatory uppercase, digits, symbols) — research and NIST 800-63B advise against such rules — but shall reject passwords that appear in a public breach list of the last 100,000 most-common breached credentials.

**Acceptance criteria:**
- AC-1 Registration with a 7-character password is rejected with a clear error
- AC-2 Registration with `password`, `12345678`, `qwerty` and other common breached passwords is rejected [GAP — breach list check not implemented]
- AC-3 Registration with a long, sufficiently-random password succeeds without composition error

#### NFR-SEC-003 — TLS for inbound traffic

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

All inbound HTTP traffic from user-agents and API clients shall be served over HTTPS. The reverse proxy shall:

- AC-1 Redirect HTTP → HTTPS at the network edge
- AC-2 Refuse TLS protocol versions below 1.2
- AC-3 Use HSTS with `max-age ≥ 6 months` and `includeSubDomains`
- AC-4 Use a publicly-trusted certificate (Let's Encrypt or equivalent)

#### NFR-SEC-004 — TLS for outbound traffic

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

All outbound HTTP traffic to external services (Stripe, Resend, Shodan, customer webhooks, etc.) shall use HTTPS with certificate validation enabled. Falling back to HTTP is not permitted under any flag or environment.

#### NFR-SEC-005 — Session token format and lifetime

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Session tokens (issued at login) shall:

- AC-1 Be JWTs signed with the application secret using HS256 or stronger
- AC-2 Carry minimum claims: `sub` (user id), `iat`, `exp`
- AC-3 Have an expiry of [TBD — currently approximately 14 days; final value to be confirmed under NFR-SEC-006 review]
- AC-4 Be invalidated by the inactivity gate (NFR-SEC-006)
- AC-5 Be transmitted in the `Authorization: Bearer <token>` header for API calls

#### NFR-SEC-006 — Inactivity timeout

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall force re-authentication after **30 minutes of user inactivity** in the browser session, regardless of remaining JWT lifetime.

#### NFR-SEC-007 — RBAC enforcement at the route layer

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Every authenticated route shall enforce the role + permission required by the called operation via a route decorator (`@require_role`, `@require_permission`). The check shall:

- AC-1 Re-fetch the user's current role from the database, not trust the JWT alone
- AC-2 Return HTTP 403 (not 401) on insufficient privilege
- AC-3 Be tested by at least one negative case in the test suite

#### NFR-SEC-008 — Tenant data isolation

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Every query that returns tenant-owned data shall filter on the requesting user's `organization_id`. Cross-tenant data leakage via parameter manipulation (IDOR) shall not be possible.

**Acceptance criteria:**
- AC-1 Manually constructed URLs/payloads referencing another organisation's resource ID return HTTP 404 (not 403, to avoid existence enumeration)
- AC-2 The test suite includes IDOR negative cases for at least: assets, scan jobs, findings, monitors, reports, members, integrations, API keys
- AC-3 Superadmin endpoints are explicitly opt-out of tenant scoping; non-admin endpoints are explicitly opt-in to tenant scoping (default-deny)

#### NFR-SEC-009 — Encryption at rest

**Priority:** P0 — Must
**Status:** [PARTIAL — relies on AWS EBS volume encryption; no application-level field encryption for sensitive data]

The PostgreSQL database and any persistent storage holding tenant data shall be encrypted at rest using AES-256 or stronger. Backups shall inherit this property.

**Acceptance criteria:**
- AC-1 The EBS volume hosting Postgres is encrypted with a customer-managed or AWS-managed key
- AC-2 Database backups (logical and physical) are encrypted at rest
- AC-3 [GAP] Sensitive single-value fields (API key plaintext at issue time, OAuth tokens, integration secrets) are encrypted at the application layer with a key from outside the database

#### NFR-SEC-010 — Secrets handling

**Priority:** P0 — Must
**Status:** [PARTIAL — env-var based, no centralised secrets manager]

Production secrets (database password, Stripe secret key, Resend API key, Shodan API key, JWT signing secret, OAuth client secrets) shall:

- AC-1 Never appear in source code, documentation, error messages, or logs
- AC-2 Be supplied to the application via environment variables
- AC-3 Be rotatable without code changes
- AC-4 [TBD] Be stored centrally in a secrets manager rather than per-host env files when team size > 1

#### NFR-SEC-011 — API key format and storage

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

User-issued API keys shall:

- AC-1 Be displayed in plaintext to the user **exactly once** at creation
- AC-2 Be stored server-side only as a salted, irreversible hash
- AC-3 Use a recognisable, opaque format with a domain prefix (e.g., `ag_sk_...`)
- AC-4 Be revocable individually without affecting other keys
- AC-5 Be scope-restrictable [TBD — current implementation grants org-wide access]

#### NFR-SEC-012 — Rate limiting on public unauthenticated endpoints

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Public unauthenticated endpoints (Quick Scan, contact form, password reset request, login attempt, registration attempt, resend verification) shall be rate-limited per IP address. The default limits are:

- AC-1 Quick Scan: ≤ 5 scans/hour/IP
- AC-2 Contact form: ≤ 5 submissions/hour/IP
- AC-3 Login attempts: ≤ 10/minute/IP
- AC-4 Password reset request: ≤ 3/hour/email
- AC-5 Resend verification: ≤ 1/5 minutes/email
- AC-6 Registration: [TBD — currently unlimited; recommend ≤ 10/hour/IP]
- AC-7 Exceeded limit returns HTTP 429 with `Retry-After` header

#### NFR-SEC-013 — IP block list

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall support superadmin-managed IP blocking. A blocked IP shall:

- AC-1 Receive HTTP 403 on every public endpoint
- AC-2 Have its block recorded with reason, blocker, and optional expiry
- AC-3 Be unblockable individually

#### NFR-SEC-014 — Audit logging coverage

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The following actions shall produce an audit log entry capturing actor, target, action, organisation, timestamp, and IP address:

- AC-1 All authentication events (login, logout, registration, password reset, email verification)
- AC-2 All authorisation changes (role assignment, member invitation, member removal)
- AC-3 All settings changes (org settings, integrations, notification rules, API keys)
- AC-4 All scan job lifecycle events (started, completed, failed, deleted, cancelled)
- AC-5 All discovery job lifecycle events
- AC-6 All findings status changes
- AC-7 All admin/superadmin actions
- AC-8 All export and report generation events
- AC-9 All Stripe webhook events received (idempotency-keyed)

Audit log entries shall be append-only (no in-place edit) and retained per `NFR-DATA-002`.

#### NFR-SEC-015 — Audit log webhook signature

**Priority:** P0 — Must (when feature is enabled)
**Status:** [IMPLEMENTED]

When the audit log webhook stream feature (FR-AUDIT-*) is configured, deliveries shall:

- AC-1 Carry an `X-Nano-Signature: sha256=<hex>` header containing the HMAC-SHA256 of the raw body using the org's signing secret
- AC-2 Carry an `X-Nano-Event-Id: <uuid>` header for receiver-side idempotency
- AC-3 Carry an `X-Nano-Event-Type: <category>` header for routing
- AC-4 Use a per-org secret generated server-side (the customer cannot supply a weak secret)
- AC-5 Reveal the secret in plaintext only once at creation/rotation

#### NFR-SEC-016 — Sensitive data sanitisation in user-facing errors

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Errors returned to users shall not contain Python exception types, stack traces, raw SQL fragments, internal hostnames, or secrets. A sanitisation layer maps known exception classes to user-safe messages and falls back to a generic "internal error" message for unknown exceptions. (See `app/scanner/errors.py`.)

#### NFR-SEC-017 — Email enumeration resistance

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

Public endpoints that take an email address (password reset request, resend verification) shall return identical responses regardless of whether the email is registered, to avoid disclosing the existence of an account.

#### NFR-SEC-018 — HMAC signature on outbound webhook deliveries

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

All outbound webhook deliveries originated by the system (notification routing, audit log stream, integration callbacks) shall include an HMAC-SHA256 signature header signed with a per-recipient secret. The recipient is responsible for verifying the signature.

#### NFR-SEC-019 — Verification of inbound Stripe webhooks

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Inbound Stripe webhooks shall be signature-verified using Stripe's documented verification mechanism. Webhooks failing verification shall be rejected with HTTP 400, logged, and not processed.

#### NFR-SEC-020 — SSRF protection on outbound user-driven requests

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Any outbound HTTP/network request whose target is derived from user input (Lookup tools, scan targets, discovery targets, public Quick Scan) shall be blocked from resolving to:

- Private IP ranges (RFC 1918, link-local, loopback, carrier-grade NAT)
- Cloud metadata endpoints (`169.254.169.254`, etc.)
- Multicast and reserved ranges

Resolution and blocking happen *after* DNS lookup, *before* the connection is opened (see `app/tools/routes.py:_resolve_and_check_ssrf`).

#### NFR-SEC-021 — CSRF protection

**Priority:** P0 — Must
**Status:** [IMPLEMENTED via JWT-Bearer pattern]

Browser-driven mutating requests are authenticated via the `Authorization: Bearer <jwt>` header (not a cookie). This eliminates classic CSRF surface because cross-origin requests cannot set arbitrary headers without preflight + CORS approval.

**Acceptance criteria:**
- AC-1 No mutating endpoint accepts authentication via cookie alone
- AC-2 The CORS configuration restricts `Access-Control-Allow-Origin` to known frontend origins
- AC-3 The CORS configuration does not echo arbitrary `Origin` headers

#### NFR-SEC-022 — Dependency vulnerability monitoring

**Priority:** P1 — Should
**Status:** [GAP: no automated scanning in place]

Backend (`requirements.txt`) and frontend (`package.json`) dependencies shall be scanned for known vulnerabilities at least weekly. Critical vulnerabilities shall be remediated within 7 days; high within 30 days; medium within 90 days.

#### NFR-SEC-023 — No third-party trackers on authenticated pages

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

Authenticated application pages shall not load third-party analytics, advertising, or tracking scripts. The marketing site (unauthenticated) may include opt-in analytics with explicit consent (cookie banner).

#### NFR-SEC-024 — Account lockout after repeated failed login

**Priority:** P1 — Should
**Status:** [GAP: not implemented]

After 10 failed login attempts to the same account within 10 minutes, the account shall be temporarily locked for 15 minutes. The user is informed via the UI; the IP is rate-limited per NFR-SEC-012.

### 5.3 Usability

#### NFR-USAB-001 — Browser support

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The web application shall function in the latest two major versions of Chrome, Firefox, Edge, and Safari on desktop. Older browsers receive a graceful "please upgrade" message rather than a broken UI.

#### NFR-USAB-002 — Mobile responsiveness (read-only)

**Priority:** P1 — Should
**Status:** [PARTIAL]

The web application shall be readable on a viewport ≥ 375 px wide (modern phones). Day-to-day mutation operations (creating monitors, configuring integrations) are optimised for desktop; mobile is read-first.

#### NFR-USAB-003 — Accessibility — WCAG 2.1 Level AA

**Priority:** P1 — Should
**Status:** [GAP: not formally audited]

The web application should meet WCAG 2.1 Level AA. Specifically:

- AC-1 All interactive elements are keyboard accessible
- AC-2 Visible focus state on all focusable elements
- AC-3 Colour contrast ≥ 4.5:1 for body text against background
- AC-4 All images have meaningful `alt` attributes (or `alt=""` for decorative)
- AC-5 Form fields have associated `<label>` elements
- AC-6 Dynamic content updates announce themselves to screen readers (live regions where appropriate)

[GAP — full audit not performed; periodic audits recommended.]

#### NFR-USAB-004 — Onboarding affordance

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

A first-time signed-in user shall, within 60 seconds of arriving at the dashboard, see (a) a step-by-step "get started" checklist on the dashboard, (b) per-page hint cards explaining what each page does, and (c) an opt-in guided tour of the main workflow.

#### NFR-USAB-005 — Error messages are actionable

**Priority:** P0 — Must
**Status:** [PARTIAL]

User-facing errors shall:

- AC-1 Use plain language (no Python exception names, no SQL fragments, no stack traces)
- AC-2 State what the user can do next
- AC-3 Not require the user to read backend logs to understand

#### NFR-USAB-006 — Internationalisation

**Priority:** P2 — Could
**Status:** [GAP: not implemented]

The application is English-only at this time. The codebase shall not preclude future internationalisation (no hard-coded English in templates that would block extraction). [TBD — i18n is not on the roadmap during the current product phase.]

### 5.4 Reliability and Availability

#### NFR-REL-001 — Uptime target

**Priority:** P0 — Must
**Status:** [PARTIAL — no formal monitoring]

Backend service uptime shall be:

- 6-month rolling average: **≥ 99.0%**
- 12-month rolling average: **≥ 99.5%**

Planned maintenance windows are excluded from the calculation provided they are announced ≥ 48 hours in advance via in-app announcement.

#### NFR-REL-002 — Backup cadence

**Priority:** P0 — Must
**Status:** [PARTIAL — daily logical dump exists; physical PITR not in place]

Database backups shall be:

- AC-1 Logical dump: daily, retained 14 days
- AC-2 Physical (WAL-archive / PITR): [GAP] continuous, retained 7 days
- AC-3 Verified by test restore at least quarterly

#### NFR-REL-003 — Recovery objectives

**Priority:** P0 — Must
**Status:** [PARTIAL]

For a complete loss of the production EC2 instance, the system shall be restored within:

- **RTO (Recovery Time Objective):** ≤ 4 hours
- **RPO (Recovery Point Objective):** ≤ 24 hours (logical dump only) → improving to ≤ 5 minutes once PITR is in place

Detailed recovery procedure lives in the Backup & DR Plan (doc 08, forthcoming).

#### NFR-REL-004 — Graceful degradation when an external service fails

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

External service failures shall not crash the system:

- AC-1 Resend outage → email send returns False; calling code logs and continues; user-facing operation is not aborted
- AC-2 Shodan outage → scan engine for that source returns empty/error; other engines continue; finding aggregation reflects the gap
- AC-3 Stripe outage → checkout/portal returns a friendly error message; existing subscriptions are unaffected
- AC-4 GitHub outage → leak scan returns no results with a "rate limited / unavailable" indicator

#### NFR-REL-005 — Background job retry

**Priority:** P1 — Should
**Status:** [PARTIAL]

Failed background jobs (scans, discoveries, monitor sweeps) shall be retried at least once with exponential backoff. After the retry budget is exhausted, the job is marked failed and the user is notified via the standard notification routing.

### 5.5 Maintainability

#### NFR-MAINT-001 — Code review required

**Priority:** P0 — Must (when team size > 1)
**Status:** [TBD — currently single-author]

When the engineering team has more than one engineer, every production code change shall be reviewed by at least one engineer other than the author before merge to the main branch.

#### NFR-MAINT-002 — Secrets never committed

**Priority:** P0 — Must
**Status:** [IMPLEMENTED — `.env` files in `.gitignore`]

No secret value (API keys, passwords, tokens, certificates, JWT signing secrets) shall be committed to the source repository. Detection via pre-commit hook is recommended.

#### NFR-MAINT-003 — Test coverage

**Priority:** P1 — Should
**Status:** [TBD — coverage not measured]

Backend code shall maintain ≥ 70% line coverage by automated tests. Critical paths (auth, billing, RBAC) shall maintain ≥ 90%. Coverage reports are published per build.

#### NFR-MAINT-004 — Logging structure

**Priority:** P1 — Should
**Status:** [PARTIAL]

Application logs shall be structured (JSON or key=value pairs) with at minimum: timestamp, level, module, message, request id (where applicable), tenant id (where applicable). Personally identifiable information (PII) shall be masked or omitted from log output.

#### NFR-MAINT-005 — Database migrations

**Priority:** P0 — Must
**Status:** [IMPLEMENTED — Flask-Migrate / Alembic]

Schema changes shall be applied via versioned migrations. Migrations shall be:

- AC-1 Idempotent (re-runnable on a partially-applied state)
- AC-2 Reversible where data preservation allows (downgrade defined)
- AC-3 Reviewed before merge with the same rigour as application code
- AC-4 Tested on a copy of production-shaped data before applying to production

#### NFR-MAINT-006 — Configuration via environment variables

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Environment-specific configuration (database URL, API keys, feature flags, region) shall be supplied via environment variables, not hard-coded into source files. The set of required environment variables shall be documented in a `.env.example` file (no real values).

### 5.6 Portability

#### NFR-PORT-001 — Hosting independence

**Priority:** P2 — Could
**Status:** [PARTIAL]

The application shall be deployable on any Linux host running Docker Compose. Strong AWS-specific dependencies (other than EBS encryption and the EC2 instance itself) shall be avoided where they would lock in to a single cloud.

#### NFR-PORT-002 — Database engine independence

**Priority:** P2 — Could
**Status:** [PARTIAL — uses Postgres-specific JSON operators in some queries]

The application targets PostgreSQL 16 only. Cross-database portability (MySQL, SQLite at scale) is not a current requirement.

#### NFR-PORT-003 — Browser-only frontend

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The frontend shall function as a standalone web app served from a single Node.js host. It shall not require browser plugins, native helpers, or desktop wrappers.

### 5.7 Compliance

#### NFR-COMP-001 — Honesty stance on framework certifications

**Priority:** P0 — Must
**Status:** [IMPLEMENTED — enforced by structural checks in `app/scanner/compliance_map.py`]

The system shall never claim a "direct" mapping for SOC 2 Trust Services Criteria or ISO/IEC 27001 Annex A controls. All references to those frameworks in product copy, finding output, reports, and marketing materials shall be labelled as *supports* with a cross-walk citation.

This is the charter §12 stance encoded as a non-functional requirement so it cannot be quietly relaxed in code or copy.

#### NFR-COMP-002 — Right to erasure (GDPR Art. 17 / Privacy Act)

**Priority:** P0 — Must
**Status:** [PARTIAL — manual process via superadmin; no self-serve flow]

A user who requests deletion of their account shall, within 30 days:

- AC-1 Have their personal account record deleted
- AC-2 Have their organisation deleted if they are the sole member (chained user delete)
- AC-3 Have audit log entries either deleted or anonymised (foreign key set to NULL)
- AC-4 Receive a confirmation email when deletion completes
- AC-5 Backups containing the deleted data age out of retention (no extraordinary backup deletion required if retention is ≤ 90 days)

[GAP — self-serve "delete my account" UI is not exposed to non-Owner users; superadmin can perform on request.]

#### NFR-COMP-003 — Data subject access request (DSAR)

**Priority:** P1 — Should
**Status:** [GAP — manual process]

A user shall be able to request a machine-readable export of all personal data the system holds about them. The export shall be delivered within 30 days of request.

#### NFR-COMP-004 — Acceptable Use Policy acceptance

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Every user shall accept the Acceptable Use Policy and Security Scanning Authorisation at registration. Acceptance shall be recorded with timestamp and version. Material AUP changes require re-acceptance.

#### NFR-COMP-005 — Data residency

**Priority:** P0 — Must
**Status:** [IMPLEMENTED — single AU region]

Tenant data (database, backups, logs) shall reside within Australia (`ap-southeast-2` region or successor AU regions). Outbound data transfers to external service providers (Stripe, Resend, Shodan, GitHub) are necessary and disclosed in the Privacy Policy and DPA.

---

## 6. Data Requirements

The full data model lives in the SAD (doc 03). The SRS records the high-level entities and the data-handling rules that bind them.

### 6.1 Entity Overview

The principal data entities are:

- **User** — a natural person with a verified email and credentials
- **Organization** — a tenant; owns assets, scans, findings, monitors, integrations, billing context
- **OrganizationMember** — many-to-many between User and Organization with a role
- **PendingInvitation** — outstanding org invite to an email address
- **Asset** — a discrete tracked resource (domain, subdomain, IP, etc.) belonging to an Organization, with a criticality tier
- **AssetGroup** — a logical grouping of assets (e.g., "Production", "Subsidiary X")
- **DiscoveryJob** — one execution of the discovery pipeline against a root domain
- **DiscoveredAsset** — an asset surfaced by discovery, pending or accepted into the inventory
- **ScanJob** — one execution of a scan profile against an asset
- **ScanProfile** — system or org-defined scan recipe
- **ScanSchedule** — cron-like recurrence config for scans
- **Finding** — a discrete vulnerability / misconfiguration tied to an Asset and ScanJob
- **Monitor** — continuous monitoring configuration for an asset or group
- **MonitorAlert** — an alert raised by a monitor
- **Report** — a generated PDF artefact
- **Integration** — a configured external system (Slack, Jira, etc.)
- **NotificationRule** — routing rule from an event type to an Integration
- **ApiKey** — a programmatic credential
- **AuditLog** — an append-only event row
- **AuditWebhookDelivery** — per-attempt log of audit webhook deliveries
- **ContactRequest** — public contact form submission, trial request, demo request
- **PlatformAnnouncement** — admin-broadcast banner
- **QuickScanLog** — abuse log for the public Quick Scan tool
- **BlockedIP** — IP block list entry
- **StripeEvent** — idempotency record for processed Stripe webhooks
- **BillingEvent** — user-visible billing audit trail
- **TrialHistory** — per-org trial usage record

The entity-relationship diagram and field-level schema live in the SAD.

### 6.2 Data Classification

Data held by the system is classified as follows. Handling requirements (encryption, masking, access controls) flow from this classification.

| Class | Examples | Handling |
|---|---|---|
| **Public** | Marketing site content, public Quick Scan results returned to anonymous users (rate-limited) | No special handling |
| **Internal** | Application logs (with PII masked), aggregate platform stats, audit log entries | Access restricted to authorised personnel |
| **Confidential** | Tenant inventory (assets, scan results, findings, reports), org members, settings | Tenant-isolated; access only by tenant members per RBAC; encrypted at rest |
| **Sensitive** | User passwords (hashed), API keys (hashed), OAuth tokens, integration secrets, audit webhook secrets, Stripe customer ids, payment instrument identifiers | Encrypted at rest; never logged; never rendered in error messages; never returned in API responses except at creation time (one-shot reveal) |
| **Personal Identifiable Information (PII)** | User email, name, IP address, country | Subject to NFR-COMP-002 (right to erasure); masked in logs; not used for marketing without consent |

### 6.3 Data Retention

| Data | Retention | Trigger for deletion |
|---|---|---|
| User account + profile | Indefinite while active | User request (NFR-COMP-002) or hard-delete via admin |
| Organisation + tenant data | Indefinite while active | Organisation owner deletion request, or 30 days after Free-tier expiry per Free-tier lifecycle |
| Audit log | **Minimum 1 year**, target 2 years | Roll-off at retention limit |
| Audit webhook delivery log | 7 days | Pruned by background cleanup |
| Application logs | 30 days | Log rotation |
| Database backups (logical) | 14 days | Rolling deletion |
| Database backups (physical / PITR) | 7 days | Rolling deletion |
| Quick Scan log entries | 90 days | Rolling deletion |
| Contact requests | 1 year after closure | Manual or scheduled cleanup |
| Stripe event idempotency rows | 90 days | Rolling deletion |
| Billing events (user-visible audit trail) | 7 years | Regulatory retention for financial records |

### 6.4 Data Residency

All persistent tenant data shall reside in Australia. Specifically:

- **Database** (Postgres EBS volume) — `ap-southeast-2`
- **Logical backups** — `ap-southeast-2` S3 bucket
- **Application logs** — `ap-southeast-2`
- **Quick Scan logs** — `ap-southeast-2`

Outbound data flows that necessarily cross borders (Resend in the US, Stripe in the US, Shodan in the US, GitHub in the US) are limited to the minimum data required for the operation and disclosed in the Privacy Policy and DPA.

---

## 7. Appendices

### Appendix A — Use Case Summary (high-level)

A complete use case catalogue is not maintained in the SRS; module files contain task-level requirements that double as detailed use cases. The principal high-level use cases the system supports are:

| UC | Description | Primary actor | Module |
|---|---|---|---|
| UC-1 | Sign up, verify email, log in | New user | Authentication (01) |
| UC-2 | Add a root domain, run discovery, accept discovered assets into inventory | Owner / Admin / Analyst | Asset Mgmt (03) + Discovery (04) |
| UC-3 | Run an on-demand scan and triage the resulting findings | Analyst | Scanning (05) + Findings (06) |
| UC-4 | Set up a monitor on an asset and receive alerts when something changes | Analyst | Monitoring (07) |
| UC-5 | Generate and download a compliance PDF report for an external auditor | Owner / Admin | Reports (08) |
| UC-6 | Configure a Slack integration and a notification rule for critical findings | Admin | Integrations (09) |
| UC-7 | Upgrade from Free tier to Starter via Stripe checkout | Owner | Billing (10) |
| UC-8 | Export the audit log as CSV for SOC review | Admin | Audit (11) |
| UC-9 | Use the Lookup workspace to investigate a domain ad-hoc | Analyst | Lookup (12) |
| UC-10 | Run an unauthenticated Quick Scan from the marketing site as a prospect | Anonymous user | Quick Scan (13) |
| UC-11 | Suspend an abusive tenant via the admin console | Superadmin | Admin (15) |
| UC-12 | Stream the audit log into a corporate SIEM | Admin (Enterprise Gold tier) | Audit Webhook (16) |
| UC-13 | Programmatically pull findings into a CI pipeline using an API key | API consumer | API (17) |

### Appendix B — Module Index

See §4. Each module file is the authoritative location for its module's functional requirements; this appendix exists to make the index discoverable from the appendices.

### Appendix C — Document History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-05-05 | [TBD] | Initial draft of parent SRS (intro, NFRs, data, appendices). Module files [GAP: not yet drafted]. |

---

*End of Document.*
