# Nano EASM — Vision & Charter

## Document Control

| Field | Value |
|---|---|
| Document ID | SDLC-01 |
| Title | Nano EASM — Vision & Charter |
| Version | 0.1 (Draft) |
| Status | Draft — pending sign-off |
| Owner | [Desire Iradukunda |
| Author | Desire Iradukunda |
| Created | 2026-05-05 |
| Last reviewed | 2026-05-05 |
| Next review | +90 days |
| Related documents | 02 SRS, 03 SAD, 04 Threat Model, 05 Security Policy |

---

## 1. Project Name & History

The product is **Nano EASM**, delivered through the domain **nanoeasm.com**.

The codebase originated under the working name *BoltEdge EASM* and was fully rebranded to *Nano EASM* in April 2026. All customer-facing surfaces, brand assets, and email infrastructure use *Nano EASM*. The legacy name should not appear in any documentation, code, or copy going forward; the *boltedge-easm* directory name on disk is preserved only to avoid breaking deployment paths and version control history.

---

## 2. Problem Statement

Most organisations underestimate their internet-facing attack surface. Subdomains spin up without security review, cloud assets are provisioned outside the asset inventory, certificates expire, ports stay open after the project that needed them is forgotten, and credentials leak into public source-code repositories. Existing solutions either:

- **Cost too much** for small teams and MSPs (Tenable ASM, CrowdStrike Falcon Surface, Detectify all start at thousands of dollars per month),
- **Stop at raw data** (Shodan, SecurityTrails) and leave the operator to interpret findings, or
- **Bury small operators in noise** (every open-source scanner produces output but no triage workflow).

The result: small businesses, MSPs, security consultants, and SOC teams who *want* to monitor their external surface either pay for a heavyweight platform they don't fully use, or stitch together five free tools and live with the gaps.

---

## 3. Vision Statement

> **An honest, affordable view of what's exposed on the internet — for teams who care, regardless of budget.**

---

## 4. Mission Statement

Nano EASM is a multi-tenant External Attack Surface Management platform that discovers internet-facing assets, scans them for vulnerabilities and misconfigurations, scores exposure risk against asset criticality, and continuously monitors for change. The platform produces practical, triaged findings with clear remediation guidance and audit-ready evidence, delivered through a workflow designed for small security teams, MSPs, and consultants — not Fortune 500 SOCs.

---

## 5. Product Scope

### 5.1 In Scope

- **External asset discovery** — root domains in, complete attack surface out (subdomains, IPs, services, cloud resources). Eleven discovery modules including certificate transparency logs, DNS enumeration, Shodan integration, and brute-force lookup.
- **Multi-engine scanning** — port scanning, vulnerability templates, TLS analysis, header analysis, and host intelligence across nine engines and thirteen analysers, with four user-selectable scan profiles (Quick, Standard, Deep, Full).
- **Findings management** — a curated catalogue of finding templates with severity, CWE mapping, technical detail, remediation steps, and reference links; triage workflow (open → acknowledged → resolved → accepted-risk); compliance framework cross-walk (OWASP ASVS, CIS Controls, NIST CSF, PCI-DSS, SOC 2, ISO 27001).
- **Continuous monitoring** — scheduled re-scanning with change detection across DNS, SSL, ports, headers, technology fingerprints and CVEs, with alerts routed to in-app, email, Slack, Jira, PagerDuty, and generic webhooks.
- **Reporting** — executive, technical, and compliance PDF reports scoped to the organisation or to individual asset groups.
- **Multi-tenancy & RBAC** — tenant-scoped data with Owner / Admin / Analyst / Viewer roles, audit log, API keys, scheduled scans, asset groups, and team invitations.
- **Public-facing tooling** — a rate-limited public Quick Scan as a top-of-funnel discovery mechanism, plus a Lookup workspace for ad-hoc investigations (cert lookup, DNS, WHOIS, header check, sensitive-paths scan, GitHub leak scan, etc.).
- **Platform administration** — a hidden superadmin console for managing tenants, users, abuse, announcements, audit log, contact requests, and platform health.
- **Freemium commercial model** — a permanent set of paid tiers (Starter, Professional, Enterprise Silver, Enterprise Gold, Custom) plus a **Free tier that expires 90 days after sign-up** to convert prospects through evaluation rather than indefinite free use. Trial requests for paid tiers are admin-reviewed.

### 5.2 Out of Scope (current release)

The following are intentionally not included in the current product. Each may be revisited in a future phase but should not appear in the SRS, architecture, or roadmap as a current requirement.

- **Authenticated / credentialed scanning** — Nano EASM scans only what's externally observable. No agent, no insider view, no authenticated vulnerability assessment of internal systems.
- **Internal / on-premises asset discovery** — agents and connectors for internal networks are not in scope.
- **Endpoint, EDR, or workload protection** — Nano EASM is not an EDR / XDR / EPP product.
- **Dynamic application security testing (DAST) of authenticated workflows** — only unauthenticated probes.
- **Phishing simulation, awareness training, or social engineering testing**.
- **Mobile application scanning (iOS/Android binaries)**.
- **Threat intelligence feed publication** — Nano EASM is a consumer of intelligence (Shodan, CT logs, etc.), not a provider.
- **Self-hosted / customer-managed deployment**. Nano EASM is a hosted SaaS only; on-premises or customer-VPC deployment is not offered.

---

## 6. Target Users

### 6.1 Operator Personas (in-product roles)

These describe **users inside the application**. Permissions and feature access are driven from these roles via the platform's RBAC system.

- **Owner** — created the organisation, controls billing and ultimate destruction of the workspace. Cannot be removed by other members.
- **Admin** — manages members, integrations, scheduled scans, API keys, organisation-level configuration.
- **Analyst** — triages findings, runs scans, creates and manages monitors. Day-to-day operator.
- **Viewer** — read-only access to assets, scans, findings, and reports. Typical for executives and external auditors.

### 6.2 Buyer Personas (commercial audiences)

These describe **the customer segments Nano EASM positions to**. Sequencing of go-to-market effort across these segments is documented separately in the GTM plan; the charter only enumerates which segments are in-scope.

- **Independent security consultants and pentesters** — need an affordable, white-label-friendly EASM to bundle with engagements; primary day-1 audience.
- **Managed Security Service Providers (MSPs/MSSPs)** — manage external surfaces for multiple clients; multi-tenancy is a hard requirement.
- **In-house SOC and security engineering teams** at small-to-mid organisations — need continuous monitoring without a six-figure platform spend.
- **Security-aware founders and IT leads** at startups (typically Seed–Series B) — want exposure visibility without hiring a dedicated security engineer.
- **Small businesses** with regulatory pressure (e.g., AU Privacy Act, sector-specific obligations) — need basic external posture monitoring as part of compliance evidence.

---

## 7. Strategic Objectives

The product exists to achieve the following strategic outcomes. Each is a *direction*, not a metric — the corresponding metrics live in §8.

1. **Be honest** — Nano EASM never claims compliance certification or coverage it cannot back up. Marketing copy, finding output, and compliance mapping all default to the conservative interpretation.
2. **Be affordable** — pricing tiers are calibrated to remain accessible to single-operator consultants and small MSPs (entry tier under A$30/month, no per-seat upcharges below the Enterprise tier).
3. **Commercially sustainable from day one** — Nano EASM is a paid SaaS with a freemium on-ramp. The Free tier exists to let a prospect prove the product works on their assets in evaluation, not as a permanent free service: it expires 90 days after sign-up and the customer must convert to a paid tier or wind down. Pricing tiers are calibrated so the Starter tier is approachable to single-operator consultants, and recurring revenue from the platform funds ongoing engineering, infrastructure, and security work.
4. **Bias toward workflow over data** — scans produce *triaged findings* with severity, remediation, and compliance mapping, not a JSON dump of scanner output. The product's value is in the triage layer, not raw data acquisition.
5. **Build for small teams first** — UX, defaults, and pricing optimise for solo operators and teams of <10. Enterprise features (audit-log streaming, custom limits, priority support) exist on top tiers but never compromise the small-team experience.
6. **Operate from Australia** — primary market is AU/NZ + APAC, AUD-priced. Global access is supported but not optimised for in the first 12 months.
7. **Keep the platform itself defensible** — the platform performs active scanning of third-party infrastructure; abuse handling, authorisation, audit, and tenant isolation must be first-class concerns, not afterthoughts.

---

## 8. Success Criteria / KPIs

KPI targets are intentionally `[TBD]` until the founder confirms numbers. Categories listed are the ones that should be tracked, with the metric definition fixed even if the target is open.

| Category | Metric | 6-month target | 12-month target |
|---|---|---|---|
| Adoption | Active organisations (≥1 scan in trailing 30 days) | [TBD] | [TBD] |
| Adoption | Total registered users | [TBD] | [TBD] |
| Engagement | Scans completed per active organisation per month | [TBD] | [TBD] |
| Engagement | % of orgs with ≥1 active monitor | [TBD] | [TBD] |
| Retention | Logo retention (rolling 90-day) | [TBD] | [TBD] |
| Quality | False-positive rate against an internal benchmark corpus | [TBD] | [TBD] |
| Reliability | Backend uptime (rolling 30-day) | 99.0% | 99.5% |
| Reliability | Median scan completion time (Standard profile) | <2 min | <90 sec |
| Security | Mean time to remediate a critical security finding in our own platform | <72 h | <48 h |
| Security | Number of unresolved Critical/High self-findings | 0 | 0 |
| Commercial | Paying customers | [TBD] | [TBD] |
| Commercial | Monthly recurring revenue (AUD) | [TBD] | [TBD] |
| Commercial | Free → paid conversion rate (within 90-day Free window) | [TBD] | [TBD] |
| Commercial | % of expired Free tenants who convert vs. churn | [TBD] | [TBD] |

---

## 9. Stakeholders

| Stakeholder | Role | Interest |
|---|---|---|
| Founder | Product, engineering, GTM | Sole decision-maker during community preview |
| Early users (preview) | Design partners | Provide product feedback; inform roadmap |
| Open-source contributors | External engineers | Submit code, file issues; inform standards |
| Auditors / customers' compliance teams | External | Will request evidence (security policy, threat model, etc.) |
| AWS | Infrastructure provider | Operational dependency |
| Resend | Email delivery | Operational dependency |
| Shodan, GitHub, certificate transparency log operators | Data source | Operational dependency; usage subject to their ToS |
| Stripe | Payment processor (post-billing-flip) | Will hold billing data |

---

## 10. Constraints

### 10.1 Technical

- Single-region deployment on AWS EC2 (Sydney region); no multi-region today.
- PostgreSQL as the sole datastore; no separate cache, queue, or search engine.
- Synchronous scan orchestration on the same instance as the web tier; no dedicated worker pool.
- Backend in Python (Flask + SQLAlchemy); frontend in TypeScript (Next.js App Router).
- Background jobs handled in-process via APScheduler — no separate Celery / RQ infrastructure.

### 10.2 Regulatory & Legal

- Active scanning of third-party infrastructure carries legal exposure. The Acceptable Use Policy and Security Scanning Authorisation must be accepted by every user; all active scans must be authorised by the asset owner.
- Australian Privacy Act 1988 applies to user PII held by the platform (account email, name, IP addresses).
- GDPR applies if any EU resident registers; right-to-erasure and data-export must be supported.
- The platform itself is **not** SOC 2 Type 1/2, ISO 27001, or PCI-DSS certified. Product copy and sales conversations must reflect this honestly.
- Compliance framework cross-walks shipped in product (SOC 2, ISO 27001) explicitly label themselves as *supports* rather than *direct* mappings; this stance must not be relaxed without auditor sign-off.

### 10.3 Resource

- Solo founder (≈10 productive marketing/sales hours per week, balance on engineering).
- No external funding; runway tied to founder's personal runway.
- No dedicated QA, ops, or design resource.
- Email delivery dependent on Resend's free / low-tier limits.

---

## 11. High-level Risks

The full risk register lives in a separate document. Listed here are the strategic risks that affect the *charter* — i.e., risks that could invalidate the product direction itself, not implementation risks.

| ID | Risk | Likelihood | Impact | Direction |
|---|---|---|---|---|
| CR-01 | Active scanning misuse — a customer scans a target they're not authorised to scan, regulator or victim contacts us | Medium | High | Mitigate via ToS, AUP, audit log, abuse-detection scoring |
| CR-02 | False-positive incident — a noisy critical finding turns out to be wrong, posted publicly, kills credibility with security crowd | Medium | High | Curate templates conservatively; document confidence levels |
| CR-03 | Single-founder bus factor — primary sales objection from enterprise buyers | High | Medium | Acknowledge openly; defer enterprise-tier sale until co-founder/team in place |
| CR-04 | Incumbent feature parity — Tenable / Detectify / CrowdStrike ship a "good enough" cheap tier | Medium | Medium | Compete on workflow + price + transparency, not raw data |
| CR-05 | Free tier abuse — users repeatedly create burner accounts to evade the 90-day expiry, eroding margin | Medium | Medium | Cooldown on re-registration with same domain/IP; abuse signals fed to admin review; cap on parallel Free tenants per email domain |
| CR-08 | Low Free → paid conversion at 90-day expiry — Free users wind down rather than convert, undermining the commercial model | Medium | High | Track conversion KPI from launch; tighten Free tier limits or shorten window if conversion stays low; in-product upgrade nudges throughout the 90 days |
| CR-06 | Resend / Shodan / Stripe pricing or policy change | Medium | Medium | Abstract dependencies; document a swap-out path in SAD |
| CR-07 | Compliance overclaim by founder under sales pressure | Low | High | Hard rule in security policy; never claim certified status without audit evidence |

---

## 12. Compliance Posture

Nano EASM's official posture toward compliance frameworks, established at the charter level so it cannot be relaxed downstream:

- **Direct mapping** — findings are mapped to **OWASP ASVS 4.0**, **CIS Controls v8**, **NIST CSF v2.0**, and **PCI-DSS 4.0** based on CWE associations. These mappings are derived from machine-readable framework taxonomies and are labelled in product as *direct*.
- **Cross-walked / supporting only** — findings are *not* directly mapped to **SOC 2 Trust Services Criteria** or **ISO/IEC 27001:2022 Annex A**. Where these frameworks are referenced, the mapping is derived through NIST CSF cross-walks and is labelled in product as *supports*. Marketing and sales copy must use phrasing such as "surfaces findings that may inform your compliance evidence — verify with your auditor", and **never** "audit-ready for SOC 2" or "ISO 27001 compliant".
- **Platform certification** — Nano EASM as an organisation is **not** SOC 2 / ISO 27001 / PCI-DSS / HIPAA certified. The charter does not currently commit to obtaining any of these certifications; the decision to pursue certification is deferred until customer demand justifies the audit cost and the 6–12 month engagement timeline.
- **Customer expectations** — buyers asking for evidence will be provided with: this charter, the SRS, the Software Architecture Document, the Threat Model, the Security Policy, the Incident Response Plan, and the Backup & DR Plan. Any further evidence (penetration test report, SOC 2 report) is out of scope until explicitly funded.

---

## 13. Competitive Landscape

The EASM market is dominated by enterprise platforms — **Tenable Attack Surface Management**, **CrowdStrike Falcon Surface**, **Detectify**, **Censys ASM**, **Microsoft Defender EASM** — most of which start in the four-to-six-figures-per-year range and target organisations with dedicated security teams. At the data-source layer, **Shodan** and **SecurityTrails** sell raw exposure data without a triage workflow. Open-source projects (**Nuclei**, **subfinder**, **Amass**) provide the underlying primitives Nano EASM uses, but require operator assembly and offer no multi-tenancy, RBAC, or compliance mapping. **Intruder.io** is the closest commercial small-team competitor, priced an order of magnitude above Nano EASM's intended tiers. Nano EASM's commercial position is therefore *not* "better data than Tenable" or "more accurate than Detectify", but "the same workflow shape at a price point a consultant or MSP can actually justify". A more thorough competitive analysis should be written when entering active GTM motion; it is intentionally deferred from this charter.

---

## 14. Resources & Budget

Nano EASM operates on **founder time, fixed infrastructure cost, and the variable cost of upstream data providers and payment processing**. There is no payroll and no dedicated marketing budget; the founder is the sole engineer, marketer, and support function.

| Item | Approximate monthly cost (AUD) | Notes |
|---|---|---|
| AWS EC2 t2.medium (production) | ~A$50 | Single instance hosting backend + frontend + Postgres |
| Domain registration (nanoeasm.com) | ~A$2 amortised | Annual renewal |
| Resend (transactional email) | A$0–A$30 | Tier dependent on volume |
| Shodan API (Corporate) | ~A$120 | USD-billed, AUD equivalent |
| Stripe (payment processing) | 1.7% + A$0.30 per transaction | No fixed fee; scales with revenue |
| **Total recurring (fixed)** | **~A$200/mo** | Excludes Stripe transaction fees |

The founder's time is the binding resource. The GTM plan budgets ≈10 hours/week for non-engineering work (marketing, sales, support); engineering capacity is the residual.

This budget section is intentionally minimal. As recurring revenue grows, separate budget planning (replacement infrastructure costs at scale, first hire, marketing spend, audit costs) will be tracked outside this charter — likely in a quarterly operating plan.

---

## 15. Timeline

The charter does not commit to specific calendar dates because they would anchor expectations the founder cannot reliably commit to. Instead, work is grouped into Now / Next / Later bands. Concrete dates live in the rolling roadmap document.

### Now (current quarter)

- Stabilise existing product surface; close known critical bugs.
- Complete this SDLC documentation set (Vision, SRS, SAD, Threat Model, Security Policy, Test Strategy, Incident Response, Backup & DR, SLA, DPA — Tier 1–4 from the SDLC plan).
- Implement the 90-day Free-tier expiry behaviour (in-product countdown, email reminders, expiry action).
- Verify Stripe integration end-to-end (test cards, AUD prices for all paid tiers, hosted Checkout, Customer Portal, webhook idempotency, receipts via Resend).
- Publish initial SLA and DPA template.
- Onboard first 5 design-partner customers.
- Author and publish three pieces of go-to-market content.

### Next (one quarter out)

- First 25 active tenants and first paying customers.
- Complete an external penetration test (or peer review) of the platform itself.
- Tighten Free-tier abuse handling based on early signal (re-registration cooldown, per-domain caps).
- Track Free → paid conversion and adjust limits / window if conversion is materially below target.

### Later (two-to-four quarters out)

- First co-founder or hire decision based on revenue trajectory.
- Evaluate SOC 2 Type 1 readiness if customer demand justifies the audit cost.
- Evaluate API-first / partner-channel motion (MSPs reselling).

---

## 16. Glossary

| Term | Definition |
|---|---|
| **EASM** | External Attack Surface Management — discovery and monitoring of an organisation's internet-exposed assets, from an outside-in perspective. |
| **ASM** | Attack Surface Management (broader term, includes internal ASM). |
| **CWE** | Common Weakness Enumeration — taxonomy of software security weaknesses maintained by MITRE. |
| **CVE** | Common Vulnerabilities and Exposures — public catalogue of disclosed vulnerabilities. |
| **CVSS** | Common Vulnerability Scoring System — numeric severity rating for CVEs. |
| **CT logs** | Certificate Transparency logs — public append-only logs of every TLS certificate issued by a participating CA. Used for subdomain discovery. |
| **OWASP ASVS** | Open Web Application Security Project Application Security Verification Standard. |
| **CIS Controls** | Center for Internet Security Controls (v8) — prescriptive cybersecurity baseline. |
| **NIST CSF** | National Institute of Standards and Technology Cybersecurity Framework (v2.0). |
| **PCI-DSS** | Payment Card Industry Data Security Standard. |
| **SOC 2** | Service Organisation Control 2 — AICPA attestation framework for service providers. |
| **ISO 27001** | International Organisation for Standardisation — Information Security Management System standard. |
| **RBAC** | Role-Based Access Control. |
| **MSP / MSSP** | Managed Service Provider / Managed Security Service Provider. |
| **SDLC** | Software Development Life Cycle. |
| **SRS** | Software Requirements Specification. |
| **SAD** | Software Architecture Document. |
| **DPA** | Data Processing Agreement. |
| **SLA** | Service Level Agreement. |
| **AUP** | Acceptable Use Policy. |
| **DAST** | Dynamic Application Security Testing. |

---

## 17. Approval & Sign-off

| Role | Name | Signature / Acknowledgement | Date |
|---|---|---|---|
| Project Owner | [TBD] | | |
| Author | [TBD] | | |
| Reviewer (peer / advisor, optional) | [TBD] | | |

Approval indicates agreement with the vision, scope, strategic objectives, and constraints expressed in this charter. Subsequent material changes (in/out-of-scope additions, strategic objective changes, compliance posture changes) require re-approval of the affected sections by the Project Owner.

---

*End of Document.*
