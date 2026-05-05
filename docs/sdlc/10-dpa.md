# 10 — Data Processing Addendum (DPA)

| Field | Value |
|---|---|
| Document | 10 — DPA |
| Owner | Founder / sole engineer (acting as Data Protection Contact) |
| Status | Draft |
| Effective from | (per-customer; on signature) |
| Last reviewed | 2026-05-05 |
| Related docs | `02-srs.md`, `05-security-policy.md`, `08-backup-and-dr.md`, `09-sla.md` |

> **Legal notice.** This document is a working draft of the Data Processing Addendum that customers will be asked to accept. It is **not** a legal opinion and is **not** a substitute for review by qualified counsel. Before this document is offered to customers as binding, it must be reviewed and adjusted by a privacy lawyer competent in the jurisdictions Nano EASM serves (Australia primary; EU / UK / US likely). The structure below is informed by GDPR-style frameworks, the EU Standard Contractual Clauses (SCCs), and common SaaS DPA practice — but the **specific legal language a court would enforce is for counsel to write, not engineers**.

---

## 1. Purpose and scope

This Data Processing Addendum ("**DPA**") forms part of the agreement between **Nano EASM Pty Ltd** ("**Nano EASM**", "**we**", "**Processor**") and the customer ("**Customer**", "**you**", "**Controller**") under which Nano EASM provides the Service. It governs how Nano EASM processes Personal Data on the Customer's behalf.

This DPA applies whenever Customer Personal Data is processed by Nano EASM. To the extent this DPA conflicts with the main agreement, this DPA prevails for matters of personal-data processing.

---

## 2. Definitions

Capitalised terms have the meanings given here, complemented by the meanings under applicable data-protection law where stricter.

| Term | Meaning |
|---|---|
| **Applicable Law** | All laws, regulations, codes, and standards in force in any jurisdiction where Nano EASM processes Personal Data on the Customer's behalf, including the GDPR, the UK GDPR, the Australian Privacy Act 1988 (Cth), and US state privacy laws to the extent applicable |
| **Controller** | The natural or legal person determining purposes and means of processing — typically the Customer |
| **Customer Data** | Data the Customer or its users submit to or generate within the Service, including Personal Data |
| **Data Subject** | An identified or identifiable natural person whose Personal Data is processed |
| **Personal Data** | Any information relating to an identified or identifiable natural person within Customer Data |
| **Personal Data Breach** | A breach of security leading to accidental or unlawful destruction, loss, alteration, unauthorised disclosure of, or access to, Personal Data |
| **Processor** | The entity processing Personal Data on the Controller's behalf — Nano EASM |
| **Sub-processor** | A third party engaged by Nano EASM that processes Personal Data on the Controller's behalf |
| **Processing** | Any operation performed on Personal Data — collection, storage, use, disclosure, deletion |

---

## 3. Roles

For the purpose of this DPA:

- The **Customer** is the **Controller** of Customer Personal Data.
- **Nano EASM** is the **Processor** of Customer Personal Data, acting only on documented instructions from the Customer.
- Each party shall comply with its obligations under Applicable Law.

Nano EASM is **not** a Controller in respect of Customer Personal Data (it is a Controller of its own internal records — billing contact information, the founder's accounts, etc., which are out of scope of this DPA).

---

## 4. Customer instructions and processing scope

### 4.1 Documented instructions

Nano EASM will process Personal Data only on the Customer's documented instructions, including:
- The instructions set out in the main agreement and this DPA.
- The instructions inherent in the Customer's use of the Service (e.g., adding an asset, running a scan, generating a report).
- Any further written instructions from the Customer that Nano EASM accepts as compatible with the Service.

If Nano EASM is required by law to process Personal Data outside these instructions, we will notify the Customer before doing so unless that law prohibits notification.

### 4.2 Subject matter, nature, and purpose

| Item | Description |
|---|---|
| **Subject matter** | Provision of the Nano EASM external attack surface management Service |
| **Nature of processing** | Collection, storage, organisation, retrieval, use, disclosure (to Sub-processors), erasure |
| **Purpose** | Enabling the Customer to discover, scan, monitor, and report on its external attack surface |
| **Categories of Data Subjects** | The Customer's authorised users (administrators, analysts, viewers); and **incidentally**, individuals whose data appears in the Customer's discovered assets (e.g., subdomains containing employee names, public profile IDs) |
| **Categories of Personal Data** | Names, email addresses, IP addresses, login metadata (user agent, timestamp), authentication credentials (hashed only); Customer asset metadata that may incidentally contain personal data |
| **Special-category data** | Not intentionally processed. The Service is not designed for and the Customer must not submit special-category data (health, biometric, etc.) |
| **Duration** | For the term of the agreement, plus the retention periods set out in §10 below |

### 4.3 Limits

The Service is **not** designed to receive or process:
- Special-category Personal Data under GDPR Art. 9 (health, biometric, racial or ethnic origin, etc.).
- Children's data (Data Subjects under 16 / 13 depending on jurisdiction).
- Payment card data (PCI scope is fully delegated to Stripe).

The Customer warrants it will not submit such data to the Service.

---

## 5. Confidentiality and access

Nano EASM will:
- Ensure that personnel authorised to process Customer Personal Data are subject to a duty of confidentiality.
- Limit access to Customer Personal Data to personnel who need access for the purposes of providing the Service.
- Maintain a record of personnel with such access (today: one operator; recorded in the access register referenced in `05-security-policy.md` §5).

---

## 6. Security measures

Nano EASM has implemented technical and organisational measures appropriate to the risk, including those described in `03-sad/06-security-architecture.md` and `05-security-policy.md`. A summary:

| Domain | Measure |
|---|---|
| Encryption in transit | TLS for all customer-facing endpoints; TLS for outbound calls to Sub-processors |
| Encryption at rest | AWS-managed encryption on EBS volumes; column-level encryption for sensitive secrets is in roadmap |
| Authentication | Password + optional MFA (mandatory for elevated roles, when implemented); JWT-based sessions |
| Access control | RBAC (Owner / Admin / Analyst / Viewer); tenant-scoped queries; audit logging |
| Network | Single-host deployment with restricted ingress; outbound TLS only |
| Secrets management | OS-level file permissions on production secrets; documented rotation policy |
| Logging and monitoring | Application logs + audit logs; tenant-scoped surface for customer review |
| Backups | Nightly logical backup + nightly EBS snapshot; RPO 24 h |
| Vulnerability management | Pinned dependencies, quarterly upgrades, internal review |
| Personnel | FDE-encrypted laptops; mandatory 2FA on all production-relevant SaaS |
| Disposal | Cryptographic erasure on disk decommissioning (AWS-managed) |

These measures may evolve over time. Nano EASM may update them provided that the security posture is not materially weakened. Material strengthening is communicated as part of routine product updates.

---

## 7. Sub-processors

### 7.1 Authorisation

The Customer authorises Nano EASM to engage Sub-processors to process Customer Personal Data, subject to the conditions in this clause.

### 7.2 Current Sub-processors

As at the date of this DPA:

| Sub-processor | Role | Region | Personal Data shared |
|---|---|---|---|
| Amazon Web Services, Inc. | Cloud infrastructure (compute, storage, DNS, backup) | `us-east-1` (United States) | All Customer Personal Data at rest and in transit on Nano EASM infrastructure |
| Stripe, Inc. | Payment processing | Global, US-headquartered | Billing-contact name, email, billing address, tokenised payment instrument |
| Resend, Inc. | Transactional email delivery | EU and US | Recipient email address; email content (verification links, receipts, alerts) |
| Shodan LLC | Service / port enrichment for scans | United States | Customer's asset IPs / domains submitted for enrichment |
| VirusTotal (Google LLC) | Optional reputation enrichment (when configured) | Global | Customer's IPs / domains, when explicitly configured |
| AbuseIPDB | Optional reputation enrichment (when configured) | United States | Customer's IPs, when explicitly configured |
| Google LLC (reCAPTCHA) | Bot defence on public surfaces | Global | Page-interaction signals from anonymous visitors (no Customer Personal Data) |

A current list is also maintained in `05-security-policy.md` §9 and is the canonical record.

### 7.3 New Sub-processors

Nano EASM will provide the Customer at least **30 days advance notice** before engaging a new Sub-processor that will process Customer Personal Data. The Customer may object on reasonable data-protection grounds within that period. If the Customer's objection cannot be resolved, the Customer may terminate the affected Service component on notice (sole and exclusive remedy).

### 7.4 Conditions imposed on Sub-processors

Nano EASM will ensure that each Sub-processor is bound by data-protection obligations no less protective than those in this DPA, by way of a written agreement (typically the Sub-processor's standard DPA / SCCs).

Nano EASM remains responsible for the Sub-processor's compliance.

---

## 8. International data transfers

### 8.1 Transfers from the EEA / UK / Switzerland

Where Customer Personal Data of EEA / UK / Swiss Data Subjects is transferred to Nano EASM or its Sub-processors outside those jurisdictions, the parties rely on:

- The **EU Standard Contractual Clauses** (Module 2 — Controller to Processor, where the Customer is the Controller; or Module 3 — Processor to Sub-processor, where applicable), in the form approved by the European Commission Decision (EU) 2021/914.
- The **UK International Data Transfer Addendum** issued by the UK ICO, where applicable.
- The **Swiss Addendum** to the SCCs, where applicable.

Where Nano EASM acts as exporter to a Sub-processor in a third country, the corresponding SCCs apply between Nano EASM and that Sub-processor.

### 8.2 Transfers to the United States

For transfers to US-based Sub-processors, the parties additionally rely on, where applicable:
- The **EU–US Data Privacy Framework**, where the Sub-processor is certified.
- The **UK extension** to the DPF.
- Supplementary measures (encryption in transit, strong authentication, vendor commitments) where DPF is not available.

### 8.3 Transfers from Australia

For transfers from Australia, Nano EASM operates consistently with Australian Privacy Principle 8 — transfer to overseas recipients with comparable protections.

---

## 9. Data Subject rights

### 9.1 Customer's role

The Customer is responsible for responding to requests from its users / Data Subjects exercising rights under Applicable Law (access, rectification, erasure, portability, restriction, objection).

### 9.2 Nano EASM's assistance

Nano EASM will, taking into account the nature of the processing:
- Provide reasonable assistance to the Customer in responding to such requests, by appropriate technical and organisational measures.
- Where Nano EASM receives such a request directly from a Data Subject, refer the Data Subject to the Customer (and notify the Customer where appropriate), unless required by law to respond directly.
- Provide self-service tooling where practical (the customer can export, delete, or anonymise individual users via the Settings → Members surface).

### 9.3 Costs

Where the Customer's requests for assistance are unreasonable in volume or complexity, Nano EASM may charge a reasonable fee. Routine assistance is included in the Service.

---

## 10. Retention and deletion

### 10.1 During the term

Customer Personal Data is retained per the retention policies in `02-srs.md` §6 and `03-sad/05-data-architecture.md` §8:

| Data class | Retention |
|---|---|
| User accounts, organisations, assets, scan jobs, findings | For the duration of the agreement, unless deleted by the Customer earlier |
| Audit logs | 90 days (Free / Starter), 1 year (Professional / Silver), 7 years (Gold / Custom) |
| Backups | 30 nightly, 12 monthly |
| Quick-scan log (anonymous; not tied to a Customer) | 30 days |
| Sent transactional email metadata | 30 days |

### 10.2 On termination

Within **30 days** of the effective date of termination of the agreement:
- Nano EASM will, at the Customer's option (specified in writing within 7 days of termination):
  - **Delete** all Customer Personal Data, including from backups (subject to backup-retention windows below); or
  - **Return** Customer Personal Data to the Customer in a structured, machine-readable format (typically JSON / CSV exports of the Customer's tenant).
- If no instruction is received within 7 days, Nano EASM will delete the data.

### 10.3 Backups

Customer Personal Data may persist in backups for up to **12 months** after deletion from the live Service, due to the backup-retention window. Backup-resident data is logically inaccessible to Service users, is overwritten on the standard rotation, and is processed only for backup integrity.

### 10.4 Records and audit logs

Nano EASM may retain audit logs and records of processing activity beyond the deletion window, where required by law, regulatory obligation, or for the establishment, exercise, or defence of legal claims. Such records are restricted in access and not used for any other purpose.

---

## 11. Personal Data Breach notification

### 11.1 Nano EASM's commitments

Nano EASM will:
- Notify the Customer **without undue delay**, and in any event within **72 hours of becoming aware** of a Personal Data Breach affecting Customer Personal Data.
- Provide, in stages as information becomes available:
  - Description of the nature of the breach.
  - Categories and approximate number of Data Subjects and records affected.
  - Likely consequences.
  - Measures taken or proposed to address the breach and mitigate effects.

### 11.2 Cooperation

Nano EASM will cooperate reasonably with the Customer's own breach-notification obligations to regulators and Data Subjects under Applicable Law.

### 11.3 What is not a breach

Unsuccessful access attempts, failed login attempts, and similar routine security events that do not result in unauthorised access are not Personal Data Breaches. The audit log captures these for the Customer's review without triggering a breach notification.

---

## 12. Audits and information

### 12.1 Information

Nano EASM will, on the Customer's reasonable written request, make available to the Customer information necessary to demonstrate compliance with this DPA, including:
- This DPA and supporting policies (security policy, threat model, architecture documentation).
- The current Sub-processor list.
- Description of technical and organisational measures (this document and `05-security-policy.md`).
- Recent third-party security attestations, if applicable.

### 12.2 Audits

The Customer may, on reasonable advance notice (≥ 30 days) and at the Customer's expense:
- Conduct or have conducted by an independent third-party auditor (subject to confidentiality undertakings) an audit of Nano EASM's compliance with this DPA.
- Audits are limited to once per 12-month period unless triggered by a Personal Data Breach.
- Audits are conducted during normal business hours and in a way that does not unreasonably disrupt Nano EASM's operations.
- Where Nano EASM holds a recent third-party attestation (e.g., SOC 2 Type II, ISO 27001) covering the audit's scope, Nano EASM may provide that attestation in lieu of an on-site audit, and the Customer agrees to accept it as substantive evidence.

Nano EASM does not currently hold SOC 2 Type II or ISO 27001 certifications; the path to obtaining such certifications is on the platform roadmap and will be communicated to Enterprise customers when material progress is made.

---

## 13. Liability

The liability of each party under this DPA is subject to the exclusions and limitations of liability in the main agreement. Nothing in this DPA limits any party's liability for matters that cannot be limited by law (gross negligence, wilful misconduct, fraud, death, or personal injury).

---

## 14. Term

This DPA is effective on the effective date of the main agreement and remains in force for as long as Nano EASM processes Customer Personal Data on the Customer's behalf. Provisions that by their nature should survive termination (deletion, audit, breach notification for past events) survive accordingly.

---

## 15. Governing law

This DPA is governed by the law that governs the main agreement, except where mandatory data-protection law or the SCCs require otherwise. For SCCs, the Member-State law specified in the SCCs themselves applies.

---

## 16. Order of precedence

In the event of conflict between:
1. Mandatory data-protection law,
2. The SCCs (where incorporated),
3. This DPA,
4. The main agreement,

precedence applies in the order listed.

---

## 17. Amendments

Nano EASM may update this DPA on **60 days written notice** to existing Customers, where the update is necessary to:
- Comply with Applicable Law.
- Reflect changes in security measures (provided they do not materially weaken the posture).
- Reflect changes to the Sub-processor list (within the bounds of §7.3).

Material amendments unfavourable to the Customer give the Customer a 30-day window to terminate without penalty.

---

## 18. Contact

For matters relating to this DPA:
- **Data Protection Contact:** founder@nanoasm.com (placeholder; canonical address via the main agreement)
- **Security incidents:** `security@nanoasm.com` (planned; today via support channel)
- **Subject access requests on behalf of users:** the Customer's own admin tools, with assistance per §9

---

## 19. Schedules

The following schedules form part of this DPA:

- **Schedule 1 — Description of Processing** (matters in §4.2 above).
- **Schedule 2 — Technical and Organisational Measures** (matters in §6 above; cross-reference to `05-security-policy.md`).
- **Schedule 3 — Sub-processor list** (matters in §7.2 above; canonical version maintained in `05-security-policy.md` §9).
- **Schedule 4 — Standard Contractual Clauses** (the SCCs themselves, attached when required by the Customer's transfer scenario).

These schedules may be updated as set out in this DPA.

---

## 20. References

- `02-srs.md` §6 — data classification and retention policy
- `03-sad/05-data-architecture.md` §8 — retention mechanism
- `03-sad/06-security-architecture.md` — technical measures
- `05-security-policy.md` — organisational measures, incident response, sub-processor list
- `08-backup-and-dr.md` — backup behaviour, RPO / RTO
- `09-sla.md` — availability commitments (separate from data-processing commitments)
- GDPR (Regulation (EU) 2016/679); UK GDPR; Australian Privacy Act 1988 (Cth); applicable US state privacy laws

---

*End of 10 DPA.*
