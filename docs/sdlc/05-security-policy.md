# 05 — Security Policy

| Field | Value |
|---|---|
| Document | 05 — Security Policy |
| Owner | Founder / sole engineer (acting as Security Lead) |
| Status | Draft |
| Effective from | 2026-05-05 |
| Next review | 2026-08-05 (quarterly) |
| Related docs | `02-srs.md`, `03-sad.md`, `04-threat-model.md`, `08-backup-and-dr.md` (forthcoming), `10-dpa.md` (forthcoming) |

---

## 1. Purpose

This policy is the **organisational** counterpart to the technical controls in the SAD and Threat Model. It states: who is accountable for what, what is expected of every person with access, how we handle incidents, how secrets are managed, and what discipline production access carries.

It is short on purpose. A 100-page policy that nobody reads is worse than a 20-page policy that everyone follows.

---

## 2. Scope

This policy applies to:
- Anyone with commit access to the Nano EASM repository.
- Anyone with administrative access to the EC2 host, AWS console, Stripe dashboard, Resend dashboard, GitHub organisation, or any other production system.
- Anyone with `is_superadmin=true` in the production database.
- Subprocessors and contractors who handle Nano EASM customer data.

Today, that is **one person**. The policy is written for the team we are growing into.

---

## 3. Roles and responsibilities

| Role | Held by | Responsibilities |
|---|---|---|
| Security Lead | Founder | Owns this policy; reviews quarterly; final call on any policy exception |
| Production Operator | Founder (today) | Holds production credentials; performs deploys; responds to incidents |
| Engineer | Anyone with commit access | Writes secure code; respects this policy; reports incidents |
| Customer Support | Founder (today) | Triages customer-reported issues; routes security reports to Security Lead within 1 business day |
| Data Protection Contact | Founder | Receives privacy / DPA / GDPR-style requests; routes per `10-dpa.md` |

Until the team grows past one person, every role is the same person; the **discipline** of treating these as distinct hats is what matters. When we hire, we split the hats explicitly.

---

## 4. Acceptable use

Anyone with access to Nano EASM systems agrees:

1. **Use access only for legitimate work.** Curiosity is not a legitimate reason to read a customer's tenant data.
2. **Do not store production secrets** outside of the approved locations (the `.env` file on the production host; password manager; the team's documented secret-handling tools).
3. **Do not commit secrets to git**, including in branches that "won't be merged." Once it is in `.git`, it is in the history forever.
4. **Do not run production data through third-party AI / chat tools** unless the tool is on the approved subprocessor list and the data class permits it.
5. **Report a suspected incident** (lost laptop, suspicious access, accidentally published secret, anything) **immediately** — see §10.

Violations are grounds for revocation of access. Wilful violations are grounds for termination of contract / employment.

---

## 5. Account and access management

### 5.1 Production-system access

| System | Granted by | Form |
|---|---|---|
| EC2 SSH | Security Lead | SSH key, FDE-encrypted laptop |
| AWS console | Security Lead | IAM user, mandatory 2FA, scoped policies |
| GitHub repo | Security Lead | GitHub account, mandatory 2FA |
| Stripe dashboard | Security Lead | Account, mandatory 2FA, role-scoped |
| Resend dashboard | Security Lead | Account, mandatory 2FA |
| Production DB shell | (No direct access; via backend container `flask shell`) | Same as EC2 SSH |
| Superadmin (`is_superadmin`) | Security Lead, granted via `flask grant-superadmin` | One per actual operator; no service accounts |

### 5.2 Principle of least privilege

- Engineers do **not** automatically get production access. Production access is a separate grant with a documented business reason.
- Superadmin is **not** required for normal engineering work. Code can be reviewed, tested, and shipped without it. Superadmin is a customer-support / incident-response tool.
- The number of people with each access tier is recorded (today: 1) and reviewed quarterly.

### 5.3 Joiner / mover / leaver

When the team is more than one person:

| Event | Action | Done by | SLA |
|---|---|---|---|
| Joiner | Provision named accounts; document grants in access register | Security Lead | Day 1 |
| Mover (role change) | Re-evaluate access against new role; revoke unneeded | Security Lead | Within 5 business days |
| Leaver | Revoke **every** access on the same business day; rotate any shared / unrotatable secret they touched | Security Lead | Within 24 hours of separation |

There are no shared accounts. If a leaver had access to a system that does not support per-user accounts, that secret rotates on departure.

### 5.4 Authentication requirements

- **Workstation:** full-disk encryption mandatory; screen lock ≤ 10 minutes; OS auto-update on.
- **Password manager:** mandatory for any non-SSO production credential.
- **2FA:** mandatory on every external SaaS that supports it (GitHub, AWS, Stripe, Resend, etc.). TOTP or hardware key; SMS not accepted.
- **MFA on Nano EASM superadmin accounts:** mandatory once FR-AUTH-017 ships (currently a gap; tracked in `00-positioning-pivot-tasks.md` §10.1).
- **Passwords:** minimum 16 characters, generated by password manager. No reuse across systems.
- **SSH keys:** ed25519 or rsa-4096; passphrase-protected; not shared between machines.

---

## 6. Secrets management

### 6.1 Where secrets live

| Class | Today | Future |
|---|---|---|
| Production application secrets (DB password, JWT secret, Stripe keys, Resend, Shodan, etc.) | `~/boltedge-easm/.env` on EC2, mode 600 | AWS Secrets Manager / SSM Parameter Store (planned, scaling step) |
| Personal credentials (engineer SSH keys, AWS console, GitHub) | Engineer's password manager + 2FA | Same |
| Customer-supplied integration secrets (Slack webhook, Jira API token, audit-webhook secret) | Hashed/encrypted in DB | Same; encryption at rest column-level |
| Backups | EBS-encrypted volume | S3 with SSE-KMS (planned) |

### 6.2 Rotation

| Secret | Cadence | On-event rotation |
|---|---|---|
| Personal account passwords | – (long, unique, password-manager managed) | Immediately on suspected compromise |
| 2FA seeds | – (per device) | Immediately on device loss |
| SSH keys | Annually | Immediately on laptop loss / suspected compromise |
| `SECRET_KEY` (JWT signing) | – | On suspected compromise; invalidates all sessions |
| `STRIPE_*` | When Stripe rotates | On suspected compromise |
| `RESEND_API_KEY` / `SHODAN_API_KEY` / etc. | Annually | On suspected compromise |
| Postgres password | Annually | On suspected compromise |
| TLS cert | 60–90 days, automated by certbot | Manual issuance if certbot fails |

The rotation cadence is conservative — annual for low-risk vendor keys is acceptable while access is tightly scoped. If we increase the operator headcount, the cadence on shared secrets shortens.

### 6.3 What is forbidden

- Committing any secret to git.
- Sending a secret in Slack / chat / email — use a vault link.
- Pasting secrets into AI / LLM prompts.
- Storing secrets in unencrypted text files outside the approved locations.
- Sharing personal credentials between people.

---

## 7. Code and change management

### 7.1 Code review

- Every change to the production codebase merges via PR.
- At least one human reviewer who is not the author. (When the team is one person, this is a known compensating gap — peer review is mocked by tooling and self-review with a 24-hour gap when feasible.)
- Reviewer signs off on: correctness, security implications, tenant-scoping, test coverage, scope discipline.
- AI-assisted commits are reviewed with the same care as human-authored commits.

### 7.2 Branch protection

GitHub branch protection on `master`:
- PR required; direct push disallowed.
- CI green required.
- Force-push disallowed.
- Branch deletion of `master` disallowed.

### 7.3 Deployment

- Production deploys happen from the EC2 host: `git pull && docker compose up -d --build`.
- Migrations are applied explicitly (`flask db upgrade`) and reviewed before deployment.
- Rollback is `git checkout <prev-sha> && docker compose up -d --build`.
- Destructive database operations (drops, large deletes) require explicit pre-approval and are accompanied by a verified backup taken within the previous hour.
- A deploy that requires breaking changes is split into expand/contract migrations (§03 SAD Development View §8).

### 7.4 Hotfix protocol

- A genuine emergency (active outage, security regression in production) may bypass the normal review window — but never CI, never branch protection.
- Any hotfix is followed by a same-week post-mortem and the PR is filed for retroactive review.

---

## 8. Data classification

| Class | Examples | Handling |
|---|---|---|
| **Public** | Marketing copy, public docs, finding-template catalogue | No restrictions |
| **Internal** | Architecture docs (this directory), internal runbooks | Repo-restricted |
| **Customer data** | Asset inventory, scan results, findings, audit logs | Tenant-scoped; see SRS §6 |
| **Sensitive customer data** | API keys (hashed), integration secrets, billing details | As above + encryption at rest where supported |
| **Crown jewels** | Password hashes, MFA secrets (planned), Stripe webhook secret, JWT signing key | As above + special handling: never logged, never returned by API beyond what's strictly necessary, rotated on incident |

The retention policy per class lives in SRS §6 and `08 Backup & DR`. The classification here is the input to those.

---

## 9. Vendor / subprocessor management

We use third-party services that process customer data on our behalf. The current list (kept current; the canonical version lives in `10-dpa.md`):

| Subprocessor | Purpose | Data | Region |
|---|---|---|---|
| AWS (EC2, EBS, Route 53) | Hosting | All persisted data | `us-east-1` |
| Stripe | Payment processing | Billing details (name, email, payment method tokenised by Stripe) | Global |
| Resend | Transactional email | Email recipient + message body | EU/US |
| Shodan | Service / port enrichment | Customer's asset IPs sent for enrichment | US |
| VirusTotal | Optional reputation enrichment | Customer's IPs / domains, when configured | US |
| AbuseIPDB | Optional reputation enrichment | Customer's IPs, when configured | US |
| Google reCAPTCHA | Bot defence on public surfaces | Page interaction signals (no customer data per se) | Global |

Adding a new subprocessor requires:
1. Documented business reason.
2. Security Lead review of the vendor's posture (SOC 2 / ISO 27001 attestation, DPA terms).
3. Update to `10-dpa.md`.
4. Customer notification per the DPA's terms (today, the bar is "subprocessors named in the DPA"; the DPA reserves the right to add with notice).

---

## 10. Incident response

### 10.1 What counts as an incident

| Severity | Examples |
|---|---|
| **SEV-1** | Cross-tenant data leak; production breach of customer data; widespread outage > 1 hour; payment processor failure for > 24 hours |
| **SEV-2** | Unauthorised access to a single tenant; partial outage > 30 minutes; security regression discovered in production |
| **SEV-3** | Suspicious activity not yet confirmed as compromise; degraded vendor service; transient outage |
| **SEV-4** | Near-miss; security-relevant bug found internally before exploitation |

### 10.2 Response process

```
0.  Detect or receive report
1.  Acknowledge — Security Lead within 1 business hour for SEV-1/2
2.  Assess — confirm severity; identify scope; preserve evidence (logs, audit rows)
3.  Contain — stop the bleeding (revoke key, block IP, take system offline if necessary)
4.  Eradicate — fix the root cause
5.  Recover — restore service; verify integrity
6.  Notify — affected customers, regulators (per 10-dpa.md), payment processor (if billing impacted)
7.  Post-mortem — within 5 business days for SEV-1/2; document timeline, root cause, remediation
8.  Follow-up — file tracked work items for systemic improvements
```

### 10.3 Customer notification

For incidents involving customer data:

- **Confirmed leak / unauthorised access:** notify affected customers within **72 hours** of confirmation, per `10-dpa.md` and applicable law (GDPR Article 33 sets the regulator-notification benchmark at 72 hours; we hold ourselves to the same window for customer-direct notification).
- **Suspected but unconfirmed:** investigate first; notify if confirmation arrives or if the investigation passes 5 business days without resolution.
- **Outage > 1 hour:** notify proactively via status channel.

Notification content: what happened, when, what data was affected, what we have done, what the customer should do (rotate keys, etc.), how we are preventing recurrence.

### 10.4 Reporting channels

| Reporter | Channel |
|---|---|
| Customer | `security@nanoasm.com` (planned — currently `contact@nanoasm.com`); any support channel |
| External researcher | `security@nanoasm.com`; vulnerability disclosure policy on `/security` (planned) |
| Internal | Direct message to Security Lead; chat thread |

We commit to acknowledging external security reports within **2 business days** and providing a substantive response within **10 business days**.

---

## 11. Vulnerability disclosure

External researchers acting in good faith may submit findings to `security@nanoasm.com`. The policy:

- We will not pursue legal action against good-faith researchers who follow this policy.
- Good faith means: do not access data beyond what is required to demonstrate the issue; do not disrupt service; do not exfiltrate or publicly disclose customer data; give us a reasonable period (generally 90 days) before public disclosure.
- A formal Vulnerability Disclosure Policy (VDP) page at `/security` will be published.
- We do not currently run a paid bug bounty. We can offer acknowledgement on a security-acknowledgements page for reporters who request it.

---

## 12. Logging, monitoring, audit

- The platform writes structured **application logs** (operations) and **audit logs** (privileged actions). See SAD §08 Observability and §05 Data §3.4.
- Audit logs are append-only; retention is plan-tier-dependent (90d / 1y / 7y; SRS §6).
- Access to audit logs is per-tenant for that tenant; platform-wide for superadmins.
- Customer-configured audit-webhook stream gives the customer their own immutable copy in their SIEM.

The expectation: any privileged action — login, role change, scan kickoff, finding status change, integration secret view, plan change, superadmin action — produces an audit row. If you find an action that doesn't, it is a bug.

---

## 13. Privacy

- We collect only the personal data we need: email + name (user), org name, billing details (when billing is on), and authentication metadata (IP for rate-limiting; user agent on login).
- We do not sell personal data.
- We process customer data per `10-dpa.md`.
- Subject access / deletion / portability requests go to the Data Protection Contact (§3) and are handled per the DPA's terms (typically within 30 days).
- We do not use customer data to train AI models.

---

## 14. Compliance posture

We make claims aligned to the **machine-mappable** frameworks (OWASP ASVS 4.0, CIS Controls v8, NIST CSF v2.0, PCI-DSS 4.0). For SOC 2 and ISO 27001 we say: *"we surface findings that may inform your compliance evidence — verify with your auditor."* We do **not** claim "audit-ready for SOC 2" or "ISO 27001 certified" until we hold the relevant attestation.

The compliance-mapping detail lives in `backend/app/scanner/compliance_map.py` and is surfaced in the product. The marketing posture is documented in CLAUDE.md "Compliance Framework Mappings" — it is enforced by code structure and product copy, not by hope.

---

## 15. Backup and recovery

Detailed backup and DR procedures are in `08-backup-and-dr.md` (forthcoming). The policy-level commitments:

- **RPO** (recovery point objective) — 24 hours. Daily `pg_dump` + nightly EBS snapshot.
- **RTO** (recovery time objective) — 4 hours for SEV-1 outages.
- Backup restoration is tested **quarterly** against a non-production environment.
- Backups are retained: 30 nightly + 12 monthly snapshots.

---

## 16. Workstation and physical security

- Engineer laptops: FDE encryption (FileVault / BitLocker / LUKS); screen lock ≤ 10 minutes; OS auto-update.
- Mobile devices that can read production email or 2FA: passcode / biometric required.
- Lost device: Security Lead notified within **1 hour of discovery**; rotate all credentials the device had access to within **24 hours**.

We do not have an office; remote-first. There is no physical "production environment" we control beyond AWS data centres.

---

## 17. Acceptable AI / tooling use

AI assistants (Claude Code, Cursor, GitHub Copilot, etc.) are used in development. Rules:

- Source code is not customer data; pasting source code into AI tooling is permitted.
- **Production data** (database dumps, customer scan results, audit logs, API keys) is **not** pasted into AI tooling.
- Prompts and responses produced for production-affecting work are reviewed with the same care as any human contribution.
- AI-generated code passes the same code review and CI as any other code.
- Outputs that touch security-sensitive surfaces (auth, tenant scoping, secret handling) get extra scrutiny — the reviewer assumes the AI does not understand the load-bearing invariants.

---

## 18. Policy exceptions

Any deviation from this policy requires:
1. Written request to the Security Lead, naming the deviation, the scope, and the duration.
2. Risk assessment from the Security Lead.
3. Compensating control documented.
4. Expiry date — exceptions are time-bounded.

Exceptions are recorded. Any exception > 90 days warrants amending the policy itself.

---

## 19. Review and amendment

- This policy is reviewed **quarterly** by the Security Lead.
- Material amendments are committed via PR with the change visible in `git log`.
- Last-reviewed date at the top of this document is updated on every review (even if no changes).
- Major reviews coincide with: customer-facing security events, hiring beyond the founding team, multi-region deployment, significant architectural changes (queue, multi-host, cache).

---

## 20. References

- `02-srs.md` — security requirements (NFR-SEC-*)
- `03-sad.md` and views — implementation of controls
- `04-threat-model.md` — threats this policy addresses
- `08-backup-and-dr.md` (forthcoming) — recovery procedures
- `10-dpa.md` (forthcoming) — Data Processing Addendum (customer-facing)
- AWS shared responsibility model — assumed reference for what AWS handles
- OWASP ASVS 4.0 — referenced for application-layer controls

---

*End of 05 Security Policy.*
