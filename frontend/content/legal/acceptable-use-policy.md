# Acceptable Use Policy

**Effective date:** 1 May 2026
**Last updated:** 1 May 2026

This Acceptable Use Policy (**"AUP"**) sets out what you can and
cannot do with Nano EASM (the **"Service"**). It is incorporated into
and governed by the [Terms of Use](./terms-of-use.md). Capitalised
terms used here have the meanings given in the Terms of Use.

A breach of this AUP is a breach of the Terms of Use. We may suspend
or terminate any Account or Organisation that violates it.

---

## 1. The core rule: authorised targets only

You may only submit assets to the Service — and only direct any of
its discovery, scanning, or monitoring features at — assets that:

1. you own and have authority to scan, or
2. you have prior written permission from the asset owner to test.

This includes domains, subdomains, IP addresses, IP ranges, cloud
assets, and any other identifier you submit.

You are **solely responsible** for the legal and operational
consequences of any scan you initiate. The Service does not
pre-validate ownership.

For the controlling authorisation language, see
[Security & Scanning Authorisation](./security-scanning-authorisation.md).

## 2. Prohibited activities

You must not use the Service to:

### 2.1 Unauthorised scanning or attack

- Scan, probe, enumerate, or fingerprint systems you are not
  authorised to test.
- Perform denial-of-service (DoS), distributed denial-of-service
  (DDoS), brute-force, password-spraying, or credential-stuffing
  attacks against any system.
- Use the Service as part of an attack chain — e.g. as a
  reconnaissance step in an unauthorised intrusion, or to deliver
  malware, ransomware, phishing payloads, or command-and-control
  traffic.
- Generate scan traffic intended to disrupt, overwhelm, or degrade
  any third-party system.

### 2.2 Circumvention

- Circumvent or attempt to circumvent rate limits, plan limits,
  feature gates, IP blocks, abuse controls, or any other access
  control we have put in place.
- Create multiple accounts, organisations, or personas to evade
  per-tenant limits or to extend free-tier usage beyond fair use.
- Use proxies, VPNs, or anonymisation networks to evade IP-level
  abuse controls or to mask the origin of scanning traffic.

### 2.3 Misuse of data

- Use the Service to harvest personal data for harassment,
  doxxing, stalking, or any unlawful purpose.
- Submit assets, scan targets, or other Customer Data that you do
  not have the legal right to process.
- Use scan output to facilitate identity theft, fraud, or
  unauthorised access.

### 2.4 Service integrity

- Reverse-engineer, decompile, or disassemble the Service except to
  the extent expressly permitted by applicable law.
- Probe, scan, or test the vulnerability of the Service itself,
  except via a coordinated disclosure programme (see §6).
- Interfere with, disrupt, or deny service to other users,
  including by submitting workloads that consume disproportionate
  resources.
- Scrape, mirror, or systematically extract content from the
  Service, including finding templates, asset intelligence
  enrichment data, or admin views.

### 2.5 Account integrity

- Share login credentials between users — every Authorised User
  must have their own account. (Note: organisation-level resources
  are shared with Authorised Users by design.)
- Misrepresent your identity, affiliation, or authority when
  registering or using the Service.
- Resell, sublicense, or repackage the Service to third parties
  without a prior written agreement (e.g. an MSSP/reseller
  agreement).

### 2.6 Legal compliance

- Use the Service in any way that violates applicable law,
  including computer misuse, anti-hacking, wiretap, data
  protection, sanctions, or export-control laws.
- Use the Service from, or to scan assets within, any jurisdiction
  where such use would be unlawful or where we are prohibited from
  providing the Service.

## 3. Quick-scan abuse policy

The unauthenticated quick-scan tools at https://nanoasm.com let
anyone run a one-off scan against a target without registering. They
are subject to additional rules:

- **Logging.** Every quick-scan request is logged with the
  submitter's IP address, user agent, target, request status, and
  timestamp. This log is retained for abuse prevention.
- **Rate limits.** Quick-scan requests are rate-limited per IP
  address (currently 5 scans per hour). Exceeding the limit returns
  HTTP 429 and is recorded.
- **IP blocking.** Repeated abuse — including attempts to scan
  systems you do not own, automated scripted use of the public
  tools, or attempts to evade rate limits — may result in
  IP-level blocking without notice. Blocks may be temporary or
  permanent.
- **No expectation of service.** Quick-scan capacity is best-effort
  and may be reduced or withdrawn at any time.

## 4. Resource fair use

Paid plans have explicit limits documented in your plan summary
(assets, scans/month, monitored assets, scheduled scans, etc.).
Within those limits, normal use is welcome.

We reserve the right to take action — including throttling or
suspension — if your usage:

- creates a sustained capacity strain disproportionate to your plan,
- causes platform-wide performance issues,
- appears designed to inflate consumption for the purpose of
  re-quoting, denial-of-resource against others, or exhausting
  third-party API quotas (e.g. Shodan credits) we operate under.

If you have a legitimate need for higher capacity, contact us via
the [contact form](https://nanoasm.com/#contact) — we'd rather raise
your limits than throttle you.

## 5. Reporting violations

If you believe someone is using the Service in violation of this
AUP — including scanning assets they don't own — report it to
**contact@nanoasm.com**. Where possible, include:

- the time and date of the activity,
- the target asset (if known) or other identifying details,
- any evidence (logs, screenshots, headers).

We investigate all credible reports.

## 6. Reporting vulnerabilities in Nano EASM itself

If you discover a security vulnerability in the Service, please
disclose it responsibly via **contact@nanoasm.com**. We commit to:

- acknowledging your report within a reasonable timeframe,
- coordinating disclosure timelines with you,
- not pursuing legal action against good-faith researchers who
  follow these guidelines and do not access, modify, or exfiltrate
  data beyond what is necessary to demonstrate the issue.

## 7. Enforcement

Where we identify a breach or suspected breach of this AUP, we may,
at our discretion and without prior notice:

- issue a warning,
- temporarily suspend the Account, Organisation, or specific
  feature,
- terminate the Account or Organisation,
- block the source IP address (for unauthenticated abuse),
- preserve and disclose relevant data to law enforcement where
  required by law or where we reasonably suspect serious harm.

The action we take depends on the severity, intent, and recurrence
of the breach. Material or wilful breaches may result in immediate
termination without refund.

## 8. Changes to this AUP

We may update this AUP from time to time. Material changes will be
communicated via the Service or by email to account holders.
Continued use after the effective date constitutes acceptance.

## 9. Contact

- Report abuse: **contact@nanoasm.com**
- Report vulnerabilities: **contact@nanoasm.com**
- General contact: https://nanoasm.com/#contact
