# Security & Scanning Authorisation

**Effective date:** 1 May 2026
**Last updated:** 1 May 2026

This document is the **controlling authorisation language** for any
discovery, scanning, monitoring, or testing performed using the
Service. It is incorporated into the [Terms of Use](./terms-of-use.md)
and the [Acceptable Use Policy](./acceptable-use-policy.md).

The defined terms used here have the meanings given in the Terms of
Use.

---

## 1. Purpose

Active reconnaissance and vulnerability scanning is a sensitive
activity. In most jurisdictions, performing it against systems you
do not own or are not explicitly authorised to test is a criminal
offence — regardless of intent — under laws such as:

- **Part 10.7 of the Criminal Code Act 1995 (Cth)** and the
  **Cybercrime Act 2001 (Cth)** (Australia),
- the **Computer Misuse Act 1990** (United Kingdom),
- the **Computer Fraud and Abuse Act** (United States),
- the **Cybercrime Convention** implementations in EU member states,
- equivalent legislation in your own jurisdiction.

This document records what you affirm every time you submit an asset
to, or initiate a scan via, the Service — both interactively and
programmatically.

## 2. Authorisation warranty

By submitting any asset (domain, subdomain, IP address, IP range,
cloud asset, URL, or other identifier) to the Service for discovery,
scanning, monitoring, or any other security-testing function, **you
represent and warrant** that:

1. **Authority.** You either (a) own the asset and have the legal
   authority to authorise security testing of it, or (b) hold prior
   written permission from the person or entity that does, valid
   for the duration of the testing.

2. **Scope.** Your authority covers the specific testing activities
   the Service will perform — including external port scanning, DNS
   enumeration, subdomain discovery, certificate inspection, web
   request probing, vulnerability checks against discovered services,
   and continuous monitoring of the asset and its derivatives.

3. **Compliance.** Your use of the Service complies with all
   applicable laws and regulations in (i) the jurisdiction in which
   you are located, (ii) the jurisdiction in which the asset is
   hosted, and (iii) any other jurisdiction whose computer-misuse
   laws are relevant to the testing.

4. **No third-party harm.** You will not direct the Service at
   systems or networks belonging to a third party for the purpose of
   reconnaissance preceding an unauthorised intrusion, harassment,
   competitive intelligence gathering, or any other unlawful
   purpose.

5. **Termination on loss of authority.** If your authority to test an
   asset is revoked, expires, or otherwise ends, you will remove the
   asset from the Service promptly and not initiate further scans
   against it.

These warranties apply equally to assets submitted via the web
interface, the API, scheduled scans, monitor configurations, and the
unauthenticated quick-scan tools.

## 3. What counts as "authority to test"

Acceptable forms of authority include, in approximate order of
strength:

- **Direct ownership** — the asset is registered to, hosted by, or
  legally controlled by the legal entity you are using the Service
  on behalf of.
- **Written contract** — a signed contract or order form (e.g. a
  penetration testing engagement, MSSP services agreement, or
  internal authorisation) that names the asset and the scope of
  testing.
- **Statement of work / Rules of engagement** — a written document
  from the asset owner authorising specified testing activities for
  a specified period.
- **Bug bounty programme scope** — for assets explicitly listed as
  "in scope" in a published bug-bounty programme, where the
  programme rules permit the kind of testing the Service performs.

Acceptable forms of authority **do not** include:

- "I think it's probably okay."
- "It's publicly accessible on the internet."
- "I used to work there."
- "It belongs to a competitor."
- "It's an old system nobody uses any more."
- Reliance on `/security.txt`, generic responsible-disclosure pages,
  or social-media statements unless those documents expressly
  authorise the type of testing in question.

If you are not sure whether you have authority, do not submit the
asset.

## 4. Out-of-scope targets

The following must **never** be submitted to the Service, regardless
of any authority you believe you may have:

- Critical national infrastructure where testing is regulated
  (power grids, water utilities, air-traffic systems, signals
  intelligence systems).
- Government, military, or law-enforcement systems unless you have
  a contract that specifically permits unauthenticated external
  scanning.
- Healthcare systems subject to HIPAA, NHS Digital rules, or
  equivalent — unless authorised under a written engagement that
  has cleared compliance review.
- Systems located in jurisdictions where you are subject to
  sanctions or where we are prohibited from providing the Service.
- Shared cloud infrastructure where your authority extends only to
  your tenancy and the scan would unavoidably touch other tenants'
  resources.

Stripe, Resend, AWS, Cloudflare, and the other sub-processors
listed in our [Privacy Policy](./privacy-policy.md) are not your
property and may not be scanned via the Service.

## 5. Risk acknowledgement

You acknowledge that:

- Active scanning can, in some configurations, cause service
  disruption, generate alerts in third-party security products,
  trigger rate limits, or otherwise affect the target.
- Even properly authorised scans can produce false positives, false
  negatives, or stale findings.
- Findings, severity scores, and remediation guidance produced by
  the Service are best-effort and require your independent
  validation before being acted on.
- The Service is **not** a substitute for a manual penetration test
  or a qualified security review.

You assume responsibility for the operational and legal consequences
of every scan you initiate.

## 6. Indemnification

You agree to defend, indemnify, and hold harmless Nano EASM, its
operators, and its sub-processors from any claim, investigation,
loss, liability, or expense (including reasonable legal fees)
arising out of:

- a scan, discovery, or monitor configuration that you initiated
  against a system you did not have authority to test,
- a third-party complaint, abuse report, or law-enforcement inquiry
  relating to traffic the Service generated on your instruction,
- any breach of the warranties in §2.

This indemnification survives termination of your Account.

## 7. Logging and traceability

Every scan, discovery job, and monitor execution is logged with at
least the following metadata, retained as set out in the [Data
Handling & Retention Policy](./data-handling-retention.md):

- The Account that initiated it (or the source IP for unauthenticated
  quick-scans).
- The Organisation, target asset, scan profile, and timestamp.
- The configuration parameters used.
- The outcome (completed, failed, cancelled, blocked, rate-limited).

We may produce these logs in response to a lawful request from a
competent authority, in connection with an abuse complaint, or to
defend ourselves against a claim arising from your use of the
Service.

This is not a deterrent we hide. We are explicit about it because
it is part of the legal hygiene of a scanning service: every action
is attributable.

## 8. Where this language is presented to users

For clarity, this document is the controlling text. It is presented
to users at the points where authorisation matters most:

- **Registration.** During account creation, the user must check a
  box affirming the warranties in §2 before the account is created.
- **Adding an asset.** When an asset is added to the Service, the
  user is shown a confirmation that re-states the warranty.
- **Quick-scan tools.** Before an unauthenticated scan runs, the
  submitter is shown a warning that re-states the warranty and
  warns that the request will be logged.
- **API.** API documentation references this document; programmatic
  use is treated as ongoing affirmation of the warranties.

In each surface, the language is shorter than this document for
readability — but this document remains the controlling text.

### 8.1 Recommended click-through wording

For the registration checkbox:

> *"I agree to the [Terms of Use](./terms-of-use.md) and confirm I
> will only scan domains, IP addresses, or other assets that I own
> or am authorised to test."*

For the asset-add confirmation:

> *"By adding this asset, you confirm you own it or have written
> permission to scan it. Unauthorised scanning may be a criminal
> offence in your jurisdiction."*

For the unauthenticated quick-scan submit button:

> *"Quick scans are logged with your IP address. By submitting,
> you confirm you have authority to scan the target. See our
> [Acceptable Use Policy](./acceptable-use-policy.md)."*

## 9. Reporting suspected misuse

If you become aware that someone has used the Service to scan an
asset you control without authorisation, contact us at
**contact@nanoasm.com** with as much detail as you have (date, time,
target asset, source IP if known). We investigate every credible
report and will preserve relevant logs.

If you are a researcher reporting a vulnerability in the Service
itself (rather than an abuse of it), follow §6 of the [Acceptable
Use Policy](./acceptable-use-policy.md).

## 10. Changes

We may update this document from time to time. Material changes
will be communicated via the Service or by email to account holders.
Continued use of the Service after the effective date constitutes
ongoing affirmation of the updated warranties.

## 11. Contact

- Email: **contact@nanoasm.com**
- Web: https://nanoasm.com/#contact
