# Nano EASM — Finding Template Catalogue

_Auto-generated from `backend/app/scanner/templates.py` on 2026-05-08._

**Total templates registered: 341**

This catalogue is the single source of truth for every finding the platform produces. Each template carries the title, description, remediation, severity, CWE, references, and monitoring metadata that gets surfaced in the UI, in PDF reports, in email alerts, and inside the Nano EASM Assistant explainer.

Placeholders rendered at scan time: `{asset}`, `{value}`, `{port}`, `{provider}`, `{url}`, `{cname_target}`, `{service}`, `{cve}`, `{header_name}`, `{path}`. Missing placeholders are left intact rather than blanked out.

## Index

- [DNS / Email Security](#dns--email-security) — 12 templates
- [Subdomain Takeover](#subdomain-takeover) — 44 templates
- [Cloud Asset Exposure](#cloud-asset-exposure) — 11 templates
- [Sensitive Path / Leak Detection](#sensitive-path--leak-detection) — 32 templates
- [Nuclei — Marquee CVEs](#nuclei--marquee-cves) — 42 templates
- [Nuclei — Other (panels, default-creds, misconfig, info-disclosure, generic)](#nuclei--other-panels-default-creds-misconfig-info-disclosure-generic) — 148 templates
- [SSL / TLS](#ssl--tls) — 13 templates
- [HTTP Security Headers](#http-security-headers) — 8 templates
- [HTTP / Redirects](#http--redirects) — 1 template
- [Cookie Security](#cookie-security) — 3 templates
- [Ports / Services](#ports--services) — 10 templates
- [CVE / Vulnerabilities](#cve--vulnerabilities) — 1 template
- [Technology Detection](#technology-detection) — 2 templates
- [Exposure Score](#exposure-score) — 1 template
- [Monitoring / Change Detection](#monitoring--change-detection) — 10 templates

## Severity legend

- **critical** — Immediate-action exposure. Active credential leaks, ransomware vectors, takeover-confirmed.
- **high** — Material risk that should be fixed in the current sprint.
- **medium** — Should be fixed but lower priority. Hardening gaps, weak-but-not-broken configs.
- **low** — Information disclosure or minor misconfiguration. Often a hardening win, not a vulnerability.
- **info** — Not a problem. Inventory or change-detection records.

---

## DNS / Email Security

_12 templates_

### `dns-zone-transfer-open`

**Severity:** CRITICAL · **CWE:** CWE-200 · **Category:** security_hygiene

**Title:** DNS zone transfer (AXFR) successful for {asset}

**Summary:** Your entire DNS zone is publicly downloadable, exposing your full infrastructure map.

**Description:**

> A DNS zone transfer (AXFR) was completed against a public nameserver, returning every record in the zone. Attackers now have a complete map of your subdomains, internal hostnames, mail servers, and IP allocations — a primary recon goldmine.

**Remediation:**

> Restrict AXFR to authorised secondary nameservers only. In BIND: allow-transfer { trusted-servers; }; in NSD/Knot: configure provide-xfr explicitly. Most managed DNS providers (Route 53, Cloudflare, Azure DNS, Google Cloud DNS) disable AXFR by default — if you see this finding on managed DNS, investigate the misconfiguration urgently.

**Tags:** `dns`, `zone-transfer`, `critical`
**Alert name:** Zone Transfer Exposed
**Monitor type:** `dns_change`

**References:**
- RFC 5936 — DNS Zone Transfer Protocol (AXFR)
- DNS-OARC — Zone Transfer Best Practices
- CWE-200: Exposure of Sensitive Information

---

### `dns-dmarc-none`

**Severity:** HIGH · **CWE:** CWE-290 · **Category:** security_hygiene

**Title:** DMARC policy is 'none' (monitoring only) for {asset}

**Summary:** DMARC is in monitor-only mode — spoofed emails still get delivered.

**Description:**

> DMARC for {asset} is published with p=none. Failed messages are still delivered — DMARC is only collecting reports, not enforcing. This is the right starting position, but staying here long-term means spoofed mail still reaches your customers.

**Remediation:**

> Review two weeks of DMARC aggregate reports (rua=) to confirm all legitimate senders are passing SPF or DKIM alignment, then raise the policy to p=quarantine for a week, and finally to p=reject. Use pct=25/50/75 to roll out gradually.

**Tags:** `dns`, `email`, `dmarc`
**Alert name:** DMARC Not Enforcing
**Monitor type:** `dns_change`

**References:**
- RFC 7489 §6.3 — Policies
- DMARC.org Deployment Guide

---

### `dns-no-dmarc`

**Severity:** HIGH · **CWE:** CWE-290 · **Category:** security_hygiene

**Title:** No DMARC record for {asset}

**Summary:** Your domain has no DMARC record, leaving email authentication unenforced.

**Description:**

> No DMARC record was found for {asset}. DMARC tells receiving servers what to do when SPF or DKIM checks fail, and gives you back reports about who's sending mail in your name. Without it, there's no enforcement and no visibility.

**Remediation:**

> Publish a DMARC TXT record at _dmarc.{asset}. Start with:
> "v=DMARC1; p=none; rua=mailto:dmarc@{asset}"
>
> p=none collects reports without affecting delivery. After two weeks of clean reports, move to p=quarantine, then p=reject.

**Tags:** `dns`, `email`, `dmarc`
**Alert name:** DMARC Record Missing
**Monitor type:** `dns_change`

**References:**
- RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- M3AAWG Sender Best Common Practices v3
- DMARC.org Deployment Guide

---

### `dns-no-spf`

**Severity:** HIGH · **CWE:** CWE-290 · **Category:** security_hygiene

**Title:** No SPF record for {asset}

**Summary:** Your domain has no SPF record, so anyone can send emails pretending to be you.

**Description:**

> No SPF (Sender Policy Framework) record was found for {asset}. SPF tells receiving mail servers which IP addresses are allowed to send email as your domain. Without it, attackers can spoof your address in phishing campaigns and your real mail is more likely to be flagged as spam.

**Remediation:**

> Inventory every service that sends email as {asset} (your mail provider, marketing tool, transactional sender, ticketing system). Publish an SPF TXT record at the apex listing all of them, ending with -all to reject everything else.
>
> Example for Google Workspace: "v=spf1 include:_spf.google.com -all".
>
> If you're not certain you've captured every sender, start with ~all (softfail) and tighten to -all once a week of DMARC reports comes back clean.

**Tags:** `dns`, `email`, `spf`
**Alert name:** SPF Record Missing
**Monitor type:** `dns_change`

**References:**
- RFC 7208 — Sender Policy Framework v1
- M3AAWG Sender Best Common Practices v3
- OWASP Email Security Cheat Sheet

---

### `dns-spf-plus-all`

**Severity:** HIGH · **CWE:** CWE-290 · **Category:** security_hygiene

**Title:** SPF record allows all senders (+all) for {asset}

**Summary:** Your SPF record allows anyone to send email as your domain — it's wide open.

**Description:**

> The SPF record for {asset} ends with +all, which means ANY server on the internet is authorised to send email as your domain. This completely defeats the purpose of SPF and is often the result of a copy-paste error during setup.

**Remediation:**

> Change +all to -all (hardfail) to reject unauthorised senders, or ~all (softfail) if you're still verifying which services send email for you. Never leave +all in production.

**Tags:** `dns`, `email`, `spf`, `misconfigured`
**Alert name:** SPF Allows All Senders
**Monitor type:** `dns_change`

**References:**
- RFC 7208 — Sender Policy Framework v1
- M3AAWG Sender Best Common Practices v3

---

### `dns-dmarc-no-rua`

**Severity:** MEDIUM · **CWE:** CWE-778 · **Category:** security_hygiene

**Title:** DMARC record has no reporting address (rua) for {asset}

**Summary:** You're not receiving DMARC reports because no reporting address is set.

**Description:**

> The DMARC record for {asset} doesn't include an rua= reporting address. Without it you receive no aggregate reports, so you can't see who's sending mail in your name, can't detect new abuse patterns, and can't safely tighten the policy to quarantine or reject.

**Remediation:**

> Add rua=mailto:dmarc@{asset} (or a dedicated mailbox / a third-party DMARC processor). If your reporting address is on a different domain, also publish a DMARC reporting authorisation record at the receiving end.

**Tags:** `dns`, `email`, `dmarc`
**Alert name:** DMARC No Reporting
**Monitor type:** `dns_change`

**References:**
- RFC 7489 §7 — DMARC Feedback

---

### `dns-no-dkim`

**Severity:** MEDIUM · **CWE:** CWE-345 · **Category:** security_hygiene

**Title:** No DKIM records found for {asset}

**Summary:** No DKIM email signing was found, so recipients can't verify your emails are genuine.

**Description:**

> No DKIM (DomainKeys Identified Mail) records were found at any common selector for {asset}. DKIM cryptographically signs your outgoing mail so recipients can verify it really came from you and wasn't modified in transit. Without DKIM, DMARC can only rely on SPF, which doesn't survive email forwarding.

**Remediation:**

> Enable DKIM signing in your mail provider's admin console, publish the public key as a TXT record at <selector>._domainkey.{asset}, and verify in headers of a test send that the DKIM-Signature header is present and passing. Google Workspace, Microsoft 365, and most ESPs have one-click DKIM setup.

**Tags:** `dns`, `email`, `dkim`
**Alert name:** DKIM Not Configured
**Monitor type:** `dns_change`

**References:**
- RFC 6376 — DomainKeys Identified Mail (DKIM) Signatures
- M3AAWG Sender Best Common Practices v3

---

### `dns-single-nameserver`

**Severity:** MEDIUM · **CWE:** — · **Category:** security_hygiene

**Title:** Only one nameserver for {asset}

**Summary:** Your domain relies on a single nameserver — if it fails, your site goes offline.

**Description:**

> Only one nameserver was found for {asset}. If it goes offline or is briefly unreachable, your domain becomes unresolvable everywhere — websites disappear, mail bounces, APIs error out.

**Remediation:**

> Add at least one additional NS record pointing to a different nameserver (ideally on a different network or provider). Most managed DNS providers ship redundancy by default — adding two to four NS records is standard.

**Tags:** `dns`, `nameserver`, `redundancy`
**Alert name:** Single Nameserver
**Monitor type:** `dns_change`

**References:**
- RFC 1034 §4.1 — Multiple authoritative servers
- ICANN — DNS Operational Best Practices

---

### `dns-spf-neutral`

**Severity:** MEDIUM · **CWE:** CWE-290 · **Category:** security_hygiene

**Title:** SPF uses neutral (?all) for {asset}

**Summary:** Your SPF record is set to neutral, which provides no email protection at all.

**Description:**

> The SPF record for {asset} ends with ?all (neutral). Receiving servers are explicitly told not to make a decision based on SPF, which provides no protection against spoofing.

**Remediation:**

> Replace ?all with -all (hardfail). If you can't yet rule out false positives, at least step up to ~all (softfail) and review DMARC reports before tightening to -all.

**Tags:** `dns`, `email`, `spf`
**Alert name:** SPF Neutral Policy
**Monitor type:** `dns_change`

**References:**
- RFC 7208 — Sender Policy Framework v1

---

### `dns-spf-softfail`

**Severity:** MEDIUM · **CWE:** CWE-290 · **Category:** security_hygiene

**Title:** SPF uses softfail (~all) for {asset}

**Summary:** Your SPF record flags unauthorized emails but doesn't block them.

**Description:**

> The SPF record for {asset} ends with ~all (softfail). Unauthorised emails are flagged but still delivered, usually to the spam folder. Spammers and phishing kits often slip through softfail.

**Remediation:**

> Once you've verified every legitimate sender is in your SPF record (review a week of DMARC aggregate reports), tighten the policy to -all so unauthorised mail is rejected outright.

**Tags:** `dns`, `email`, `spf`
**Alert name:** SPF Softfail Only
**Monitor type:** `dns_change`

**References:**
- RFC 7208 — Sender Policy Framework v1
- M3AAWG Sender Best Common Practices v3

---

### `dns-spf-too-many-lookups`

**Severity:** MEDIUM · **CWE:** CWE-754 · **Category:** security_hygiene

**Title:** SPF record exceeds 10-lookup limit for {asset}

**Summary:** Your SPF record has too many DNS lookups and may break email authentication.

**Description:**

> The SPF record for {asset} requires more than 10 DNS lookups to evaluate. RFC 7208 caps SPF at 10 lookups; exceeding the limit causes a permanent error (permerror) and SPF fails entirely — including for legitimate senders.

**Remediation:**

> Reduce DNS lookups by flattening nested includes into ip4: and ip6: mechanisms, or remove unused providers. SPF flattening services (e.g. EasyDMARC, dmarcian, Valimail) automate this and keep the flat record up to date as your providers' IPs change.

**Tags:** `dns`, `email`, `spf`
**Alert name:** SPF Lookup Limit Exceeded
**Monitor type:** `dns_change`

**References:**
- RFC 7208 §4.6.4 — Lookup limits
- M3AAWG Sender Best Common Practices v3

---

### `dns-no-ipv6`

**Severity:** LOW · **CWE:** — · **Category:** security_hygiene

**Title:** No IPv6 (AAAA) records for {asset}

**Summary:** Your domain isn't reachable over IPv6, which a growing number of networks use.

**Description:**

> No AAAA records were found for {asset}. IPv6 deployment is above 40% on major networks (Google, mobile carriers, ISPs in India/Brazil/US), and some access networks are now IPv6-only. Visitors on those networks reach your site over a NAT64/CGN translator, which adds latency and a failure surface.

**Remediation:**

> Add AAAA records pointing to IPv6 addresses. Most managed hosting (Cloudflare, AWS, GCP, Azure) gives you IPv6 automatically — you may just need to enable it. Verify with test-ipv6.com after the change.

**Tags:** `dns`, `ipv6`
**Alert name:** No IPv6 Support
**Monitor type:** `dns_change`

**References:**
- Google IPv6 Statistics
- RFC 8200 — Internet Protocol, Version 6

---

## Subdomain Takeover

_44 templates_

### `takeover-confirmed`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed third-party resource at {asset}

**Summary:** A subdomain of yours points to an unclaimed third-party resource — anyone can claim it.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and the third-party service it targets is showing an unclaimed-resource page or NXDOMAIN response. Anyone with an account at that service can claim the same name and have your subdomain serve their content. This is used in the wild to host phishing pages, steal cookies via cross-subdomain trust, and bypass Content Security Policies that whitelist your apex domain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if the resource is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the resource** (if {asset} should still serve content):
>   1. Identify the service from {cname_target} and its reclaim/registration mechanism.
>   2. Register the same resource name under the account that should own this subdomain.
>   3. Re-attach {asset} as the custom domain.
>
> Then audit every other CNAME in your DNS zone for the same pattern.

**Tags:** `subdomain-takeover`, `dangling-cname`
**Alert name:** Takeover Confirmed
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz

---

### `takeover-confirmed-aws-cloudfront`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed AWS CloudFront distribution at {asset}

**Summary:** A subdomain of yours points to an unclaimed AWS CloudFront distribution — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and AWS CloudFront is returning its "ERROR: The request could not be satisfied" response. The resource has been deleted (or never created) — anyone with a AWS CloudFront account can claim the same name and have your subdomain serve their content. An attacker who registers the alternate domain on a new CloudFront distribution can serve arbitrary content under your subdomain with a valid AWS-issued certificate.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if distribution is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the distribution** (if {asset} should still serve content):
>   1. Sign in to the AWS account that should own this distribution.
>   2. Create a new CloudFront distribution with {asset} listed as an Alternate Domain Name (CNAME).
>   3. Attach an ACM certificate covering {asset} and configure your origin.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `aws-cloudfront`
**Alert name:** Takeover — CloudFront
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- AWS — Using custom URLs for CloudFront

---

### `takeover-confirmed-aws-elastic-beanstalk`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed AWS Elastic Beanstalk environment at {asset}

**Summary:** A subdomain of yours points to an unclaimed AWS Elastic Beanstalk environment — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and AWS Elastic Beanstalk is returning its "NXDOMAIN — environment does not exist" response. The resource has been deleted (or never created) — anyone with a AWS Elastic Beanstalk account can claim the same name and have your subdomain serve their content. An attacker can create an Elastic Beanstalk environment with the same name in any AWS region and serve their application from your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if environment is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the environment** (if {asset} should still serve content):
>   1. Sign in to the AWS account that should own this environment.
>   2. Create an Elastic Beanstalk environment with the exact name from {cname_target} in the original region.
>   3. Deploy the intended application or remove the CNAME if the environment is no longer required.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `aws-elastic-beanstalk`
**Alert name:** Takeover — Beanstalk
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- AWS — Elastic Beanstalk environment URLs

---

### `takeover-confirmed-aws-s3-cloudfront`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed AWS S3 bucket at {asset}

**Summary:** A subdomain of yours points to an unclaimed AWS S3 bucket — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and AWS S3 is returning its "NoSuchBucket / The specified bucket does not exist" response. The resource has been deleted (or never created) — anyone with a AWS S3 account can claim the same name and have your subdomain serve their content. Used in the wild to host phishing pages, steal cookies via cross-subdomain trust, and bypass Content Security Policies that whitelist your apex domain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if bucket is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the bucket** (if {asset} should still serve content):
>   1. Sign in to the AWS account that should own this resource.
>   2. Create an S3 bucket with the exact name from {cname_target} (strip the regional `.s3-website-...` suffix).
>   3. Re-apply the original bucket policy and static-hosting configuration.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `aws-s3-cloudfront`
**Alert name:** Takeover — AWS S3
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- AWS — S3 bucket naming rules

---

### `takeover-confirmed-azure-api-management`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Azure API Management service instance at {asset}

**Summary:** A subdomain of yours points to an unclaimed Azure API Management service instance — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Azure API Management is returning its "ResourceNotFound" response. The resource has been deleted (or never created) — anyone with a Azure API Management account can claim the same name and have your subdomain serve their content. An attacker who recreates the APIM instance can publish API endpoints under your subdomain that look authentic to client applications still pointing at the old hostname.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if service instance is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the service instance** (if {asset} should still serve content):
>   1. Sign in to the Azure subscription that should own this instance.
>   2. Create an API Management service with the exact name from {cname_target}.
>   3. Re-add {asset} as a custom domain on the gateway.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `azure-api-management`
**Alert name:** Takeover — Azure APIM
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Microsoft — APIM custom domains

---

### `takeover-confirmed-azure-app-service`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Azure App Service app at {asset}

**Summary:** A subdomain of yours points to an unclaimed Azure App Service app — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Azure App Service is returning its "404 Web Site not found" response. The resource has been deleted (or never created) — anyone with a Azure App Service account can claim the same name and have your subdomain serve their content. Anyone with an Azure subscription can create an App Service with the same name and serve content under your subdomain — a known abuse pattern that Microsoft has documented as "dangling DNS".

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if app is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the app** (if {asset} should still serve content):
>   1. Sign in to the Azure subscription that should own this app.
>   2. Create an App Service with the exact name from {cname_target}.
>   3. Add {asset} as a custom domain and bind a certificate.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `azure-app-service`
**Alert name:** Takeover — Azure App Service
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Microsoft — Prevent dangling DNS entries

---

### `takeover-confirmed-azure-blob-storage`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Azure Blob Storage container at {asset}

**Summary:** A subdomain of yours points to an unclaimed Azure Blob Storage container — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Azure Blob Storage is returning its "BlobNotFound / The specified resource does not exist" response. The resource has been deleted (or never created) — anyone with a Azure Blob Storage account can claim the same name and have your subdomain serve their content. An attacker who creates a storage account with the same name can host files under your subdomain — particularly dangerous for static-site or asset-CDN subdomains where users implicitly trust the content.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if container is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the container** (if {asset} should still serve content):
>   1. Sign in to the Azure subscription that should own this account.
>   2. Create a storage account with the exact name from {cname_target}.
>   3. Recreate the container and configure access as required.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `azure-blob-storage`
**Alert name:** Takeover — Azure Blob
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Microsoft — Prevent dangling DNS entries

---

### `takeover-confirmed-azure-cdn`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Azure CDN endpoint at {asset}

**Summary:** A subdomain of yours points to an unclaimed Azure CDN endpoint — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Azure CDN is returning its "404 Web Site not found / Our services aren't available right now" response. The resource has been deleted (or never created) — anyone with a Azure CDN account can claim the same name and have your subdomain serve their content. An attacker who recreates the CDN endpoint can serve arbitrary content under your subdomain — often with the Azure-issued certificate auto-renewing successfully because domain validation passes via the dangling CNAME.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if endpoint is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the endpoint** (if {asset} should still serve content):
>   1. Sign in to the Azure subscription that should own this endpoint.
>   2. Create a CDN endpoint with the exact name from {cname_target}.
>   3. Add {asset} as a custom domain and re-issue the certificate.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `azure-cdn`
**Alert name:** Takeover — Azure CDN
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Microsoft — Prevent dangling DNS entries

---

### `takeover-confirmed-azure-traffic-manager`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Azure Traffic Manager profile at {asset}

**Summary:** A subdomain of yours points to an unclaimed Azure Traffic Manager profile — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Azure Traffic Manager is returning its "NXDOMAIN — Traffic Manager profile not registered" response. The resource has been deleted (or never created) — anyone with a Azure Traffic Manager account can claim the same name and have your subdomain serve their content. Recreating the profile in any Azure subscription routes traffic for {asset} to attacker-controlled endpoints.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if profile is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the profile** (if {asset} should still serve content):
>   1. Sign in to the Azure subscription that should own this profile.
>   2. Create a Traffic Manager profile with the exact name from {cname_target}.
>   3. Configure the original endpoint pool and routing method.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `azure-traffic-manager`
**Alert name:** Takeover — Traffic Manager
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Microsoft — Prevent dangling DNS entries

---

### `takeover-confirmed-azure-virtual-machine`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Azure Virtual Machine DNS label at {asset}

**Summary:** A subdomain of yours points to an unclaimed Azure Virtual Machine DNS label — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Azure Virtual Machine is returning its "NXDOMAIN — VM DNS label not registered" response. The resource has been deleted (or never created) — anyone with a Azure Virtual Machine account can claim the same name and have your subdomain serve their content. An attacker can spin up a VM in the same Azure region with the same DNS label and have public traffic to your subdomain land on their machine.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if DNS label is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the DNS label** (if {asset} should still serve content):
>   1. Sign in to the Azure subscription that should own this label.
>   2. Provision a VM in the original region and assign the public DNS label from {cname_target}.
>   3. Or remove the CNAME if the VM is no longer required.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `azure-virtual-machine`
**Alert name:** Takeover — Azure VM
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Microsoft — Prevent dangling DNS entries

---

### `takeover-confirmed-bitbucket-pages`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Bitbucket Pages repository at {asset}

**Summary:** A subdomain of yours points to an unclaimed Bitbucket Pages repository — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Bitbucket Pages is returning its "Repository not found" response. The resource has been deleted (or never created) — anyone with a Bitbucket Pages account can claim the same name and have your subdomain serve their content. Recreating the repository under any Bitbucket workspace lets an attacker host static content under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if repository is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the repository** (if {asset} should still serve content):
>   1. Sign in to the Bitbucket workspace that should own this site.
>   2. Create a repository matching the workspace and repo name in {cname_target}.
>   3. Configure Pages with the appropriate branch.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `bitbucket-pages`
**Alert name:** Takeover — Bitbucket
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Bitbucket Docs — Publishing a website on Bitbucket Cloud

---

### `takeover-confirmed-cargo-collective`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Cargo Collective site at {asset}

**Summary:** A subdomain of yours points to an unclaimed Cargo Collective site — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Cargo Collective is returning its "404 Not Found" response. The resource has been deleted (or never created) — anyone with a Cargo Collective account can claim the same name and have your subdomain serve their content. Cargo handles tend to be short and memorable — claimable ones are quickly registered by squatters who serve their own portfolio under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if site is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the site** (if {asset} should still serve content):
>   1. Sign in to the Cargo account that should own this site.
>   2. Recreate the site at the exact handle from {cname_target}.
>   3. Add {asset} as the custom domain.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `cargo-collective`
**Alert name:** Takeover — Cargo
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Cargo — Custom domains

---

### `takeover-confirmed-cloudflare`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Cloudflare resource at {asset}

**Summary:** A subdomain of yours points to an unclaimed Cloudflare resource — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Cloudflare is returning its "NXDOMAIN — Cloudflare resource not configured" response. The resource has been deleted (or never created) — anyone with a Cloudflare account can claim the same name and have your subdomain serve their content. A CNAME pointing into Cloudflare without an active Cloudflare configuration can let an attacker who adds the domain to their own Cloudflare account proxy traffic for {asset}.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if resource is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the resource** (if {asset} should still serve content):
>   1. Sign in to the Cloudflare account that should serve this domain.
>   2. Confirm the domain is on the correct Cloudflare account, with an active zone configuration.
>   3. Or remove the CNAME if Cloudflare is no longer in front of this subdomain.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `cloudflare`
**Alert name:** Takeover — Cloudflare
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Cloudflare — CNAME setup

---

### `takeover-confirmed-fastly`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Fastly service at {asset}

**Summary:** A subdomain of yours points to an unclaimed Fastly service — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Fastly is returning its "Fastly error: unknown domain" response. The resource has been deleted (or never created) — anyone with a Fastly account can claim the same name and have your subdomain serve their content. An attacker who configures the same domain on their own Fastly service can intercept traffic intended for your subdomain — Fastly's edge will route based on whoever has the domain attached.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if service is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the service** (if {asset} should still serve content):
>   1. Sign in to the Fastly account that should own this service.
>   2. Add {asset} to a Fastly service and configure the appropriate origin and TLS.
>   3. Or remove the CNAME if Fastly is no longer the intended edge.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `fastly`
**Alert name:** Takeover — Fastly
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Fastly — Custom domains and TLS

---

### `takeover-confirmed-feedpress`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Feedpress feed at {asset}

**Summary:** A subdomain of yours points to an unclaimed Feedpress feed — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Feedpress is returning its "The feed has not been found" response. The resource has been deleted (or never created) — anyone with a Feedpress account can claim the same name and have your subdomain serve their content. Reclaiming the feed lets an attacker push arbitrary content to subscribers of any RSS reader still pointed at your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if feed is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the feed** (if {asset} should still serve content):
>   1. Sign in to the Feedpress account that should own this feed.
>   2. Recreate the feed with the exact name from {cname_target}.
>   3. Configure {asset} as the custom feed domain.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `feedpress`
**Alert name:** Takeover — Feedpress
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz

---

### `takeover-confirmed-fly-io`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Fly.io app at {asset}

**Summary:** A subdomain of yours points to an unclaimed Fly.io app — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Fly.io is returning its "NXDOMAIN — Fly app not registered" response. The resource has been deleted (or never created) — anyone with a Fly.io account can claim the same name and have your subdomain serve their content. An attacker can run `fly launch` with the same app name and deploy a container under your subdomain anywhere on Fly's global edge.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if app is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the app** (if {asset} should still serve content):
>   1. Sign in to the Fly.io account that should own this app: `fly auth login`.
>   2. Create an app with the exact name from {cname_target}: `fly apps create <name>`.
>   3. Run `fly certs add {asset}` to attach the custom domain.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `fly-io`
**Alert name:** Takeover — Fly.io
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Fly.io Docs — Custom domains

---

### `takeover-confirmed-freshdesk`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Freshdesk helpdesk at {asset}

**Summary:** A subdomain of yours points to an unclaimed Freshdesk helpdesk — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Freshdesk is returning its "There is no helpdesk here" response. The resource has been deleted (or never created) — anyone with a Freshdesk account can claim the same name and have your subdomain serve their content. Recreating the helpdesk lets an attacker run a fake support portal under your domain, complete with fake ticket creation and credential capture.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if helpdesk is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the helpdesk** (if {asset} should still serve content):
>   1. Sign in to the Freshdesk account that should own this helpdesk.
>   2. Create a helpdesk with the exact subdomain from {cname_target}.
>   3. Add {asset} as a vanity URL in Admin → Helpdesk Settings.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `freshdesk`
**Alert name:** Takeover — Freshdesk
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Freshdesk — Vanity URLs

---

### `takeover-confirmed-ghost`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Ghost publication at {asset}

**Summary:** A subdomain of yours points to an unclaimed Ghost publication — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Ghost is returning its "The thing you were looking for is no longer here" response. The resource has been deleted (or never created) — anyone with a Ghost account can claim the same name and have your subdomain serve their content. An attacker can claim the publication name on Ghost(Pro) and host a fake blog under your subdomain — particularly damaging if the subdomain previously hosted thought-leadership content search engines have indexed.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if publication is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the publication** (if {asset} should still serve content):
>   1. Sign up for Ghost(Pro) (or self-host on Ghost) with the exact subdomain from {cname_target}.
>   2. Add {asset} as the publication's custom domain.
>   3. Restore the original content from backup if needed.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `ghost`
**Alert name:** Takeover — Ghost
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Ghost Docs — Custom Domain

---

### `takeover-confirmed-github-pages`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed GitHub Pages site at {asset}

**Summary:** A subdomain of yours points to an unclaimed GitHub Pages site — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and GitHub Pages is returning its "There isn't a GitHub Pages site here" response. The resource has been deleted (or never created) — anyone with a GitHub Pages account can claim the same name and have your subdomain serve their content. Anyone can create a repository on a personal or organisation account, enable Pages, and add a CNAME file targeting your subdomain — serving arbitrary HTML and JavaScript with a GitHub-issued certificate.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if site is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the site** (if {asset} should still serve content):
>   1. Sign in to the GitHub account or organisation that should own this site.
>   2. Create a repository matching the user/org and repo name in {cname_target}.
>   3. Enable Pages (Settings → Pages → Source) and add a CNAME file containing `{asset}`.
>   4. Verify the custom domain in Pages settings.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `github-pages`
**Alert name:** Takeover — GitHub Pages
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- GitHub Docs — Configuring a custom domain for GitHub Pages

---

### `takeover-confirmed-gitlab-pages`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed GitLab Pages site at {asset}

**Summary:** A subdomain of yours points to an unclaimed GitLab Pages site — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and GitLab Pages is returning its "NXDOMAIN — GitLab Pages site not registered" response. The resource has been deleted (or never created) — anyone with a GitLab Pages account can claim the same name and have your subdomain serve their content. An attacker can create a GitLab project with the matching namespace and enable Pages, taking over your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if site is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the site** (if {asset} should still serve content):
>   1. Sign in to the GitLab account or group that should own this site.
>   2. Create a project matching the namespace and project name in {cname_target}.
>   3. Enable Pages and add `{asset}` as a custom domain in Settings → Pages.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `gitlab-pages`
**Alert name:** Takeover — GitLab Pages
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- GitLab Docs — Custom domains for Pages

---

### `takeover-confirmed-google-cloud-storage`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Google Cloud Storage bucket at {asset}

**Summary:** A subdomain of yours points to an unclaimed Google Cloud Storage bucket — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Google Cloud Storage is returning its "NoSuchBucket / The specified bucket does not exist" response. The resource has been deleted (or never created) — anyone with a Google Cloud Storage account can claim the same name and have your subdomain serve their content. Bucket names in GCS are globally unique — anyone with a GCP project can create a bucket with the same name and serve static content under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if bucket is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the bucket** (if {asset} should still serve content):
>   1. Sign in to the GCP project that should own this bucket.
>   2. Create a Cloud Storage bucket with the exact name from {cname_target}.
>   3. Re-apply IAM and static-website settings.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `google-cloud-storage`
**Alert name:** Takeover — GCS
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Google — Cloud Storage bucket naming

---

### `takeover-confirmed-helpjuice`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Helpjuice knowledge base at {asset}

**Summary:** A subdomain of yours points to an unclaimed Helpjuice knowledge base — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Helpjuice is returning its "We could not find what you're looking for" response. The resource has been deleted (or never created) — anyone with a Helpjuice account can claim the same name and have your subdomain serve their content. An attacker can register the Helpjuice site with the same subdomain and serve arbitrary documentation under your domain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if knowledge base is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the knowledge base** (if {asset} should still serve content):
>   1. Sign in to the Helpjuice account that should own this site.
>   2. Create a knowledge base with the exact subdomain from {cname_target}.
>   3. Configure a custom domain for {asset}.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `helpjuice`
**Alert name:** Takeover — Helpjuice
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Helpjuice — Custom domain setup

---

### `takeover-confirmed-helpscout`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed HelpScout docs site at {asset}

**Summary:** A subdomain of yours points to an unclaimed HelpScout docs site — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and HelpScout is returning its "No settings were found for this company" response. The resource has been deleted (or never created) — anyone with a HelpScout account can claim the same name and have your subdomain serve their content. Reclaim by an attacker lets them publish a parallel HelpScout Docs site under your subdomain — confusing customers about which support resources are official.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if docs site is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the docs site** (if {asset} should still serve content):
>   1. Sign in to the HelpScout account that should own this site.
>   2. Create a Docs collection mapped to the exact subdomain from {cname_target}.
>   3. Configure the custom domain pointing at {asset}.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `helpscout`
**Alert name:** Takeover — HelpScout
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- HelpScout — Docs custom domain

---

### `takeover-confirmed-heroku`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Heroku app at {asset}

**Summary:** A subdomain of yours points to an unclaimed Heroku app — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Heroku is returning its "No such app" response. The resource has been deleted (or never created) — anyone with a Heroku account can claim the same name and have your subdomain serve their content. Anyone with a Heroku account can register the slug and deploy any code under your subdomain — bypassing same-origin trust your apex extends to its subdomains.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if app is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the app** (if {asset} should still serve content):
>   1. From the Heroku account that should own this name, run `heroku apps:create <app-slug>` using the exact slug from {cname_target}.
>   2. Add the custom domain back: `heroku domains:add {asset}`.
>   3. Redeploy the application.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `heroku`
**Alert name:** Takeover — Heroku
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Heroku — Custom Domain Names

---

### `takeover-confirmed-landingi`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Landingi landing page at {asset}

**Summary:** A subdomain of yours points to an unclaimed Landingi landing page — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Landingi is returning its "NXDOMAIN — Landingi page not registered" response. The resource has been deleted (or never created) — anyone with a Landingi account can claim the same name and have your subdomain serve their content. An attacker can create a Landingi landing page with the same domain configuration and host arbitrary marketing or phishing content under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if landing page is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the landing page** (if {asset} should still serve content):
>   1. Sign in to the Landingi account that should own this page.
>   2. Recreate the landing page.
>   3. Reconnect {asset} as the custom domain.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `landingi`
**Alert name:** Takeover — Landingi
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz

---

### `takeover-confirmed-launchrock`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed LaunchRock landing page at {asset}

**Summary:** A subdomain of yours points to an unclaimed LaunchRock landing page — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and LaunchRock is returning its "It looks like you may have taken a wrong turn somewhere" response. The resource has been deleted (or never created) — anyone with a LaunchRock account can claim the same name and have your subdomain serve their content. An attacker who registers the same site name on LaunchRock can run any pre-launch / coming-soon page under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if landing page is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the landing page** (if {asset} should still serve content):
>   1. Sign in to the LaunchRock account that should own this page.
>   2. Recreate the launch page.
>   3. Configure {asset} as the custom domain in account settings.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `launchrock`
**Alert name:** Takeover — LaunchRock
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz

---

### `takeover-confirmed-netlify`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Netlify site at {asset}

**Summary:** A subdomain of yours points to an unclaimed Netlify site — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Netlify is returning its "Not Found - Request ID" response. The resource has been deleted (or never created) — anyone with a Netlify account can claim the same name and have your subdomain serve their content. Recreating the site name on any Netlify account lets an attacker publish arbitrary static content under your subdomain — Netlify auto-issues a Let's Encrypt certificate that passes browser validation.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if site is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the site** (if {asset} should still serve content):
>   1. Sign in to the Netlify account that should own this site.
>   2. Create a site with the exact name from {cname_target}.
>   3. Add {asset} as a custom domain (Site settings → Domain management → Add custom domain).
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `netlify`
**Alert name:** Takeover — Netlify
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Netlify Docs — Custom domains

---

### `takeover-confirmed-pantheon`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Pantheon site at {asset}

**Summary:** A subdomain of yours points to an unclaimed Pantheon site — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Pantheon is returning its "404 error unknown site" response. The resource has been deleted (or never created) — anyone with a Pantheon account can claim the same name and have your subdomain serve their content. An attacker who creates a Pantheon site with the same machine name can serve any WordPress or Drupal content under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if site is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the site** (if {asset} should still serve content):
>   1. Sign in to the Pantheon account that should own this site.
>   2. Create a site with the exact machine name from {cname_target}.
>   3. Add {asset} as a custom domain in the site's Domains tab.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `pantheon`
**Alert name:** Takeover — Pantheon
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Pantheon — Custom domains

---

### `takeover-confirmed-readme-io`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed ReadMe.io docs at {asset}

**Summary:** A subdomain of yours points to an unclaimed ReadMe.io docs — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and ReadMe.io is returning its "Project doesnt exist" response. The resource has been deleted (or never created) — anyone with a ReadMe.io account can claim the same name and have your subdomain serve their content. Recreating the project key on ReadMe.io lets an attacker host arbitrary API documentation under your subdomain — particularly damaging if developers integrate against the fake docs.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if docs is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the docs** (if {asset} should still serve content):
>   1. Sign in to the ReadMe.io account that should own this project.
>   2. Create a project with the exact project key from {cname_target}.
>   3. Add {asset} as a custom domain.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `readme-io`
**Alert name:** Takeover — ReadMe
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- ReadMe.io — Custom domains

---

### `takeover-confirmed-render`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Render service at {asset}

**Summary:** A subdomain of yours points to an unclaimed Render service — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Render is returning its "NXDOMAIN — Render service not registered" response. The resource has been deleted (or never created) — anyone with a Render account can claim the same name and have your subdomain serve their content. An attacker can create a Render service with the same name and deploy any application under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if service is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the service** (if {asset} should still serve content):
>   1. Sign in to the Render account that should own this service.
>   2. Create a service with the exact name from {cname_target}.
>   3. Add {asset} as a custom domain in the service's Settings.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `render`
**Alert name:** Takeover — Render
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Render Docs — Custom domains

---

### `takeover-confirmed-shopify`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Shopify store at {asset}

**Summary:** A subdomain of yours points to an unclaimed Shopify store — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Shopify is returning its "Sorry, this shop is currently unavailable" response. The resource has been deleted (or never created) — anyone with a Shopify account can claim the same name and have your subdomain serve their content. Anyone can register a Shopify account with the same store handle and run a fake storefront under your subdomain — customers see your domain in the address bar while paying the attacker.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if store is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the store** (if {asset} should still serve content):
>   1. Sign in to the Shopify account that should own this handle, or sign up at shopify.com using the exact handle from {cname_target}.
>   2. Add {asset} as a custom domain (Settings → Domains → Connect existing domain).
>   3. Verify the connection in the Shopify admin.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `shopify`
**Alert name:** Takeover — Shopify
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Shopify Help — Connecting an existing domain

---

### `takeover-confirmed-statuspage`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Statuspage status page at {asset}

**Summary:** A subdomain of yours points to an unclaimed Statuspage status page — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Statuspage is returning its "StatusPage / You are being redirected" response. The resource has been deleted (or never created) — anyone with a Statuspage account can claim the same name and have your subdomain serve their content. An attacker who creates a Statuspage with the same subdomain can publish fake incident reports under your domain — a real-world technique used to spread misinformation about company outages or breaches.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if status page is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the status page** (if {asset} should still serve content):
>   1. Sign in to the Statuspage (Atlassian) account that should own this page.
>   2. Create a status page with the exact subdomain from {cname_target}.
>   3. Add {asset} as the custom domain.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `statuspage`
**Alert name:** Takeover — Statuspage
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Atlassian — Statuspage custom domains

---

### `takeover-confirmed-surge-sh`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Surge.sh project at {asset}

**Summary:** A subdomain of yours points to an unclaimed Surge.sh project — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Surge.sh is returning its "project not found" response. The resource has been deleted (or never created) — anyone with a Surge.sh account can claim the same name and have your subdomain serve their content. Anyone can run `surge` and publish to the same domain — Surge doesn't verify ownership beyond the CLI invocation.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if project is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the project** (if {asset} should still serve content):
>   1. Install the Surge CLI and authenticate with the account that should own this domain: `surge login`.
>   2. Publish to the exact domain from {cname_target}: `surge ./public {asset}`.
>   3. Or remove the CNAME if Surge.sh is no longer in use.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `surge-sh`
**Alert name:** Takeover — Surge.sh
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Surge.sh Docs — Custom domains

---

### `takeover-confirmed-teamwork`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Teamwork site at {asset}

**Summary:** A subdomain of yours points to an unclaimed Teamwork site — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Teamwork is returning its "Oops - We didn't find your site" response. The resource has been deleted (or never created) — anyone with a Teamwork account can claim the same name and have your subdomain serve their content. Anyone can register a Teamwork account with the same site URL and host arbitrary project-management content under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if site is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the site** (if {asset} should still serve content):
>   1. Sign in to the Teamwork account that should own this site.
>   2. Create a Teamwork site with the exact subdomain from {cname_target}.
>   3. Configure {asset} as the custom domain.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `teamwork`
**Alert name:** Takeover — Teamwork
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Teamwork — Custom domains

---

### `takeover-confirmed-tilda`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Tilda site at {asset}

**Summary:** A subdomain of yours points to an unclaimed Tilda site — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Tilda is returning its "Domain is not configured / Please renew your subscription" response. The resource has been deleted (or never created) — anyone with a Tilda account can claim the same name and have your subdomain serve their content. Anyone with a Tilda account can claim the domain and serve arbitrary marketing content under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if site is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the site** (if {asset} should still serve content):
>   1. Sign in to the Tilda account that should own this site.
>   2. Create a project and configure {asset} as the custom domain.
>   3. Or renew the lapsed subscription if the original site is still recoverable.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `tilda`
**Alert name:** Takeover — Tilda
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Tilda — Custom domain

---

### `takeover-confirmed-tumblr`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Tumblr blog at {asset}

**Summary:** A subdomain of yours points to an unclaimed Tumblr blog — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Tumblr is returning its "Whatever you were looking for doesn't currently exist" response. The resource has been deleted (or never created) — anyone with a Tumblr account can claim the same name and have your subdomain serve their content. Anyone can create a Tumblr blog with the same name and host any content under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if blog is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the blog** (if {asset} should still serve content):
>   1. Sign in to the Tumblr account that should own this blog.
>   2. Create a blog with the exact name from {cname_target}.
>   3. Add {asset} under Blog Settings → Custom Domain.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `tumblr`
**Alert name:** Takeover — Tumblr
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Tumblr Help — Custom domains

---

### `takeover-confirmed-unbounce`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Unbounce landing page at {asset}

**Summary:** A subdomain of yours points to an unclaimed Unbounce landing page — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Unbounce is returning its "The requested URL was not found on this server" response. The resource has been deleted (or never created) — anyone with a Unbounce account can claim the same name and have your subdomain serve their content. Recreating the landing page under another Unbounce account lets an attacker host conversion forms or phishing pages under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if landing page is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the landing page** (if {asset} should still serve content):
>   1. Sign in to the Unbounce account that should own this page.
>   2. Recreate or restore the landing page.
>   3. Reconnect {asset} via Page Settings → Domain.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `unbounce`
**Alert name:** Takeover — Unbounce
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Unbounce — Custom domains

---

### `takeover-confirmed-uservoice`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed UserVoice feedback site at {asset}

**Summary:** A subdomain of yours points to an unclaimed UserVoice feedback site — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and UserVoice is returning its "This UserVoice subdomain is currently available" response. The resource has been deleted (or never created) — anyone with a UserVoice account can claim the same name and have your subdomain serve their content. Anyone can register the UserVoice subdomain and host a feedback site that customers will treat as official.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if feedback site is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the feedback site** (if {asset} should still serve content):
>   1. Sign in to the UserVoice account that should own this subdomain.
>   2. Recreate the feedback site at the exact subdomain from {cname_target}.
>   3. Configure {asset} as the custom domain.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `uservoice`
**Alert name:** Takeover — UserVoice
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- UserVoice — Custom domains

---

### `takeover-confirmed-vercel`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Vercel project at {asset}

**Summary:** A subdomain of yours points to an unclaimed Vercel project — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Vercel is returning its "NXDOMAIN — Vercel project not registered" response. The resource has been deleted (or never created) — anyone with a Vercel account can claim the same name and have your subdomain serve their content. Recreating the project name on any Vercel account gives an attacker a CDN-fronted, certificate-valid surface under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if project is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the project** (if {asset} should still serve content):
>   1. Sign in to the Vercel account that should own this project.
>   2. Create a project with the exact name from {cname_target}.
>   3. Add {asset} under Project Settings → Domains.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `vercel`
**Alert name:** Takeover — Vercel
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Vercel Docs — Custom domains

---

### `takeover-confirmed-webflow`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Webflow site at {asset}

**Summary:** A subdomain of yours points to an unclaimed Webflow site — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Webflow is returning its "The page you are looking for doesn't exist or has been moved" response. The resource has been deleted (or never created) — anyone with a Webflow account can claim the same name and have your subdomain serve their content. Recreating the site under any Webflow workspace lets an attacker publish a designer-grade fake homepage under your subdomain.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if site is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the site** (if {asset} should still serve content):
>   1. Sign in to the Webflow workspace that should own this site.
>   2. Create a project and connect it to the exact subdomain from {cname_target}.
>   3. Add {asset} as a custom domain (Site Settings → Publishing).
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `webflow`
**Alert name:** Takeover — Webflow
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Webflow — Connecting a custom domain

---

### `takeover-confirmed-wordpress-com`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed WordPress.com site at {asset}

**Summary:** A subdomain of yours points to an unclaimed WordPress.com site — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and WordPress.com is returning its "Do you want to register" response. The resource has been deleted (or never created) — anyone with a WordPress.com account can claim the same name and have your subdomain serve their content. An attacker can register a wordpress.com site with the same subdomain and host arbitrary content — WordPress.com handles TLS automatically, so the takeover is invisible at the browser level.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if site is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the site** (if {asset} should still serve content):
>   1. Sign in to the WordPress.com account that should own this site.
>   2. Create a site at the exact subdomain from {cname_target}.
>   3. Map {asset} as a custom domain via the site's domain settings.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `wordpress-com`
**Alert name:** Takeover — WordPress.com
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- WordPress.com — Map an existing domain

---

### `takeover-confirmed-zendesk`

**Severity:** CRITICAL · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Subdomain takeover — unclaimed Zendesk help center at {asset}

**Summary:** A subdomain of yours points to an unclaimed Zendesk help center — anyone can claim it and host content as you.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, and Zendesk is returning its "Help Center Closed" response. The resource has been deleted (or never created) — anyone with a Zendesk account can claim the same name and have your subdomain serve their content. An attacker who registers the Zendesk subdomain can publish fake support content under your domain — particularly dangerous because customers contacting "support" implicitly trust the experience.

**Remediation:**

> Pick one path:
>
> **Remove the DNS record** (recommended if help center is no longer needed):
>   Delete the CNAME `{asset} → {cname_target}` from your DNS zone.
>
> **Reclaim the help center** (if {asset} should still serve content):
>   1. Sign in to the Zendesk account that should own this subdomain.
>   2. If the subdomain is still in your account: re-enable the Help Center and re-add {asset} as a host-mapped domain.
>   3. If the subdomain has been released: open a Zendesk support ticket to reclaim it before signing up fresh.
>
> Then audit every other CNAME in your DNS zone for the same pattern — one missed dangling record is enough.

**Tags:** `subdomain-takeover`, `dangling-cname`, `zendesk`
**Alert name:** Takeover — Zendesk
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz
- Zendesk Help — Host-mapping your help center

---

### `takeover-dangling-cname`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Dangling CNAME at {asset} → {cname_target}

**Summary:** One of your subdomains points to a third-party service that no longer exists — likely a takeover risk.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, but the target does not resolve. Either the third-party resource was decommissioned without removing the DNS record, or it's pointing at a service that doesn't exist yet. Dangling CNAMEs are a takeover risk waiting to happen — if the resource name becomes registrable on the target service, anyone can claim it.

**Remediation:**

> Remove the CNAME `{asset} → {cname_target}` from your DNS zone. If the subdomain is still needed, repoint it to the correct active resource. Audit your zone for similar dangling references — it's common to find several at once after a service migration.

**Tags:** `subdomain-takeover`, `dangling-cname`, `nxdomain`
**Alert name:** Dangling CNAME
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz

---

### `takeover-suspicious`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** security_hygiene

**Title:** Suspicious CNAME at {asset} → {cname_target}

**Summary:** A CNAME on your domain points to a third-party service we couldn't verify — worth a manual check.

**Description:**

> The subdomain {asset} has a CNAME record pointing to {cname_target}, a known third-party service pattern. We couldn't confirm whether the resource is unclaimed — the HTTP probe returned an error, or the service was unreachable from our scanner. This is worth a manual check: if the resource is decommissioned, this is a takeover-in-waiting.

**Remediation:**

> Verify that the resource at {cname_target} is still active and owned by your team. If it's decommissioned or unowned, remove the CNAME. If active, you can suppress this finding via the tuning UI.

**Tags:** `subdomain-takeover`, `cname-check`
**Alert name:** Suspicious CNAME
**Monitor type:** `dns_change`

**References:**
- OWASP WSTG — Test for Subdomain Takeover
- EdOverflow — can-i-take-over-xyz

---

## Cloud Asset Exposure

_11 templates_

### `cloud-registry-public-images`

**Severity:** CRITICAL · **CWE:** CWE-200 · **Category:** service_exposure

**Title:** Public {provider} with pullable images: {value}

**Summary:** A container registry on your domain is publicly pullable — images often contain embedded secrets and source code.

**Description:**

> The {provider} {value} allows unauthenticated access to container images. Public images frequently contain embedded secrets (API keys, database passwords baked into env files), source code, and proprietary build dependencies. Anyone with Docker installed can pull, inspect, and exfiltrate the contents within seconds. Continuously scraped by automated tooling looking for AWS/GCP credentials.

**Remediation:**

> **Treat as a credential incident first**
>   Pull each exposed image yourself, scan it for secrets (`gitleaks`, `trufflehog`, `docker scout secrets`), and rotate every credential, API key, or token that turns up. Assume any secret in a public image is already compromised.
>
> **Restrict the registry**
>   • Azure Container Registry — set *Admin user* off and require AAD authentication; private endpoints recommended.
>   • Google Container / Artifact Registry — remove `allUsers` from the IAM policy on the repository or registry.
>   • AWS ECR Public — move sensitive images to a private ECR repository; ECR Public is internet-readable by design.
>   • Docker Hub — flip each repository to *Private* (paid plans) or move to a private registry.
>
> **Prevent recurrence**
>   Add secret scanning to your image build pipeline so `.env`, `id_rsa`, and credential files never get baked in.

**Tags:** `cloud`, `registry`, `container`, `public-access`
**Alert name:** Container Registry — Public Images
**Monitor type:** `cloud_change`

**References:**
- OWASP — Container Security Verification Standard
- Microsoft — Authenticate with an Azure container registry
- Google Cloud — Configure access control for Artifact Registry
- Docker — Repository visibility settings

---

### `cloud-serverless-config-leak`

**Severity:** CRITICAL · **CWE:** CWE-215 · **Category:** service_exposure

**Title:** {provider} endpoint leaking configuration: {value}

**Summary:** A serverless endpoint on your domain is leaking configuration data — likely including credentials. Rotate now.

**Description:**

> The {provider} app {value} is publicly accessible without authentication and is returning content that looks like configuration data — environment variables, debug pages, framework error dumps, or response bodies containing keys. Leaked AWS / GCP / database credentials in serverless responses are routinely the entry point for full account compromise.

**Remediation:**

> **Rotate first**
>   Treat anything that appeared in the leaked content as compromised: AWS access keys, database passwords, OAuth client secrets, internal service tokens. Rotate before closing the leak — once rotated, attackers lose access even if they already exfiltrated the values.
>
> **Stop the leak**
>   • Azure Functions — set *Authentication* to required and configure an identity provider; ensure debug-mode env variables are off in production.
>   • Google Cloud Run — restrict invokers via IAM (`roles/run.invoker`); turn off detailed error traces in the runtime config.
>   • AWS Lambda — front the function with API Gateway and a JWT or IAM authoriser; never use anonymous Function URLs for production traffic.
>
> **Prevent recurrence**
>   Move all secrets out of environment variables and into a managed secret store (Key Vault, Secret Manager, AWS Secrets Manager); use managed identity to fetch them at runtime.

**Tags:** `cloud`, `serverless`, `config-leak`, `public-access`
**Alert name:** Serverless — Config Leak
**Monitor type:** `cloud_change`

**References:**
- OWASP — Serverless Top 10
- Microsoft — Authentication and authorization in Azure App Service
- Google Cloud — Authenticating service-to-service
- AWS — Lambda function URLs and authorization

---

### `cloud-storage-listing-enabled`

**Severity:** CRITICAL · **CWE:** CWE-548 · **Category:** service_exposure

**Title:** Public {provider} bucket with directory listing: {value}

**Summary:** A cloud bucket on your domain lists its contents publicly — anyone can browse and download every file in it.

**Description:**

> The {provider} bucket {value} is publicly accessible with object listing enabled. Anyone can enumerate every object in the bucket and download them. This is one of the most common breach patterns on the public internet — automated scanners harvest exposed buckets within hours.

**Remediation:**

> **Disable listing and lock down access**
>   • AWS S3 — enable *Block Public Access* and remove any policy granting `s3:ListBucket` to `"Principal": "*"`.
>   • Azure Blob Storage — set the container's access level to *Private (no anonymous access)*.
>   • Google Cloud Storage — remove `roles/storage.objectViewer` and `roles/storage.legacyBucketReader` from `allUsers`.
>
> **Audit downloads**
>   Review server access logs (S3) / storage diagnostic logs (Azure) / data access audit logs (GCS) for the period the bucket has been public. Any object downloaded by an unknown principal should be treated as exfiltrated.

**Tags:** `cloud`, `storage`, `directory-listing`, `public-access`
**Alert name:** Cloud Bucket — Listing Enabled
**Monitor type:** `cloud_change`

**References:**
- AWS — Blocking public access to your S3 storage
- Microsoft — Set anonymous read access for containers and blobs
- Google Cloud — Make data public
- CWE-548: Exposure of Information Through Directory Listing

---

### `cloud-storage-sensitive-files`

**Severity:** CRITICAL · **CWE:** CWE-552 · **Category:** service_exposure

**Title:** Public {provider} bucket with sensitive files: {value}

**Summary:** An exposed cloud bucket on your domain contains files that look like credentials, backups, or config — anyone can download them.

**Description:**

> The {provider} bucket {value} is publicly accessible and contains files whose names or extensions strongly suggest credentials, database dumps, configuration secrets, or customer data. Exposed buckets are scraped continuously — real incidents (Capital One, Accenture, Verizon, Twilio) started exactly this way. Treat any credential or key in this bucket as compromised from now.

**Remediation:**

> Treat this as an active incident: rotate credentials first, then lock the bucket down.
>
> **Rotate now**
>   Any AWS keys, database passwords, OAuth tokens, or signing keys that may be in the exposed files must be rotated before you close the door.
>
> **Lock down access**
>   • AWS S3 — enable account-level *Block Public Access* (S3 console → Block Public Access settings → Edit). Remove any `"Principal": "*"` from the bucket policy.
>   • Azure Blob Storage — set the storage account's *Allow Blob anonymous access* to *Disabled* and switch each container's access level to *Private*.
>   • Google Cloud Storage — remove `allUsers` and `allAuthenticatedUsers` from the bucket's IAM bindings.
>
> **Audit and harden**
>   Enable server-side encryption, turn on access logging, and review log history for unauthorised downloads since the bucket became public.

**Tags:** `cloud`, `storage`, `sensitive-data`, `public-access`
**Alert name:** Cloud Bucket — Sensitive Files
**Monitor type:** `cloud_change`

**References:**
- OWASP — Cloud-Native Application Security
- AWS — Blocking public access to your S3 storage
- Microsoft — Configure anonymous public read access for containers and blobs
- Google Cloud — Make data public

---

### `cloud-cdn-origin-exposed`

**Severity:** HIGH · **CWE:** CWE-1327 · **Category:** service_exposure

**Title:** {provider} origin reachable, bypassing CDN: {value}

**Summary:** The origin server behind your CDN looks reachable directly — attackers can bypass your WAF and rate limits.

**Description:**

> The domain {value} is fronted by {provider}, but its origin server appears to be directly reachable on the public internet. Attackers who learn the origin IP can bypass everything the CDN provides — WAF rules, rate limiting, DDoS mitigation, bot management — by hitting the origin host directly. Origin IPs are routinely discovered via SSL certificate transparency logs, Shodan history, header leaks, and stale DNS records.

**Remediation:**

> **Lock the origin firewall to the CDN's IP ranges**
>   • Cloudflare — accept traffic only from Cloudflare IP ranges (cloudflare.com/ips).
>   • CloudFront — use the AWS-managed prefix list `com.amazonaws.global.cloudfront.origin-facing` in your security group.
>   • Fastly / Azure CDN / Akamai — pull the published ASN or IP-range list from the vendor and restrict at the host or VPC firewall.
>
> **Remove direct exposure**
>   • Delete any DNS A records that point straight to the origin IP from public zones.
>   • Strip headers that may leak origin info: `X-Served-By`, `Via`, `X-Backend-Server`, `X-Real-IP` outbound.
>
> **Change the IP if it's been public**
>   Any origin IP that was reachable for any meaningful period should be rotated — adversary tools cache historical IPs aggressively.

**Tags:** `cloud`, `cdn`, `origin-exposure`, `waf-bypass`
**Alert name:** CDN — Origin Exposed
**Monitor type:** `cloud_change`

**References:**
- Cloudflare — Restoring original visitor IPs
- AWS — Restricting access to CloudFront origins
- Akamai — Site Shield

---

### `cloud-registry-public-access`

**Severity:** HIGH · **CWE:** CWE-306 · **Category:** service_exposure

**Title:** Public {provider} catalogue exposed: {value}

**Summary:** A container registry catalogue on your domain is publicly accessible — anything pushed to it will be pullable.

**Description:**

> The {provider} {value} responds to unauthenticated catalogue queries. We didn't enumerate any images on this scan — the registry may be empty, paginated, or rate-limiting us — but the catalogue endpoint itself shouldn't be reachable without authentication. Once images are pushed, they'll be pullable by anyone.

**Remediation:**

> Require authentication on the registry's Docker V2 API (`/v2/`) endpoint. Most managed registries do this by default — if yours is public, check whether *Admin user* or anonymous pull is enabled and disable it. Don't rely on "no images yet" as a control.

**Tags:** `cloud`, `registry`, `container`, `public-access`
**Alert name:** Container Registry — Public Catalog
**Monitor type:** `cloud_change`

**References:**
- OCI Distribution Spec — Authentication
- Microsoft — Authenticate with an Azure container registry

---

### `cloud-serverless-no-auth`

**Severity:** HIGH · **CWE:** CWE-306 · **Category:** service_exposure

**Title:** Unauthenticated {provider} endpoint: {value}

**Summary:** A serverless endpoint on your domain is callable without authentication — review whether that's intentional.

**Description:**

> The {provider} app {value} is callable from the public internet without authentication. Even when the function doesn't leak data directly, public functions can expose business logic, allow data exfiltration via crafted inputs, and let third parties run up your compute bill.

**Remediation:**

> Add authentication appropriate to the platform:
>   • Azure Functions — set *Authentication* to required, or use function-level keys for machine-to-machine traffic.
>   • Google Cloud Run — make the service private and grant `roles/run.invoker` only to the identities that need it.
>   • AWS Lambda — replace anonymous Function URLs with API Gateway plus a JWT authoriser, or set `AuthType=AWS_IAM` on the Function URL.
>
> If the endpoint is intentionally public (webhook, signup form), ensure rate limiting and strict input validation are in place — public functions are often abused to amplify spam, brute-force credentials, or exhaust API quotas.

**Tags:** `cloud`, `serverless`, `no-auth`, `public-access`
**Alert name:** Serverless — No Auth
**Monitor type:** `cloud_change`

**References:**
- OWASP — Serverless Top 10
- Microsoft — Authentication and authorization in Azure App Service
- Google Cloud — Authenticating service-to-service
- AWS — Lambda function URL invoke modes

---

### `cloud-serverless-stack-trace`

**Severity:** HIGH · **CWE:** CWE-209 · **Category:** service_exposure

**Title:** {provider} endpoint leaking stack traces: {value}

**Summary:** A serverless endpoint on your domain returns full stack traces in error responses, exposing internal code paths.

**Description:**

> The {provider} app {value} is publicly accessible and returns full stack traces in error responses. The traces reveal internal file paths, dependency versions, and code structure — material that lets an attacker tailor exploits to the exact framework versions in use, and identify vulnerable dependencies that haven't been patched.

**Remediation:**

> Return generic error messages to clients in production; log the full stack trace server-side instead. Most frameworks have a single config switch:
>   • Express / Node — `NODE_ENV=production`.
>   • Django — `DEBUG = False`.
>   • Flask — `app.debug = False`.
>   • Spring Boot — `server.error.include-stacktrace=never`.
>   • ASP.NET — `<customErrors mode="On"/>` or `UseExceptionHandler` middleware.
>
> Add authentication to the endpoint as well — a verbose-error config flag is a one-line miss away from regressing.

**Tags:** `cloud`, `serverless`, `stack-trace`, `public-access`
**Alert name:** Serverless — Stack Trace Leak
**Monitor type:** `cloud_change`

**References:**
- OWASP — Improper Error Handling
- CWE-209: Generation of Error Message Containing Sensitive Information

---

### `cloud-storage-public-access`

**Severity:** HIGH · **CWE:** CWE-732 · **Category:** service_exposure

**Title:** Publicly accessible {provider} bucket: {value}

**Summary:** A cloud bucket on your domain is publicly readable — anyone who knows or guesses an object name can download it.

**Description:**

> The {provider} bucket {value} allows public access. Object listing is not enabled, so attackers can't trivially enumerate the bucket — but any object whose name they can guess (or learn from logs, leaks, or referrer headers) is downloadable. Public buckets without listing are still a common source of backup-file and config-file leaks.

**Remediation:**

> **Decide whether public access is intentional**
>   Static-site assets, marketing PDFs, and product images are legitimate use cases. Anything else should be private.
>
> **If public access is required**
>   • Confirm no sensitive data is stored in the bucket — no backups, no `.env`, no internal docs, no PII.
>   • Enable access logging and review periodically.
>   • Consider serving content via CDN with origin auth so the bucket itself can stay private.
>
> **If public access is NOT required**
>   • AWS S3 — enable *Block Public Access* and remove `Principal: "*"` from the bucket policy.
>   • Azure Blob Storage — set anonymous access to *Disabled*.
>   • Google Cloud Storage — remove `allUsers` from IAM bindings.

**Tags:** `cloud`, `storage`, `public-access`
**Alert name:** Cloud Bucket — Public
**Monitor type:** `cloud_change`

**References:**
- AWS — Blocking public access to your S3 storage
- Microsoft — Configure anonymous public read access
- Google Cloud — Make data public

---

### `cloud-registry-private-tracked`

**Severity:** INFO · **CWE:** — · **Category:** service_exposure · **Tunable:** no

**Title:** {provider} detected (private): {value}

**Summary:** A private container registry on your domain — tracked so we'll notice if it later becomes public.

**Description:**

> The {provider} {value} exists and requires authentication. Recorded for inventory and change-detection — if the registry later opens up, the monitor will fire.

**Remediation:**

> No action required. Registry access is correctly restricted.

**Tags:** `cloud`, `registry`, `container`, `inventory`
**Alert name:** Container Registry — Inventory
**Monitor type:** `cloud_change`

---

### `cloud-storage-private-tracked`

**Severity:** INFO · **CWE:** — · **Category:** service_exposure · **Tunable:** no

**Title:** {provider} bucket detected (private): {value}

**Summary:** A private cloud bucket on your domain — tracked so we'll notice if it later becomes public.

**Description:**

> The {provider} bucket {value} exists and is configured for private access. Recorded for inventory and change-detection — if the bucket later becomes public, the monitor will fire.

**Remediation:**

> No action required. Bucket access is correctly restricted.

**Tags:** `cloud`, `storage`, `inventory`
**Alert name:** Cloud Bucket — Inventory
**Monitor type:** `cloud_change`

---

## Sensitive Path / Leak Detection

_32 templates_

### `leak-env-file`

**Severity:** CRITICAL · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Environment file exposed at {asset} ({value})

**Summary:** An environment file on {asset} is publicly readable — its credentials should be considered compromised. Rotate now.

**Description:**

> An environment file at {value} is publicly readable on {asset}. Environment files routinely contain database passwords, API keys for AWS / Stripe / Google / Twilio, OAuth client secrets, and signing keys — exactly the credentials an attacker needs for full account compromise.

**Remediation:**

> **Rotate first, then close the door**
>   Treat every credential in the file as compromised — assume automated scanners pulled it within minutes of exposure. Rotate AWS keys, database passwords, OAuth secrets, signing keys, and any third-party API tokens before doing anything else.
>
> **Block .env files at the web server**
>   • nginx: `location ~ /\.env { deny all; return 404; }`
>   • Apache: `RedirectMatch 404 /\.env`
>
> **Stop deploying secrets in files**
>   Move secrets into a managed store (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, or your platform's equivalent) and inject them into the runtime as env vars at process start, not as files in the deploy bundle.

**Tags:** `exposed-file`, `secrets`, `env-file`
**Alert name:** Environment File Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- OWASP Cheat Sheet — Secrets Management

---

### `leak-git-exposed`

**Severity:** CRITICAL · **CWE:** CWE-538 · **Category:** data_leaks

**Title:** Git repository exposed at {asset} ({value})

**Summary:** The .git directory on {asset} is downloadable — anyone can reconstruct your full source code and commit history.

**Description:**

> The .git directory is publicly served from {asset}. The full commit history, including any secrets that were committed and later "removed", is reachable. Tools like `git-dumper` reconstruct the entire repo from this in under a minute, yielding source code, internal documentation, and credential history.

**Remediation:**

> **Block .git/ at the web server**
>   • nginx: `location ~ /\.git { deny all; return 404; }`
>   • Apache: `RedirectMatch 404 /\.git(/|$)`
>   • IIS: add a request-filtering rule for `/.git/`.
>
> **Treat exposed history as compromised**
>   Run a secret scanner (`gitleaks`, `trufflehog`) over the repo and rotate every credential that's ever been committed — even ones in `git rm`'d commits, since the history is now public.
>
> **Prevent recurrence**
>   Don't deploy a working copy to a public webroot. CI/CD should produce a build artefact and copy only that.

**Tags:** `exposed-file`, `source_control`, `git`
**Alert name:** Git Repo Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- git-dumper — repo reconstruction tool

---

### `leak-github-api-key`

**Severity:** CRITICAL · **CWE:** CWE-798 · **Category:** data_leaks

**Title:** API keys referencing {asset} found in public GitHub code

**Summary:** Code search found API keys referencing {asset} in public GitHub repos — rotate and audit usage.

**Description:**

> Public-GitHub code search returned matches for API key / secret key / token patterns alongside references to {asset}. API keys leaked into public code are routinely abused within hours — for spam, crypto-mining via the compromised account, data exfiltration, or as a stepping stone to broader compromise.

**Remediation:**

> Open each matching file and confirm whether a real API key is present. If it is, rotate it immediately at the issuing service (AWS console / Stripe dashboard / Twilio account keys / etc.). Review the API's usage logs since the leak for any abuse. Get the file removed from the repo and rewrite history with `git filter-repo`. Enable secret scanning + push protection on your GitHub orgs to catch the next one before it pushes.

**Tags:** `github-leak`, `api-key`, `code-search`
**Alert name:** GitHub — API Key Leaked
**Monitor type:** `github_change`

**References:**
- GitHub — About secret scanning
- OWASP Cheat Sheet — Secrets Management
- trufflesecurity/trufflehog (open-source secret scanning)

---

### `leak-github-cloud-creds`

**Severity:** CRITICAL · **CWE:** CWE-798 · **Category:** data_leaks

**Title:** Cloud credentials referencing {asset} found in public GitHub code

**Summary:** Code search found cloud credentials referencing {asset} in public GitHub repos — rotate now and audit cloud activity.

**Description:**

> Public-GitHub code search returned matches for AWS / GCP / Azure credential patterns alongside references to {asset}. Cloud credentials in public code are the most aggressively harvested type — Trufflehog-style scanners poll GitHub's events API constantly, and exposed AWS keys are typically abused for crypto-mining within minutes.

**Remediation:**

> **Treat as an active incident**
>   Rotate the cloud credentials immediately at the provider:
>   • AWS — IAM → Access Keys → Make inactive, then delete; audit CloudTrail for the key's recent activity.
>   • GCP — IAM → Service Accounts → revoke the key; review Audit Logs.
>   • Azure — App registrations / managed identities → rotate the secret; review Sign-in logs.
>
> **Scope the impact**
>   Use the cloud provider's audit logs to confirm whether the key was used by an unknown principal during the leak window. If it was, escalate to a full IR.
>
> **Prevent recurrence**
>   Use short-lived credentials wherever possible (IAM roles, Workload Identity, managed identities) instead of static access keys. Enable GitHub secret scanning + push protection.

**Tags:** `github-leak`, `cloud-creds`, `code-search`
**Alert name:** GitHub — Cloud Creds Leaked
**Monitor type:** `github_change`

**References:**
- GitHub — About secret scanning
- OWASP Cheat Sheet — Secrets Management
- trufflesecurity/trufflehog (open-source secret scanning)
- AWS — What to do if you inadvertently expose an AWS access key

---

### `leak-github-credentials`

**Severity:** CRITICAL · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Credentials referencing {asset} found in public GitHub code

**Summary:** Code search found credentials referencing {asset} in public GitHub repos — verify and rotate any real secrets.

**Description:**

> Public-GitHub code search returned matches for password / credential / SMTP / JDBC patterns alongside references to {asset}. This often means a developer committed a secret into a public repository — the credential may already be in attacker-run scanners that harvest GitHub continuously.

**Remediation:**

> **Verify and rotate**
>   Open each matching file. If a real credential is present, rotate it immediately — assume it's already been exfiltrated by automation that monitors public-repo pushes.
>
> **Get the leak removed**
>   Ask the repo owner to remove the file and rewrite history (`git filter-repo` or BFG). A simple `git rm` doesn't help — the credential remains in the commit history. If the repo is yours, rewrite history; if it's a third party, contact them or use GitHub's content-removal process.
>
> **Prevent recurrence**
>   Enable GitHub's secret scanning + push protection on all your orgs. Add `gitleaks` or `trufflehog` to the CI pipeline as a pre-merge gate.

**Tags:** `github-leak`, `credentials`, `code-search`
**Alert name:** GitHub — Credentials Leaked
**Monitor type:** `github_change`

**References:**
- GitHub — About secret scanning
- OWASP Cheat Sheet — Secrets Management
- trufflesecurity/trufflehog (open-source secret scanning)

---

### `leak-github-env-file`

**Severity:** CRITICAL · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** .env files referencing {asset} found in public GitHub code

**Summary:** Code search found .env files referencing {asset} in public GitHub repos — rotate every secret inside.

**Description:**

> .env files referencing {asset} were found in public-GitHub code search results. Environment files committed to public repos are a well-known pattern — they typically contain database credentials, API keys, and OAuth secrets in their production form.

**Remediation:**

> Open each matching file. Treat every credential inside as compromised — rotate database passwords, API keys, OAuth secrets, signing keys, and any third-party tokens. Have the .env file removed from the repository and rewrite history with `git filter-repo`. Add `.env` to .gitignore going forward and enable GitHub's secret scanning so the next push that includes a .env is blocked at PR time.

**Tags:** `github-leak`, `env-file`, `code-search`
**Alert name:** GitHub — .env Leaked
**Monitor type:** `github_change`

**References:**
- GitHub — About secret scanning
- OWASP Cheat Sheet — Secrets Management
- trufflesecurity/trufflehog (open-source secret scanning)

---

### `leak-github-secrets`

**Severity:** CRITICAL · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Private keys referencing {asset} found in public GitHub code

**Summary:** Code search found private keys referencing {asset} in public GitHub repos — revoke and rotate immediately.

**Description:**

> Public-GitHub code search returned matches for private-key material (RSA / EC / OpenSSH / PGP private blocks) alongside references to {asset}. Whatever the key authenticates to — SSH access, code-signing, certificate issuance, JWT signing — should now be considered compromised.

**Remediation:**

> Identify what the key authenticates and revoke it: remove the public key from authorized_keys (SSH); revoke the certificate (code-signing, TLS); rotate the JWT signing secret. Generate a fresh keypair and distribute the new public component only to systems that need it. Get the private key removed from the public repository and rewrite history. Enable GitHub secret scanning.

**Tags:** `github-leak`, `secrets`, `private-key`, `code-search`
**Alert name:** GitHub — Private Key Leaked
**Monitor type:** `github_change`

**References:**
- GitHub — About secret scanning
- OWASP Cheat Sheet — Secrets Management
- trufflesecurity/trufflehog (open-source secret scanning)

---

### `leak-gitlab-api-key`

**Severity:** CRITICAL · **CWE:** CWE-798 · **Category:** data_leaks

**Title:** API tokens referencing {asset} found in public GitLab code

**Summary:** Public GitLab code search returned API tokens referencing {asset} — verify each match and rotate immediately if real.

**Description:**

> Public-GitLab blob search returned files referencing {asset} alongside identifiers that look like API tokens or keys. Some matches will be false positives (variable names, comments, fixtures), but each one needs eyes on it because a single live key can hand attackers full programmatic access to your service.

**Remediation:**

> Open each matching file and check whether a real token is present. If yes, revoke or rotate the token at the issuing service immediately, then scrub the file from the project's git history (deleting the current commit isn't enough — history retains the value). Notify the project owner if the repository isn't yours.

**Tags:** `gitlab-leak`, `api-key`, `code-search`
**Alert name:** GitLab — API Token Possibly Leaked
**Monitor type:** `github_change`

**References:**
- GitLab — Removing sensitive data from a repository
- OWASP Application Security Verification Standard — Secrets Management
- CIS Critical Security Controls — v8 Control 4 (Secure Configuration)

---

### `leak-gitlab-cloud-creds`

**Severity:** CRITICAL · **CWE:** CWE-798 · **Category:** data_leaks

**Title:** Cloud credentials referencing {asset} found in public GitLab code

**Summary:** Public GitLab code search returned cloud-credential strings referencing {asset} — rotate at the cloud provider TODAY if real.

**Description:**

> Public-GitLab blob search returned files referencing {asset} alongside cloud-credential strings (AWS_SECRET_ACCESS_KEY, GCP service-account JSON, Azure shared keys). Cloud credentials are among the highest-impact leaks — a working key can cost five to six figures within hours via crypto mining or data exfiltration.

**Remediation:**

> Treat this as same-day work. Verify whether a real credential is present in each match. If yes:
>   1. Rotate the credential at the cloud provider IMMEDIATELY.
>   2. Audit the cloud account for unauthorised activity since      the file's commit date.
>   3. Scrub the file from project history.
>   4. Configure git pre-commit hooks (gitleaks, detect-secrets)      to block future commits.

**Tags:** `gitlab-leak`, `cloud-creds`, `aws`, `gcp`, `azure`
**Alert name:** GitLab — Cloud Credentials Possibly Leaked
**Monitor type:** `github_change`

**References:**
- GitLab — Removing sensitive data from a repository
- OWASP Application Security Verification Standard — Secrets Management
- CIS Critical Security Controls — v8 Control 4 (Secure Configuration)

---

### `leak-gitlab-credentials`

**Severity:** CRITICAL · **CWE:** CWE-798 · **Category:** data_leaks

**Title:** Credentials referencing {asset} found in public GitLab code

**Summary:** Public GitLab code search returned files referencing {asset} that may contain credentials — open each match and rotate any real secrets.

**Description:**

> Public-GitLab blob search returned files referencing {asset} alongside what looks like credential material (passwords, DB_PASSWORD-style env strings). Code search alone can't confirm a true leak — the matched files might use the keyword in a different context — but every match is worth opening and verifying. Real credential exposure on a public GitLab project means an attacker can copy/paste the secret straight into a working session.

**Remediation:**

> Open each matching file linked in the finding details and verify whether a real credential is present. If yes, rotate the credential immediately and revoke any tokens it grants. Then have the file removed: GitLab keeps full history, so deleting the current copy isn't enough — use `git filter-repo` or BFG Repo-Cleaner to scrub history, then force-push. If the repository belongs to someone else, contact the project owner or use GitLab's abuse-reporting form to request takedown.

**Tags:** `gitlab-leak`, `credentials`, `code-search`
**Alert name:** GitLab — Credentials Possibly Leaked
**Monitor type:** `github_change`

**References:**
- GitLab — Removing sensitive data from a repository
- OWASP Application Security Verification Standard — Secrets Management
- CIS Critical Security Controls — v8 Control 4 (Secure Configuration)

---

### `leak-htpasswd`

**Severity:** CRITICAL · **CWE:** CWE-522 · **Category:** data_leaks

**Title:** Apache password file exposed at {asset} ({value})

**Summary:** Your Apache .htpasswd file is publicly readable — every account in it should be reset.

**Description:**

> The Apache .htpasswd file at {value} is publicly readable on {asset}. The hashes inside are crackable offline — GPU-accelerated tools can crunch through tens of millions of guesses per second against bcrypt or MD5-crypt hashes — turning a single misconfigured line in your Apache config into account takeover.

**Remediation:**

> Move the .htpasswd file outside the web root entirely (`/etc/apache2/.htpasswd` is conventional). Update your AuthUserFile directive to point at the new location. Block `/.htpasswd` at the server level as a defence-in-depth. Force a password reset for every user listed in the leaked file — assume the hashes are being cracked right now.

**Tags:** `exposed-file`, `config`, `htpasswd`
**Alert name:** htpasswd Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- Apache Docs — Authentication and Authorization

---

### `leak-sql-dump`

**Severity:** CRITICAL · **CWE:** CWE-552 · **Category:** data_leaks

**Title:** SQL database dump exposed at {asset} ({value})

**Summary:** A SQL database dump is publicly downloadable from {asset} — treat as a confirmed breach. Notify and reset.

**Description:**

> A SQL dump file at {value} is publicly downloadable from {asset}. Database dumps typically contain every row in every table at the moment of export — user accounts (often with hashed passwords), session data, payment records, internal admin notes. Exposed dumps are routinely the starting point of regulator-reportable breaches.

**Remediation:**

> **Treat as a confirmed data breach**
>   Assume the dump has been downloaded — automated scanners harvest exposed `.sql` files within minutes. Engage your incident-response process: notify your privacy officer / DPO, scope the data classes involved (PII, payment, health, auth material), and start your jurisdictional breach-notification clock.
>
> **Remove and block**
>   Delete the dump from the webroot. Block `*.sql`, `*.dump`, `*.bak.sql`, `backup-*` patterns at the web server.
>
> **Reset auth material**
>   Force a password reset for every user account in the dump; rotate any API keys or session-signing keys that were in the database; invalidate every session token issued before the dump was first reachable.

**Tags:** `exposed-file`, `data_leak`, `sql-dump`
**Alert name:** SQL Dump Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- OAIC — Notifiable Data Breaches scheme (Australia)
- ICO — Personal data breaches (UK)

---

### `leak-ssh-private-key`

**Severity:** CRITICAL · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** SSH private key exposed at {asset} ({value})

**Summary:** An SSH private key on {asset} is publicly readable — assume any host that trusts the matching public key is compromised.

**Description:**

> An SSH private key at {value} is publicly readable on {asset}. Anyone who downloaded it can SSH into any system where the corresponding public key is authorised. This is a direct path to remote shell access on whatever the key opens.

**Remediation:**

> **Treat the key as compromised, immediately**
>   Identify every host where the corresponding public key appears in `~/.ssh/authorized_keys` (or in a managed key system / IAM). Remove the public key from all of them.
>
> **Generate a fresh keypair**
>   Use a modern algorithm (`ssh-keygen -t ed25519`) and distribute the new public key only to the systems that need it.
>
> **Block private-key files at the web server**
>   Deny `/id_rsa`, `/.ssh/`, `/*.pem`, `/*.key` paths at the edge so a single deploy mistake doesn't expose another key.
>
> **Audit access logs**
>   Review SSH and bastion logs for any successful auth that could have used the leaked key while it was reachable.

**Tags:** `exposed-file`, `secrets`, `ssh-key`
**Alert name:** SSH Key Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- OpenSSH — Best Practices

---

### `leak-wp-config-backup`

**Severity:** CRITICAL · **CWE:** CWE-552 · **Category:** data_leaks

**Title:** WordPress config backup exposed at {asset} ({value})

**Summary:** A WordPress wp-config backup is publicly readable on {asset} — DB credentials and auth keys should be rotated now.

**Description:**

> A backup copy of wp-config.php (e.g. wp-config.php.bak, wp-config.php~, common when an editor saves a `.bak` alongside the file) is publicly readable on {asset}. PHP isn't executed for the .bak extension, so the file is served as plain text — exposing DB_NAME, DB_USER, DB_PASSWORD, AUTH_KEY, and other secrets.

**Remediation:**

> **Rotate first**
>   Treat the database password, auth keys, and any API keys in wp-config.php as compromised. Rotate the DB password immediately; regenerate AUTH_KEY/SECURE_AUTH_KEY/LOGGED_IN_KEY/NONCE_KEY and the four corresponding salts (use the WordPress salt generator).
>
> **Remove backup files from the webroot**
>   Delete every `*.bak`, `*~`, `*.orig`, `*.old` file from the webroot. Add a deny rule at the web server for those extensions so editor-save patterns can't recreate the exposure.
>
> **Audit for further compromise**
>   Review wp-content/uploads for unfamiliar PHP files, and the wp_users table for unexpected admin accounts.

**Tags:** `exposed-file`, `config`, `wordpress`
**Alert name:** WordPress Config Backup Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- WordPress — Editing wp-config.php
- WordPress.org — Salt Generator

---

### `leak-apache-status`

**Severity:** HIGH · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Apache server status / info exposed at {asset} ({value})

**Summary:** Apache server-status / server-info is publicly reachable on {asset} — it leaks live request info to anyone who looks.

**Description:**

> Apache mod_status / mod_info output is publicly reachable at {value}. The page lists active connections (with client IPs and the URLs they're requesting), child worker state, loaded modules, and configuration directives — live intelligence about who's using your site and how the server is wired.

**Remediation:**

> Restrict /server-status and /server-info to localhost or your monitoring network:
> ```
> <Location "/server-status">
>   SetHandler server-status
>   Require ip 127.0.0.1
> </Location>
> ```
> Better, disable mod_status entirely if you have a separate metrics pipeline (Prometheus exporter, Datadog, etc.).

**Tags:** `exposed-file`, `info_leak`, `apache`
**Alert name:** Apache Status Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- Apache Docs — mod_status

---

### `leak-docker-compose`

**Severity:** HIGH · **CWE:** CWE-538 · **Category:** data_leaks

**Title:** docker-compose.yml exposed at {asset} ({value})

**Summary:** A docker-compose.yml is publicly readable on {asset} — it likely contains environment secrets that should be rotated.

**Description:**

> A docker-compose.yml file at {value} is publicly readable on {asset}. The file describes service architecture, container images, environment variables, internal port wiring, and frequently — by accident — secrets baked into `environment:` blocks (database passwords, API keys, JWT signing secrets).

**Remediation:**

> **Rotate any secrets that appear in the file**
>   Treat values inside `environment:` as compromised; rotate before doing anything else.
>
> **Block YAML files at the web server**
>   Deny `/*.yml`, `/*.yaml`, `/Dockerfile`, `/docker-compose*`. These should never be in a webroot.
>
> **Move secrets out of compose**
>   Use Docker secrets, Compose's `secrets:` block, or a managed secret store (Vault, Doppler, AWS Secrets Manager) and reference them by name rather than embedding values.

**Tags:** `exposed-file`, `config`, `docker`
**Alert name:** docker-compose Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- Docker Docs — Manage sensitive data with Docker secrets

---

### `leak-github`

**Severity:** HIGH · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Possible code leak referencing {asset} in public GitHub repos

**Summary:** Public GitHub code search found content referencing {asset} — review for any leaked secrets.

**Description:**

> Public-GitHub code search returned results referencing {asset}. The matches may include credentials, configuration, or other material that shouldn't be in public code.

**Remediation:**

> Open each matching file and assess whether real secrets, credentials, or sensitive configuration are exposed. If so, rotate immediately and have the file removed from the public repository (a `git rm` isn't enough — use `git filter-repo` to scrub history). Enable GitHub's secret scanning + push protection to prevent recurrence.

**Tags:** `github-leak`, `code-search`
**Alert name:** GitHub — Code Leak
**Monitor type:** `github_change`

**References:**
- GitHub — About secret scanning
- OWASP Cheat Sheet — Secrets Management
- trufflesecurity/trufflehog (open-source secret scanning)

---

### `leak-gitlab-env-file`

**Severity:** HIGH · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Environment files referencing {asset} found in public GitLab code

**Summary:** Public GitLab code search returned .env files referencing {asset} — assume credentials inside are leaked and rotate.

**Description:**

> Public-GitLab blob search returned `.env` files referencing {asset}. Environment files routinely contain database passwords, API keys, OAuth secrets, and other production-critical material. A `.env` published to a public repo is one of the highest-impact leak categories.

**Remediation:**

> Open each matching `.env` file and review every line. Rotate every real credential, scrub the file from git history, and add `.env*` to `.gitignore` going forward. Configure a pre-commit hook to block future `.env` commits.

**Tags:** `gitlab-leak`, `env-file`, `code-search`
**Alert name:** GitLab — .env File Leaked
**Monitor type:** `github_change`

**References:**
- GitLab — Removing sensitive data from a repository
- OWASP Application Security Verification Standard — Secrets Management
- CIS Critical Security Controls — v8 Control 4 (Secure Configuration)

---

### `leak-gitlab-secrets`

**Severity:** HIGH · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Secret-like strings referencing {asset} found in public GitLab code

**Summary:** Public GitLab code search returned secret-like strings referencing {asset} — verify each match.

**Description:**

> Public-GitLab blob search returned files referencing {asset} alongside the keyword 'secret'. Many of these will be config constants or comments rather than real secrets, but each match should be opened and verified.

**Remediation:**

> Open each matching file and check whether a real secret is present. Rotate any live values, scrub the file from git history, and add pre-commit secret-scanning to the repository.

**Tags:** `gitlab-leak`, `secrets`, `code-search`
**Alert name:** GitLab — Secret-Like String Found
**Monitor type:** `github_change`

**References:**
- GitLab — Removing sensitive data from a repository
- OWASP Application Security Verification Standard — Secrets Management
- CIS Critical Security Controls — v8 Control 4 (Secure Configuration)

---

### `leak-package-creds`

**Severity:** HIGH · **CWE:** CWE-522 · **Category:** data_leaks

**Title:** Package manager credentials exposed at {asset} ({value})

**Summary:** A package-manager auth file on {asset} is publicly readable — registry tokens should be rotated.

**Description:**

> A package-manager configuration file at {value} is publicly readable on {asset}. Files like .npmrc and .pypirc commonly contain auth tokens for private package registries — leaking them lets an attacker push malicious package versions that your build pipeline will consume on the next install.

**Remediation:**

> Rotate the registry auth token immediately (npm: regenerate in npmjs.com → Access Tokens; PyPI: regenerate via pypi.org/manage/account/token). Block dotfiles at the web server (nginx `location ~ /\.npmrc`, etc.). Don't commit auth files to the deploy bundle — inject the token at CI time via environment variables and clean it up after the publish step.

**Tags:** `exposed-file`, `secrets`, `package-manager`
**Alert name:** Package Manager Creds Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- npm Docs — Access Tokens
- PyPI Help — API tokens

---

### `leak-phpinfo`

**Severity:** HIGH · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** phpinfo() exposed at {asset} ({value})

**Summary:** A phpinfo() page is exposed on {asset} — delete it; it's a recon goldmine.

**Description:**

> A phpinfo() page is reachable at {value} on {asset}. The page reveals the PHP version (mappable to known CVEs), every loaded module, full server environment variables, file system paths, and INI settings — high-value reconnaissance that lets an attacker pinpoint exploitable versions.

**Remediation:**

> Delete the phpinfo file. It's almost always a debug artefact left over from a deploy or troubleshooting session — there's no production use case for serving it. Add a deny rule for `phpinfo.php` and similar diagnostic filenames at the web server.

**Tags:** `exposed-file`, `info_leak`, `phpinfo`
**Alert name:** phpinfo Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- OWASP WSTG — Test for Information Exposure

---

### `leak-svn-exposed`

**Severity:** HIGH · **CWE:** CWE-538 · **Category:** data_leaks

**Title:** Subversion metadata exposed at {asset} ({value})

**Summary:** The .svn directory on {asset} is downloadable — your source code and history are reachable.

**Description:**

> The .svn metadata directory is publicly served from {asset}. Like exposed .git, this lets an attacker reconstruct the Subversion working copy — source code, prior revisions, and any credentials that were committed.

**Remediation:**

> Block `/.svn/` at the web server (nginx `deny all`, Apache `RedirectMatch 404`, IIS request filtering). Don't deploy a working copy to a public webroot — produce a build artefact instead. Rotate any credentials that may be in the repository history.

**Tags:** `exposed-file`, `source_control`, `svn`
**Alert name:** SVN Metadata Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File

---

### `leak-web-config`

**Severity:** HIGH · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** IIS web.config exposed at {asset} ({value})

**Summary:** Your IIS web.config is publicly readable — it may include database connection strings and machine keys.

**Description:**

> The IIS web.config file at {value} is publicly readable on {asset}. IIS should never serve web.config — when it does, an attacker may see database connection strings (sometimes with passwords), encryption keys for ViewState / forms auth, and the full module pipeline.

**Remediation:**

> IIS blocks web.config by default via `<hiddenSegments>` in applicationHost.config — restore that setting. Move connection strings and other secrets out of web.config and into Azure Key Vault, environment variables, or `secrets.json` (development only). Rotate any credentials or machineKey values that were exposed.

**Tags:** `exposed-file`, `config`, `iis`
**Alert name:** web.config Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- Microsoft — Hidden Segments in IIS

---

### `leak-wp-installer`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** data_leaks

**Title:** WordPress installer accessible at {asset} ({value})

**Summary:** WordPress installer is reachable on {asset} — confirm the site hasn't been re-initialised by an attacker.

**Description:**

> WordPress's install.php is reachable on {asset}. If the site isn't already initialised, an attacker can complete the install with their own admin credentials and database configuration — taking ownership of the site outright. Even on an initialised site, the installer leaks version information.

**Remediation:**

> Block /wp-admin/install.php at the web server until the install is complete, then keep it blocked: `location = /wp-admin/install.php { deny all; }` (nginx) or an equivalent Apache rule. Confirm the wp-admin/ login page redirects to the dashboard — if it shows the installer form, the site has been re-initialised by an attacker; restore from backup.

**Tags:** `exposed-file`, `config`, `wordpress`
**Alert name:** WordPress Installer Accessible
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- WordPress — Hardening WordPress

---

### `leak-api-docs`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** API documentation exposed at {asset} ({value})

**Summary:** API documentation is publicly accessible on {asset} — verify whether this is intentional.

**Description:**

> An OpenAPI / Swagger documentation endpoint is reachable at {value} on {asset}. Public API docs are intentional for many products — but if this endpoint describes internal or admin APIs, you've handed an attacker a complete map of every endpoint, method, parameter, and response shape, including ones you didn't intend to expose.

**Remediation:**

> Decide whether the docs are intentionally public:
>   • **Public docs** (e.g., a developer portal) — leave them, but ensure they describe only the public API surface. Generate from source so admin endpoints can't accidentally leak.
>   • **Internal docs** — restrict to authenticated users, or to your VPN / private network. Most API frameworks expose a config flag (`springdoc.api-docs.enabled=false` for Spring; `SWAGGER_UI=False` in Django REST; mount behind auth in FastAPI/Express).

**Tags:** `exposed-file`, `info_leak`, `api-docs`
**Alert name:** API Docs Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- OWASP API Security Top 10

---

### `leak-dockerfile`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Dockerfile exposed at {asset} ({value})

**Summary:** A Dockerfile is publicly readable on {asset} — it leaks build details and may contain hardcoded credentials.

**Description:**

> A Dockerfile at {value} is publicly readable on {asset}. It reveals the base image, exact build steps, file paths, and dependency list — and occasionally hardcoded credentials, registry tokens, or signing keys baked into the build.

**Remediation:**

> Don't deploy Dockerfiles to a public webroot — produce a build artefact and copy only that. Block `/Dockerfile` at the web server. Audit the file for any hardcoded secrets (`ARG TOKEN=...`, `ENV API_KEY=...`) and rotate them; future builds should pull secrets at build time via `--secret` mounts rather than baking them into the image.

**Tags:** `exposed-file`, `config`, `docker`
**Alert name:** Dockerfile Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- Docker Docs — Build secrets

---

### `leak-github-config`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Config files referencing {asset} found in public GitHub code

**Summary:** Code search found config files referencing {asset} in public GitHub repos — review for credential or topology leaks.

**Description:**

> Public-GitHub code search returned config files (json, yaml, ini, conf) referencing {asset}. Config files don't always contain secrets, but they routinely leak internal hostnames, API endpoints, ports, ACL rules, and other reconnaissance material that helps an attacker map your environment.

**Remediation:**

> Open each matching file and confirm what's exposed. If real credentials are present, rotate. If only configuration metadata is exposed, decide whether it should be public — internal hostnames and endpoint lists are sometimes deliberately published, but more often they're an oversight. Have the file removed from the repo if it's an oversight.

**Tags:** `github-leak`, `config`, `code-search`
**Alert name:** GitHub — Config Leaked
**Monitor type:** `github_change`

**References:**
- GitHub — About secret scanning
- OWASP Cheat Sheet — Secrets Management
- trufflesecurity/trufflehog (open-source secret scanning)

---

### `leak-gitlab-config`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Config files referencing {asset} found in public GitLab code

**Summary:** Code search found config files referencing {asset} in public GitLab projects — review for credential or topology leaks.

**Description:**

> Public-GitLab blob search returned config files (json, yaml, ini, conf) referencing {asset}. Config files don't always contain secrets, but they often leak internal hostnames, API endpoints, ports, and ACL rules that help an attacker map your environment.

**Remediation:**

> Open each matching file and confirm what's exposed. If real credentials are present, rotate. If only configuration metadata is exposed, decide whether it should be public — internal hostnames and endpoint lists are sometimes deliberately published, but more often they're an oversight. Have the file removed from the project if it's an oversight.

**Tags:** `gitlab-leak`, `config`, `code-search`
**Alert name:** GitLab — Config Leaked
**Monitor type:** `github_change`

**References:**
- GitLab — Removing sensitive data from a repository
- OWASP Application Security Verification Standard — Secrets Management
- CIS Critical Security Controls — v8 Control 4 (Secure Configuration)

---

### `leak-htaccess`

**Severity:** MEDIUM · **CWE:** CWE-538 · **Category:** data_leaks

**Title:** Apache .htaccess exposed at {asset} ({value})

**Summary:** Your .htaccess file is publicly readable — recon material for attackers, not a direct breach.

**Description:**

> An .htaccess file at {value} is publicly readable on {asset}. Itself it isn't a secret, but it often reveals rewrite rules, internal endpoints, basic-auth realms, IP allowlists, and other recon hints that tell an attacker where to focus.

**Remediation:**

> Block `.htaccess` at the web server: nginx already ignores it; Apache should set `<FilesMatch "^\.">` to deny. The file's settings should still apply to the application — only the file content needs to be hidden.

**Tags:** `exposed-file`, `config`, `htaccess`
**Alert name:** .htaccess Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File

---

### `leak-path`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Sensitive path exposed at {asset}: {value}

**Summary:** A sensitive path is publicly readable on {asset} — review and remove or restrict.

**Description:**

> The path {value} is publicly readable on {asset} and matches a sensitive-path pattern (config file, backup, debug endpoint, or similar). The contents may include credentials, configuration, or material that aids reconnaissance.

**Remediation:**

> Confirm what the file contains and whether it's intended to be public. If it's not, remove it from the webroot and add a deny rule at the web server. If any credentials, keys, or session-signing material were in the file, rotate them before closing the door — assume automated scanners captured the contents.

**Tags:** `exposed-file`
**Alert name:** Sensitive Path Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File

---

### `leak-ds-store`

**Severity:** LOW · **CWE:** CWE-538 · **Category:** data_leaks

**Title:** .DS_Store exposed at {asset} ({value})

**Summary:** A .DS_Store file on {asset} reveals the names of files in the directory — minor recon win for attackers.

**Description:**

> A macOS .DS_Store file at {value} is publicly readable on {asset}. The binary file lists every file and folder in the directory it was created from — a quick way for an attacker to discover hidden filenames the directory listing wouldn't otherwise show. Often a sign that the site was deployed by drag-and-drop from a Mac.

**Remediation:**

> Delete .DS_Store files from the webroot. Add `.DS_Store` to your deploy ignore list and to .gitignore. Block the filename at the web server as a defence in depth. Run `find . -name .DS_Store -delete` over the deploy artefact before publishing.

**Tags:** `exposed-file`, `info_leak`, `macos`
**Alert name:** .DS_Store Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File

---

### `leak-package-manifest`

**Severity:** LOW · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Package manifest exposed at {asset} ({value})

**Summary:** A package manifest is publicly readable on {asset} — your full dependency list is visible to attackers.

**Description:**

> A package manifest (package.json, composer.json) at {value} is publicly readable on {asset}. The exposure isn't directly exploitable, but the manifest reveals every dependency and version — which lets an attacker run a vulnerability-database lookup against your full dependency tree without lifting a finger.

**Remediation:**

> Don't ship the source-tree manifest into a public webroot — production builds shouldn't have package.json or composer.json reachable. If you really need to expose version info (some dev consoles do), publish a deliberately-curated subset rather than the raw file.

**Tags:** `exposed-file`, `info_leak`, `manifest`
**Alert name:** Package Manifest Exposed
**Monitor type:** `path_change`

**References:**
- OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File

---

## Nuclei — Marquee CVEs

_42 templates_

### `nuclei-cve-2017-5638`

**Severity:** CRITICAL · **CWE:** CWE-1336 · **Category:** vulnerabilities

**Title:** CVE-2017-5638: Apache Struts2 RCE (Equifax-grade) on {asset}

**Summary:** CVE-2017-5638 — Apache Struts2 RCE (Equifax-grade) — detected on {asset}. Patch immediately.

**Description:**

> Apache Struts2's Jakarta Multipart parser evaluated OGNL expressions in the Content-Type header, allowing unauthenticated remote code execution on any application using the affected parser.
>
> **Real-world exploitation**
> The vulnerability behind the 2017 Equifax breach (143M records). Still fires on legacy Java applications years after disclosure — Equifax itself was unpatched for 2 months post-disclosure when the breach occurred.

**Remediation:**

> Upgrade Apache Struts to 2.3.32 / 2.5.10.1 (or later). Confirm no legacy Java applications still ship vulnerable Struts2 versions in their WARs.

**Tags:** `nuclei`, `cve`, `cve-2017-5638`, `rce`, `java`, `struts`
**Alert name:** CVE — CVE-2017-5638
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2017-5638
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638

---

### `nuclei-cve-2018-13379`

**Severity:** CRITICAL · **CWE:** CWE-22 · **Category:** vulnerabilities

**Title:** CVE-2018-13379: Fortinet FortiOS SSL VPN path traversal on {asset}

**Summary:** CVE-2018-13379 — Fortinet FortiOS SSL VPN path traversal — detected on {asset}. Patch immediately.

**Description:**

> Path-traversal flaw in FortiOS's SSL VPN portal allowed unauthenticated attackers to retrieve system files including the file containing user session credentials.
>
> **Real-world exploitation**
> Six years post-disclosure (2018), still routinely exploited against unpatched edge devices. Stolen creds from this CVE appear in dark-web markets and ransomware playbooks.

**Remediation:**

> Upgrade FortiOS — anything 6.x and earlier should already be patched but isn't always. Force-reset every VPN user credential; the historical session file may have been exfiltrated long ago.

**Tags:** `nuclei`, `cve`, `cve-2018-13379`, `path-traversal`, `fortinet`, `ssl-vpn`
**Alert name:** CVE — CVE-2018-13379
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2018-13379
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-13379

---

### `nuclei-cve-2019-0708`

**Severity:** CRITICAL · **CWE:** CWE-416 · **Category:** vulnerabilities

**Title:** CVE-2019-0708: BlueKeep — Windows RDP RCE on {asset}

**Summary:** CVE-2019-0708 — BlueKeep — Windows RDP RCE — detected on {asset}. Patch immediately.

**Description:**

> Use-after-free in the Remote Desktop Protocol service on Windows 7 / Server 2008 / 2008 R2 allowed unauthenticated remote code execution. Wormable — capable of self-propagation across networks.
>
> **Real-world exploitation**
> Microsoft took the unusual step of releasing patches for out-of-support Windows XP/Server 2003. Did not produce a WannaCry-scale worm but remains highly exploitable on unpatched legacy systems.

**Remediation:**

> Apply Microsoft's May 2019 patches. RDP should never be exposed to the public internet. Disable RDP on systems that don't need it; tunnel it via VPN or a zero-trust service for those that do.

**Tags:** `nuclei`, `cve`, `cve-2019-0708`, `rce`, `rdp`, `windows`
**Alert name:** CVE — CVE-2019-0708
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-0708
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708

---

### `nuclei-cve-2019-11510`

**Severity:** CRITICAL · **CWE:** CWE-22 · **Category:** vulnerabilities

**Title:** CVE-2019-11510: Pulse Secure SSL VPN path traversal on {asset}

**Summary:** CVE-2019-11510 — Pulse Secure SSL VPN path traversal — detected on {asset}. Patch immediately.

**Description:**

> Pre-auth file-read in Pulse Connect Secure (now Ivanti Connect Secure) allowed unauthenticated attackers to read arbitrary files including session-credential dumps.
>
> **Real-world exploitation**
> One of the most-exploited VPN flaws in history; ransomware groups (REvil, Sodinokibi, Maze) routinely entered networks via this CVE long after patches were available.

**Remediation:**

> Upgrade to a fixed Pulse Secure / Ivanti Connect Secure build. Force-reset all VPN credentials — historical session dumps may have been exfiltrated years before the incident becomes apparent.

**Tags:** `nuclei`, `cve`, `cve-2019-11510`, `path-traversal`, `ivanti`, `ssl-vpn`
**Alert name:** CVE — CVE-2019-11510
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-11510
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11510

---

### `nuclei-cve-2020-1472`

**Severity:** CRITICAL · **CWE:** CWE-330 · **Category:** vulnerabilities

**Title:** CVE-2020-1472: Zerologon — Netlogon privilege escalation on {asset}

**Summary:** CVE-2020-1472 — Zerologon — Netlogon privilege escalation — detected on {asset}. Patch immediately.

**Description:**

> Cryptographic flaw in the Netlogon Remote Protocol allowed an attacker on the same network as a Windows domain controller to set the DC's machine account password to a blank string — effectively granting domain admin.
>
> **Real-world exploitation**
> One of the highest-impact Windows vulnerabilities of the last decade. Used in the wild by ransomware crews and APT groups for rapid lateral movement to domain-admin within Windows networks.

**Remediation:**

> Apply Microsoft's August/February 2020/2021 patches (two-stage rollout). Enable Netlogon enforcement mode (`FullSecureChannelProtection=1`).

**Tags:** `nuclei`, `cve`, `cve-2020-1472`, `privilege-escalation`, `active-directory`, `windows`
**Alert name:** CVE — CVE-2020-1472
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2020-1472
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472

---

### `nuclei-cve-2020-14882`

**Severity:** CRITICAL · **CWE:** CWE-22 · **Category:** vulnerabilities

**Title:** CVE-2020-14882: Oracle WebLogic Server unauthenticated RCE on {asset}

**Summary:** CVE-2020-14882 — Oracle WebLogic Server unauthenticated RCE — detected on {asset}. Patch immediately.

**Description:**

> Oracle WebLogic Server's Console component allowed unauthenticated attackers to bypass authentication and execute arbitrary commands by sending crafted HTTP requests to the admin console.
>
> **Real-world exploitation**
> Mass-exploited within days of disclosure; cryptojacking campaigns and ransomware deployment observed. WebLogic is heavily deployed in finance and government estates.

**Remediation:**

> Apply Oracle's October 2020 Critical Patch Update. Restrict the WebLogic admin console to internal networks only — it shouldn't be reachable from the public internet.

**Tags:** `nuclei`, `cve`, `cve-2020-14882`, `rce`, `weblogic`, `oracle`
**Alert name:** CVE — CVE-2020-14882
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2020-14882
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14882

---

### `nuclei-cve-2021-26084`

**Severity:** CRITICAL · **CWE:** CWE-917 · **Category:** vulnerabilities

**Title:** CVE-2021-26084: Atlassian Confluence OGNL injection on {asset}

**Summary:** CVE-2021-26084 — Atlassian Confluence OGNL injection — detected on {asset}. Patch immediately.

**Description:**

> Confluence Server and Data Center allowed unauthenticated OGNL injection through specially crafted webwork URLs, leading to remote code execution.
>
> **Real-world exploitation**
> Mass-exploited from August 2021; cryptominers and webshell deployments common. Earlier Confluence equivalent of CVE-2022-26134.

**Remediation:**

> Upgrade Confluence to 6.13.23 / 7.4.11 / 7.11.6 / 7.12.5 / 7.13.x (or later).

**Tags:** `nuclei`, `cve`, `cve-2021-26084`, `rce`, `confluence`, `atlassian`
**Alert name:** CVE — CVE-2021-26084
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2021-26084
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26084

---

### `nuclei-cve-2021-26855`

**Severity:** CRITICAL · **CWE:** CWE-918 · **Category:** vulnerabilities

**Title:** CVE-2021-26855: ProxyLogon — Exchange Server SSRF on {asset}

**Summary:** CVE-2021-26855 — ProxyLogon — Exchange Server SSRF — detected on {asset}. Patch immediately.

**Description:**

> Server-side request forgery in Microsoft Exchange Server allowed unauthenticated attackers to authenticate as the Exchange server itself. Part of the ProxyLogon chain that led to mass Exchange compromise in early 2021.
>
> **Real-world exploitation**
> HAFNIUM (Chinese state actor) exploited this as zero-day starting January 2021; an estimated 250,000+ Exchange servers were compromised before patches were deployed. Webshells from this campaign are still being found years later.

**Remediation:**

> Apply Microsoft's March 2021 out-of-band Exchange patches. Run Microsoft's MSERT/EOMT tooling to identify and remove ProxyLogon webshells. Assume any internet-facing Exchange that was unpatched between 2021-01 and 2021-03 is compromised until proven otherwise.

**Tags:** `nuclei`, `cve`, `cve-2021-26855`, `ssrf`, `exchange`, `microsoft`
**Alert name:** CVE — CVE-2021-26855
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2021-26855
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26855
- Microsoft — HAFNIUM targeting Exchange Servers

---

### `nuclei-cve-2021-34527`

**Severity:** CRITICAL · **CWE:** CWE-269 · **Category:** vulnerabilities

**Title:** CVE-2021-34527: PrintNightmare — Windows Print Spooler RCE on {asset}

**Summary:** CVE-2021-34527 — PrintNightmare — Windows Print Spooler RCE — detected on {asset}. Patch immediately.

**Description:**

> The Windows Print Spooler service allowed remote code execution via crafted print-driver loading; attackers with any authenticated AD identity could execute SYSTEM-level code on domain controllers and member servers.
>
> **Real-world exploitation**
> Released as zero-day during 2021's print-driver disclosure chain; led Microsoft to substantially restructure Print Spooler's privilege model.

**Remediation:**

> Apply the July 2021 + later Print Spooler patches. Disable the Print Spooler service on systems that don't need to print (especially domain controllers).

**Tags:** `nuclei`, `cve`, `cve-2021-34527`, `rce`, `privilege-escalation`, `print-spooler`, `windows`
**Alert name:** CVE — CVE-2021-34527
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2021-34527
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527

---

### `nuclei-cve-2021-44228`

**Severity:** CRITICAL · **CWE:** CWE-502 · **Category:** vulnerabilities

**Title:** CVE-2021-44228: Log4Shell — Apache Log4j RCE on {asset}

**Summary:** CVE-2021-44228 — Log4Shell — Apache Log4j RCE — detected on {asset}. Patch immediately.

**Description:**

> Apache Log4j 2.x (versions 2.0-beta9 through 2.14.1) allows remote code execution via the JNDI lookup feature. Any string logged by Log4j that contains a `${jndi:ldap://...}` payload triggers remote class loading and arbitrary code execution in the JVM.
>
> **Real-world exploitation**
> Mass-exploited from December 2021 onward — ransomware crews, cryptojacking botnets, and state-affiliated actors all incorporated Log4Shell into their toolkits within hours of disclosure. Any internet-facing Java application that logged user-controlled input (User-Agent, X-Forwarded-For, search fields, login forms) was at risk.

**Remediation:**

> **Upgrade**
>   Move to Log4j 2.17.1 or later — earlier 2.x patches missed follow-up issues (CVE-2021-45046, CVE-2021-45105, CVE-2021-44832).
>
> **If you can't upgrade today**
>   Set `log4j2.formatMsgNoLookups=true` or remove the `JndiLookup` class from the classpath:
>   `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`
>
> **Audit for compromise**
>   Search outbound connection logs for traffic to attacker-controlled LDAP/RMI hosts since 2021-12-09. Many incident responders have found post-exploitation persistence from this period that's still active.

**Tags:** `nuclei`, `cve`, `cve-2021-44228`, `rce`, `java`, `log4j`
**Alert name:** CVE — CVE-2021-44228
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228
- Apache Log4j Security Advisory
- CISA — Apache Log4j Vulnerability Guidance

---

### `nuclei-cve-2021-45046`

**Severity:** CRITICAL · **CWE:** CWE-502 · **Category:** vulnerabilities

**Title:** CVE-2021-45046: Log4j 2.15 mitigation bypass on {asset}

**Summary:** CVE-2021-45046 — Log4j 2.15 mitigation bypass — detected on {asset}. Patch immediately.

**Description:**

> The Log4j 2.15 release intended to fix Log4Shell still allowed remote code execution under certain non-default configurations. Lookups in Thread Context Map values remained exploitable.
>
> **Real-world exploitation**
> Released alongside Log4Shell scanning campaigns — adversaries who'd already weaponised Log4j tooling pivoted to this secondary issue within days. Upgrading to 2.15 was not enough.

**Remediation:**

> Upgrade to Log4j 2.17.1 or later. Don't stop at 2.15 or 2.16 — they each had follow-up issues.

**Tags:** `nuclei`, `cve`, `cve-2021-45046`, `rce`, `java`, `log4j`
**Alert name:** CVE — CVE-2021-45046
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2021-45046
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046

---

### `nuclei-cve-2022-1388`

**Severity:** CRITICAL · **CWE:** CWE-287 · **Category:** vulnerabilities

**Title:** CVE-2022-1388: F5 BIG-IP iControl REST auth bypass on {asset}

**Summary:** CVE-2022-1388 — F5 BIG-IP iControl REST auth bypass — detected on {asset}. Patch immediately.

**Description:**

> Undisclosed flaw in F5 BIG-IP's iControl REST allowed unauthenticated attackers to execute system commands, create or delete files, or disable services on the device.
>
> **Real-world exploitation**
> Mass-exploited within days of disclosure (2022-05-04). BIG-IPs front major enterprise traffic, so successful exploitation gave attackers a privileged position in the victim's network edge.

**Remediation:**

> Upgrade BIG-IP to a fixed release (15.1.5.1, 14.1.4.6, 13.1.5, 12.1.6.1, or 11.6.5.3 / latest). Restrict access to the management interface to trusted networks only — never expose iControl REST to the internet.

**Tags:** `nuclei`, `cve`, `cve-2022-1388`, `rce`, `auth-bypass`, `f5`
**Alert name:** CVE — CVE-2022-1388
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2022-1388
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1388

---

### `nuclei-cve-2022-22954`

**Severity:** CRITICAL · **CWE:** CWE-1336 · **Category:** vulnerabilities

**Title:** CVE-2022-22954: VMware Workspace ONE Access SSTI RCE on {asset}

**Summary:** CVE-2022-22954 — VMware Workspace ONE Access SSTI RCE — detected on {asset}. Patch immediately.

**Description:**

> Server-side template injection in the VMware Workspace ONE Access (formerly Identity Manager) catalog UI allowed unauthenticated remote code execution.
>
> **Real-world exploitation**
> Quickly weaponised; appeared in mass-scanning data within days of disclosure. Identity-tier service compromise has downstream blast radius across federated SSO.

**Remediation:**

> Apply VMware advisory VMSA-2022-0011 patches. Audit identity-service logs for unusual admin activity since 2022-04-06.

**Tags:** `nuclei`, `cve`, `cve-2022-22954`, `rce`, `vmware`
**Alert name:** CVE — CVE-2022-22954
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2022-22954
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22954

---

### `nuclei-cve-2022-22963`

**Severity:** CRITICAL · **CWE:** CWE-94 · **Category:** vulnerabilities

**Title:** CVE-2022-22963: Spring Cloud Function SpEL injection on {asset}

**Summary:** CVE-2022-22963 — Spring Cloud Function SpEL injection — detected on {asset}. Patch immediately.

**Description:**

> Spring Cloud Function's routing functionality evaluates user-controlled SpEL expressions submitted through the `spring.cloud.function.routing-expression` HTTP header. Attackers can inject expressions that execute arbitrary code.
>
> **Real-world exploitation**
> Often confused with Spring4Shell (CVE-2022-22965); this is a separate flaw in Spring Cloud Function. Both saw rapid exploitation in early 2022.

**Remediation:**

> Upgrade Spring Cloud Function to 3.1.7 or 3.2.3 (or later). If patching isn't immediate, block the `spring.cloud.function.routing-expression` header at the edge.

**Tags:** `nuclei`, `cve`, `cve-2022-22963`, `rce`, `java`, `spring`
**Alert name:** CVE — CVE-2022-22963
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2022-22963
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22963

---

### `nuclei-cve-2022-22965`

**Severity:** CRITICAL · **CWE:** CWE-915 · **Category:** vulnerabilities

**Title:** CVE-2022-22965: Spring4Shell — Spring Framework RCE on {asset}

**Summary:** CVE-2022-22965 — Spring4Shell — Spring Framework RCE — detected on {asset}. Patch immediately.

**Description:**

> Spring Framework's data-binding mechanism allowed an attacker to manipulate the application class loader, write a malicious JSP file to disk, and execute arbitrary code on the server (JDK 9+ on Tomcat with Spring MVC/WebFlux).
>
> **Real-world exploitation**
> Public proof-of-concept released within hours of disclosure. Mass-scanning began the same day — Spring Boot apps that exposed any controller accepting form-style input were potentially affected.

**Remediation:**

> Upgrade Spring Framework to 5.3.18+ or 5.2.20+. If patching is delayed, set a controller advice that filters the `class.module.classLoader` binding path. Audit web roots for unfamiliar JSP files dropped since 2022-03-30.

**Tags:** `nuclei`, `cve`, `cve-2022-22965`, `rce`, `java`, `spring`
**Alert name:** CVE — CVE-2022-22965
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2022-22965
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965
- Spring — Spring Framework RCE, Early Announcement

---

### `nuclei-cve-2022-26134`

**Severity:** CRITICAL · **CWE:** CWE-917 · **Category:** vulnerabilities

**Title:** CVE-2022-26134: Atlassian Confluence OGNL injection RCE on {asset}

**Summary:** CVE-2022-26134 — Atlassian Confluence OGNL injection RCE — detected on {asset}. Patch immediately.

**Description:**

> Confluence Server and Data Center allowed unauthenticated OGNL expression injection through specially crafted URLs, leading to remote code execution as the Confluence user.
>
> **Real-world exploitation**
> Exploited in the wild as a zero-day before patches landed (disclosed 2022-06-02). Attacker activity included webshell deployment, credential theft, and pivoting into corporate Atlassian estates.

**Remediation:**

> Upgrade Confluence to 7.4.17 / 7.13.7 / 7.14.3 / 7.15.2 / 7.16.4 / 7.17.4 / 7.18.1 (or later). Audit logs for unexpected child processes of `confluence/conf/server.xml` or unfamiliar files in `confluence/webapps/`.

**Tags:** `nuclei`, `cve`, `cve-2022-26134`, `rce`, `java`, `confluence`, `atlassian`
**Alert name:** CVE — CVE-2022-26134
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2022-26134
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-26134
- Atlassian — Security Advisory CVE-2022-26134

---

### `nuclei-cve-2022-41082`

**Severity:** CRITICAL · **CWE:** CWE-502 · **Category:** vulnerabilities

**Title:** CVE-2022-41082: ProxyNotShell — Microsoft Exchange RCE on {asset}

**Summary:** CVE-2022-41082 — ProxyNotShell — Microsoft Exchange RCE — detected on {asset}. Patch immediately.

**Description:**

> Authenticated attackers could trigger remote code execution in Microsoft Exchange Server through a deserialisation vulnerability in PowerShell remoting. Chained with CVE-2022-41040 for the full unauthenticated path.
>
> **Real-world exploitation**
> Same exploitation campaign as ProxyNotShell #1. Active ransomware deployment and webshell installation observed.

**Remediation:**

> Apply Microsoft's November 2022 Exchange security updates. Audit Exchange for unfamiliar webshells and PowerShell execution events since 2022-09-01.

**Tags:** `nuclei`, `cve`, `cve-2022-41082`, `rce`, `exchange`, `microsoft`
**Alert name:** CVE — CVE-2022-41082
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2022-41082
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41082

---

### `nuclei-cve-2022-47966`

**Severity:** CRITICAL · **CWE:** CWE-611 · **Category:** vulnerabilities

**Title:** CVE-2022-47966: ManageEngine ADSelfService Plus RCE on {asset}

**Summary:** CVE-2022-47966 — ManageEngine ADSelfService Plus RCE — detected on {asset}. Patch immediately.

**Description:**

> Multiple Zoho ManageEngine products (ADSelfService Plus, ServiceDesk Plus, others) were vulnerable to remote code execution via XML external entity (XXE) injection in the SAML SSO endpoint.
>
> **Real-world exploitation**
> Mass-exploited from January 2023 onward; APT actors and ransomware crews both incorporated this into their toolkits. ADSelfService Plus is widely deployed for Active Directory self-service password reset, so compromise = AD privilege.

**Remediation:**

> Upgrade affected ManageEngine products to current builds (see Zoho's advisory for the per-product matrix). Audit logs for SAML auth events and SYSTEM-level command execution since 2022-12.

**Tags:** `nuclei`, `cve`, `cve-2022-47966`, `rce`, `xxe`, `manageengine`
**Alert name:** CVE — CVE-2022-47966
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2022-47966
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47966

---

### `nuclei-cve-2023-22515`

**Severity:** CRITICAL · **CWE:** CWE-287 · **Category:** vulnerabilities

**Title:** CVE-2023-22515: Confluence broken access control on {asset}

**Summary:** CVE-2023-22515 — Confluence broken access control — detected on {asset}. Patch immediately.

**Description:**

> Confluence Data Center and Server permitted unauthenticated attackers to create administrator accounts on internet-facing instances by manipulating setup-page state.
>
> **Real-world exploitation**
> Exploited in the wild as a zero-day; Atlassian disclosed it as already-active on 2023-10-04. Full Confluence admin = macros, plugins, full data access.

**Remediation:**

> Upgrade Confluence to 8.3.3 / 8.4.3 / 8.5.2 (or later). Audit user-management logs for new admin accounts created since 2023-09-15. Atlassian Cloud is unaffected.

**Tags:** `nuclei`, `cve`, `cve-2023-22515`, `auth-bypass`, `confluence`, `atlassian`
**Alert name:** CVE — CVE-2023-22515
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-22515
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-22515
- Atlassian — Confluence CVE-2023-22515 advisory

---

### `nuclei-cve-2023-22518`

**Severity:** CRITICAL · **CWE:** CWE-285 · **Category:** vulnerabilities

**Title:** CVE-2023-22518: Confluence improper authorisation on {asset}

**Summary:** CVE-2023-22518 — Confluence improper authorisation — detected on {asset}. Patch immediately.

**Description:**

> Confluence Data Center and Server allowed unauthenticated attackers to reset administrative credentials and trigger data destruction.
>
> **Real-world exploitation**
> Disclosed shortly after CVE-2023-22515; attacker activity included data wiping (used as a destructive ransom lever) as well as account takeover.

**Remediation:**

> Upgrade Confluence to 7.19.16 / 8.3.4 / 8.4.4 / 8.5.3 / 8.6.1 (or later). Verify backups are intact and recent.

**Tags:** `nuclei`, `cve`, `cve-2023-22518`, `auth-bypass`, `confluence`, `atlassian`
**Alert name:** CVE — CVE-2023-22518
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-22518
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-22518

---

### `nuclei-cve-2023-23397`

**Severity:** CRITICAL · **CWE:** CWE-294 · **Category:** vulnerabilities

**Title:** CVE-2023-23397: Outlook NTLM credential leak on {asset}

**Summary:** CVE-2023-23397 — Outlook NTLM credential leak — detected on {asset}. Patch immediately.

**Description:**

> Microsoft Outlook on Windows could be coerced into authenticating to attacker-controlled SMB shares via crafted calendar invites — leaking the Net-NTLMv2 hash without user interaction (no preview pane click required).
>
> **Real-world exploitation**
> Exploited by APT28 (Fancy Bear) against European government and military targets through 2022 before disclosure. Net-NTLMv2 hashes can be relayed or cracked offline.

**Remediation:**

> Apply Microsoft's March 2023 patches. Block outbound TCP/445 at the perimeter so Outlook can't reach external SMB hosts. Audit Net-NTLMv2 authentication events from Outlook since 2022-04 on potentially-targeted accounts.

**Tags:** `nuclei`, `cve`, `cve-2023-23397`, `credential-theft`, `outlook`, `microsoft`
**Alert name:** CVE — CVE-2023-23397
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-23397
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23397

---

### `nuclei-cve-2023-27350`

**Severity:** CRITICAL · **CWE:** CWE-287 · **Category:** vulnerabilities

**Title:** CVE-2023-27350: PaperCut MF/NG auth bypass + RCE on {asset}

**Summary:** CVE-2023-27350 — PaperCut MF/NG auth bypass + RCE — detected on {asset}. Patch immediately.

**Description:**

> PaperCut MF/NG print-management software allowed unauthenticated attackers to bypass authentication and execute arbitrary code via the SetupCompleted page and embedded scripting.
>
> **Real-world exploitation**
> Mass-exploited from April 2023 onward by ransomware crews (Cl0p, LockBit, FIN7-affiliated) targeting US healthcare and education networks where PaperCut is widely deployed.

**Remediation:**

> Upgrade to PaperCut MF/NG 20.1.7 / 21.2.11 / 22.0.9 / 23.0.x (or later). Block external access to the PaperCut admin UI on port 9191/9192.

**Tags:** `nuclei`, `cve`, `cve-2023-27350`, `rce`, `auth-bypass`, `papercut`
**Alert name:** CVE — CVE-2023-27350
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-27350
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27350

---

### `nuclei-cve-2023-34362`

**Severity:** CRITICAL · **CWE:** CWE-89 · **Category:** vulnerabilities

**Title:** CVE-2023-34362: MOVEit Transfer SQL injection RCE on {asset}

**Summary:** CVE-2023-34362 — MOVEit Transfer SQL injection RCE — detected on {asset}. Patch immediately.

**Description:**

> Progress Software's MOVEit Transfer (a managed file-transfer appliance) had a SQL injection flaw that allowed unauthenticated attackers to extract uploaded files and execute SQL-side code.
>
> **Real-world exploitation**
> Cl0p ransomware gang exploited this as a zero-day at internet scale starting May 2023; one of the largest mass-exploitation campaigns ever recorded — the public victim list ran into hundreds of organisations including major banks, government agencies, and HR data processors.

**Remediation:**

> Upgrade MOVEit Transfer to a fixed release (2020.0.6+ / 2020.1.6+ / 2021.0.8+ / 2021.1.6+ / 2022.0.4+ / 2022.1.5+ / 2023.0.1+). Audit web logs for `human.aspx` activity, the `LEMURLOOT` webshell, and uploaded files exfiltrated since 2023-05-27.

**Tags:** `nuclei`, `cve`, `cve-2023-34362`, `sqli`, `rce`, `moveit`, `data-breach`
**Alert name:** CVE — CVE-2023-34362
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-34362
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362
- Progress Software — MOVEit Transfer Critical Vulnerability

---

### `nuclei-cve-2023-4966`

**Severity:** CRITICAL · **CWE:** CWE-119 · **Category:** vulnerabilities

**Title:** CVE-2023-4966: Citrix Bleed — NetScaler ADC/Gateway on {asset}

**Summary:** CVE-2023-4966 — Citrix Bleed — NetScaler ADC/Gateway — detected on {asset}. Patch immediately.

**Description:**

> A buffer over-read in Citrix NetScaler ADC and Gateway allowed unauthenticated attackers to extract session tokens from device memory by sending a specially crafted request to the AAA endpoint.
>
> **Real-world exploitation**
> Mass-exploited from October 2023; LockBit ransomware deployed against Boeing, ICBC, DP World, and others through this vector. Stolen session tokens bypassed MFA on the VPN/gateway.

**Remediation:**

> Upgrade NetScaler to a fixed build (14.1-8.50, 13.1-49.15, 13.0-92.19, or later). After patching, **terminate all active sessions** — `kill icaconnection -all` and `kill aaa session -all` — because stolen session tokens remain valid until the session expires server-side.

**Tags:** `nuclei`, `cve`, `cve-2023-4966`, `info-leak`, `session-hijack`, `citrix`
**Alert name:** CVE — CVE-2023-4966
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-4966
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966
- Citrix — CVE-2023-4966 advisory
- Mandiant — Citrix Bleed exploitation

---

### `nuclei-cve-2023-50164`

**Severity:** CRITICAL · **CWE:** CWE-22 · **Category:** vulnerabilities

**Title:** CVE-2023-50164: Apache Struts file-upload path traversal on {asset}

**Summary:** CVE-2023-50164 — Apache Struts file-upload path traversal — detected on {asset}. Patch immediately.

**Description:**

> Apache Struts (versions 2.5.0 to 2.5.32 and 6.x) had a file-upload flaw that allowed attackers to traverse paths and write files to arbitrary locations, leading to remote code execution on vulnerable applications.
>
> **Real-world exploitation**
> Quickly weaponised after December 2023 disclosure; another in the long line of Struts-driven RCEs that affect long-lived enterprise Java estates.

**Remediation:**

> Upgrade Struts to 2.5.33 / 6.3.0.2 (or later). Audit web roots for unfamiliar files dropped by upload handlers since 2023-12-07.

**Tags:** `nuclei`, `cve`, `cve-2023-50164`, `rce`, `path-traversal`, `struts`
**Alert name:** CVE — CVE-2023-50164
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-50164
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50164

---

### `nuclei-cve-2023-7028`

**Severity:** CRITICAL · **CWE:** CWE-640 · **Category:** vulnerabilities

**Title:** CVE-2023-7028: GitLab account takeover via password reset on {asset}

**Summary:** CVE-2023-7028 — GitLab account takeover via password reset — detected on {asset}. Patch immediately.

**Description:**

> GitLab's password-reset flow accepted multiple email addresses on the reset request, sending the reset link to any address an attacker chose. Combined with knowledge of the target username, this yielded full account takeover without any prior access.
>
> **Real-world exploitation**
> Disclosed January 2024 with patches available; weaponised publicly within days. Particularly damaging for organisations where GitLab houses CI/CD pipelines and signing keys.

**Remediation:**

> Upgrade GitLab to 16.7.2 / 16.6.4 / 16.5.6 (or later). Force a password reset for all users; audit recent password-reset events and account-recovery confirmations for unusual patterns. Rotate any CI/CD secrets exposed via GitLab.

**Tags:** `nuclei`, `cve`, `cve-2023-7028`, `account-takeover`, `gitlab`
**Alert name:** CVE — CVE-2023-7028
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-7028
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-7028
- GitLab Security Advisory CVE-2023-7028

---

### `nuclei-cve-2024-1709`

**Severity:** CRITICAL · **CWE:** CWE-287 · **Category:** vulnerabilities

**Title:** CVE-2024-1709: ConnectWise ScreenConnect auth bypass on {asset}

**Summary:** CVE-2024-1709 — ConnectWise ScreenConnect auth bypass — detected on {asset}. Patch immediately.

**Description:**

> ConnectWise ScreenConnect (remote-management software widely deployed by MSPs) allowed unauthenticated attackers to create administrator accounts via a setup-page authentication bypass.
>
> **Real-world exploitation**
> Mass-exploited from February 2024 onward — ransomware groups (BlackBasta, BlackCat) used compromised ScreenConnect instances to push payloads downstream to MSP customers.

**Remediation:**

> Upgrade ScreenConnect to 23.9.8 or later. Audit user accounts for recently-created admins; rotate any ScreenConnect session tokens; audit downstream client environments for unauthorised remote-control sessions since 2024-02-13.

**Tags:** `nuclei`, `cve`, `cve-2024-1709`, `auth-bypass`, `screenconnect`, `msp`
**Alert name:** CVE — CVE-2024-1709
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-1709
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1709
- ConnectWise — ScreenConnect 23.9.8 release

---

### `nuclei-cve-2024-21762`

**Severity:** CRITICAL · **CWE:** CWE-787 · **Category:** vulnerabilities

**Title:** CVE-2024-21762: Fortinet FortiOS SSL VPN OOB write on {asset}

**Summary:** CVE-2024-21762 — Fortinet FortiOS SSL VPN OOB write — detected on {asset}. Patch immediately.

**Description:**

> An out-of-bounds write in Fortinet FortiOS's SSL VPN implementation allowed unauthenticated attackers to execute arbitrary code by sending a specially crafted HTTP request.
>
> **Real-world exploitation**
> Disclosed February 2024 alongside reports of in-the-wild exploitation by Chinese-state-affiliated actor Volt Typhoon. Fortinet SSL VPNs are heavily deployed at network edges.

**Remediation:**

> Upgrade FortiOS to 7.4.3 / 7.2.7 / 7.0.14 / 6.4.15 / 6.2.16 (or later). Disable SSL VPN until patched if upgrade isn't immediate. Audit logs for unusual VPN auth and admin activity since 2023-12.

**Tags:** `nuclei`, `cve`, `cve-2024-21762`, `rce`, `fortinet`, `ssl-vpn`
**Alert name:** CVE — CVE-2024-21762
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-21762
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21762
- Fortinet PSIRT — FG-IR-24-015

---

### `nuclei-cve-2024-21887`

**Severity:** CRITICAL · **CWE:** CWE-77 · **Category:** vulnerabilities

**Title:** CVE-2024-21887: Ivanti Connect Secure command injection on {asset}

**Summary:** CVE-2024-21887 — Ivanti Connect Secure command injection — detected on {asset}. Patch immediately.

**Description:**

> Command injection in the web component of Ivanti Connect Secure (formerly Pulse Connect Secure) and Policy Secure allowed authenticated attackers to execute arbitrary commands on the appliance. Chained with CVE-2023-46805 (auth bypass) for full unauthenticated RCE.
>
> **Real-world exploitation**
> Exploited as zero-day in early 2024 by UTA0178 (suspected Chinese state actor). Hundreds of internet-facing Ivanti appliances were compromised before patches landed.

**Remediation:**

> Upgrade to Ivanti Connect Secure 22.5R2.2+. Apply Ivanti's external integrity check tool to verify the device hasn't been backdoored. Reset all VPN credentials post-patching.

**Tags:** `nuclei`, `cve`, `cve-2024-21887`, `rce`, `command-injection`, `ivanti`
**Alert name:** CVE — CVE-2024-21887
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-21887
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21887
- Ivanti — Connect Secure / Policy Secure advisory
- Volexity — Active Exploitation of Ivanti VPN

---

### `nuclei-cve-2024-23113`

**Severity:** CRITICAL · **CWE:** CWE-134 · **Category:** vulnerabilities

**Title:** CVE-2024-23113: Fortinet FortiOS format-string RCE on {asset}

**Summary:** CVE-2024-23113 — Fortinet FortiOS format-string RCE — detected on {asset}. Patch immediately.

**Description:**

> A format-string vulnerability in FortiOS's fgfmd daemon allowed unauthenticated remote attackers to execute arbitrary code via crafted requests to the device's management daemon.
>
> **Real-world exploitation**
> Disclosed alongside CVE-2024-21762; same exploitation context, same threat actors, same urgency.

**Remediation:**

> Upgrade FortiOS as for CVE-2024-21762. Restrict access to the management interface to trusted networks only — never internet-facing.

**Tags:** `nuclei`, `cve`, `cve-2024-23113`, `rce`, `fortinet`
**Alert name:** CVE — CVE-2024-23113
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-23113
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-23113

---

### `nuclei-cve-2024-27198`

**Severity:** CRITICAL · **CWE:** CWE-287 · **Category:** vulnerabilities

**Title:** CVE-2024-27198: JetBrains TeamCity authentication bypass on {asset}

**Summary:** CVE-2024-27198 — JetBrains TeamCity authentication bypass — detected on {asset}. Patch immediately.

**Description:**

> JetBrains TeamCity (CI/CD) allowed unauthenticated remote attackers to bypass authentication and access administrative endpoints by manipulating URL-handling logic.
>
> **Real-world exploitation**
> Mass-exploited from March 2024 onward; one of the most targeted CI/CD platforms post-disclosure. Compromised TeamCity = supply-chain access to every artefact it builds.

**Remediation:**

> Upgrade TeamCity to 2023.11.4 or later. Audit build history for unfamiliar plugin installations, modified build steps, and exfiltrated artefacts. Rotate every secret stored in TeamCity (deploy keys, API tokens, signing keys).

**Tags:** `nuclei`, `cve`, `cve-2024-27198`, `auth-bypass`, `teamcity`, `ci-cd`, `supply-chain`
**Alert name:** CVE — CVE-2024-27198
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-27198
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-27198
- JetBrains — TeamCity Security Advisory

---

### `nuclei-cve-2024-29849`

**Severity:** CRITICAL · **CWE:** CWE-287 · **Category:** vulnerabilities

**Title:** CVE-2024-29849: Veeam Backup Enterprise Manager auth bypass on {asset}

**Summary:** CVE-2024-29849 — Veeam Backup Enterprise Manager auth bypass — detected on {asset}. Patch immediately.

**Description:**

> Veeam Backup Enterprise Manager (the web UI for managing Veeam backup infrastructure) allowed unauthenticated attackers to log in as any user via an authentication bypass in the Single Sign-On flow.
>
> **Real-world exploitation**
> Direct path to backup-infrastructure compromise — and compromised backups are the difference between recoverable and unrecoverable ransomware incidents.

**Remediation:**

> Upgrade Veeam Backup Enterprise Manager to 12.1.2.172 or later. Audit SSO and admin-UI activity for unauthorised logins. Consider taking VBEM off the public internet entirely.

**Tags:** `nuclei`, `cve`, `cve-2024-29849`, `auth-bypass`, `veeam`, `backup`
**Alert name:** CVE — CVE-2024-29849
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-29849
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-29849
- Veeam — VBEM advisory KB4581

---

### `nuclei-cve-2024-3094`

**Severity:** CRITICAL · **CWE:** CWE-506 · **Category:** vulnerabilities

**Title:** CVE-2024-3094: XZ Utils backdoor on {asset}

**Summary:** CVE-2024-3094 — XZ Utils backdoor — detected on {asset}. Patch immediately.

**Description:**

> Malicious code was inserted into the upstream XZ Utils compression library (versions 5.6.0 and 5.6.1) by a long-running supply-chain operation, providing an SSH authentication backdoor on certain systemd-linked builds of OpenSSH.
>
> **Real-world exploitation**
> Caught early — the backdoor was deployed in distro testing channels (Fedora, Debian unstable, openSUSE Tumbleweed, Kali) but not widely in stable releases. Had it shipped, it would have been a generational supply-chain compromise.

**Remediation:**

> Downgrade XZ Utils to 5.4.6 or upgrade to a patched 5.6.2+ release where the malicious code has been removed. Audit package histories on bleeding-edge or rolling-release systems to confirm 5.6.0/5.6.1 wasn't installed.

**Tags:** `nuclei`, `cve`, `cve-2024-3094`, `backdoor`, `supply-chain`, `xz`, `openssh`
**Alert name:** CVE — CVE-2024-3094
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-3094
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3094
- Andres Freund — backdoor in upstream xz/liblzma
- Red Hat — Urgent security alert for Fedora users

---

### `nuclei-cve-2024-3400`

**Severity:** CRITICAL · **CWE:** CWE-77 · **Category:** vulnerabilities

**Title:** CVE-2024-3400: Palo Alto GlobalProtect command injection on {asset}

**Summary:** CVE-2024-3400 — Palo Alto GlobalProtect command injection — detected on {asset}. Patch immediately.

**Description:**

> Command injection in the GlobalProtect feature of Palo Alto PAN-OS allowed unauthenticated remote attackers to execute arbitrary code with root privileges on the firewall.
>
> **Real-world exploitation**
> Exploited as zero-day starting March 2024 by suspected state actor UTA0218; at least dozens of internet-facing PAN-OS devices compromised before disclosure.

**Remediation:**

> Upgrade PAN-OS to 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3 (or later). Disable telemetry as a temporary workaround if patching is delayed. Audit firewall logs for command execution and config changes since 2024-03-26.

**Tags:** `nuclei`, `cve`, `cve-2024-3400`, `rce`, `command-injection`, `palo-alto`
**Alert name:** CVE — CVE-2024-3400
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-3400
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400
- Palo Alto Networks — CVE-2024-3400 advisory
- Volexity — Operation MidnightEclipse

---

### `nuclei-cve-2020-3452`

**Severity:** HIGH · **CWE:** CWE-22 · **Category:** vulnerabilities

**Title:** CVE-2020-3452: Cisco ASA / FTD path traversal on {asset}

**Summary:** CVE-2020-3452 — Cisco ASA / FTD path traversal — detected on {asset}. Patch immediately.

**Description:**

> Cisco Adaptive Security Appliance and Firepower Threat Defense allowed unauthenticated remote attackers to read arbitrary files from the device's web-services file system.
>
> **Real-world exploitation**
> Exploited in the wild for credential extraction; ASA appliances are common edge firewalls in enterprise deployments.

**Remediation:**

> Upgrade Cisco ASA / FTD to a fixed release. Audit retrieved file paths in web-services logs for suspicious access patterns.

**Tags:** `nuclei`, `cve`, `cve-2020-3452`, `path-traversal`, `cisco`, `firewall`
**Alert name:** CVE — CVE-2020-3452
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2020-3452
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3452

---

### `nuclei-cve-2022-30190`

**Severity:** HIGH · **CWE:** CWE-94 · **Category:** vulnerabilities

**Title:** CVE-2022-30190: Follina — MS Office MSDT RCE on {asset}

**Summary:** CVE-2022-30190 — Follina — MS Office MSDT RCE — detected on {asset}. Patch immediately.

**Description:**

> The Microsoft Support Diagnostic Tool (MSDT) URL protocol allowed code execution via crafted Office documents that invoked `ms-msdt` schemes. Detected on Word documents delivered via email or web download.
>
> **Real-world exploitation**
> Initially exploited as a zero-day in targeted attacks; broad criminal adoption followed once disclosed. Click-to-open Office documents were the primary vector.

**Remediation:**

> Apply Microsoft's June 2022 security update. Disable the `ms-msdt` URL protocol via registry (`HKEY_CLASSES_ROOT\ms-msdt`) on systems pending patch.

**Tags:** `nuclei`, `cve`, `cve-2022-30190`, `rce`, `windows`, `office`
**Alert name:** CVE — CVE-2022-30190
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2022-30190
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30190

---

### `nuclei-cve-2022-41040`

**Severity:** HIGH · **CWE:** CWE-918 · **Category:** vulnerabilities

**Title:** CVE-2022-41040: ProxyNotShell — Microsoft Exchange SSRF on {asset}

**Summary:** CVE-2022-41040 — ProxyNotShell — Microsoft Exchange SSRF — detected on {asset}. Patch immediately.

**Description:**

> Server-side request forgery in Microsoft Exchange Server (2013/2016/2019) allowed authenticated attackers to forge requests against internal endpoints. Used in chain with CVE-2022-41082 for remote code execution.
>
> **Real-world exploitation**
> Exploited in the wild as a zero-day before patches landed (disclosed 2022-09-29). Common chain: phishing for low-priv credentials, then CVE-2022-41040 + 41082 for SYSTEM-level code execution on Exchange.

**Remediation:**

> Apply Microsoft's November 2022 Exchange security updates. Block the `Autodiscover/PowerShell` URL pattern at the front-end IIS rewrite layer if patching is delayed.

**Tags:** `nuclei`, `cve`, `cve-2022-41040`, `ssrf`, `exchange`, `microsoft`
**Alert name:** CVE — CVE-2022-41040
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2022-41040
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41040

---

### `nuclei-cve-2023-46805`

**Severity:** HIGH · **CWE:** CWE-287 · **Category:** vulnerabilities

**Title:** CVE-2023-46805: Ivanti Connect Secure auth bypass on {asset}

**Summary:** CVE-2023-46805 — Ivanti Connect Secure auth bypass — detected on {asset}. Patch immediately.

**Description:**

> Authentication bypass in the Ivanti Connect Secure / Policy Secure web component allowed unauthenticated attackers to reach restricted endpoints. Chained with CVE-2024-21887 for remote code execution.
>
> **Real-world exploitation**
> Same exploitation campaign as CVE-2024-21887. The two together form the unauthenticated RCE chain.

**Remediation:**

> Upgrade per CVE-2024-21887 guidance. Apply the integrity checker.

**Tags:** `nuclei`, `cve`, `cve-2023-46805`, `auth-bypass`, `ivanti`
**Alert name:** CVE — CVE-2023-46805
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-46805
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46805

---

### `nuclei-cve-2024-21893`

**Severity:** HIGH · **CWE:** CWE-918 · **Category:** vulnerabilities

**Title:** CVE-2024-21893: Ivanti Connect Secure SSRF on {asset}

**Summary:** CVE-2024-21893 — Ivanti Connect Secure SSRF — detected on {asset}. Patch immediately.

**Description:**

> Server-side request forgery in Ivanti Connect Secure / Policy Secure / Neurons for ZTA components allowed an unauthenticated attacker to access certain restricted resources without authentication.
>
> **Real-world exploitation**
> Disclosed during active Ivanti exploitation campaigns (early 2024). Often chained with the other Ivanti issues.

**Remediation:**

> Upgrade to a fixed Ivanti release; apply the integrity checker; rotate VPN credentials.

**Tags:** `nuclei`, `cve`, `cve-2024-21893`, `ssrf`, `ivanti`
**Alert name:** CVE — CVE-2024-21893
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-21893
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21893

---

### `nuclei-cve-2024-26229`

**Severity:** HIGH · **CWE:** CWE-269 · **Category:** vulnerabilities

**Title:** CVE-2024-26229: Windows CSC SYSTEM elevation on {asset}

**Summary:** CVE-2024-26229 — Windows CSC SYSTEM elevation — detected on {asset}. Patch immediately.

**Description:**

> The Windows Client/Server Run-time Subsystem (CSRSS) had a privilege-escalation flaw allowing local attackers to elevate from low-privilege user to SYSTEM.
>
> **Real-world exploitation**
> Public proof-of-concept released within weeks of patch; incorporated into post-exploitation toolkits.

**Remediation:**

> Apply Microsoft's April 2024 Patch Tuesday updates.

**Tags:** `nuclei`, `cve`, `cve-2024-26229`, `privilege-escalation`, `windows`
**Alert name:** CVE — CVE-2024-26229
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-26229
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26229

---

### `nuclei-cve-2024-27199`

**Severity:** HIGH · **CWE:** CWE-22 · **Category:** vulnerabilities

**Title:** CVE-2024-27199: JetBrains TeamCity path traversal on {asset}

**Summary:** CVE-2024-27199 — JetBrains TeamCity path traversal — detected on {asset}. Patch immediately.

**Description:**

> Path traversal vulnerability in TeamCity allowed unauthenticated remote attackers to access certain restricted endpoints, potentially leading to limited information disclosure or modification of system settings.
>
> **Real-world exploitation**
> Disclosed alongside CVE-2024-27198. Less severe individually but extends the exploitation surface.

**Remediation:**

> Upgrade TeamCity to 2023.11.4 or later.

**Tags:** `nuclei`, `cve`, `cve-2024-27199`, `path-traversal`, `teamcity`
**Alert name:** CVE — CVE-2024-27199
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-27199
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-27199

---

### `nuclei-cve-2021-45105`

**Severity:** MEDIUM · **CWE:** CWE-674 · **Category:** vulnerabilities

**Title:** CVE-2021-45105: Log4j 2.16 DoS via recursive lookup on {asset}

**Summary:** CVE-2021-45105 — Log4j 2.16 DoS via recursive lookup — detected on {asset}. Patch immediately.

**Description:**

> Log4j 2.16 was vulnerable to a denial-of-service condition when self-referential lookups in the Thread Context Map caused infinite recursion.
>
> **Real-world exploitation**
> Less severe than the earlier RCE issues but still affected production stability — exploitable by anyone who could influence logged data.

**Remediation:**

> Upgrade to Log4j 2.17.1 or later.

**Tags:** `nuclei`, `cve`, `cve-2021-45105`, `dos`, `java`, `log4j`
**Alert name:** CVE — CVE-2021-45105
**Monitor type:** `vuln_change`

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2021-45105
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105

---

## Nuclei — Other (panels, default-creds, misconfig, info-disclosure, generic)

_148 templates_

### `nuclei-apache-airflow-default-login`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Apache Airflow default credentials accepted at {asset}

**Summary:** Default credentials work on the Apache Airflow instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Apache Airflow instance on {asset} accepts known default credentials (`airflow/airflow`, `admin/admin`). Authenticated Airflow users can typically execute arbitrary Python via DAG file uploads or the Airflow Variables / Connections, so default-creds is effectively RCE on the Airflow workers and any system the workers can reach. Airflow workers commonly hold cloud credentials, database creds, and access to data warehouses.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Apache Airflow audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.
>
> **Audit DAGs and Variables**
>   Review the Airflow DAGs folder for unfamiliar files. Inspect Variables for unexpected entries — attackers often drop reverse-shell payloads here. Rotate every connection credential stored in Airflow.

**Tags:** `nuclei`, `default-credentials`, `apache-airflow-default-login`, `rce-risk`
**Alert name:** Default Creds — Airflow
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Apache Airflow — Security

---

### `nuclei-aws-access-key-disclosure`

**Severity:** CRITICAL · **CWE:** CWE-798 · **Category:** data_leaks

**Title:** AWS access key disclosed in response from {asset}

**Summary:** An AWS access key is visible in an HTTP response from {asset} — verify if live and rotate.

**Description:**

> An AWS access key (AKIA-prefixed identifier, sometimes with a paired secret) was found in an HTTP response from {asset}. If the key is live, attackers can use it to interact with AWS at whatever scope the key's IAM policy grants. Common false-positive sources are tutorial snippets and docs pages — verify before treating as breach, but treat as breach until verified.

**Remediation:**

> **Verify whether the key is live**
>   Use AWS IAM (`aws iam list-access-keys`) to confirm the key ID exists in your account. If yes, treat as compromised.
>
> **Rotate immediately**
>   Mark the key inactive in IAM, then delete it. Generate a fresh key for any legitimate consumer; deliver it via a secret manager, not by pasting it into a doc/page.
>
> **Audit CloudTrail**
>   Search CloudTrail for `accessKeyId` matching the leaked key over the entire window the page has been reachable. Any API call from an unfamiliar source IP is the breach.
>
> **Remove from the response**
>   Find what's serving the key (an error page? a debug endpoint? a static doc?) and remove it. Add a CI guard (`gitleaks`, `trufflehog`) to prevent recurrence.

**Tags:** `nuclei`, `info-disclosure`, `aws-access-key-disclosure`, `aws`, `credentials`
**Alert name:** Info Disclosure — AWS Key Leak
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- AWS — What to do if you inadvertently expose an AWS access key

---

### `nuclei-aws-imds-ssrf`

**Severity:** CRITICAL · **CWE:** CWE-918 · **Category:** vulnerabilities

**Title:** AWS IMDS reachable via SSRF from {asset}

**Summary:** Your AWS instance metadata service is reachable via SSRF from {asset} — the instance role's credentials should be considered exfiltrated. Audit CloudTrail and rotate.

**Description:**

> Nuclei reached the AWS Instance Metadata Service (169.254.169.254) via a vulnerable endpoint on {asset}. On EC2, IMDS returns the IAM role's temporary credentials — an attacker with this SSRF has full access to whatever AWS resources the instance role grants. The Capital One breach (100M+ records) followed exactly this pattern.

**Remediation:**

> **Treat as an active incident**
>   Assume the instance role's credentials have been exfiltrated and used. Review CloudTrail for unfamiliar API calls from the instance role since the endpoint became vulnerable; rotate the role's session credentials by stopping/starting the instance.
>
> **Enforce IMDSv2**
>   Set the EC2 instance metadata options to `HttpTokens=required` — IMDSv2 requires a PUT-issued session token, defeating classic single-step SSRF. Use the EC2 console / `aws ec2 modify-instance-metadata-options` or set it as a default at the account level via the instance-metadata-defaults setting.
>
> **Patch the SSRF**
>   Fix the underlying endpoint (allow-list destinations, block 169.254.169.254 explicitly) regardless — IMDSv2 is defence-in-depth, not a substitute.

**Tags:** `nuclei`, `misconfiguration`, `aws-imds-ssrf`, `ssrf`, `aws`, `imds`, `cloud-creds`
**Alert name:** Misconfig — AWS IMDS SSRF
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- AWS — Use IMDSv2
- Krebs — Capital One breach analysis

---

### `nuclei-azure-imds-ssrf`

**Severity:** CRITICAL · **CWE:** CWE-918 · **Category:** vulnerabilities

**Title:** Azure IMDS reachable via SSRF from {asset}

**Summary:** Azure IMDS reachable via SSRF on {asset} — the VM's managed identity should be considered compromised.

**Description:**

> Nuclei reached the Azure Instance Metadata Service (169.254.169.254) via a vulnerable endpoint on {asset}. Azure IMDS returns access tokens for the VM's managed identity — equivalent to that managed identity's full Azure permissions, including any subscription / resource-group / Key Vault grants.

**Remediation:**

> Patch the SSRF (allow-list, block 169.254.169.254). Azure IMDS already requires the `Metadata: true` header (blocks classic SSRF that doesn't set arbitrary headers) but many SSRF primitives can supply that. Audit Azure AD sign-in logs for the managed identity since the endpoint became vulnerable; check Key Vault audit logs for unauthorised secret reads. Rotate the managed-identity secrets if compromise is suspected.

**Tags:** `nuclei`, `misconfiguration`, `azure-imds-ssrf`, `ssrf`, `azure`, `imds`, `cloud-creds`
**Alert name:** Misconfig — Azure IMDS SSRF
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Microsoft — Azure Instance Metadata service

---

### `nuclei-azure-shared-key-disclosure`

**Severity:** CRITICAL · **CWE:** CWE-798 · **Category:** data_leaks

**Title:** Azure storage shared key disclosed at {asset}

**Summary:** An Azure storage shared key is visible in an HTTP response from {asset} — rotate immediately.

**Description:**

> An Azure storage account shared key was found in an HTTP response from {asset}. Shared keys grant unlimited access to every blob, queue, table, and file share in the storage account. They don't expire — once leaked, the key is compromised until manually rotated.

**Remediation:**

> **Rotate the storage account key**
>   In the Azure portal: Storage account → Access keys → Rotate key. Update every consumer with the new value.
>
> **Audit storage diagnostic logs**
>   Look for unfamiliar SAS-key usage and operations from unexpected source IPs over the leak window.
>
> **Migrate to managed identity**
>   Azure managed identities eliminate shared keys for service-to-service auth. For end-user access, use SAS tokens with short expiry instead of shared keys.

**Tags:** `nuclei`, `info-disclosure`, `azure-shared-key-disclosure`, `azure`, `credentials`
**Alert name:** Info Disclosure — Azure Key Leak
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- Microsoft — Manage storage account access keys

---

### `nuclei-cpanel-default-login`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** cPanel default credentials accepted at {asset}

**Summary:** Default credentials work on the cPanel instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the cPanel instance on {asset} accepts known default credentials (`root/changeme`, `admin/admin`). cPanel WHM admin access grants root-equivalent control over every hosted account — DNS, mail, databases, file system. A foothold for mass-defacement or web-shell deployment across every customer site.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the cPanel audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `cpanel-default-login`, `rce-risk`
**Alert name:** Default Creds — cPanel
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-etcd-exposed`

**Severity:** CRITICAL · **CWE:** CWE-306 · **Category:** service_exposure

**Title:** etcd cluster exposed at {asset}

**Summary:** An exposed etcd cluster was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An etcd cluster is reachable on {asset}. etcd holds all Kubernetes cluster state — secrets, RBAC bindings, every object definition. Unauthenticated etcd access is equivalent to full cluster compromise. The exposure also applies to non-K8s etcd deployments (Vault storage, service-mesh state).

**Remediation:**

> etcd should never be reachable from outside the cluster. Configure mutual TLS auth on etcd's client port (2379) and peer port (2380). Restrict at the network layer. If etcd has been internet-exposed, treat all secrets stored in the cluster as compromised — rotate them.

**Tags:** `nuclei`, `exposed-panel`, `etcd-exposed`, `k8s`, `rce-risk`
**Alert name:** Exposed Panel — etcd
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- etcd — Security model

---

### `nuclei-exposed-helm-tiller`

**Severity:** CRITICAL · **CWE:** CWE-306 · **Category:** misconfigurations

**Title:** Helm Tiller (v2) reachable on {asset}

**Summary:** Helm Tiller (v2) is reachable on {asset} — anyone on the network can deploy arbitrary workloads. Migrate to Helm v3 now.

**Description:**

> A Helm Tiller (v2) endpoint is reachable on {asset}. Tiller v2 ran with cluster-admin equivalent permissions and accepted unauthenticated gRPC requests by default — anyone reaching the port could deploy arbitrary workloads to the cluster. Helm v3 removed Tiller entirely; if you see this finding, you're on a deprecated and fundamentally-insecure Helm version.

**Remediation:**

> **Migrate to Helm v3 immediately**
>   Helm v2 was deprecated in 2020 and reached end-of-life in November 2020. The `helm 2to3` plugin migrates releases.
>
> **Audit cluster state**
>   Review every Deployment, StatefulSet, DaemonSet, and Job in the cluster for unfamiliar workloads that could have been planted via Tiller. Check ClusterRoleBindings for new entries.

**Tags:** `nuclei`, `misconfiguration`, `exposed-helm-tiller`, `k8s`, `helm`, `rce-risk`
**Alert name:** Misconfig — Helm Tiller
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Helm — Migrating Helm v2 to v3

---

### `nuclei-gcp-metadata-ssrf`

**Severity:** CRITICAL · **CWE:** CWE-918 · **Category:** vulnerabilities

**Title:** GCP metadata server reachable via SSRF from {asset}

**Summary:** GCP metadata server reachable via SSRF on {asset} — the instance service-account's tokens should be considered compromised.

**Description:**

> Nuclei reached the GCP metadata server (metadata.google.internal / 169.254.169.254) via a vulnerable endpoint on {asset}. GCP metadata returns access tokens for the instance's service account — full GCP API access at the service account's permissions, including any project, dataset, bucket, or secret it can read.

**Remediation:**

> Patch the SSRF (allow-list destinations, block metadata.google.internal and 169.254.169.254). GCP requires the `Metadata-Flavor: Google` header which blocks naive SSRF — but flexible SSRF primitives can supply it. Audit GCP Audit Logs for the service account since the endpoint became vulnerable; rotate the service account's keys if compromise is suspected.

**Tags:** `nuclei`, `misconfiguration`, `gcp-metadata-ssrf`, `ssrf`, `gcp`, `imds`, `cloud-creds`
**Alert name:** Misconfig — GCP Metadata SSRF
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Google Cloud — Metadata server protection

---

### `nuclei-gcp-service-account-disclosure`

**Severity:** CRITICAL · **CWE:** CWE-798 · **Category:** data_leaks

**Title:** GCP service account credentials disclosed at {asset}

**Summary:** GCP service-account credentials are visible in an HTTP response from {asset} — rotate and audit.

**Description:**

> A GCP service account JSON key file was found in an HTTP response from {asset}. The key contains a private RSA component used to sign auth tokens for the service account — anyone holding the file can act as that identity at its full granted scope (project, organisation, dataset, bucket).

**Remediation:**

> **Treat as compromised credentials**
>   Disable and delete the service-account key in GCP IAM (`gcloud iam service-accounts keys delete`). Generate a new key only for legitimate consumers and deliver via Secret Manager.
>
> **Audit GCP Audit Logs**
>   Search Cloud Audit Logs for the leaked service-account email over the page's reachability window. Look for unfamiliar API calls or principal IPs.
>
> **Move to keyless auth where possible**
>   Workload Identity Federation eliminates JSON key files entirely for many use cases — use it instead of service-account keys for production workloads.

**Tags:** `nuclei`, `info-disclosure`, `gcp-service-account-disclosure`, `gcp`, `credentials`
**Alert name:** Info Disclosure — GCP SA Key Leak
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- Google Cloud — Best practices for managing service account keys

---

### `nuclei-jboss-default-login`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** JBoss default credentials accepted at {asset}

**Summary:** Default credentials work on the JBoss instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the JBoss instance on {asset} accepts known default credentials (`admin/admin`, `jboss/jboss`). JBoss / WildFly admin access allows arbitrary application deployment via the JMX console or admin-console UI. Combined with JBoss's deserialisation-CVE history, default-creds is a direct path to RCE.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the JBoss audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `jboss-default-login`, `rce-risk`
**Alert name:** Default Creds — JBoss
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Red Hat — JBoss EAP Security

---

### `nuclei-jenkins-default-credentials`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Jenkins default credentials accepted at {asset}

**Summary:** Default credentials work on the Jenkins instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Jenkins instance on {asset} accepts known default credentials (`admin/admin`, `admin/jenkins`, `jenkins/jenkins`). Jenkins admin access is functionally equivalent to RCE on the controller — admins can run Groovy via the script console (`/script`), trigger arbitrary builds, and read every credential in the Credentials store. Jenkins is one of the most-attacked CI/CD platforms; default-creds findings here are entry points to full supply-chain compromise.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Jenkins audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.
>
> **Rotate every secret in the Credentials store**
>   Treat all stored deploy keys, API tokens, signing keys, and passwords as compromised. Cross-reference with downstream systems (artefact registries, cloud accounts) for unauthorised use.
>
> **Disable signup, enforce SSO**
>   Configure Matrix-based authorisation; require external IdP login. Disable the script console for non-admin roles.

**Tags:** `nuclei`, `default-credentials`, `jenkins-default-credentials`, `ci-cd`, `rce-risk`, `supply-chain`
**Alert name:** Default Creds — Jenkins
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Jenkins — Securing Jenkins

---

### `nuclei-jenkins-script-console`

**Severity:** CRITICAL · **CWE:** CWE-77 · **Category:** service_exposure

**Title:** Jenkins script console exposed at {asset}

**Summary:** An exposed Jenkins script console was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> The Jenkins Groovy script console is reachable on {asset}. If it's accessible without authentication — or with default credentials — any visitor can execute arbitrary Groovy code on the controller, which is equivalent to RCE on the Jenkins host.

**Remediation:**

> **Lock the script console behind admin auth immediately**
>   Disable anonymous access; restrict the console to a small set of named admin accounts.
>
> **Audit recent script-console activity**
>   Check `$JENKINS_HOME/logs/`, build histories, and the Audit Trail plugin if installed. Look for unfamiliar build jobs, modified pipelines, and exfiltrated credentials.
>
> **Rotate all secrets stored in Jenkins**
>   Treat every credential, deploy key, and API token in the Credentials store as compromised.

**Tags:** `nuclei`, `exposed-panel`, `jenkins-script-console`, `rce-risk`
**Alert name:** Exposed Panel — Jenkins Script Console
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Jenkins — Script console

---

### `nuclei-jmx-rmi-exposed`

**Severity:** CRITICAL · **CWE:** CWE-306 · **Category:** service_exposure

**Title:** JMX-RMI management endpoint exposed at {asset}

**Summary:** An exposed JMX-RMI management endpoint was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A JMX-RMI management endpoint is reachable on {asset}. JMX without auth lets anyone register an MBean that executes arbitrary Java code on the JVM — a classic and still-common path to RCE on JBoss, Tomcat, Cassandra, and other Java services. Even with auth, JMX over RMI is a documented attack surface.

**Remediation:**

> **Disable JMX-RMI on production** unless you're actively using it for monitoring.
>
> **If JMX is required**
>   Restrict to localhost or an internal management subnet only.
>   Enable JMX authentication and require SSL: `-Dcom.sun.management.jmxremote.authenticate=true`, `-Dcom.sun.management.jmxremote.ssl=true`.
>   Use jmxremote.password and jmxremote.access files with strong credentials.
>
> **Audit for prior compromise**
>   Java services that have had unauth JMX exposed often show evidence of MBean registration in their logs.

**Tags:** `nuclei`, `exposed-panel`, `jmx-rmi-exposed`, `rce-risk`
**Alert name:** Exposed Panel — JMX-RMI
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Oracle — JMX Security

---

### `nuclei-kubernetes-api-exposed`

**Severity:** CRITICAL · **CWE:** CWE-306 · **Category:** service_exposure

**Title:** Kubernetes API server exposed at {asset}

**Summary:** An exposed Kubernetes API server was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Kubernetes API server is reachable on {asset} without authentication, or with anonymous access enabled. Anonymous K8s API access typically grants `system:anonymous` / `system:unauthenticated` group membership — many clusters have leftover overly-permissive ClusterRoleBindings on those groups, granting read or even write across the whole cluster.

**Remediation:**

> Disable anonymous auth (`--anonymous-auth=false` on kube-apiserver). Audit ClusterRoleBindings for any binding to `system:anonymous` or `system:unauthenticated` groups and remove them. Restrict the API server to known networks via `--bind-address` and a firewall. Audit recent API calls for unauthorised activity.

**Tags:** `nuclei`, `exposed-panel`, `kubernetes-api-exposed`, `k8s`, `rce-risk`
**Alert name:** Exposed Panel — K8s API
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Kubernetes — Authentication
- CIS Kubernetes Benchmark

---

### `nuclei-mssql-default-login`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Microsoft SQL Server default credentials accepted at {asset}

**Summary:** Default credentials work on the Microsoft SQL Server instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Microsoft SQL Server instance on {asset} accepts known default credentials (`sa/sa`, `sa/`, `sa/password`, `sa/Password1`). MS SQL Server's `sa` account has implicit sysadmin role — default credentials grant unlimited database access plus the `xp_cmdshell` extended procedure, which executes arbitrary commands on the host as the SQL Server service account. This is a direct path to RCE on Windows servers.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Microsoft SQL Server audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.
>
> **Disable `xp_cmdshell` if not needed**
>   `sp_configure 'xp_cmdshell', 0; RECONFIGURE;`
>
> **Disable the `sa` account entirely**
>   Use Windows Authentication (integrated security) where possible. If `sa` must exist, rename it and set a strong password.

**Tags:** `nuclei`, `default-credentials`, `mssql-default-login`, `database`, `rce-risk`
**Alert name:** Default Creds — MSSQL
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Microsoft — Securing SQL Server

---

### `nuclei-mysql-default-credentials`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** MySQL default credentials accepted at {asset}

**Summary:** Default credentials work on the MySQL instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the MySQL instance on {asset} accepts known default credentials (`root/`, `root/root`, `root/mysql`, `root/password`). MySQL `root` access grants unlimited database access plus `SELECT INTO OUTFILE` for filesystem writes — a classic path to web-shell deployment when the MySQL data directory is writable from the web server. Direct route to data theft and host compromise.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the MySQL audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.
>
> Rename the `root` account and set a strong password. Disable remote root access (`bind-address = 127.0.0.1`). Disable `LOAD DATA LOCAL INFILE` if your application doesn't need it.

**Tags:** `nuclei`, `default-credentials`, `mysql-default-credentials`, `database`, `rce-risk`
**Alert name:** Default Creds — MySQL
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- MySQL — Securing the Initial MySQL Account

---

### `nuclei-phpmyadmin-default-login`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** phpMyAdmin default credentials accepted at {asset}

**Summary:** Default credentials work on the phpMyAdmin instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the phpMyAdmin instance on {asset} accepts known default credentials (`root/`, `root/root`). phpMyAdmin uses underlying MySQL credentials — default-cred logins succeed against MySQL instances with `root/` or `root/root` passwords. With phpMyAdmin's web UI, an attacker has interactive SQL access including `SELECT INTO OUTFILE` to drop a web shell into the web root.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the phpMyAdmin audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `phpmyadmin-default-login`, `database`, `rce-risk`
**Alert name:** Default Creds — phpMyAdmin
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- phpMyAdmin — Configuration

---

### `nuclei-plesk-default-login`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Plesk default credentials accepted at {asset}

**Summary:** Default credentials work on the Plesk instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Plesk instance on {asset} accepts known default credentials (`admin/admin`, `admin/setup`). Plesk admin access grants control over every hosted website, database, and email account on the server — and via the Plesk Server Administration interface, root-equivalent host access. A common target on shared-hosting servers.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Plesk audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `plesk-default-login`, `rce-risk`
**Alert name:** Default Creds — Plesk
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-postgres-default-credentials`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** PostgreSQL default credentials accepted at {asset}

**Summary:** Default credentials work on the PostgreSQL instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the PostgreSQL instance on {asset} accepts known default credentials (`postgres/postgres`, `postgres/`, `postgres/password`). PostgreSQL `postgres` superuser access grants unlimited database access plus `COPY ... FROM PROGRAM` for command execution — direct path to RCE as the postgres service user. Several PostgreSQL CVEs gain additional scope from a superuser foothold.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the PostgreSQL audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.
>
> Set a strong password for the `postgres` superuser. Disable remote postgres login via `pg_hba.conf` or restrict to internal networks only. Avoid running application workloads as the `postgres` user — create per-application accounts with least privilege.

**Tags:** `nuclei`, `default-credentials`, `postgres-default-credentials`, `database`, `rce-risk`
**Alert name:** Default Creds — Postgres
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- PostgreSQL — Authentication

---

### `nuclei-private-key-disclosure`

**Severity:** CRITICAL · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Private key material disclosed at {asset}

**Summary:** A private key is visible in an HTTP response from {asset} — anything it authenticates is compromised.

**Description:**

> Private key material (RSA, EC, DSA, OpenSSH, or PGP private key block) was found in an HTTP response from {asset}. Whatever the key authenticates — SSH access, code-signing certificates, JWT signing, TLS certificates — should be considered compromised.

**Remediation:**

> **Identify and revoke**
>   Match the key to its purpose: SSH `authorized_keys`, code-signing certificate, JWT signing config, internal TLS, etc. Revoke / replace at every consumer.
>
> **Generate a fresh keypair**
>   Use a modern algorithm (Ed25519 for SSH; ECDSA P-256 or Ed25519 for general-purpose). Distribute the new public component only to systems that need it.
>
> **Remove the leak source**
>   Find the file/page/error that exposed the key and remove it. Add CI checks to prevent private-key blobs being committed to public surfaces.

**Tags:** `nuclei`, `info-disclosure`, `private-key-disclosure`, `credentials`, `private-key`
**Alert name:** Info Disclosure — Private Key Leak
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information

---

### `nuclei-solarwinds-default-login`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** SolarWinds default credentials accepted at {asset}

**Summary:** Default credentials work on the SolarWinds instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the SolarWinds instance on {asset} accepts known default credentials (`admin/admin`). SolarWinds admin access has supply-chain implications (SUNBURST, 2020). Admin users can deploy custom agents, configure SQL queries that run as the SolarWinds service account, and modify alert actions to run arbitrary commands. Default creds on a SolarWinds instance is a direct path to the network's monitoring estate.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the SolarWinds audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `solarwinds-default-login`, `rce-risk`, `supply-chain`
**Alert name:** Default Creds — SolarWinds
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- SolarWinds — Security Resource Center

---

### `nuclei-solr-default-credentials`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Apache Solr default credentials accepted at {asset}

**Summary:** Default credentials work on the Apache Solr instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Apache Solr instance on {asset} accepts known default credentials (`solr/SolrRocks`, `admin/admin`). Solr admin access lets attackers configure VelocityResponseWriter or DataImportHandler to execute arbitrary code (the CVE-2019-0193 / CVE-2019-17558 attack chains).

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Apache Solr audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `solr-default-credentials`, `rce-risk`
**Alert name:** Default Creds — Solr
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-spring-actuator-env`

**Severity:** CRITICAL · **CWE:** CWE-200 · **Category:** service_exposure

**Title:** Spring Boot Actuator /env endpoint exposed at {asset}

**Summary:** An exposed Spring Boot Actuator /env endpoint was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> Spring Boot's `/actuator/env` endpoint is publicly reachable on {asset}. The endpoint dumps every property in the Spring environment — `spring.datasource.password`, JWT signing keys, OAuth client secrets, third-party API tokens. Direct path to full credential leak.

**Remediation:**

> **Rotate immediately** — every property visible in /env must be considered compromised: database passwords, signing keys, third-party tokens.
>
> **Lock down Actuator**
>   Set `management.endpoints.web.exposure.include=health,info` or front Actuator with Spring Security requiring an admin role. Don't expose the management port to the internet.
>
> **Audit recent activity**
>   Review database access logs, signing-key usage logs, and any third-party API audit logs since the endpoint was first reachable.

**Tags:** `nuclei`, `exposed-panel`, `spring-actuator-env`
**Alert name:** Exposed Panel — Spring /env
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Spring — Spring Boot Actuator Security

---

### `nuclei-tomcat-default-login`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Tomcat Manager default credentials accepted at {asset}

**Summary:** Default credentials work on the Tomcat Manager instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Tomcat Manager instance on {asset} accepts known default credentials (`tomcat/tomcat`, `admin/admin`, `tomcat/s3cret`, `admin/tomcat`). The Tomcat Manager app accepts default credentials. With Manager access, anyone can deploy a malicious WAR file via the upload form and achieve remote code execution as the Tomcat process user — ransomware crews target this exact configuration at internet scale.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Tomcat Manager audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.
>
> **Better — remove Tomcat Manager entirely**
>   Manager has no place on internet-facing Tomcat instances. `rm -rf $CATALINA_HOME/webapps/manager` and `host-manager` is the right answer. If you genuinely need remote deploy, do it through CI/CD over SSH, not via the web UI.

**Tags:** `nuclei`, `default-credentials`, `tomcat-default-login`, `rce-risk`
**Alert name:** Default Creds — Tomcat Manager
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Apache Tomcat — Manager App How-To

---

### `nuclei-weblogic-default-login`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Oracle WebLogic default credentials accepted at {asset}

**Summary:** Default credentials work on the Oracle WebLogic instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Oracle WebLogic instance on {asset} accepts known default credentials (`weblogic/weblogic1`, `system/weblogic1`, `weblogic/welcome1`, `weblogic/Oracle@123`). WebLogic admin access lets attackers deploy arbitrary applications, modify the JVM classpath, and chain into deserialisation RCE via several long-lived WebLogic CVEs. Combined with the steady stream of WebLogic CVEs, default creds are a high-leverage finding.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Oracle WebLogic audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `weblogic-default-login`, `rce-risk`
**Alert name:** Default Creds — WebLogic
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Oracle — WebLogic Security

---

### `nuclei-webmin-default-credentials`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Webmin default credentials accepted at {asset}

**Summary:** Default credentials work on the Webmin instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Webmin instance on {asset} accepts known default credentials (`root/admin`, `admin/admin`). Webmin admin access grants full Unix system administration via the web UI — package management, user management, firewall rules, file editing, and direct shell command execution. Effectively SSH-as-root over a web browser.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Webmin audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.
>
> Take Webmin off the public internet — it should only be reachable from internal admin networks. Replace any default credentials. Patch to the current Webmin release (recent CVEs include CVE-2019-15107 RCE).

**Tags:** `nuclei`, `default-credentials`, `webmin-default-credentials`, `rce-risk`
**Alert name:** Default Creds — Webmin
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Webmin — Security

---

### `nuclei-websphere-default-login`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** IBM WebSphere default credentials accepted at {asset}

**Summary:** Default credentials work on the IBM WebSphere instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the IBM WebSphere instance on {asset} accepts known default credentials (`admin/admin`, `websphere/websphere`, `wasadmin/wasadmin`). WebSphere admin access allows arbitrary application deployment and access to credential stores configured inside WebSphere. Less common in modern estates but still appears in long-tail enterprise deployments.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the IBM WebSphere audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `websphere-default-login`, `rce-risk`
**Alert name:** Default Creds — WebSphere
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-wordpress-default-credentials`

**Severity:** CRITICAL · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** WordPress default credentials accepted at {asset}

**Summary:** Default credentials work on the WordPress instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the WordPress instance on {asset} accepts known default credentials (`admin/admin`, `admin/password`, `admin/wordpress`). WordPress admin access grants control over plugins, themes, and the editor — admins can install a malicious plugin or edit theme PHP files directly to achieve RCE on the web server. WordPress estate compromise is a major vector for SEO spam, malware distribution, and supply-chain attacks (via plugins).

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the WordPress audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.
>
> **Disable plugin / theme editing in admin**
>   Add `define('DISALLOW_FILE_EDIT', true);` to wp-config.php to remove the in-admin file editor.
>
> **Enforce 2FA for all admin accounts**
>   Use a plugin like Wordfence or miniOrange. Default-creds + 2FA = the rotated password is moot.

**Tags:** `nuclei`, `default-credentials`, `wordpress-default-credentials`, `cms`, `rce-risk`
**Alert name:** Default Creds — WordPress
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- WordPress — Hardening WordPress

---

### `nuclei-activemq-admin-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** ActiveMQ web console exposed at {asset}

**Summary:** An exposed ActiveMQ web console was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An Apache ActiveMQ web console is reachable on {asset}. Default credentials (`admin/admin`) are still common; CVE-2023-46604 (OpenWire protocol RCE) was exploited at scale by ransomware actors throughout late 2023 and 2024. Exposed brokers also leak queue contents.

**Remediation:**

> Patch ActiveMQ to a current release (5.17.6+ / 5.18.3+ or Artemis 2.31+). Restrict the web console and the OpenWire port (61616) to internal networks. Replace default credentials.

**Tags:** `nuclei`, `exposed-panel`, `activemq-admin-exposed`, `rce-risk`
**Alert name:** Exposed Panel — ActiveMQ
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Apache ActiveMQ — Security

---

### `nuclei-activemq-default-credentials`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** ActiveMQ default credentials accepted at {asset}

**Summary:** Default credentials work on the ActiveMQ instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the ActiveMQ instance on {asset} accepts known default credentials (`admin/admin`). ActiveMQ admin access lets attackers read every queue's contents, send arbitrary messages, and configure broker settings. Combined with CVE-2023-46604 (OpenWire RCE), default creds make exploitation trivial.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the ActiveMQ audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `activemq-default-credentials`
**Alert name:** Default Creds — ActiveMQ
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Apache ActiveMQ — Security

---

### `nuclei-airflow-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Apache Airflow webserver exposed at {asset}

**Summary:** An exposed Apache Airflow webserver was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An Apache Airflow webserver is reachable on {asset}. Airflow has had several auth-bypass and RCE CVEs (CVE-2022-40954, CVE-2022-46651). Authenticated Airflow users can typically execute arbitrary Python via DAGs, so any account compromise = code execution on Airflow infrastructure. Many older deployments shipped without auth by default.

**Remediation:**

> Take Airflow off the public internet — it should only be reachable from your data team's network. Confirm RBAC is enabled and there's no anonymous access. Patch to current Airflow release.

**Tags:** `nuclei`, `exposed-panel`, `airflow-exposed`, `rce-risk`
**Alert name:** Exposed Panel — Airflow
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Apache Airflow — Security

---

### `nuclei-argo-cd-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Argo CD UI exposed at {asset}

**Summary:** An exposed Argo CD UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An Argo CD UI is reachable on {asset}. Argo CD orchestrates Kubernetes deployments — compromise of an Argo CD instance is functionally equivalent to controlling every cluster it manages. Several historical CVEs (CVE-2022-29165 auth bypass, CVE-2022-24348 path traversal) make exposed Argo particularly worth locking down.

**Remediation:**

> Argo CD should sit behind your organisation's auth proxy or VPN, never directly on the public internet. If the UI must be reachable, enforce SSO and disable the local admin account. Patch to the current Argo CD release.

**Tags:** `nuclei`, `exposed-panel`, `argo-cd-exposed`, `k8s`
**Alert name:** Exposed Panel — Argo CD
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Argo CD — Hardening guide

---

### `nuclei-axis-default-credentials`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Axis camera default credentials accepted at {asset}

**Summary:** Default credentials work on the Axis camera instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Axis camera instance on {asset} accepts known default credentials (`root/pass`, `admin/admin`). Axis camera admin access grants live and recorded video viewing plus access to firmware-update functionality — a pivot for botnet recruitment and surveillance compromise.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Axis camera audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `axis-default-credentials`, `iot`, `camera`
**Alert name:** Default Creds — Axis Camera
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-blind-ssrf`

**Severity:** HIGH · **CWE:** CWE-918 · **Category:** vulnerabilities

**Title:** Blind server-side request forgery on {asset}

**Summary:** Blind SSRF on {asset} — confirmed via out-of-band interaction. Patch as you would any SSRF.

**Description:**

> Nuclei detected blind SSRF on {asset} — the application fetches an attacker-supplied URL but doesn't return the response body. Confirmed via out-of-band (OOB) interaction: the affected endpoint reached out to a Nuclei-hosted callback. Blind SSRF is harder to exploit but still actionable for internal-network reconnaissance and cloud-metadata theft.

**Remediation:**

> Same approach as standard SSRF: allow-list destinations, block private address space, use IMDSv2. The blind variant is still exploitable — patch with the same urgency. Audit outbound network connections from the affected service for unexpected destinations since the issue first surfaced.

**Tags:** `nuclei`, `misconfiguration`, `blind-ssrf`, `ssrf`
**Alert name:** Misconfig — Blind SSRF
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- OWASP — SSRF Prevention Cheat Sheet

---

### `nuclei-cacti-default-login`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Cacti default credentials accepted at {asset}

**Summary:** Default credentials work on the Cacti instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Cacti instance on {asset} accepts known default credentials (`admin/admin`). Cacti admin access exposes monitored device inventories and SNMP credentials. Cacti has had several authenticated RCE CVEs (CVE-2022-46169 command injection chained from default creds was actively exploited).

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Cacti audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `cacti-default-login`
**Alert name:** Default Creds — Cacti
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Cacti — Security

---

### `nuclei-cisco-default-credentials`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Cisco device default credentials accepted at {asset}

**Summary:** Default credentials work on the Cisco device instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Cisco device instance on {asset} accepts known default credentials (`cisco/cisco`, `admin/admin`, `admin/cisco`). Cisco device admin access lets attackers read configuration (routing tables, ACLs, SNMP community strings), modify routing to redirect or capture traffic, and use the device as a pivot into the internal network. Cisco devices are high-value targets for state-level adversaries.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Cisco device audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `cisco-default-credentials`, `network-device`
**Alert name:** Default Creds — Cisco
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-consul-ui-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Consul UI exposed at {asset}

**Summary:** An exposed Consul UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A HashiCorp Consul UI is reachable on {asset}. Consul without ACLs configured allows anyone with UI access to register services, modify health checks, and read service metadata that often contains internal IPs, DNS names, and occasionally credentials in tags or KV values.

**Remediation:**

> Enable Consul ACLs (`acl.enabled = true`) with a default deny policy. Restrict UI access to internal networks. Audit the KV store for exposed credentials and migrate them to Vault.

**Tags:** `nuclei`, `exposed-panel`, `consul-ui-exposed`
**Alert name:** Exposed Panel — Consul
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- HashiCorp — Consul ACL system

---

### `nuclei-cors-wildcard-with-credentials`

**Severity:** HIGH · **CWE:** CWE-942 · **Category:** misconfigurations

**Title:** CORS allows wildcard origin with credentials on {asset}

**Summary:** Your CORS config lets any origin read authenticated responses on {asset} — credential-bearing endpoints are exposed cross-origin.

**Description:**

> The application returns `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`. Modern browsers refuse this combination, but older browsers and many non-browser clients accept it — and the underlying intent (any origin can read authenticated responses) is almost always wrong. If a more nuanced CORS rule reflects the request origin while sending credentials, the same issue applies in spirit even when wildcard isn't used.

**Remediation:**

> Pick the right model:
>   • If credentials must travel: maintain an explicit allow-list of trusted origins and reflect only those into `Access-Control-Allow-Origin`. Never combine with `*`.
>   • If credentials don't need to travel: drop `Access-Control-Allow-Credentials`; wildcard origin is safe without it.
>
> Audit every endpoint that returns sensitive data to confirm the response can't be read cross-origin without authentication context.

**Tags:** `nuclei`, `misconfiguration`, `cors-wildcard-with-credentials`, `cors`, `headers`
**Alert name:** Misconfig — CORS Wildcard + Creds
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- MDN — Cross-Origin Resource Sharing
- PortSwigger — Cross-origin resource sharing (CORS)

---

### `nuclei-couchdb-default-login`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Apache CouchDB default credentials accepted at {asset}

**Summary:** Default credentials work on the Apache CouchDB instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Apache CouchDB instance on {asset} accepts known default credentials (`admin/admin`). CouchDB admin access grants full read/write/delete on every database. Older CouchDB versions chained admin access into RCE via CVE-2017-12635 / CVE-2017-12636.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Apache CouchDB audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `couchdb-default-login`, `rce-risk`
**Alert name:** Default Creds — CouchDB
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-couchdb-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** CouchDB Fauxton admin UI exposed at {asset}

**Summary:** An exposed CouchDB Fauxton admin UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An Apache CouchDB Fauxton admin UI is reachable on {asset}. Pre-3.x CouchDB ran in 'admin party' mode by default — any anonymous user could create, read, update, and delete every database. CVE-2017-12635 and CVE-2017-12636 chained for unauthenticated RCE.

**Remediation:**

> Restrict the CouchDB UI to internal networks. Disable admin-party mode by setting an admin password (CouchDB 3.x does this on first install; older versions need explicit setup). Patch to current CouchDB release.

**Tags:** `nuclei`, `exposed-panel`, `couchdb-exposed`
**Alert name:** Exposed Panel — CouchDB
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- CouchDB — Security

---

### `nuclei-docker-registry-v2-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Docker Registry v2 API exposed at {asset}

**Summary:** An exposed Docker Registry v2 API was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An open Docker Registry v2 API is reachable on {asset}. Without auth, anyone can list repositories and pull images. Pulled images frequently contain embedded secrets (API keys, database passwords in env vars), source code, and build dependencies.

**Remediation:**

> Enable authentication on the registry (token auth, basic auth via reverse proxy). Better — don't expose the registry to the public internet at all. If you need public images, publish them to a managed registry (GHCR, GHCR public, Docker Hub public).

**Tags:** `nuclei`, `exposed-panel`, `docker-registry-v2-exposed`
**Alert name:** Exposed Panel — Docker Registry
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Docker — Distribution authentication

---

### `nuclei-elasticsearch-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Elasticsearch cluster exposed at {asset}

**Summary:** An exposed Elasticsearch cluster was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An Elasticsearch HTTP API is reachable on {asset}. Older OSS releases had no built-in auth — exposed instances are routinely scraped by automated tooling that either steals data or ransom-wipes indexes ('Meow' attacks). Even with Elastic Security enabled, exposing the management API to the internet leaves the cluster vulnerable to credential-spray and version-specific CVEs.

**Remediation:**

> Enable Elastic security features (free since 7.x with 8.0 enabling them by default). Restrict the HTTP API to internal networks. Front with a reverse proxy enforcing auth if the API must be public.

**Tags:** `nuclei`, `exposed-panel`, `elasticsearch-exposed`
**Alert name:** Exposed Panel — Elasticsearch
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Elastic — Securing Elasticsearch

---

### `nuclei-exposed-cassandra`

**Severity:** HIGH · **CWE:** CWE-306 · **Category:** misconfigurations

**Title:** Apache Cassandra exposed without authentication on {asset}

**Summary:** Cassandra on {asset} accepts unauthenticated connections — every keyspace is reachable.

**Description:**

> Nuclei confirmed an Apache Cassandra instance on {asset} responds without authentication. Cassandra ships with auth disabled by default; exposed instances let any client connect and read/write every keyspace. Several documented breach incidents involved unauthenticated Cassandra clusters.

**Remediation:**

> Enable authentication in `cassandra.yaml`: set `authenticator: PasswordAuthenticator` and `authorizer: CassandraAuthorizer`. Restart and create non-default users via cqlsh; remove the default `cassandra` superuser or change its password from the default (`cassandra/cassandra`). Restrict the CQL port (9042) and internode port (7000/7001) to internal networks.

**Tags:** `nuclei`, `misconfiguration`, `exposed-cassandra`, `database`, `no-auth`
**Alert name:** Misconfig — Cassandra
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Apache Cassandra — Security

---

### `nuclei-exposed-couchbase`

**Severity:** HIGH · **CWE:** CWE-306 · **Category:** misconfigurations

**Title:** Couchbase exposed without authentication on {asset}

**Summary:** Couchbase on {asset} is reachable without proper auth — every bucket is at risk.

**Description:**

> A Couchbase node is reachable on {asset} without authentication, or with default credentials. Couchbase's REST and N1QL endpoints (typically 8091, 8092, 8093) should never be internet-exposed. Once authenticated, an attacker has full read/write to every bucket.

**Remediation:**

> Restrict Couchbase node ports (8091/8092/8093/11210) to internal networks. Replace any default credentials. Enable encryption-in-transit via Couchbase's TLS configuration. Audit recent admin activity in the Couchbase Web Console.

**Tags:** `nuclei`, `misconfiguration`, `exposed-couchbase`, `database`, `no-auth`
**Alert name:** Misconfig — Couchbase
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Couchbase — Security

---

### `nuclei-exposed-helm-values`

**Severity:** HIGH · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Exposed Helm chart values on {asset}

**Summary:** A Helm values file is publicly readable on {asset} — likely contains secrets that should be rotated.

**Description:**

> A Helm chart `values.yaml` (or rendered chart manifest) is publicly readable on {asset}. Helm values frequently contain secrets that haven't yet been moved into Sealed Secrets / External Secrets Operator: database passwords, S3 bucket keys, image-pull credentials, OAuth client secrets, signing keys.

**Remediation:**

> Move secrets out of `values.yaml` into Sealed Secrets, External Secrets Operator, or a Helm secrets plugin backed by a managed KMS. Treat any secret currently in a publicly-readable values file as compromised — rotate. Don't deploy chart sources to a public webroot; produce a release artefact that doesn't include `values.yaml`.

**Tags:** `nuclei`, `misconfiguration`, `exposed-helm-values`, `k8s`, `helm`, `secrets`
**Alert name:** Misconfig — Helm Values Exposed
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Sealed Secrets
- External Secrets Operator

---

### `nuclei-exposed-ldap-anonymous`

**Severity:** HIGH · **CWE:** CWE-287 · **Category:** misconfigurations

**Title:** Anonymous LDAP bind allowed on {asset}

**Summary:** LDAP on {asset} allows anonymous binds — your directory structure is enumerable.

**Description:**

> The LDAP server on {asset} accepts anonymous binds and returns directory contents without authentication. Attackers harvest organisational structure, employee usernames, group memberships, and (in some misconfigured AD environments) credential material from `userPassword`-like attributes.

**Remediation:**

> Disable anonymous binds:
>   • OpenLDAP: set `disallow bind_anon` in slapd.conf, or set `olcDisallows: bind_anon` in dynamic config.
>   • Active Directory: set `dsHeuristics` attribute to disallow anonymous binds; audit `domain controllers` for the `LDAP server channel binding token requirements` registry setting.
>   • 389-ds: use `nsslapd-allow-anonymous-access: off`.
> Restrict LDAP (389) and LDAPS (636) to internal networks.

**Tags:** `nuclei`, `misconfiguration`, `exposed-ldap-anonymous`, `ldap`, `active-directory`
**Alert name:** Misconfig — LDAP Anonymous
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Microsoft — LDAP server channel binding

---

### `nuclei-exposed-memcached`

**Severity:** HIGH · **CWE:** CWE-306 · **Category:** misconfigurations

**Title:** Memcached exposed on {asset}

**Summary:** Memcached on {asset} is reachable without auth — your data is at risk and your server may be participating in DDoS amplification.

**Description:**

> A Memcached instance is reachable on {asset}. Memcached has no authentication mechanism — anyone reaching port 11211 can read, write, and flush every cache entry. Exposed Memcached has also been weaponised for amplification DDoS attacks (Memcrashed, 2018) — your server may have participated in attacks against third parties without your knowledge.

**Remediation:**

> Bind Memcached to localhost (`-l 127.0.0.1`) or an internal interface only. Disable UDP support entirely (`-U 0`) — this is the change that prevents amplification-DDoS abuse. If remote access is genuinely required, use a reverse proxy with auth or SASL-enabled Memcached (many distributions don't ship SASL by default).

**Tags:** `nuclei`, `misconfiguration`, `exposed-memcached`, `cache`, `no-auth`, `amplification`
**Alert name:** Misconfig — Memcached
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Memcached — Security
- Cloudflare — The Memcrashed amplification attack

---

### `nuclei-exposed-mongodb-public`

**Severity:** HIGH · **CWE:** CWE-306 · **Category:** misconfigurations

**Title:** Unauthenticated MongoDB on {asset}

**Summary:** MongoDB on {asset} accepts unauthenticated connections — restore from backup if data is missing, then enable auth.

**Description:**

> Nuclei confirmed MongoDB on {asset} responds without authentication. Pre-3.6 MongoDB shipped with auth disabled by default — the resulting mass-ransom campaigns ('Meow' wipes, ransom notes left in databases) hit thousands of instances. Modern MongoDB binds to localhost out of the box, so an internet-exposed unauthenticated instance has been actively reconfigured.

**Remediation:**

> Enable authentication in `mongod.conf`: `security.authorization: enabled`. Create a per-database user with least privilege; remove any test accounts. Bind to an internal interface, not 0.0.0.0. Restore from the most recent clean backup if your data has been wiped or ransomed (don't pay).

**Tags:** `nuclei`, `misconfiguration`, `exposed-mongodb-public`, `database`, `no-auth`
**Alert name:** Misconfig — MongoDB Unauth
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- MongoDB — Security Checklist

---

### `nuclei-exposed-redis-public`

**Severity:** HIGH · **CWE:** CWE-306 · **Category:** misconfigurations

**Title:** Unauthenticated Redis on {asset}

**Summary:** Redis on {asset} accepts unauthenticated connections — patch and audit for compromise immediately.

**Description:**

> Nuclei confirmed Redis on {asset} responds without authentication. Even when AUTH is set, default config exposed to the internet allows attackers to write arbitrary files via CONFIG SET (including SSH authorized_keys). Exposed Redis instances are routinely compromised within hours.

**Remediation:**

> **Lock down immediately**
>   Bind to localhost or an internal interface (`bind 127.0.0.1`). Enable `protected-mode yes`. Run Redis as an unprivileged user. Set a strong AUTH password or, on Redis 6+, configure ACL users with least privilege.
>
> **Audit for compromise**
>   Check `~/.ssh/authorized_keys` on the Redis host for unfamiliar entries. Review the Redis dump file for unexpected keys (cryptominer config is common). Inspect running processes for `xmrig` and friends.

**Tags:** `nuclei`, `misconfiguration`, `exposed-redis-public`, `database`, `no-auth`
**Alert name:** Misconfig — Redis Unauth
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Redis — Security

---

### `nuclei-exposed-rsync`

**Severity:** HIGH · **CWE:** CWE-306 · **Category:** misconfigurations

**Title:** Unauthenticated rsync server on {asset}

**Summary:** An unauthenticated rsync server on {asset} — anyone can list and download every module's contents.

**Description:**

> An rsync server on {asset} (port 873) accepts connections without authentication. Attackers can list every module, download arbitrary files, and on misconfigured modules write files into the host's filesystem. Common as a leftover from backup-replication setups that were never secured.

**Remediation:**

> Edit `rsyncd.conf` to require authentication: set `auth users` and `secrets file` per module. Add `read only = yes` on modules where write access isn't needed. Restrict module access via `hosts allow` to known source IPs. Better — bind rsync to localhost and tunnel over SSH for remote replication.

**Tags:** `nuclei`, `misconfiguration`, `exposed-rsync`, `rsync`
**Alert name:** Misconfig — rsync Unauth
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- rsync — rsyncd.conf manpage

---

### `nuclei-exposed-snmp-public-community`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** SNMP with default 'public' community string on {asset}

**Summary:** SNMP on {asset} responds to 'public' community — network topology and device config are exposed.

**Description:**

> SNMP on {asset} responds to the default `public` community string. SNMP returns device configuration, routing tables, interface stats, and ARP/MAC tables — full network topology recon. Many devices also respond to `private` with read-write access, allowing config changes.

**Remediation:**

> Replace the `public` community string with a strong secret-equivalent string. Disable SNMPv1/v2c and switch to SNMPv3 with authentication and encryption. Restrict SNMP (UDP 161) to known monitoring servers via firewall. Audit any device that previously had `public` enabled — config changes may have been made via `private`.

**Tags:** `nuclei`, `misconfiguration`, `exposed-snmp-public-community`, `snmp`
**Alert name:** Misconfig — SNMP Public
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- RFC 3414 — SNMPv3 User-based Security Model

---

### `nuclei-firebase-realtime-db-public`

**Severity:** HIGH · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Firebase Realtime Database publicly readable on {asset}

**Summary:** A Firebase Realtime Database on {asset} is publicly readable — likely contains user data that's been scraped.

**Description:**

> A Firebase Realtime Database is reachable from {asset} with public read (and possibly write) rules. Firebase's default rules used to be open, and many tutorials still show open rules — exposed databases routinely leak production user data, chat messages, location history, and authentication tokens stored as JSON values.

**Remediation:**

> Tighten Firebase security rules in the Firebase Console (Realtime Database → Rules):
> ```
> { "rules": { ".read": "auth != null", ".write": "auth != null" } }
> ```
> Then iterate to require specific role / user-scope constraints on each path. Audit the database's contents and authentication logs for unfamiliar reads since the database was first reachable.

**Tags:** `nuclei`, `info-disclosure`, `firebase-realtime-db-public`, `firebase`, `gcp`
**Alert name:** Info Disclosure — Firebase RTDB
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- Firebase — Database security rules

---

### `nuclei-fortinet-default-credentials`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Fortinet device default credentials accepted at {asset}

**Summary:** Default credentials work on the Fortinet device instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Fortinet device instance on {asset} accepts known default credentials (`admin/`, `admin/admin`, `admin/fortinet`). Fortinet device admin access lets attackers modify firewall rules, read VPN credentials and configurations, and use the device as a pivot. Fortinet appliances are heavily targeted (see CVE-2024-21762, CVE-2018-13379) — default credentials compound the risk.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Fortinet device audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `fortinet-default-credentials`, `network-device`
**Alert name:** Default Creds — Fortinet
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-ftp-default-credentials`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** FTP default credentials accepted at {asset}

**Summary:** Default credentials work on the FTP instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the FTP instance on {asset} accepts known default credentials (`anonymous/anonymous`, `ftp/ftp`, `anonymous/`, `admin/admin`). FTP default credentials give attackers direct file-system access. Anonymous FTP frequently leaks system configuration, uploaded user content, and (worst case) the web root itself — a vector for serving attacker-modified content from your domain.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the FTP audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.
>
> Disable FTP entirely — use SFTP (SSH-based) or FTPS. If FTP must stay, disable anonymous access in the FTP daemon's configuration.

**Tags:** `nuclei`, `default-credentials`, `ftp-default-credentials`
**Alert name:** Default Creds — FTP
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-github-token-disclosure`

**Severity:** HIGH · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** GitHub token disclosed at {asset}

**Summary:** A GitHub token is visible at {asset} — revoke and audit user activity.

**Description:**

> A GitHub personal access token (ghp_, gho_, ghu_, ghs_, or github_pat_-prefixed) was found in a response from {asset}. PATs can read and modify any repository the issuing user has access to — including private repos, GitHub Actions secrets, and organisation administration depending on token scope.

**Remediation:**

> Revoke the token immediately at github.com/settings/tokens (or the org-level Personal access tokens page for fine-grained tokens). Audit the user's recent activity in GitHub's audit log for any commits, releases, or workflow runs that weren't them. Treat any GitHub Actions secrets the user could read as compromised.

**Tags:** `nuclei`, `info-disclosure`, `github-token-disclosure`, `github`, `credentials`
**Alert name:** Info Disclosure — GitHub Token
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- GitHub — Reviewing your security log
- GitHub — Keeping your account and data secure

---

### `nuclei-grafana-default-credentials`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Grafana default credentials accepted at {asset}

**Summary:** Default credentials work on the Grafana instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Grafana instance on {asset} accepts known default credentials (`admin/admin`). Grafana ships with `admin/admin` as the default. Once authenticated as admin, an attacker can install plugins (a vector for RCE on certain plugins), use the data-source SQL editor on backends like MySQL/Postgres to query the underlying database, and modify dashboards / alert rules. Several Grafana CVEs (CVE-2021-43798) gain extra scope from an authenticated foothold.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Grafana audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `grafana-default-credentials`
**Alert name:** Default Creds — Grafana
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Grafana — Hardening Recommendations

---

### `nuclei-hikvision-default-credentials`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Hikvision camera default credentials accepted at {asset}

**Summary:** Default credentials work on the Hikvision camera instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Hikvision camera instance on {asset} accepts known default credentials (`admin/12345`, `admin/admin`). IP camera admin access lets attackers view live and recorded video, listen to two-way audio (where supported), and incorporate the camera into Mirai-style botnets. Privacy implications are substantial.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Hikvision camera audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `hikvision-default-credentials`, `iot`, `camera`
**Alert name:** Default Creds — Hikvision
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-host-header-injection`

**Severity:** HIGH · **CWE:** CWE-644 · **Category:** misconfigurations

**Title:** Host header injection vulnerability on {asset}

**Summary:** {asset} uses unverified Host headers — password-reset emails and cached URLs can be poisoned by attackers.

**Description:**

> The application uses the request `Host` header without validation when generating absolute URLs (e.g. password-reset links, OAuth callbacks, web cache keys). An attacker who controls the Host header can poison generated URLs to point at attacker-controlled domains, leading to credential theft via password-reset emails or web cache poisoning.

**Remediation:**

> Validate the `Host` header against an explicit allow-list (your canonical hostnames). Reject requests with unexpected hosts at the web server / CDN tier. In applications, never pass the raw Host header into URL construction — use a hardcoded canonical base URL for outbound emails and OAuth callbacks.

**Tags:** `nuclei`, `misconfiguration`, `host-header-injection`, `host-header`, `headers`
**Alert name:** Misconfig — Host Header Injection
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- PortSwigger — HTTP Host header attacks

---

### `nuclei-http-request-smuggling`

**Severity:** HIGH · **CWE:** CWE-444 · **Category:** misconfigurations

**Title:** HTTP request smuggling on {asset}

**Summary:** HTTP request smuggling is possible on {asset} — attackers can hijack sessions and bypass your CDN/WAF.

**Description:**

> {asset} appears vulnerable to HTTP request smuggling — a discrepancy between how a frontend (CDN, load balancer, WAF) and the backend interpret request boundaries via Content-Length and Transfer-Encoding headers. Smuggled requests bypass frontend security controls, can hijack other users' sessions, and are often used to chain into cache poisoning or stored XSS.

**Remediation:**

> Standardise request parsing across the chain:
>   • Reject requests with both Content-Length and Transfer-Encoding headers at the frontend (most modern WAFs offer a toggle).
>   • Enforce HTTP/2 from frontend to backend where possible — HTTP/2's framing eliminates smuggling.
>   • Patch the frontend and backend to current versions; many smuggling fixes are framework-version-specific.
> Investigate logs since the issue first surfaced for anomalous request sequences.

**Tags:** `nuclei`, `misconfiguration`, `http-request-smuggling`, `smuggling`, `http`
**Alert name:** Misconfig — Request Smuggling
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- PortSwigger — HTTP request smuggling
- OWASP — HTTP Request Smuggling

---

### `nuclei-influxdb-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** InfluxDB API exposed at {asset}

**Summary:** An exposed InfluxDB API was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An InfluxDB API is reachable on {asset}. Older InfluxDB 1.x versions had no auth by default; even modern 2.x deployments with auth disabled expose all time-series data and write endpoints. Exposed Influx instances frequently leak metrics that include PII, internal service names, and operational secrets.

**Remediation:**

> Enable authentication (`auth-enabled = true` in 1.x; user setup mandatory in 2.x). Restrict the HTTP API to internal networks. Patch to current InfluxDB release.

**Tags:** `nuclei`, `exposed-panel`, `influxdb-exposed`
**Alert name:** Exposed Panel — InfluxDB
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- InfluxData — Manage authentication

---

### `nuclei-jboss-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** JBoss admin console exposed at {asset}

**Summary:** An exposed JBoss admin console was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A JBoss / WildFly admin console is reachable on {asset}. JBoss has a long CVE history, including unauthenticated RCE via the JMX console (CVE-2017-12149) and the EJB invoker servlet. Default credentials (`admin/admin`, `jboss/jboss`) still appear on exposed instances.

**Remediation:**

> Block the admin console (`/admin-console`, `/management`, `/jmx-console`) from internet access. Replace default credentials. Patch to a current Wildfly release; legacy JBoss EAP versions should be retired.

**Tags:** `nuclei`, `exposed-panel`, `jboss-exposed`, `rce-risk`
**Alert name:** Exposed Panel — JBoss
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Red Hat — JBoss EAP security

---

### `nuclei-juniper-default-credentials`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Juniper device default credentials accepted at {asset}

**Summary:** Default credentials work on the Juniper device instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Juniper device instance on {asset} accepts known default credentials (`root/`, `admin/`, `juniper/juniper`). Juniper device admin access exposes routing configuration and gives attackers a network pivot. Routinely targeted by APT actors for traffic collection.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Juniper device audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `juniper-default-credentials`, `network-device`
**Alert name:** Default Creds — Juniper
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-jwt-no-signature-verification`

**Severity:** HIGH · **CWE:** CWE-347 · **Category:** vulnerabilities

**Title:** JWT signature not verified by {asset}

**Summary:** JWT signature verification is broken on {asset} — attackers can forge any user identity. Patch immediately.

**Description:**

> Nuclei detected that {asset} accepts JWTs without verifying the signature — typically because the server accepts `alg: none` headers, or doesn't verify the signature at all. Attackers craft a token with arbitrary claims (any user ID, any role) and the server treats it as authentic — direct authentication bypass.

**Remediation:**

> Configure the JWT library to require a specific algorithm (HS256, RS256, ES256) and reject `alg: none` outright. Verify the signature on every request before reading claims. If using a JWT middleware, audit its config — many frameworks have a `verify=False` option that's been left on from a copy-pasted example. Audit recent authenticated sessions for forged tokens (claims that don't match real user records).

**Tags:** `nuclei`, `info-disclosure`, `jwt-no-signature-verification`, `jwt`, `auth-bypass`
**Alert name:** Info Disclosure — JWT Unsigned
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- RFC 8725 — JSON Web Token Best Current Practices
- OWASP — JSON Web Token Cheat Sheet

---

### `nuclei-kubernetes-dashboard-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Kubernetes Dashboard exposed at {asset}

**Summary:** An exposed Kubernetes Dashboard was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Kubernetes Dashboard is reachable on {asset}. Historic Dashboard exposures (Tesla 2018) led to crypto-mining compromise of entire clusters; Dashboard with overly-broad permissions hands out credentials and pod-exec to anyone who can reach the URL.

**Remediation:**

> Don't expose Dashboard to the public internet. Use `kubectl proxy` for local access. If exposure is required, enforce strong auth (OIDC bearer token); never use the default ServiceAccount with cluster-admin permissions.

**Tags:** `nuclei`, `exposed-panel`, `kubernetes-dashboard-exposed`, `k8s`
**Alert name:** Exposed Panel — K8s Dashboard
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Kubernetes — Web UI Dashboard
- Kubernetes — Tesla cryptojacking incident

---

### `nuclei-mikrotik-default-credentials`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** MikroTik RouterOS default credentials accepted at {asset}

**Summary:** Default credentials work on the MikroTik RouterOS instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the MikroTik RouterOS instance on {asset} accepts known default credentials (`admin/`, `admin/admin`). MikroTik RouterOS admin access has been a major botnet-recruitment vector (Mēris, TrickBot's MikroTik scanning) — compromised MikroTiks act as proxies for credential-spray campaigns and host-file modification redirects users to phishing pages.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the MikroTik RouterOS audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `mikrotik-default-credentials`, `network-device`
**Alert name:** Default Creds — MikroTik
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-mlflow-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** MLflow tracking server exposed at {asset}

**Summary:** An exposed MLflow tracking server was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An MLflow tracking server is reachable on {asset}. MLflow by default ships without auth; CVE-2023-6976 (path traversal) and other MLflow CVEs allow unauthenticated file read and model substitution. Exposed instances leak training data, model artefacts, and any embedded credentials.

**Remediation:**

> Enable basic authentication or front MLflow with an OAuth proxy. Restrict artefact-store access. Patch to current MLflow release; verify CVE-2023-6976 and follow-on CVEs are addressed.

**Tags:** `nuclei`, `exposed-panel`, `mlflow-exposed`
**Alert name:** Exposed Panel — MLflow
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- MLflow — Authentication

---

### `nuclei-mongo-express-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** mongo-express UI exposed at {asset}

**Summary:** An exposed mongo-express UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A mongo-express UI is reachable on {asset}. mongo-express ships with default credentials (`admin/pass`); exposed instances are routinely compromised within hours. Once authenticated, an attacker has full read/write/delete access to every MongoDB database.

**Remediation:**

> Don't expose mongo-express. If it must be reachable, set `ME_CONFIG_BASICAUTH_USERNAME` / `ME_CONFIG_BASICAUTH_PASSWORD` to non-default values. Confirm the underlying MongoDB itself enforces auth.

**Tags:** `nuclei`, `exposed-panel`, `mongo-express-exposed`
**Alert name:** Exposed Panel — mongo-express
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- mongo-express — README security

---

### `nuclei-mongodb-default-credentials`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** MongoDB default credentials accepted at {asset}

**Summary:** Default credentials work on the MongoDB instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the MongoDB instance on {asset} accepts known default credentials (`admin/admin`, `root/root`). MongoDB admin access grants read/write/delete on every database. While MongoDB 3.6+ binds to localhost by default, remotely-accessible instances with default creds are routinely scraped by automated tooling and ransom-wiped.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the MongoDB audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `mongodb-default-credentials`, `database`
**Alert name:** Default Creds — MongoDB
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- MongoDB — Security Checklist

---

### `nuclei-nagios-default-login`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Nagios default credentials accepted at {asset}

**Summary:** Default credentials work on the Nagios instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Nagios instance on {asset} accepts known default credentials (`nagiosadmin/nagiosadmin`, `nagiosadmin/PASSW0RD`). Nagios admin access exposes monitored host inventories, credentials configured in checks, and Nagios's command submission capability. Authenticated users can submit external commands that may execute on monitored hosts via NRPE / NSCA agents.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Nagios audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `nagios-default-login`
**Alert name:** Default Creds — Nagios
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Nagios — Security Considerations

---

### `nuclei-oauth-token-leak`

**Severity:** HIGH · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** OAuth token disclosed at {asset}

**Summary:** An OAuth token is visible at {asset} — revoke at the issuing provider and audit user activity.

**Description:**

> An OAuth access or refresh token was found in a response from {asset}. OAuth tokens grant access to whatever scopes the issuing user authorised — for refresh tokens, that access can be re-issued indefinitely until the token is explicitly revoked.

**Remediation:**

> Revoke the token at the issuing OAuth provider. For most providers (Google, Microsoft, GitHub, etc.) this is a single API call (e.g. `POST /oauth/revoke`). Audit the user's account for unfamiliar activity within the token's scope. Find the response surface that leaked it (error page, log endpoint, debug response) and remove it.

**Tags:** `nuclei`, `info-disclosure`, `oauth-token-leak`, `oauth`, `credentials`
**Alert name:** Info Disclosure — OAuth Token Leak
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- OAuth 2.0 — Token Revocation (RFC 7009)

---

### `nuclei-opennms-default-login`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** OpenNMS default credentials accepted at {asset}

**Summary:** Default credentials work on the OpenNMS instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the OpenNMS instance on {asset} accepts known default credentials (`admin/admin`). OpenNMS admin access exposes monitored host inventories and credentials configured for SNMP / WMI / SSH polling. Authenticated users can configure event notifications that execute arbitrary commands on the OpenNMS server.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the OpenNMS audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `opennms-default-login`
**Alert name:** Default Creds — OpenNMS
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-portainer-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Portainer UI exposed at {asset}

**Summary:** An exposed Portainer UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Portainer (container management) UI is reachable on {asset}. Portainer admins have full container lifecycle control — create, start, stop, exec into any container managed by the Docker / Swarm / Kubernetes endpoints Portainer connects to. Exposed login pages see credential-spray.

**Remediation:**

> Don't expose Portainer to the public internet. Place behind a VPN or auth proxy. Enforce 2FA for admin accounts. Verify the initial admin signup hasn't been completed by an attacker — fresh Portainer installs accept first-visitor admin registration.

**Tags:** `nuclei`, `exposed-panel`, `portainer-exposed`
**Alert name:** Exposed Panel — Portainer
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Portainer — Security

---

### `nuclei-rabbitmq-default-login`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** RabbitMQ default credentials accepted at {asset}

**Summary:** Default credentials work on the RabbitMQ instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the RabbitMQ instance on {asset} accepts known default credentials (`guest/guest`). RabbitMQ ships with `guest/guest` as the default — restricted to localhost by default but commonly enabled for remote access in misconfigured deployments. Authenticated users can read every queue's messages, including any sensitive data that flows through the broker.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the RabbitMQ audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.
>
> Restore the localhost-only default for the `guest` account in `rabbitmq.conf`: `loopback_users.guest = true`. Create named accounts with strong passwords for each application that connects.

**Tags:** `nuclei`, `default-credentials`, `rabbitmq-default-login`
**Alert name:** Default Creds — RabbitMQ
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- RabbitMQ — Access Control

---

### `nuclei-rancher-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Rancher UI exposed at {asset}

**Summary:** An exposed Rancher UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Rancher (Kubernetes management) UI is reachable on {asset}. Rancher governs every cluster it manages — compromising the Rancher UI is functionally equivalent to owning all those clusters' workloads. CVE-2021-25741 and others.

**Remediation:**

> Take Rancher off the public internet. Enforce SSO. Audit user list, especially for accounts with `cluster-admin` or Rancher's `admin` global role. Patch to current Rancher release.

**Tags:** `nuclei`, `exposed-panel`, `rancher-exposed`, `k8s`
**Alert name:** Exposed Panel — Rancher
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Rancher — Hardening Guide

---

### `nuclei-router-default-login`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Router web UI default credentials accepted at {asset}

**Summary:** Default credentials work on the Router web UI instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Router web UI instance on {asset} accepts known default credentials (`admin/admin`, `admin/`, `admin/password`, `root/root`). Router admin access lets attackers modify DNS settings (redirecting traffic to attacker-controlled servers), open port forwards into the internal network, install firmware modifications, and read connected device lists. A common consumer-router compromise vector.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Router web UI audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.
>
> Replace default credentials. Disable WAN-side admin access if not needed. Update firmware to the current version.

**Tags:** `nuclei`, `default-credentials`, `router-default-login`, `network-device`
**Alert name:** Default Creds — Router
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-server-side-template-injection`

**Severity:** HIGH · **CWE:** CWE-1336 · **Category:** vulnerabilities

**Title:** Server-side template injection (SSTI) on {asset}

**Summary:** Server-side template injection on {asset} — likely remote code execution. Patch and audit immediately.

**Description:**

> Nuclei detected server-side template injection on {asset}. The application renders user-supplied input inside a templating engine (Jinja2, Twig, Velocity, FreeMarker, Pug, Handlebars, etc.) without sandboxing — leading to remote code execution via template syntax in user input. VMware Workspace ONE (CVE-2022-22954) was the highest-profile recent SSTI.

**Remediation:**

> **Patch the affected endpoint immediately**
>   Stop passing user input directly into template rendering. Pass user data as bound variables (template context) instead — the template should be a static asset.
>
> **Restrict template engine capabilities**
>   Most templating engines have a sandbox mode that disables filesystem and process access. Enable it.
>
> **Audit for compromise**
>   SSTI typically means RCE was already possible; review process and filesystem audit logs since the endpoint became vulnerable.

**Tags:** `nuclei`, `misconfiguration`, `server-side-template-injection`, `ssti`, `rce-risk`
**Alert name:** Misconfig — SSTI
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- PortSwigger — Server-side template injection

---

### `nuclei-slack-token-disclosure`

**Severity:** HIGH · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Slack token disclosed at {asset}

**Summary:** A Slack token is visible at {asset} — revoke and audit workspace activity.

**Description:**

> A Slack token (xoxb-, xoxp-, xoxa-, xoxr-prefixed) was found in a response from {asset}. Slack bot, user, and app tokens grant access to the workspace they belong to — attackers can read channels, send messages, exfiltrate files, and (with admin tokens) modify workspace configuration.

**Remediation:**

> Revoke the token via the Slack admin console (Apps → the owning app → Install App → revoke). Generate a new token and deliver via a secret store. Audit the Slack workspace's audit log for unfamiliar API activity from the token's IP range over the leak window.

**Tags:** `nuclei`, `info-disclosure`, `slack-token-disclosure`, `slack`, `credentials`
**Alert name:** Info Disclosure — Slack Token
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- Slack — Token security

---

### `nuclei-smtp-open-relay`

**Severity:** HIGH · **CWE:** CWE-285 · **Category:** misconfigurations

**Title:** SMTP open relay on {asset}

**Summary:** SMTP on {asset} relays mail for anyone — your IP is being used for spam and phishing.

**Description:**

> {asset} accepts and forwards email for arbitrary sender / recipient combinations without authentication — an open relay. Spammers and phishing operators use open relays to send mail that appears to originate from your IP (damaging your IP reputation) or to spoof other domains (damaging your domain reputation when the relay's outgoing IP gets associated with abuse).

**Remediation:**

> Configure the MTA to require authentication for relaying and to restrict relaying to known-trusted sender networks only. In Postfix: set `smtpd_recipient_restrictions` to `permit_mynetworks, permit_sasl_authenticated, reject`. In Exim: configure `acl_smtp_rcpt` accordingly. Verify by attempting to relay from an external IP to an external address — should be rejected. Check IP-reputation lookups (Spamhaus, SORBS) — may need delisting after fix.

**Tags:** `nuclei`, `misconfiguration`, `smtp-open-relay`, `smtp`, `email`
**Alert name:** Misconfig — Open SMTP Relay
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Postfix — STANDARD_CONFIGURATION_README

---

### `nuclei-solr-admin-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Apache Solr admin UI exposed at {asset}

**Summary:** An exposed Apache Solr admin UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An Apache Solr admin UI is reachable on {asset}. Solr has a long unauthenticated-RCE CVE history (CVE-2019-0193 DataImportHandler, CVE-2019-17558 Velocity, CVE-2021-27905 ReplicationHandler). Exposed admin UIs are primary mass-exploitation targets.

**Remediation:**

> Take Solr off the public internet. Configure auth (BasicAuthPlugin) and disable the modules that drive the RCE chain — VelocityResponseWriter, DataImportHandler — if not in use. Patch to current Solr release.

**Tags:** `nuclei`, `exposed-panel`, `solr-admin-exposed`, `rce-risk`
**Alert name:** Exposed Panel — Solr
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Apache Solr — Securing Solr

---

### `nuclei-spark-master-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Apache Spark master UI exposed at {asset}

**Summary:** An exposed Apache Spark master UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An Apache Spark master UI is reachable on {asset}. Spark's master UI without auth lets visitors submit applications which run with Spark worker privileges — effectively remote code execution on every worker node. CVE-2022-33891 and predecessors.

**Remediation:**

> Restrict the Spark master UI to internal networks. Enable auth (`spark.acls.enable=true` / `spark.ui.acls.enable=true`). Patch Spark to a current release.

**Tags:** `nuclei`, `exposed-panel`, `spark-master-exposed`, `rce-risk`
**Alert name:** Exposed Panel — Spark Master
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Apache Spark — Security

---

### `nuclei-spring-boot-actuator`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Spring Boot Actuator endpoints exposed at {asset}

**Summary:** An exposed Spring Boot Actuator endpoints was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> Spring Boot Actuator endpoints are reachable on {asset}. Default Actuator exposure varies by version, but unsecured `/actuator/env`, `/actuator/heapdump`, and `/actuator/threaddump` leak environment variables (often containing credentials), full JVM heap snapshots, and active thread state. CVE-2017-8046 / CVE-2018-1273 chained via Actuator-exposed env.

**Remediation:**

> Restrict Actuator endpoints to internal networks via Spring Security or an external auth proxy. Set `management.endpoints.web.exposure.include=health,info` to expose only the safe endpoints (Spring Boot 2.x default is this). Audit env vars for credentials and rotate any that may have been exposed.

**Tags:** `nuclei`, `exposed-panel`, `spring-boot-actuator`
**Alert name:** Exposed Panel — Spring Actuator
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Spring — Spring Boot Actuator Security

---

### `nuclei-spring-cloud-env`

**Severity:** HIGH · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Spring Cloud Config server exposing /env on {asset}

**Summary:** Spring Cloud Config /env exposed on {asset} — secrets across all profiles are leaking. Rotate now.

**Description:**

> A Spring Cloud Config Server (or Spring application exposing `/env` directly) is publicly readable on {asset}. The endpoint dumps every property in the Spring environment — database passwords, third-party API keys, JWT signing secrets — across all profiles served by the config server.

**Remediation:**

> Restrict Spring Cloud Config Server to internal networks. Enable basic auth via Spring Security on the config server. Move sensitive properties out of plaintext git-backed config and into encrypted form (Spring Cloud Config supports JCE-based property encryption) or a managed secret store. Rotate anything visible in the currently-exposed `/env`.

**Tags:** `nuclei`, `misconfiguration`, `spring-cloud-env`, `spring`, `java`, `config-leak`
**Alert name:** Misconfig — Spring Cloud /env
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Spring Cloud Config — Security

---

### `nuclei-ssrf-detected`

**Severity:** HIGH · **CWE:** CWE-918 · **Category:** vulnerabilities

**Title:** Server-side request forgery (SSRF) on {asset}

**Summary:** An SSRF vulnerability on {asset} — attackers may reach your internal services and cloud metadata. Patch and audit.

**Description:**

> Nuclei detected server-side request forgery on {asset}. An endpoint accepts a URL parameter and fetches it from the server side without validation, letting attackers reach internal services, cloud metadata endpoints (169.254.169.254), and localhost-only management interfaces. SSRF is the entry point for many cloud-account compromises (Capital One, 2019).

**Remediation:**

> Validate fetch targets against an allow-list of known hostnames or IP ranges. Reject requests to private address space (RFC 1918, RFC 6598, link-local, loopback). Use IMDSv2 on AWS (requires session token, defeats classic SSRF). Front the affected endpoint with an egress proxy that enforces destination policy regardless of the application code.

**Tags:** `nuclei`, `misconfiguration`, `ssrf-detected`, `ssrf`
**Alert name:** Misconfig — SSRF
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- OWASP — Server Side Request Forgery Prevention Cheat Sheet

---

### `nuclei-stripe-key-disclosure`

**Severity:** HIGH · **CWE:** CWE-798 · **Category:** data_leaks

**Title:** Stripe API key disclosed at {asset}

**Summary:** A Stripe API key is visible at {asset} — distinguish publishable (safe) from secret (rotate).

**Description:**

> A Stripe API key was found in a response from {asset}. Stripe publishable keys (pk_live_*) are designed to be client-side and aren't a breach by themselves. Stripe secret keys (sk_live_*) and restricted keys (rk_live_*) grant server-side access to your Stripe account — payment creation, customer reads, refunds depending on the key's permissions.

**Remediation:**

> Verify the key prefix. If it's `pk_live_*` (publishable), no action needed — it's safe to expose. If it's `sk_live_*` or `rk_live_*`:
>   • Roll the key in the Stripe Dashboard immediately (Developers → API keys → Roll secret key).
>   • Update every consumer with the new value via your secret manager.
>   • Audit Stripe's events log for unfamiliar API activity during the leak window.

**Tags:** `nuclei`, `info-disclosure`, `stripe-key-disclosure`, `stripe`, `credentials`
**Alert name:** Info Disclosure — Stripe Key
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- Stripe — Roll API keys

---

### `nuclei-tomcat-host-manager`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Apache Tomcat Host Manager app exposed at {asset}

**Summary:** An exposed Apache Tomcat Host Manager app was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> Apache Tomcat's Host Manager (`/host-manager/html`) is reachable on {asset}. Host Manager is even more privileged than the regular Manager — it lets an authenticated user create new virtual hosts, which can be used to take over the entire Tomcat instance. Default credentials apply same as Manager.

**Remediation:**

> Remove the Host Manager webapp from production. If required, restrict source IPs and replace default credentials.

**Tags:** `nuclei`, `exposed-panel`, `tomcat-host-manager`, `rce-risk`
**Alert name:** Exposed Panel — Tomcat Host Manager
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Apache Tomcat — Security Considerations

---

### `nuclei-tomcat-manager-exposed`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** service_exposure

**Title:** Apache Tomcat Manager app exposed at {asset}

**Summary:** An exposed Apache Tomcat Manager app was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> Apache Tomcat's Manager web application (`/manager/html`) is reachable on {asset}. Manager allows WAR file deployment — if default credentials (`tomcat/tomcat`, `admin/admin`, `tomcat/s3cret`) work, an attacker can deploy a malicious WAR and achieve remote code execution. Routinely exploited by ransomware crews.

**Remediation:**

> Remove the Manager webapp entirely from production (`rm -rf $CATALINA_HOME/webapps/manager`) — it shouldn't be reachable on internet-facing instances. If it must be kept, restrict by IP in `context.xml`'s `RemoteAddrValve` and replace default credentials with strong ones in `tomcat-users.xml`.

**Tags:** `nuclei`, `exposed-panel`, `tomcat-manager-exposed`, `rce-risk`
**Alert name:** Exposed Panel — Tomcat Manager
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Apache Tomcat — Security Considerations

---

### `nuclei-unifi-default-login`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Ubiquiti UniFi default credentials accepted at {asset}

**Summary:** Default credentials work on the Ubiquiti UniFi instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Ubiquiti UniFi instance on {asset} accepts known default credentials (`ubnt/ubnt`, `admin/ubnt`). Ubiquiti UniFi controller admin access grants control over every UniFi access point, switch, and gateway managed by the controller — a pivot into the wireless network and any device using it.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Ubiquiti UniFi audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `unifi-default-login`, `network-device`
**Alert name:** Default Creds — UniFi
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-weave-scope-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Weave Scope UI exposed at {asset}

**Summary:** An exposed Weave Scope UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Weave Scope UI is reachable on {asset}. Weave Scope provides interactive visualisation of running containers — with no auth by default, it lets visitors view every process, environment variable (often containing secrets), and exec into any container in the cluster.

**Remediation:**

> Take Weave Scope off the public internet. Place behind a reverse proxy with authentication (Weave Scope itself doesn't ship auth). Audit historical access logs.

**Tags:** `nuclei`, `exposed-panel`, `weave-scope-exposed`, `k8s`
**Alert name:** Exposed Panel — Weave Scope
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Weave — Securing Scope

---

### `nuclei-weblogic-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Oracle WebLogic admin console exposed at {asset}

**Summary:** An exposed Oracle WebLogic admin console was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An Oracle WebLogic admin console is reachable on {asset}. WebLogic has been hit by multiple unauthenticated RCE CVEs (CVE-2020-14882, CVE-2020-14750 deserialisation, CVE-2023-21931 SSRF). Exposed admin consoles are routinely used as initial access by both crimeware and APT actors.

**Remediation:**

> Restrict the WebLogic admin console (`/console`) to internal networks. Apply Oracle's Critical Patch Updates promptly — quarterly is the cadence. Audit recent admin logins.

**Tags:** `nuclei`, `exposed-panel`, `weblogic-exposed`, `rce-risk`
**Alert name:** Exposed Panel — WebLogic
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Oracle — Critical Patch Updates

---

### `nuclei-websphere-exposed`

**Severity:** HIGH · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** IBM WebSphere admin console exposed at {asset}

**Summary:** An exposed IBM WebSphere admin console was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An IBM WebSphere admin console is reachable on {asset}. WebSphere has a deep history of deserialisation CVEs (CVE-2020-4276 and others) and routine default-credential issues. Less common in newer estates but still seen in long-tail enterprise deployments.

**Remediation:**

> Restrict the admin console to internal networks. Apply current IBM PSIRT patches. Audit recent admin activity.

**Tags:** `nuclei`, `exposed-panel`, `websphere-exposed`
**Alert name:** Exposed Panel — WebSphere
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- IBM — WebSphere security

---

### `nuclei-zabbix-default-login`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Zabbix default credentials accepted at {asset}

**Summary:** Default credentials work on the Zabbix instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Zabbix instance on {asset} accepts known default credentials (`Admin/zabbix`). Zabbix admin access exposes monitored host inventories, alert configurations, and the Zabbix agent's command-execution capability — admins can configure Zabbix to run arbitrary commands on monitored hosts via the script execution feature. Effectively RCE on every monitored host.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Zabbix audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `zabbix-default-login`, `rce-risk`
**Alert name:** Default Creds — Zabbix
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Zabbix — Authentication and authorisation

---

### `nuclei-zyxel-default-credentials`

**Severity:** HIGH · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Zyxel device default credentials accepted at {asset}

**Summary:** Default credentials work on the Zyxel device instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Zyxel device instance on {asset} accepts known default credentials (`admin/1234`, `admin/admin`). Zyxel device admin access exposes routing configuration and device controls. Recent Zyxel CVEs (CVE-2022-30525 command injection) make compromise more impactful when chained with default creds.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Zyxel device audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `zyxel-default-credentials`, `network-device`
**Alert name:** Default Creds — Zyxel
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-adminer-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Adminer login page exposed at {asset}

**Summary:** An exposed Adminer login page was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An Adminer instance is reachable on {asset}. Adminer is a single-PHP-file database admin tool — it's particularly risky when left in production webroots because it's hard to spot. CVE-2020-35572 (SSRF on connect-to-different-host) is routinely exploited.

**Remediation:**

> Remove Adminer from production. If genuinely needed, gate behind HTTP basic auth or VPN. Patch to current Adminer release.

**Tags:** `nuclei`, `exposed-panel`, `adminer-exposed`
**Alert name:** Exposed Panel — Adminer
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Adminer — Security

---

### `nuclei-aws-s3-bucket-info-disclosure`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** service_exposure

**Title:** AWS S3 bucket info disclosed at {asset}

**Summary:** S3 bucket names are visible from {asset} — audit those buckets for public-access misconfiguration.

**Description:**

> {asset} discloses S3 bucket names, regions, or ARNs in response bodies, error messages, or HTML source. Knowing your bucket names lets attackers probe for public-access misconfigurations on those specific buckets — the disclosure isn't a breach itself but accelerates the discovery step toward one.

**Remediation:**

> Audit each disclosed bucket for misconfigured public access — enable S3 Block Public Access at the account level and check each bucket's policy. Find the source of the disclosure (often error messages or commented-out HTML) and suppress.

**Tags:** `nuclei`, `info-disclosure`, `aws-s3-bucket-info-disclosure`, `aws`
**Alert name:** Info Disclosure — S3 Info
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- AWS — Blocking public access to your S3 storage

---

### `nuclei-bitbucket-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Bitbucket Server instance exposed at {asset}

**Summary:** An exposed Bitbucket Server instance was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Bitbucket Server (Data Center) instance is reachable on {asset}. Several Bitbucket CVEs in 2022-2023 have been actively exploited (CVE-2022-36804 command injection). Exposed instances also leak source code, build pipelines, and SSH deploy keys.

**Remediation:**

> Move behind auth proxy or VPN. Disable anonymous read. Patch to the current Bitbucket release; Atlassian's Cloud version is unaffected by self-hosted CVE issues.

**Tags:** `nuclei`, `exposed-panel`, `bitbucket-exposed`
**Alert name:** Exposed Panel — Bitbucket
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Atlassian — Bitbucket Server security

---

### `nuclei-cache-deception`

**Severity:** MEDIUM · **CWE:** CWE-525 · **Category:** misconfigurations

**Title:** Web cache deception possible on {asset}

**Summary:** Web cache deception is possible on {asset} — authenticated user data may end up in the public cache.

**Description:**

> {asset} appears vulnerable to web cache deception — appending a static-looking suffix (`.css`, `.png`) to dynamic URLs causes the CDN to cache authenticated responses meant only for the user. Attackers exploit this by tricking authenticated users into requesting `/account.css`, then reading the cached user-specific response anonymously.

**Remediation:**

> Configure the CDN to cache by content-type or by an explicit allow-list of paths, not by URL extension. Set `Cache-Control: no-store, private` on responses to authenticated endpoints. Verify that adding an arbitrary static-looking suffix doesn't hit the cache for authenticated routes.

**Tags:** `nuclei`, `misconfiguration`, `cache-deception`, `cache`, `headers`
**Alert name:** Misconfig — Cache Deception
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- PortSwigger — Web cache deception

---

### `nuclei-confluence-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Atlassian Confluence instance exposed at {asset}

**Summary:** An exposed Atlassian Confluence instance was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Confluence Server / Data Center instance is reachable on {asset}. Confluence has been hit by a string of high-severity CVEs (CVE-2022-26134 OGNL RCE, CVE-2023-22515 broken access control, CVE-2023-22518 improper authorisation) — exposed self-hosted Confluence is consistently among the top attacker targets.

**Remediation:**

> Move Confluence behind your auth proxy / VPN if it's not intentionally public. Patch to the current minor release and check Atlassian's advisory feed monthly. Audit admin accounts and API tokens. Atlassian Cloud is unaffected by the self-hosted CVE chain.

**Tags:** `nuclei`, `exposed-panel`, `confluence-exposed`
**Alert name:** Exposed Panel — Confluence
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Atlassian — Security advisories
- Atlassian — Confluence security recommendations

---

### `nuclei-cors-permissive`

**Severity:** MEDIUM · **CWE:** CWE-942 · **Category:** misconfigurations

**Title:** Permissive CORS configuration on {asset}

**Summary:** CORS on {asset} reflects arbitrary origins — cross-origin reads from untrusted sites may be possible.

**Description:**

> The application reflects an arbitrary origin from the request `Origin` header back into `Access-Control-Allow-Origin`, or accepts overly broad CORS headers. While not as severe as wildcard-with-credentials, this can still allow attacker-origin pages to read responses that should be scoped to specific trusted origins.

**Remediation:**

> Replace dynamic origin reflection with an explicit allow-list of trusted origins. Validate `Origin` against the list rather than echoing it. Don't use suffix matching (`endsWith("example.com")`) — `attackerexample.com` will match. Use exact-match or hostname-based validation.

**Tags:** `nuclei`, `misconfiguration`, `cors-permissive`, `cors`, `headers`
**Alert name:** Misconfig — CORS Permissive
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration

---

### `nuclei-dns-open-resolver`

**Severity:** MEDIUM · **CWE:** CWE-406 · **Category:** misconfigurations

**Title:** DNS open resolver on {asset}

**Summary:** DNS on {asset} answers recursive queries from anywhere — being used for amplification attacks.

**Description:**

> {asset} answers recursive DNS queries from arbitrary internet sources. Open resolvers are abused for DNS amplification attacks — attackers send small spoofed queries that elicit large responses, overwhelming the spoofed victim. Your server's bandwidth is being consumed by attacks against third parties.

**Remediation:**

> Restrict recursion to your customers / internal networks only. In BIND: `allow-recursion { trusted-clients; };`. In Unbound: set `access-control:` for known networks. If the server is intended as an authoritative-only DNS, disable recursion entirely (`recursion no;`). Enable response-rate-limiting (RRL) as defence-in-depth.

**Tags:** `nuclei`, `misconfiguration`, `dns-open-resolver`, `dns`, `amplification`
**Alert name:** Misconfig — Open DNS Resolver
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- DNS-OARC — Open resolver problem

---

### `nuclei-drupal-admin-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Drupal admin login exposed at {asset}

**Summary:** An exposed Drupal admin login was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Drupal admin login page is reachable on {asset}. Drupal has a CVE history that reads like a greatest-hits compilation of unauthenticated RCE (CVE-2014-3704 'Drupalgeddon', CVE-2018-7600 'Drupalgeddon2', CVE-2018-7602). Exposed admin interfaces with unpatched cores are routinely compromised.

**Remediation:**

> Patch Drupal core and contrib modules promptly — Drupal publishes a security advisory feed worth subscribing to. Enforce 2FA for admin accounts. Restrict /user/login by IP where possible.

**Tags:** `nuclei`, `exposed-panel`, `drupal-admin-exposed`
**Alert name:** Exposed Panel — Drupal Admin
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Drupal — Securing your site

---

### `nuclei-exposed-build-artifacts`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** CI/CD build artefacts exposed at {asset}

**Summary:** CI/CD build artefacts are reachable at {asset} — they often include credentials in logs.

**Description:**

> Build artefacts (Jenkins build logs, GitHub Actions workflow runs, GitLab CI artifacts) are publicly readable at {asset}. Build logs frequently leak environment variables, deploy keys, third-party tokens, internal hostnames, and CI runner metadata. Build artefacts can also include test fixtures with seed data.

**Remediation:**

> Restrict CI/CD artefacts to authenticated users only. In Jenkins: configure matrix-based authorisation so artefacts follow per-job permissions. In GitHub Actions: workflow logs visibility is controlled by repo visibility — make the repo private. In GitLab: configure `artifacts:` scope per-job and use `artifacts:expose_as` carefully.

**Tags:** `nuclei`, `info-disclosure`, `exposed-build-artifacts`, `ci-cd`
**Alert name:** Info Disclosure — Build Artefacts
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information

---

### `nuclei-exposed-flink-ui`

**Severity:** MEDIUM · **CWE:** CWE-306 · **Category:** misconfigurations

**Title:** Apache Flink dashboard exposed on {asset}

**Summary:** Apache Flink dashboard on {asset} is reachable without auth — anyone can submit JARs and run code.

**Description:**

> An Apache Flink dashboard is reachable on {asset}. Flink's web UI doesn't ship with auth — anyone reaching it can submit JAR files and execute arbitrary code via the job submission interface. Exposed Flink dashboards have been used for cryptojacking by automated tooling.

**Remediation:**

> Take Flink off the public internet. Place behind a reverse proxy enforcing authentication. Disable JAR upload via `web.submit.enable: false` if the cluster is read-only. Review submitted JARs for unfamiliar jobs.

**Tags:** `nuclei`, `misconfiguration`, `exposed-flink-ui`, `streaming`, `rce-risk`
**Alert name:** Misconfig — Flink
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Apache Flink — Security

---

### `nuclei-exposed-mqtt`

**Severity:** MEDIUM · **CWE:** CWE-306 · **Category:** misconfigurations

**Title:** MQTT broker exposed without authentication on {asset}

**Summary:** An MQTT broker on {asset} accepts unauthenticated connections — IoT data and commands are exposed.

**Description:**

> An MQTT broker on {asset} accepts connections without authentication. MQTT is the dominant protocol for IoT device telemetry; exposed brokers leak sensor data, device identity, and command topics — and authenticated-but-anonymous-allowed brokers let attackers inject commands that devices act on.

**Remediation:**

> Enable authentication in the broker config (Mosquitto: `allow_anonymous false` + `password_file`). Use TLS for the MQTT port (8883 instead of 1883). Restrict broker access to internal networks where possible.

**Tags:** `nuclei`, `misconfiguration`, `exposed-mqtt`, `mqtt`, `iot`
**Alert name:** Misconfig — MQTT
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Mosquitto — Security

---

### `nuclei-exposed-spring-eureka`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** misconfigurations

**Title:** Spring Eureka service registry exposed on {asset}

**Summary:** A Spring Eureka registry is reachable on {asset} — your full microservice topology is visible.

**Description:**

> A Spring Eureka service registry is reachable on {asset}. Eureka stores the names, hostnames, and ports of every microservice in the deployment — exactly the internal-topology map an attacker wants for lateral movement and targeted SSRF. Eureka also accepts service registrations, letting an attacker register their own host and intercept client traffic.

**Remediation:**

> Restrict Eureka to internal networks. Enable basic auth via Spring Security on the Eureka server. Disable anonymous service registration if not needed.

**Tags:** `nuclei`, `misconfiguration`, `exposed-spring-eureka`, `spring`, `java`, `info-disclosure`
**Alert name:** Misconfig — Spring Eureka
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- Spring Cloud Netflix — Eureka

---

### `nuclei-firebase-database-info-exposure`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** service_exposure

**Title:** Firebase database info disclosed at {asset}

**Summary:** Firebase project metadata is disclosed at {asset} — verify the database's security rules are tight.

**Description:**

> Firebase project metadata — database URL, project ID, API key — was disclosed at {asset}. While Firebase API keys and database URLs are designed to be client-visible, their disclosure combined with overly-permissive security rules is the chain that leads to data exposure (see `firebase-realtime-db-public`).

**Remediation:**

> Confirm Firebase security rules are tight (see the Realtime DB or Firestore rules documentation). The config disclosure itself is fine if rules are correct; the rules are the actual security boundary.

**Tags:** `nuclei`, `info-disclosure`, `firebase-database-info-exposure`, `firebase`, `gcp`
**Alert name:** Info Disclosure — Firebase Info
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- Firebase — Understand Firebase Security Rules

---

### `nuclei-gitea-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Gitea instance exposed at {asset}

**Summary:** An exposed Gitea instance was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Gitea instance is reachable on {asset}. Gitea is a lightweight self-hosted Git server; exposed instances see credential-spray and have had several auth-bypass and RCE CVEs over the years. Source code, deploy keys, and webhooks are typical exposure surface.

**Remediation:**

> Restrict to internal network or require SSO via external IdP. Disable signup. Patch to the current Gitea release. Audit user accounts and admin privileges.

**Tags:** `nuclei`, `exposed-panel`, `gitea-exposed`
**Alert name:** Exposed Panel — Gitea
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Gitea — Security Tips

---

### `nuclei-gitlab-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** GitLab login page exposed at {asset}

**Summary:** An exposed GitLab login page was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A GitLab instance is reachable on {asset}. Self-hosted GitLab in particular is a frequent target — recent high-severity CVEs (CVE-2023-7028 account takeover, CVE-2024-0402 path traversal) make exposed instances high-value. GitLab also stores CI/CD secrets, signing keys, and source code, so account compromise has supply-chain blast radius.

**Remediation:**

> If GitLab is intentionally public (typical for open-source communities), keep it patched on the current minor release and enforce 2FA on all accounts. If it shouldn't be public, move it behind a VPN or zero-trust gateway. Disable signup if not needed; review admin accounts for unfamiliar additions.

**Tags:** `nuclei`, `exposed-panel`, `gitlab-exposed`
**Alert name:** Exposed Panel — GitLab
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- GitLab — Hardening recommendations

---

### `nuclei-google-api-key-disclosure`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** data_leaks

**Title:** Google API key disclosed at {asset}

**Summary:** A Google API key is visible at {asset} — verify whether it's an intentionally-public client-side key or a leaked server-side one.

**Description:**

> A Google API key (AIza-prefixed) was found in a response from {asset}. Many Google API keys are intentionally client-side (Maps JavaScript, YouTube embed) and restricted to specific HTTP referrers — those are designed to be public. Unrestricted server-side keys leaked the same way are a credential breach.

**Remediation:**

> Confirm the key's intended scope. In Google Cloud Console → APIs & Services → Credentials, check whether the key has application restrictions (HTTP referrers, IP addresses) and API restrictions. If it's an unrestricted server-side key, rotate it immediately and constrain the new key to specific APIs and referrer/IP ranges. Audit the GCP project's API usage logs for unfamiliar callers.

**Tags:** `nuclei`, `info-disclosure`, `google-api-key-disclosure`, `gcp`, `credentials`
**Alert name:** Info Disclosure — Google API Key
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- Google Cloud — Best practices for securely using API keys

---

### `nuclei-grafana-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Grafana login page exposed at {asset}

**Summary:** An exposed Grafana login page was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Grafana login page is reachable on {asset}. Default credentials (admin/admin) are still found on internet-facing Grafana instances regularly; once authenticated, an attacker with admin rights can execute arbitrary code via plugin uploads or the data-source SQL editor on certain backends. CVE-2021-43798 (path traversal) made anonymous data-source queries possible on older versions.

**Remediation:**

> If Grafana is intentionally public (some SaaS products embed it), enforce SSO and disable the local admin account after creating an SSO-bound admin. Otherwise, move behind your auth proxy or VPN. Confirm `admin/admin` doesn't work; reset if it does. Patch to current.

**Tags:** `nuclei`, `exposed-panel`, `grafana-exposed`
**Alert name:** Exposed Panel — Grafana
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Grafana — Hardening Recommendations

---

### `nuclei-graphql-batching`

**Severity:** MEDIUM · **CWE:** CWE-770 · **Category:** misconfigurations

**Title:** GraphQL batching attacks possible on {asset}

**Summary:** GraphQL on {asset} accepts batched queries — rate limits can be bypassed by stacking many queries per request.

**Description:**

> The GraphQL endpoint on {asset} accepts arrays of queries in a single request (query batching) without rate limiting the array size or per-query cost. Attackers exploit this to bypass per-request rate limits — sending hundreds of login attempts or expensive mutations in a single HTTP request, none of which trip per-request throttles.

**Remediation:**

> Implement query-cost analysis (e.g., `graphql-cost-analysis` for Apollo, `graphql-validation-complexity`) and reject requests that exceed a complexity budget. Cap the batch size to a small number (e.g., 10) at the GraphQL server. Apply rate limits to each query in the batch, not the request as a whole.

**Tags:** `nuclei`, `misconfiguration`, `graphql-batching`, `graphql`, `rate-limiting`
**Alert name:** Misconfig — GraphQL Batching
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration

---

### `nuclei-graphql-introspection-enabled`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** misconfigurations

**Title:** GraphQL introspection enabled on {asset}

**Summary:** GraphQL on {asset} returns its full schema to anyone — disable introspection in production.

**Description:**

> The GraphQL endpoint on {asset} responds to introspection queries. Introspection returns the full schema — every type, field, mutation, and argument — which removes the primary obstacle to API enumeration. Public APIs sometimes leave introspection enabled deliberately, but for internal or partner-only APIs it's a reconnaissance gift.

**Remediation:**

> Disable introspection in production:
>   • Apollo Server: set `introspection: false` in the `ApolloServer` config.
>   • express-graphql / GraphQL.js: disable via the `introspection` option or wrap with a query-validation plugin that rejects `__schema` / `__type` queries.
>   • Hasura: disable in console settings → API.
> If you need introspection for tooling (codegen, IDE), gate it behind an authenticated admin role.

**Tags:** `nuclei`, `misconfiguration`, `graphql-introspection-enabled`, `graphql`, `info-disclosure`
**Alert name:** Misconfig — GraphQL Introspection
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- OWASP — GraphQL Cheat Sheet

---

### `nuclei-graphql-playground-exposed`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** misconfigurations

**Title:** GraphQL Playground / GraphiQL exposed on {asset}

**Summary:** A GraphQL playground UI is reachable on {asset} — it shouldn't be in production.

**Description:**

> An interactive GraphQL UI (GraphQL Playground, GraphiQL, Apollo Studio, Altair) is reachable on {asset}. These tools are intended for development and combine introspection with an interactive query builder — anyone who reaches the URL can map your API and run authenticated queries if they have any credentials.

**Remediation:**

> Disable the playground/IDE in production:
>   • Apollo Server v3+: set `playground: false`.
>   • Apollo Server v4+: the landing page is configured via `plugins`; use `ApolloServerPluginLandingPageDisabled()`.
>   • GraphiQL: usually exposed via a separate route — remove it from production builds.
> If a UI is genuinely useful, gate it behind authentication on a non-production hostname only.

**Tags:** `nuclei`, `misconfiguration`, `graphql-playground-exposed`, `graphql`
**Alert name:** Misconfig — GraphQL Playground
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- OWASP — GraphQL Cheat Sheet

---

### `nuclei-harbor-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Harbor UI exposed at {asset}

**Summary:** An exposed Harbor UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Harbor (container registry) UI is reachable on {asset}. Harbor has had several authentication and RBAC CVEs (CVE-2019-19026 SQLi, CVE-2022-31671 broken access control). Even when properly configured, exposed login pages see credential-spray.

**Remediation:**

> Restrict Harbor to internal networks where possible. Enforce SSO and disable local admin signup. Patch to current Harbor release.

**Tags:** `nuclei`, `exposed-panel`, `harbor-exposed`
**Alert name:** Exposed Panel — Harbor
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Harbor — Configure Harbor

---

### `nuclei-jenkins-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Jenkins login page exposed at {asset}

**Summary:** An exposed Jenkins login page was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Jenkins instance is reachable on {asset}. Jenkins itself is one of the most-attacked CI/CD targets — exposed instances see continuous credential-spray (admin/admin, jenkins/jenkins, etc.) and are a common entry point into supply-chain compromise. Authenticated users on Jenkins can execute Groovy on the controller via the script console, so any account compromise is effectively code-execution.

**Remediation:**

> Decide whether Jenkins should be internet-facing. If not, restrict to your VPN or internal network. If it must be public:
>   • Disable signup; require SSO with an external IdP.
>   • Enable matrix-based authorisation; lock anonymous reads.
>   • Disable the script console for non-admin roles.
>   • Audit user list — remove `admin/admin` or any default credentials.
>   • Run Jenkins with up-to-date plugins; many CVEs are plugin-side.

**Tags:** `nuclei`, `exposed-panel`, `jenkins-exposed`
**Alert name:** Exposed Panel — Jenkins
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Jenkins — Securing Jenkins

---

### `nuclei-jira-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Atlassian Jira instance exposed at {asset}

**Summary:** An exposed Atlassian Jira instance was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Jira Server / Data Center instance is reachable on {asset}. Like Confluence, self-hosted Jira has had multiple high-severity CVEs and is a routine target for ransomware and APT actors. Issue trackers also leak organisational information (project structure, internal hostnames in tickets, employee identities).

**Remediation:**

> Move Jira behind a VPN or auth proxy if it's not intended to be public. Disable signup; require SSO. Patch to the current minor release. Audit project permissions for unintended public-read settings.

**Tags:** `nuclei`, `exposed-panel`, `jira-exposed`
**Alert name:** Exposed Panel — Jira
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Atlassian — Jira security recommendations

---

### `nuclei-joomla-admin-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Joomla administrator panel exposed at {asset}

**Summary:** An exposed Joomla administrator panel was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Joomla administrator panel is reachable on {asset}. Joomla has had multiple high-severity CVEs (CVE-2023-23752 auth bypass, CVE-2015-8562 RCE). Exposed admin paths (`/administrator/`) see continuous credential-spray.

**Remediation:**

> Patch Joomla core and extensions. Restrict /administrator/ by IP if possible; otherwise enforce 2FA on admin accounts. Audit installed extensions for unfamiliar additions.

**Tags:** `nuclei`, `exposed-panel`, `joomla-admin-exposed`
**Alert name:** Exposed Panel — Joomla Admin
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Joomla — Security checklist

---

### `nuclei-jwt-weak-secret`

**Severity:** MEDIUM · **CWE:** CWE-326 · **Category:** vulnerabilities

**Title:** JWT signed with weak secret on {asset}

**Summary:** JWT secret on {asset} is brute-forceable — anyone with the secret can forge tokens. Rotate now.

**Description:**

> Nuclei brute-forced the HMAC secret used to sign JWTs on {asset} from a common-passwords or default-secret list. With the secret known, attackers forge tokens for any user / role and the server accepts them. Common cause: a secret like `secret`, `your-256-bit-secret`, or the name of a framework that's hardcoded in tutorials.

**Remediation:**

> Generate a cryptographically-random secret of at least 32 bytes (256 bits) and set it via your application's environment / secret store. Migrate to RS256 or ES256 (asymmetric) where possible — the public key validates, the private key signs, and the validating servers don't need the signing material. Invalidate all existing JWTs after rotating the secret (force user re-auth).

**Tags:** `nuclei`, `info-disclosure`, `jwt-weak-secret`, `jwt`
**Alert name:** Info Disclosure — JWT Weak Secret
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- OWASP — JSON Web Token Cheat Sheet

---

### `nuclei-kafka-ui-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Kafka management UI exposed at {asset}

**Summary:** An exposed Kafka management UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Kafka management UI (Kafka UI / Kafdrop / Conduktor) is reachable on {asset}. These tools often have minimal or no auth out of the box; exposed instances let visitors inspect every topic and message — a frequent source of unintended PII / credential exposure.

**Remediation:**

> Restrict Kafka management UIs to internal networks. Enforce auth at the proxy layer if web access is needed. Audit topic contents for sensitive data that shouldn't be viewable in real-time.

**Tags:** `nuclei`, `exposed-panel`, `kafka-ui-exposed`
**Alert name:** Exposed Panel — Kafka UI
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration

---

### `nuclei-kibana-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Kibana instance exposed at {asset}

**Summary:** An exposed Kibana instance was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Kibana instance is reachable on {asset}. Kibana exposes search and dashboarding over an Elasticsearch cluster — if the underlying ES cluster has no authentication (common on older OSS deployments), Kibana effectively grants anonymous read of every index. Several Kibana CVEs (CVE-2019-7609 RCE) have also been exploited.

**Remediation:**

> Enable Elastic security features (free since 7.x); require auth on Kibana itself. If older Elasticsearch open-source version, front Kibana with a reverse proxy enforcing authentication. Patch to current Elastic Stack release.

**Tags:** `nuclei`, `exposed-panel`, `kibana-exposed`
**Alert name:** Exposed Panel — Kibana
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Elastic — Kibana security

---

### `nuclei-magento-admin-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Magento admin panel exposed at {asset}

**Summary:** An exposed Magento admin panel was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Magento admin panel is reachable on {asset}. Magento (now Adobe Commerce) has had multiple unauthenticated RCE CVEs and is heavily targeted by skimmer/Magecart actors. Default admin URLs (`/admin`, `/admin/index/index`) are frequently left unchanged.

**Remediation:**

> Customise the admin URL via `frontName` config; this isn't a security control on its own but reduces background scanning noise. Enforce 2FA (built into Magento 2.4+). Patch to current; subscribe to Adobe's security advisory feed.

**Tags:** `nuclei`, `exposed-panel`, `magento-admin-exposed`
**Alert name:** Exposed Panel — Magento Admin
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Adobe Commerce — Security

---

### `nuclei-nexus-repository-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Sonatype Nexus repository manager exposed at {asset}

**Summary:** An exposed Sonatype Nexus repository manager was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Sonatype Nexus Repository Manager UI is reachable on {asset}. Nexus has had multiple RCE CVEs (CVE-2024-4956 path traversal, CVE-2020-10199 deserialisation). Nexus stores build artefacts and proxy-cached dependencies, so compromise has supply-chain implications.

**Remediation:**

> Restrict to internal networks. Disable the default `admin` account or rotate its password. Patch to current Nexus release.

**Tags:** `nuclei`, `exposed-panel`, `nexus-repository-exposed`
**Alert name:** Exposed Panel — Nexus
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Sonatype — Nexus Security

---

### `nuclei-ntp-monlist`

**Severity:** MEDIUM · **CWE:** CWE-406 · **Category:** misconfigurations

**Title:** NTP monlist enabled on {asset}

**Summary:** NTP on {asset} responds to monlist — being used for DDoS amplification.

**Description:**

> The NTP server on {asset} responds to the deprecated `monlist` command (mode 7). monlist returns up to 600 of the most recent NTP clients with each query — a ~200x amplification factor that's weaponised for DDoS. Has been a major DDoS-amplification vector since 2014.

**Remediation:**

> Upgrade ntpd to 4.2.7p26 or later (2010+). On older ntpd, disable monlist explicitly: add `disable monitor` to ntp.conf. Even better: switch to chrony (the modern default on most Linux distributions) which doesn't implement monlist at all. Confirm `ntpdc -c monlist <host>` returns no data after the fix.

**Tags:** `nuclei`, `misconfiguration`, `ntp-monlist`, `ntp`, `amplification`
**Alert name:** Misconfig — NTP monlist
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- US-CERT — NTP Amplification Attacks Using CVE-2013-5211

---

### `nuclei-open-redirect`

**Severity:** MEDIUM · **CWE:** CWE-601 · **Category:** misconfigurations

**Title:** Open redirect on {asset}

**Summary:** An open redirect on {asset} lets attackers craft phishing links that appear to point at your domain.

**Description:**

> An endpoint on {asset} redirects to user-controlled URLs without validation. Attackers use open redirects to make phishing links look legitimate (`https://yourdomain.com/redirect?to=evil.com`) — the URL appears to point at your trusted domain but bounces to attacker content. Frequently abused in OAuth phishing and credential-stuffing campaigns.

**Remediation:**

> Validate redirect targets against an allow-list of trusted destinations. For internal redirects, only accept relative paths or explicit known hostnames — never reflect arbitrary URLs. If user-controlled redirects are essential (e.g., signed return-URL in OAuth), require a cryptographic signature on the destination parameter.

**Tags:** `nuclei`, `misconfiguration`, `open-redirect`, `redirect`, `phishing`
**Alert name:** Misconfig — Open Redirect
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- OWASP — Unvalidated Redirects and Forwards Cheat Sheet

---

### `nuclei-phpmyadmin-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** phpMyAdmin login page exposed at {asset}

**Summary:** An exposed phpMyAdmin login page was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A phpMyAdmin instance is reachable on {asset}. phpMyAdmin is a widely-deployed MySQL admin UI; exposed instances see continuous credential-spray. Multiple CVEs over the years (CVE-2018-12613 LFI, CVE-2020-26935 SQLi). Once authenticated, an attacker has full database access.

**Remediation:**

> Don't expose phpMyAdmin to the public internet — front it with an auth proxy or restrict to internal networks. Use strong DB credentials; never default. Patch phpMyAdmin to current.

**Tags:** `nuclei`, `exposed-panel`, `phpmyadmin-exposed`
**Alert name:** Exposed Panel — phpMyAdmin
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- phpMyAdmin — Security

---

### `nuclei-pihole-default-credentials`

**Severity:** MEDIUM · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Pi-hole default credentials accepted at {asset}

**Summary:** Default credentials work on the Pi-hole instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Pi-hole instance on {asset} accepts known default credentials (`admin/admin`, `admin/pihole`). Pi-hole admin access lets attackers add DNS-rewrite rules (redirecting bank.com → attacker IP for every device using this Pi-hole as resolver) and modify the blocklist to allow ad-tracking and malware domains. Lower severity than RCE-capable products but a foothold for downstream attacks on every device behind the resolver.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Pi-hole audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `pihole-default-credentials`
**Alert name:** Default Creds — Pi-hole
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource
- Pi-hole — Documentation

---

### `nuclei-printer-default-login`

**Severity:** MEDIUM · **CWE:** CWE-1188 · **Category:** misconfigurations

**Title:** Printer default credentials accepted at {asset}

**Summary:** Default credentials work on the Printer instance at {asset} — rotate immediately and audit recent activity.

**Description:**

> Nuclei confirmed that the Printer instance on {asset} accepts known default credentials (`admin/admin`, `admin/`, `admin/password`). Printer admin access exposes print job logs (containing document content), address books, and Wi-Fi credentials. Some printers also accept arbitrary firmware uploads — a vector for persistent network compromise.

**Remediation:**

> **Rotate the credentials immediately**
>   Reset the default account's password to a strong, unique value. If multiple accounts may share the default, force a reset across all admin accounts.
>
> **Audit recent activity**
>   Review the Printer audit log / sign-in log for unfamiliar sessions, configuration changes, and admin actions since the system was first reachable. Treat any default-credential session as potentially attacker activity until proven otherwise.
>
> **Restrict reachability**
>   If the panel doesn't need to be public, move it behind a VPN or auth proxy. Default-creds findings on internal-only surfaces are easier to triage and limit blast radius.

**Tags:** `nuclei`, `default-credentials`, `printer-default-login`, `iot`, `printer`
**Alert name:** Default Creds — Printer
**Monitor type:** `config_change`

**References:**
- OWASP A07 — Identification and Authentication Failures
- CWE-1188: Insecure Default Initialization of Resource

---

### `nuclei-prometheus-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** Prometheus metrics endpoint exposed at {asset}

**Summary:** An exposed Prometheus metrics endpoint was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A Prometheus instance is reachable on {asset}. Prometheus doesn't ship with auth — by default any reachable instance lets visitors query every metric, often revealing internal service topology, HTTP path patterns, error rates by endpoint, and historical traffic data. Sometimes leaks credentials embedded in service metadata or label values.

**Remediation:**

> Front Prometheus with a reverse proxy enforcing auth (nginx + basic auth, or an OAuth proxy like oauth2-proxy). For managed deployments, restrict at the network layer to your scraper/visualisation tier. Don't expose the federation endpoint without auth.

**Tags:** `nuclei`, `exposed-panel`, `prometheus-exposed`
**Alert name:** Exposed Panel — Prometheus
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- Prometheus — Securing Prometheus API

---

### `nuclei-rabbitmq-management-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** RabbitMQ management UI exposed at {asset}

**Summary:** An exposed RabbitMQ management UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A RabbitMQ management UI is reachable on {asset}. RabbitMQ ships with a default `guest/guest` account that's restricted to localhost — but exposed instances often have it explicitly enabled. Authenticated management users can read every queue's contents.

**Remediation:**

> Disable the `guest` account or restrict to localhost (the default). Move the management UI off the public internet. Patch to current RabbitMQ release.

**Tags:** `nuclei`, `exposed-panel`, `rabbitmq-management-exposed`
**Alert name:** Exposed Panel — RabbitMQ
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- RabbitMQ — Access Control

---

### `nuclei-session-token-in-url`

**Severity:** MEDIUM · **CWE:** CWE-598 · **Category:** service_exposure

**Title:** Session token transmitted in URL on {asset}

**Summary:** Session tokens travel in URL parameters on {asset} — they leak to third parties via Referer and logs.

**Description:**

> {asset} transmits session identifiers in URL query parameters (e.g., `?sessionid=...`, `?token=...`) instead of in cookies or Authorization headers. URL parameters leak via the Referer header to third-party sites, are logged in web-server access logs and CDN logs, and end up in browser history.

**Remediation:**

> Move session tokens into HttpOnly cookies (for browser-based apps) or into the Authorization header (for API calls). For backwards-compatibility with old links that still carry tokens in URLs, accept them but issue a fresh token via cookie on first use and reject the URL parameter on subsequent requests. Sanitise web-server logs that may have captured the tokens.

**Tags:** `nuclei`, `info-disclosure`, `session-token-in-url`, `session`, `auth`
**Alert name:** Info Disclosure — Token in URL
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- OWASP — Session Management Cheat Sheet

---

### `nuclei-sonarqube-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** SonarQube instance exposed at {asset}

**Summary:** An exposed SonarQube instance was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A SonarQube instance is reachable on {asset}. SonarQube stores code-quality and security analysis results — exposed instances may leak source code excerpts, vulnerability findings, and historical secret-scanner results. Default credentials (`admin/admin`) are still seen on internet-facing instances.

**Remediation:**

> Restrict SonarQube to internal networks. Replace default admin credentials. Enforce SSO. Patch to current SonarQube LTS release.

**Tags:** `nuclei`, `exposed-panel`, `sonarqube-exposed`
**Alert name:** Exposed Panel — SonarQube
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- SonarQube — Security recommendations

---

### `nuclei-uncategorized`

**Severity:** MEDIUM · **CWE:** — · **Category:** vulnerabilities

**Title:** Nuclei finding: {value} on {asset}

**Summary:** Nuclei matched a template on {asset} — see references and evidence for details.

**Description:**

> Nuclei's template-based scanner matched a finding on {asset}. Template details and severity come from the upstream Nuclei template metadata. We don't yet ship a curated explanation for this specific template ID — the evidence section captures the matched URL, extracted values, and any CVE/CWE/CVSS classification Nuclei provided. Use those to evaluate impact, then patch or configure the affected service per the upstream Nuclei references below.

**Remediation:**

> Open the Nuclei references attached to this finding for the upstream template's recommended remediation. If a CVE is named in the evidence, look it up at https://nvd.nist.gov for vendor-fixed versions and apply patches. If this is a configuration finding, identify the responsible service and apply the relevant hardening documentation from the vendor. When in doubt, reach out — Nano EASM support can help interpret the finding.

**Tags:** `nuclei`, `uncategorized`
**Alert name:** Nuclei Finding
**Monitor type:** `vuln_change`

**References:**
- ProjectDiscovery — Nuclei
- NIST National Vulnerability Database (NVD)

---

### `nuclei-vault-ui-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** HashiCorp Vault UI exposed at {asset}

**Summary:** An exposed HashiCorp Vault UI was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A HashiCorp Vault UI is reachable on {asset}. Vault itself is designed for internet exposure (auth required), but exposed instances see credential-spray and historic CVEs (CVE-2020-16250 GCP auth bypass) make patching cadence important. Sensitive operational metadata (auth method list, mount paths) is visible without auth.

**Remediation:**

> Vault is typically internet-facing by design — keep it current with the latest release, enforce strong auth methods, audit Sentinel policies, and watch the audit log. If Vault is internal-only, restrict at the network layer.

**Tags:** `nuclei`, `exposed-panel`, `vault-ui-exposed`
**Alert name:** Exposed Panel — Vault
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- HashiCorp — Vault Production Hardening

---

### `nuclei-wordpress-admin-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** WordPress admin login (wp-admin) exposed at {asset}

**Summary:** An exposed WordPress admin login (wp-admin) was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> A WordPress wp-login.php / wp-admin page is reachable on {asset}. WordPress login pages are the single most-bruteforced authentication surface on the internet — exposed instances see continuous credential-spray, especially against `admin`, `administrator`, and the publicly-discoverable username from `/?author=1`.

**Remediation:**

> Hide the user-enumeration endpoint by disabling the REST API user list or rewriting `?author=` URLs. Enforce 2FA on every admin account (Wordfence, Two Factor Authentication, miniOrange plugins). Rate-limit wp-login.php at the WAF or via a plugin. Patch core, themes, and plugins on a regular cadence — most WordPress compromise comes through plugin CVEs.

**Tags:** `nuclei`, `exposed-panel`, `wordpress-admin-exposed`
**Alert name:** Exposed Panel — WordPress Admin
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- WordPress — Hardening

---

### `nuclei-zookeeper-admin-exposed`

**Severity:** MEDIUM · **CWE:** CWE-284 · **Category:** service_exposure

**Title:** ZooKeeper admin server exposed at {asset}

**Summary:** An exposed ZooKeeper admin server was detected on {asset} — verify it's intentionally public and properly secured.

**Description:**

> An Apache ZooKeeper admin server (4-letter words) is reachable on {asset}. The admin endpoint reveals cluster state, client connections (with source IPs), and configuration — useful reconnaissance even when no direct compromise vector exists.

**Remediation:**

> Restrict ZooKeeper to internal networks. Disable 4-letter words you don't need (`4lw.commands.whitelist=stat,ruok` for minimum). Configure SASL / Kerberos auth where the deployment supports it.

**Tags:** `nuclei`, `exposed-panel`, `zookeeper-admin-exposed`
**Alert name:** Exposed Panel — ZooKeeper
**Monitor type:** `panel_change`

**References:**
- OWASP — Security Misconfiguration
- ZooKeeper — Administrator's Guide

---

### `nuclei-apache-version-disclosure`

**Severity:** LOW · **CWE:** CWE-200 · **Category:** service_exposure

**Title:** Apache HTTP Server version disclosed by {asset}

**Summary:** Apache on {asset} reveals its exact version — set ServerTokens Prod for hardening.

**Description:**

> {asset} reveals the exact Apache HTTP Server version in the `Server` header or in default error pages. Apache CVEs are routinely published; the version reveal makes it trivial for an attacker to check if the server is exploitable.

**Remediation:**

> Set `ServerTokens Prod` and `ServerSignature Off` in your main Apache configuration. Replace the default error pages with custom ones. Confirm with `curl -I` that the Server header is just `Server: Apache` rather than including the version.

**Tags:** `nuclei`, `info-disclosure`, `apache-version-disclosure`, `apache`, `version-disclosure`
**Alert name:** Info Disclosure — Apache Version
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information

---

### `nuclei-csrf-token-disclosure`

**Severity:** LOW · **CWE:** CWE-598 · **Category:** service_exposure

**Title:** CSRF token in URL/log on {asset}

**Summary:** CSRF tokens travel in URLs on {asset} — they leak via Referer.

**Description:**

> {asset} transmits a CSRF token via a URL parameter rather than in a header or hidden form field. CSRF tokens in URLs leak via Referer headers and access logs — defeating the token's purpose for cross-site requests originated from the same browser session.

**Remediation:**

> Move CSRF tokens into hidden form fields (synchroniser token pattern) or into custom request headers (e.g., `X-CSRF-Token`). Most modern frameworks handle this automatically — the URL-based variant is usually a leftover from a manual implementation.

**Tags:** `nuclei`, `info-disclosure`, `csrf-token-disclosure`, `csrf`
**Alert name:** Info Disclosure — CSRF in URL
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information
- OWASP — Cross-Site Request Forgery Prevention Cheat Sheet

---

### `nuclei-drupal-version-disclosure`

**Severity:** LOW · **CWE:** CWE-200 · **Category:** service_exposure

**Title:** Drupal version disclosed by {asset}

**Summary:** Drupal version on {asset} is publicly visible — strip the meta tag and block CHANGELOG-style files.

**Description:**

> {asset} reveals the Drupal version via meta tags, CHANGELOG.txt, or default file paths. Drupal's CVE history (Drupalgeddon, Drupalgeddon2) makes version disclosure a high-value recon step for attackers targeting older installs.

**Remediation:**

> Remove the generator meta tag via a custom theme's preprocess hook. Block public access to CHANGELOG.txt, INSTALL.txt, README.txt, and the `core/CHANGELOG.txt` files at the web server. Patch Drupal core and contrib modules promptly.

**Tags:** `nuclei`, `info-disclosure`, `drupal-version-disclosure`, `drupal`, `version-disclosure`
**Alert name:** Info Disclosure — Drupal Version
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information

---

### `nuclei-http-trace-enabled`

**Severity:** LOW · **CWE:** CWE-693 · **Category:** misconfigurations

**Title:** HTTP TRACE method enabled on {asset}

**Summary:** HTTP TRACE method is enabled on {asset} — disable it as part of your web-server hardening baseline.

**Description:**

> The HTTP TRACE method is enabled on {asset}. TRACE was historically abusable for Cross-Site Tracing (XST) attacks to steal HttpOnly cookies via Flash or older browser quirks. Modern browsers block this; the residual concern today is as a reconnaissance signal — TRACE shouldn't be enabled on a hardened web server.

**Remediation:**

> Disable TRACE at the web server:
>   • Apache: `TraceEnable Off`
>   • nginx: TRACE is not implemented by default; check any custom modules that may have re-enabled it.
>   • IIS: disable via Request Filtering rules.
>   • Behind a CDN: most CDNs allow restricting accepted methods to GET / POST / HEAD only.

**Tags:** `nuclei`, `misconfiguration`, `http-trace-enabled`, `http`
**Alert name:** Misconfig — TRACE Enabled
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration

---

### `nuclei-iis-version-disclosure`

**Severity:** LOW · **CWE:** CWE-200 · **Category:** service_exposure

**Title:** IIS version disclosed by {asset}

**Summary:** IIS on {asset} reveals its version — remove the Server and X-Powered-By headers.

**Description:**

> {asset} reveals the IIS version via the `Server` or `X-Powered-By` headers. Information disclosure that helps attackers correlate the server with known CVEs.

**Remediation:**

> Remove the Server header in IIS by editing applicationHost.config (set `removeServerHeader="true"` under `<system.webServer><security><requestFiltering>`) or via URL Rewrite outbound rules. Remove `X-Powered-By: ASP.NET` via web.config:
> ```xml
> <httpProtocol><customHeaders><remove name="X-Powered-By"/></customHeaders></httpProtocol>
> ```

**Tags:** `nuclei`, `info-disclosure`, `iis-version-disclosure`, `iis`, `version-disclosure`
**Alert name:** Info Disclosure — IIS Version
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information

---

### `nuclei-internal-ip-disclosure`

**Severity:** LOW · **CWE:** CWE-200 · **Category:** service_exposure

**Title:** Internal IP address disclosed by {asset}

**Summary:** Internal IP addresses are visible from {asset} — strip them from responses.

**Description:**

> {asset} discloses an internal/private IP address (RFC 1918, RFC 6598, or link-local) in HTTP responses, headers, or error messages. Internal IPs leak network topology — subnet sizes, addressing scheme — that helps attackers plan post-exploitation lateral movement.

**Remediation:**

> Find the source of the leak. Common culprits are debug log endpoints, error pages with stack traces, `X-Forwarded-For` reflection, and CORS preflight responses that include internal hostnames. Strip internal IPs from HTTP responses at the application or proxy layer; replace them with anonymised placeholders for legitimate diagnostic use.

**Tags:** `nuclei`, `info-disclosure`, `internal-ip-disclosure`, `info-disclosure`
**Alert name:** Info Disclosure — Internal IP
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information

---

### `nuclei-joomla-version-disclosure`

**Severity:** LOW · **CWE:** CWE-200 · **Category:** service_exposure

**Title:** Joomla version disclosed by {asset}

**Summary:** Joomla version on {asset} is publicly visible — strip the generator tag.

**Description:**

> {asset} reveals the Joomla version via meta tags, default manifest files (`administrator/manifests/files/joomla.xml`), or generator strings.

**Remediation:**

> Strip the generator meta tag and block public access to manifest files at the web server. Patch Joomla core promptly — Joomla CVEs (CVE-2023-23752, CVE-2015-8562) are routinely exploited.

**Tags:** `nuclei`, `info-disclosure`, `joomla-version-disclosure`, `joomla`, `version-disclosure`
**Alert name:** Info Disclosure — Joomla Version
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information

---

### `nuclei-mixed-content`

**Severity:** LOW · **CWE:** CWE-319 · **Category:** misconfigurations

**Title:** Mixed content (HTTPS page loads HTTP resources) on {asset}

**Summary:** An HTTPS page on {asset} loads HTTP resources — a network attacker can inject content into the page.

**Description:**

> An HTTPS page on {asset} loads scripts, stylesheets, images, or iframes over plain HTTP. Modern browsers block active mixed content (scripts, frames) and warn on passive (images, video). Even passive mixed content gives a network-positioned attacker a vector to inject malicious responses, and the browser address bar removes the secure padlock — undermining the trust signal you're paying for with TLS.

**Remediation:**

> Replace `http://` references with `https://` (or protocol-relative `//` URLs that inherit the page's scheme). Add a `Content-Security-Policy: upgrade-insecure-requests` header to silently upgrade mixed content during transition. Test with the browser developer console which will report every mixed-content load.

**Tags:** `nuclei`, `misconfiguration`, `mixed-content`, `mixed-content`, `tls`
**Alert name:** Misconfig — Mixed Content
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration
- MDN — Mixed content

---

### `nuclei-nginx-version-disclosure`

**Severity:** LOW · **CWE:** CWE-200 · **Category:** service_exposure

**Title:** nginx version disclosed by {asset}

**Summary:** nginx on {asset} reveals its exact version — disable server_tokens for hardening.

**Description:**

> {asset} reveals the exact nginx version in the `Server` header or in default error pages. The information itself isn't directly exploitable, but it shortens an attacker's reconnaissance step — they can immediately match the version against published nginx CVEs.

**Remediation:**

> Suppress the version in the Server header by adding `server_tokens off;` to your nginx configuration (http{} block). Use a custom error page so the default page that exposes the version doesn't appear. Removing the version isn't a substitute for keeping nginx patched.

**Tags:** `nuclei`, `info-disclosure`, `nginx-version-disclosure`, `nginx`, `version-disclosure`
**Alert name:** Info Disclosure — nginx Version
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information

---

### `nuclei-path-disclosure`

**Severity:** LOW · **CWE:** CWE-209 · **Category:** service_exposure

**Title:** Server file system path disclosed by {asset}

**Summary:** File system paths leak in errors from {asset} — disable debug mode in production.

**Description:**

> {asset} discloses absolute file system paths (`/var/www/html/...`, `C:\inetpub\wwwroot\...`) in error messages, stack traces, or response bodies. Path disclosure helps attackers chain into LFI/RFI exploits — they no longer need to guess the server's directory layout.

**Remediation:**

> Configure the application framework to return generic error messages in production and log full stack traces server-side instead. Most frameworks have a single production-mode toggle that handles this (Django `DEBUG=False`, ASP.NET `customErrors mode="On"`, Express `NODE_ENV=production`). Audit existing logs for paths that may have already been exposed in user-visible responses.

**Tags:** `nuclei`, `info-disclosure`, `path-disclosure`, `error-handling`
**Alert name:** Info Disclosure — Path Disclosure
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information

---

### `nuclei-tabnabbing`

**Severity:** LOW · **CWE:** CWE-1022 · **Category:** misconfigurations

**Title:** Reverse tabnabbing — links missing rel=noopener on {asset}

**Summary:** External links on {asset} use target=_blank without noopener — older browsers and webviews are vulnerable to tabnabbing.

**Description:**

> Outbound links on {asset} use `target="_blank"` without `rel="noopener noreferrer"`. The newly-opened tab can navigate the original tab via `window.opener` — used in reverse-tabnabbing phishing where the user returns to a lookalike of your site after clicking an outbound link. Modern browsers default to `noopener` for `target="_blank"` links, so this finding is mostly a concern for older browsers and mobile webviews.

**Remediation:**

> Add `rel="noopener noreferrer"` to every external link with `target="_blank"`. Most templating frameworks and Markdown renderers can be configured to do this automatically. Web linters (eslint-plugin-react/jsx-no-target-blank) catch these at build time.

**Tags:** `nuclei`, `misconfiguration`, `tabnabbing`, `tabnabbing`
**Alert name:** Misconfig — Tabnabbing
**Monitor type:** `config_change`

**References:**
- OWASP — Security Misconfiguration

---

### `nuclei-tomcat-version-disclosure`

**Severity:** LOW · **CWE:** CWE-200 · **Category:** service_exposure

**Title:** Apache Tomcat version disclosed by {asset}

**Summary:** Tomcat on {asset} reveals its version — replace default error pages and override server banner.

**Description:**

> {asset} reveals the exact Tomcat version in default error pages or HTTP headers. Helps attackers map to known Tomcat CVEs for targeted exploitation.

**Remediation:**

> Override Tomcat's default error pages — every `<error-page>` mapping in `web.xml`. Set `server.info`, `server.number`, and `server.built` in `$CATALINA_HOME/lib/org/apache/catalina/util/ServerInfo.properties` or override via the `org.apache.catalina.connector.X_POWERED_BY` system property to suppress the version banner.

**Tags:** `nuclei`, `info-disclosure`, `tomcat-version-disclosure`, `tomcat`, `version-disclosure`
**Alert name:** Info Disclosure — Tomcat Version
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information

---

### `nuclei-wordpress-version-disclosure`

**Severity:** LOW · **CWE:** CWE-200 · **Category:** service_exposure

**Title:** WordPress version disclosed by {asset}

**Summary:** WordPress version on {asset} is publicly visible — strip the generator tag and version query strings.

**Description:**

> {asset} reveals the WordPress version via the `<meta name="generator">` tag, RSS feeds, or JS/CSS asset version strings. WordPress is one of the most-attacked platforms; the version disclosure is recon material for version-specific exploits, especially against the long tail of vulnerable plugins.

**Remediation:**

> Remove the generator meta tag (add a small functions.php snippet: `remove_action('wp_head', 'wp_generator')`) and strip version query strings on JS/CSS. A maintained security plugin (Wordfence, iThemes Security) does this automatically. Keeping WordPress core, themes, and plugins patched is the actual defence — version hiding is secondary.

**Tags:** `nuclei`, `info-disclosure`, `wordpress-version-disclosure`, `wordpress`, `version-disclosure`
**Alert name:** Info Disclosure — WP Version
**Monitor type:** `config_change`

**References:**
- OWASP — Sensitive Data Exposure
- CWE-200: Exposure of Sensitive Information

---

## SSL / TLS

_13 templates_

### `ssl-cert-expired`

**Severity:** CRITICAL · **CWE:** CWE-295 · **Category:** security_hygiene

**Title:** SSL certificate expired on {asset}:{port}

**Summary:** Your SSL certificate has expired — visitors see security warnings and can't connect safely.

**Description:**

> The SSL/TLS certificate has expired. Browsers, mobile apps, and API clients refuse to connect; visitors see a full-page security warning and most won't click through. This is usually a missed renewal.

**Remediation:**

> Renew the certificate immediately. If the certificate came from a manual issuance, set up automated renewal via Let's Encrypt (certbot, acme.sh) or your hosting provider's managed TLS. Add a calendar reminder 30 days before expiry as a fallback.

**Tags:** `ssl`, `certificate`, `expired`
**Alert name:** SSL Certificate Expired
**Monitor type:** `cert_expiry`

**References:**
- RFC 5280 — Internet X.509 Public Key Infrastructure
- Mozilla Server-Side TLS Configuration

---

### `ssl-cert-expiring-7d`

**Severity:** HIGH · **CWE:** CWE-298 · **Category:** security_hygiene

**Title:** SSL certificate expires in {value} days on {asset}:{port}

**Summary:** Your SSL certificate expires in less than a week — renew it now to avoid downtime.

**Description:**

> The SSL certificate expires within 7 days. If renewal hasn't already started, you're at imminent risk of an outage.

**Remediation:**

> Renew the certificate now — don't wait. Verify automated renewal is configured and successfully issuing new certificates (check the renewal logs, not just the cron job).

**Tags:** `ssl`, `certificate`, `expiring`
**Alert name:** SSL Certificate Expiring Soon
**Monitor type:** `cert_expiry`

**References:**
- Mozilla Server-Side TLS Configuration

---

### `ssl-hostname-mismatch`

**Severity:** HIGH · **CWE:** CWE-297 · **Category:** security_hygiene

**Title:** SSL certificate hostname mismatch on {asset}:{port}

**Summary:** Your SSL certificate was issued for a different domain — browsers show a mismatch warning.

**Description:**

> The hostname doesn't appear in the certificate's Subject Common Name or Subject Alternative Names. Browsers show a warning and HTTPS clients refuse to connect by default.

**Remediation:**

> Reissue the certificate with the correct hostname listed as a SAN entry. If you serve multiple hostnames from one certificate, ensure every one is included; if you serve them from separate vhosts, configure SNI properly so each gets the right certificate.

**Tags:** `ssl`, `certificate`, `hostname`
**Alert name:** SSL Hostname Mismatch
**Monitor type:** `cert_change`

**References:**
- RFC 6125 — Representation and Verification of Domain-Based Application Service Identity
- Mozilla Server-Side TLS Configuration

---

### `ssl-only-deprecated-protocols`

**Severity:** HIGH · **CWE:** CWE-326 · **Category:** security_hygiene

**Title:** Only deprecated TLS versions supported on {asset}

**Summary:** Your server only supports outdated encryption — modern browsers can't connect at all.

**Description:**

> The endpoint only accepts TLS 1.0 and/or TLS 1.1. Modern browsers (Chrome, Firefox, Safari, Edge) refuse to connect and most API clients have removed support entirely. The site is effectively offline for current clients.

**Remediation:**

> Enable TLS 1.2 and TLS 1.3 urgently — disable TLS 1.0 and 1.1 in the same change. This is high-priority remediation; customers on modern devices currently can't reach you.

**Tags:** `ssl`, `protocol`, `critical`
**Alert name:** Only Deprecated TLS
**Monitor type:** `cert_change`

**References:**
- RFC 8996 — Deprecating TLS 1.0 and TLS 1.1
- Mozilla Server-Side TLS Configuration

---

### `ssl-self-signed`

**Severity:** HIGH · **CWE:** CWE-295 · **Category:** security_hygiene

**Title:** Self-signed SSL certificate on {asset}:{port}

**Summary:** Your site uses a self-signed certificate — browsers will warn visitors it's not trusted.

**Description:**

> The certificate is self-signed — not issued by a trusted Certificate Authority. Browsers show a full-page security warning and clients can't verify the server's identity, leaving the connection trivially MITM-able.

**Remediation:**

> Replace with a certificate from a public CA. Let's Encrypt issues free, browser-trusted certificates with automated renewal in under five minutes. For internal-only services, stand up an internal CA and distribute its root to the clients that need it — never rely on self-signed certificates in production.

**Tags:** `ssl`, `certificate`, `self-signed`
**Alert name:** Self-Signed Certificate
**Monitor type:** `cert_change`

**References:**
- Let's Encrypt — Getting Started
- Mozilla Server-Side TLS Configuration

---

### `ssl-tls10-enabled`

**Severity:** HIGH · **CWE:** CWE-326 · **Category:** security_hygiene

**Title:** TLS 1.0 enabled on {asset}

**Summary:** Your server still supports TLS 1.0, which has known security vulnerabilities.

**Description:**

> The server still accepts TLS 1.0 connections. TLS 1.0 was deprecated in 2020 and is vulnerable to BEAST and POODLE downgrade attacks. PCI DSS and most other compliance regimes explicitly prohibit TLS 1.0.

**Remediation:**

> Disable TLS 1.0 in your web-server / load-balancer / TLS-termination layer. Support only TLS 1.2 and TLS 1.3. Mozilla's SSL Configuration Generator produces ready-to-paste configs for nginx, Apache, HAProxy, AWS, etc.

**Tags:** `ssl`, `protocol`, `tls1.0`, `deprecated`
**Alert name:** TLS 1.0 Enabled
**Monitor type:** `cert_change`

**References:**
- RFC 8996 — Deprecating TLS 1.0 and TLS 1.1
- PCI DSS v4.0 §4.2.1
- Mozilla Server-Side TLS Configuration

---

### `ssl-cert-expiring-30d`

**Severity:** MEDIUM · **CWE:** CWE-298 · **Category:** security_hygiene

**Title:** SSL certificate expires in {value} days on {asset}:{port}

**Summary:** Your SSL certificate expires within a month — plan to renew it soon.

**Description:**

> The SSL certificate expires within 30 days. Plan the renewal now, especially if your renewal process involves manual steps or vendor coordination.

**Remediation:**

> Schedule the renewal. If you're not already on automated issuance (Let's Encrypt, ACME), now is the right time to switch — manual renewals are the leading cause of certificate expiry incidents.

**Tags:** `ssl`, `certificate`, `expiring`
**Alert name:** SSL Certificate Expiring
**Monitor type:** `cert_expiry`

**References:**
- Mozilla Server-Side TLS Configuration

---

### `ssl-tls11-enabled`

**Severity:** MEDIUM · **CWE:** CWE-326 · **Category:** security_hygiene

**Title:** TLS 1.1 enabled on {asset}

**Summary:** Your server supports TLS 1.1, which is outdated and being dropped by browsers.

**Description:**

> The server accepts TLS 1.1 connections. TLS 1.1 was deprecated in 2021 (RFC 8996), uses outdated cryptographic primitives, and modern browsers no longer negotiate it.

**Remediation:**

> Disable TLS 1.1 alongside TLS 1.0. Support only TLS 1.2 and TLS 1.3.

**Tags:** `ssl`, `protocol`, `tls1.1`, `deprecated`
**Alert name:** TLS 1.1 Enabled
**Monitor type:** `cert_change`

**References:**
- RFC 8996 — Deprecating TLS 1.0 and TLS 1.1
- Mozilla Server-Side TLS Configuration

---

### `ssl-cert-expiring-90d`

**Severity:** LOW · **CWE:** CWE-298 · **Category:** security_hygiene

**Title:** SSL certificate expires in {value} days on {asset}:{port}

**Summary:** Your SSL certificate expires within 3 months — a good time to set up auto-renewal.

**Description:**

> The SSL certificate expires within 90 days. Not urgent yet, but worth confirming auto-renewal is in place.

**Remediation:**

> Verify automated renewal is configured and tested. Add a monitoring alert at the 30-day and 7-day marks so a missed renewal doesn't surprise you.

**Tags:** `ssl`, `certificate`
**Alert name:** SSL Certificate Expiry Notice
**Monitor type:** `cert_expiry`

**References:**
- Mozilla Server-Side TLS Configuration

---

### `ssl-no-tls13`

**Severity:** LOW · **CWE:** — · **Category:** security_hygiene

**Title:** TLS 1.3 not supported on {asset}

**Summary:** Your server doesn't support TLS 1.3, the latest and most secure protocol version.

**Description:**

> The server doesn't support TLS 1.3. TLS 1.3 reduces handshake round-trips, removes cryptographic primitives that have caused real-world breaks (CBC, RC4, RSA key exchange), and is the default for most modern clients.

**Remediation:**

> Enable TLS 1.3. OpenSSL 1.1.1+ supports it natively; LibreSSL 3.2+; BoringSSL; recent Microsoft Schannel. If you're behind a managed load balancer or CDN, enabling TLS 1.3 is usually a single setting.

**Tags:** `ssl`, `protocol`, `tls1.3`
**Alert name:** TLS 1.3 Not Supported
**Monitor type:** `cert_change`

**References:**
- RFC 8446 — TLS 1.3
- Mozilla Server-Side TLS Configuration

---

### `ssl-cert-info`

**Severity:** INFO · **CWE:** — · **Category:** security_hygiene · **Tunable:** no

**Title:** SSL certificate on {asset}:{port}: {value}

**Summary:** Details about the SSL certificate on this endpoint.

**Description:**

> SSL/TLS certificate details for the endpoint, recorded for inventory and change-detection.

**Tags:** `ssl`, `certificate`, `info`
**Alert name:** SSL Certificate Info
**Monitor type:** `cert_change`

---

### `ssl-connection-error`

**Severity:** INFO · **CWE:** — · **Category:** security_hygiene · **Tunable:** no

**Title:** SSL/TLS connection failed on {asset}:{port}

**Summary:** We couldn't establish a secure connection to this port.

**Description:**

> Could not establish an SSL/TLS connection. The port may not serve HTTPS, may be firewalled, or the TLS stack may be misconfigured.

**Tags:** `ssl`, `error`

---

### `ssl-no-tls12`

**Severity:** INFO · **CWE:** — · **Category:** security_hygiene

**Title:** TLS 1.2 not supported on {asset}

**Summary:** Your server doesn't support TLS 1.2, which some older clients still need.

**Description:**

> TLS 1.2 isn't accepted on this endpoint. Older client libraries and embedded devices that don't yet speak TLS 1.3 will fail to connect.

**Remediation:**

> Enable TLS 1.2 alongside TLS 1.3 for the broadest compatibility without sacrificing security. Mozilla's 'intermediate' profile is the standard recommendation.

**Tags:** `ssl`, `protocol`
**Alert name:** TLS 1.2 Not Supported
**Monitor type:** `cert_change`

**References:**
- RFC 5246 — TLS 1.2
- Mozilla Server-Side TLS — Intermediate Profile

---

## HTTP Security Headers

_8 templates_

### `header-missing-content_security_policy`

**Severity:** MEDIUM · **CWE:** CWE-79 · **Category:** security_hygiene

**Title:** Missing Content-Security-Policy header on {asset}:{port}

**Summary:** Your site has no Content Security Policy, leaving it more vulnerable to XSS attacks.

**Description:**

> No Content-Security-Policy header is set. CSP is the strongest in-browser defence against XSS and data injection — it tells the browser exactly which scripts, styles, and connections are allowed. Without it, a single XSS bug becomes full account takeover.

**Remediation:**

> Start in report-only mode to surface what your site actually loads:
> Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
>
> Tighten the directives based on the reports, then switch to the enforcing header. Use nonces or hashes for inline scripts rather than 'unsafe-inline'.

**Tags:** `headers`, `security`, `content-security-policy`
**Alert name:** CSP Missing
**Monitor type:** `header_change`

**References:**
- W3C Content Security Policy Level 3
- OWASP Secure Headers Project
- MDN — Content-Security-Policy

---

### `header-missing-permissions_policy`

**Severity:** MEDIUM · **CWE:** — · **Category:** security_hygiene

**Title:** Missing Permissions-Policy header on {asset}:{port}

**Summary:** Your site doesn't restrict browser features like camera and mic access for embedded content.

**Description:**

> No Permissions-Policy header is set. Permissions-Policy controls which browser features (camera, microphone, geolocation, payment, USB, etc.) the page and its embedded frames are allowed to use. Without it, a compromised third-party script or framed widget can prompt for sensitive permissions.

**Remediation:**

> Add a deny-by-default policy listing only the features you actually use:
> Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
>
> Whitelist specific origins where features are needed:
> Permissions-Policy: camera=(self "https://video.example.com")

**Tags:** `headers`, `security`, `permissions-policy`
**Alert name:** Permissions-Policy Missing
**Monitor type:** `header_change`

**References:**
- W3C Permissions Policy
- MDN — Permissions-Policy

---

### `header-missing-referrer_policy`

**Severity:** MEDIUM · **CWE:** CWE-200 · **Category:** security_hygiene

**Title:** Missing Referrer-Policy header on {asset}:{port}

**Summary:** Your site leaks full page URLs to third parties when users click links.

**Description:**

> No Referrer-Policy is set. By default, browsers send the full URL — including query parameters and path — to any site your users navigate to or fetch resources from. Sensitive tokens, user IDs, or session data in URLs leak to third parties this way.

**Remediation:**

> Add: Referrer-Policy: strict-origin-when-cross-origin. This sends the full URL only on same-origin navigations, the origin (no path or query) on cross-origin HTTPS requests, and nothing on HTTPS-to-HTTP downgrades.

**Tags:** `headers`, `security`, `referrer-policy`
**Alert name:** Referrer-Policy Missing
**Monitor type:** `header_change`

**References:**
- W3C Referrer Policy
- OWASP Secure Headers Project

---

### `header-missing-strict_transport_security`

**Severity:** MEDIUM · **CWE:** CWE-319 · **Category:** security_hygiene

**Title:** Missing Strict-Transport-Security header on {asset}:{port}

**Summary:** Your site doesn't force browsers to always use HTTPS, allowing downgrade attacks.

**Description:**

> The HSTS header isn't set. Browsers will follow HTTP-to-HTTPS redirects on the first visit, but a network attacker between the user and your server can intercept that initial request and downgrade it to plain HTTP, then proxy unencrypted traffic.

**Remediation:**

> Add the header to every HTTPS response:
> Strict-Transport-Security: max-age=31536000; includeSubDomains
>
> Once you've verified everything works at one year and includeSubDomains, consider submitting your domain to the browser preload list so even first visits are protected.

**Tags:** `headers`, `security`, `strict-transport-security`
**Alert name:** HSTS Missing
**Monitor type:** `header_change`

**References:**
- RFC 6797 — HTTP Strict Transport Security
- OWASP Secure Headers Project
- hstspreload.org

---

### `header-missing-x_content_type_options`

**Severity:** MEDIUM · **CWE:** CWE-16 · **Category:** security_hygiene

**Title:** Missing X-Content-Type-Options header on {asset}:{port}

**Summary:** Browsers may misinterpret file types on your site, which could enable script injection.

**Description:**

> X-Content-Type-Options: nosniff isn't set. Without it, browsers may MIME-sniff a response — guessing its real type from the first few bytes — and execute a file you intended to serve as data (e.g., a JSON response) as JavaScript. This is a known XSS vector when uploaded user content is served from your origin.

**Remediation:**

> Add to every response: X-Content-Type-Options: nosniff. This is universally safe — there's no compatibility cost — and is required if you have any user-uploaded content.

**Tags:** `headers`, `security`, `x-content-type-options`
**Alert name:** X-Content-Type-Options Missing
**Monitor type:** `header_change`

**References:**
- OWASP Secure Headers Project
- MDN — X-Content-Type-Options

---

### `header-missing-x_frame_options`

**Severity:** MEDIUM · **CWE:** CWE-1021 · **Category:** security_hygiene

**Title:** Missing X-Frame-Options header on {asset}:{port}

**Summary:** Your site can be embedded in malicious iframes, enabling clickjacking attacks.

**Description:**

> Neither X-Frame-Options nor a CSP frame-ancestors directive was set. The page can be embedded in an iframe on any other site, enabling clickjacking attacks where a victim is tricked into clicking inside your site through a transparent overlay.

**Remediation:**

> If you don't need to be framed: add X-Frame-Options: DENY. If you only frame yourself: SAMEORIGIN. The modern equivalent is Content-Security-Policy: frame-ancestors 'none' (or 'self'), which is preferred — set both for compatibility with older browsers.

**Tags:** `headers`, `security`, `x-frame-options`
**Alert name:** X-Frame-Options Missing
**Monitor type:** `header_change`

**References:**
- OWASP Clickjacking Defense Cheat Sheet
- MDN — X-Frame-Options
- W3C CSP — frame-ancestors

---

### `header-powered-by-leak`

**Severity:** LOW · **CWE:** CWE-200 · **Category:** security_hygiene

**Title:** X-Powered-By header exposes technology: {value}

**Summary:** Your site reveals what technology it runs on, giving attackers a head start.

**Description:**

> X-Powered-By reveals the application framework or runtime (PHP version, Express, ASP.NET, etc.). Like Server: it shortens an attacker's reconnaissance step by giving them a specific version to match against known CVEs.

**Remediation:**

> Remove the header at the application or proxy layer.
>   • PHP: expose_php = Off in php.ini
>   • Express: app.disable('x-powered-by')
>   • ASP.NET: <httpProtocol><customHeaders><remove name="X-Powered-By"/></customHeaders></httpProtocol>
>   • Generic: strip via reverse proxy

**Tags:** `headers`, `information-disclosure`
**Alert name:** Technology Stack Exposed
**Monitor type:** `header_change`

**References:**
- OWASP Secure Headers Project

---

### `header-server-version-leak`

**Severity:** LOW · **CWE:** CWE-200 · **Category:** security_hygiene

**Title:** Server header exposes version: {value}

**Summary:** Your web server is advertising its exact software version, making it easier to attack.

**Description:**

> The Server response header reveals the exact software and version running. This isn't a vulnerability on its own, but it shortens the reconnaissance step — an attacker can match the version against known CVE databases without probing.

**Remediation:**

> Suppress or minimise the Server header.
>   • nginx: server_tokens off;
>   • Apache: ServerTokens Prod and ServerSignature Off
>   • IIS: remove via URL Rewrite outbound rule
>   • Express: app.disable('x-powered-by') (also covers X-Powered-By)
>
> Removing the header isn't a substitute for patching — but it raises the bar for opportunistic scanning.

**Tags:** `headers`, `information-disclosure`, `server`
**Alert name:** Server Version Exposed
**Monitor type:** `header_change`

**References:**
- OWASP Secure Headers Project
- MDN — Server header

---

## HTTP / Redirects

_1 template_

### `http-no-https-redirect`

**Severity:** HIGH · **CWE:** CWE-319 · **Category:** security_hygiene

**Title:** HTTP does not redirect to HTTPS on {asset}

**Summary:** Visitors who don't type 'https://' get an unencrypted, insecure connection.

**Description:**

> Plain HTTP requests aren't redirected to HTTPS. Anyone typing the bare hostname into a browser, or following an old http:// link, gets an unencrypted connection — credentials, cookies, and traffic content travel in clear text. Network attackers between the user and your server can read or rewrite the response.

**Remediation:**

> Configure a permanent redirect (HTTP 301) from every plain HTTP path to its HTTPS equivalent. Combined with HSTS, this removes the downgrade window after the first secure visit. Don't return content over HTTP at all — redirect from / onward.

**Tags:** `http`, `redirect`, `https`
**Alert name:** No HTTPS Redirect
**Monitor type:** `header_change`

**References:**
- RFC 6797 — HTTP Strict Transport Security
- OWASP Transport Layer Protection Cheat Sheet

---

## Cookie Security

_3 templates_

### `cookie-missing-httponly`

**Severity:** MEDIUM · **CWE:** CWE-1004 · **Category:** security_hygiene

**Title:** Cookie '{value}' missing HttpOnly flag

**Summary:** A cookie on your site can be stolen through JavaScript injection attacks.

**Description:**

> The cookie is readable by client-side JavaScript via document.cookie. If your site has any XSS vulnerability — even in third-party widgets — that bug becomes session theft because attacker JavaScript can simply exfiltrate the cookie.

**Remediation:**

> Set the HttpOnly attribute on this cookie. There's no compatibility cost for session and authentication cookies — they should always be HttpOnly.

**Tags:** `cookie`, `httponly`
**Alert name:** Cookie Missing HttpOnly
**Monitor type:** `header_change`

**References:**
- OWASP Session Management Cheat Sheet

---

### `cookie-missing-samesite`

**Severity:** MEDIUM · **CWE:** CWE-1275 · **Category:** security_hygiene

**Title:** Cookie '{value}' missing SameSite attribute

**Summary:** A cookie on your site is sent with cross-site requests, which could enable forgery attacks.

**Description:**

> The cookie has no SameSite attribute. Browsers treat the cookie as Lax by default in modern versions, but older browsers and some embedded webviews still send it on cross-site requests, enabling cross-site request forgery (CSRF) attacks.

**Remediation:**

> Set SameSite=Lax for most cookies. Use SameSite=Strict for sensitive operations where the cookie should never travel with cross-site requests. Use SameSite=None; Secure only when you genuinely need cross-site cookies (e.g., third-party SSO).

**Tags:** `cookie`, `samesite`
**Alert name:** Cookie Missing SameSite
**Monitor type:** `header_change`

**References:**
- RFC 6265bis §4.1.2.7 — SameSite
- OWASP CSRF Prevention Cheat Sheet

---

### `cookie-missing-secure`

**Severity:** MEDIUM · **CWE:** CWE-614 · **Category:** security_hygiene

**Title:** Cookie '{value}' missing Secure flag

**Summary:** A cookie on your site can be stolen by anyone on the same network.

**Description:**

> The cookie is set without the Secure attribute. It can be transmitted over plain HTTP — including on automatic downgrade or mixed-content fetches — exposing the cookie value to any network observer between the user and your server.

**Remediation:**

> Set the Secure attribute on this cookie. If the cookie is session-related, also set HttpOnly and an explicit SameSite value. Most frameworks default to Secure in production — check the cookie-issuance configuration in your app.

**Tags:** `cookie`, `secure`
**Alert name:** Insecure Cookie
**Monitor type:** `header_change`

**References:**
- RFC 6265bis — HTTP Cookies
- OWASP Session Management Cheat Sheet

---

## Ports / Services

_10 templates_

### `port-docker-api-exposed`

**Severity:** CRITICAL · **CWE:** CWE-1327 · **Category:** service_exposure

**Title:** Docker API (unencrypted) exposed on {asset}:{port}

**Summary:** Your Docker API is wide open to the internet — anyone can take full control of your server.

**Description:**

> The Docker daemon API is reachable on port 2375 without TLS or authentication. Anyone who can reach this port can launch containers, mount the host filesystem, and trivially escape to root on the host — this is equivalent to an unauthenticated remote shell.

**Remediation:**

> Block port 2375 immediately at the firewall. If remote Docker access is required, use port 2376 with mutual TLS authentication. Better: don't expose the Docker socket directly — manage containers through an orchestrator (Kubernetes, Nomad, ECS) with proper RBAC.

**Tags:** `port`, `docker`, `container`
**Alert name:** Docker API Exposed
**Monitor type:** `port_change`

**References:**
- Docker — Protect the Docker daemon socket
- CIS Docker Benchmark §2.8

---

### `port-elasticsearch-exposed`

**Severity:** CRITICAL · **CWE:** CWE-1327 · **Category:** service_exposure

**Title:** Elasticsearch exposed on {asset}:{port}

**Summary:** Your Elasticsearch instance is open to the internet — bots routinely scrape exposed instances.

**Description:**

> Elasticsearch is reachable from the public internet. Pre-8.0 open-source builds have no built-in authentication; bots routinely scrape exposed instances and either steal data or ransom-wipe indexes. Even authenticated instances expose version information that maps to specific CVEs.

**Remediation:**

> Block port 9200 (and 9300) from the internet. Enable the free Elastic security features (8.0+ has them on by default) or front the cluster with a reverse proxy enforcing authentication. Bind to a private interface.

**Tags:** `port`, `elasticsearch`, `database`
**Alert name:** Elasticsearch Exposed
**Monitor type:** `port_change`

**References:**
- Elastic — Securing Elasticsearch

---

### `port-ftp-exposed`

**Severity:** CRITICAL · **CWE:** CWE-319 · **Category:** service_exposure

**Title:** FTP exposed on {asset}:{port}

**Summary:** FTP is running on your server — login credentials are sent without encryption.

**Description:**

> FTP is reachable on the public internet. FTP transmits credentials and data in plain text and is frequently configured with anonymous access still enabled. The protocol was designed before the internet had adversaries; it has no modern protections.

**Remediation:**

> Disable FTP. Use SFTP (over SSH) or FTPS (FTP over TLS) for file transfer, or move to HTTPS-based alternatives like S3 presigned URLs, Box, or managed file-transfer services. Confirm anonymous access is disabled even on internal FTP.

**Tags:** `port`, `ftp`, `unencrypted`
**Alert name:** FTP Exposed
**Monitor type:** `port_change`

**References:**
- RFC 4217 — Securing FTP with TLS
- NIST SP 800-53 SC-8

---

### `port-mongodb-exposed`

**Severity:** CRITICAL · **CWE:** CWE-1327 · **Category:** service_exposure

**Title:** MongoDB exposed on {asset}:{port}

**Summary:** Your MongoDB database is accessible from the internet.

**Description:**

> MongoDB is reachable from the public internet. Pre-3.6 builds didn't enable authentication by default and were the subject of mass-ransom campaigns. Modern builds bind to localhost out of the box, so an internet-exposed instance has been deliberately reconfigured.

**Remediation:**

> Block port 27017 from the internet. Confirm authorization is enabled in mongod.conf (security.authorization: enabled), create per-user accounts with least privilege, and bind to an internal interface.

**Tags:** `port`, `mongodb`, `database`
**Alert name:** MongoDB Exposed
**Monitor type:** `port_change`

**References:**
- MongoDB — Security Checklist
- CIS MongoDB Benchmark

---

### `port-mysql-exposed`

**Severity:** CRITICAL · **CWE:** CWE-1327 · **Category:** service_exposure

**Title:** MySQL exposed on {asset}:{port}

**Summary:** Your MySQL database is directly accessible from the internet.

**Description:**

> A MySQL/MariaDB database server is reachable from the public internet. Even with authentication enabled, this exposes the service to credential stuffing, version-specific exploits, and data exfiltration if any account is weakly secured.

**Remediation:**

> Block port 3306 from the internet. Bind MySQL to 127.0.0.1 or an internal subnet (bind-address in my.cnf). If application servers need remote access, put them on a private network or use SSH tunnelling / a managed VPN — never expose the database to the internet.

**Tags:** `port`, `mysql`, `database`
**Alert name:** MySQL Exposed
**Monitor type:** `port_change`

**References:**
- CIS MySQL Benchmark
- MySQL — Securing the Initial MySQL Account

---

### `port-rdp-exposed`

**Severity:** CRITICAL · **CWE:** CWE-1327 · **Category:** service_exposure

**Title:** RDP (Remote Desktop) exposed on {asset}:{port}

**Summary:** Remote Desktop is open to the internet — this is a primary ransomware entry point.

**Description:**

> Microsoft RDP is reachable from the public internet. RDP is the single most common ransomware entry point — attackers spray credential-stuffing attacks against exposed RDP at internet scale, and historic RDP CVEs (BlueKeep, DejaBlue) remain widely exploited.

**Remediation:**

> Block port 3389 from the internet at your firewall or security group. Reach RDP through a VPN, an SSH tunnel, or a zero-trust access service (Cloudflare Access, Tailscale, AWS SSM Session Manager). If RDP must be exposed temporarily, restrict the source IPs and enforce Network Level Authentication.

**Tags:** `port`, `rdp`, `remote_access`
**Alert name:** RDP Exposed
**Monitor type:** `port_change`

**References:**
- CISA — Securing Remote Desktop (RDP)
- Microsoft — Securing remote access

---

### `port-redis-exposed`

**Severity:** CRITICAL · **CWE:** CWE-1327 · **Category:** service_exposure

**Title:** Redis exposed on {asset}:{port}

**Summary:** Your Redis cache is open to the internet — attackers can read all your data or take over the server.

**Description:**

> Redis is reachable from the public internet. Older versions ship with no authentication by default, and even with AUTH configured, an attacker who reaches port 6379 can write arbitrary files via CONFIG SET — including authorized_keys for remote shell access. Exposed Redis instances are routinely compromised within hours.

**Remediation:**

> Block port 6379 from the internet. Bind Redis to 127.0.0.1 or a private interface. Enable AUTH with a strong password (or ACL users in Redis 6+), enable protected-mode, and run Redis as a non-root user.

**Tags:** `port`, `redis`, `database`
**Alert name:** Redis Exposed
**Monitor type:** `port_change`

**References:**
- Redis — Security
- CIS Redis Benchmark

---

### `port-smb-exposed`

**Severity:** CRITICAL · **CWE:** CWE-1327 · **Category:** service_exposure

**Title:** SMB exposed on {asset}:{port}

**Summary:** Windows file sharing (SMB) is exposed — this is how WannaCry ransomware spread.

**Description:**

> SMB (Windows file sharing) is reachable from the public internet. SMB has a long, ongoing history of critical vulnerabilities — EternalBlue (MS17-010, used by WannaCry and NotPetya), SMBGhost (CVE-2020-0796), and others. There is no scenario where SMB should be internet-facing.

**Remediation:**

> Block port 445 (and 139) from the internet at the firewall, without exception. For remote file access, use a VPN or modern alternatives (OneDrive, SharePoint, S3, Nextcloud). Internally, ensure SMBv1 is disabled and SMB signing is enforced.

**Tags:** `port`, `smb`, `file_sharing`
**Alert name:** SMB Exposed
**Monitor type:** `port_change`

**References:**
- CISA Alert TA17-132A — EternalBlue / WannaCry
- Microsoft — SMB security best practices

---

### `port-telnet-exposed`

**Severity:** CRITICAL · **CWE:** CWE-319 · **Category:** service_exposure

**Title:** Telnet exposed on {asset}:{port}

**Summary:** Telnet is running on your server — all logins and data are sent in plaintext.

**Description:**

> Telnet is reachable on the public internet. Telnet transmits all traffic — including username and password during login — in plain text. Anyone on the network path can capture credentials passively. There is no legitimate reason to expose Telnet on the internet.

**Remediation:**

> Disable telnetd entirely. Use SSH (port 22) with key-based authentication for shell access. Network device management should also use SSH or HTTPS-based platforms (NETCONF, RESTCONF) — never Telnet.

**Tags:** `port`, `telnet`, `unencrypted`
**Alert name:** Telnet Exposed
**Monitor type:** `port_change`

**References:**
- RFC 4250 — SSH Architecture (replacement for Telnet)
- NIST SP 800-53 SC-8 — Transmission Confidentiality and Integrity

---

### `port-generic-open`

**Severity:** INFO · **CWE:** — · **Category:** service_exposure

**Title:** Open port {port}/{value} on {asset}

**Summary:** An open port was found on your server.

**Description:**

> An open port was detected. We don't classify it as inherently risky on its own, but every internet-facing service is part of your attack surface — if this service isn't required from the public internet, close the port.

**Remediation:**

> Confirm the port needs to be publicly accessible. Close it at the host firewall or cloud security group if not. Restrict to known source IP ranges where possible.

**Tags:** `port`, `exposure`
**Alert name:** New Port Detected
**Monitor type:** `port_change`

**References:**
- CIS Critical Security Controls v8 — Control 4: Secure Configuration

---

## CVE / Vulnerabilities

_1 template_

### `cve-generic`

**Severity:** HIGH · **CWE:** — · **Category:** vulnerabilities

**Title:** Known vulnerability: {value}

**Summary:** A known security vulnerability was found on your server.

**Description:**

> A known CVE was matched against software running on this host. The CVE record describes the affected versions and impact (remote code execution, information disclosure, denial of service, etc.). Per-finding severity comes from the CVE's CVSS score.

**Remediation:**

> Look up the CVE ID at nvd.nist.gov for the full advisory and vendor-fixed versions. Apply the vendor patch or upgrade to the fixed release. If no patch is available yet, apply any documented mitigations (configuration changes, network controls, WAF rules) and track the CVE for resolution.

**Tags:** `cve`
**Alert name:** CVE Detected
**Monitor type:** `vuln_change`

**References:**
- NIST National Vulnerability Database (NVD)
- MITRE CVE
- FIRST CVSS v3.1 Specification

---

## Technology Detection

_2 templates_

### `tech-eol`

**Severity:** MEDIUM · **CWE:** CWE-1104 · **Category:** security_hygiene

**Title:** End-of-life software: {value} on {asset}

**Summary:** You're running end-of-life software that no longer gets security updates.

**Description:**

> {value} is end-of-life — the vendor no longer ships security patches. Any vulnerability discovered from this point on stays unpatched in your environment, and CVE-driven vulnerability scanners will flag this host as exposed indefinitely until you upgrade.

**Remediation:**

> Plan a migration to a supported version. Test in staging first; some major-version upgrades have breaking changes (PHP 7→8, Python 2→3, .NET Framework→.NET, Ubuntu 18.04→22.04). Where an immediate upgrade isn't possible, isolate the EOL host on a private network and limit its blast radius.

**Tags:** `technology`, `outdated`
**Alert name:** End-of-Life Software
**Monitor type:** `tech_change`

**References:**
- CIS Critical Security Controls v8 — Control 7: Continuous Vulnerability Management
- endoflife.date

---

### `tech-detected`

**Severity:** INFO · **CWE:** — · **Category:** security_hygiene · **Tunable:** no

**Title:** Technology detected: {value}

**Summary:** We identified a technology running on your server.

**Description:**

> We identified a technology component (web server, framework, CMS, library) running on this asset. Recorded for inventory and to drive version-aware vulnerability matching during future scans.

**Tags:** `technology`
**Alert name:** Technology Detected
**Monitor type:** `tech_change`

---

## Exposure Score

_1 template_

### `exposure-score`

**Severity:** INFO · **CWE:** — · **Category:** service_exposure · **Tunable:** no

**Title:** Exposure Score: {value}/100 (Grade {grade})

**Summary:** Your overall security exposure score based on all scan findings.

**Description:**

> Overall security exposure score based on all open findings, weighted by severity and asset criticality.

**Tags:** `exposure`, `score`
**Alert name:** Exposure Score Updated
**Monitor type:** `exposure_change`

---

## Monitoring / Change Detection

_10 templates_

### `monitor-tech-eol-detected`

**Severity:** HIGH · **CWE:** — · **Category:** security_hygiene

**Title:** End-of-life software detected on {asset}

**Summary:** We detected end-of-life software on your server that no longer gets security patches.

**Description:**

> Continuous monitoring picked up software that has now reached end-of-life since the previous scan. Vendor patches have stopped or are about to.

**Remediation:**

> Plan an upgrade to a supported version. Where the EOL software is a base OS or core runtime, upgrade timelines often span weeks — start the planning now.

**Tags:** `monitoring`, `technology`, `eol`
**Alert name:** EOL Software Detected
**Monitor type:** `tech_change`

**References:**
- endoflife.date

---

### `monitor-dmarc-changed`

**Severity:** MEDIUM · **CWE:** — · **Category:** security_hygiene

**Title:** DMARC record changed for {asset}

**Summary:** Your DMARC email security record was just changed.

**Description:**

> The DMARC TXT record was modified since the last scan. Verify the changes were authorised.

**Tags:** `monitoring`, `dns`, `dmarc`, `change`
**Alert name:** DMARC Record Changed
**Monitor type:** `dns_change`

---

### `monitor-new-port`

**Severity:** MEDIUM · **CWE:** — · **Category:** service_exposure

**Title:** New port {port} detected on {asset}

**Summary:** A new port just opened on your server that wasn't there before.

**Description:**

> A port that wasn't open in the previous monitoring run is now responding. This may be a planned change, but it can also be a misconfiguration, an unauthorised service, or a sign of compromise.

**Remediation:**

> Confirm the new port is expected. If it is, decide whether it should be reachable from the public internet — if not, close it at the firewall. If it isn't expected, investigate what process is listening.

**Tags:** `monitoring`, `port`, `change`
**Alert name:** New Port Opened
**Monitor type:** `port_change`

**References:**
- CIS Critical Security Controls v8 — Control 4: Secure Configuration

---

### `monitor-new-service`

**Severity:** MEDIUM · **CWE:** — · **Category:** security_hygiene

**Title:** New service detected on {asset}:{port}

**Summary:** A new service appeared on your server that wasn't running before.

**Description:**

> A new service or different software is now responding on a port that was previously running something else. Could be a planned upgrade or an unexpected change.

**Remediation:**

> Confirm the change was authorised. If the new service is less hardened than the old one (e.g. moved from nginx behind WAF to a direct application server), revisit the security configuration.

**Tags:** `monitoring`, `service`, `change`
**Alert name:** New Service Detected
**Monitor type:** `tech_change`

---

### `monitor-spf-changed`

**Severity:** MEDIUM · **CWE:** — · **Category:** security_hygiene

**Title:** SPF record changed for {asset}

**Summary:** Your email SPF record was just changed — make sure it was authorized.

**Description:**

> The SPF TXT record was modified since the last scan. Verify the changes were authorised.

**Tags:** `monitoring`, `dns`, `spf`, `change`
**Alert name:** SPF Record Changed
**Monitor type:** `dns_change`

---

### `monitor-new-subdomain`

**Severity:** LOW · **CWE:** — · **Category:** security_hygiene

**Title:** New subdomain discovered: {value}

**Summary:** A new subdomain was found for your domain that we hadn't seen before.

**Description:**

> A subdomain was discovered during continuous monitoring that wasn't in our previous inventory. Could be a planned launch, shadow IT, or an attacker setting up a phishing page on a dangling DNS record.

**Remediation:**

> Confirm the subdomain is yours and intentional. Add it to the appropriate asset group so it's covered by future scans. If you don't recognise it, investigate ownership and consider removing the DNS record.

**Tags:** `monitoring`, `dns`, `subdomain`, `discovery`
**Alert name:** New Subdomain Discovered
**Monitor type:** `dns_change`

---

### `monitor-cert-changed`

**Severity:** INFO · **CWE:** — · **Category:** security_hygiene · **Tunable:** no

**Title:** SSL certificate changed on {asset}:{port}

**Summary:** The SSL certificate on your server was just replaced.

**Description:**

> The SSL/TLS certificate has been replaced with a different one. Recorded for change history.

**Tags:** `monitoring`, `ssl`, `change`
**Alert name:** Certificate Changed
**Monitor type:** `cert_change`

---

### `monitor-dns-record-changed`

**Severity:** INFO · **CWE:** — · **Category:** security_hygiene · **Tunable:** no

**Title:** DNS record changed for {asset}

**Summary:** A DNS record for your domain was just changed.

**Description:**

> A DNS record was added, removed, or modified. Recorded for change history.

**Tags:** `monitoring`, `dns`, `change`
**Alert name:** DNS Record Changed
**Monitor type:** `dns_change`

---

### `monitor-header-changed`

**Severity:** INFO · **CWE:** — · **Category:** security_hygiene · **Tunable:** no

**Title:** Security header changed on {asset}

**Summary:** A security header on your site was just changed.

**Description:**

> A security header (HSTS, CSP, X-Frame-Options, etc.) was added, removed, or modified. Recorded for change history.

**Tags:** `monitoring`, `header`, `change`
**Alert name:** Security Header Changed
**Monitor type:** `header_change`

---

### `monitor-port-closed`

**Severity:** INFO · **CWE:** — · **Category:** service_exposure · **Tunable:** no

**Title:** Port {port} closed on {asset}

**Summary:** A port that was previously open on your server has been closed.

**Description:**

> A previously open port is no longer responding. Recorded for change history.

**Tags:** `monitoring`, `port`, `change`
**Alert name:** Port Closed
**Monitor type:** `port_change`

---
