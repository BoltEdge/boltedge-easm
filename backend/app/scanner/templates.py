# app/scanner/templates.py
"""
Finding Template Registry.

Canonical source of truth for every finding type the platform can produce.
Keyed by template_id (e.g. "dns-no-dmarc", "header-missing-csp").

Used by:
    - Analyzers:    Look up default severity, description, remediation
    - Monitoring:   Match template_id → alert_name, monitor_type
    - Tuning:       Users suppress/customize findings by tuning_key
    - Reporting:    Consistent titles and categories across exports
    - Frontend:     Category badges, remediation display

Each template defines the DEFAULTS. Analyzers can override any field
per-finding (e.g. injecting the actual hostname into the title pattern,
or bumping severity based on context).

Placeholders in title/description/remediation:
    {asset}   — the asset value (domain or IP)
    {port}    — port number
    {value}   — dynamic value (header name, CVE ID, tech name, etc.)
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional


# ═══════════════════════════════════════════════════════════════════════════
# CUSTOMER-FACING CATEGORIES
# ═══════════════════════════════════════════════════════════════════════════
#
# The internal `category` field on each template is fine-grained (11 values)
# and reflects how the analysers think. Customers see something coarser —
# 5 buckets that map to the public Coverage page, the alert-toggle UI, and
# the marketing-side catalogue.
#
# `customer_category` is auto-derived from `category` via the mapping
# below at template-registration time, so every existing template gets
# one for free. A template can override by passing `customer_category=`
# explicitly when there's a special case (e.g. a `dns` template that's
# really about exposure rather than hygiene).
#
# When adding a new internal `category` value, add it to the mapping
# here. The validator below will fail loudly if a template uses an
# internal category we haven't mapped.

# Customer-facing category IDs. These are stable strings used as URL
# slugs, JSON keys, env-var-safe identifiers — do not rename.
CUSTOMER_CATEGORIES: Dict[str, Dict[str, str]] = {
    "vulnerabilities": {
        "label": "Vulnerabilities",
        "blurb": "Known CVEs and software flaws in services running on your assets.",
    },
    "service_exposure": {
        "label": "Service Exposure",
        "blurb": "Admin panels, dev tools, databases, and cloud assets reachable from the internet.",
    },
    "data_leaks": {
        "label": "Data Leaks",
        "blurb": "Secrets, credentials, configuration files, and source code exposed in public repos or directly on the asset.",
    },
    "misconfigurations": {
        "label": "Misconfigurations",
        "blurb": "CORS, open redirects, default credentials, and accessible admin endpoints.",
    },
    "security_hygiene": {
        "label": "Security Hygiene",
        "blurb": "Expiring certificates, missing security headers, weak DMARC/SPF, and end-of-life software stacks.",
    },
    "lookalike": {
        "label": "Lookalike Domains",
        "blurb": "Typosquats, homoglyph confusables, TLD swaps, and other domains registered to impersonate yours.",
    },
}

CUSTOMER_CATEGORY_IDS = list(CUSTOMER_CATEGORIES.keys())

# Internal category → customer-facing category. Every internal category
# in templates.py MUST appear here — the validator at registration time
# refuses templates whose category isn't mapped.
_INTERNAL_TO_CUSTOMER: Dict[str, str] = {
    "cve":              "vulnerabilities",
    "vulnerability":    "vulnerabilities",
    "exposure":         "service_exposure",
    "ports":            "service_exposure",
    "cloud":            "service_exposure",
    "leak":             "data_leaks",
    "misconfiguration": "misconfigurations",
    "ssl":              "security_hygiene",
    "headers":          "security_hygiene",
    "dns":              "security_hygiene",
    "technology":       "security_hygiene",
    "tech":             "security_hygiene",  # legacy alias for technology
    "lookalike":        "lookalike",         # 1:1 mapping — own customer bucket
}


@dataclass(frozen=True)
class FindingTemplate:
    template_id: str
    title: str
    description: str
    severity: str                    # critical, high, medium, low, info
    category: str                    # ssl, ports, headers, cve, dns, tech, exposure

    remediation: Optional[str] = None
    cwe: Optional[str] = None
    confidence: str = "high"
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    # Human-readable one-liner for notifications / executive reports
    summary: Optional[str] = None

    # Monitoring & alerting
    alert_name: Optional[str] = None
    monitor_type: Optional[str] = None

    # Tuning
    tunable: bool = True
    tuning_key: Optional[str] = None  # defaults to template_id if None

    # Customer-facing taxonomy. Auto-derived from `category` at register
    # time via _INTERNAL_TO_CUSTOMER. Override by passing this explicitly
    # when the internal category misrepresents the customer view.
    customer_category: Optional[str] = None

    @property
    def effective_tuning_key(self) -> str:
        return self.tuning_key or self.template_id

    @property
    def effective_customer_category(self) -> str:
        """The customer-facing category, auto-derived if not set."""
        if self.customer_category:
            return self.customer_category
        return _INTERNAL_TO_CUSTOMER.get(self.category, "security_hygiene")


# ═══════════════════════════════════════════════════════════════════════════
# REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

_TEMPLATES: Dict[str, FindingTemplate] = {}


def _r(tmpl: FindingTemplate) -> FindingTemplate:
    """Register a template.

    Auto-fills `customer_category` from the internal `category` so every
    template has one, and validates that the mapping is complete. If a
    new internal category is added without a corresponding customer
    mapping, registration fails immediately at import — making the
    drift impossible to ship by accident.
    """
    if tmpl.customer_category is None:
        derived = _INTERNAL_TO_CUSTOMER.get(tmpl.category)
        if derived is None:
            raise ValueError(
                f"Template '{tmpl.template_id}' uses internal category "
                f"'{tmpl.category}' which has no customer-facing mapping. "
                f"Add it to _INTERNAL_TO_CUSTOMER in templates.py."
            )
        tmpl = replace(tmpl, customer_category=derived)
    elif tmpl.customer_category not in CUSTOMER_CATEGORIES:
        raise ValueError(
            f"Template '{tmpl.template_id}' has invalid customer_category "
            f"'{tmpl.customer_category}'. Valid: {CUSTOMER_CATEGORY_IDS}"
        )
    _TEMPLATES[tmpl.template_id] = tmpl
    return tmpl


def templates_by_customer_category() -> Dict[str, List[FindingTemplate]]:
    """Group every registered template by customer-facing category.

    Used by the public /coverage page, the catalogue regen script, and
    the alert-toggle UI. Returns a dict keyed by CUSTOMER_CATEGORY_IDS,
    even for empty buckets, so consumers can render every card without
    having to handle missing keys.
    """
    out: Dict[str, List[FindingTemplate]] = {cid: [] for cid in CUSTOMER_CATEGORY_IDS}
    for tmpl in _TEMPLATES.values():
        out[tmpl.effective_customer_category].append(tmpl)
    return out


# ───────────────────────────────────────────────────────────────────────────
# DNS / Email Security
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="dns-no-spf",
    title="No SPF record for {asset}",
    description=(
        "No SPF (Sender Policy Framework) record was found for {asset}. "
        "SPF tells receiving mail servers which IP addresses are allowed "
        "to send email as your domain. Without it, attackers can spoof "
        "your address in phishing campaigns and your real mail is more "
        "likely to be flagged as spam."
    ),
    remediation=(
        "Inventory every service that sends email as {asset} (your mail "
        "provider, marketing tool, transactional sender, ticketing "
        "system). Publish an SPF TXT record at the apex listing all of "
        "them, ending with -all to reject everything else.\n\n"
        'Example for Google Workspace: "v=spf1 include:_spf.google.com -all".\n\n'
        "If you're not certain you've captured every sender, start with "
        "~all (softfail) and tighten to -all once a week of DMARC reports "
        "comes back clean."
    ),
    severity="high",
    category="dns",
    cwe="CWE-290",
    tags=["dns", "email", "spf"],
    summary="Your domain has no SPF record, so anyone can send emails pretending to be you.",
    alert_name="SPF Record Missing",
    monitor_type="dns_change",
    references=[
        "RFC 7208 — Sender Policy Framework v1",
        "M3AAWG Sender Best Common Practices v3",
        "OWASP Email Security Cheat Sheet",
    ],
))

_r(FindingTemplate(
    template_id="dns-spf-plus-all",
    title="SPF record allows all senders (+all) for {asset}",
    description=(
        "The SPF record for {asset} ends with +all, which means ANY "
        "server on the internet is authorised to send email as your "
        "domain. This completely defeats the purpose of SPF and is "
        "often the result of a copy-paste error during setup."
    ),
    remediation=(
        "Change +all to -all (hardfail) to reject unauthorised senders, "
        "or ~all (softfail) if you're still verifying which services "
        "send email for you. Never leave +all in production."
    ),
    severity="high",
    category="dns",
    cwe="CWE-290",
    tags=["dns", "email", "spf", "misconfigured"],
    summary="Your SPF record allows anyone to send email as your domain — it's wide open.",
    alert_name="SPF Allows All Senders",
    monitor_type="dns_change",
    references=[
        "RFC 7208 — Sender Policy Framework v1",
        "M3AAWG Sender Best Common Practices v3",
    ],
))

_r(FindingTemplate(
    template_id="dns-spf-softfail",
    title="SPF uses softfail (~all) for {asset}",
    description=(
        "The SPF record for {asset} ends with ~all (softfail). "
        "Unauthorised emails are flagged but still delivered, usually "
        "to the spam folder. Spammers and phishing kits often slip "
        "through softfail."
    ),
    remediation=(
        "Once you've verified every legitimate sender is in your SPF "
        "record (review a week of DMARC aggregate reports), tighten "
        "the policy to -all so unauthorised mail is rejected outright."
    ),
    severity="medium",
    category="dns",
    cwe="CWE-290",
    tags=["dns", "email", "spf"],
    summary="Your SPF record flags unauthorized emails but doesn't block them.",
    alert_name="SPF Softfail Only",
    monitor_type="dns_change",
    references=[
        "RFC 7208 — Sender Policy Framework v1",
        "M3AAWG Sender Best Common Practices v3",
    ],
))

_r(FindingTemplate(
    template_id="dns-spf-neutral",
    title="SPF uses neutral (?all) for {asset}",
    description=(
        "The SPF record for {asset} ends with ?all (neutral). Receiving "
        "servers are explicitly told not to make a decision based on "
        "SPF, which provides no protection against spoofing."
    ),
    remediation=(
        "Replace ?all with -all (hardfail). If you can't yet rule out "
        "false positives, at least step up to ~all (softfail) and "
        "review DMARC reports before tightening to -all."
    ),
    severity="medium",
    category="dns",
    cwe="CWE-290",
    tags=["dns", "email", "spf"],
    summary="Your SPF record is set to neutral, which provides no email protection at all.",
    alert_name="SPF Neutral Policy",
    monitor_type="dns_change",
    references=[
        "RFC 7208 — Sender Policy Framework v1",
    ],
))

_r(FindingTemplate(
    template_id="dns-spf-too-many-lookups",
    title="SPF record exceeds 10-lookup limit for {asset}",
    description=(
        "The SPF record for {asset} requires more than 10 DNS lookups "
        "to evaluate. RFC 7208 caps SPF at 10 lookups; exceeding the "
        "limit causes a permanent error (permerror) and SPF fails "
        "entirely — including for legitimate senders."
    ),
    remediation=(
        "Reduce DNS lookups by flattening nested includes into ip4: "
        "and ip6: mechanisms, or remove unused providers. SPF flattening "
        "services (e.g. EasyDMARC, dmarcian, Valimail) automate this and "
        "keep the flat record up to date as your providers' IPs change."
    ),
    severity="medium",
    category="dns",
    cwe="CWE-754",
    tags=["dns", "email", "spf"],
    summary="Your SPF record has too many DNS lookups and may break email authentication.",
    alert_name="SPF Lookup Limit Exceeded",
    monitor_type="dns_change",
    references=[
        "RFC 7208 §4.6.4 — Lookup limits",
        "M3AAWG Sender Best Common Practices v3",
    ],
))

_r(FindingTemplate(
    template_id="dns-no-dmarc",
    title="No DMARC record for {asset}",
    description=(
        "No DMARC record was found for {asset}. DMARC tells receiving "
        "servers what to do when SPF or DKIM checks fail, and gives you "
        "back reports about who's sending mail in your name. Without it, "
        "there's no enforcement and no visibility."
    ),
    remediation=(
        "Publish a DMARC TXT record at _dmarc.{asset}. Start with:\n"
        '"v=DMARC1; p=none; rua=mailto:dmarc@{asset}"\n\n'
        "p=none collects reports without affecting delivery. After two "
        "weeks of clean reports, move to p=quarantine, then p=reject."
    ),
    severity="high",
    category="dns",
    cwe="CWE-290",
    tags=["dns", "email", "dmarc"],
    summary="Your domain has no DMARC record, leaving email authentication unenforced.",
    alert_name="DMARC Record Missing",
    monitor_type="dns_change",
    references=[
        "RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC)",
        "M3AAWG Sender Best Common Practices v3",
        "DMARC.org Deployment Guide",
    ],
))

_r(FindingTemplate(
    template_id="dns-dmarc-none",
    title="DMARC policy is 'none' (monitoring only) for {asset}",
    description=(
        "DMARC for {asset} is published with p=none. Failed messages "
        "are still delivered — DMARC is only collecting reports, not "
        "enforcing. This is the right starting position, but staying "
        "here long-term means spoofed mail still reaches your customers."
    ),
    remediation=(
        "Review two weeks of DMARC aggregate reports (rua=) to confirm "
        "all legitimate senders are passing SPF or DKIM alignment, then "
        "raise the policy to p=quarantine for a week, and finally to "
        "p=reject. Use pct=25/50/75 to roll out gradually."
    ),
    severity="high",
    category="dns",
    cwe="CWE-290",
    tags=["dns", "email", "dmarc"],
    summary="DMARC is in monitor-only mode — spoofed emails still get delivered.",
    alert_name="DMARC Not Enforcing",
    monitor_type="dns_change",
    references=[
        "RFC 7489 §6.3 — Policies",
        "DMARC.org Deployment Guide",
    ],
))

_r(FindingTemplate(
    template_id="dns-dmarc-no-rua",
    title="DMARC record has no reporting address (rua) for {asset}",
    description=(
        "The DMARC record for {asset} doesn't include an rua= reporting "
        "address. Without it you receive no aggregate reports, so you "
        "can't see who's sending mail in your name, can't detect new "
        "abuse patterns, and can't safely tighten the policy to "
        "quarantine or reject."
    ),
    remediation=(
        "Add rua=mailto:dmarc@{asset} (or a dedicated mailbox / a "
        "third-party DMARC processor). If your reporting address is on "
        "a different domain, also publish a DMARC reporting "
        "authorisation record at the receiving end."
    ),
    severity="medium",
    category="dns",
    cwe="CWE-778",
    tags=["dns", "email", "dmarc"],
    summary="You're not receiving DMARC reports because no reporting address is set.",
    alert_name="DMARC No Reporting",
    monitor_type="dns_change",
    references=[
        "RFC 7489 §7 — DMARC Feedback",
    ],
))

_r(FindingTemplate(
    template_id="dns-no-dkim",
    title="No DKIM records found for {asset}",
    description=(
        "No DKIM (DomainKeys Identified Mail) records were found at any "
        "common selector for {asset}. DKIM cryptographically signs your "
        "outgoing mail so recipients can verify it really came from you "
        "and wasn't modified in transit. Without DKIM, DMARC can only "
        "rely on SPF, which doesn't survive email forwarding."
    ),
    remediation=(
        "Enable DKIM signing in your mail provider's admin console, "
        "publish the public key as a TXT record at "
        "<selector>._domainkey.{asset}, and verify in headers of a test "
        "send that the DKIM-Signature header is present and passing. "
        "Google Workspace, Microsoft 365, and most ESPs have one-click "
        "DKIM setup."
    ),
    severity="medium",
    category="dns",
    cwe="CWE-345",
    tags=["dns", "email", "dkim"],
    summary="No DKIM email signing was found, so recipients can't verify your emails are genuine.",
    alert_name="DKIM Not Configured",
    monitor_type="dns_change",
    references=[
        "RFC 6376 — DomainKeys Identified Mail (DKIM) Signatures",
        "M3AAWG Sender Best Common Practices v3",
    ],
))

_r(FindingTemplate(
    template_id="dns-zone-transfer-open",
    title="DNS zone transfer (AXFR) successful for {asset}",
    description=(
        "A DNS zone transfer (AXFR) was completed against a public "
        "nameserver, returning every record in the zone. Attackers now "
        "have a complete map of your subdomains, internal hostnames, "
        "mail servers, and IP allocations — a primary recon goldmine."
    ),
    remediation=(
        "Restrict AXFR to authorised secondary nameservers only. In "
        "BIND: allow-transfer { trusted-servers; }; in NSD/Knot: "
        "configure provide-xfr explicitly. Most managed DNS providers "
        "(Route 53, Cloudflare, Azure DNS, Google Cloud DNS) disable "
        "AXFR by default — if you see this finding on managed DNS, "
        "investigate the misconfiguration urgently."
    ),
    severity="critical",
    category="dns",
    cwe="CWE-200",
    tags=["dns", "zone-transfer", "critical"],
    summary="Your entire DNS zone is publicly downloadable, exposing your full infrastructure map.",
    alert_name="Zone Transfer Exposed",
    monitor_type="dns_change",
    references=[
        "RFC 5936 — DNS Zone Transfer Protocol (AXFR)",
        "DNS-OARC — Zone Transfer Best Practices",
        "CWE-200: Exposure of Sensitive Information",
    ],
))

_r(FindingTemplate(
    template_id="dns-single-nameserver",
    title="Only one nameserver for {asset}",
    description=(
        "Only one nameserver was found for {asset}. If it goes offline "
        "or is briefly unreachable, your domain becomes unresolvable "
        "everywhere — websites disappear, mail bounces, APIs error out."
    ),
    remediation=(
        "Add at least one additional NS record pointing to a different "
        "nameserver (ideally on a different network or provider). Most "
        "managed DNS providers ship redundancy by default — adding two "
        "to four NS records is standard."
    ),
    severity="medium",
    category="dns",
    tags=["dns", "nameserver", "redundancy"],
    summary="Your domain relies on a single nameserver — if it fails, your site goes offline.",
    alert_name="Single Nameserver",
    monitor_type="dns_change",
    references=[
        "RFC 1034 §4.1 — Multiple authoritative servers",
        "ICANN — DNS Operational Best Practices",
    ],
))

_r(FindingTemplate(
    template_id="dns-no-ipv6",
    title="No IPv6 (AAAA) records for {asset}",
    description=(
        "No AAAA records were found for {asset}. IPv6 deployment is "
        "above 40% on major networks (Google, mobile carriers, ISPs in "
        "India/Brazil/US), and some access networks are now IPv6-only. "
        "Visitors on those networks reach your site over a NAT64/CGN "
        "translator, which adds latency and a failure surface."
    ),
    remediation=(
        "Add AAAA records pointing to IPv6 addresses. Most managed "
        "hosting (Cloudflare, AWS, GCP, Azure) gives you IPv6 "
        "automatically — you may just need to enable it. Verify with "
        "test-ipv6.com after the change."
    ),
    severity="low",
    category="dns",
    tags=["dns", "ipv6"],
    summary="Your domain isn't reachable over IPv6, which a growing number of networks use.",
    alert_name="No IPv6 Support",
    monitor_type="dns_change",
    references=[
        "Google IPv6 Statistics",
        "RFC 8200 — Internet Protocol, Version 6",
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Subdomain Takeover
# ───────────────────────────────────────────────────────────────────────────
# One template per claimable third-party service (matches the slugs the
# subdomain_takeover_analyzer produces from the engine's fingerprint
# table) plus three generic fallbacks that the registry's prefix matcher
# uses for unknown services and for the dangling-CNAME / suspicious tiers.
#
# Placeholders rendered at scan time: {asset} (the affected subdomain),
# {cname_target} (where the CNAME points).

# Standard sources cited on every takeover template — added to a per-
# template references list along with vendor-specific docs.
_TAKEOVER_REFS_COMMON = [
    "OWASP WSTG — Test for Subdomain Takeover",
    "EdOverflow — can-i-take-over-xyz",
]


def _takeover_confirmed(slug: str, service: str, noun: str, error_text: str,
                        impact: str, reclaim_steps: list[str],
                        extra_refs: list[str] | None = None,
                        alert_short: str | None = None) -> FindingTemplate:
    """Build a confirmed-takeover template with consistent shape.

    The per-service variation lives in `noun` (what the takeover surface
    is — bucket / app / store / ...), `error_text` (what the service's
    unclaimed-resource page says), `impact` (what an attacker can do),
    and `reclaim_steps` (the service-specific reclaim path)."""
    steps_block = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(reclaim_steps))
    description = (
        "The subdomain {asset} has a CNAME record pointing to "
        "{cname_target}, and " + service + " is returning its "
        "\"" + error_text + "\" response. The resource has been "
        "deleted (or never created) — anyone with a " + service + " "
        "account can claim the same name and have your subdomain "
        "serve their content. " + impact
    )
    remediation = (
        "Pick one path:\n\n"
        "**Remove the DNS record** (recommended if " + noun + " is no "
        "longer needed):\n"
        "  Delete the CNAME `{asset} → {cname_target}` from your DNS zone.\n\n"
        "**Reclaim the " + noun + "** (if {asset} should still serve "
        "content):\n" + steps_block + "\n\n"
        "Then audit every other CNAME in your DNS zone for the same "
        "pattern — one missed dangling record is enough."
    )
    summary = (
        "A subdomain of yours points to an unclaimed " + service + " "
        + noun + " — anyone can claim it and host content as you."
    )
    return FindingTemplate(
        template_id=f"takeover-confirmed-{slug}",
        title="Subdomain takeover — unclaimed " + service + " " + noun + " at {asset}",
        description=description,
        remediation=remediation,
        severity="critical",
        category="dns",
        cwe="CWE-284",
        tags=["subdomain-takeover", "dangling-cname", slug],
        summary=summary,
        alert_name="Takeover — " + (alert_short or service),
        monitor_type="dns_change",
        references=_TAKEOVER_REFS_COMMON + (extra_refs or []),
    )


# ── Cloud platforms ──

_r(_takeover_confirmed(
    slug="aws-s3-cloudfront",
    service="AWS S3",
    noun="bucket",
    error_text="NoSuchBucket / The specified bucket does not exist",
    impact=(
        "Used in the wild to host phishing pages, steal cookies via "
        "cross-subdomain trust, and bypass Content Security Policies "
        "that whitelist your apex domain."
    ),
    reclaim_steps=[
        "Sign in to the AWS account that should own this resource.",
        "Create an S3 bucket with the exact name from {cname_target} "
        "(strip the regional `.s3-website-...` suffix).",
        "Re-apply the original bucket policy and static-hosting "
        "configuration.",
    ],
    extra_refs=["AWS — S3 bucket naming rules"],
    alert_short="AWS S3",
))

_r(_takeover_confirmed(
    slug="aws-cloudfront",
    service="AWS CloudFront",
    noun="distribution",
    error_text="ERROR: The request could not be satisfied",
    impact=(
        "An attacker who registers the alternate domain on a new "
        "CloudFront distribution can serve arbitrary content under "
        "your subdomain with a valid AWS-issued certificate."
    ),
    reclaim_steps=[
        "Sign in to the AWS account that should own this distribution.",
        "Create a new CloudFront distribution with {asset} listed as "
        "an Alternate Domain Name (CNAME).",
        "Attach an ACM certificate covering {asset} and configure "
        "your origin.",
    ],
    extra_refs=["AWS — Using custom URLs for CloudFront"],
    alert_short="CloudFront",
))

_r(_takeover_confirmed(
    slug="aws-elastic-beanstalk",
    service="AWS Elastic Beanstalk",
    noun="environment",
    error_text="NXDOMAIN — environment does not exist",
    impact=(
        "An attacker can create an Elastic Beanstalk environment with "
        "the same name in any AWS region and serve their application "
        "from your subdomain."
    ),
    reclaim_steps=[
        "Sign in to the AWS account that should own this environment.",
        "Create an Elastic Beanstalk environment with the exact name "
        "from {cname_target} in the original region.",
        "Deploy the intended application or remove the CNAME if the "
        "environment is no longer required.",
    ],
    extra_refs=["AWS — Elastic Beanstalk environment URLs"],
    alert_short="Beanstalk",
))

_r(_takeover_confirmed(
    slug="azure-app-service",
    service="Azure App Service",
    noun="app",
    error_text="404 Web Site not found",
    impact=(
        "Anyone with an Azure subscription can create an App Service "
        "with the same name and serve content under your subdomain — "
        "a known abuse pattern that Microsoft has documented as "
        "\"dangling DNS\"."
    ),
    reclaim_steps=[
        "Sign in to the Azure subscription that should own this app.",
        "Create an App Service with the exact name from {cname_target}.",
        "Add {asset} as a custom domain and bind a certificate.",
    ],
    extra_refs=["Microsoft — Prevent dangling DNS entries"],
    alert_short="Azure App Service",
))

_r(_takeover_confirmed(
    slug="azure-blob-storage",
    service="Azure Blob Storage",
    noun="container",
    error_text="BlobNotFound / The specified resource does not exist",
    impact=(
        "An attacker who creates a storage account with the same name "
        "can host files under your subdomain — particularly dangerous "
        "for static-site or asset-CDN subdomains where users implicitly "
        "trust the content."
    ),
    reclaim_steps=[
        "Sign in to the Azure subscription that should own this account.",
        "Create a storage account with the exact name from {cname_target}.",
        "Recreate the container and configure access as required.",
    ],
    extra_refs=["Microsoft — Prevent dangling DNS entries"],
    alert_short="Azure Blob",
))

_r(_takeover_confirmed(
    slug="azure-virtual-machine",
    service="Azure Virtual Machine",
    noun="DNS label",
    error_text="NXDOMAIN — VM DNS label not registered",
    impact=(
        "An attacker can spin up a VM in the same Azure region with "
        "the same DNS label and have public traffic to your subdomain "
        "land on their machine."
    ),
    reclaim_steps=[
        "Sign in to the Azure subscription that should own this label.",
        "Provision a VM in the original region and assign the public "
        "DNS label from {cname_target}.",
        "Or remove the CNAME if the VM is no longer required.",
    ],
    extra_refs=["Microsoft — Prevent dangling DNS entries"],
    alert_short="Azure VM",
))

_r(_takeover_confirmed(
    slug="azure-cdn",
    service="Azure CDN",
    noun="endpoint",
    error_text="404 Web Site not found / Our services aren't available right now",
    impact=(
        "An attacker who recreates the CDN endpoint can serve "
        "arbitrary content under your subdomain — often with the "
        "Azure-issued certificate auto-renewing successfully because "
        "domain validation passes via the dangling CNAME."
    ),
    reclaim_steps=[
        "Sign in to the Azure subscription that should own this endpoint.",
        "Create a CDN endpoint with the exact name from {cname_target}.",
        "Add {asset} as a custom domain and re-issue the certificate.",
    ],
    extra_refs=["Microsoft — Prevent dangling DNS entries"],
    alert_short="Azure CDN",
))

_r(_takeover_confirmed(
    slug="azure-traffic-manager",
    service="Azure Traffic Manager",
    noun="profile",
    error_text="NXDOMAIN — Traffic Manager profile not registered",
    impact=(
        "Recreating the profile in any Azure subscription routes "
        "traffic for {asset} to attacker-controlled endpoints."
    ),
    reclaim_steps=[
        "Sign in to the Azure subscription that should own this profile.",
        "Create a Traffic Manager profile with the exact name from "
        "{cname_target}.",
        "Configure the original endpoint pool and routing method.",
    ],
    extra_refs=["Microsoft — Prevent dangling DNS entries"],
    alert_short="Traffic Manager",
))

_r(_takeover_confirmed(
    slug="azure-api-management",
    service="Azure API Management",
    noun="service instance",
    error_text="ResourceNotFound",
    impact=(
        "An attacker who recreates the APIM instance can publish API "
        "endpoints under your subdomain that look authentic to client "
        "applications still pointing at the old hostname."
    ),
    reclaim_steps=[
        "Sign in to the Azure subscription that should own this instance.",
        "Create an API Management service with the exact name from "
        "{cname_target}.",
        "Re-add {asset} as a custom domain on the gateway.",
    ],
    extra_refs=["Microsoft — APIM custom domains"],
    alert_short="Azure APIM",
))

_r(_takeover_confirmed(
    slug="google-cloud-storage",
    service="Google Cloud Storage",
    noun="bucket",
    error_text="NoSuchBucket / The specified bucket does not exist",
    impact=(
        "Bucket names in GCS are globally unique — anyone with a GCP "
        "project can create a bucket with the same name and serve "
        "static content under your subdomain."
    ),
    reclaim_steps=[
        "Sign in to the GCP project that should own this bucket.",
        "Create a Cloud Storage bucket with the exact name from "
        "{cname_target}.",
        "Re-apply IAM and static-website settings.",
    ],
    extra_refs=["Google — Cloud Storage bucket naming"],
    alert_short="GCS",
))

# ── Hosting / PaaS ──

_r(_takeover_confirmed(
    slug="heroku",
    service="Heroku",
    noun="app",
    error_text="No such app",
    impact=(
        "Anyone with a Heroku account can register the slug and "
        "deploy any code under your subdomain — bypassing same-origin "
        "trust your apex extends to its subdomains."
    ),
    reclaim_steps=[
        "From the Heroku account that should own this name, run "
        "`heroku apps:create <app-slug>` using the exact slug from "
        "{cname_target}.",
        "Add the custom domain back: `heroku domains:add {asset}`.",
        "Redeploy the application.",
    ],
    extra_refs=["Heroku — Custom Domain Names"],
    alert_short="Heroku",
))

_r(_takeover_confirmed(
    slug="ghost",
    service="Ghost",
    noun="publication",
    error_text="The thing you were looking for is no longer here",
    impact=(
        "An attacker can claim the publication name on Ghost(Pro) and "
        "host a fake blog under your subdomain — particularly damaging "
        "if the subdomain previously hosted thought-leadership content "
        "search engines have indexed."
    ),
    reclaim_steps=[
        "Sign up for Ghost(Pro) (or self-host on Ghost) with the exact "
        "subdomain from {cname_target}.",
        "Add {asset} as the publication's custom domain.",
        "Restore the original content from backup if needed.",
    ],
    extra_refs=["Ghost Docs — Custom Domain"],
    alert_short="Ghost",
))

_r(_takeover_confirmed(
    slug="pantheon",
    service="Pantheon",
    noun="site",
    error_text="404 error unknown site",
    impact=(
        "An attacker who creates a Pantheon site with the same machine "
        "name can serve any WordPress or Drupal content under your "
        "subdomain."
    ),
    reclaim_steps=[
        "Sign in to the Pantheon account that should own this site.",
        "Create a site with the exact machine name from {cname_target}.",
        "Add {asset} as a custom domain in the site's Domains tab.",
    ],
    extra_refs=["Pantheon — Custom domains"],
    alert_short="Pantheon",
))

_r(_takeover_confirmed(
    slug="netlify",
    service="Netlify",
    noun="site",
    error_text="Not Found - Request ID",
    impact=(
        "Recreating the site name on any Netlify account lets an "
        "attacker publish arbitrary static content under your "
        "subdomain — Netlify auto-issues a Let's Encrypt certificate "
        "that passes browser validation."
    ),
    reclaim_steps=[
        "Sign in to the Netlify account that should own this site.",
        "Create a site with the exact name from {cname_target}.",
        "Add {asset} as a custom domain (Site settings → Domain "
        "management → Add custom domain).",
    ],
    extra_refs=["Netlify Docs — Custom domains"],
    alert_short="Netlify",
))

_r(_takeover_confirmed(
    slug="fly-io",
    service="Fly.io",
    noun="app",
    error_text="NXDOMAIN — Fly app not registered",
    impact=(
        "An attacker can run `fly launch` with the same app name and "
        "deploy a container under your subdomain anywhere on Fly's "
        "global edge."
    ),
    reclaim_steps=[
        "Sign in to the Fly.io account that should own this app: "
        "`fly auth login`.",
        "Create an app with the exact name from {cname_target}: "
        "`fly apps create <name>`.",
        "Run `fly certs add {asset}` to attach the custom domain.",
    ],
    extra_refs=["Fly.io Docs — Custom domains"],
    alert_short="Fly.io",
))

_r(_takeover_confirmed(
    slug="vercel",
    service="Vercel",
    noun="project",
    error_text="NXDOMAIN — Vercel project not registered",
    impact=(
        "Recreating the project name on any Vercel account gives an "
        "attacker a CDN-fronted, certificate-valid surface under your "
        "subdomain."
    ),
    reclaim_steps=[
        "Sign in to the Vercel account that should own this project.",
        "Create a project with the exact name from {cname_target}.",
        "Add {asset} under Project Settings → Domains.",
    ],
    extra_refs=["Vercel Docs — Custom domains"],
    alert_short="Vercel",
))

_r(_takeover_confirmed(
    slug="render",
    service="Render",
    noun="service",
    error_text="NXDOMAIN — Render service not registered",
    impact=(
        "An attacker can create a Render service with the same name "
        "and deploy any application under your subdomain."
    ),
    reclaim_steps=[
        "Sign in to the Render account that should own this service.",
        "Create a service with the exact name from {cname_target}.",
        "Add {asset} as a custom domain in the service's Settings.",
    ],
    extra_refs=["Render Docs — Custom domains"],
    alert_short="Render",
))

_r(_takeover_confirmed(
    slug="surge-sh",
    service="Surge.sh",
    noun="project",
    error_text="project not found",
    impact=(
        "Anyone can run `surge` and publish to the same domain — Surge "
        "doesn't verify ownership beyond the CLI invocation."
    ),
    reclaim_steps=[
        "Install the Surge CLI and authenticate with the account that "
        "should own this domain: `surge login`.",
        "Publish to the exact domain from {cname_target}: "
        "`surge ./public {asset}`.",
        "Or remove the CNAME if Surge.sh is no longer in use.",
    ],
    extra_refs=["Surge.sh Docs — Custom domains"],
    alert_short="Surge.sh",
))

# ── Git pages ──

_r(_takeover_confirmed(
    slug="github-pages",
    service="GitHub Pages",
    noun="site",
    error_text="There isn't a GitHub Pages site here",
    impact=(
        "Anyone can create a repository on a personal or organisation "
        "account, enable Pages, and add a CNAME file targeting your "
        "subdomain — serving arbitrary HTML and JavaScript with a "
        "GitHub-issued certificate."
    ),
    reclaim_steps=[
        "Sign in to the GitHub account or organisation that should "
        "own this site.",
        "Create a repository matching the user/org and repo name in "
        "{cname_target}.",
        "Enable Pages (Settings → Pages → Source) and add a CNAME "
        "file containing `{asset}`.",
        "Verify the custom domain in Pages settings.",
    ],
    extra_refs=["GitHub Docs — Configuring a custom domain for GitHub Pages"],
    alert_short="GitHub Pages",
))

_r(_takeover_confirmed(
    slug="gitlab-pages",
    service="GitLab Pages",
    noun="site",
    error_text="NXDOMAIN — GitLab Pages site not registered",
    impact=(
        "An attacker can create a GitLab project with the matching "
        "namespace and enable Pages, taking over your subdomain."
    ),
    reclaim_steps=[
        "Sign in to the GitLab account or group that should own this site.",
        "Create a project matching the namespace and project name in "
        "{cname_target}.",
        "Enable Pages and add `{asset}` as a custom domain in "
        "Settings → Pages.",
    ],
    extra_refs=["GitLab Docs — Custom domains for Pages"],
    alert_short="GitLab Pages",
))

_r(_takeover_confirmed(
    slug="bitbucket-pages",
    service="Bitbucket Pages",
    noun="repository",
    error_text="Repository not found",
    impact=(
        "Recreating the repository under any Bitbucket workspace lets "
        "an attacker host static content under your subdomain."
    ),
    reclaim_steps=[
        "Sign in to the Bitbucket workspace that should own this site.",
        "Create a repository matching the workspace and repo name in "
        "{cname_target}.",
        "Configure Pages with the appropriate branch.",
    ],
    extra_refs=["Bitbucket Docs — Publishing a website on Bitbucket Cloud"],
    alert_short="Bitbucket",
))

# ── E-commerce / CMS ──

_r(_takeover_confirmed(
    slug="shopify",
    service="Shopify",
    noun="store",
    error_text="Sorry, this shop is currently unavailable",
    impact=(
        "Anyone can register a Shopify account with the same store "
        "handle and run a fake storefront under your subdomain — "
        "customers see your domain in the address bar while paying "
        "the attacker."
    ),
    reclaim_steps=[
        "Sign in to the Shopify account that should own this handle, "
        "or sign up at shopify.com using the exact handle from "
        "{cname_target}.",
        "Add {asset} as a custom domain (Settings → Domains → Connect "
        "existing domain).",
        "Verify the connection in the Shopify admin.",
    ],
    extra_refs=["Shopify Help — Connecting an existing domain"],
    alert_short="Shopify",
))

_r(_takeover_confirmed(
    slug="wordpress-com",
    service="WordPress.com",
    noun="site",
    error_text="Do you want to register",
    impact=(
        "An attacker can register a wordpress.com site with the same "
        "subdomain and host arbitrary content — WordPress.com handles "
        "TLS automatically, so the takeover is invisible at the "
        "browser level."
    ),
    reclaim_steps=[
        "Sign in to the WordPress.com account that should own this site.",
        "Create a site at the exact subdomain from {cname_target}.",
        "Map {asset} as a custom domain via the site's domain settings.",
    ],
    extra_refs=["WordPress.com — Map an existing domain"],
    alert_short="WordPress.com",
))

_r(_takeover_confirmed(
    slug="tumblr",
    service="Tumblr",
    noun="blog",
    error_text="Whatever you were looking for doesn't currently exist",
    impact=(
        "Anyone can create a Tumblr blog with the same name and "
        "host any content under your subdomain."
    ),
    reclaim_steps=[
        "Sign in to the Tumblr account that should own this blog.",
        "Create a blog with the exact name from {cname_target}.",
        "Add {asset} under Blog Settings → Custom Domain.",
    ],
    extra_refs=["Tumblr Help — Custom domains"],
    alert_short="Tumblr",
))

# ── Helpdesk / SaaS ──

_r(_takeover_confirmed(
    slug="zendesk",
    service="Zendesk",
    noun="help center",
    error_text="Help Center Closed",
    impact=(
        "An attacker who registers the Zendesk subdomain can publish "
        "fake support content under your domain — particularly "
        "dangerous because customers contacting \"support\" implicitly "
        "trust the experience."
    ),
    reclaim_steps=[
        "Sign in to the Zendesk account that should own this subdomain.",
        "If the subdomain is still in your account: re-enable the "
        "Help Center and re-add {asset} as a host-mapped domain.",
        "If the subdomain has been released: open a Zendesk support "
        "ticket to reclaim it before signing up fresh.",
    ],
    extra_refs=["Zendesk Help — Host-mapping your help center"],
    alert_short="Zendesk",
))

_r(_takeover_confirmed(
    slug="freshdesk",
    service="Freshdesk",
    noun="helpdesk",
    error_text="There is no helpdesk here",
    impact=(
        "Recreating the helpdesk lets an attacker run a fake support "
        "portal under your domain, complete with fake ticket creation "
        "and credential capture."
    ),
    reclaim_steps=[
        "Sign in to the Freshdesk account that should own this helpdesk.",
        "Create a helpdesk with the exact subdomain from {cname_target}.",
        "Add {asset} as a vanity URL in Admin → Helpdesk Settings.",
    ],
    extra_refs=["Freshdesk — Vanity URLs"],
    alert_short="Freshdesk",
))

_r(_takeover_confirmed(
    slug="helpjuice",
    service="Helpjuice",
    noun="knowledge base",
    error_text="We could not find what you're looking for",
    impact=(
        "An attacker can register the Helpjuice site with the same "
        "subdomain and serve arbitrary documentation under your "
        "domain."
    ),
    reclaim_steps=[
        "Sign in to the Helpjuice account that should own this site.",
        "Create a knowledge base with the exact subdomain from "
        "{cname_target}.",
        "Configure a custom domain for {asset}.",
    ],
    extra_refs=["Helpjuice — Custom domain setup"],
    alert_short="Helpjuice",
))

_r(_takeover_confirmed(
    slug="helpscout",
    service="HelpScout",
    noun="docs site",
    error_text="No settings were found for this company",
    impact=(
        "Reclaim by an attacker lets them publish a parallel HelpScout "
        "Docs site under your subdomain — confusing customers about "
        "which support resources are official."
    ),
    reclaim_steps=[
        "Sign in to the HelpScout account that should own this site.",
        "Create a Docs collection mapped to the exact subdomain from "
        "{cname_target}.",
        "Configure the custom domain pointing at {asset}.",
    ],
    extra_refs=["HelpScout — Docs custom domain"],
    alert_short="HelpScout",
))

_r(_takeover_confirmed(
    slug="tilda",
    service="Tilda",
    noun="site",
    error_text="Domain is not configured / Please renew your subscription",
    impact=(
        "Anyone with a Tilda account can claim the domain and serve "
        "arbitrary marketing content under your subdomain."
    ),
    reclaim_steps=[
        "Sign in to the Tilda account that should own this site.",
        "Create a project and configure {asset} as the custom domain.",
        "Or renew the lapsed subscription if the original site is "
        "still recoverable.",
    ],
    extra_refs=["Tilda — Custom domain"],
    alert_short="Tilda",
))

# ── Marketing / Landing pages ──

_r(_takeover_confirmed(
    slug="unbounce",
    service="Unbounce",
    noun="landing page",
    error_text="The requested URL was not found on this server",
    impact=(
        "Recreating the landing page under another Unbounce account "
        "lets an attacker host conversion forms or phishing pages "
        "under your subdomain."
    ),
    reclaim_steps=[
        "Sign in to the Unbounce account that should own this page.",
        "Recreate or restore the landing page.",
        "Reconnect {asset} via Page Settings → Domain.",
    ],
    extra_refs=["Unbounce — Custom domains"],
    alert_short="Unbounce",
))

_r(_takeover_confirmed(
    slug="launchrock",
    service="LaunchRock",
    noun="landing page",
    error_text="It looks like you may have taken a wrong turn somewhere",
    impact=(
        "An attacker who registers the same site name on LaunchRock "
        "can run any pre-launch / coming-soon page under your subdomain."
    ),
    reclaim_steps=[
        "Sign in to the LaunchRock account that should own this page.",
        "Recreate the launch page.",
        "Configure {asset} as the custom domain in account settings.",
    ],
    alert_short="LaunchRock",
))

_r(_takeover_confirmed(
    slug="landingi",
    service="Landingi",
    noun="landing page",
    error_text="NXDOMAIN — Landingi page not registered",
    impact=(
        "An attacker can create a Landingi landing page with the same "
        "domain configuration and host arbitrary marketing or "
        "phishing content under your subdomain."
    ),
    reclaim_steps=[
        "Sign in to the Landingi account that should own this page.",
        "Recreate the landing page.",
        "Reconnect {asset} as the custom domain.",
    ],
    alert_short="Landingi",
))

_r(_takeover_confirmed(
    slug="cargo-collective",
    service="Cargo Collective",
    noun="site",
    error_text="404 Not Found",
    impact=(
        "Cargo handles tend to be short and memorable — claimable "
        "ones are quickly registered by squatters who serve their "
        "own portfolio under your subdomain."
    ),
    reclaim_steps=[
        "Sign in to the Cargo account that should own this site.",
        "Recreate the site at the exact handle from {cname_target}.",
        "Add {asset} as the custom domain.",
    ],
    extra_refs=["Cargo — Custom domains"],
    alert_short="Cargo",
))

_r(_takeover_confirmed(
    slug="webflow",
    service="Webflow",
    noun="site",
    error_text="The page you are looking for doesn't exist or has been moved",
    impact=(
        "Recreating the site under any Webflow workspace lets an "
        "attacker publish a designer-grade fake homepage under your "
        "subdomain."
    ),
    reclaim_steps=[
        "Sign in to the Webflow workspace that should own this site.",
        "Create a project and connect it to the exact subdomain from "
        "{cname_target}.",
        "Add {asset} as a custom domain (Site Settings → Publishing).",
    ],
    extra_refs=["Webflow — Connecting a custom domain"],
    alert_short="Webflow",
))

# ── CDN / DNS ──

_r(_takeover_confirmed(
    slug="fastly",
    service="Fastly",
    noun="service",
    error_text="Fastly error: unknown domain",
    impact=(
        "An attacker who configures the same domain on their own "
        "Fastly service can intercept traffic intended for your "
        "subdomain — Fastly's edge will route based on whoever has "
        "the domain attached."
    ),
    reclaim_steps=[
        "Sign in to the Fastly account that should own this service.",
        "Add {asset} to a Fastly service and configure the appropriate "
        "origin and TLS.",
        "Or remove the CNAME if Fastly is no longer the intended edge.",
    ],
    extra_refs=["Fastly — Custom domains and TLS"],
    alert_short="Fastly",
))

_r(_takeover_confirmed(
    slug="cloudflare",
    service="Cloudflare",
    noun="resource",
    error_text="NXDOMAIN — Cloudflare resource not configured",
    impact=(
        "A CNAME pointing into Cloudflare without an active Cloudflare "
        "configuration can let an attacker who adds the domain to "
        "their own Cloudflare account proxy traffic for {asset}."
    ),
    reclaim_steps=[
        "Sign in to the Cloudflare account that should serve this domain.",
        "Confirm the domain is on the correct Cloudflare account, with "
        "an active zone configuration.",
        "Or remove the CNAME if Cloudflare is no longer in front of "
        "this subdomain.",
    ],
    extra_refs=["Cloudflare — CNAME setup"],
    alert_short="Cloudflare",
))

# ── Status pages / Docs ──

_r(_takeover_confirmed(
    slug="statuspage",
    service="Statuspage",
    noun="status page",
    error_text="StatusPage / You are being redirected",
    impact=(
        "An attacker who creates a Statuspage with the same subdomain "
        "can publish fake incident reports under your domain — a "
        "real-world technique used to spread misinformation about "
        "company outages or breaches."
    ),
    reclaim_steps=[
        "Sign in to the Statuspage (Atlassian) account that should "
        "own this page.",
        "Create a status page with the exact subdomain from "
        "{cname_target}.",
        "Add {asset} as the custom domain.",
    ],
    extra_refs=["Atlassian — Statuspage custom domains"],
    alert_short="Statuspage",
))

_r(_takeover_confirmed(
    slug="readme-io",
    service="ReadMe.io",
    noun="docs",
    error_text="Project doesnt exist",
    impact=(
        "Recreating the project key on ReadMe.io lets an attacker "
        "host arbitrary API documentation under your subdomain — "
        "particularly damaging if developers integrate against the "
        "fake docs."
    ),
    reclaim_steps=[
        "Sign in to the ReadMe.io account that should own this project.",
        "Create a project with the exact project key from {cname_target}.",
        "Add {asset} as a custom domain.",
    ],
    extra_refs=["ReadMe.io — Custom domains"],
    alert_short="ReadMe",
))

# ── Feedback / Engagement ──

_r(_takeover_confirmed(
    slug="uservoice",
    service="UserVoice",
    noun="feedback site",
    error_text="This UserVoice subdomain is currently available",
    impact=(
        "Anyone can register the UserVoice subdomain and host a "
        "feedback site that customers will treat as official."
    ),
    reclaim_steps=[
        "Sign in to the UserVoice account that should own this subdomain.",
        "Recreate the feedback site at the exact subdomain from "
        "{cname_target}.",
        "Configure {asset} as the custom domain.",
    ],
    extra_refs=["UserVoice — Custom domains"],
    alert_short="UserVoice",
))

_r(_takeover_confirmed(
    slug="feedpress",
    service="Feedpress",
    noun="feed",
    error_text="The feed has not been found",
    impact=(
        "Reclaiming the feed lets an attacker push arbitrary content "
        "to subscribers of any RSS reader still pointed at your "
        "subdomain."
    ),
    reclaim_steps=[
        "Sign in to the Feedpress account that should own this feed.",
        "Recreate the feed with the exact name from {cname_target}.",
        "Configure {asset} as the custom feed domain.",
    ],
    alert_short="Feedpress",
))

# ── Project Management ──

_r(_takeover_confirmed(
    slug="teamwork",
    service="Teamwork",
    noun="site",
    error_text="Oops - We didn't find your site",
    impact=(
        "Anyone can register a Teamwork account with the same site "
        "URL and host arbitrary project-management content under "
        "your subdomain."
    ),
    reclaim_steps=[
        "Sign in to the Teamwork account that should own this site.",
        "Create a Teamwork site with the exact subdomain from "
        "{cname_target}.",
        "Configure {asset} as the custom domain.",
    ],
    extra_refs=["Teamwork — Custom domains"],
    alert_short="Teamwork",
))


# ── Generic fallbacks (used by registry prefix-match for unknown services) ──

_r(FindingTemplate(
    template_id="takeover-confirmed",
    title="Subdomain takeover — unclaimed third-party resource at {asset}",
    description=(
        "The subdomain {asset} has a CNAME record pointing to "
        "{cname_target}, and the third-party service it targets is "
        "showing an unclaimed-resource page or NXDOMAIN response. "
        "Anyone with an account at that service can claim the same "
        "name and have your subdomain serve their content. This is "
        "used in the wild to host phishing pages, steal cookies via "
        "cross-subdomain trust, and bypass Content Security Policies "
        "that whitelist your apex domain."
    ),
    remediation=(
        "Pick one path:\n\n"
        "**Remove the DNS record** (recommended if the resource is no "
        "longer needed):\n"
        "  Delete the CNAME `{asset} → {cname_target}` from your DNS zone.\n\n"
        "**Reclaim the resource** (if {asset} should still serve "
        "content):\n"
        "  1. Identify the service from {cname_target} and its "
        "reclaim/registration mechanism.\n"
        "  2. Register the same resource name under the account that "
        "should own this subdomain.\n"
        "  3. Re-attach {asset} as the custom domain.\n\n"
        "Then audit every other CNAME in your DNS zone for the same "
        "pattern."
    ),
    severity="critical",
    category="dns",
    cwe="CWE-284",
    tags=["subdomain-takeover", "dangling-cname"],
    summary="A subdomain of yours points to an unclaimed third-party resource — anyone can claim it.",
    alert_name="Takeover Confirmed",
    monitor_type="dns_change",
    references=list(_TAKEOVER_REFS_COMMON),
))

_r(FindingTemplate(
    template_id="takeover-dangling-cname",
    title="Dangling CNAME at {asset} → {cname_target}",
    description=(
        "The subdomain {asset} has a CNAME record pointing to "
        "{cname_target}, but the target does not resolve. Either the "
        "third-party resource was decommissioned without removing the "
        "DNS record, or it's pointing at a service that doesn't exist "
        "yet. Dangling CNAMEs are a takeover risk waiting to happen — "
        "if the resource name becomes registrable on the target "
        "service, anyone can claim it."
    ),
    remediation=(
        "Remove the CNAME `{asset} → {cname_target}` from your DNS "
        "zone. If the subdomain is still needed, repoint it to the "
        "correct active resource. Audit your zone for similar "
        "dangling references — it's common to find several at once "
        "after a service migration."
    ),
    severity="high",
    category="dns",
    cwe="CWE-284",
    tags=["subdomain-takeover", "dangling-cname", "nxdomain"],
    summary="One of your subdomains points to a third-party service that no longer exists — likely a takeover risk.",
    alert_name="Dangling CNAME",
    monitor_type="dns_change",
    references=list(_TAKEOVER_REFS_COMMON),
))

_r(FindingTemplate(
    template_id="takeover-suspicious",
    title="Suspicious CNAME at {asset} → {cname_target}",
    description=(
        "The subdomain {asset} has a CNAME record pointing to "
        "{cname_target}, a known third-party service pattern. We "
        "couldn't confirm whether the resource is unclaimed — the "
        "HTTP probe returned an error, or the service was unreachable "
        "from our scanner. This is worth a manual check: if the "
        "resource is decommissioned, this is a takeover-in-waiting."
    ),
    remediation=(
        "Verify that the resource at {cname_target} is still active "
        "and owned by your team. If it's decommissioned or unowned, "
        "remove the CNAME. If active, you can suppress this finding "
        "via the tuning UI."
    ),
    severity="medium",
    category="dns",
    cwe="CWE-284",
    tags=["subdomain-takeover", "cname-check"],
    summary="A CNAME on your domain points to a third-party service we couldn't verify — worth a manual check.",
    alert_name="Suspicious CNAME",
    monitor_type="dns_change",
    references=list(_TAKEOVER_REFS_COMMON),
))


# ───────────────────────────────────────────────────────────────────────────
# Cloud Asset Exposure
# ───────────────────────────────────────────────────────────────────────────
# Findings produced by the cloud_asset analyzer for storage buckets,
# container registries, serverless endpoints, and CDN-origin exposure.
#
# Provider-agnostic copy — the human-readable provider label (e.g.,
# "AWS S3", "Azure Blob Storage", "Google Cloud Storage") is rendered
# at scan time via the {provider} placeholder. Per-provider lockdown
# steps live inside each template's remediation so a Silver buyer with
# a multi-cloud surface can act regardless of where the finding came
# from.

# ── Storage Buckets ──

_r(FindingTemplate(
    template_id="cloud-storage-sensitive-files",
    title="Public {provider} bucket with sensitive files: {value}",
    description=(
        "The {provider} bucket {value} is publicly accessible and "
        "contains files whose names or extensions strongly suggest "
        "credentials, database dumps, configuration secrets, or "
        "customer data. Exposed buckets are scraped continuously — "
        "real incidents (Capital One, Accenture, Verizon, Twilio) "
        "started exactly this way. Treat any credential or key in "
        "this bucket as compromised from now."
    ),
    remediation=(
        "Treat this as an active incident: rotate credentials first, "
        "then lock the bucket down.\n\n"
        "**Rotate now**\n"
        "  Any AWS keys, database passwords, OAuth tokens, or signing "
        "keys that may be in the exposed files must be rotated before "
        "you close the door.\n\n"
        "**Lock down access**\n"
        "  • AWS S3 — enable account-level *Block Public Access* "
        "(S3 console → Block Public Access settings → Edit). Remove "
        "any `\"Principal\": \"*\"` from the bucket policy.\n"
        "  • Azure Blob Storage — set the storage account's *Allow "
        "Blob anonymous access* to *Disabled* and switch each "
        "container's access level to *Private*.\n"
        "  • Google Cloud Storage — remove `allUsers` and "
        "`allAuthenticatedUsers` from the bucket's IAM bindings.\n\n"
        "**Audit and harden**\n"
        "  Enable server-side encryption, turn on access logging, "
        "and review log history for unauthorised downloads since the "
        "bucket became public."
    ),
    severity="critical",
    category="cloud",
    cwe="CWE-552",
    tags=["cloud", "storage", "sensitive-data", "public-access"],
    summary="An exposed cloud bucket on your domain contains files that look like credentials, backups, or config — anyone can download them.",
    alert_name="Cloud Bucket — Sensitive Files",
    monitor_type="cloud_change",
    references=[
        "OWASP — Cloud-Native Application Security",
        "AWS — Blocking public access to your S3 storage",
        "Microsoft — Configure anonymous public read access for containers and blobs",
        "Google Cloud — Make data public",
    ],
))

_r(FindingTemplate(
    template_id="cloud-storage-listing-enabled",
    title="Public {provider} bucket with directory listing: {value}",
    description=(
        "The {provider} bucket {value} is publicly accessible with "
        "object listing enabled. Anyone can enumerate every object "
        "in the bucket and download them. This is one of the most "
        "common breach patterns on the public internet — automated "
        "scanners harvest exposed buckets within hours."
    ),
    remediation=(
        "**Disable listing and lock down access**\n"
        "  • AWS S3 — enable *Block Public Access* and remove any "
        "policy granting `s3:ListBucket` to `\"Principal\": \"*\"`.\n"
        "  • Azure Blob Storage — set the container's access level to "
        "*Private (no anonymous access)*.\n"
        "  • Google Cloud Storage — remove `roles/storage.objectViewer` "
        "and `roles/storage.legacyBucketReader` from `allUsers`.\n\n"
        "**Audit downloads**\n"
        "  Review server access logs (S3) / storage diagnostic logs "
        "(Azure) / data access audit logs (GCS) for the period the "
        "bucket has been public. Any object downloaded by an unknown "
        "principal should be treated as exfiltrated."
    ),
    severity="critical",
    category="cloud",
    cwe="CWE-548",
    tags=["cloud", "storage", "directory-listing", "public-access"],
    summary="A cloud bucket on your domain lists its contents publicly — anyone can browse and download every file in it.",
    alert_name="Cloud Bucket — Listing Enabled",
    monitor_type="cloud_change",
    references=[
        "AWS — Blocking public access to your S3 storage",
        "Microsoft — Set anonymous read access for containers and blobs",
        "Google Cloud — Make data public",
        "CWE-548: Exposure of Information Through Directory Listing",
    ],
))

_r(FindingTemplate(
    template_id="cloud-storage-public-access",
    title="Publicly accessible {provider} bucket: {value}",
    description=(
        "The {provider} bucket {value} allows public access. Object "
        "listing is not enabled, so attackers can't trivially "
        "enumerate the bucket — but any object whose name they can "
        "guess (or learn from logs, leaks, or referrer headers) is "
        "downloadable. Public buckets without listing are still a "
        "common source of backup-file and config-file leaks."
    ),
    remediation=(
        "**Decide whether public access is intentional**\n"
        "  Static-site assets, marketing PDFs, and product images "
        "are legitimate use cases. Anything else should be private.\n\n"
        "**If public access is required**\n"
        "  • Confirm no sensitive data is stored in the bucket — "
        "no backups, no `.env`, no internal docs, no PII.\n"
        "  • Enable access logging and review periodically.\n"
        "  • Consider serving content via CDN with origin auth so "
        "the bucket itself can stay private.\n\n"
        "**If public access is NOT required**\n"
        "  • AWS S3 — enable *Block Public Access* and remove "
        "`Principal: \"*\"` from the bucket policy.\n"
        "  • Azure Blob Storage — set anonymous access to *Disabled*.\n"
        "  • Google Cloud Storage — remove `allUsers` from IAM bindings."
    ),
    severity="high",
    category="cloud",
    cwe="CWE-732",
    tags=["cloud", "storage", "public-access"],
    summary="A cloud bucket on your domain is publicly readable — anyone who knows or guesses an object name can download it.",
    alert_name="Cloud Bucket — Public",
    monitor_type="cloud_change",
    references=[
        "AWS — Blocking public access to your S3 storage",
        "Microsoft — Configure anonymous public read access",
        "Google Cloud — Make data public",
    ],
))

_r(FindingTemplate(
    template_id="cloud-storage-private-tracked",
    title="{provider} bucket detected (private): {value}",
    description=(
        "The {provider} bucket {value} exists and is configured for "
        "private access. Recorded for inventory and change-detection — "
        "if the bucket later becomes public, the monitor will fire."
    ),
    remediation="No action required. Bucket access is correctly restricted.",
    severity="info",
    category="cloud",
    tags=["cloud", "storage", "inventory"],
    tunable=False,
    summary="A private cloud bucket on your domain — tracked so we'll notice if it later becomes public.",
    alert_name="Cloud Bucket — Inventory",
    monitor_type="cloud_change",
))

# ── Container Registries ──

_r(FindingTemplate(
    template_id="cloud-registry-public-images",
    title="Public {provider} with pullable images: {value}",
    description=(
        "The {provider} {value} allows unauthenticated access to "
        "container images. Public images frequently contain embedded "
        "secrets (API keys, database passwords baked into env files), "
        "source code, and proprietary build dependencies. Anyone with "
        "Docker installed can pull, inspect, and exfiltrate the "
        "contents within seconds. Continuously scraped by automated "
        "tooling looking for AWS/GCP credentials."
    ),
    remediation=(
        "**Treat as a credential incident first**\n"
        "  Pull each exposed image yourself, scan it for secrets "
        "(`gitleaks`, `trufflehog`, `docker scout secrets`), and "
        "rotate every credential, API key, or token that turns up. "
        "Assume any secret in a public image is already compromised.\n\n"
        "**Restrict the registry**\n"
        "  • Azure Container Registry — set *Admin user* off and "
        "require AAD authentication; private endpoints recommended.\n"
        "  • Google Container / Artifact Registry — remove `allUsers` "
        "from the IAM policy on the repository or registry.\n"
        "  • AWS ECR Public — move sensitive images to a private "
        "ECR repository; ECR Public is internet-readable by design.\n"
        "  • Docker Hub — flip each repository to *Private* (paid "
        "plans) or move to a private registry.\n\n"
        "**Prevent recurrence**\n"
        "  Add secret scanning to your image build pipeline so "
        "`.env`, `id_rsa`, and credential files never get baked in."
    ),
    severity="critical",
    category="cloud",
    cwe="CWE-200",
    tags=["cloud", "registry", "container", "public-access"],
    summary="A container registry on your domain is publicly pullable — images often contain embedded secrets and source code.",
    alert_name="Container Registry — Public Images",
    monitor_type="cloud_change",
    references=[
        "OWASP — Container Security Verification Standard",
        "Microsoft — Authenticate with an Azure container registry",
        "Google Cloud — Configure access control for Artifact Registry",
        "Docker — Repository visibility settings",
    ],
))

_r(FindingTemplate(
    template_id="cloud-registry-public-access",
    title="Public {provider} catalogue exposed: {value}",
    description=(
        "The {provider} {value} responds to unauthenticated catalogue "
        "queries. We didn't enumerate any images on this scan — the "
        "registry may be empty, paginated, or rate-limiting us — but "
        "the catalogue endpoint itself shouldn't be reachable without "
        "authentication. Once images are pushed, they'll be pullable "
        "by anyone."
    ),
    remediation=(
        "Require authentication on the registry's Docker V2 API "
        "(`/v2/`) endpoint. Most managed registries do this by "
        "default — if yours is public, check whether *Admin user* "
        "or anonymous pull is enabled and disable it. Don't rely "
        "on \"no images yet\" as a control."
    ),
    severity="high",
    category="cloud",
    cwe="CWE-306",
    tags=["cloud", "registry", "container", "public-access"],
    summary="A container registry catalogue on your domain is publicly accessible — anything pushed to it will be pullable.",
    alert_name="Container Registry — Public Catalog",
    monitor_type="cloud_change",
    references=[
        "OCI Distribution Spec — Authentication",
        "Microsoft — Authenticate with an Azure container registry",
    ],
))

_r(FindingTemplate(
    template_id="cloud-registry-private-tracked",
    title="{provider} detected (private): {value}",
    description=(
        "The {provider} {value} exists and requires authentication. "
        "Recorded for inventory and change-detection — if the "
        "registry later opens up, the monitor will fire."
    ),
    remediation="No action required. Registry access is correctly restricted.",
    severity="info",
    category="cloud",
    tags=["cloud", "registry", "container", "inventory"],
    tunable=False,
    summary="A private container registry on your domain — tracked so we'll notice if it later becomes public.",
    alert_name="Container Registry — Inventory",
    monitor_type="cloud_change",
))

# ── Serverless Endpoints ──

_r(FindingTemplate(
    template_id="cloud-serverless-config-leak",
    title="{provider} endpoint leaking configuration: {value}",
    description=(
        "The {provider} app {value} is publicly accessible without "
        "authentication and is returning content that looks like "
        "configuration data — environment variables, debug pages, "
        "framework error dumps, or response bodies containing keys. "
        "Leaked AWS / GCP / database credentials in serverless "
        "responses are routinely the entry point for full account "
        "compromise."
    ),
    remediation=(
        "**Rotate first**\n"
        "  Treat anything that appeared in the leaked content as "
        "compromised: AWS access keys, database passwords, OAuth "
        "client secrets, internal service tokens. Rotate before "
        "closing the leak — once rotated, attackers lose access "
        "even if they already exfiltrated the values.\n\n"
        "**Stop the leak**\n"
        "  • Azure Functions — set *Authentication* to required and "
        "configure an identity provider; ensure debug-mode env "
        "variables are off in production.\n"
        "  • Google Cloud Run — restrict invokers via IAM "
        "(`roles/run.invoker`); turn off detailed error traces in "
        "the runtime config.\n"
        "  • AWS Lambda — front the function with API Gateway and a "
        "JWT or IAM authoriser; never use anonymous Function URLs "
        "for production traffic.\n\n"
        "**Prevent recurrence**\n"
        "  Move all secrets out of environment variables and into a "
        "managed secret store (Key Vault, Secret Manager, AWS "
        "Secrets Manager); use managed identity to fetch them at "
        "runtime."
    ),
    severity="critical",
    category="cloud",
    cwe="CWE-215",
    tags=["cloud", "serverless", "config-leak", "public-access"],
    summary="A serverless endpoint on your domain is leaking configuration data — likely including credentials. Rotate now.",
    alert_name="Serverless — Config Leak",
    monitor_type="cloud_change",
    references=[
        "OWASP — Serverless Top 10",
        "Microsoft — Authentication and authorization in Azure App Service",
        "Google Cloud — Authenticating service-to-service",
        "AWS — Lambda function URLs and authorization",
    ],
))

_r(FindingTemplate(
    template_id="cloud-serverless-stack-trace",
    title="{provider} endpoint leaking stack traces: {value}",
    description=(
        "The {provider} app {value} is publicly accessible and "
        "returns full stack traces in error responses. The traces "
        "reveal internal file paths, dependency versions, and code "
        "structure — material that lets an attacker tailor exploits "
        "to the exact framework versions in use, and identify "
        "vulnerable dependencies that haven't been patched."
    ),
    remediation=(
        "Return generic error messages to clients in production; "
        "log the full stack trace server-side instead. Most "
        "frameworks have a single config switch:\n"
        "  • Express / Node — `NODE_ENV=production`.\n"
        "  • Django — `DEBUG = False`.\n"
        "  • Flask — `app.debug = False`.\n"
        "  • Spring Boot — `server.error.include-stacktrace=never`.\n"
        "  • ASP.NET — `<customErrors mode=\"On\"/>` or "
        "`UseExceptionHandler` middleware.\n\n"
        "Add authentication to the endpoint as well — a verbose-"
        "error config flag is a one-line miss away from regressing."
    ),
    severity="high",
    category="cloud",
    cwe="CWE-209",
    tags=["cloud", "serverless", "stack-trace", "public-access"],
    summary="A serverless endpoint on your domain returns full stack traces in error responses, exposing internal code paths.",
    alert_name="Serverless — Stack Trace Leak",
    monitor_type="cloud_change",
    references=[
        "OWASP — Improper Error Handling",
        "CWE-209: Generation of Error Message Containing Sensitive Information",
    ],
))

_r(FindingTemplate(
    template_id="cloud-serverless-no-auth",
    title="Unauthenticated {provider} endpoint: {value}",
    description=(
        "The {provider} app {value} is callable from the public "
        "internet without authentication. Even when the function "
        "doesn't leak data directly, public functions can expose "
        "business logic, allow data exfiltration via crafted "
        "inputs, and let third parties run up your compute bill."
    ),
    remediation=(
        "Add authentication appropriate to the platform:\n"
        "  • Azure Functions — set *Authentication* to required, or "
        "use function-level keys for machine-to-machine traffic.\n"
        "  • Google Cloud Run — make the service private and grant "
        "`roles/run.invoker` only to the identities that need it.\n"
        "  • AWS Lambda — replace anonymous Function URLs with API "
        "Gateway plus a JWT authoriser, or set `AuthType=AWS_IAM` "
        "on the Function URL.\n\n"
        "If the endpoint is intentionally public (webhook, signup "
        "form), ensure rate limiting and strict input validation are "
        "in place — public functions are often abused to amplify "
        "spam, brute-force credentials, or exhaust API quotas."
    ),
    severity="high",
    category="cloud",
    cwe="CWE-306",
    tags=["cloud", "serverless", "no-auth", "public-access"],
    summary="A serverless endpoint on your domain is callable without authentication — review whether that's intentional.",
    alert_name="Serverless — No Auth",
    monitor_type="cloud_change",
    references=[
        "OWASP — Serverless Top 10",
        "Microsoft — Authentication and authorization in Azure App Service",
        "Google Cloud — Authenticating service-to-service",
        "AWS — Lambda function URL invoke modes",
    ],
))

# ── CDN Origin Exposure ──

_r(FindingTemplate(
    template_id="cloud-cdn-origin-exposed",
    title="{provider} origin reachable, bypassing CDN: {value}",
    description=(
        "The domain {value} is fronted by {provider}, but its "
        "origin server appears to be directly reachable on the "
        "public internet. Attackers who learn the origin IP can "
        "bypass everything the CDN provides — WAF rules, rate "
        "limiting, DDoS mitigation, bot management — by hitting "
        "the origin host directly. Origin IPs are routinely "
        "discovered via SSL certificate transparency logs, Shodan "
        "history, header leaks, and stale DNS records."
    ),
    remediation=(
        "**Lock the origin firewall to the CDN's IP ranges**\n"
        "  • Cloudflare — accept traffic only from "
        "Cloudflare IP ranges (cloudflare.com/ips).\n"
        "  • CloudFront — use the AWS-managed prefix list "
        "`com.amazonaws.global.cloudfront.origin-facing` in your "
        "security group.\n"
        "  • Fastly / Azure CDN / Akamai — pull the published ASN "
        "or IP-range list from the vendor and restrict at the host "
        "or VPC firewall.\n\n"
        "**Remove direct exposure**\n"
        "  • Delete any DNS A records that point straight to the "
        "origin IP from public zones.\n"
        "  • Strip headers that may leak origin info: `X-Served-By`, "
        "`Via`, `X-Backend-Server`, `X-Real-IP` outbound.\n\n"
        "**Change the IP if it's been public**\n"
        "  Any origin IP that was reachable for any meaningful "
        "period should be rotated — adversary tools cache historical "
        "IPs aggressively."
    ),
    severity="high",
    category="cloud",
    cwe="CWE-1327",
    tags=["cloud", "cdn", "origin-exposure", "waf-bypass"],
    summary="The origin server behind your CDN looks reachable directly — attackers can bypass your WAF and rate limits.",
    alert_name="CDN — Origin Exposed",
    monitor_type="cloud_change",
    references=[
        "Cloudflare — Restoring original visitor IPs",
        "AWS — Restricting access to CloudFront origins",
        "Akamai — Site Shield",
    ],
))


# ───────────────────────────────────────────────────────────────────────────
# Sensitive Path / Leak Detection
# ───────────────────────────────────────────────────────────────────────────
# Findings produced by the leak analyzer when the engine probes the host
# for commonly-exposed files (.git, .env, SQL dumps, debug endpoints,
# etc.) and finds them publicly readable. One template per file family;
# the analyzer maps each probe path to its family template via
# PATH_TEMPLATE_MAP. {value} renders as the actual path that was
# accessible (e.g. /.env.production).
#
# A second group covers public-GitHub code-search hits (passwords,
# API keys, AWS creds, env files, etc. found in public repos that
# reference the asset).

_LEAK_REFS_FILE_EXPOSURE = [
    "OWASP WSTG — Review Old Backup and Unreferenced Files for Sensitive Information",
    "CWE-538: Insertion of Sensitive Information into Externally-Accessible File",
]
_LEAK_REFS_GITHUB = [
    "GitHub — About secret scanning",
    "OWASP Cheat Sheet — Secrets Management",
    "trufflesecurity/trufflehog (open-source secret scanning)",
]

# ── Sensitive path families ──

_r(FindingTemplate(
    template_id="leak-git-exposed",
    title="Git repository exposed at {asset} ({value})",
    description=(
        "The .git directory is publicly served from {asset}. The full "
        "commit history, including any secrets that were committed and "
        "later \"removed\", is reachable. Tools like `git-dumper` "
        "reconstruct the entire repo from this in under a minute, "
        "yielding source code, internal documentation, and credential "
        "history."
    ),
    remediation=(
        "**Block .git/ at the web server**\n"
        "  • nginx: `location ~ /\\.git { deny all; return 404; }`\n"
        "  • Apache: `RedirectMatch 404 /\\.git(/|$)`\n"
        "  • IIS: add a request-filtering rule for `/.git/`.\n\n"
        "**Treat exposed history as compromised**\n"
        "  Run a secret scanner (`gitleaks`, `trufflehog`) over the "
        "repo and rotate every credential that's ever been committed — "
        "even ones in `git rm`'d commits, since the history is now "
        "public.\n\n"
        "**Prevent recurrence**\n"
        "  Don't deploy a working copy to a public webroot. CI/CD "
        "should produce a build artefact and copy only that."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-538",
    tags=["exposed-file", "source_control", "git"],
    summary="The .git directory on {asset} is downloadable — anyone can reconstruct your full source code and commit history.",
    alert_name="Git Repo Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "git-dumper — repo reconstruction tool",
    ],
))

_r(FindingTemplate(
    template_id="leak-svn-exposed",
    title="Subversion metadata exposed at {asset} ({value})",
    description=(
        "The .svn metadata directory is publicly served from {asset}. "
        "Like exposed .git, this lets an attacker reconstruct the "
        "Subversion working copy — source code, prior revisions, and "
        "any credentials that were committed."
    ),
    remediation=(
        "Block `/.svn/` at the web server (nginx `deny all`, Apache "
        "`RedirectMatch 404`, IIS request filtering). Don't deploy a "
        "working copy to a public webroot — produce a build artefact "
        "instead. Rotate any credentials that may be in the repository "
        "history."
    ),
    severity="high",
    category="leak",
    cwe="CWE-538",
    tags=["exposed-file", "source_control", "svn"],
    summary="The .svn directory on {asset} is downloadable — your source code and history are reachable.",
    alert_name="SVN Metadata Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE),
))

_r(FindingTemplate(
    template_id="leak-env-file",
    title="Environment file exposed at {asset} ({value})",
    description=(
        "An environment file at {value} is publicly readable on "
        "{asset}. Environment files routinely contain database "
        "passwords, API keys for AWS / Stripe / Google / Twilio, "
        "OAuth client secrets, and signing keys — exactly the "
        "credentials an attacker needs for full account compromise."
    ),
    remediation=(
        "**Rotate first, then close the door**\n"
        "  Treat every credential in the file as compromised — assume "
        "automated scanners pulled it within minutes of exposure. "
        "Rotate AWS keys, database passwords, OAuth secrets, signing "
        "keys, and any third-party API tokens before doing anything "
        "else.\n\n"
        "**Block .env files at the web server**\n"
        "  • nginx: `location ~ /\\.env { deny all; return 404; }`\n"
        "  • Apache: `RedirectMatch 404 /\\.env`\n\n"
        "**Stop deploying secrets in files**\n"
        "  Move secrets into a managed store (AWS Secrets Manager, "
        "GCP Secret Manager, HashiCorp Vault, or your platform's "
        "equivalent) and inject them into the runtime as env vars at "
        "process start, not as files in the deploy bundle."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-200",
    tags=["exposed-file", "secrets", "env-file"],
    summary="An environment file on {asset} is publicly readable — its credentials should be considered compromised. Rotate now.",
    alert_name="Environment File Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "OWASP Cheat Sheet — Secrets Management",
    ],
))

_r(FindingTemplate(
    template_id="leak-ssh-private-key",
    title="SSH private key exposed at {asset} ({value})",
    description=(
        "An SSH private key at {value} is publicly readable on "
        "{asset}. Anyone who downloaded it can SSH into any system "
        "where the corresponding public key is authorised. This is a "
        "direct path to remote shell access on whatever the key opens."
    ),
    remediation=(
        "**Treat the key as compromised, immediately**\n"
        "  Identify every host where the corresponding public key "
        "appears in `~/.ssh/authorized_keys` (or in a managed key "
        "system / IAM). Remove the public key from all of them.\n\n"
        "**Generate a fresh keypair**\n"
        "  Use a modern algorithm (`ssh-keygen -t ed25519`) and "
        "distribute the new public key only to the systems that need "
        "it.\n\n"
        "**Block private-key files at the web server**\n"
        "  Deny `/id_rsa`, `/.ssh/`, `/*.pem`, `/*.key` paths at the "
        "edge so a single deploy mistake doesn't expose another key.\n\n"
        "**Audit access logs**\n"
        "  Review SSH and bastion logs for any successful auth that "
        "could have used the leaked key while it was reachable."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-200",
    tags=["exposed-file", "secrets", "ssh-key"],
    summary="An SSH private key on {asset} is publicly readable — assume any host that trusts the matching public key is compromised.",
    alert_name="SSH Key Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "OpenSSH — Best Practices",
    ],
))

_r(FindingTemplate(
    template_id="leak-package-creds",
    title="Package manager credentials exposed at {asset} ({value})",
    description=(
        "A package-manager configuration file at {value} is publicly "
        "readable on {asset}. Files like .npmrc and .pypirc commonly "
        "contain auth tokens for private package registries — leaking "
        "them lets an attacker push malicious package versions that "
        "your build pipeline will consume on the next install."
    ),
    remediation=(
        "Rotate the registry auth token immediately (npm: regenerate "
        "in npmjs.com → Access Tokens; PyPI: regenerate via "
        "pypi.org/manage/account/token). Block dotfiles at the web "
        "server (nginx `location ~ /\\.npmrc`, etc.). Don't commit "
        "auth files to the deploy bundle — inject the token at CI "
        "time via environment variables and clean it up after the "
        "publish step."
    ),
    severity="high",
    category="leak",
    cwe="CWE-522",
    tags=["exposed-file", "secrets", "package-manager"],
    summary="A package-manager auth file on {asset} is publicly readable — registry tokens should be rotated.",
    alert_name="Package Manager Creds Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "npm Docs — Access Tokens",
        "PyPI Help — API tokens",
    ],
))

_r(FindingTemplate(
    template_id="leak-htpasswd",
    title="Apache password file exposed at {asset} ({value})",
    description=(
        "The Apache .htpasswd file at {value} is publicly readable on "
        "{asset}. The hashes inside are crackable offline — "
        "GPU-accelerated tools can crunch through tens of millions "
        "of guesses per second against bcrypt or MD5-crypt hashes — "
        "turning a single misconfigured line in your Apache config "
        "into account takeover."
    ),
    remediation=(
        "Move the .htpasswd file outside the web root entirely "
        "(`/etc/apache2/.htpasswd` is conventional). Update your "
        "AuthUserFile directive to point at the new location. Block "
        "`/.htpasswd` at the server level as a defence-in-depth. "
        "Force a password reset for every user listed in the leaked "
        "file — assume the hashes are being cracked right now."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-522",
    tags=["exposed-file", "config", "htpasswd"],
    summary="Your Apache .htpasswd file is publicly readable — every account in it should be reset.",
    alert_name="htpasswd Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "Apache Docs — Authentication and Authorization",
    ],
))

_r(FindingTemplate(
    template_id="leak-htaccess",
    title="Apache .htaccess exposed at {asset} ({value})",
    description=(
        "An .htaccess file at {value} is publicly readable on {asset}. "
        "Itself it isn't a secret, but it often reveals rewrite rules, "
        "internal endpoints, basic-auth realms, IP allowlists, and "
        "other recon hints that tell an attacker where to focus."
    ),
    remediation=(
        "Block `.htaccess` at the web server: nginx already ignores "
        "it; Apache should set `<FilesMatch \"^\\.\">` to deny. The "
        "file's settings should still apply to the application — "
        "only the file content needs to be hidden."
    ),
    severity="medium",
    category="leak",
    cwe="CWE-538",
    tags=["exposed-file", "config", "htaccess"],
    summary="Your .htaccess file is publicly readable — recon material for attackers, not a direct breach.",
    alert_name=".htaccess Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE),
))

_r(FindingTemplate(
    template_id="leak-web-config",
    title="IIS web.config exposed at {asset} ({value})",
    description=(
        "The IIS web.config file at {value} is publicly readable on "
        "{asset}. IIS should never serve web.config — when it does, "
        "an attacker may see database connection strings (sometimes "
        "with passwords), encryption keys for ViewState / forms auth, "
        "and the full module pipeline."
    ),
    remediation=(
        "IIS blocks web.config by default via "
        "`<hiddenSegments>` in applicationHost.config — restore that "
        "setting. Move connection strings and other secrets out of "
        "web.config and into Azure Key Vault, environment variables, "
        "or `secrets.json` (development only). Rotate any credentials "
        "or machineKey values that were exposed."
    ),
    severity="high",
    category="leak",
    cwe="CWE-200",
    tags=["exposed-file", "config", "iis"],
    summary="Your IIS web.config is publicly readable — it may include database connection strings and machine keys.",
    alert_name="web.config Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "Microsoft — Hidden Segments in IIS",
    ],
))

_r(FindingTemplate(
    template_id="leak-wp-config-backup",
    title="WordPress config backup exposed at {asset} ({value})",
    description=(
        "A backup copy of wp-config.php (e.g. wp-config.php.bak, "
        "wp-config.php~, common when an editor saves a `.bak` "
        "alongside the file) is publicly readable on {asset}. PHP "
        "isn't executed for the .bak extension, so the file is "
        "served as plain text — exposing DB_NAME, DB_USER, "
        "DB_PASSWORD, AUTH_KEY, and other secrets."
    ),
    remediation=(
        "**Rotate first**\n"
        "  Treat the database password, auth keys, and any API keys "
        "in wp-config.php as compromised. Rotate the DB password "
        "immediately; regenerate AUTH_KEY/SECURE_AUTH_KEY/LOGGED_IN_KEY/"
        "NONCE_KEY and the four corresponding salts (use the WordPress "
        "salt generator).\n\n"
        "**Remove backup files from the webroot**\n"
        "  Delete every `*.bak`, `*~`, `*.orig`, `*.old` file from "
        "the webroot. Add a deny rule at the web server for those "
        "extensions so editor-save patterns can't recreate the "
        "exposure.\n\n"
        "**Audit for further compromise**\n"
        "  Review wp-content/uploads for unfamiliar PHP files, and "
        "the wp_users table for unexpected admin accounts."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-552",
    tags=["exposed-file", "config", "wordpress"],
    summary="A WordPress wp-config backup is publicly readable on {asset} — DB credentials and auth keys should be rotated now.",
    alert_name="WordPress Config Backup Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "WordPress — Editing wp-config.php",
        "WordPress.org — Salt Generator",
    ],
))

_r(FindingTemplate(
    template_id="leak-wp-installer",
    title="WordPress installer accessible at {asset} ({value})",
    description=(
        "WordPress's install.php is reachable on {asset}. If the site "
        "isn't already initialised, an attacker can complete the "
        "install with their own admin credentials and database "
        "configuration — taking ownership of the site outright. Even "
        "on an initialised site, the installer leaks version "
        "information."
    ),
    remediation=(
        "Block /wp-admin/install.php at the web server until the "
        "install is complete, then keep it blocked: "
        "`location = /wp-admin/install.php { deny all; }` (nginx) or "
        "an equivalent Apache rule. Confirm the wp-admin/ login page "
        "redirects to the dashboard — if it shows the installer "
        "form, the site has been re-initialised by an attacker; "
        "restore from backup."
    ),
    severity="high",
    category="leak",
    cwe="CWE-1188",
    tags=["exposed-file", "config", "wordpress"],
    summary="WordPress installer is reachable on {asset} — confirm the site hasn't been re-initialised by an attacker.",
    alert_name="WordPress Installer Accessible",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "WordPress — Hardening WordPress",
    ],
))

_r(FindingTemplate(
    template_id="leak-sql-dump",
    title="SQL database dump exposed at {asset} ({value})",
    description=(
        "A SQL dump file at {value} is publicly downloadable from "
        "{asset}. Database dumps typically contain every row in "
        "every table at the moment of export — user accounts (often "
        "with hashed passwords), session data, payment records, "
        "internal admin notes. Exposed dumps are routinely the "
        "starting point of regulator-reportable breaches."
    ),
    remediation=(
        "**Treat as a confirmed data breach**\n"
        "  Assume the dump has been downloaded — automated scanners "
        "harvest exposed `.sql` files within minutes. Engage your "
        "incident-response process: notify your privacy officer / "
        "DPO, scope the data classes involved (PII, payment, health, "
        "auth material), and start your jurisdictional breach-"
        "notification clock.\n\n"
        "**Remove and block**\n"
        "  Delete the dump from the webroot. Block `*.sql`, `*.dump`, "
        "`*.bak.sql`, `backup-*` patterns at the web server.\n\n"
        "**Reset auth material**\n"
        "  Force a password reset for every user account in the "
        "dump; rotate any API keys or session-signing keys that "
        "were in the database; invalidate every session token "
        "issued before the dump was first reachable."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-552",
    tags=["exposed-file", "data_leak", "sql-dump"],
    summary="A SQL database dump is publicly downloadable from {asset} — treat as a confirmed breach. Notify and reset.",
    alert_name="SQL Dump Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "OAIC — Notifiable Data Breaches scheme (Australia)",
        "ICO — Personal data breaches (UK)",
    ],
))

_r(FindingTemplate(
    template_id="leak-phpinfo",
    title="phpinfo() exposed at {asset} ({value})",
    description=(
        "A phpinfo() page is reachable at {value} on {asset}. The "
        "page reveals the PHP version (mappable to known CVEs), every "
        "loaded module, full server environment variables, file "
        "system paths, and INI settings — high-value reconnaissance "
        "that lets an attacker pinpoint exploitable versions."
    ),
    remediation=(
        "Delete the phpinfo file. It's almost always a debug artefact "
        "left over from a deploy or troubleshooting session — there's "
        "no production use case for serving it. Add a deny rule for "
        "`phpinfo.php` and similar diagnostic filenames at the web "
        "server."
    ),
    severity="high",
    category="leak",
    cwe="CWE-200",
    tags=["exposed-file", "info_leak", "phpinfo"],
    summary="A phpinfo() page is exposed on {asset} — delete it; it's a recon goldmine.",
    alert_name="phpinfo Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "OWASP WSTG — Test for Information Exposure",
    ],
))

_r(FindingTemplate(
    template_id="leak-apache-status",
    title="Apache server status / info exposed at {asset} ({value})",
    description=(
        "Apache mod_status / mod_info output is publicly reachable at "
        "{value}. The page lists active connections (with client "
        "IPs and the URLs they're requesting), child worker state, "
        "loaded modules, and configuration directives — live "
        "intelligence about who's using your site and how the server "
        "is wired."
    ),
    remediation=(
        "Restrict /server-status and /server-info to localhost or "
        "your monitoring network:\n"
        "```\n"
        "<Location \"/server-status\">\n"
        "  SetHandler server-status\n"
        "  Require ip 127.0.0.1\n"
        "</Location>\n"
        "```\n"
        "Better, disable mod_status entirely if you have a separate "
        "metrics pipeline (Prometheus exporter, Datadog, etc.)."
    ),
    severity="high",
    category="leak",
    cwe="CWE-200",
    tags=["exposed-file", "info_leak", "apache"],
    summary="Apache server-status / server-info is publicly reachable on {asset} — it leaks live request info to anyone who looks.",
    alert_name="Apache Status Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "Apache Docs — mod_status",
    ],
))

_r(FindingTemplate(
    template_id="leak-api-docs",
    title="API documentation exposed at {asset} ({value})",
    description=(
        "An OpenAPI / Swagger documentation endpoint is reachable at "
        "{value} on {asset}. Public API docs are intentional for "
        "many products — but if this endpoint describes internal "
        "or admin APIs, you've handed an attacker a complete map of "
        "every endpoint, method, parameter, and response shape, "
        "including ones you didn't intend to expose."
    ),
    remediation=(
        "Decide whether the docs are intentionally public:\n"
        "  • **Public docs** (e.g., a developer portal) — leave them, "
        "but ensure they describe only the public API surface. "
        "Generate from source so admin endpoints can't accidentally "
        "leak.\n"
        "  • **Internal docs** — restrict to authenticated users, or "
        "to your VPN / private network. Most API frameworks expose a "
        "config flag (`springdoc.api-docs.enabled=false` for Spring; "
        "`SWAGGER_UI=False` in Django REST; mount behind auth in "
        "FastAPI/Express)."
    ),
    severity="medium",
    category="leak",
    cwe="CWE-200",
    tags=["exposed-file", "info_leak", "api-docs"],
    summary="API documentation is publicly accessible on {asset} — verify whether this is intentional.",
    alert_name="API Docs Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "OWASP API Security Top 10",
    ],
))

_r(FindingTemplate(
    template_id="leak-docker-compose",
    title="docker-compose.yml exposed at {asset} ({value})",
    description=(
        "A docker-compose.yml file at {value} is publicly readable "
        "on {asset}. The file describes service architecture, "
        "container images, environment variables, internal port "
        "wiring, and frequently — by accident — secrets baked into "
        "`environment:` blocks (database passwords, API keys, JWT "
        "signing secrets)."
    ),
    remediation=(
        "**Rotate any secrets that appear in the file**\n"
        "  Treat values inside `environment:` as compromised; rotate "
        "before doing anything else.\n\n"
        "**Block YAML files at the web server**\n"
        "  Deny `/*.yml`, `/*.yaml`, `/Dockerfile`, "
        "`/docker-compose*`. These should never be in a webroot.\n\n"
        "**Move secrets out of compose**\n"
        "  Use Docker secrets, Compose's `secrets:` block, or a "
        "managed secret store (Vault, Doppler, AWS Secrets Manager) "
        "and reference them by name rather than embedding values."
    ),
    severity="high",
    category="leak",
    cwe="CWE-538",
    tags=["exposed-file", "config", "docker"],
    summary="A docker-compose.yml is publicly readable on {asset} — it likely contains environment secrets that should be rotated.",
    alert_name="docker-compose Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "Docker Docs — Manage sensitive data with Docker secrets",
    ],
))

_r(FindingTemplate(
    template_id="leak-dockerfile",
    title="Dockerfile exposed at {asset} ({value})",
    description=(
        "A Dockerfile at {value} is publicly readable on {asset}. "
        "It reveals the base image, exact build steps, file paths, "
        "and dependency list — and occasionally hardcoded "
        "credentials, registry tokens, or signing keys baked into "
        "the build."
    ),
    remediation=(
        "Don't deploy Dockerfiles to a public webroot — produce a "
        "build artefact and copy only that. Block `/Dockerfile` at "
        "the web server. Audit the file for any hardcoded secrets "
        "(`ARG TOKEN=...`, `ENV API_KEY=...`) and rotate them; "
        "future builds should pull secrets at build time via "
        "`--secret` mounts rather than baking them into the image."
    ),
    severity="medium",
    category="leak",
    cwe="CWE-200",
    tags=["exposed-file", "config", "docker"],
    summary="A Dockerfile is publicly readable on {asset} — it leaks build details and may contain hardcoded credentials.",
    alert_name="Dockerfile Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE) + [
        "Docker Docs — Build secrets",
    ],
))

_r(FindingTemplate(
    template_id="leak-package-manifest",
    title="Package manifest exposed at {asset} ({value})",
    description=(
        "A package manifest (package.json, composer.json) at {value} "
        "is publicly readable on {asset}. The exposure isn't "
        "directly exploitable, but the manifest reveals every "
        "dependency and version — which lets an attacker run a "
        "vulnerability-database lookup against your full dependency "
        "tree without lifting a finger."
    ),
    remediation=(
        "Don't ship the source-tree manifest into a public webroot — "
        "production builds shouldn't have package.json or "
        "composer.json reachable. If you really need to expose "
        "version info (some dev consoles do), publish a "
        "deliberately-curated subset rather than the raw file."
    ),
    severity="low",
    category="leak",
    cwe="CWE-200",
    tags=["exposed-file", "info_leak", "manifest"],
    summary="A package manifest is publicly readable on {asset} — your full dependency list is visible to attackers.",
    alert_name="Package Manifest Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE),
))

_r(FindingTemplate(
    template_id="leak-ds-store",
    title=".DS_Store exposed at {asset} ({value})",
    description=(
        "A macOS .DS_Store file at {value} is publicly readable on "
        "{asset}. The binary file lists every file and folder in "
        "the directory it was created from — a quick way for an "
        "attacker to discover hidden filenames the directory "
        "listing wouldn't otherwise show. Often a sign that the "
        "site was deployed by drag-and-drop from a Mac."
    ),
    remediation=(
        "Delete .DS_Store files from the webroot. Add `.DS_Store` "
        "to your deploy ignore list and to .gitignore. Block the "
        "filename at the web server as a defence in depth. Run "
        "`find . -name .DS_Store -delete` over the deploy artefact "
        "before publishing."
    ),
    severity="low",
    category="leak",
    cwe="CWE-538",
    tags=["exposed-file", "info_leak", "macos"],
    summary="A .DS_Store file on {asset} reveals the names of files in the directory — minor recon win for attackers.",
    alert_name=".DS_Store Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE),
))

# ── Generic fallback for any sensitive path not covered above ──

_r(FindingTemplate(
    template_id="leak-path",
    title="Sensitive path exposed at {asset}: {value}",
    description=(
        "The path {value} is publicly readable on {asset} and matches "
        "a sensitive-path pattern (config file, backup, debug "
        "endpoint, or similar). The contents may include credentials, "
        "configuration, or material that aids reconnaissance."
    ),
    remediation=(
        "Confirm what the file contains and whether it's intended to "
        "be public. If it's not, remove it from the webroot and add "
        "a deny rule at the web server. If any credentials, keys, "
        "or session-signing material were in the file, rotate them "
        "before closing the door — assume automated scanners "
        "captured the contents."
    ),
    severity="medium",
    category="leak",
    cwe="CWE-200",
    tags=["exposed-file"],
    summary="A sensitive path is publicly readable on {asset} — review and remove or restrict.",
    alert_name="Sensitive Path Exposed",
    monitor_type="path_change",
    references=list(_LEAK_REFS_FILE_EXPOSURE),
))

# ── GitHub code-search leaks ──

_r(FindingTemplate(
    template_id="leak-github-credentials",
    title="Credentials referencing {asset} found in public GitHub code",
    description=(
        "Public-GitHub code search returned matches for password / "
        "credential / SMTP / JDBC patterns alongside references to "
        "{asset}. This often means a developer committed a secret "
        "into a public repository — the credential may already be "
        "in attacker-run scanners that harvest GitHub continuously."
    ),
    remediation=(
        "**Verify and rotate**\n"
        "  Open each matching file. If a real credential is present, "
        "rotate it immediately — assume it's already been "
        "exfiltrated by automation that monitors public-repo pushes.\n\n"
        "**Get the leak removed**\n"
        "  Ask the repo owner to remove the file and rewrite history "
        "(`git filter-repo` or BFG). A simple `git rm` doesn't help — "
        "the credential remains in the commit history. If the repo "
        "is yours, rewrite history; if it's a third party, contact "
        "them or use GitHub's content-removal process.\n\n"
        "**Prevent recurrence**\n"
        "  Enable GitHub's secret scanning + push protection on all "
        "your orgs. Add `gitleaks` or `trufflehog` to the CI pipeline "
        "as a pre-merge gate."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-200",
    tags=["github-leak", "credentials", "code-search"],
    summary="Code search found credentials referencing {asset} in public GitHub repos — verify and rotate any real secrets.",
    alert_name="GitHub — Credentials Leaked",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITHUB),
))

_r(FindingTemplate(
    template_id="leak-github-api-key",
    title="API keys referencing {asset} found in public GitHub code",
    description=(
        "Public-GitHub code search returned matches for API key / "
        "secret key / token patterns alongside references to "
        "{asset}. API keys leaked into public code are routinely "
        "abused within hours — for spam, crypto-mining via the "
        "compromised account, data exfiltration, or as a stepping "
        "stone to broader compromise."
    ),
    remediation=(
        "Open each matching file and confirm whether a real API key "
        "is present. If it is, rotate it immediately at the issuing "
        "service (AWS console / Stripe dashboard / Twilio account "
        "keys / etc.). Review the API's usage logs since the leak "
        "for any abuse. Get the file removed from the repo and "
        "rewrite history with `git filter-repo`. Enable secret "
        "scanning + push protection on your GitHub orgs to catch "
        "the next one before it pushes."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-798",
    tags=["github-leak", "api-key", "code-search"],
    summary="Code search found API keys referencing {asset} in public GitHub repos — rotate and audit usage.",
    alert_name="GitHub — API Key Leaked",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITHUB),
))

_r(FindingTemplate(
    template_id="leak-github-cloud-creds",
    title="Cloud credentials referencing {asset} found in public GitHub code",
    description=(
        "Public-GitHub code search returned matches for AWS / GCP / "
        "Azure credential patterns alongside references to {asset}. "
        "Cloud credentials in public code are the most aggressively "
        "harvested type — Trufflehog-style scanners poll GitHub's "
        "events API constantly, and exposed AWS keys are typically "
        "abused for crypto-mining within minutes."
    ),
    remediation=(
        "**Treat as an active incident**\n"
        "  Rotate the cloud credentials immediately at the provider:\n"
        "  • AWS — IAM → Access Keys → Make inactive, then delete; "
        "audit CloudTrail for the key's recent activity.\n"
        "  • GCP — IAM → Service Accounts → revoke the key; review "
        "Audit Logs.\n"
        "  • Azure — App registrations / managed identities → "
        "rotate the secret; review Sign-in logs.\n\n"
        "**Scope the impact**\n"
        "  Use the cloud provider's audit logs to confirm whether the "
        "key was used by an unknown principal during the leak window. "
        "If it was, escalate to a full IR.\n\n"
        "**Prevent recurrence**\n"
        "  Use short-lived credentials wherever possible (IAM roles, "
        "Workload Identity, managed identities) instead of static "
        "access keys. Enable GitHub secret scanning + push protection."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-798",
    tags=["github-leak", "cloud-creds", "code-search"],
    summary="Code search found cloud credentials referencing {asset} in public GitHub repos — rotate now and audit cloud activity.",
    alert_name="GitHub — Cloud Creds Leaked",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITHUB) + [
        "AWS — What to do if you inadvertently expose an AWS access key",
    ],
))

_r(FindingTemplate(
    template_id="leak-github-secrets",
    title="Private keys referencing {asset} found in public GitHub code",
    description=(
        "Public-GitHub code search returned matches for private-key "
        "material (RSA / EC / OpenSSH / PGP private blocks) alongside "
        "references to {asset}. Whatever the key authenticates to — "
        "SSH access, code-signing, certificate issuance, JWT signing — "
        "should now be considered compromised."
    ),
    remediation=(
        "Identify what the key authenticates and revoke it: remove "
        "the public key from authorized_keys (SSH); revoke the "
        "certificate (code-signing, TLS); rotate the JWT signing "
        "secret. Generate a fresh keypair and distribute the new "
        "public component only to systems that need it. Get the "
        "private key removed from the public repository and rewrite "
        "history. Enable GitHub secret scanning."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-200",
    tags=["github-leak", "secrets", "private-key", "code-search"],
    summary="Code search found private keys referencing {asset} in public GitHub repos — revoke and rotate immediately.",
    alert_name="GitHub — Private Key Leaked",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITHUB),
))

_r(FindingTemplate(
    template_id="leak-github-env-file",
    title=".env files referencing {asset} found in public GitHub code",
    description=(
        ".env files referencing {asset} were found in public-GitHub "
        "code search results. Environment files committed to public "
        "repos are a well-known pattern — they typically contain "
        "database credentials, API keys, and OAuth secrets in their "
        "production form."
    ),
    remediation=(
        "Open each matching file. Treat every credential inside as "
        "compromised — rotate database passwords, API keys, OAuth "
        "secrets, signing keys, and any third-party tokens. Have "
        "the .env file removed from the repository and rewrite "
        "history with `git filter-repo`. Add `.env` to .gitignore "
        "going forward and enable GitHub's secret scanning so the "
        "next push that includes a .env is blocked at PR time."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-200",
    tags=["github-leak", "env-file", "code-search"],
    summary="Code search found .env files referencing {asset} in public GitHub repos — rotate every secret inside.",
    alert_name="GitHub — .env Leaked",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITHUB),
))

_r(FindingTemplate(
    template_id="leak-github-config",
    title="Config files referencing {asset} found in public GitHub code",
    description=(
        "Public-GitHub code search returned config files (json, yaml, "
        "ini, conf) referencing {asset}. Config files don't always "
        "contain secrets, but they routinely leak internal hostnames, "
        "API endpoints, ports, ACL rules, and other reconnaissance "
        "material that helps an attacker map your environment."
    ),
    remediation=(
        "Open each matching file and confirm what's exposed. If real "
        "credentials are present, rotate. If only configuration "
        "metadata is exposed, decide whether it should be public — "
        "internal hostnames and endpoint lists are sometimes "
        "deliberately published, but more often they're an oversight. "
        "Have the file removed from the repo if it's an oversight."
    ),
    severity="medium",
    category="leak",
    cwe="CWE-200",
    tags=["github-leak", "config", "code-search"],
    summary="Code search found config files referencing {asset} in public GitHub repos — review for credential or topology leaks.",
    alert_name="GitHub — Config Leaked",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITHUB),
))


# ───────────────────────────────────────────────────────────────────────────
# Leaks — GitLab Code Search (parallel to GitHub family)
# ───────────────────────────────────────────────────────────────────────────
# Mirrors the GitHub leak templates. Distinct so the user-facing copy
# accurately names the source (GitLab vs GitHub) — same triage flow,
# different remediation steps because GitLab's takedown process and
# code-removal UX differ from GitHub's.

_LEAK_REFS_GITLAB = (
    "GitLab — Removing sensitive data from a repository",
    "OWASP Application Security Verification Standard — Secrets Management",
    "CIS Critical Security Controls — v8 Control 4 (Secure Configuration)",
)

_r(FindingTemplate(
    template_id="leak-gitlab-credentials",
    title="Credentials referencing {asset} found in public GitLab code",
    description=(
        "Public-GitLab blob search returned files referencing {asset} "
        "alongside what looks like credential material (passwords, "
        "DB_PASSWORD-style env strings). Code search alone can't "
        "confirm a true leak — the matched files might use the keyword "
        "in a different context — but every match is worth opening "
        "and verifying. Real credential exposure on a public GitLab "
        "project means an attacker can copy/paste the secret straight "
        "into a working session."
    ),
    remediation=(
        "Open each matching file linked in the finding details and "
        "verify whether a real credential is present. If yes, rotate "
        "the credential immediately and revoke any tokens it grants. "
        "Then have the file removed: GitLab keeps full history, so "
        "deleting the current copy isn't enough — use `git filter-repo` "
        "or BFG Repo-Cleaner to scrub history, then force-push. If the "
        "repository belongs to someone else, contact the project owner "
        "or use GitLab's abuse-reporting form to request takedown."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-798",
    tags=["gitlab-leak", "credentials", "code-search"],
    summary="Public GitLab code search returned files referencing {asset} that may contain credentials — open each match and rotate any real secrets.",
    alert_name="GitLab — Credentials Possibly Leaked",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITLAB),
))

_r(FindingTemplate(
    template_id="leak-gitlab-api-key",
    title="API tokens referencing {asset} found in public GitLab code",
    description=(
        "Public-GitLab blob search returned files referencing {asset} "
        "alongside identifiers that look like API tokens or keys. "
        "Some matches will be false positives (variable names, "
        "comments, fixtures), but each one needs eyes on it because a "
        "single live key can hand attackers full programmatic access "
        "to your service."
    ),
    remediation=(
        "Open each matching file and check whether a real token is "
        "present. If yes, revoke or rotate the token at the issuing "
        "service immediately, then scrub the file from the project's "
        "git history (deleting the current commit isn't enough — "
        "history retains the value). Notify the project owner if the "
        "repository isn't yours."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-798",
    tags=["gitlab-leak", "api-key", "code-search"],
    summary="Public GitLab code search returned API tokens referencing {asset} — verify each match and rotate immediately if real.",
    alert_name="GitLab — API Token Possibly Leaked",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITLAB),
))

_r(FindingTemplate(
    template_id="leak-gitlab-cloud-creds",
    title="Cloud credentials referencing {asset} found in public GitLab code",
    description=(
        "Public-GitLab blob search returned files referencing {asset} "
        "alongside cloud-credential strings (AWS_SECRET_ACCESS_KEY, "
        "GCP service-account JSON, Azure shared keys). Cloud "
        "credentials are among the highest-impact leaks — a working "
        "key can cost five to six figures within hours via crypto "
        "mining or data exfiltration."
    ),
    remediation=(
        "Treat this as same-day work. Verify whether a real credential "
        "is present in each match. If yes:\n"
        "  1. Rotate the credential at the cloud provider IMMEDIATELY.\n"
        "  2. Audit the cloud account for unauthorised activity since "
        "     the file's commit date.\n"
        "  3. Scrub the file from project history.\n"
        "  4. Configure git pre-commit hooks (gitleaks, detect-secrets) "
        "     to block future commits."
    ),
    severity="critical",
    category="leak",
    cwe="CWE-798",
    tags=["gitlab-leak", "cloud-creds", "aws", "gcp", "azure"],
    summary="Public GitLab code search returned cloud-credential strings referencing {asset} — rotate at the cloud provider TODAY if real.",
    alert_name="GitLab — Cloud Credentials Possibly Leaked",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITLAB),
))

_r(FindingTemplate(
    template_id="leak-gitlab-secrets",
    title="Secret-like strings referencing {asset} found in public GitLab code",
    description=(
        "Public-GitLab blob search returned files referencing {asset} "
        "alongside the keyword 'secret'. Many of these will be config "
        "constants or comments rather than real secrets, but each "
        "match should be opened and verified."
    ),
    remediation=(
        "Open each matching file and check whether a real secret is "
        "present. Rotate any live values, scrub the file from git "
        "history, and add pre-commit secret-scanning to the repository."
    ),
    severity="high",
    category="leak",
    cwe="CWE-200",
    tags=["gitlab-leak", "secrets", "code-search"],
    summary="Public GitLab code search returned secret-like strings referencing {asset} — verify each match.",
    alert_name="GitLab — Secret-Like String Found",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITLAB),
))

_r(FindingTemplate(
    template_id="leak-gitlab-env-file",
    title="Environment files referencing {asset} found in public GitLab code",
    description=(
        "Public-GitLab blob search returned `.env` files referencing "
        "{asset}. Environment files routinely contain database "
        "passwords, API keys, OAuth secrets, and other "
        "production-critical material. A `.env` published to a public "
        "repo is one of the highest-impact leak categories."
    ),
    remediation=(
        "Open each matching `.env` file and review every line. Rotate "
        "every real credential, scrub the file from git history, and "
        "add `.env*` to `.gitignore` going forward. Configure a "
        "pre-commit hook to block future `.env` commits."
    ),
    severity="high",
    category="leak",
    cwe="CWE-200",
    tags=["gitlab-leak", "env-file", "code-search"],
    summary="Public GitLab code search returned .env files referencing {asset} — assume credentials inside are leaked and rotate.",
    alert_name="GitLab — .env File Leaked",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITLAB),
))

_r(FindingTemplate(
    template_id="leak-gitlab-config",
    title="Config files referencing {asset} found in public GitLab code",
    description=(
        "Public-GitLab blob search returned config files (json, yaml, "
        "ini, conf) referencing {asset}. Config files don't always "
        "contain secrets, but they often leak internal hostnames, API "
        "endpoints, ports, and ACL rules that help an attacker map "
        "your environment."
    ),
    remediation=(
        "Open each matching file and confirm what's exposed. If real "
        "credentials are present, rotate. If only configuration "
        "metadata is exposed, decide whether it should be public — "
        "internal hostnames and endpoint lists are sometimes "
        "deliberately published, but more often they're an oversight. "
        "Have the file removed from the project if it's an oversight."
    ),
    severity="medium",
    category="leak",
    cwe="CWE-200",
    tags=["gitlab-leak", "config", "code-search"],
    summary="Code search found config files referencing {asset} in public GitLab projects — review for credential or topology leaks.",
    alert_name="GitLab — Config Leaked",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITLAB),
))


# ───────────────────────────────────────────────────────────────────────────
# Nuclei — Marquee CVEs (Batch D1)
# ───────────────────────────────────────────────────────────────────────────
# Curated copy for the high-impact CVEs that customers recognise by
# name. Each template is keyed `nuclei-cve-YYYY-NNNNN`; the registry's
# prefix-matcher resolves Nuclei's longer template IDs (e.g.,
# `cve-2021-44228-apache-log4j-rce`) onto the short ID.
#
# Architectural note: Nuclei runs the full upstream template library
# at scan time, so detection coverage doesn't depend on this list. What
# this list does is upgrade the customer-facing copy from "Nuclei
# template fired" to a real, polished finding. Templates not in this
# list fall through to Nuclei's own metadata via the generic
# `nuclei-uncategorized` template (registered in batch D6).

_NUCLEI_REFS_NVD = "NIST NVD — CVE detail"
_NUCLEI_REFS_MITRE = "MITRE CVE Database"


def _nuclei_cve(
    *,
    cve_id: str,
    short: str,
    severity: str,
    description: str,
    impact: str,
    remediation: str,
    cwe: str = "CWE-1395",
    extra_refs: list[str] | None = None,
    tags: list[str] | None = None,
) -> FindingTemplate:
    """Build a curated Nuclei CVE template.

    `cwe` defaults to CWE-1395 (Dependency on Vulnerable Third-Party
    Component) which fits most CVE-driven findings. Override for
    specific weakness types (CWE-77 command injection, CWE-22 path
    traversal, CWE-287 broken auth, etc.) where the underlying
    weakness is well-known.
    """
    cve_lower = cve_id.lower()
    template_id = f"nuclei-{cve_lower}"
    full_description = (
        description.rstrip() + "\n\n" +
        "**Real-world exploitation**\n" +
        impact.rstrip()
    )
    return FindingTemplate(
        template_id=template_id,
        title=f"{cve_id}: {short} on {{asset}}",
        description=full_description,
        remediation=remediation,
        severity=severity,
        category="cve",
        cwe=cwe,
        tags=["nuclei", "cve", cve_lower] + (tags or []),
        summary=f"{cve_id} — {short} — detected on {{asset}}. Patch immediately.",
        alert_name=f"CVE — {cve_id}",
        monitor_type="vuln_change",
        references=[
            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
        ] + (extra_refs or []),
    )


# ─── Auth bypass / direct RCE on internet-facing services ─────────────────

_r(_nuclei_cve(
    cve_id="CVE-2021-44228",
    short="Log4Shell — Apache Log4j RCE",
    severity="critical",
    cwe="CWE-502",
    description=(
        "Apache Log4j 2.x (versions 2.0-beta9 through 2.14.1) allows "
        "remote code execution via the JNDI lookup feature. Any string "
        "logged by Log4j that contains a `${jndi:ldap://...}` payload "
        "triggers remote class loading and arbitrary code execution "
        "in the JVM."
    ),
    impact=(
        "Mass-exploited from December 2021 onward — ransomware crews, "
        "cryptojacking botnets, and state-affiliated actors all "
        "incorporated Log4Shell into their toolkits within hours of "
        "disclosure. Any internet-facing Java application that logged "
        "user-controlled input (User-Agent, X-Forwarded-For, search "
        "fields, login forms) was at risk."
    ),
    remediation=(
        "**Upgrade**\n"
        "  Move to Log4j 2.17.1 or later — earlier 2.x patches missed "
        "follow-up issues (CVE-2021-45046, CVE-2021-45105, "
        "CVE-2021-44832).\n\n"
        "**If you can't upgrade today**\n"
        "  Set `log4j2.formatMsgNoLookups=true` or remove the "
        "`JndiLookup` class from the classpath:\n"
        "  `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`\n\n"
        "**Audit for compromise**\n"
        "  Search outbound connection logs for traffic to "
        "attacker-controlled LDAP/RMI hosts since 2021-12-09. Many "
        "incident responders have found post-exploitation persistence "
        "from this period that's still active."
    ),
    extra_refs=[
        "Apache Log4j Security Advisory",
        "CISA — Apache Log4j Vulnerability Guidance",
    ],
    tags=["rce", "java", "log4j"],
))

_r(_nuclei_cve(
    cve_id="CVE-2021-45046",
    short="Log4j 2.15 mitigation bypass",
    severity="critical",
    cwe="CWE-502",
    description=(
        "The Log4j 2.15 release intended to fix Log4Shell still "
        "allowed remote code execution under certain non-default "
        "configurations. Lookups in Thread Context Map values "
        "remained exploitable."
    ),
    impact=(
        "Released alongside Log4Shell scanning campaigns — adversaries "
        "who'd already weaponised Log4j tooling pivoted to this "
        "secondary issue within days. Upgrading to 2.15 was not enough."
    ),
    remediation=(
        "Upgrade to Log4j 2.17.1 or later. Don't stop at 2.15 or "
        "2.16 — they each had follow-up issues."
    ),
    tags=["rce", "java", "log4j"],
))

_r(_nuclei_cve(
    cve_id="CVE-2021-45105",
    short="Log4j 2.16 DoS via recursive lookup",
    severity="medium",
    cwe="CWE-674",
    description=(
        "Log4j 2.16 was vulnerable to a denial-of-service condition "
        "when self-referential lookups in the Thread Context Map "
        "caused infinite recursion."
    ),
    impact=(
        "Less severe than the earlier RCE issues but still affected "
        "production stability — exploitable by anyone who could "
        "influence logged data."
    ),
    remediation=(
        "Upgrade to Log4j 2.17.1 or later."
    ),
    tags=["dos", "java", "log4j"],
))

_r(_nuclei_cve(
    cve_id="CVE-2022-22965",
    short="Spring4Shell — Spring Framework RCE",
    severity="critical",
    cwe="CWE-915",
    description=(
        "Spring Framework's data-binding mechanism allowed an attacker "
        "to manipulate the application class loader, write a malicious "
        "JSP file to disk, and execute arbitrary code on the server "
        "(JDK 9+ on Tomcat with Spring MVC/WebFlux)."
    ),
    impact=(
        "Public proof-of-concept released within hours of disclosure. "
        "Mass-scanning began the same day — Spring Boot apps that "
        "exposed any controller accepting form-style input were "
        "potentially affected."
    ),
    remediation=(
        "Upgrade Spring Framework to 5.3.18+ or 5.2.20+. If patching "
        "is delayed, set a controller advice that filters the "
        "`class.module.classLoader` binding path. Audit web roots for "
        "unfamiliar JSP files dropped since 2022-03-30."
    ),
    extra_refs=[
        "Spring — Spring Framework RCE, Early Announcement",
    ],
    tags=["rce", "java", "spring"],
))

_r(_nuclei_cve(
    cve_id="CVE-2022-22963",
    short="Spring Cloud Function SpEL injection",
    severity="critical",
    cwe="CWE-94",
    description=(
        "Spring Cloud Function's routing functionality evaluates "
        "user-controlled SpEL expressions submitted through the "
        "`spring.cloud.function.routing-expression` HTTP header. "
        "Attackers can inject expressions that execute arbitrary code."
    ),
    impact=(
        "Often confused with Spring4Shell (CVE-2022-22965); this is a "
        "separate flaw in Spring Cloud Function. Both saw rapid "
        "exploitation in early 2022."
    ),
    remediation=(
        "Upgrade Spring Cloud Function to 3.1.7 or 3.2.3 (or later). "
        "If patching isn't immediate, block the "
        "`spring.cloud.function.routing-expression` header at the "
        "edge."
    ),
    tags=["rce", "java", "spring"],
))

_r(_nuclei_cve(
    cve_id="CVE-2022-26134",
    short="Atlassian Confluence OGNL injection RCE",
    severity="critical",
    cwe="CWE-917",
    description=(
        "Confluence Server and Data Center allowed unauthenticated "
        "OGNL expression injection through specially crafted URLs, "
        "leading to remote code execution as the Confluence user."
    ),
    impact=(
        "Exploited in the wild as a zero-day before patches landed "
        "(disclosed 2022-06-02). Attacker activity included webshell "
        "deployment, credential theft, and pivoting into corporate "
        "Atlassian estates."
    ),
    remediation=(
        "Upgrade Confluence to 7.4.17 / 7.13.7 / 7.14.3 / 7.15.2 / "
        "7.16.4 / 7.17.4 / 7.18.1 (or later). Audit logs for "
        "unexpected child processes of `confluence/conf/server.xml` "
        "or unfamiliar files in `confluence/webapps/`."
    ),
    extra_refs=[
        "Atlassian — Security Advisory CVE-2022-26134",
    ],
    tags=["rce", "java", "confluence", "atlassian"],
))

_r(_nuclei_cve(
    cve_id="CVE-2022-22954",
    short="VMware Workspace ONE Access SSTI RCE",
    severity="critical",
    cwe="CWE-1336",
    description=(
        "Server-side template injection in the VMware Workspace ONE "
        "Access (formerly Identity Manager) catalog UI allowed "
        "unauthenticated remote code execution."
    ),
    impact=(
        "Quickly weaponised; appeared in mass-scanning data within "
        "days of disclosure. Identity-tier service compromise has "
        "downstream blast radius across federated SSO."
    ),
    remediation=(
        "Apply VMware advisory VMSA-2022-0011 patches. Audit identity-"
        "service logs for unusual admin activity since 2022-04-06."
    ),
    tags=["rce", "vmware"],
))

_r(_nuclei_cve(
    cve_id="CVE-2022-1388",
    short="F5 BIG-IP iControl REST auth bypass",
    severity="critical",
    cwe="CWE-287",
    description=(
        "Undisclosed flaw in F5 BIG-IP's iControl REST allowed "
        "unauthenticated attackers to execute system commands, create "
        "or delete files, or disable services on the device."
    ),
    impact=(
        "Mass-exploited within days of disclosure (2022-05-04). "
        "BIG-IPs front major enterprise traffic, so successful "
        "exploitation gave attackers a privileged position in the "
        "victim's network edge."
    ),
    remediation=(
        "Upgrade BIG-IP to a fixed release (15.1.5.1, 14.1.4.6, "
        "13.1.5, 12.1.6.1, or 11.6.5.3 / latest). Restrict access to "
        "the management interface to trusted networks only — never "
        "expose iControl REST to the internet."
    ),
    tags=["rce", "auth-bypass", "f5"],
))

_r(_nuclei_cve(
    cve_id="CVE-2022-30190",
    short="Follina — MS Office MSDT RCE",
    severity="high",
    cwe="CWE-94",
    description=(
        "The Microsoft Support Diagnostic Tool (MSDT) URL protocol "
        "allowed code execution via crafted Office documents that "
        "invoked `ms-msdt` schemes. Detected on Word documents "
        "delivered via email or web download."
    ),
    impact=(
        "Initially exploited as a zero-day in targeted attacks; "
        "broad criminal adoption followed once disclosed. Click-to-"
        "open Office documents were the primary vector."
    ),
    remediation=(
        "Apply Microsoft's June 2022 security update. Disable the "
        "`ms-msdt` URL protocol via registry "
        "(`HKEY_CLASSES_ROOT\\ms-msdt`) on systems pending patch."
    ),
    tags=["rce", "windows", "office"],
))

_r(_nuclei_cve(
    cve_id="CVE-2022-41040",
    short="ProxyNotShell — Microsoft Exchange SSRF",
    severity="high",
    cwe="CWE-918",
    description=(
        "Server-side request forgery in Microsoft Exchange Server "
        "(2013/2016/2019) allowed authenticated attackers to forge "
        "requests against internal endpoints. Used in chain with "
        "CVE-2022-41082 for remote code execution."
    ),
    impact=(
        "Exploited in the wild as a zero-day before patches landed "
        "(disclosed 2022-09-29). Common chain: phishing for low-priv "
        "credentials, then CVE-2022-41040 + 41082 for SYSTEM-level "
        "code execution on Exchange."
    ),
    remediation=(
        "Apply Microsoft's November 2022 Exchange security updates. "
        "Block the `Autodiscover/PowerShell` URL pattern at the "
        "front-end IIS rewrite layer if patching is delayed."
    ),
    tags=["ssrf", "exchange", "microsoft"],
))

_r(_nuclei_cve(
    cve_id="CVE-2022-41082",
    short="ProxyNotShell — Microsoft Exchange RCE",
    severity="critical",
    cwe="CWE-502",
    description=(
        "Authenticated attackers could trigger remote code execution "
        "in Microsoft Exchange Server through a deserialisation "
        "vulnerability in PowerShell remoting. Chained with "
        "CVE-2022-41040 for the full unauthenticated path."
    ),
    impact=(
        "Same exploitation campaign as ProxyNotShell #1. Active "
        "ransomware deployment and webshell installation observed."
    ),
    remediation=(
        "Apply Microsoft's November 2022 Exchange security updates. "
        "Audit Exchange for unfamiliar webshells and PowerShell "
        "execution events since 2022-09-01."
    ),
    tags=["rce", "exchange", "microsoft"],
))

_r(_nuclei_cve(
    cve_id="CVE-2023-22515",
    short="Confluence broken access control",
    severity="critical",
    cwe="CWE-287",
    description=(
        "Confluence Data Center and Server permitted unauthenticated "
        "attackers to create administrator accounts on internet-"
        "facing instances by manipulating setup-page state."
    ),
    impact=(
        "Exploited in the wild as a zero-day; Atlassian disclosed it "
        "as already-active on 2023-10-04. Full Confluence admin = "
        "macros, plugins, full data access."
    ),
    remediation=(
        "Upgrade Confluence to 8.3.3 / 8.4.3 / 8.5.2 (or later). "
        "Audit user-management logs for new admin accounts created "
        "since 2023-09-15. Atlassian Cloud is unaffected."
    ),
    extra_refs=[
        "Atlassian — Confluence CVE-2023-22515 advisory",
    ],
    tags=["auth-bypass", "confluence", "atlassian"],
))

_r(_nuclei_cve(
    cve_id="CVE-2023-22518",
    short="Confluence improper authorisation",
    severity="critical",
    cwe="CWE-285",
    description=(
        "Confluence Data Center and Server allowed unauthenticated "
        "attackers to reset administrative credentials and trigger "
        "data destruction."
    ),
    impact=(
        "Disclosed shortly after CVE-2023-22515; attacker activity "
        "included data wiping (used as a destructive ransom lever) "
        "as well as account takeover."
    ),
    remediation=(
        "Upgrade Confluence to 7.19.16 / 8.3.4 / 8.4.4 / 8.5.3 / "
        "8.6.1 (or later). Verify backups are intact and recent."
    ),
    tags=["auth-bypass", "confluence", "atlassian"],
))

_r(_nuclei_cve(
    cve_id="CVE-2023-23397",
    short="Outlook NTLM credential leak",
    severity="critical",
    cwe="CWE-294",
    description=(
        "Microsoft Outlook on Windows could be coerced into "
        "authenticating to attacker-controlled SMB shares via crafted "
        "calendar invites — leaking the Net-NTLMv2 hash without user "
        "interaction (no preview pane click required)."
    ),
    impact=(
        "Exploited by APT28 (Fancy Bear) against European government "
        "and military targets through 2022 before disclosure. "
        "Net-NTLMv2 hashes can be relayed or cracked offline."
    ),
    remediation=(
        "Apply Microsoft's March 2023 patches. Block outbound TCP/445 "
        "at the perimeter so Outlook can't reach external SMB hosts. "
        "Audit Net-NTLMv2 authentication events from Outlook since "
        "2022-04 on potentially-targeted accounts."
    ),
    tags=["credential-theft", "outlook", "microsoft"],
))

_r(_nuclei_cve(
    cve_id="CVE-2023-27350",
    short="PaperCut MF/NG auth bypass + RCE",
    severity="critical",
    cwe="CWE-287",
    description=(
        "PaperCut MF/NG print-management software allowed "
        "unauthenticated attackers to bypass authentication and "
        "execute arbitrary code via the SetupCompleted page and "
        "embedded scripting."
    ),
    impact=(
        "Mass-exploited from April 2023 onward by ransomware crews "
        "(Cl0p, LockBit, FIN7-affiliated) targeting US healthcare "
        "and education networks where PaperCut is widely deployed."
    ),
    remediation=(
        "Upgrade to PaperCut MF/NG 20.1.7 / 21.2.11 / 22.0.9 / 23.0.x "
        "(or later). Block external access to the PaperCut admin UI "
        "on port 9191/9192."
    ),
    tags=["rce", "auth-bypass", "papercut"],
))

_r(_nuclei_cve(
    cve_id="CVE-2023-34362",
    short="MOVEit Transfer SQL injection RCE",
    severity="critical",
    cwe="CWE-89",
    description=(
        "Progress Software's MOVEit Transfer (a managed file-transfer "
        "appliance) had a SQL injection flaw that allowed "
        "unauthenticated attackers to extract uploaded files and "
        "execute SQL-side code."
    ),
    impact=(
        "Cl0p ransomware gang exploited this as a zero-day at "
        "internet scale starting May 2023; one of the largest mass-"
        "exploitation campaigns ever recorded — the public victim "
        "list ran into hundreds of organisations including major "
        "banks, government agencies, and HR data processors."
    ),
    remediation=(
        "Upgrade MOVEit Transfer to a fixed release (2020.0.6+ / "
        "2020.1.6+ / 2021.0.8+ / 2021.1.6+ / 2022.0.4+ / 2022.1.5+ / "
        "2023.0.1+). Audit web logs for `human.aspx` activity, the "
        "`LEMURLOOT` webshell, and uploaded files exfiltrated since "
        "2023-05-27."
    ),
    extra_refs=[
        "Progress Software — MOVEit Transfer Critical Vulnerability",
    ],
    tags=["sqli", "rce", "moveit", "data-breach"],
))

_r(_nuclei_cve(
    cve_id="CVE-2023-4966",
    short="Citrix Bleed — NetScaler ADC/Gateway",
    severity="critical",
    cwe="CWE-119",
    description=(
        "A buffer over-read in Citrix NetScaler ADC and Gateway "
        "allowed unauthenticated attackers to extract session tokens "
        "from device memory by sending a specially crafted request to "
        "the AAA endpoint."
    ),
    impact=(
        "Mass-exploited from October 2023; LockBit ransomware "
        "deployed against Boeing, ICBC, DP World, and others through "
        "this vector. Stolen session tokens bypassed MFA on the "
        "VPN/gateway."
    ),
    remediation=(
        "Upgrade NetScaler to a fixed build (14.1-8.50, 13.1-49.15, "
        "13.0-92.19, or later). After patching, **terminate all "
        "active sessions** — `kill icaconnection -all` and "
        "`kill aaa session -all` — because stolen session tokens "
        "remain valid until the session expires server-side."
    ),
    extra_refs=[
        "Citrix — CVE-2023-4966 advisory",
        "Mandiant — Citrix Bleed exploitation",
    ],
    tags=["info-leak", "session-hijack", "citrix"],
))

_r(_nuclei_cve(
    cve_id="CVE-2023-7028",
    short="GitLab account takeover via password reset",
    severity="critical",
    cwe="CWE-640",
    description=(
        "GitLab's password-reset flow accepted multiple email "
        "addresses on the reset request, sending the reset link to "
        "any address an attacker chose. Combined with knowledge of "
        "the target username, this yielded full account takeover "
        "without any prior access."
    ),
    impact=(
        "Disclosed January 2024 with patches available; weaponised "
        "publicly within days. Particularly damaging for organisations "
        "where GitLab houses CI/CD pipelines and signing keys."
    ),
    remediation=(
        "Upgrade GitLab to 16.7.2 / 16.6.4 / 16.5.6 (or later). "
        "Force a password reset for all users; audit recent password-"
        "reset events and account-recovery confirmations for unusual "
        "patterns. Rotate any CI/CD secrets exposed via GitLab."
    ),
    extra_refs=[
        "GitLab Security Advisory CVE-2023-7028",
    ],
    tags=["account-takeover", "gitlab"],
))

_r(_nuclei_cve(
    cve_id="CVE-2024-21762",
    short="Fortinet FortiOS SSL VPN OOB write",
    severity="critical",
    cwe="CWE-787",
    description=(
        "An out-of-bounds write in Fortinet FortiOS's SSL VPN "
        "implementation allowed unauthenticated attackers to execute "
        "arbitrary code by sending a specially crafted HTTP request."
    ),
    impact=(
        "Disclosed February 2024 alongside reports of in-the-wild "
        "exploitation by Chinese-state-affiliated actor Volt Typhoon. "
        "Fortinet SSL VPNs are heavily deployed at network edges."
    ),
    remediation=(
        "Upgrade FortiOS to 7.4.3 / 7.2.7 / 7.0.14 / 6.4.15 / 6.2.16 "
        "(or later). Disable SSL VPN until patched if upgrade isn't "
        "immediate. Audit logs for unusual VPN auth and admin "
        "activity since 2023-12."
    ),
    extra_refs=[
        "Fortinet PSIRT — FG-IR-24-015",
    ],
    tags=["rce", "fortinet", "ssl-vpn"],
))

_r(_nuclei_cve(
    cve_id="CVE-2024-23113",
    short="Fortinet FortiOS format-string RCE",
    severity="critical",
    cwe="CWE-134",
    description=(
        "A format-string vulnerability in FortiOS's fgfmd daemon "
        "allowed unauthenticated remote attackers to execute "
        "arbitrary code via crafted requests to the device's "
        "management daemon."
    ),
    impact=(
        "Disclosed alongside CVE-2024-21762; same exploitation "
        "context, same threat actors, same urgency."
    ),
    remediation=(
        "Upgrade FortiOS as for CVE-2024-21762. Restrict access to "
        "the management interface to trusted networks only — never "
        "internet-facing."
    ),
    tags=["rce", "fortinet"],
))

_r(_nuclei_cve(
    cve_id="CVE-2024-21887",
    short="Ivanti Connect Secure command injection",
    severity="critical",
    cwe="CWE-77",
    description=(
        "Command injection in the web component of Ivanti Connect "
        "Secure (formerly Pulse Connect Secure) and Policy Secure "
        "allowed authenticated attackers to execute arbitrary "
        "commands on the appliance. Chained with CVE-2023-46805 "
        "(auth bypass) for full unauthenticated RCE."
    ),
    impact=(
        "Exploited as zero-day in early 2024 by UTA0178 (suspected "
        "Chinese state actor). Hundreds of internet-facing Ivanti "
        "appliances were compromised before patches landed."
    ),
    remediation=(
        "Upgrade to Ivanti Connect Secure 22.5R2.2+. Apply Ivanti's "
        "external integrity check tool to verify the device hasn't "
        "been backdoored. Reset all VPN credentials post-patching."
    ),
    extra_refs=[
        "Ivanti — Connect Secure / Policy Secure advisory",
        "Volexity — Active Exploitation of Ivanti VPN",
    ],
    tags=["rce", "command-injection", "ivanti"],
))

_r(_nuclei_cve(
    cve_id="CVE-2023-46805",
    short="Ivanti Connect Secure auth bypass",
    severity="high",
    cwe="CWE-287",
    description=(
        "Authentication bypass in the Ivanti Connect Secure / Policy "
        "Secure web component allowed unauthenticated attackers to "
        "reach restricted endpoints. Chained with CVE-2024-21887 for "
        "remote code execution."
    ),
    impact=(
        "Same exploitation campaign as CVE-2024-21887. The two "
        "together form the unauthenticated RCE chain."
    ),
    remediation=(
        "Upgrade per CVE-2024-21887 guidance. Apply the integrity "
        "checker."
    ),
    tags=["auth-bypass", "ivanti"],
))

_r(_nuclei_cve(
    cve_id="CVE-2024-21893",
    short="Ivanti Connect Secure SSRF",
    severity="high",
    cwe="CWE-918",
    description=(
        "Server-side request forgery in Ivanti Connect Secure / "
        "Policy Secure / Neurons for ZTA components allowed an "
        "unauthenticated attacker to access certain restricted "
        "resources without authentication."
    ),
    impact=(
        "Disclosed during active Ivanti exploitation campaigns "
        "(early 2024). Often chained with the other Ivanti issues."
    ),
    remediation=(
        "Upgrade to a fixed Ivanti release; apply the integrity "
        "checker; rotate VPN credentials."
    ),
    tags=["ssrf", "ivanti"],
))

_r(_nuclei_cve(
    cve_id="CVE-2024-3400",
    short="Palo Alto GlobalProtect command injection",
    severity="critical",
    cwe="CWE-77",
    description=(
        "Command injection in the GlobalProtect feature of Palo Alto "
        "PAN-OS allowed unauthenticated remote attackers to execute "
        "arbitrary code with root privileges on the firewall."
    ),
    impact=(
        "Exploited as zero-day starting March 2024 by suspected state "
        "actor UTA0218; at least dozens of internet-facing PAN-OS "
        "devices compromised before disclosure."
    ),
    remediation=(
        "Upgrade PAN-OS to 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3 (or "
        "later). Disable telemetry as a temporary workaround if "
        "patching is delayed. Audit firewall logs for command "
        "execution and config changes since 2024-03-26."
    ),
    extra_refs=[
        "Palo Alto Networks — CVE-2024-3400 advisory",
        "Volexity — Operation MidnightEclipse",
    ],
    tags=["rce", "command-injection", "palo-alto"],
))

_r(_nuclei_cve(
    cve_id="CVE-2024-1709",
    short="ConnectWise ScreenConnect auth bypass",
    severity="critical",
    cwe="CWE-287",
    description=(
        "ConnectWise ScreenConnect (remote-management software widely "
        "deployed by MSPs) allowed unauthenticated attackers to "
        "create administrator accounts via a setup-page "
        "authentication bypass."
    ),
    impact=(
        "Mass-exploited from February 2024 onward — ransomware "
        "groups (BlackBasta, BlackCat) used compromised ScreenConnect "
        "instances to push payloads downstream to MSP customers."
    ),
    remediation=(
        "Upgrade ScreenConnect to 23.9.8 or later. Audit user "
        "accounts for recently-created admins; rotate any ScreenConnect "
        "session tokens; audit downstream client environments for "
        "unauthorised remote-control sessions since 2024-02-13."
    ),
    extra_refs=[
        "ConnectWise — ScreenConnect 23.9.8 release",
    ],
    tags=["auth-bypass", "screenconnect", "msp"],
))

_r(_nuclei_cve(
    cve_id="CVE-2024-3094",
    short="XZ Utils backdoor",
    severity="critical",
    cwe="CWE-506",
    description=(
        "Malicious code was inserted into the upstream XZ Utils "
        "compression library (versions 5.6.0 and 5.6.1) by a "
        "long-running supply-chain operation, providing an SSH "
        "authentication backdoor on certain systemd-linked builds "
        "of OpenSSH."
    ),
    impact=(
        "Caught early — the backdoor was deployed in distro testing "
        "channels (Fedora, Debian unstable, openSUSE Tumbleweed, "
        "Kali) but not widely in stable releases. Had it shipped, "
        "it would have been a generational supply-chain compromise."
    ),
    remediation=(
        "Downgrade XZ Utils to 5.4.6 or upgrade to a patched 5.6.2+ "
        "release where the malicious code has been removed. Audit "
        "package histories on bleeding-edge or rolling-release "
        "systems to confirm 5.6.0/5.6.1 wasn't installed."
    ),
    extra_refs=[
        "Andres Freund — backdoor in upstream xz/liblzma",
        "Red Hat — Urgent security alert for Fedora users",
    ],
    tags=["backdoor", "supply-chain", "xz", "openssh"],
))

_r(_nuclei_cve(
    cve_id="CVE-2024-27198",
    short="JetBrains TeamCity authentication bypass",
    severity="critical",
    cwe="CWE-287",
    description=(
        "JetBrains TeamCity (CI/CD) allowed unauthenticated remote "
        "attackers to bypass authentication and access administrative "
        "endpoints by manipulating URL-handling logic."
    ),
    impact=(
        "Mass-exploited from March 2024 onward; one of the most "
        "targeted CI/CD platforms post-disclosure. Compromised "
        "TeamCity = supply-chain access to every artefact it builds."
    ),
    remediation=(
        "Upgrade TeamCity to 2023.11.4 or later. Audit build "
        "history for unfamiliar plugin installations, modified "
        "build steps, and exfiltrated artefacts. Rotate every secret "
        "stored in TeamCity (deploy keys, API tokens, signing keys)."
    ),
    extra_refs=[
        "JetBrains — TeamCity Security Advisory",
    ],
    tags=["auth-bypass", "teamcity", "ci-cd", "supply-chain"],
))

_r(_nuclei_cve(
    cve_id="CVE-2024-27199",
    short="JetBrains TeamCity path traversal",
    severity="high",
    cwe="CWE-22",
    description=(
        "Path traversal vulnerability in TeamCity allowed "
        "unauthenticated remote attackers to access certain restricted "
        "endpoints, potentially leading to limited information "
        "disclosure or modification of system settings."
    ),
    impact=(
        "Disclosed alongside CVE-2024-27198. Less severe individually "
        "but extends the exploitation surface."
    ),
    remediation=(
        "Upgrade TeamCity to 2023.11.4 or later."
    ),
    tags=["path-traversal", "teamcity"],
))

_r(_nuclei_cve(
    cve_id="CVE-2024-29849",
    short="Veeam Backup Enterprise Manager auth bypass",
    severity="critical",
    cwe="CWE-287",
    description=(
        "Veeam Backup Enterprise Manager (the web UI for managing "
        "Veeam backup infrastructure) allowed unauthenticated "
        "attackers to log in as any user via an authentication "
        "bypass in the Single Sign-On flow."
    ),
    impact=(
        "Direct path to backup-infrastructure compromise — and "
        "compromised backups are the difference between recoverable "
        "and unrecoverable ransomware incidents."
    ),
    remediation=(
        "Upgrade Veeam Backup Enterprise Manager to 12.1.2.172 or "
        "later. Audit SSO and admin-UI activity for unauthorised "
        "logins. Consider taking VBEM off the public internet "
        "entirely."
    ),
    extra_refs=[
        "Veeam — VBEM advisory KB4581",
    ],
    tags=["auth-bypass", "veeam", "backup"],
))

_r(_nuclei_cve(
    cve_id="CVE-2024-26229",
    short="Windows CSC SYSTEM elevation",
    severity="high",
    cwe="CWE-269",
    description=(
        "The Windows Client/Server Run-time Subsystem (CSRSS) had a "
        "privilege-escalation flaw allowing local attackers to "
        "elevate from low-privilege user to SYSTEM."
    ),
    impact=(
        "Public proof-of-concept released within weeks of patch; "
        "incorporated into post-exploitation toolkits."
    ),
    remediation=(
        "Apply Microsoft's April 2024 Patch Tuesday updates."
    ),
    tags=["privilege-escalation", "windows"],
))

# ─── Older CVEs that still fire on real internet-facing assets ───────────

_r(_nuclei_cve(
    cve_id="CVE-2017-5638",
    short="Apache Struts2 RCE (Equifax-grade)",
    severity="critical",
    cwe="CWE-1336",
    description=(
        "Apache Struts2's Jakarta Multipart parser evaluated OGNL "
        "expressions in the Content-Type header, allowing "
        "unauthenticated remote code execution on any application "
        "using the affected parser."
    ),
    impact=(
        "The vulnerability behind the 2017 Equifax breach (143M "
        "records). Still fires on legacy Java applications years "
        "after disclosure — Equifax itself was unpatched for 2 months "
        "post-disclosure when the breach occurred."
    ),
    remediation=(
        "Upgrade Apache Struts to 2.3.32 / 2.5.10.1 (or later). "
        "Confirm no legacy Java applications still ship vulnerable "
        "Struts2 versions in their WARs."
    ),
    tags=["rce", "java", "struts"],
))

_r(_nuclei_cve(
    cve_id="CVE-2018-13379",
    short="Fortinet FortiOS SSL VPN path traversal",
    severity="critical",
    cwe="CWE-22",
    description=(
        "Path-traversal flaw in FortiOS's SSL VPN portal allowed "
        "unauthenticated attackers to retrieve system files including "
        "the file containing user session credentials."
    ),
    impact=(
        "Six years post-disclosure (2018), still routinely exploited "
        "against unpatched edge devices. Stolen creds from this CVE "
        "appear in dark-web markets and ransomware playbooks."
    ),
    remediation=(
        "Upgrade FortiOS — anything 6.x and earlier should already "
        "be patched but isn't always. Force-reset every VPN user "
        "credential; the historical session file may have been "
        "exfiltrated long ago."
    ),
    tags=["path-traversal", "fortinet", "ssl-vpn"],
))

_r(_nuclei_cve(
    cve_id="CVE-2019-0708",
    short="BlueKeep — Windows RDP RCE",
    severity="critical",
    cwe="CWE-416",
    description=(
        "Use-after-free in the Remote Desktop Protocol service on "
        "Windows 7 / Server 2008 / 2008 R2 allowed unauthenticated "
        "remote code execution. Wormable — capable of self-propagation "
        "across networks."
    ),
    impact=(
        "Microsoft took the unusual step of releasing patches for "
        "out-of-support Windows XP/Server 2003. Did not produce a "
        "WannaCry-scale worm but remains highly exploitable on "
        "unpatched legacy systems."
    ),
    remediation=(
        "Apply Microsoft's May 2019 patches. RDP should never be "
        "exposed to the public internet. Disable RDP on systems "
        "that don't need it; tunnel it via VPN or a zero-trust "
        "service for those that do."
    ),
    tags=["rce", "rdp", "windows"],
))

_r(_nuclei_cve(
    cve_id="CVE-2019-11510",
    short="Pulse Secure SSL VPN path traversal",
    severity="critical",
    cwe="CWE-22",
    description=(
        "Pre-auth file-read in Pulse Connect Secure (now Ivanti "
        "Connect Secure) allowed unauthenticated attackers to read "
        "arbitrary files including session-credential dumps."
    ),
    impact=(
        "One of the most-exploited VPN flaws in history; ransomware "
        "groups (REvil, Sodinokibi, Maze) routinely entered networks "
        "via this CVE long after patches were available."
    ),
    remediation=(
        "Upgrade to a fixed Pulse Secure / Ivanti Connect Secure "
        "build. Force-reset all VPN credentials — historical "
        "session dumps may have been exfiltrated years before the "
        "incident becomes apparent."
    ),
    tags=["path-traversal", "ivanti", "ssl-vpn"],
))

_r(_nuclei_cve(
    cve_id="CVE-2020-1472",
    short="Zerologon — Netlogon privilege escalation",
    severity="critical",
    cwe="CWE-330",
    description=(
        "Cryptographic flaw in the Netlogon Remote Protocol allowed "
        "an attacker on the same network as a Windows domain "
        "controller to set the DC's machine account password to a "
        "blank string — effectively granting domain admin."
    ),
    impact=(
        "One of the highest-impact Windows vulnerabilities of the "
        "last decade. Used in the wild by ransomware crews and APT "
        "groups for rapid lateral movement to domain-admin within "
        "Windows networks."
    ),
    remediation=(
        "Apply Microsoft's August/February 2020/2021 patches "
        "(two-stage rollout). Enable Netlogon enforcement mode "
        "(`FullSecureChannelProtection=1`)."
    ),
    tags=["privilege-escalation", "active-directory", "windows"],
))

_r(_nuclei_cve(
    cve_id="CVE-2020-14882",
    short="Oracle WebLogic Server unauthenticated RCE",
    severity="critical",
    cwe="CWE-22",
    description=(
        "Oracle WebLogic Server's Console component allowed "
        "unauthenticated attackers to bypass authentication and "
        "execute arbitrary commands by sending crafted HTTP requests "
        "to the admin console."
    ),
    impact=(
        "Mass-exploited within days of disclosure; cryptojacking "
        "campaigns and ransomware deployment observed. WebLogic is "
        "heavily deployed in finance and government estates."
    ),
    remediation=(
        "Apply Oracle's October 2020 Critical Patch Update. Restrict "
        "the WebLogic admin console to internal networks only — it "
        "shouldn't be reachable from the public internet."
    ),
    tags=["rce", "weblogic", "oracle"],
))

_r(_nuclei_cve(
    cve_id="CVE-2020-3452",
    short="Cisco ASA / FTD path traversal",
    severity="high",
    cwe="CWE-22",
    description=(
        "Cisco Adaptive Security Appliance and Firepower Threat "
        "Defense allowed unauthenticated remote attackers to read "
        "arbitrary files from the device's web-services file system."
    ),
    impact=(
        "Exploited in the wild for credential extraction; ASA "
        "appliances are common edge firewalls in enterprise "
        "deployments."
    ),
    remediation=(
        "Upgrade Cisco ASA / FTD to a fixed release. Audit retrieved "
        "file paths in web-services logs for suspicious access "
        "patterns."
    ),
    tags=["path-traversal", "cisco", "firewall"],
))

_r(_nuclei_cve(
    cve_id="CVE-2021-26855",
    short="ProxyLogon — Exchange Server SSRF",
    severity="critical",
    cwe="CWE-918",
    description=(
        "Server-side request forgery in Microsoft Exchange Server "
        "allowed unauthenticated attackers to authenticate as the "
        "Exchange server itself. Part of the ProxyLogon chain that "
        "led to mass Exchange compromise in early 2021."
    ),
    impact=(
        "HAFNIUM (Chinese state actor) exploited this as zero-day "
        "starting January 2021; an estimated 250,000+ Exchange "
        "servers were compromised before patches were deployed. "
        "Webshells from this campaign are still being found years "
        "later."
    ),
    remediation=(
        "Apply Microsoft's March 2021 out-of-band Exchange patches. "
        "Run Microsoft's MSERT/EOMT tooling to identify and remove "
        "ProxyLogon webshells. Assume any internet-facing Exchange "
        "that was unpatched between 2021-01 and 2021-03 is "
        "compromised until proven otherwise."
    ),
    extra_refs=[
        "Microsoft — HAFNIUM targeting Exchange Servers",
    ],
    tags=["ssrf", "exchange", "microsoft"],
))

_r(_nuclei_cve(
    cve_id="CVE-2021-26084",
    short="Atlassian Confluence OGNL injection",
    severity="critical",
    cwe="CWE-917",
    description=(
        "Confluence Server and Data Center allowed unauthenticated "
        "OGNL injection through specially crafted webwork URLs, "
        "leading to remote code execution."
    ),
    impact=(
        "Mass-exploited from August 2021; cryptominers and webshell "
        "deployments common. Earlier Confluence equivalent of "
        "CVE-2022-26134."
    ),
    remediation=(
        "Upgrade Confluence to 6.13.23 / 7.4.11 / 7.11.6 / 7.12.5 / "
        "7.13.x (or later)."
    ),
    tags=["rce", "confluence", "atlassian"],
))

_r(_nuclei_cve(
    cve_id="CVE-2021-34527",
    short="PrintNightmare — Windows Print Spooler RCE",
    severity="critical",
    cwe="CWE-269",
    description=(
        "The Windows Print Spooler service allowed remote code "
        "execution via crafted print-driver loading; attackers with "
        "any authenticated AD identity could execute SYSTEM-level "
        "code on domain controllers and member servers."
    ),
    impact=(
        "Released as zero-day during 2021's print-driver disclosure "
        "chain; led Microsoft to substantially restructure Print "
        "Spooler's privilege model."
    ),
    remediation=(
        "Apply the July 2021 + later Print Spooler patches. Disable "
        "the Print Spooler service on systems that don't need to "
        "print (especially domain controllers)."
    ),
    tags=["rce", "privilege-escalation", "print-spooler", "windows"],
))

_r(_nuclei_cve(
    cve_id="CVE-2023-50164",
    short="Apache Struts file-upload path traversal",
    severity="critical",
    cwe="CWE-22",
    description=(
        "Apache Struts (versions 2.5.0 to 2.5.32 and 6.x) had a "
        "file-upload flaw that allowed attackers to traverse paths "
        "and write files to arbitrary locations, leading to remote "
        "code execution on vulnerable applications."
    ),
    impact=(
        "Quickly weaponised after December 2023 disclosure; another "
        "in the long line of Struts-driven RCEs that affect long-"
        "lived enterprise Java estates."
    ),
    remediation=(
        "Upgrade Struts to 2.5.33 / 6.3.0.2 (or later). Audit web "
        "roots for unfamiliar files dropped by upload handlers since "
        "2023-12-07."
    ),
    tags=["rce", "path-traversal", "struts"],
))

_r(_nuclei_cve(
    cve_id="CVE-2022-47966",
    short="ManageEngine ADSelfService Plus RCE",
    severity="critical",
    cwe="CWE-611",
    description=(
        "Multiple Zoho ManageEngine products (ADSelfService Plus, "
        "ServiceDesk Plus, others) were vulnerable to remote code "
        "execution via XML external entity (XXE) injection in the "
        "SAML SSO endpoint."
    ),
    impact=(
        "Mass-exploited from January 2023 onward; APT actors and "
        "ransomware crews both incorporated this into their toolkits. "
        "ADSelfService Plus is widely deployed for Active Directory "
        "self-service password reset, so compromise = AD privilege."
    ),
    remediation=(
        "Upgrade affected ManageEngine products to current builds "
        "(see Zoho's advisory for the per-product matrix). Audit "
        "logs for SAML auth events and SYSTEM-level command "
        "execution since 2022-12."
    ),
    tags=["rce", "xxe", "manageengine"],
))


# ───────────────────────────────────────────────────────────────────────────
# Nuclei — Exposed Admin / Debug Panels (Batch D2)
# ───────────────────────────────────────────────────────────────────────────
# Curated copy for the most-fired Nuclei panel-exposure templates.
# Most fire on "panel detected" rather than "auth bypassed" — severity
# reflects what an attacker can do with the panel reachable, not just
# its existence. Panels that hand out RCE without auth (Jenkins script
# console, JMX-RMI, exposed etcd) are critical; login-gated panels
# default to medium with notes about credential-spray and default-cred
# risk.

def _nuclei_panel(
    *,
    slug: str,
    product: str,
    panel_type: str,
    severity: str,
    description: str,
    remediation: str,
    summary: str | None = None,
    cwe: str = "CWE-284",
    extra_refs: list[str] | None = None,
    tags: list[str] | None = None,
    alert_short: str | None = None,
) -> FindingTemplate:
    """Factory for exposed-panel templates.

    `panel_type` reads in the title and summary (e.g. "CI/CD admin
    panel"). Description and remediation are passed in pre-written
    so per-product lockdown details remain handcrafted.
    """
    template_id = f"nuclei-{slug}"
    default_summary = (
        f"An exposed {product} {panel_type} was detected on {{asset}} — "
        f"verify it's intentionally public and properly secured."
    )
    return FindingTemplate(
        template_id=template_id,
        title=f"{product} {panel_type} exposed at {{asset}}",
        description=description,
        remediation=remediation,
        severity=severity,
        category="exposure",
        cwe=cwe,
        tags=["nuclei", "exposed-panel", slug] + (tags or []),
        summary=summary or default_summary,
        alert_name=f"Exposed Panel — {alert_short or product}",
        monitor_type="panel_change",
        references=[
            "OWASP — Security Misconfiguration",
        ] + (extra_refs or []),
    )


# ─── CI/CD ─────────────────────────────────────────────────────────────────

_r(_nuclei_panel(
    slug="jenkins-exposed",
    product="Jenkins",
    panel_type="login page",
    severity="medium",
    description=(
        "A Jenkins instance is reachable on {asset}. Jenkins itself "
        "is one of the most-attacked CI/CD targets — exposed "
        "instances see continuous credential-spray (admin/admin, "
        "jenkins/jenkins, etc.) and are a common entry point into "
        "supply-chain compromise. Authenticated users on Jenkins can "
        "execute Groovy on the controller via the script console, "
        "so any account compromise is effectively code-execution."
    ),
    remediation=(
        "Decide whether Jenkins should be internet-facing. If not, "
        "restrict to your VPN or internal network. If it must be "
        "public:\n"
        "  • Disable signup; require SSO with an external IdP.\n"
        "  • Enable matrix-based authorisation; lock anonymous reads.\n"
        "  • Disable the script console for non-admin roles.\n"
        "  • Audit user list — remove `admin/admin` or any default "
        "credentials.\n"
        "  • Run Jenkins with up-to-date plugins; many CVEs are "
        "plugin-side."
    ),
    extra_refs=["Jenkins — Securing Jenkins"],
    alert_short="Jenkins",
))

_r(_nuclei_panel(
    slug="jenkins-script-console",
    product="Jenkins",
    panel_type="script console",
    severity="critical",
    description=(
        "The Jenkins Groovy script console is reachable on {asset}. "
        "If it's accessible without authentication — or with default "
        "credentials — any visitor can execute arbitrary Groovy code "
        "on the controller, which is equivalent to RCE on the Jenkins "
        "host."
    ),
    remediation=(
        "**Lock the script console behind admin auth immediately**\n"
        "  Disable anonymous access; restrict the console to a small "
        "set of named admin accounts.\n\n"
        "**Audit recent script-console activity**\n"
        "  Check `$JENKINS_HOME/logs/`, build histories, and the "
        "Audit Trail plugin if installed. Look for unfamiliar build "
        "jobs, modified pipelines, and exfiltrated credentials.\n\n"
        "**Rotate all secrets stored in Jenkins**\n"
        "  Treat every credential, deploy key, and API token in the "
        "Credentials store as compromised."
    ),
    cwe="CWE-77",
    extra_refs=["Jenkins — Script console"],
    tags=["rce-risk"],
    alert_short="Jenkins Script Console",
))

_r(_nuclei_panel(
    slug="gitlab-exposed",
    product="GitLab",
    panel_type="login page",
    severity="medium",
    description=(
        "A GitLab instance is reachable on {asset}. Self-hosted "
        "GitLab in particular is a frequent target — recent "
        "high-severity CVEs (CVE-2023-7028 account takeover, "
        "CVE-2024-0402 path traversal) make exposed instances "
        "high-value. GitLab also stores CI/CD secrets, signing keys, "
        "and source code, so account compromise has supply-chain "
        "blast radius."
    ),
    remediation=(
        "If GitLab is intentionally public (typical for open-source "
        "communities), keep it patched on the current minor release "
        "and enforce 2FA on all accounts. If it shouldn't be public, "
        "move it behind a VPN or zero-trust gateway. Disable signup "
        "if not needed; review admin accounts for unfamiliar "
        "additions."
    ),
    extra_refs=["GitLab — Hardening recommendations"],
    alert_short="GitLab",
))

_r(_nuclei_panel(
    slug="gitea-exposed",
    product="Gitea",
    panel_type="instance",
    severity="medium",
    description=(
        "A Gitea instance is reachable on {asset}. Gitea is a "
        "lightweight self-hosted Git server; exposed instances see "
        "credential-spray and have had several auth-bypass and RCE "
        "CVEs over the years. Source code, deploy keys, and webhooks "
        "are typical exposure surface."
    ),
    remediation=(
        "Restrict to internal network or require SSO via external "
        "IdP. Disable signup. Patch to the current Gitea release. "
        "Audit user accounts and admin privileges."
    ),
    extra_refs=["Gitea — Security Tips"],
    alert_short="Gitea",
))

_r(_nuclei_panel(
    slug="argo-cd-exposed",
    product="Argo CD",
    panel_type="UI",
    severity="high",
    description=(
        "An Argo CD UI is reachable on {asset}. Argo CD orchestrates "
        "Kubernetes deployments — compromise of an Argo CD instance "
        "is functionally equivalent to controlling every cluster it "
        "manages. Several historical CVEs (CVE-2022-29165 auth "
        "bypass, CVE-2022-24348 path traversal) make exposed Argo "
        "particularly worth locking down."
    ),
    remediation=(
        "Argo CD should sit behind your organisation's auth proxy "
        "or VPN, never directly on the public internet. If the UI "
        "must be reachable, enforce SSO and disable the local admin "
        "account. Patch to the current Argo CD release."
    ),
    extra_refs=["Argo CD — Hardening guide"],
    tags=["k8s"],
    alert_short="Argo CD",
))

# ─── Issue tracking / wikis ───────────────────────────────────────────────

_r(_nuclei_panel(
    slug="confluence-exposed",
    product="Atlassian Confluence",
    panel_type="instance",
    severity="medium",
    description=(
        "A Confluence Server / Data Center instance is reachable on "
        "{asset}. Confluence has been hit by a string of "
        "high-severity CVEs (CVE-2022-26134 OGNL RCE, "
        "CVE-2023-22515 broken access control, CVE-2023-22518 "
        "improper authorisation) — exposed self-hosted Confluence is "
        "consistently among the top attacker targets."
    ),
    remediation=(
        "Move Confluence behind your auth proxy / VPN if it's not "
        "intentionally public. Patch to the current minor release "
        "and check Atlassian's advisory feed monthly. Audit admin "
        "accounts and API tokens. Atlassian Cloud is unaffected by "
        "the self-hosted CVE chain."
    ),
    extra_refs=[
        "Atlassian — Security advisories",
        "Atlassian — Confluence security recommendations",
    ],
    alert_short="Confluence",
))

_r(_nuclei_panel(
    slug="jira-exposed",
    product="Atlassian Jira",
    panel_type="instance",
    severity="medium",
    description=(
        "A Jira Server / Data Center instance is reachable on "
        "{asset}. Like Confluence, self-hosted Jira has had multiple "
        "high-severity CVEs and is a routine target for ransomware "
        "and APT actors. Issue trackers also leak organisational "
        "information (project structure, internal hostnames in "
        "tickets, employee identities)."
    ),
    remediation=(
        "Move Jira behind a VPN or auth proxy if it's not intended "
        "to be public. Disable signup; require SSO. Patch to the "
        "current minor release. Audit project permissions for "
        "unintended public-read settings."
    ),
    extra_refs=["Atlassian — Jira security recommendations"],
    alert_short="Jira",
))

_r(_nuclei_panel(
    slug="bitbucket-exposed",
    product="Bitbucket Server",
    panel_type="instance",
    severity="medium",
    description=(
        "A Bitbucket Server (Data Center) instance is reachable on "
        "{asset}. Several Bitbucket CVEs in 2022-2023 have been "
        "actively exploited (CVE-2022-36804 command injection). "
        "Exposed instances also leak source code, build pipelines, "
        "and SSH deploy keys."
    ),
    remediation=(
        "Move behind auth proxy or VPN. Disable anonymous read. "
        "Patch to the current Bitbucket release; Atlassian's Cloud "
        "version is unaffected by self-hosted CVE issues."
    ),
    extra_refs=["Atlassian — Bitbucket Server security"],
    alert_short="Bitbucket",
))

# ─── Observability / monitoring ───────────────────────────────────────────

_r(_nuclei_panel(
    slug="grafana-exposed",
    product="Grafana",
    panel_type="login page",
    severity="medium",
    description=(
        "A Grafana login page is reachable on {asset}. Default "
        "credentials (admin/admin) are still found on internet-facing "
        "Grafana instances regularly; once authenticated, an attacker "
        "with admin rights can execute arbitrary code via plugin "
        "uploads or the data-source SQL editor on certain backends. "
        "CVE-2021-43798 (path traversal) made anonymous data-source "
        "queries possible on older versions."
    ),
    remediation=(
        "If Grafana is intentionally public (some SaaS products "
        "embed it), enforce SSO and disable the local admin account "
        "after creating an SSO-bound admin. Otherwise, move behind "
        "your auth proxy or VPN. Confirm `admin/admin` doesn't work; "
        "reset if it does. Patch to current."
    ),
    extra_refs=["Grafana — Hardening Recommendations"],
    alert_short="Grafana",
))

_r(_nuclei_panel(
    slug="kibana-exposed",
    product="Kibana",
    panel_type="instance",
    severity="medium",
    description=(
        "A Kibana instance is reachable on {asset}. Kibana exposes "
        "search and dashboarding over an Elasticsearch cluster — if "
        "the underlying ES cluster has no authentication (common on "
        "older OSS deployments), Kibana effectively grants anonymous "
        "read of every index. Several Kibana CVEs (CVE-2019-7609 "
        "RCE) have also been exploited."
    ),
    remediation=(
        "Enable Elastic security features (free since 7.x); require "
        "auth on Kibana itself. If older Elasticsearch open-source "
        "version, front Kibana with a reverse proxy enforcing "
        "authentication. Patch to current Elastic Stack release."
    ),
    extra_refs=["Elastic — Kibana security"],
    alert_short="Kibana",
))

_r(_nuclei_panel(
    slug="prometheus-exposed",
    product="Prometheus",
    panel_type="metrics endpoint",
    severity="medium",
    description=(
        "A Prometheus instance is reachable on {asset}. Prometheus "
        "doesn't ship with auth — by default any reachable instance "
        "lets visitors query every metric, often revealing internal "
        "service topology, HTTP path patterns, error rates by "
        "endpoint, and historical traffic data. Sometimes leaks "
        "credentials embedded in service metadata or label values."
    ),
    remediation=(
        "Front Prometheus with a reverse proxy enforcing auth (nginx "
        "+ basic auth, or an OAuth proxy like oauth2-proxy). For "
        "managed deployments, restrict at the network layer to your "
        "scraper/visualisation tier. Don't expose the federation "
        "endpoint without auth."
    ),
    extra_refs=["Prometheus — Securing Prometheus API"],
    alert_short="Prometheus",
))

_r(_nuclei_panel(
    slug="influxdb-exposed",
    product="InfluxDB",
    panel_type="API",
    severity="high",
    description=(
        "An InfluxDB API is reachable on {asset}. Older InfluxDB 1.x "
        "versions had no auth by default; even modern 2.x deployments "
        "with auth disabled expose all time-series data and write "
        "endpoints. Exposed Influx instances frequently leak "
        "metrics that include PII, internal service names, and "
        "operational secrets."
    ),
    remediation=(
        "Enable authentication (`auth-enabled = true` in 1.x; "
        "user setup mandatory in 2.x). Restrict the HTTP API to "
        "internal networks. Patch to current InfluxDB release."
    ),
    extra_refs=["InfluxData — Manage authentication"],
    alert_short="InfluxDB",
))

_r(_nuclei_panel(
    slug="weave-scope-exposed",
    product="Weave Scope",
    panel_type="UI",
    severity="high",
    description=(
        "A Weave Scope UI is reachable on {asset}. Weave Scope "
        "provides interactive visualisation of running containers — "
        "with no auth by default, it lets visitors view every "
        "process, environment variable (often containing secrets), "
        "and exec into any container in the cluster."
    ),
    remediation=(
        "Take Weave Scope off the public internet. Place behind a "
        "reverse proxy with authentication (Weave Scope itself "
        "doesn't ship auth). Audit historical access logs."
    ),
    extra_refs=["Weave — Securing Scope"],
    tags=["k8s"],
    alert_short="Weave Scope",
))

_r(_nuclei_panel(
    slug="mlflow-exposed",
    product="MLflow",
    panel_type="tracking server",
    severity="high",
    description=(
        "An MLflow tracking server is reachable on {asset}. MLflow "
        "by default ships without auth; CVE-2023-6976 (path traversal) "
        "and other MLflow CVEs allow unauthenticated file read and "
        "model substitution. Exposed instances leak training data, "
        "model artefacts, and any embedded credentials."
    ),
    remediation=(
        "Enable basic authentication or front MLflow with an OAuth "
        "proxy. Restrict artefact-store access. Patch to current "
        "MLflow release; verify CVE-2023-6976 and follow-on CVEs are "
        "addressed."
    ),
    extra_refs=["MLflow — Authentication"],
    alert_short="MLflow",
))

# ─── Application servers ──────────────────────────────────────────────────

_r(_nuclei_panel(
    slug="tomcat-manager-exposed",
    product="Apache Tomcat",
    panel_type="Manager app",
    severity="high",
    description=(
        "Apache Tomcat's Manager web application (`/manager/html`) "
        "is reachable on {asset}. Manager allows WAR file deployment "
        "— if default credentials (`tomcat/tomcat`, `admin/admin`, "
        "`tomcat/s3cret`) work, an attacker can deploy a malicious "
        "WAR and achieve remote code execution. Routinely exploited "
        "by ransomware crews."
    ),
    remediation=(
        "Remove the Manager webapp entirely from production "
        "(`rm -rf $CATALINA_HOME/webapps/manager`) — it shouldn't "
        "be reachable on internet-facing instances. If it must be "
        "kept, restrict by IP in `context.xml`'s `RemoteAddrValve` "
        "and replace default credentials with strong ones in "
        "`tomcat-users.xml`."
    ),
    cwe="CWE-1188",
    extra_refs=["Apache Tomcat — Security Considerations"],
    tags=["rce-risk"],
    alert_short="Tomcat Manager",
))

_r(_nuclei_panel(
    slug="tomcat-host-manager",
    product="Apache Tomcat",
    panel_type="Host Manager app",
    severity="high",
    description=(
        "Apache Tomcat's Host Manager (`/host-manager/html`) is "
        "reachable on {asset}. Host Manager is even more privileged "
        "than the regular Manager — it lets an authenticated user "
        "create new virtual hosts, which can be used to take over "
        "the entire Tomcat instance. Default credentials apply same "
        "as Manager."
    ),
    remediation=(
        "Remove the Host Manager webapp from production. If "
        "required, restrict source IPs and replace default "
        "credentials."
    ),
    extra_refs=["Apache Tomcat — Security Considerations"],
    tags=["rce-risk"],
    alert_short="Tomcat Host Manager",
))

_r(_nuclei_panel(
    slug="jboss-exposed",
    product="JBoss",
    panel_type="admin console",
    severity="high",
    description=(
        "A JBoss / WildFly admin console is reachable on {asset}. "
        "JBoss has a long CVE history, including unauthenticated RCE "
        "via the JMX console (CVE-2017-12149) and the EJB invoker "
        "servlet. Default credentials (`admin/admin`, "
        "`jboss/jboss`) still appear on exposed instances."
    ),
    remediation=(
        "Block the admin console (`/admin-console`, "
        "`/management`, `/jmx-console`) from internet access. "
        "Replace default credentials. Patch to a current Wildfly "
        "release; legacy JBoss EAP versions should be retired."
    ),
    extra_refs=["Red Hat — JBoss EAP security"],
    tags=["rce-risk"],
    alert_short="JBoss",
))

_r(_nuclei_panel(
    slug="weblogic-exposed",
    product="Oracle WebLogic",
    panel_type="admin console",
    severity="high",
    description=(
        "An Oracle WebLogic admin console is reachable on {asset}. "
        "WebLogic has been hit by multiple unauthenticated RCE CVEs "
        "(CVE-2020-14882, CVE-2020-14750 deserialisation, "
        "CVE-2023-21931 SSRF). Exposed admin consoles are routinely "
        "used as initial access by both crimeware and APT actors."
    ),
    remediation=(
        "Restrict the WebLogic admin console (`/console`) to "
        "internal networks. Apply Oracle's Critical Patch Updates "
        "promptly — quarterly is the cadence. Audit recent admin "
        "logins."
    ),
    extra_refs=["Oracle — Critical Patch Updates"],
    tags=["rce-risk"],
    alert_short="WebLogic",
))

_r(_nuclei_panel(
    slug="websphere-exposed",
    product="IBM WebSphere",
    panel_type="admin console",
    severity="high",
    description=(
        "An IBM WebSphere admin console is reachable on {asset}. "
        "WebSphere has a deep history of deserialisation CVEs "
        "(CVE-2020-4276 and others) and routine default-credential "
        "issues. Less common in newer estates but still seen in "
        "long-tail enterprise deployments."
    ),
    remediation=(
        "Restrict the admin console to internal networks. Apply "
        "current IBM PSIRT patches. Audit recent admin activity."
    ),
    extra_refs=["IBM — WebSphere security"],
    alert_short="WebSphere",
))

# ─── Databases / data stores (reachable admin UIs) ────────────────────────

_r(_nuclei_panel(
    slug="phpmyadmin-exposed",
    product="phpMyAdmin",
    panel_type="login page",
    severity="medium",
    description=(
        "A phpMyAdmin instance is reachable on {asset}. phpMyAdmin "
        "is a widely-deployed MySQL admin UI; exposed instances see "
        "continuous credential-spray. Multiple CVEs over the years "
        "(CVE-2018-12613 LFI, CVE-2020-26935 SQLi). Once "
        "authenticated, an attacker has full database access."
    ),
    remediation=(
        "Don't expose phpMyAdmin to the public internet — front it "
        "with an auth proxy or restrict to internal networks. Use "
        "strong DB credentials; never default. Patch phpMyAdmin to "
        "current."
    ),
    extra_refs=["phpMyAdmin — Security"],
    alert_short="phpMyAdmin",
))

_r(_nuclei_panel(
    slug="adminer-exposed",
    product="Adminer",
    panel_type="login page",
    severity="medium",
    description=(
        "An Adminer instance is reachable on {asset}. Adminer is a "
        "single-PHP-file database admin tool — it's particularly "
        "risky when left in production webroots because it's hard "
        "to spot. CVE-2020-35572 (SSRF on connect-to-different-host) "
        "is routinely exploited."
    ),
    remediation=(
        "Remove Adminer from production. If genuinely needed, gate "
        "behind HTTP basic auth or VPN. Patch to current Adminer "
        "release."
    ),
    extra_refs=["Adminer — Security"],
    alert_short="Adminer",
))

_r(_nuclei_panel(
    slug="mongo-express-exposed",
    product="mongo-express",
    panel_type="UI",
    severity="high",
    description=(
        "A mongo-express UI is reachable on {asset}. mongo-express "
        "ships with default credentials (`admin/pass`); exposed "
        "instances are routinely compromised within hours. Once "
        "authenticated, an attacker has full read/write/delete "
        "access to every MongoDB database."
    ),
    remediation=(
        "Don't expose mongo-express. If it must be reachable, set "
        "`ME_CONFIG_BASICAUTH_USERNAME` / "
        "`ME_CONFIG_BASICAUTH_PASSWORD` to non-default values. "
        "Confirm the underlying MongoDB itself enforces auth."
    ),
    extra_refs=["mongo-express — README security"],
    alert_short="mongo-express",
))

_r(_nuclei_panel(
    slug="couchdb-exposed",
    product="CouchDB",
    panel_type="Fauxton admin UI",
    severity="high",
    description=(
        "An Apache CouchDB Fauxton admin UI is reachable on {asset}. "
        "Pre-3.x CouchDB ran in 'admin party' mode by default — any "
        "anonymous user could create, read, update, and delete every "
        "database. CVE-2017-12635 and CVE-2017-12636 chained for "
        "unauthenticated RCE."
    ),
    remediation=(
        "Restrict the CouchDB UI to internal networks. Disable admin-"
        "party mode by setting an admin password (CouchDB 3.x does "
        "this on first install; older versions need explicit setup). "
        "Patch to current CouchDB release."
    ),
    extra_refs=["CouchDB — Security"],
    alert_short="CouchDB",
))

_r(_nuclei_panel(
    slug="solr-admin-exposed",
    product="Apache Solr",
    panel_type="admin UI",
    severity="high",
    description=(
        "An Apache Solr admin UI is reachable on {asset}. Solr has "
        "a long unauthenticated-RCE CVE history "
        "(CVE-2019-0193 DataImportHandler, CVE-2019-17558 Velocity, "
        "CVE-2021-27905 ReplicationHandler). Exposed admin UIs are "
        "primary mass-exploitation targets."
    ),
    remediation=(
        "Take Solr off the public internet. Configure auth "
        "(BasicAuthPlugin) and disable the modules that drive the "
        "RCE chain — VelocityResponseWriter, DataImportHandler — if "
        "not in use. Patch to current Solr release."
    ),
    extra_refs=["Apache Solr — Securing Solr"],
    tags=["rce-risk"],
    alert_short="Solr",
))

_r(_nuclei_panel(
    slug="elasticsearch-exposed",
    product="Elasticsearch",
    panel_type="cluster",
    severity="high",
    description=(
        "An Elasticsearch HTTP API is reachable on {asset}. Older "
        "OSS releases had no built-in auth — exposed instances are "
        "routinely scraped by automated tooling that either steals "
        "data or ransom-wipes indexes ('Meow' attacks). Even with "
        "Elastic Security enabled, exposing the management API to "
        "the internet leaves the cluster vulnerable to credential-"
        "spray and version-specific CVEs."
    ),
    remediation=(
        "Enable Elastic security features (free since 7.x with "
        "8.0 enabling them by default). Restrict the HTTP API to "
        "internal networks. Front with a reverse proxy enforcing "
        "auth if the API must be public."
    ),
    extra_refs=["Elastic — Securing Elasticsearch"],
    alert_short="Elasticsearch",
))

# ─── Container / infrastructure ───────────────────────────────────────────

_r(_nuclei_panel(
    slug="docker-registry-v2-exposed",
    product="Docker Registry v2",
    panel_type="API",
    severity="high",
    description=(
        "An open Docker Registry v2 API is reachable on {asset}. "
        "Without auth, anyone can list repositories and pull images. "
        "Pulled images frequently contain embedded secrets (API "
        "keys, database passwords in env vars), source code, and "
        "build dependencies."
    ),
    remediation=(
        "Enable authentication on the registry (token auth, basic "
        "auth via reverse proxy). Better — don't expose the registry "
        "to the public internet at all. If you need public images, "
        "publish them to a managed registry (GHCR, GHCR public, "
        "Docker Hub public)."
    ),
    extra_refs=["Docker — Distribution authentication"],
    alert_short="Docker Registry",
))

_r(_nuclei_panel(
    slug="harbor-exposed",
    product="Harbor",
    panel_type="UI",
    severity="medium",
    description=(
        "A Harbor (container registry) UI is reachable on {asset}. "
        "Harbor has had several authentication and RBAC CVEs "
        "(CVE-2019-19026 SQLi, CVE-2022-31671 broken access control). "
        "Even when properly configured, exposed login pages see "
        "credential-spray."
    ),
    remediation=(
        "Restrict Harbor to internal networks where possible. "
        "Enforce SSO and disable local admin signup. Patch to current "
        "Harbor release."
    ),
    extra_refs=["Harbor — Configure Harbor"],
    alert_short="Harbor",
))

_r(_nuclei_panel(
    slug="nexus-repository-exposed",
    product="Sonatype Nexus",
    panel_type="repository manager",
    severity="medium",
    description=(
        "A Sonatype Nexus Repository Manager UI is reachable on "
        "{asset}. Nexus has had multiple RCE CVEs (CVE-2024-4956 "
        "path traversal, CVE-2020-10199 deserialisation). Nexus "
        "stores build artefacts and proxy-cached dependencies, so "
        "compromise has supply-chain implications."
    ),
    remediation=(
        "Restrict to internal networks. Disable the default `admin` "
        "account or rotate its password. Patch to current Nexus "
        "release."
    ),
    extra_refs=["Sonatype — Nexus Security"],
    alert_short="Nexus",
))

_r(_nuclei_panel(
    slug="portainer-exposed",
    product="Portainer",
    panel_type="UI",
    severity="high",
    description=(
        "A Portainer (container management) UI is reachable on "
        "{asset}. Portainer admins have full container lifecycle "
        "control — create, start, stop, exec into any container "
        "managed by the Docker / Swarm / Kubernetes endpoints "
        "Portainer connects to. Exposed login pages see "
        "credential-spray."
    ),
    remediation=(
        "Don't expose Portainer to the public internet. Place "
        "behind a VPN or auth proxy. Enforce 2FA for admin accounts. "
        "Verify the initial admin signup hasn't been completed by an "
        "attacker — fresh Portainer installs accept first-visitor "
        "admin registration."
    ),
    extra_refs=["Portainer — Security"],
    alert_short="Portainer",
))

_r(_nuclei_panel(
    slug="rancher-exposed",
    product="Rancher",
    panel_type="UI",
    severity="high",
    description=(
        "A Rancher (Kubernetes management) UI is reachable on "
        "{asset}. Rancher governs every cluster it manages — "
        "compromising the Rancher UI is functionally equivalent to "
        "owning all those clusters' workloads. CVE-2021-25741 and "
        "others."
    ),
    remediation=(
        "Take Rancher off the public internet. Enforce SSO. Audit "
        "user list, especially for accounts with `cluster-admin` or "
        "Rancher's `admin` global role. Patch to current Rancher "
        "release."
    ),
    extra_refs=["Rancher — Hardening Guide"],
    tags=["k8s"],
    alert_short="Rancher",
))

_r(_nuclei_panel(
    slug="kubernetes-api-exposed",
    product="Kubernetes",
    panel_type="API server",
    severity="critical",
    description=(
        "A Kubernetes API server is reachable on {asset} without "
        "authentication, or with anonymous access enabled. "
        "Anonymous K8s API access typically grants `system:anonymous` "
        "/ `system:unauthenticated` group membership — many clusters "
        "have leftover overly-permissive ClusterRoleBindings on "
        "those groups, granting read or even write across the whole "
        "cluster."
    ),
    remediation=(
        "Disable anonymous auth (`--anonymous-auth=false` on "
        "kube-apiserver). Audit ClusterRoleBindings for any binding "
        "to `system:anonymous` or `system:unauthenticated` groups "
        "and remove them. Restrict the API server to known networks "
        "via `--bind-address` and a firewall. Audit recent API "
        "calls for unauthorised activity."
    ),
    cwe="CWE-306",
    extra_refs=[
        "Kubernetes — Authentication",
        "CIS Kubernetes Benchmark",
    ],
    tags=["k8s", "rce-risk"],
    alert_short="K8s API",
))

_r(_nuclei_panel(
    slug="kubernetes-dashboard-exposed",
    product="Kubernetes",
    panel_type="Dashboard",
    severity="high",
    description=(
        "A Kubernetes Dashboard is reachable on {asset}. Historic "
        "Dashboard exposures (Tesla 2018) led to crypto-mining "
        "compromise of entire clusters; Dashboard with overly-broad "
        "permissions hands out credentials and pod-exec to anyone "
        "who can reach the URL."
    ),
    remediation=(
        "Don't expose Dashboard to the public internet. Use "
        "`kubectl proxy` for local access. If exposure is required, "
        "enforce strong auth (OIDC bearer token); never use the "
        "default ServiceAccount with cluster-admin permissions."
    ),
    extra_refs=[
        "Kubernetes — Web UI Dashboard",
        "Kubernetes — Tesla cryptojacking incident",
    ],
    tags=["k8s"],
    alert_short="K8s Dashboard",
))

_r(_nuclei_panel(
    slug="etcd-exposed",
    product="etcd",
    panel_type="cluster",
    severity="critical",
    description=(
        "An etcd cluster is reachable on {asset}. etcd holds all "
        "Kubernetes cluster state — secrets, RBAC bindings, every "
        "object definition. Unauthenticated etcd access is "
        "equivalent to full cluster compromise. The exposure also "
        "applies to non-K8s etcd deployments (Vault storage, "
        "service-mesh state)."
    ),
    remediation=(
        "etcd should never be reachable from outside the cluster. "
        "Configure mutual TLS auth on etcd's client port (2379) and "
        "peer port (2380). Restrict at the network layer. If etcd "
        "has been internet-exposed, treat all secrets stored in the "
        "cluster as compromised — rotate them."
    ),
    cwe="CWE-306",
    extra_refs=["etcd — Security model"],
    tags=["k8s", "rce-risk"],
    alert_short="etcd",
))

_r(_nuclei_panel(
    slug="consul-ui-exposed",
    product="Consul",
    panel_type="UI",
    severity="high",
    description=(
        "A HashiCorp Consul UI is reachable on {asset}. Consul "
        "without ACLs configured allows anyone with UI access to "
        "register services, modify health checks, and read service "
        "metadata that often contains internal IPs, DNS names, and "
        "occasionally credentials in tags or KV values."
    ),
    remediation=(
        "Enable Consul ACLs (`acl.enabled = true`) with a default "
        "deny policy. Restrict UI access to internal networks. "
        "Audit the KV store for exposed credentials and migrate "
        "them to Vault."
    ),
    extra_refs=["HashiCorp — Consul ACL system"],
    alert_short="Consul",
))

_r(_nuclei_panel(
    slug="vault-ui-exposed",
    product="HashiCorp Vault",
    panel_type="UI",
    severity="medium",
    description=(
        "A HashiCorp Vault UI is reachable on {asset}. Vault itself "
        "is designed for internet exposure (auth required), but "
        "exposed instances see credential-spray and historic CVEs "
        "(CVE-2020-16250 GCP auth bypass) make patching cadence "
        "important. Sensitive operational metadata (auth method "
        "list, mount paths) is visible without auth."
    ),
    remediation=(
        "Vault is typically internet-facing by design — keep it "
        "current with the latest release, enforce strong auth "
        "methods, audit Sentinel policies, and watch the audit log. "
        "If Vault is internal-only, restrict at the network layer."
    ),
    extra_refs=["HashiCorp — Vault Production Hardening"],
    alert_short="Vault",
))

_r(_nuclei_panel(
    slug="airflow-exposed",
    product="Apache Airflow",
    panel_type="webserver",
    severity="high",
    description=(
        "An Apache Airflow webserver is reachable on {asset}. "
        "Airflow has had several auth-bypass and RCE CVEs "
        "(CVE-2022-40954, CVE-2022-46651). Authenticated Airflow "
        "users can typically execute arbitrary Python via DAGs, so "
        "any account compromise = code execution on Airflow "
        "infrastructure. Many older deployments shipped without auth "
        "by default."
    ),
    remediation=(
        "Take Airflow off the public internet — it should only be "
        "reachable from your data team's network. Confirm RBAC is "
        "enabled and there's no anonymous access. Patch to current "
        "Airflow release."
    ),
    extra_refs=["Apache Airflow — Security"],
    tags=["rce-risk"],
    alert_short="Airflow",
))

_r(_nuclei_panel(
    slug="sonarqube-exposed",
    product="SonarQube",
    panel_type="instance",
    severity="medium",
    description=(
        "A SonarQube instance is reachable on {asset}. SonarQube "
        "stores code-quality and security analysis results — exposed "
        "instances may leak source code excerpts, vulnerability "
        "findings, and historical secret-scanner results. Default "
        "credentials (`admin/admin`) are still seen on internet-"
        "facing instances."
    ),
    remediation=(
        "Restrict SonarQube to internal networks. Replace default "
        "admin credentials. Enforce SSO. Patch to current SonarQube "
        "LTS release."
    ),
    extra_refs=["SonarQube — Security recommendations"],
    alert_short="SonarQube",
))

# ─── Message brokers / queues ─────────────────────────────────────────────

_r(_nuclei_panel(
    slug="activemq-admin-exposed",
    product="ActiveMQ",
    panel_type="web console",
    severity="high",
    description=(
        "An Apache ActiveMQ web console is reachable on {asset}. "
        "Default credentials (`admin/admin`) are still common; "
        "CVE-2023-46604 (OpenWire protocol RCE) was exploited at "
        "scale by ransomware actors throughout late 2023 and 2024. "
        "Exposed brokers also leak queue contents."
    ),
    remediation=(
        "Patch ActiveMQ to a current release (5.17.6+ / 5.18.3+ or "
        "Artemis 2.31+). Restrict the web console and the OpenWire "
        "port (61616) to internal networks. Replace default "
        "credentials."
    ),
    extra_refs=["Apache ActiveMQ — Security"],
    tags=["rce-risk"],
    alert_short="ActiveMQ",
))

_r(_nuclei_panel(
    slug="rabbitmq-management-exposed",
    product="RabbitMQ",
    panel_type="management UI",
    severity="medium",
    description=(
        "A RabbitMQ management UI is reachable on {asset}. RabbitMQ "
        "ships with a default `guest/guest` account that's restricted "
        "to localhost — but exposed instances often have it "
        "explicitly enabled. Authenticated management users can "
        "read every queue's contents."
    ),
    remediation=(
        "Disable the `guest` account or restrict to localhost (the "
        "default). Move the management UI off the public internet. "
        "Patch to current RabbitMQ release."
    ),
    extra_refs=["RabbitMQ — Access Control"],
    alert_short="RabbitMQ",
))

_r(_nuclei_panel(
    slug="kafka-ui-exposed",
    product="Kafka",
    panel_type="management UI",
    severity="medium",
    description=(
        "A Kafka management UI (Kafka UI / Kafdrop / Conduktor) is "
        "reachable on {asset}. These tools often have minimal or no "
        "auth out of the box; exposed instances let visitors inspect "
        "every topic and message — a frequent source of unintended "
        "PII / credential exposure."
    ),
    remediation=(
        "Restrict Kafka management UIs to internal networks. "
        "Enforce auth at the proxy layer if web access is needed. "
        "Audit topic contents for sensitive data that shouldn't be "
        "viewable in real-time."
    ),
    alert_short="Kafka UI",
))

# ─── CMS admin panels ─────────────────────────────────────────────────────

_r(_nuclei_panel(
    slug="wordpress-admin-exposed",
    product="WordPress",
    panel_type="admin login (wp-admin)",
    severity="medium",
    description=(
        "A WordPress wp-login.php / wp-admin page is reachable on "
        "{asset}. WordPress login pages are the single most-bruteforced "
        "authentication surface on the internet — exposed instances "
        "see continuous credential-spray, especially against "
        "`admin`, `administrator`, and the publicly-discoverable "
        "username from `/?author=1`."
    ),
    remediation=(
        "Hide the user-enumeration endpoint by disabling the "
        "REST API user list or rewriting `?author=` URLs. Enforce "
        "2FA on every admin account (Wordfence, Two Factor "
        "Authentication, miniOrange plugins). Rate-limit "
        "wp-login.php at the WAF or via a plugin. Patch core, "
        "themes, and plugins on a regular cadence — most WordPress "
        "compromise comes through plugin CVEs."
    ),
    extra_refs=["WordPress — Hardening"],
    alert_short="WordPress Admin",
))

_r(_nuclei_panel(
    slug="drupal-admin-exposed",
    product="Drupal",
    panel_type="admin login",
    severity="medium",
    description=(
        "A Drupal admin login page is reachable on {asset}. Drupal "
        "has a CVE history that reads like a greatest-hits compilation "
        "of unauthenticated RCE (CVE-2014-3704 'Drupalgeddon', "
        "CVE-2018-7600 'Drupalgeddon2', CVE-2018-7602). Exposed admin "
        "interfaces with unpatched cores are routinely compromised."
    ),
    remediation=(
        "Patch Drupal core and contrib modules promptly — Drupal "
        "publishes a security advisory feed worth subscribing to. "
        "Enforce 2FA for admin accounts. Restrict /user/login by IP "
        "where possible."
    ),
    extra_refs=["Drupal — Securing your site"],
    alert_short="Drupal Admin",
))

_r(_nuclei_panel(
    slug="magento-admin-exposed",
    product="Magento",
    panel_type="admin panel",
    severity="medium",
    description=(
        "A Magento admin panel is reachable on {asset}. Magento "
        "(now Adobe Commerce) has had multiple unauthenticated RCE "
        "CVEs and is heavily targeted by skimmer/Magecart actors. "
        "Default admin URLs (`/admin`, `/admin/index/index`) are "
        "frequently left unchanged."
    ),
    remediation=(
        "Customise the admin URL via `frontName` config; this isn't "
        "a security control on its own but reduces background "
        "scanning noise. Enforce 2FA (built into Magento 2.4+). "
        "Patch to current; subscribe to Adobe's security advisory "
        "feed."
    ),
    extra_refs=["Adobe Commerce — Security"],
    alert_short="Magento Admin",
))

_r(_nuclei_panel(
    slug="joomla-admin-exposed",
    product="Joomla",
    panel_type="administrator panel",
    severity="medium",
    description=(
        "A Joomla administrator panel is reachable on {asset}. "
        "Joomla has had multiple high-severity CVEs (CVE-2023-23752 "
        "auth bypass, CVE-2015-8562 RCE). Exposed admin paths "
        "(`/administrator/`) see continuous credential-spray."
    ),
    remediation=(
        "Patch Joomla core and extensions. Restrict /administrator/ "
        "by IP if possible; otherwise enforce 2FA on admin accounts. "
        "Audit installed extensions for unfamiliar additions."
    ),
    extra_refs=["Joomla — Security checklist"],
    alert_short="Joomla Admin",
))

# ─── Spring Boot Actuator ─────────────────────────────────────────────────

_r(_nuclei_panel(
    slug="spring-boot-actuator",
    product="Spring Boot",
    panel_type="Actuator endpoints",
    severity="high",
    description=(
        "Spring Boot Actuator endpoints are reachable on {asset}. "
        "Default Actuator exposure varies by version, but unsecured "
        "`/actuator/env`, `/actuator/heapdump`, and "
        "`/actuator/threaddump` leak environment variables (often "
        "containing credentials), full JVM heap snapshots, and "
        "active thread state. CVE-2017-8046 / CVE-2018-1273 chained "
        "via Actuator-exposed env."
    ),
    remediation=(
        "Restrict Actuator endpoints to internal networks via Spring "
        "Security or an external auth proxy. Set "
        "`management.endpoints.web.exposure.include=health,info` to "
        "expose only the safe endpoints (Spring Boot 2.x default is "
        "this). Audit env vars for credentials and rotate any that "
        "may have been exposed."
    ),
    extra_refs=["Spring — Spring Boot Actuator Security"],
    alert_short="Spring Actuator",
))

_r(_nuclei_panel(
    slug="spring-actuator-env",
    product="Spring Boot",
    panel_type="Actuator /env endpoint",
    severity="critical",
    description=(
        "Spring Boot's `/actuator/env` endpoint is publicly reachable "
        "on {asset}. The endpoint dumps every property in the "
        "Spring environment — `spring.datasource.password`, JWT "
        "signing keys, OAuth client secrets, third-party API tokens. "
        "Direct path to full credential leak."
    ),
    remediation=(
        "**Rotate immediately** — every property visible in /env "
        "must be considered compromised: database passwords, "
        "signing keys, third-party tokens.\n\n"
        "**Lock down Actuator**\n"
        "  Set `management.endpoints.web.exposure.include=health,info` "
        "or front Actuator with Spring Security requiring an admin "
        "role. Don't expose the management port to the internet.\n\n"
        "**Audit recent activity**\n"
        "  Review database access logs, signing-key usage logs, and "
        "any third-party API audit logs since the endpoint was "
        "first reachable."
    ),
    cwe="CWE-200",
    extra_refs=["Spring — Spring Boot Actuator Security"],
    alert_short="Spring /env",
))

# ─── Storage / streaming ──────────────────────────────────────────────────

_r(_nuclei_panel(
    slug="spark-master-exposed",
    product="Apache Spark",
    panel_type="master UI",
    severity="high",
    description=(
        "An Apache Spark master UI is reachable on {asset}. Spark's "
        "master UI without auth lets visitors submit applications "
        "which run with Spark worker privileges — effectively "
        "remote code execution on every worker node. CVE-2022-33891 "
        "and predecessors."
    ),
    remediation=(
        "Restrict the Spark master UI to internal networks. Enable "
        "auth (`spark.acls.enable=true` / `spark.ui.acls.enable=true`). "
        "Patch Spark to a current release."
    ),
    extra_refs=["Apache Spark — Security"],
    tags=["rce-risk"],
    alert_short="Spark Master",
))

_r(_nuclei_panel(
    slug="zookeeper-admin-exposed",
    product="ZooKeeper",
    panel_type="admin server",
    severity="medium",
    description=(
        "An Apache ZooKeeper admin server (4-letter words) is "
        "reachable on {asset}. The admin endpoint reveals cluster "
        "state, client connections (with source IPs), and "
        "configuration — useful reconnaissance even when no direct "
        "compromise vector exists."
    ),
    remediation=(
        "Restrict ZooKeeper to internal networks. Disable 4-letter "
        "words you don't need (`4lw.commands.whitelist=stat,ruok` "
        "for minimum). Configure SASL / Kerberos auth where the "
        "deployment supports it."
    ),
    extra_refs=["ZooKeeper — Administrator's Guide"],
    alert_short="ZooKeeper",
))

_r(_nuclei_panel(
    slug="jmx-rmi-exposed",
    product="JMX-RMI",
    panel_type="management endpoint",
    severity="critical",
    description=(
        "A JMX-RMI management endpoint is reachable on {asset}. "
        "JMX without auth lets anyone register an MBean that "
        "executes arbitrary Java code on the JVM — a classic and "
        "still-common path to RCE on JBoss, Tomcat, Cassandra, "
        "and other Java services. Even with auth, JMX over RMI is "
        "a documented attack surface."
    ),
    remediation=(
        "**Disable JMX-RMI on production** unless you're actively "
        "using it for monitoring.\n\n"
        "**If JMX is required**\n"
        "  Restrict to localhost or an internal management subnet "
        "only.\n"
        "  Enable JMX authentication and require SSL: "
        "`-Dcom.sun.management.jmxremote.authenticate=true`, "
        "`-Dcom.sun.management.jmxremote.ssl=true`.\n"
        "  Use jmxremote.password and jmxremote.access files "
        "with strong credentials.\n\n"
        "**Audit for prior compromise**\n"
        "  Java services that have had unauth JMX exposed often "
        "show evidence of MBean registration in their logs."
    ),
    cwe="CWE-306",
    extra_refs=["Oracle — JMX Security"],
    tags=["rce-risk"],
    alert_short="JMX-RMI",
))


# ───────────────────────────────────────────────────────────────────────────
# Nuclei — Misconfigurations (Batch D4)
# ───────────────────────────────────────────────────────────────────────────
# Curated copy for the high-impact misconfiguration templates Nuclei
# detects. Coverage spans web (CORS, host-header, request smuggling),
# GraphQL, server-side injection, cloud metadata SSRF, IaC, exposed
# data stores, network services, and DNS/NTP amplification.

def _nuclei_misconfig(
    *,
    slug: str,
    title: str,
    severity: str,
    description: str,
    remediation: str,
    summary: str,
    cwe: str,
    alert_short: str,
    extra_refs: list[str] | None = None,
    tags: list[str] | None = None,
    category: str = "misconfiguration",
) -> FindingTemplate:
    """Factory for misconfiguration templates."""
    return FindingTemplate(
        template_id=f"nuclei-{slug}",
        title=title,
        description=description,
        remediation=remediation,
        severity=severity,
        category=category,
        cwe=cwe,
        tags=["nuclei", "misconfiguration", slug] + (tags or []),
        summary=summary,
        alert_name=f"Misconfig — {alert_short}",
        monitor_type="config_change",
        references=[
            "OWASP — Security Misconfiguration",
        ] + (extra_refs or []),
    )


# ─── CORS / Web misconfigurations ─────────────────────────────────────────

_r(_nuclei_misconfig(
    slug="cors-wildcard-with-credentials",
    title="CORS allows wildcard origin with credentials on {asset}",
    severity="high",
    cwe="CWE-942",
    description=(
        "The application returns `Access-Control-Allow-Origin: *` "
        "together with `Access-Control-Allow-Credentials: true`. "
        "Modern browsers refuse this combination, but older browsers "
        "and many non-browser clients accept it — and the underlying "
        "intent (any origin can read authenticated responses) is "
        "almost always wrong. If a more nuanced CORS rule reflects "
        "the request origin while sending credentials, the same "
        "issue applies in spirit even when wildcard isn't used."
    ),
    remediation=(
        "Pick the right model:\n"
        "  • If credentials must travel: maintain an explicit "
        "allow-list of trusted origins and reflect only those into "
        "`Access-Control-Allow-Origin`. Never combine with `*`.\n"
        "  • If credentials don't need to travel: drop "
        "`Access-Control-Allow-Credentials`; wildcard origin is "
        "safe without it.\n\n"
        "Audit every endpoint that returns sensitive data to confirm "
        "the response can't be read cross-origin without "
        "authentication context."
    ),
    summary="Your CORS config lets any origin read authenticated responses on {asset} — credential-bearing endpoints are exposed cross-origin.",
    extra_refs=[
        "MDN — Cross-Origin Resource Sharing",
        "PortSwigger — Cross-origin resource sharing (CORS)",
    ],
    tags=["cors", "headers"],
    alert_short="CORS Wildcard + Creds",
))

_r(_nuclei_misconfig(
    slug="cors-permissive",
    title="Permissive CORS configuration on {asset}",
    severity="medium",
    cwe="CWE-942",
    description=(
        "The application reflects an arbitrary origin from the "
        "request `Origin` header back into "
        "`Access-Control-Allow-Origin`, or accepts overly broad "
        "CORS headers. While not as severe as wildcard-with-credentials, "
        "this can still allow attacker-origin pages to read "
        "responses that should be scoped to specific trusted origins."
    ),
    remediation=(
        "Replace dynamic origin reflection with an explicit allow-"
        "list of trusted origins. Validate `Origin` against the "
        "list rather than echoing it. Don't use suffix matching "
        "(`endsWith(\"example.com\")`) — `attackerexample.com` will "
        "match. Use exact-match or hostname-based validation."
    ),
    summary="CORS on {asset} reflects arbitrary origins — cross-origin reads from untrusted sites may be possible.",
    tags=["cors", "headers"],
    alert_short="CORS Permissive",
))

_r(_nuclei_misconfig(
    slug="open-redirect",
    title="Open redirect on {asset}",
    severity="medium",
    cwe="CWE-601",
    description=(
        "An endpoint on {asset} redirects to user-controlled URLs "
        "without validation. Attackers use open redirects to make "
        "phishing links look legitimate (`https://yourdomain.com/"
        "redirect?to=evil.com`) — the URL appears to point at your "
        "trusted domain but bounces to attacker content. Frequently "
        "abused in OAuth phishing and credential-stuffing campaigns."
    ),
    remediation=(
        "Validate redirect targets against an allow-list of trusted "
        "destinations. For internal redirects, only accept relative "
        "paths or explicit known hostnames — never reflect arbitrary "
        "URLs. If user-controlled redirects are essential (e.g., "
        "signed return-URL in OAuth), require a cryptographic "
        "signature on the destination parameter."
    ),
    summary="An open redirect on {asset} lets attackers craft phishing links that appear to point at your domain.",
    extra_refs=[
        "OWASP — Unvalidated Redirects and Forwards Cheat Sheet",
    ],
    tags=["redirect", "phishing"],
    alert_short="Open Redirect",
))

_r(_nuclei_misconfig(
    slug="host-header-injection",
    title="Host header injection vulnerability on {asset}",
    severity="high",
    cwe="CWE-644",
    description=(
        "The application uses the request `Host` header without "
        "validation when generating absolute URLs (e.g. password-"
        "reset links, OAuth callbacks, web cache keys). An attacker "
        "who controls the Host header can poison generated URLs to "
        "point at attacker-controlled domains, leading to "
        "credential theft via password-reset emails or web cache "
        "poisoning."
    ),
    remediation=(
        "Validate the `Host` header against an explicit allow-list "
        "(your canonical hostnames). Reject requests with "
        "unexpected hosts at the web server / CDN tier. In "
        "applications, never pass the raw Host header into URL "
        "construction — use a hardcoded canonical base URL for "
        "outbound emails and OAuth callbacks."
    ),
    summary="{asset} uses unverified Host headers — password-reset emails and cached URLs can be poisoned by attackers.",
    extra_refs=[
        "PortSwigger — HTTP Host header attacks",
    ],
    tags=["host-header", "headers"],
    alert_short="Host Header Injection",
))

_r(_nuclei_misconfig(
    slug="http-request-smuggling",
    title="HTTP request smuggling on {asset}",
    severity="high",
    cwe="CWE-444",
    description=(
        "{asset} appears vulnerable to HTTP request smuggling — a "
        "discrepancy between how a frontend (CDN, load balancer, "
        "WAF) and the backend interpret request boundaries via "
        "Content-Length and Transfer-Encoding headers. Smuggled "
        "requests bypass frontend security controls, can hijack "
        "other users' sessions, and are often used to chain into "
        "cache poisoning or stored XSS."
    ),
    remediation=(
        "Standardise request parsing across the chain:\n"
        "  • Reject requests with both Content-Length and "
        "Transfer-Encoding headers at the frontend (most modern "
        "WAFs offer a toggle).\n"
        "  • Enforce HTTP/2 from frontend to backend where "
        "possible — HTTP/2's framing eliminates smuggling.\n"
        "  • Patch the frontend and backend to current versions; "
        "many smuggling fixes are framework-version-specific.\n"
        "Investigate logs since the issue first surfaced for "
        "anomalous request sequences."
    ),
    summary="HTTP request smuggling is possible on {asset} — attackers can hijack sessions and bypass your CDN/WAF.",
    extra_refs=[
        "PortSwigger — HTTP request smuggling",
        "OWASP — HTTP Request Smuggling",
    ],
    tags=["smuggling", "http"],
    alert_short="Request Smuggling",
))

_r(_nuclei_misconfig(
    slug="http-trace-enabled",
    title="HTTP TRACE method enabled on {asset}",
    severity="low",
    cwe="CWE-693",
    description=(
        "The HTTP TRACE method is enabled on {asset}. TRACE was "
        "historically abusable for Cross-Site Tracing (XST) attacks "
        "to steal HttpOnly cookies via Flash or older browser quirks. "
        "Modern browsers block this; the residual concern today is "
        "as a reconnaissance signal — TRACE shouldn't be enabled "
        "on a hardened web server."
    ),
    remediation=(
        "Disable TRACE at the web server:\n"
        "  • Apache: `TraceEnable Off`\n"
        "  • nginx: TRACE is not implemented by default; check "
        "any custom modules that may have re-enabled it.\n"
        "  • IIS: disable via Request Filtering rules.\n"
        "  • Behind a CDN: most CDNs allow restricting accepted "
        "methods to GET / POST / HEAD only."
    ),
    summary="HTTP TRACE method is enabled on {asset} — disable it as part of your web-server hardening baseline.",
    tags=["http"],
    alert_short="TRACE Enabled",
))

_r(_nuclei_misconfig(
    slug="cache-deception",
    title="Web cache deception possible on {asset}",
    severity="medium",
    cwe="CWE-525",
    description=(
        "{asset} appears vulnerable to web cache deception — appending "
        "a static-looking suffix (`.css`, `.png`) to dynamic URLs "
        "causes the CDN to cache authenticated responses meant only "
        "for the user. Attackers exploit this by tricking authenticated "
        "users into requesting `/account.css`, then reading the cached "
        "user-specific response anonymously."
    ),
    remediation=(
        "Configure the CDN to cache by content-type or by an "
        "explicit allow-list of paths, not by URL extension. Set "
        "`Cache-Control: no-store, private` on responses to "
        "authenticated endpoints. Verify that adding an arbitrary "
        "static-looking suffix doesn't hit the cache for "
        "authenticated routes."
    ),
    summary="Web cache deception is possible on {asset} — authenticated user data may end up in the public cache.",
    extra_refs=[
        "PortSwigger — Web cache deception",
    ],
    tags=["cache", "headers"],
    alert_short="Cache Deception",
))

_r(_nuclei_misconfig(
    slug="tabnabbing",
    title="Reverse tabnabbing — links missing rel=noopener on {asset}",
    severity="low",
    cwe="CWE-1022",
    description=(
        "Outbound links on {asset} use `target=\"_blank\"` without "
        "`rel=\"noopener noreferrer\"`. The newly-opened tab can "
        "navigate the original tab via `window.opener` — used in "
        "reverse-tabnabbing phishing where the user returns to a "
        "lookalike of your site after clicking an outbound link. "
        "Modern browsers default to `noopener` for "
        "`target=\"_blank\"` links, so this finding is mostly a "
        "concern for older browsers and mobile webviews."
    ),
    remediation=(
        "Add `rel=\"noopener noreferrer\"` to every external link "
        "with `target=\"_blank\"`. Most templating frameworks and "
        "Markdown renderers can be configured to do this "
        "automatically. Web linters (eslint-plugin-react/jsx-no-"
        "target-blank) catch these at build time."
    ),
    summary="External links on {asset} use target=_blank without noopener — older browsers and webviews are vulnerable to tabnabbing.",
    tags=["tabnabbing"],
    alert_short="Tabnabbing",
))

_r(_nuclei_misconfig(
    slug="mixed-content",
    title="Mixed content (HTTPS page loads HTTP resources) on {asset}",
    severity="low",
    cwe="CWE-319",
    description=(
        "An HTTPS page on {asset} loads scripts, stylesheets, "
        "images, or iframes over plain HTTP. Modern browsers block "
        "active mixed content (scripts, frames) and warn on passive "
        "(images, video). Even passive mixed content gives a "
        "network-positioned attacker a vector to inject malicious "
        "responses, and the browser address bar removes the secure "
        "padlock — undermining the trust signal you're paying for "
        "with TLS."
    ),
    remediation=(
        "Replace `http://` references with `https://` (or "
        "protocol-relative `//` URLs that inherit the page's scheme). "
        "Add a `Content-Security-Policy: upgrade-insecure-requests` "
        "header to silently upgrade mixed content during transition. "
        "Test with the browser developer console which will report "
        "every mixed-content load."
    ),
    summary="An HTTPS page on {asset} loads HTTP resources — a network attacker can inject content into the page.",
    extra_refs=[
        "MDN — Mixed content",
    ],
    tags=["mixed-content", "tls"],
    alert_short="Mixed Content",
))


# ─── GraphQL ──────────────────────────────────────────────────────────────

_r(_nuclei_misconfig(
    slug="graphql-introspection-enabled",
    title="GraphQL introspection enabled on {asset}",
    severity="medium",
    cwe="CWE-200",
    description=(
        "The GraphQL endpoint on {asset} responds to introspection "
        "queries. Introspection returns the full schema — every "
        "type, field, mutation, and argument — which removes the "
        "primary obstacle to API enumeration. Public APIs sometimes "
        "leave introspection enabled deliberately, but for internal "
        "or partner-only APIs it's a reconnaissance gift."
    ),
    remediation=(
        "Disable introspection in production:\n"
        "  • Apollo Server: set `introspection: false` in the "
        "`ApolloServer` config.\n"
        "  • express-graphql / GraphQL.js: disable via the "
        "`introspection` option or wrap with a query-validation "
        "plugin that rejects `__schema` / `__type` queries.\n"
        "  • Hasura: disable in console settings → API.\n"
        "If you need introspection for tooling (codegen, IDE), "
        "gate it behind an authenticated admin role."
    ),
    summary="GraphQL on {asset} returns its full schema to anyone — disable introspection in production.",
    extra_refs=[
        "OWASP — GraphQL Cheat Sheet",
    ],
    tags=["graphql", "info-disclosure"],
    alert_short="GraphQL Introspection",
))

_r(_nuclei_misconfig(
    slug="graphql-playground-exposed",
    title="GraphQL Playground / GraphiQL exposed on {asset}",
    severity="medium",
    cwe="CWE-200",
    description=(
        "An interactive GraphQL UI (GraphQL Playground, GraphiQL, "
        "Apollo Studio, Altair) is reachable on {asset}. These tools "
        "are intended for development and combine introspection with "
        "an interactive query builder — anyone who reaches the URL "
        "can map your API and run authenticated queries if they "
        "have any credentials."
    ),
    remediation=(
        "Disable the playground/IDE in production:\n"
        "  • Apollo Server v3+: set `playground: false`.\n"
        "  • Apollo Server v4+: the landing page is configured via "
        "`plugins`; use `ApolloServerPluginLandingPageDisabled()`.\n"
        "  • GraphiQL: usually exposed via a separate route — "
        "remove it from production builds.\n"
        "If a UI is genuinely useful, gate it behind authentication "
        "on a non-production hostname only."
    ),
    summary="A GraphQL playground UI is reachable on {asset} — it shouldn't be in production.",
    extra_refs=[
        "OWASP — GraphQL Cheat Sheet",
    ],
    tags=["graphql"],
    alert_short="GraphQL Playground",
))

_r(_nuclei_misconfig(
    slug="graphql-batching",
    title="GraphQL batching attacks possible on {asset}",
    severity="medium",
    cwe="CWE-770",
    description=(
        "The GraphQL endpoint on {asset} accepts arrays of queries "
        "in a single request (query batching) without rate limiting "
        "the array size or per-query cost. Attackers exploit this "
        "to bypass per-request rate limits — sending hundreds of "
        "login attempts or expensive mutations in a single HTTP "
        "request, none of which trip per-request throttles."
    ),
    remediation=(
        "Implement query-cost analysis (e.g., `graphql-cost-analysis` "
        "for Apollo, `graphql-validation-complexity`) and reject "
        "requests that exceed a complexity budget. Cap the batch "
        "size to a small number (e.g., 10) at the GraphQL server. "
        "Apply rate limits to each query in the batch, not the "
        "request as a whole."
    ),
    summary="GraphQL on {asset} accepts batched queries — rate limits can be bypassed by stacking many queries per request.",
    tags=["graphql", "rate-limiting"],
    alert_short="GraphQL Batching",
))


# ─── Server-side injection / SSRF ─────────────────────────────────────────

_r(_nuclei_misconfig(
    slug="server-side-template-injection",
    title="Server-side template injection (SSTI) on {asset}",
    severity="high",
    cwe="CWE-1336",
    description=(
        "Nuclei detected server-side template injection on {asset}. "
        "The application renders user-supplied input inside a "
        "templating engine (Jinja2, Twig, Velocity, FreeMarker, "
        "Pug, Handlebars, etc.) without sandboxing — leading to "
        "remote code execution via template syntax in user input. "
        "VMware Workspace ONE (CVE-2022-22954) was the highest-"
        "profile recent SSTI."
    ),
    remediation=(
        "**Patch the affected endpoint immediately**\n"
        "  Stop passing user input directly into template rendering. "
        "Pass user data as bound variables (template context) "
        "instead — the template should be a static asset.\n\n"
        "**Restrict template engine capabilities**\n"
        "  Most templating engines have a sandbox mode that disables "
        "filesystem and process access. Enable it.\n\n"
        "**Audit for compromise**\n"
        "  SSTI typically means RCE was already possible; review "
        "process and filesystem audit logs since the endpoint became "
        "vulnerable."
    ),
    summary="Server-side template injection on {asset} — likely remote code execution. Patch and audit immediately.",
    extra_refs=[
        "PortSwigger — Server-side template injection",
    ],
    tags=["ssti", "rce-risk"],
    alert_short="SSTI",
    category="cve",
))

_r(_nuclei_misconfig(
    slug="ssrf-detected",
    title="Server-side request forgery (SSRF) on {asset}",
    severity="high",
    cwe="CWE-918",
    description=(
        "Nuclei detected server-side request forgery on {asset}. "
        "An endpoint accepts a URL parameter and fetches it from "
        "the server side without validation, letting attackers "
        "reach internal services, cloud metadata endpoints "
        "(169.254.169.254), and localhost-only management "
        "interfaces. SSRF is the entry point for many cloud-account "
        "compromises (Capital One, 2019)."
    ),
    remediation=(
        "Validate fetch targets against an allow-list of known "
        "hostnames or IP ranges. Reject requests to private "
        "address space (RFC 1918, RFC 6598, link-local, loopback). "
        "Use IMDSv2 on AWS (requires session token, defeats classic "
        "SSRF). Front the affected endpoint with an egress proxy "
        "that enforces destination policy regardless of the "
        "application code."
    ),
    summary="An SSRF vulnerability on {asset} — attackers may reach your internal services and cloud metadata. Patch and audit.",
    extra_refs=[
        "OWASP — Server Side Request Forgery Prevention Cheat Sheet",
    ],
    tags=["ssrf"],
    alert_short="SSRF",
    category="cve",
))

_r(_nuclei_misconfig(
    slug="blind-ssrf",
    title="Blind server-side request forgery on {asset}",
    severity="high",
    cwe="CWE-918",
    description=(
        "Nuclei detected blind SSRF on {asset} — the application "
        "fetches an attacker-supplied URL but doesn't return the "
        "response body. Confirmed via out-of-band (OOB) interaction: "
        "the affected endpoint reached out to a Nuclei-hosted "
        "callback. Blind SSRF is harder to exploit but still "
        "actionable for internal-network reconnaissance and "
        "cloud-metadata theft."
    ),
    remediation=(
        "Same approach as standard SSRF: allow-list destinations, "
        "block private address space, use IMDSv2. The blind variant "
        "is still exploitable — patch with the same urgency. Audit "
        "outbound network connections from the affected service for "
        "unexpected destinations since the issue first surfaced."
    ),
    summary="Blind SSRF on {asset} — confirmed via out-of-band interaction. Patch as you would any SSRF.",
    extra_refs=[
        "OWASP — SSRF Prevention Cheat Sheet",
    ],
    tags=["ssrf"],
    alert_short="Blind SSRF",
    category="cve",
))


# ─── Cloud metadata SSRF ──────────────────────────────────────────────────

_r(_nuclei_misconfig(
    slug="aws-imds-ssrf",
    title="AWS IMDS reachable via SSRF from {asset}",
    severity="critical",
    cwe="CWE-918",
    description=(
        "Nuclei reached the AWS Instance Metadata Service "
        "(169.254.169.254) via a vulnerable endpoint on {asset}. "
        "On EC2, IMDS returns the IAM role's temporary "
        "credentials — an attacker with this SSRF has full access "
        "to whatever AWS resources the instance role grants. The "
        "Capital One breach (100M+ records) followed exactly this "
        "pattern."
    ),
    remediation=(
        "**Treat as an active incident**\n"
        "  Assume the instance role's credentials have been "
        "exfiltrated and used. Review CloudTrail for unfamiliar API "
        "calls from the instance role since the endpoint became "
        "vulnerable; rotate the role's session credentials by "
        "stopping/starting the instance.\n\n"
        "**Enforce IMDSv2**\n"
        "  Set the EC2 instance metadata options to "
        "`HttpTokens=required` — IMDSv2 requires a PUT-issued "
        "session token, defeating classic single-step SSRF. Use "
        "the EC2 console / `aws ec2 modify-instance-metadata-options` "
        "or set it as a default at the account level via the "
        "instance-metadata-defaults setting.\n\n"
        "**Patch the SSRF**\n"
        "  Fix the underlying endpoint (allow-list destinations, "
        "block 169.254.169.254 explicitly) regardless — IMDSv2 is "
        "defence-in-depth, not a substitute."
    ),
    summary="Your AWS instance metadata service is reachable via SSRF from {asset} — the instance role's credentials should be considered exfiltrated. Audit CloudTrail and rotate.",
    extra_refs=[
        "AWS — Use IMDSv2",
        "Krebs — Capital One breach analysis",
    ],
    tags=["ssrf", "aws", "imds", "cloud-creds"],
    alert_short="AWS IMDS SSRF",
    category="cve",
))

_r(_nuclei_misconfig(
    slug="azure-imds-ssrf",
    title="Azure IMDS reachable via SSRF from {asset}",
    severity="critical",
    cwe="CWE-918",
    description=(
        "Nuclei reached the Azure Instance Metadata Service "
        "(169.254.169.254) via a vulnerable endpoint on {asset}. "
        "Azure IMDS returns access tokens for the VM's managed "
        "identity — equivalent to that managed identity's full "
        "Azure permissions, including any subscription / resource-"
        "group / Key Vault grants."
    ),
    remediation=(
        "Patch the SSRF (allow-list, block 169.254.169.254). "
        "Azure IMDS already requires the `Metadata: true` header "
        "(blocks classic SSRF that doesn't set arbitrary headers) "
        "but many SSRF primitives can supply that. Audit Azure "
        "AD sign-in logs for the managed identity since the "
        "endpoint became vulnerable; check Key Vault audit logs "
        "for unauthorised secret reads. Rotate the managed-identity "
        "secrets if compromise is suspected."
    ),
    summary="Azure IMDS reachable via SSRF on {asset} — the VM's managed identity should be considered compromised.",
    extra_refs=[
        "Microsoft — Azure Instance Metadata service",
    ],
    tags=["ssrf", "azure", "imds", "cloud-creds"],
    alert_short="Azure IMDS SSRF",
    category="cve",
))

_r(_nuclei_misconfig(
    slug="gcp-metadata-ssrf",
    title="GCP metadata server reachable via SSRF from {asset}",
    severity="critical",
    cwe="CWE-918",
    description=(
        "Nuclei reached the GCP metadata server "
        "(metadata.google.internal / 169.254.169.254) via a "
        "vulnerable endpoint on {asset}. GCP metadata returns "
        "access tokens for the instance's service account — full "
        "GCP API access at the service account's permissions, "
        "including any project, dataset, bucket, or secret it "
        "can read."
    ),
    remediation=(
        "Patch the SSRF (allow-list destinations, block "
        "metadata.google.internal and 169.254.169.254). GCP requires "
        "the `Metadata-Flavor: Google` header which blocks naive "
        "SSRF — but flexible SSRF primitives can supply it. Audit "
        "GCP Audit Logs for the service account since the endpoint "
        "became vulnerable; rotate the service account's keys if "
        "compromise is suspected."
    ),
    summary="GCP metadata server reachable via SSRF on {asset} — the instance service-account's tokens should be considered compromised.",
    extra_refs=[
        "Google Cloud — Metadata server protection",
    ],
    tags=["ssrf", "gcp", "imds", "cloud-creds"],
    alert_short="GCP Metadata SSRF",
    category="cve",
))


# ─── IaC / DevOps misconfigurations ───────────────────────────────────────

_r(_nuclei_misconfig(
    slug="exposed-helm-values",
    title="Exposed Helm chart values on {asset}",
    severity="high",
    cwe="CWE-200",
    description=(
        "A Helm chart `values.yaml` (or rendered chart manifest) is "
        "publicly readable on {asset}. Helm values frequently "
        "contain secrets that haven't yet been moved into Sealed "
        "Secrets / External Secrets Operator: database passwords, "
        "S3 bucket keys, image-pull credentials, OAuth client "
        "secrets, signing keys."
    ),
    remediation=(
        "Move secrets out of `values.yaml` into Sealed Secrets, "
        "External Secrets Operator, or a Helm secrets plugin "
        "backed by a managed KMS. Treat any secret currently in a "
        "publicly-readable values file as compromised — rotate. "
        "Don't deploy chart sources to a public webroot; produce "
        "a release artefact that doesn't include `values.yaml`."
    ),
    summary="A Helm values file is publicly readable on {asset} — likely contains secrets that should be rotated.",
    extra_refs=[
        "Sealed Secrets",
        "External Secrets Operator",
    ],
    tags=["k8s", "helm", "secrets"],
    alert_short="Helm Values Exposed",
    category="leak",
))

_r(_nuclei_misconfig(
    slug="exposed-helm-tiller",
    title="Helm Tiller (v2) reachable on {asset}",
    severity="critical",
    cwe="CWE-306",
    description=(
        "A Helm Tiller (v2) endpoint is reachable on {asset}. "
        "Tiller v2 ran with cluster-admin equivalent permissions "
        "and accepted unauthenticated gRPC requests by default — "
        "anyone reaching the port could deploy arbitrary workloads "
        "to the cluster. Helm v3 removed Tiller entirely; if you "
        "see this finding, you're on a deprecated and "
        "fundamentally-insecure Helm version."
    ),
    remediation=(
        "**Migrate to Helm v3 immediately**\n"
        "  Helm v2 was deprecated in 2020 and reached end-of-life "
        "in November 2020. The `helm 2to3` plugin migrates "
        "releases.\n\n"
        "**Audit cluster state**\n"
        "  Review every Deployment, StatefulSet, DaemonSet, and "
        "Job in the cluster for unfamiliar workloads that could "
        "have been planted via Tiller. Check ClusterRoleBindings "
        "for new entries."
    ),
    summary="Helm Tiller (v2) is reachable on {asset} — anyone on the network can deploy arbitrary workloads. Migrate to Helm v3 now.",
    extra_refs=[
        "Helm — Migrating Helm v2 to v3",
    ],
    tags=["k8s", "helm", "rce-risk"],
    alert_short="Helm Tiller",
))

_r(_nuclei_misconfig(
    slug="spring-cloud-env",
    title="Spring Cloud Config server exposing /env on {asset}",
    severity="high",
    cwe="CWE-200",
    description=(
        "A Spring Cloud Config Server (or Spring application "
        "exposing `/env` directly) is publicly readable on {asset}. "
        "The endpoint dumps every property in the Spring environment "
        "— database passwords, third-party API keys, JWT signing "
        "secrets — across all profiles served by the config server."
    ),
    remediation=(
        "Restrict Spring Cloud Config Server to internal networks. "
        "Enable basic auth via Spring Security on the config "
        "server. Move sensitive properties out of plaintext "
        "git-backed config and into encrypted form (Spring Cloud "
        "Config supports JCE-based property encryption) or a "
        "managed secret store. Rotate anything visible in the "
        "currently-exposed `/env`."
    ),
    summary="Spring Cloud Config /env exposed on {asset} — secrets across all profiles are leaking. Rotate now.",
    extra_refs=[
        "Spring Cloud Config — Security",
    ],
    tags=["spring", "java", "config-leak"],
    alert_short="Spring Cloud /env",
    category="leak",
))

_r(_nuclei_misconfig(
    slug="exposed-spring-eureka",
    title="Spring Eureka service registry exposed on {asset}",
    severity="medium",
    cwe="CWE-200",
    description=(
        "A Spring Eureka service registry is reachable on {asset}. "
        "Eureka stores the names, hostnames, and ports of every "
        "microservice in the deployment — exactly the internal-"
        "topology map an attacker wants for lateral movement and "
        "targeted SSRF. Eureka also accepts service registrations, "
        "letting an attacker register their own host and intercept "
        "client traffic."
    ),
    remediation=(
        "Restrict Eureka to internal networks. Enable basic auth "
        "via Spring Security on the Eureka server. Disable "
        "anonymous service registration if not needed."
    ),
    summary="A Spring Eureka registry is reachable on {asset} — your full microservice topology is visible.",
    extra_refs=[
        "Spring Cloud Netflix — Eureka",
    ],
    tags=["spring", "java", "info-disclosure"],
    alert_short="Spring Eureka",
))


# ─── Database / cache exposure ────────────────────────────────────────────

_r(_nuclei_misconfig(
    slug="exposed-cassandra",
    title="Apache Cassandra exposed without authentication on {asset}",
    severity="high",
    cwe="CWE-306",
    description=(
        "Nuclei confirmed an Apache Cassandra instance on {asset} "
        "responds without authentication. Cassandra ships with "
        "auth disabled by default; exposed instances let any "
        "client connect and read/write every keyspace. Several "
        "documented breach incidents involved unauthenticated "
        "Cassandra clusters."
    ),
    remediation=(
        "Enable authentication in `cassandra.yaml`: set "
        "`authenticator: PasswordAuthenticator` and "
        "`authorizer: CassandraAuthorizer`. Restart and create "
        "non-default users via cqlsh; remove the default `cassandra` "
        "superuser or change its password from the default "
        "(`cassandra/cassandra`). Restrict the CQL port (9042) and "
        "internode port (7000/7001) to internal networks."
    ),
    summary="Cassandra on {asset} accepts unauthenticated connections — every keyspace is reachable.",
    extra_refs=[
        "Apache Cassandra — Security",
    ],
    tags=["database", "no-auth"],
    alert_short="Cassandra",
))

_r(_nuclei_misconfig(
    slug="exposed-couchbase",
    title="Couchbase exposed without authentication on {asset}",
    severity="high",
    cwe="CWE-306",
    description=(
        "A Couchbase node is reachable on {asset} without "
        "authentication, or with default credentials. Couchbase's "
        "REST and N1QL endpoints (typically 8091, 8092, 8093) "
        "should never be internet-exposed. Once authenticated, an "
        "attacker has full read/write to every bucket."
    ),
    remediation=(
        "Restrict Couchbase node ports (8091/8092/8093/11210) to "
        "internal networks. Replace any default credentials. "
        "Enable encryption-in-transit via Couchbase's TLS "
        "configuration. Audit recent admin activity in the "
        "Couchbase Web Console."
    ),
    summary="Couchbase on {asset} is reachable without proper auth — every bucket is at risk.",
    extra_refs=[
        "Couchbase — Security",
    ],
    tags=["database", "no-auth"],
    alert_short="Couchbase",
))

_r(_nuclei_misconfig(
    slug="exposed-memcached",
    title="Memcached exposed on {asset}",
    severity="high",
    cwe="CWE-306",
    description=(
        "A Memcached instance is reachable on {asset}. Memcached "
        "has no authentication mechanism — anyone reaching port "
        "11211 can read, write, and flush every cache entry. "
        "Exposed Memcached has also been weaponised for amplification "
        "DDoS attacks (Memcrashed, 2018) — your server may have "
        "participated in attacks against third parties without "
        "your knowledge."
    ),
    remediation=(
        "Bind Memcached to localhost (`-l 127.0.0.1`) or an internal "
        "interface only. Disable UDP support entirely "
        "(`-U 0`) — this is the change that prevents amplification-"
        "DDoS abuse. If remote access is genuinely required, use "
        "a reverse proxy with auth or SASL-enabled Memcached "
        "(many distributions don't ship SASL by default)."
    ),
    summary="Memcached on {asset} is reachable without auth — your data is at risk and your server may be participating in DDoS amplification.",
    extra_refs=[
        "Memcached — Security",
        "Cloudflare — The Memcrashed amplification attack",
    ],
    tags=["cache", "no-auth", "amplification"],
    alert_short="Memcached",
))

_r(_nuclei_misconfig(
    slug="exposed-redis-public",
    title="Unauthenticated Redis on {asset}",
    severity="high",
    cwe="CWE-306",
    description=(
        "Nuclei confirmed Redis on {asset} responds without "
        "authentication. Even when AUTH is set, default config "
        "exposed to the internet allows attackers to write "
        "arbitrary files via CONFIG SET (including SSH "
        "authorized_keys). Exposed Redis instances are routinely "
        "compromised within hours."
    ),
    remediation=(
        "**Lock down immediately**\n"
        "  Bind to localhost or an internal interface "
        "(`bind 127.0.0.1`). Enable `protected-mode yes`. Run "
        "Redis as an unprivileged user. Set a strong AUTH password "
        "or, on Redis 6+, configure ACL users with least privilege.\n\n"
        "**Audit for compromise**\n"
        "  Check `~/.ssh/authorized_keys` on the Redis host for "
        "unfamiliar entries. Review the Redis dump file for "
        "unexpected keys (cryptominer config is common). Inspect "
        "running processes for `xmrig` and friends."
    ),
    summary="Redis on {asset} accepts unauthenticated connections — patch and audit for compromise immediately.",
    extra_refs=[
        "Redis — Security",
    ],
    tags=["database", "no-auth"],
    alert_short="Redis Unauth",
))

_r(_nuclei_misconfig(
    slug="exposed-mongodb-public",
    title="Unauthenticated MongoDB on {asset}",
    severity="high",
    cwe="CWE-306",
    description=(
        "Nuclei confirmed MongoDB on {asset} responds without "
        "authentication. Pre-3.6 MongoDB shipped with auth disabled "
        "by default — the resulting mass-ransom campaigns ('Meow' "
        "wipes, ransom notes left in databases) hit thousands of "
        "instances. Modern MongoDB binds to localhost out of the box, "
        "so an internet-exposed unauthenticated instance has been "
        "actively reconfigured."
    ),
    remediation=(
        "Enable authentication in `mongod.conf`: "
        "`security.authorization: enabled`. Create a per-database "
        "user with least privilege; remove any test accounts. Bind "
        "to an internal interface, not 0.0.0.0. Restore from the "
        "most recent clean backup if your data has been wiped or "
        "ransomed (don't pay)."
    ),
    summary="MongoDB on {asset} accepts unauthenticated connections — restore from backup if data is missing, then enable auth.",
    extra_refs=[
        "MongoDB — Security Checklist",
    ],
    tags=["database", "no-auth"],
    alert_short="MongoDB Unauth",
))


# ─── Network services ─────────────────────────────────────────────────────

_r(_nuclei_misconfig(
    slug="smtp-open-relay",
    title="SMTP open relay on {asset}",
    severity="high",
    cwe="CWE-285",
    description=(
        "{asset} accepts and forwards email for arbitrary sender / "
        "recipient combinations without authentication — an open "
        "relay. Spammers and phishing operators use open relays to "
        "send mail that appears to originate from your IP "
        "(damaging your IP reputation) or to spoof other domains "
        "(damaging your domain reputation when the relay's "
        "outgoing IP gets associated with abuse)."
    ),
    remediation=(
        "Configure the MTA to require authentication for relaying "
        "and to restrict relaying to known-trusted sender networks "
        "only. In Postfix: set `smtpd_recipient_restrictions` to "
        "`permit_mynetworks, permit_sasl_authenticated, reject`. "
        "In Exim: configure `acl_smtp_rcpt` accordingly. Verify by "
        "attempting to relay from an external IP to an external "
        "address — should be rejected. Check IP-reputation lookups "
        "(Spamhaus, SORBS) — may need delisting after fix."
    ),
    summary="SMTP on {asset} relays mail for anyone — your IP is being used for spam and phishing.",
    extra_refs=[
        "Postfix — STANDARD_CONFIGURATION_README",
    ],
    tags=["smtp", "email"],
    alert_short="Open SMTP Relay",
))

_r(_nuclei_misconfig(
    slug="exposed-rsync",
    title="Unauthenticated rsync server on {asset}",
    severity="high",
    cwe="CWE-306",
    description=(
        "An rsync server on {asset} (port 873) accepts connections "
        "without authentication. Attackers can list every module, "
        "download arbitrary files, and on misconfigured modules "
        "write files into the host's filesystem. Common as a "
        "leftover from backup-replication setups that were never "
        "secured."
    ),
    remediation=(
        "Edit `rsyncd.conf` to require authentication: set "
        "`auth users` and `secrets file` per module. Add `read only "
        "= yes` on modules where write access isn't needed. "
        "Restrict module access via `hosts allow` to known source "
        "IPs. Better — bind rsync to localhost and tunnel over SSH "
        "for remote replication."
    ),
    summary="An unauthenticated rsync server on {asset} — anyone can list and download every module's contents.",
    extra_refs=[
        "rsync — rsyncd.conf manpage",
    ],
    tags=["rsync"],
    alert_short="rsync Unauth",
))

_r(_nuclei_misconfig(
    slug="exposed-ldap-anonymous",
    title="Anonymous LDAP bind allowed on {asset}",
    severity="high",
    cwe="CWE-287",
    description=(
        "The LDAP server on {asset} accepts anonymous binds and "
        "returns directory contents without authentication. "
        "Attackers harvest organisational structure, employee "
        "usernames, group memberships, and (in some misconfigured "
        "AD environments) credential material from "
        "`userPassword`-like attributes."
    ),
    remediation=(
        "Disable anonymous binds:\n"
        "  • OpenLDAP: set `disallow bind_anon` in slapd.conf, or "
        "set `olcDisallows: bind_anon` in dynamic config.\n"
        "  • Active Directory: set "
        "`dsHeuristics` attribute to disallow anonymous binds; "
        "audit `domain controllers` for the `LDAP server "
        "channel binding token requirements` registry setting.\n"
        "  • 389-ds: use `nsslapd-allow-anonymous-access: off`.\n"
        "Restrict LDAP (389) and LDAPS (636) to internal networks."
    ),
    summary="LDAP on {asset} allows anonymous binds — your directory structure is enumerable.",
    extra_refs=[
        "Microsoft — LDAP server channel binding",
    ],
    tags=["ldap", "active-directory"],
    alert_short="LDAP Anonymous",
))

_r(_nuclei_misconfig(
    slug="exposed-snmp-public-community",
    title="SNMP with default 'public' community string on {asset}",
    severity="high",
    cwe="CWE-1188",
    description=(
        "SNMP on {asset} responds to the default `public` community "
        "string. SNMP returns device configuration, routing tables, "
        "interface stats, and ARP/MAC tables — full network "
        "topology recon. Many devices also respond to `private` "
        "with read-write access, allowing config changes."
    ),
    remediation=(
        "Replace the `public` community string with a strong "
        "secret-equivalent string. Disable SNMPv1/v2c and switch "
        "to SNMPv3 with authentication and encryption. Restrict "
        "SNMP (UDP 161) to known monitoring servers via firewall. "
        "Audit any device that previously had `public` enabled — "
        "config changes may have been made via `private`."
    ),
    summary="SNMP on {asset} responds to 'public' community — network topology and device config are exposed.",
    extra_refs=[
        "RFC 3414 — SNMPv3 User-based Security Model",
    ],
    tags=["snmp"],
    alert_short="SNMP Public",
))

_r(_nuclei_misconfig(
    slug="exposed-mqtt",
    title="MQTT broker exposed without authentication on {asset}",
    severity="medium",
    cwe="CWE-306",
    description=(
        "An MQTT broker on {asset} accepts connections without "
        "authentication. MQTT is the dominant protocol for IoT "
        "device telemetry; exposed brokers leak sensor data, "
        "device identity, and command topics — and authenticated-"
        "but-anonymous-allowed brokers let attackers inject "
        "commands that devices act on."
    ),
    remediation=(
        "Enable authentication in the broker config (Mosquitto: "
        "`allow_anonymous false` + `password_file`). Use TLS for "
        "the MQTT port (8883 instead of 1883). Restrict broker "
        "access to internal networks where possible."
    ),
    summary="An MQTT broker on {asset} accepts unauthenticated connections — IoT data and commands are exposed.",
    extra_refs=[
        "Mosquitto — Security",
    ],
    tags=["mqtt", "iot"],
    alert_short="MQTT",
))


# ─── DNS / NTP misconfigurations ──────────────────────────────────────────

_r(_nuclei_misconfig(
    slug="dns-open-resolver",
    title="DNS open resolver on {asset}",
    severity="medium",
    cwe="CWE-406",
    description=(
        "{asset} answers recursive DNS queries from arbitrary "
        "internet sources. Open resolvers are abused for DNS "
        "amplification attacks — attackers send small spoofed "
        "queries that elicit large responses, overwhelming the "
        "spoofed victim. Your server's bandwidth is being "
        "consumed by attacks against third parties."
    ),
    remediation=(
        "Restrict recursion to your customers / internal networks "
        "only. In BIND: `allow-recursion { trusted-clients; };`. "
        "In Unbound: set `access-control:` for known networks. "
        "If the server is intended as an authoritative-only DNS, "
        "disable recursion entirely (`recursion no;`). Enable "
        "response-rate-limiting (RRL) as defence-in-depth."
    ),
    summary="DNS on {asset} answers recursive queries from anywhere — being used for amplification attacks.",
    extra_refs=[
        "DNS-OARC — Open resolver problem",
    ],
    tags=["dns", "amplification"],
    alert_short="Open DNS Resolver",
))

_r(_nuclei_misconfig(
    slug="ntp-monlist",
    title="NTP monlist enabled on {asset}",
    severity="medium",
    cwe="CWE-406",
    description=(
        "The NTP server on {asset} responds to the deprecated "
        "`monlist` command (mode 7). monlist returns up to 600 "
        "of the most recent NTP clients with each query — a "
        "~200x amplification factor that's weaponised for DDoS. "
        "Has been a major DDoS-amplification vector since 2014."
    ),
    remediation=(
        "Upgrade ntpd to 4.2.7p26 or later (2010+). On older "
        "ntpd, disable monlist explicitly: add "
        "`disable monitor` to ntp.conf. Even better: switch to "
        "chrony (the modern default on most Linux distributions) "
        "which doesn't implement monlist at all. Confirm "
        "`ntpdc -c monlist <host>` returns no data after the "
        "fix."
    ),
    summary="NTP on {asset} responds to monlist — being used for DDoS amplification.",
    extra_refs=[
        "US-CERT — NTP Amplification Attacks Using CVE-2013-5211",
    ],
    tags=["ntp", "amplification"],
    alert_short="NTP monlist",
))


# ─── Other ────────────────────────────────────────────────────────────────

_r(_nuclei_misconfig(
    slug="exposed-flink-ui",
    title="Apache Flink dashboard exposed on {asset}",
    severity="medium",
    cwe="CWE-306",
    description=(
        "An Apache Flink dashboard is reachable on {asset}. Flink's "
        "web UI doesn't ship with auth — anyone reaching it can "
        "submit JAR files and execute arbitrary code via the job "
        "submission interface. Exposed Flink dashboards have been "
        "used for cryptojacking by automated tooling."
    ),
    remediation=(
        "Take Flink off the public internet. Place behind a reverse "
        "proxy enforcing authentication. Disable JAR upload via "
        "`web.submit.enable: false` if the cluster is read-only. "
        "Review submitted JARs for unfamiliar jobs."
    ),
    summary="Apache Flink dashboard on {asset} is reachable without auth — anyone can submit JARs and run code.",
    extra_refs=[
        "Apache Flink — Security",
    ],
    tags=["streaming", "rce-risk"],
    alert_short="Flink",
))


# ───────────────────────────────────────────────────────────────────────────
# Nuclei — Default Credentials (Batch D3)
# ───────────────────────────────────────────────────────────────────────────
# Curated copy for Nuclei templates that ACTIVELY VERIFY default
# credentials work — not just that a login page exists. These findings
# fire after Nuclei successfully authenticated, so severity is high or
# critical: access is confirmed, not inferred.
#
# Different from D2 (panel detected, login required) and D4
# (service exposed without auth). The signal here is "we logged in
# with admin/admin and it worked."

def _nuclei_default_creds(
    *,
    slug: str,
    product: str,
    creds: list[str],
    impact: str,
    severity: str = "high",
    cwe: str = "CWE-1188",
    extra_remediation: str | None = None,
    extra_refs: list[str] | None = None,
    tags: list[str] | None = None,
    alert_short: str | None = None,
) -> FindingTemplate:
    """Factory for default-credential templates.

    `creds` lists the specific username/password pairs Nuclei proved
    work. Severity defaults to high because access is verified — bump
    to critical when the product grants RCE or full data access on
    successful login (Tomcat Manager, Jenkins, MongoDB, etc.).
    """
    creds_block = ", ".join(f"`{c}`" for c in creds)
    description = (
        f"Nuclei confirmed that the {product} instance on {{asset}} "
        f"accepts known default credentials ({creds_block}). " + impact
    )
    remediation = (
        "**Rotate the credentials immediately**\n"
        "  Reset the default account's password to a strong, unique "
        "value. If multiple accounts may share the default, force a "
        "reset across all admin accounts.\n\n"
        "**Audit recent activity**\n"
        f"  Review the {product} audit log / sign-in log for "
        "unfamiliar sessions, configuration changes, and admin "
        "actions since the system was first reachable. Treat any "
        "default-credential session as potentially attacker activity "
        "until proven otherwise.\n\n"
        "**Restrict reachability**\n"
        "  If the panel doesn't need to be public, move it behind a "
        "VPN or auth proxy. Default-creds findings on internal-only "
        "surfaces are easier to triage and limit blast radius."
    )
    if extra_remediation:
        remediation = remediation + "\n\n" + extra_remediation

    return FindingTemplate(
        template_id=f"nuclei-{slug}",
        title=f"{product} default credentials accepted at {{asset}}",
        description=description,
        remediation=remediation,
        severity=severity,
        category="misconfiguration",
        cwe=cwe,
        tags=["nuclei", "default-credentials", slug] + (tags or []),
        summary=(
            f"Default credentials work on the {product} instance at "
            "{asset} — rotate immediately and audit recent activity."
        ),
        alert_name=f"Default Creds — {alert_short or product}",
        monitor_type="config_change",
        references=[
            "OWASP A07 — Identification and Authentication Failures",
            "CWE-1188: Insecure Default Initialization of Resource",
        ] + (extra_refs or []),
    )


# ─── Web apps / dashboards ────────────────────────────────────────────────

_r(_nuclei_default_creds(
    slug="tomcat-default-login",
    product="Tomcat Manager",
    creds=["tomcat/tomcat", "admin/admin", "tomcat/s3cret", "admin/tomcat"],
    severity="critical",
    impact=(
        "The Tomcat Manager app accepts default credentials. With "
        "Manager access, anyone can deploy a malicious WAR file via "
        "the upload form and achieve remote code execution as the "
        "Tomcat process user — ransomware crews target this exact "
        "configuration at internet scale."
    ),
    extra_remediation=(
        "**Better — remove Tomcat Manager entirely**\n"
        "  Manager has no place on internet-facing Tomcat instances. "
        "`rm -rf $CATALINA_HOME/webapps/manager` and `host-manager` "
        "is the right answer. If you genuinely need remote deploy, "
        "do it through CI/CD over SSH, not via the web UI."
    ),
    extra_refs=["Apache Tomcat — Manager App How-To"],
    tags=["rce-risk"],
    alert_short="Tomcat Manager",
))

_r(_nuclei_default_creds(
    slug="jenkins-default-credentials",
    product="Jenkins",
    creds=["admin/admin", "admin/jenkins", "jenkins/jenkins"],
    severity="critical",
    impact=(
        "Jenkins admin access is functionally equivalent to RCE on "
        "the controller — admins can run Groovy via the script "
        "console (`/script`), trigger arbitrary builds, and read "
        "every credential in the Credentials store. Jenkins is one "
        "of the most-attacked CI/CD platforms; default-creds "
        "findings here are entry points to full supply-chain "
        "compromise."
    ),
    extra_remediation=(
        "**Rotate every secret in the Credentials store**\n"
        "  Treat all stored deploy keys, API tokens, signing keys, "
        "and passwords as compromised. Cross-reference with downstream "
        "systems (artefact registries, cloud accounts) for unauthorised "
        "use.\n\n"
        "**Disable signup, enforce SSO**\n"
        "  Configure Matrix-based authorisation; require external "
        "IdP login. Disable the script console for non-admin roles."
    ),
    extra_refs=["Jenkins — Securing Jenkins"],
    tags=["ci-cd", "rce-risk", "supply-chain"],
    alert_short="Jenkins",
))

_r(_nuclei_default_creds(
    slug="grafana-default-credentials",
    product="Grafana",
    creds=["admin/admin"],
    severity="high",
    impact=(
        "Grafana ships with `admin/admin` as the default. Once "
        "authenticated as admin, an attacker can install plugins (a "
        "vector for RCE on certain plugins), use the data-source "
        "SQL editor on backends like MySQL/Postgres to query the "
        "underlying database, and modify dashboards / alert rules. "
        "Several Grafana CVEs (CVE-2021-43798) gain extra scope from "
        "an authenticated foothold."
    ),
    extra_refs=["Grafana — Hardening Recommendations"],
    alert_short="Grafana",
))

_r(_nuclei_default_creds(
    slug="weblogic-default-login",
    product="Oracle WebLogic",
    creds=["weblogic/weblogic1", "system/weblogic1", "weblogic/welcome1", "weblogic/Oracle@123"],
    severity="critical",
    impact=(
        "WebLogic admin access lets attackers deploy arbitrary "
        "applications, modify the JVM classpath, and chain into "
        "deserialisation RCE via several long-lived WebLogic CVEs. "
        "Combined with the steady stream of WebLogic CVEs, default "
        "creds are a high-leverage finding."
    ),
    extra_refs=["Oracle — WebLogic Security"],
    tags=["rce-risk"],
    alert_short="WebLogic",
))

_r(_nuclei_default_creds(
    slug="jboss-default-login",
    product="JBoss",
    creds=["admin/admin", "jboss/jboss"],
    severity="critical",
    impact=(
        "JBoss / WildFly admin access allows arbitrary application "
        "deployment via the JMX console or admin-console UI. Combined "
        "with JBoss's deserialisation-CVE history, default-creds is "
        "a direct path to RCE."
    ),
    extra_refs=["Red Hat — JBoss EAP Security"],
    tags=["rce-risk"],
    alert_short="JBoss",
))

_r(_nuclei_default_creds(
    slug="websphere-default-login",
    product="IBM WebSphere",
    creds=["admin/admin", "websphere/websphere", "wasadmin/wasadmin"],
    severity="critical",
    impact=(
        "WebSphere admin access allows arbitrary application "
        "deployment and access to credential stores configured "
        "inside WebSphere. Less common in modern estates but still "
        "appears in long-tail enterprise deployments."
    ),
    tags=["rce-risk"],
    alert_short="WebSphere",
))

_r(_nuclei_default_creds(
    slug="apache-airflow-default-login",
    product="Apache Airflow",
    creds=["airflow/airflow", "admin/admin"],
    severity="critical",
    impact=(
        "Authenticated Airflow users can typically execute arbitrary "
        "Python via DAG file uploads or the Airflow Variables / "
        "Connections, so default-creds is effectively RCE on the "
        "Airflow workers and any system the workers can reach. "
        "Airflow workers commonly hold cloud credentials, database "
        "creds, and access to data warehouses."
    ),
    extra_remediation=(
        "**Audit DAGs and Variables**\n"
        "  Review the Airflow DAGs folder for unfamiliar files. "
        "Inspect Variables for unexpected entries — attackers often "
        "drop reverse-shell payloads here. Rotate every connection "
        "credential stored in Airflow."
    ),
    extra_refs=["Apache Airflow — Security"],
    tags=["rce-risk"],
    alert_short="Airflow",
))

_r(_nuclei_default_creds(
    slug="zabbix-default-login",
    product="Zabbix",
    creds=["Admin/zabbix"],
    severity="high",
    impact=(
        "Zabbix admin access exposes monitored host inventories, "
        "alert configurations, and the Zabbix agent's command-execution "
        "capability — admins can configure Zabbix to run arbitrary "
        "commands on monitored hosts via the script execution feature. "
        "Effectively RCE on every monitored host."
    ),
    extra_refs=["Zabbix — Authentication and authorisation"],
    tags=["rce-risk"],
    alert_short="Zabbix",
))

_r(_nuclei_default_creds(
    slug="nagios-default-login",
    product="Nagios",
    creds=["nagiosadmin/nagiosadmin", "nagiosadmin/PASSW0RD"],
    severity="high",
    impact=(
        "Nagios admin access exposes monitored host inventories, "
        "credentials configured in checks, and Nagios's command "
        "submission capability. Authenticated users can submit "
        "external commands that may execute on monitored hosts via "
        "NRPE / NSCA agents."
    ),
    extra_refs=["Nagios — Security Considerations"],
    alert_short="Nagios",
))

_r(_nuclei_default_creds(
    slug="cacti-default-login",
    product="Cacti",
    creds=["admin/admin"],
    severity="high",
    impact=(
        "Cacti admin access exposes monitored device inventories "
        "and SNMP credentials. Cacti has had several authenticated "
        "RCE CVEs (CVE-2022-46169 command injection chained from "
        "default creds was actively exploited)."
    ),
    extra_refs=["Cacti — Security"],
    alert_short="Cacti",
))

_r(_nuclei_default_creds(
    slug="solarwinds-default-login",
    product="SolarWinds",
    creds=["admin/admin"],
    severity="critical",
    impact=(
        "SolarWinds admin access has supply-chain implications "
        "(SUNBURST, 2020). Admin users can deploy custom agents, "
        "configure SQL queries that run as the SolarWinds service "
        "account, and modify alert actions to run arbitrary commands. "
        "Default creds on a SolarWinds instance is a direct path to "
        "the network's monitoring estate."
    ),
    extra_refs=["SolarWinds — Security Resource Center"],
    tags=["rce-risk", "supply-chain"],
    alert_short="SolarWinds",
))

_r(_nuclei_default_creds(
    slug="opennms-default-login",
    product="OpenNMS",
    creds=["admin/admin"],
    severity="high",
    impact=(
        "OpenNMS admin access exposes monitored host inventories "
        "and credentials configured for SNMP / WMI / SSH polling. "
        "Authenticated users can configure event notifications that "
        "execute arbitrary commands on the OpenNMS server."
    ),
    alert_short="OpenNMS",
))

_r(_nuclei_default_creds(
    slug="pihole-default-credentials",
    product="Pi-hole",
    creds=["admin/admin", "admin/pihole"],
    severity="medium",
    impact=(
        "Pi-hole admin access lets attackers add DNS-rewrite rules "
        "(redirecting bank.com → attacker IP for every device using "
        "this Pi-hole as resolver) and modify the blocklist to allow "
        "ad-tracking and malware domains. Lower severity than RCE-"
        "capable products but a foothold for downstream attacks on "
        "every device behind the resolver."
    ),
    extra_refs=["Pi-hole — Documentation"],
    alert_short="Pi-hole",
))

_r(_nuclei_default_creds(
    slug="solr-default-credentials",
    product="Apache Solr",
    creds=["solr/SolrRocks", "admin/admin"],
    severity="critical",
    impact=(
        "Solr admin access lets attackers configure VelocityResponseWriter "
        "or DataImportHandler to execute arbitrary code (the "
        "CVE-2019-0193 / CVE-2019-17558 attack chains)."
    ),
    tags=["rce-risk"],
    alert_short="Solr",
))

_r(_nuclei_default_creds(
    slug="couchdb-default-login",
    product="Apache CouchDB",
    creds=["admin/admin"],
    severity="high",
    impact=(
        "CouchDB admin access grants full read/write/delete on every "
        "database. Older CouchDB versions chained admin access into "
        "RCE via CVE-2017-12635 / CVE-2017-12636."
    ),
    tags=["rce-risk"],
    alert_short="CouchDB",
))

_r(_nuclei_default_creds(
    slug="activemq-default-credentials",
    product="ActiveMQ",
    creds=["admin/admin"],
    severity="high",
    impact=(
        "ActiveMQ admin access lets attackers read every queue's "
        "contents, send arbitrary messages, and configure broker "
        "settings. Combined with CVE-2023-46604 (OpenWire RCE), "
        "default creds make exploitation trivial."
    ),
    extra_refs=["Apache ActiveMQ — Security"],
    alert_short="ActiveMQ",
))

_r(_nuclei_default_creds(
    slug="rabbitmq-default-login",
    product="RabbitMQ",
    creds=["guest/guest"],
    severity="high",
    impact=(
        "RabbitMQ ships with `guest/guest` as the default — restricted "
        "to localhost by default but commonly enabled for remote "
        "access in misconfigured deployments. Authenticated users can "
        "read every queue's messages, including any sensitive data "
        "that flows through the broker."
    ),
    extra_remediation=(
        "Restore the localhost-only default for the `guest` account "
        "in `rabbitmq.conf`: `loopback_users.guest = true`. Create "
        "named accounts with strong passwords for each application "
        "that connects."
    ),
    extra_refs=["RabbitMQ — Access Control"],
    alert_short="RabbitMQ",
))

# ─── Database default credentials ─────────────────────────────────────────

_r(_nuclei_default_creds(
    slug="mssql-default-login",
    product="Microsoft SQL Server",
    creds=["sa/sa", "sa/", "sa/password", "sa/Password1"],
    severity="critical",
    impact=(
        "MS SQL Server's `sa` account has implicit sysadmin role — "
        "default credentials grant unlimited database access plus "
        "the `xp_cmdshell` extended procedure, which executes "
        "arbitrary commands on the host as the SQL Server service "
        "account. This is a direct path to RCE on Windows servers."
    ),
    extra_remediation=(
        "**Disable `xp_cmdshell` if not needed**\n"
        "  `sp_configure 'xp_cmdshell', 0; RECONFIGURE;`\n\n"
        "**Disable the `sa` account entirely**\n"
        "  Use Windows Authentication (integrated security) where "
        "possible. If `sa` must exist, rename it and set a strong "
        "password."
    ),
    extra_refs=["Microsoft — Securing SQL Server"],
    tags=["database", "rce-risk"],
    alert_short="MSSQL",
))

_r(_nuclei_default_creds(
    slug="mysql-default-credentials",
    product="MySQL",
    creds=["root/", "root/root", "root/mysql", "root/password"],
    severity="critical",
    impact=(
        "MySQL `root` access grants unlimited database access plus "
        "`SELECT INTO OUTFILE` for filesystem writes — a classic path "
        "to web-shell deployment when the MySQL data directory is "
        "writable from the web server. Direct route to data theft "
        "and host compromise."
    ),
    extra_remediation=(
        "Rename the `root` account and set a strong password. Disable "
        "remote root access (`bind-address = 127.0.0.1`). Disable "
        "`LOAD DATA LOCAL INFILE` if your application doesn't need it."
    ),
    extra_refs=["MySQL — Securing the Initial MySQL Account"],
    tags=["database", "rce-risk"],
    alert_short="MySQL",
))

_r(_nuclei_default_creds(
    slug="postgres-default-credentials",
    product="PostgreSQL",
    creds=["postgres/postgres", "postgres/", "postgres/password"],
    severity="critical",
    impact=(
        "PostgreSQL `postgres` superuser access grants unlimited "
        "database access plus `COPY ... FROM PROGRAM` for command "
        "execution — direct path to RCE as the postgres service user. "
        "Several PostgreSQL CVEs gain additional scope from a "
        "superuser foothold."
    ),
    extra_remediation=(
        "Set a strong password for the `postgres` superuser. Disable "
        "remote postgres login via `pg_hba.conf` or restrict to "
        "internal networks only. Avoid running application workloads "
        "as the `postgres` user — create per-application accounts "
        "with least privilege."
    ),
    extra_refs=["PostgreSQL — Authentication"],
    tags=["database", "rce-risk"],
    alert_short="Postgres",
))

_r(_nuclei_default_creds(
    slug="mongodb-default-credentials",
    product="MongoDB",
    creds=["admin/admin", "root/root"],
    severity="high",
    impact=(
        "MongoDB admin access grants read/write/delete on every "
        "database. While MongoDB 3.6+ binds to localhost by default, "
        "remotely-accessible instances with default creds are "
        "routinely scraped by automated tooling and ransom-wiped."
    ),
    extra_refs=["MongoDB — Security Checklist"],
    tags=["database"],
    alert_short="MongoDB",
))

_r(_nuclei_default_creds(
    slug="ftp-default-credentials",
    product="FTP",
    creds=["anonymous/anonymous", "ftp/ftp", "anonymous/", "admin/admin"],
    severity="high",
    impact=(
        "FTP default credentials give attackers direct file-system "
        "access. Anonymous FTP frequently leaks system configuration, "
        "uploaded user content, and (worst case) the web root itself "
        "— a vector for serving attacker-modified content from your "
        "domain."
    ),
    extra_remediation=(
        "Disable FTP entirely — use SFTP (SSH-based) or FTPS. If "
        "FTP must stay, disable anonymous access in the FTP daemon's "
        "configuration."
    ),
    alert_short="FTP",
))

# ─── Specialty admin tools ────────────────────────────────────────────────

_r(_nuclei_default_creds(
    slug="webmin-default-credentials",
    product="Webmin",
    creds=["root/admin", "admin/admin"],
    severity="critical",
    impact=(
        "Webmin admin access grants full Unix system administration "
        "via the web UI — package management, user management, "
        "firewall rules, file editing, and direct shell command "
        "execution. Effectively SSH-as-root over a web browser."
    ),
    extra_remediation=(
        "Take Webmin off the public internet — it should only be "
        "reachable from internal admin networks. Replace any default "
        "credentials. Patch to the current Webmin release (recent "
        "CVEs include CVE-2019-15107 RCE)."
    ),
    extra_refs=["Webmin — Security"],
    tags=["rce-risk"],
    alert_short="Webmin",
))

_r(_nuclei_default_creds(
    slug="plesk-default-login",
    product="Plesk",
    creds=["admin/admin", "admin/setup"],
    severity="critical",
    impact=(
        "Plesk admin access grants control over every hosted website, "
        "database, and email account on the server — and via the "
        "Plesk Server Administration interface, root-equivalent "
        "host access. A common target on shared-hosting servers."
    ),
    tags=["rce-risk"],
    alert_short="Plesk",
))

_r(_nuclei_default_creds(
    slug="cpanel-default-login",
    product="cPanel",
    creds=["root/changeme", "admin/admin"],
    severity="critical",
    impact=(
        "cPanel WHM admin access grants root-equivalent control over "
        "every hosted account — DNS, mail, databases, file system. "
        "A foothold for mass-defacement or web-shell deployment "
        "across every customer site."
    ),
    tags=["rce-risk"],
    alert_short="cPanel",
))

_r(_nuclei_default_creds(
    slug="wordpress-default-credentials",
    product="WordPress",
    creds=["admin/admin", "admin/password", "admin/wordpress"],
    severity="critical",
    impact=(
        "WordPress admin access grants control over plugins, themes, "
        "and the editor — admins can install a malicious plugin or "
        "edit theme PHP files directly to achieve RCE on the web "
        "server. WordPress estate compromise is a major vector for "
        "SEO spam, malware distribution, and supply-chain attacks "
        "(via plugins)."
    ),
    extra_remediation=(
        "**Disable plugin / theme editing in admin**\n"
        "  Add `define('DISALLOW_FILE_EDIT', true);` to wp-config.php "
        "to remove the in-admin file editor.\n\n"
        "**Enforce 2FA for all admin accounts**\n"
        "  Use a plugin like Wordfence or miniOrange. Default-creds "
        "+ 2FA = the rotated password is moot."
    ),
    extra_refs=["WordPress — Hardening WordPress"],
    tags=["cms", "rce-risk"],
    alert_short="WordPress",
))

_r(_nuclei_default_creds(
    slug="phpmyadmin-default-login",
    product="phpMyAdmin",
    creds=["root/", "root/root"],
    severity="critical",
    impact=(
        "phpMyAdmin uses underlying MySQL credentials — default-cred "
        "logins succeed against MySQL instances with `root/` or "
        "`root/root` passwords. With phpMyAdmin's web UI, an attacker "
        "has interactive SQL access including `SELECT INTO OUTFILE` "
        "to drop a web shell into the web root."
    ),
    extra_refs=["phpMyAdmin — Configuration"],
    tags=["database", "rce-risk"],
    alert_short="phpMyAdmin",
))

# ─── Network device default credentials ───────────────────────────────────

_r(_nuclei_default_creds(
    slug="router-default-login",
    product="Router web UI",
    creds=["admin/admin", "admin/", "admin/password", "root/root"],
    severity="high",
    impact=(
        "Router admin access lets attackers modify DNS settings "
        "(redirecting traffic to attacker-controlled servers), open "
        "port forwards into the internal network, install firmware "
        "modifications, and read connected device lists. A common "
        "consumer-router compromise vector."
    ),
    extra_remediation=(
        "Replace default credentials. Disable WAN-side admin access "
        "if not needed. Update firmware to the current version."
    ),
    tags=["network-device"],
    alert_short="Router",
))

_r(_nuclei_default_creds(
    slug="cisco-default-credentials",
    product="Cisco device",
    creds=["cisco/cisco", "admin/admin", "admin/cisco"],
    severity="high",
    impact=(
        "Cisco device admin access lets attackers read configuration "
        "(routing tables, ACLs, SNMP community strings), modify "
        "routing to redirect or capture traffic, and use the device "
        "as a pivot into the internal network. Cisco devices are "
        "high-value targets for state-level adversaries."
    ),
    tags=["network-device"],
    alert_short="Cisco",
))

_r(_nuclei_default_creds(
    slug="juniper-default-credentials",
    product="Juniper device",
    creds=["root/", "admin/", "juniper/juniper"],
    severity="high",
    impact=(
        "Juniper device admin access exposes routing configuration "
        "and gives attackers a network pivot. Routinely targeted by "
        "APT actors for traffic collection."
    ),
    tags=["network-device"],
    alert_short="Juniper",
))

_r(_nuclei_default_creds(
    slug="fortinet-default-credentials",
    product="Fortinet device",
    creds=["admin/", "admin/admin", "admin/fortinet"],
    severity="high",
    impact=(
        "Fortinet device admin access lets attackers modify firewall "
        "rules, read VPN credentials and configurations, and use the "
        "device as a pivot. Fortinet appliances are heavily targeted "
        "(see CVE-2024-21762, CVE-2018-13379) — default credentials "
        "compound the risk."
    ),
    tags=["network-device"],
    alert_short="Fortinet",
))

_r(_nuclei_default_creds(
    slug="unifi-default-login",
    product="Ubiquiti UniFi",
    creds=["ubnt/ubnt", "admin/ubnt"],
    severity="high",
    impact=(
        "Ubiquiti UniFi controller admin access grants control over "
        "every UniFi access point, switch, and gateway managed by "
        "the controller — a pivot into the wireless network and "
        "any device using it."
    ),
    tags=["network-device"],
    alert_short="UniFi",
))

_r(_nuclei_default_creds(
    slug="mikrotik-default-credentials",
    product="MikroTik RouterOS",
    creds=["admin/", "admin/admin"],
    severity="high",
    impact=(
        "MikroTik RouterOS admin access has been a major botnet-"
        "recruitment vector (Mēris, TrickBot's MikroTik scanning) — "
        "compromised MikroTiks act as proxies for credential-spray "
        "campaigns and host-file modification redirects users to "
        "phishing pages."
    ),
    tags=["network-device"],
    alert_short="MikroTik",
))

_r(_nuclei_default_creds(
    slug="hikvision-default-credentials",
    product="Hikvision camera",
    creds=["admin/12345", "admin/admin"],
    severity="high",
    impact=(
        "IP camera admin access lets attackers view live and recorded "
        "video, listen to two-way audio (where supported), and "
        "incorporate the camera into Mirai-style botnets. Privacy "
        "implications are substantial."
    ),
    tags=["iot", "camera"],
    alert_short="Hikvision",
))

_r(_nuclei_default_creds(
    slug="axis-default-credentials",
    product="Axis camera",
    creds=["root/pass", "admin/admin"],
    severity="high",
    impact=(
        "Axis camera admin access grants live and recorded video "
        "viewing plus access to firmware-update functionality — a "
        "pivot for botnet recruitment and surveillance compromise."
    ),
    tags=["iot", "camera"],
    alert_short="Axis Camera",
))

_r(_nuclei_default_creds(
    slug="zyxel-default-credentials",
    product="Zyxel device",
    creds=["admin/1234", "admin/admin"],
    severity="high",
    impact=(
        "Zyxel device admin access exposes routing configuration and "
        "device controls. Recent Zyxel CVEs (CVE-2022-30525 command "
        "injection) make compromise more impactful when chained with "
        "default creds."
    ),
    tags=["network-device"],
    alert_short="Zyxel",
))

_r(_nuclei_default_creds(
    slug="printer-default-login",
    product="Printer",
    creds=["admin/admin", "admin/", "admin/password"],
    severity="medium",
    impact=(
        "Printer admin access exposes print job logs (containing "
        "document content), address books, and Wi-Fi credentials. "
        "Some printers also accept arbitrary firmware uploads — a "
        "vector for persistent network compromise."
    ),
    tags=["iot", "printer"],
    alert_short="Printer",
))


# ───────────────────────────────────────────────────────────────────────────
# Nuclei — Information Disclosure (Batch D5)
# ───────────────────────────────────────────────────────────────────────────
# Curated copy for templates that detect sensitive data leaking through
# HTTP responses, error messages, headers, or misconfigured cloud
# resources. Severity calibrates to what's actually leaked: live
# credentials = critical, version banners = low, with a deliberately-
# wide spread in between.

def _nuclei_info(
    *,
    slug: str,
    title: str,
    severity: str,
    description: str,
    remediation: str,
    summary: str,
    cwe: str = "CWE-200",
    extra_refs: list[str] | None = None,
    tags: list[str] | None = None,
    alert_short: str,
    category: str = "exposure",
) -> FindingTemplate:
    """Factory for information-disclosure templates."""
    return FindingTemplate(
        template_id=f"nuclei-{slug}",
        title=title,
        description=description,
        remediation=remediation,
        severity=severity,
        category=category,
        cwe=cwe,
        tags=["nuclei", "info-disclosure", slug] + (tags or []),
        summary=summary,
        alert_name=f"Info Disclosure — {alert_short}",
        monitor_type="config_change",
        references=[
            "OWASP — Sensitive Data Exposure",
            "CWE-200: Exposure of Sensitive Information",
        ] + (extra_refs or []),
    )


# ─── Live credential / token disclosure (highest severity) ────────────────

_r(_nuclei_info(
    slug="aws-access-key-disclosure",
    title="AWS access key disclosed in response from {asset}",
    severity="critical",
    cwe="CWE-798",
    description=(
        "An AWS access key (AKIA-prefixed identifier, sometimes with "
        "a paired secret) was found in an HTTP response from {asset}. "
        "If the key is live, attackers can use it to interact with "
        "AWS at whatever scope the key's IAM policy grants. "
        "Common false-positive sources are tutorial snippets and "
        "docs pages — verify before treating as breach, but treat as "
        "breach until verified."
    ),
    remediation=(
        "**Verify whether the key is live**\n"
        "  Use AWS IAM (`aws iam list-access-keys`) to confirm the "
        "key ID exists in your account. If yes, treat as compromised.\n\n"
        "**Rotate immediately**\n"
        "  Mark the key inactive in IAM, then delete it. Generate a "
        "fresh key for any legitimate consumer; deliver it via a "
        "secret manager, not by pasting it into a doc/page.\n\n"
        "**Audit CloudTrail**\n"
        "  Search CloudTrail for `accessKeyId` matching the leaked "
        "key over the entire window the page has been reachable. Any "
        "API call from an unfamiliar source IP is the breach.\n\n"
        "**Remove from the response**\n"
        "  Find what's serving the key (an error page? a debug "
        "endpoint? a static doc?) and remove it. Add a CI guard "
        "(`gitleaks`, `trufflehog`) to prevent recurrence."
    ),
    summary="An AWS access key is visible in an HTTP response from {asset} — verify if live and rotate.",
    extra_refs=[
        "AWS — What to do if you inadvertently expose an AWS access key",
    ],
    tags=["aws", "credentials"],
    alert_short="AWS Key Leak",
    category="leak",
))

_r(_nuclei_info(
    slug="gcp-service-account-disclosure",
    title="GCP service account credentials disclosed at {asset}",
    severity="critical",
    cwe="CWE-798",
    description=(
        "A GCP service account JSON key file was found in an HTTP "
        "response from {asset}. The key contains a private RSA "
        "component used to sign auth tokens for the service "
        "account — anyone holding the file can act as that "
        "identity at its full granted scope (project, "
        "organisation, dataset, bucket)."
    ),
    remediation=(
        "**Treat as compromised credentials**\n"
        "  Disable and delete the service-account key in GCP IAM "
        "(`gcloud iam service-accounts keys delete`). Generate a new "
        "key only for legitimate consumers and deliver via Secret "
        "Manager.\n\n"
        "**Audit GCP Audit Logs**\n"
        "  Search Cloud Audit Logs for the leaked service-account "
        "email over the page's reachability window. Look for "
        "unfamiliar API calls or principal IPs.\n\n"
        "**Move to keyless auth where possible**\n"
        "  Workload Identity Federation eliminates JSON key files "
        "entirely for many use cases — use it instead of service-"
        "account keys for production workloads."
    ),
    summary="GCP service-account credentials are visible in an HTTP response from {asset} — rotate and audit.",
    extra_refs=[
        "Google Cloud — Best practices for managing service account keys",
    ],
    tags=["gcp", "credentials"],
    alert_short="GCP SA Key Leak",
    category="leak",
))

_r(_nuclei_info(
    slug="azure-shared-key-disclosure",
    title="Azure storage shared key disclosed at {asset}",
    severity="critical",
    cwe="CWE-798",
    description=(
        "An Azure storage account shared key was found in an HTTP "
        "response from {asset}. Shared keys grant unlimited access "
        "to every blob, queue, table, and file share in the storage "
        "account. They don't expire — once leaked, the key is "
        "compromised until manually rotated."
    ),
    remediation=(
        "**Rotate the storage account key**\n"
        "  In the Azure portal: Storage account → Access keys → "
        "Rotate key. Update every consumer with the new value.\n\n"
        "**Audit storage diagnostic logs**\n"
        "  Look for unfamiliar SAS-key usage and operations from "
        "unexpected source IPs over the leak window.\n\n"
        "**Migrate to managed identity**\n"
        "  Azure managed identities eliminate shared keys for "
        "service-to-service auth. For end-user access, use SAS tokens "
        "with short expiry instead of shared keys."
    ),
    summary="An Azure storage shared key is visible in an HTTP response from {asset} — rotate immediately.",
    extra_refs=[
        "Microsoft — Manage storage account access keys",
    ],
    tags=["azure", "credentials"],
    alert_short="Azure Key Leak",
    category="leak",
))

_r(_nuclei_info(
    slug="private-key-disclosure",
    title="Private key material disclosed at {asset}",
    severity="critical",
    cwe="CWE-200",
    description=(
        "Private key material (RSA, EC, DSA, OpenSSH, or PGP "
        "private key block) was found in an HTTP response from "
        "{asset}. Whatever the key authenticates — SSH access, "
        "code-signing certificates, JWT signing, TLS certificates "
        "— should be considered compromised."
    ),
    remediation=(
        "**Identify and revoke**\n"
        "  Match the key to its purpose: SSH `authorized_keys`, "
        "code-signing certificate, JWT signing config, internal "
        "TLS, etc. Revoke / replace at every consumer.\n\n"
        "**Generate a fresh keypair**\n"
        "  Use a modern algorithm (Ed25519 for SSH; ECDSA P-256 or "
        "Ed25519 for general-purpose). Distribute the new public "
        "component only to systems that need it.\n\n"
        "**Remove the leak source**\n"
        "  Find the file/page/error that exposed the key and remove "
        "it. Add CI checks to prevent private-key blobs being "
        "committed to public surfaces."
    ),
    summary="A private key is visible in an HTTP response from {asset} — anything it authenticates is compromised.",
    tags=["credentials", "private-key"],
    alert_short="Private Key Leak",
    category="leak",
))

_r(_nuclei_info(
    slug="google-api-key-disclosure",
    title="Google API key disclosed at {asset}",
    severity="medium",
    cwe="CWE-200",
    description=(
        "A Google API key (AIza-prefixed) was found in a response "
        "from {asset}. Many Google API keys are intentionally "
        "client-side (Maps JavaScript, YouTube embed) and "
        "restricted to specific HTTP referrers — those are designed "
        "to be public. Unrestricted server-side keys leaked the "
        "same way are a credential breach."
    ),
    remediation=(
        "Confirm the key's intended scope. In Google Cloud Console "
        "→ APIs & Services → Credentials, check whether the key has "
        "application restrictions (HTTP referrers, IP addresses) and "
        "API restrictions. If it's an unrestricted server-side key, "
        "rotate it immediately and constrain the new key to specific "
        "APIs and referrer/IP ranges. Audit the GCP project's API "
        "usage logs for unfamiliar callers."
    ),
    summary="A Google API key is visible at {asset} — verify whether it's an intentionally-public client-side key or a leaked server-side one.",
    extra_refs=[
        "Google Cloud — Best practices for securely using API keys",
    ],
    tags=["gcp", "credentials"],
    alert_short="Google API Key",
    category="leak",
))

_r(_nuclei_info(
    slug="slack-token-disclosure",
    title="Slack token disclosed at {asset}",
    severity="high",
    cwe="CWE-200",
    description=(
        "A Slack token (xoxb-, xoxp-, xoxa-, xoxr-prefixed) was "
        "found in a response from {asset}. Slack bot, user, and "
        "app tokens grant access to the workspace they belong to "
        "— attackers can read channels, send messages, exfiltrate "
        "files, and (with admin tokens) modify workspace "
        "configuration."
    ),
    remediation=(
        "Revoke the token via the Slack admin console (Apps → the "
        "owning app → Install App → revoke). Generate a new token "
        "and deliver via a secret store. Audit the Slack workspace's "
        "audit log for unfamiliar API activity from the token's "
        "IP range over the leak window."
    ),
    summary="A Slack token is visible at {asset} — revoke and audit workspace activity.",
    extra_refs=[
        "Slack — Token security",
    ],
    tags=["slack", "credentials"],
    alert_short="Slack Token",
    category="leak",
))

_r(_nuclei_info(
    slug="stripe-key-disclosure",
    title="Stripe API key disclosed at {asset}",
    severity="high",
    cwe="CWE-798",
    description=(
        "A Stripe API key was found in a response from {asset}. "
        "Stripe publishable keys (pk_live_*) are designed to be "
        "client-side and aren't a breach by themselves. Stripe "
        "secret keys (sk_live_*) and restricted keys (rk_live_*) "
        "grant server-side access to your Stripe account — payment "
        "creation, customer reads, refunds depending on the key's "
        "permissions."
    ),
    remediation=(
        "Verify the key prefix. If it's `pk_live_*` (publishable), "
        "no action needed — it's safe to expose. If it's `sk_live_*` "
        "or `rk_live_*`:\n"
        "  • Roll the key in the Stripe Dashboard immediately "
        "(Developers → API keys → Roll secret key).\n"
        "  • Update every consumer with the new value via your "
        "secret manager.\n"
        "  • Audit Stripe's events log for unfamiliar API activity "
        "during the leak window."
    ),
    summary="A Stripe API key is visible at {asset} — distinguish publishable (safe) from secret (rotate).",
    extra_refs=[
        "Stripe — Roll API keys",
    ],
    tags=["stripe", "credentials"],
    alert_short="Stripe Key",
    category="leak",
))

_r(_nuclei_info(
    slug="github-token-disclosure",
    title="GitHub token disclosed at {asset}",
    severity="high",
    cwe="CWE-200",
    description=(
        "A GitHub personal access token (ghp_, gho_, ghu_, ghs_, "
        "or github_pat_-prefixed) was found in a response from "
        "{asset}. PATs can read and modify any repository the "
        "issuing user has access to — including private repos, "
        "GitHub Actions secrets, and organisation administration "
        "depending on token scope."
    ),
    remediation=(
        "Revoke the token immediately at github.com/settings/tokens "
        "(or the org-level Personal access tokens page for "
        "fine-grained tokens). Audit the user's recent activity in "
        "GitHub's audit log for any commits, releases, or workflow "
        "runs that weren't them. Treat any GitHub Actions secrets "
        "the user could read as compromised."
    ),
    summary="A GitHub token is visible at {asset} — revoke and audit user activity.",
    extra_refs=[
        "GitHub — Reviewing your security log",
        "GitHub — Keeping your account and data secure",
    ],
    tags=["github", "credentials"],
    alert_short="GitHub Token",
    category="leak",
))


# ─── JWT / session / auth-token issues ────────────────────────────────────

_r(_nuclei_info(
    slug="jwt-no-signature-verification",
    title="JWT signature not verified by {asset}",
    severity="high",
    cwe="CWE-347",
    description=(
        "Nuclei detected that {asset} accepts JWTs without "
        "verifying the signature — typically because the server "
        "accepts `alg: none` headers, or doesn't verify the "
        "signature at all. Attackers craft a token with arbitrary "
        "claims (any user ID, any role) and the server treats it "
        "as authentic — direct authentication bypass."
    ),
    remediation=(
        "Configure the JWT library to require a specific algorithm "
        "(HS256, RS256, ES256) and reject `alg: none` outright. "
        "Verify the signature on every request before reading claims. "
        "If using a JWT middleware, audit its config — many "
        "frameworks have a `verify=False` option that's been left on "
        "from a copy-pasted example. Audit recent authenticated "
        "sessions for forged tokens (claims that don't match real "
        "user records)."
    ),
    summary="JWT signature verification is broken on {asset} — attackers can forge any user identity. Patch immediately.",
    extra_refs=[
        "RFC 8725 — JSON Web Token Best Current Practices",
        "OWASP — JSON Web Token Cheat Sheet",
    ],
    tags=["jwt", "auth-bypass"],
    alert_short="JWT Unsigned",
    category="cve",
))

_r(_nuclei_info(
    slug="jwt-weak-secret",
    title="JWT signed with weak secret on {asset}",
    severity="medium",
    cwe="CWE-326",
    description=(
        "Nuclei brute-forced the HMAC secret used to sign JWTs on "
        "{asset} from a common-passwords or default-secret list. "
        "With the secret known, attackers forge tokens for any "
        "user / role and the server accepts them. Common cause: "
        "a secret like `secret`, `your-256-bit-secret`, or the "
        "name of a framework that's hardcoded in tutorials."
    ),
    remediation=(
        "Generate a cryptographically-random secret of at least 32 "
        "bytes (256 bits) and set it via your application's "
        "environment / secret store. Migrate to RS256 or ES256 "
        "(asymmetric) where possible — the public key validates, the "
        "private key signs, and the validating servers don't need "
        "the signing material. Invalidate all existing JWTs after "
        "rotating the secret (force user re-auth)."
    ),
    summary="JWT secret on {asset} is brute-forceable — anyone with the secret can forge tokens. Rotate now.",
    extra_refs=[
        "OWASP — JSON Web Token Cheat Sheet",
    ],
    tags=["jwt"],
    alert_short="JWT Weak Secret",
    category="cve",
))

_r(_nuclei_info(
    slug="session-token-in-url",
    title="Session token transmitted in URL on {asset}",
    severity="medium",
    cwe="CWE-598",
    description=(
        "{asset} transmits session identifiers in URL query "
        "parameters (e.g., `?sessionid=...`, `?token=...`) instead "
        "of in cookies or Authorization headers. URL parameters "
        "leak via the Referer header to third-party sites, are "
        "logged in web-server access logs and CDN logs, and end up "
        "in browser history."
    ),
    remediation=(
        "Move session tokens into HttpOnly cookies (for browser-"
        "based apps) or into the Authorization header (for API "
        "calls). For backwards-compatibility with old links that "
        "still carry tokens in URLs, accept them but issue a fresh "
        "token via cookie on first use and reject the URL parameter "
        "on subsequent requests. Sanitise web-server logs that may "
        "have captured the tokens."
    ),
    summary="Session tokens travel in URL parameters on {asset} — they leak to third parties via Referer and logs.",
    extra_refs=[
        "OWASP — Session Management Cheat Sheet",
    ],
    tags=["session", "auth"],
    alert_short="Token in URL",
))

_r(_nuclei_info(
    slug="oauth-token-leak",
    title="OAuth token disclosed at {asset}",
    severity="high",
    cwe="CWE-200",
    description=(
        "An OAuth access or refresh token was found in a response "
        "from {asset}. OAuth tokens grant access to whatever scopes "
        "the issuing user authorised — for refresh tokens, that "
        "access can be re-issued indefinitely until the token is "
        "explicitly revoked."
    ),
    remediation=(
        "Revoke the token at the issuing OAuth provider. For most "
        "providers (Google, Microsoft, GitHub, etc.) this is a "
        "single API call (e.g. `POST /oauth/revoke`). Audit the "
        "user's account for unfamiliar activity within the token's "
        "scope. Find the response surface that leaked it (error "
        "page, log endpoint, debug response) and remove it."
    ),
    summary="An OAuth token is visible at {asset} — revoke at the issuing provider and audit user activity.",
    extra_refs=[
        "OAuth 2.0 — Token Revocation (RFC 7009)",
    ],
    tags=["oauth", "credentials"],
    alert_short="OAuth Token Leak",
    category="leak",
))


# ─── Cloud resource info disclosure ───────────────────────────────────────

_r(_nuclei_info(
    slug="firebase-realtime-db-public",
    title="Firebase Realtime Database publicly readable on {asset}",
    severity="high",
    cwe="CWE-200",
    description=(
        "A Firebase Realtime Database is reachable from {asset} "
        "with public read (and possibly write) rules. Firebase's "
        "default rules used to be open, and many tutorials still "
        "show open rules — exposed databases routinely leak "
        "production user data, chat messages, location history, "
        "and authentication tokens stored as JSON values."
    ),
    remediation=(
        "Tighten Firebase security rules in the Firebase Console "
        "(Realtime Database → Rules):\n"
        "```\n"
        '{ "rules": { ".read": "auth != null", ".write": "auth != null" } }\n'
        "```\n"
        "Then iterate to require specific role / user-scope "
        "constraints on each path. Audit the database's contents "
        "and authentication logs for unfamiliar reads since the "
        "database was first reachable."
    ),
    summary="A Firebase Realtime Database on {asset} is publicly readable — likely contains user data that's been scraped.",
    extra_refs=[
        "Firebase — Database security rules",
    ],
    tags=["firebase", "gcp"],
    alert_short="Firebase RTDB",
    category="leak",
))

_r(_nuclei_info(
    slug="firebase-database-info-exposure",
    title="Firebase database info disclosed at {asset}",
    severity="medium",
    cwe="CWE-200",
    description=(
        "Firebase project metadata — database URL, project ID, API "
        "key — was disclosed at {asset}. While Firebase API keys "
        "and database URLs are designed to be client-visible, "
        "their disclosure combined with overly-permissive security "
        "rules is the chain that leads to data exposure (see "
        "`firebase-realtime-db-public`)."
    ),
    remediation=(
        "Confirm Firebase security rules are tight (see the "
        "Realtime DB or Firestore rules documentation). The "
        "config disclosure itself is fine if rules are correct; "
        "the rules are the actual security boundary."
    ),
    summary="Firebase project metadata is disclosed at {asset} — verify the database's security rules are tight.",
    extra_refs=[
        "Firebase — Understand Firebase Security Rules",
    ],
    tags=["firebase", "gcp"],
    alert_short="Firebase Info",
))

_r(_nuclei_info(
    slug="aws-s3-bucket-info-disclosure",
    title="AWS S3 bucket info disclosed at {asset}",
    severity="medium",
    cwe="CWE-200",
    description=(
        "{asset} discloses S3 bucket names, regions, or ARNs in "
        "response bodies, error messages, or HTML source. "
        "Knowing your bucket names lets attackers probe for "
        "public-access misconfigurations on those specific buckets — "
        "the disclosure isn't a breach itself but accelerates the "
        "discovery step toward one."
    ),
    remediation=(
        "Audit each disclosed bucket for misconfigured public "
        "access — enable S3 Block Public Access at the account "
        "level and check each bucket's policy. Find the source of "
        "the disclosure (often error messages or commented-out "
        "HTML) and suppress."
    ),
    summary="S3 bucket names are visible from {asset} — audit those buckets for public-access misconfiguration.",
    extra_refs=[
        "AWS — Blocking public access to your S3 storage",
    ],
    tags=["aws"],
    alert_short="S3 Info",
))


# ─── Server / framework version disclosure ────────────────────────────────

_r(_nuclei_info(
    slug="nginx-version-disclosure",
    title="nginx version disclosed by {asset}",
    severity="low",
    cwe="CWE-200",
    description=(
        "{asset} reveals the exact nginx version in the `Server` "
        "header or in default error pages. The information itself "
        "isn't directly exploitable, but it shortens an attacker's "
        "reconnaissance step — they can immediately match the version "
        "against published nginx CVEs."
    ),
    remediation=(
        "Suppress the version in the Server header by adding "
        "`server_tokens off;` to your nginx configuration "
        "(http{} block). Use a custom error page so the default "
        "page that exposes the version doesn't appear. Removing the "
        "version isn't a substitute for keeping nginx patched."
    ),
    summary="nginx on {asset} reveals its exact version — disable server_tokens for hardening.",
    tags=["nginx", "version-disclosure"],
    alert_short="nginx Version",
))

_r(_nuclei_info(
    slug="apache-version-disclosure",
    title="Apache HTTP Server version disclosed by {asset}",
    severity="low",
    cwe="CWE-200",
    description=(
        "{asset} reveals the exact Apache HTTP Server version in "
        "the `Server` header or in default error pages. Apache CVEs "
        "are routinely published; the version reveal makes it "
        "trivial for an attacker to check if the server is "
        "exploitable."
    ),
    remediation=(
        "Set `ServerTokens Prod` and `ServerSignature Off` in your "
        "main Apache configuration. Replace the default error pages "
        "with custom ones. Confirm with `curl -I` that the Server "
        "header is just `Server: Apache` rather than including the "
        "version."
    ),
    summary="Apache on {asset} reveals its exact version — set ServerTokens Prod for hardening.",
    tags=["apache", "version-disclosure"],
    alert_short="Apache Version",
))

_r(_nuclei_info(
    slug="iis-version-disclosure",
    title="IIS version disclosed by {asset}",
    severity="low",
    cwe="CWE-200",
    description=(
        "{asset} reveals the IIS version via the `Server` or "
        "`X-Powered-By` headers. Information disclosure that helps "
        "attackers correlate the server with known CVEs."
    ),
    remediation=(
        "Remove the Server header in IIS by editing "
        "applicationHost.config (set "
        "`removeServerHeader=\"true\"` under "
        "`<system.webServer><security><requestFiltering>`) or via "
        "URL Rewrite outbound rules. Remove `X-Powered-By: ASP.NET` "
        "via web.config:\n"
        "```xml\n"
        '<httpProtocol><customHeaders><remove name="X-Powered-By"/></customHeaders></httpProtocol>\n'
        "```"
    ),
    summary="IIS on {asset} reveals its version — remove the Server and X-Powered-By headers.",
    tags=["iis", "version-disclosure"],
    alert_short="IIS Version",
))

_r(_nuclei_info(
    slug="tomcat-version-disclosure",
    title="Apache Tomcat version disclosed by {asset}",
    severity="low",
    cwe="CWE-200",
    description=(
        "{asset} reveals the exact Tomcat version in default error "
        "pages or HTTP headers. Helps attackers map to known Tomcat "
        "CVEs for targeted exploitation."
    ),
    remediation=(
        "Override Tomcat's default error pages — every "
        "`<error-page>` mapping in `web.xml`. Set "
        "`server.info`, `server.number`, and `server.built` in "
        "`$CATALINA_HOME/lib/org/apache/catalina/util/ServerInfo.properties` "
        "or override via the `org.apache.catalina.connector.X_POWERED_BY` "
        "system property to suppress the version banner."
    ),
    summary="Tomcat on {asset} reveals its version — replace default error pages and override server banner.",
    tags=["tomcat", "version-disclosure"],
    alert_short="Tomcat Version",
))

_r(_nuclei_info(
    slug="wordpress-version-disclosure",
    title="WordPress version disclosed by {asset}",
    severity="low",
    cwe="CWE-200",
    description=(
        "{asset} reveals the WordPress version via the `<meta "
        "name=\"generator\">` tag, RSS feeds, or JS/CSS asset "
        "version strings. WordPress is one of the most-attacked "
        "platforms; the version disclosure is recon material for "
        "version-specific exploits, especially against the long "
        "tail of vulnerable plugins."
    ),
    remediation=(
        "Remove the generator meta tag (add a small functions.php "
        "snippet: `remove_action('wp_head', 'wp_generator')`) and "
        "strip version query strings on JS/CSS. A maintained "
        "security plugin (Wordfence, iThemes Security) does this "
        "automatically. Keeping WordPress core, themes, and plugins "
        "patched is the actual defence — version hiding is "
        "secondary."
    ),
    summary="WordPress version on {asset} is publicly visible — strip the generator tag and version query strings.",
    tags=["wordpress", "version-disclosure"],
    alert_short="WP Version",
))

_r(_nuclei_info(
    slug="drupal-version-disclosure",
    title="Drupal version disclosed by {asset}",
    severity="low",
    cwe="CWE-200",
    description=(
        "{asset} reveals the Drupal version via meta tags, "
        "CHANGELOG.txt, or default file paths. Drupal's CVE history "
        "(Drupalgeddon, Drupalgeddon2) makes version disclosure a "
        "high-value recon step for attackers targeting older "
        "installs."
    ),
    remediation=(
        "Remove the generator meta tag via a custom theme's "
        "preprocess hook. Block public access to CHANGELOG.txt, "
        "INSTALL.txt, README.txt, and the `core/CHANGELOG.txt` "
        "files at the web server. Patch Drupal core and contrib "
        "modules promptly."
    ),
    summary="Drupal version on {asset} is publicly visible — strip the meta tag and block CHANGELOG-style files.",
    tags=["drupal", "version-disclosure"],
    alert_short="Drupal Version",
))

_r(_nuclei_info(
    slug="joomla-version-disclosure",
    title="Joomla version disclosed by {asset}",
    severity="low",
    cwe="CWE-200",
    description=(
        "{asset} reveals the Joomla version via meta tags, default "
        "manifest files (`administrator/manifests/files/joomla.xml`), "
        "or generator strings."
    ),
    remediation=(
        "Strip the generator meta tag and block public access to "
        "manifest files at the web server. Patch Joomla core "
        "promptly — Joomla CVEs (CVE-2023-23752, CVE-2015-8562) "
        "are routinely exploited."
    ),
    summary="Joomla version on {asset} is publicly visible — strip the generator tag.",
    tags=["joomla", "version-disclosure"],
    alert_short="Joomla Version",
))


# ─── Internal info disclosure ─────────────────────────────────────────────

_r(_nuclei_info(
    slug="internal-ip-disclosure",
    title="Internal IP address disclosed by {asset}",
    severity="low",
    cwe="CWE-200",
    description=(
        "{asset} discloses an internal/private IP address (RFC 1918, "
        "RFC 6598, or link-local) in HTTP responses, headers, or "
        "error messages. Internal IPs leak network topology — "
        "subnet sizes, addressing scheme — that helps attackers "
        "plan post-exploitation lateral movement."
    ),
    remediation=(
        "Find the source of the leak. Common culprits are debug "
        "log endpoints, error pages with stack traces, "
        "`X-Forwarded-For` reflection, and CORS preflight responses "
        "that include internal hostnames. Strip internal IPs from "
        "HTTP responses at the application or proxy layer; replace "
        "them with anonymised placeholders for legitimate diagnostic "
        "use."
    ),
    summary="Internal IP addresses are visible from {asset} — strip them from responses.",
    tags=["info-disclosure"],
    alert_short="Internal IP",
))

_r(_nuclei_info(
    slug="path-disclosure",
    title="Server file system path disclosed by {asset}",
    severity="low",
    cwe="CWE-209",
    description=(
        "{asset} discloses absolute file system paths "
        "(`/var/www/html/...`, `C:\\inetpub\\wwwroot\\...`) in error "
        "messages, stack traces, or response bodies. Path disclosure "
        "helps attackers chain into LFI/RFI exploits — they no "
        "longer need to guess the server's directory layout."
    ),
    remediation=(
        "Configure the application framework to return generic "
        "error messages in production and log full stack traces "
        "server-side instead. Most frameworks have a single "
        "production-mode toggle that handles this (Django "
        "`DEBUG=False`, ASP.NET `customErrors mode=\"On\"`, Express "
        "`NODE_ENV=production`). Audit existing logs for paths that "
        "may have already been exposed in user-visible responses."
    ),
    summary="File system paths leak in errors from {asset} — disable debug mode in production.",
    tags=["error-handling"],
    alert_short="Path Disclosure",
))

_r(_nuclei_info(
    slug="csrf-token-disclosure",
    title="CSRF token in URL/log on {asset}",
    severity="low",
    cwe="CWE-598",
    description=(
        "{asset} transmits a CSRF token via a URL parameter rather "
        "than in a header or hidden form field. CSRF tokens in URLs "
        "leak via Referer headers and access logs — defeating the "
        "token's purpose for cross-site requests originated from "
        "the same browser session."
    ),
    remediation=(
        "Move CSRF tokens into hidden form fields (synchroniser "
        "token pattern) or into custom request headers (e.g., "
        "`X-CSRF-Token`). Most modern frameworks handle this "
        "automatically — the URL-based variant is usually a "
        "leftover from a manual implementation."
    ),
    summary="CSRF tokens travel in URLs on {asset} — they leak via Referer.",
    extra_refs=[
        "OWASP — Cross-Site Request Forgery Prevention Cheat Sheet",
    ],
    tags=["csrf"],
    alert_short="CSRF in URL",
))

_r(_nuclei_info(
    slug="exposed-build-artifacts",
    title="CI/CD build artefacts exposed at {asset}",
    severity="medium",
    cwe="CWE-200",
    description=(
        "Build artefacts (Jenkins build logs, GitHub Actions "
        "workflow runs, GitLab CI artifacts) are publicly readable "
        "at {asset}. Build logs frequently leak environment "
        "variables, deploy keys, third-party tokens, internal "
        "hostnames, and CI runner metadata. Build artefacts can "
        "also include test fixtures with seed data."
    ),
    remediation=(
        "Restrict CI/CD artefacts to authenticated users only. In "
        "Jenkins: configure matrix-based authorisation so artefacts "
        "follow per-job permissions. In GitHub Actions: workflow "
        "logs visibility is controlled by repo visibility — "
        "make the repo private. In GitLab: configure `artifacts:` "
        "scope per-job and use `artifacts:expose_as` carefully."
    ),
    summary="CI/CD build artefacts are reachable at {asset} — they often include credentials in logs.",
    tags=["ci-cd"],
    alert_short="Build Artefacts",
    category="leak",
))


# ───────────────────────────────────────────────────────────────────────────
# Nuclei — Generic wrapper (Batch D6)
# ───────────────────────────────────────────────────────────────────────────
# Catch-all template for Nuclei findings whose template_id we haven't
# explicitly curated. The analyzer renders this with Nuclei's runtime
# metadata (template_name, description, references, CVE/CVSS) so the
# customer still sees a polished finding rather than a raw upstream
# blob.
#
# Resolved via the registry's prefix-match fallback (`nuclei-` →
# `nuclei-uncategorized`) for any Nuclei ID we don't have a more
# specific entry for. The analyzer detects this case and falls into
# its uncategorized-rendering path, which interpolates Nuclei's own
# data into the wrapper's framing copy.

_r(FindingTemplate(
    template_id="nuclei-uncategorized",
    title="Nuclei finding: {value} on {asset}",
    description=(
        "Nuclei's template-based scanner matched a finding on "
        "{asset}. Template details and severity come from the "
        "upstream Nuclei template metadata. We don't yet ship a "
        "curated explanation for this specific template ID — the "
        "evidence section captures the matched URL, extracted "
        "values, and any CVE/CWE/CVSS classification Nuclei "
        "provided. Use those to evaluate impact, then patch or "
        "configure the affected service per the upstream Nuclei "
        "references below."
    ),
    remediation=(
        "Open the Nuclei references attached to this finding for "
        "the upstream template's recommended remediation. If a CVE "
        "is named in the evidence, look it up at "
        "https://nvd.nist.gov for vendor-fixed versions and apply "
        "patches. If this is a configuration finding, identify the "
        "responsible service and apply the relevant hardening "
        "documentation from the vendor. When in doubt, reach out — "
        "Nano EASM support can help interpret the finding."
    ),
    severity="medium",
    category="vulnerability",
    cwe=None,
    tags=["nuclei", "uncategorized"],
    summary="Nuclei matched a template on {asset} — see references and evidence for details.",
    alert_name="Nuclei Finding",
    monitor_type="vuln_change",
    references=[
        "ProjectDiscovery — Nuclei",
        "NIST National Vulnerability Database (NVD)",
    ],
))


# ───────────────────────────────────────────────────────────────────────────
# Sensitive Path / Leak Detection (continued — generic GitHub fallback)
# ───────────────────────────────────────────────────────────────────────────
# Generic fallback for any GitHub category we haven't curated copy for.
_r(FindingTemplate(
    template_id="leak-github",
    title="Possible code leak referencing {asset} in public GitHub repos",
    description=(
        "Public-GitHub code search returned results referencing "
        "{asset}. The matches may include credentials, configuration, "
        "or other material that shouldn't be in public code."
    ),
    remediation=(
        "Open each matching file and assess whether real secrets, "
        "credentials, or sensitive configuration are exposed. If so, "
        "rotate immediately and have the file removed from the "
        "public repository (a `git rm` isn't enough — use "
        "`git filter-repo` to scrub history). Enable GitHub's "
        "secret scanning + push protection to prevent recurrence."
    ),
    severity="high",
    category="leak",
    cwe="CWE-200",
    tags=["github-leak", "code-search"],
    summary="Public GitHub code search found content referencing {asset} — review for any leaked secrets.",
    alert_name="GitHub — Code Leak",
    monitor_type="github_change",
    references=list(_LEAK_REFS_GITHUB),
))


# ───────────────────────────────────────────────────────────────────────────
# SSL / TLS
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="ssl-cert-expired",
    title="SSL certificate expired on {asset}:{port}",
    description=(
        "The SSL/TLS certificate has expired. Browsers, mobile apps, "
        "and API clients refuse to connect; visitors see a full-page "
        "security warning and most won't click through. This is "
        "usually a missed renewal."
    ),
    remediation=(
        "Renew the certificate immediately. If the certificate came "
        "from a manual issuance, set up automated renewal via Let's "
        "Encrypt (certbot, acme.sh) or your hosting provider's managed "
        "TLS. Add a calendar reminder 30 days before expiry as a "
        "fallback."
    ),
    severity="critical",
    category="ssl",
    cwe="CWE-295",
    tags=["ssl", "certificate", "expired"],
    summary="Your SSL certificate has expired — visitors see security warnings and can't connect safely.",
    alert_name="SSL Certificate Expired",
    monitor_type="cert_expiry",
    references=[
        "RFC 5280 — Internet X.509 Public Key Infrastructure",
        "Mozilla Server-Side TLS Configuration",
    ],
))

_r(FindingTemplate(
    template_id="ssl-cert-expiring-7d",
    title="SSL certificate expires in {value} days on {asset}:{port}",
    description=(
        "The SSL certificate expires within 7 days. If renewal hasn't "
        "already started, you're at imminent risk of an outage."
    ),
    remediation=(
        "Renew the certificate now — don't wait. Verify automated "
        "renewal is configured and successfully issuing new "
        "certificates (check the renewal logs, not just the cron job)."
    ),
    severity="high",
    category="ssl",
    cwe="CWE-298",
    tags=["ssl", "certificate", "expiring"],
    summary="Your SSL certificate expires in less than a week — renew it now to avoid downtime.",
    alert_name="SSL Certificate Expiring Soon",
    monitor_type="cert_expiry",
    references=[
        "Mozilla Server-Side TLS Configuration",
    ],
))

_r(FindingTemplate(
    template_id="ssl-cert-expiring-30d",
    title="SSL certificate expires in {value} days on {asset}:{port}",
    description=(
        "The SSL certificate expires within 30 days. Plan the renewal "
        "now, especially if your renewal process involves manual steps "
        "or vendor coordination."
    ),
    remediation=(
        "Schedule the renewal. If you're not already on automated "
        "issuance (Let's Encrypt, ACME), now is the right time to "
        "switch — manual renewals are the leading cause of certificate "
        "expiry incidents."
    ),
    severity="medium",
    category="ssl",
    cwe="CWE-298",
    tags=["ssl", "certificate", "expiring"],
    summary="Your SSL certificate expires within a month — plan to renew it soon.",
    alert_name="SSL Certificate Expiring",
    monitor_type="cert_expiry",
    references=[
        "Mozilla Server-Side TLS Configuration",
    ],
))

_r(FindingTemplate(
    template_id="ssl-cert-expiring-90d",
    title="SSL certificate expires in {value} days on {asset}:{port}",
    description=(
        "The SSL certificate expires within 90 days. Not urgent yet, "
        "but worth confirming auto-renewal is in place."
    ),
    remediation=(
        "Verify automated renewal is configured and tested. Add a "
        "monitoring alert at the 30-day and 7-day marks so a missed "
        "renewal doesn't surprise you."
    ),
    severity="low",
    category="ssl",
    cwe="CWE-298",
    tags=["ssl", "certificate"],
    summary="Your SSL certificate expires within 3 months — a good time to set up auto-renewal.",
    alert_name="SSL Certificate Expiry Notice",
    monitor_type="cert_expiry",
    references=[
        "Mozilla Server-Side TLS Configuration",
    ],
))

_r(FindingTemplate(
    template_id="ssl-self-signed",
    title="Self-signed SSL certificate on {asset}:{port}",
    description=(
        "The certificate is self-signed — not issued by a trusted "
        "Certificate Authority. Browsers show a full-page security "
        "warning and clients can't verify the server's identity, "
        "leaving the connection trivially MITM-able."
    ),
    remediation=(
        "Replace with a certificate from a public CA. Let's Encrypt "
        "issues free, browser-trusted certificates with automated "
        "renewal in under five minutes. For internal-only services, "
        "stand up an internal CA and distribute its root to the "
        "clients that need it — never rely on self-signed certificates "
        "in production."
    ),
    severity="high",
    category="ssl",
    cwe="CWE-295",
    tags=["ssl", "certificate", "self-signed"],
    summary="Your site uses a self-signed certificate — browsers will warn visitors it's not trusted.",
    alert_name="Self-Signed Certificate",
    monitor_type="cert_change",
    references=[
        "Let's Encrypt — Getting Started",
        "Mozilla Server-Side TLS Configuration",
    ],
))

_r(FindingTemplate(
    template_id="ssl-hostname-mismatch",
    title="SSL certificate hostname mismatch on {asset}:{port}",
    description=(
        "The hostname doesn't appear in the certificate's Subject "
        "Common Name or Subject Alternative Names. Browsers show a "
        "warning and HTTPS clients refuse to connect by default."
    ),
    remediation=(
        "Reissue the certificate with the correct hostname listed as "
        "a SAN entry. If you serve multiple hostnames from one "
        "certificate, ensure every one is included; if you serve them "
        "from separate vhosts, configure SNI properly so each gets the "
        "right certificate."
    ),
    severity="high",
    category="ssl",
    cwe="CWE-297",
    tags=["ssl", "certificate", "hostname"],
    summary="Your SSL certificate was issued for a different domain — browsers show a mismatch warning.",
    alert_name="SSL Hostname Mismatch",
    monitor_type="cert_change",
    references=[
        "RFC 6125 — Representation and Verification of Domain-Based Application Service Identity",
        "Mozilla Server-Side TLS Configuration",
    ],
))

_r(FindingTemplate(
    template_id="ssl-cert-info",
    title="SSL certificate on {asset}:{port}: {value}",
    description="SSL/TLS certificate details for the endpoint, recorded for inventory and change-detection.",
    severity="info",
    category="ssl",
    tags=["ssl", "certificate", "info"],
    tunable=False,
    summary="Details about the SSL certificate on this endpoint.",
    alert_name="SSL Certificate Info",
    monitor_type="cert_change",
))

_r(FindingTemplate(
    template_id="ssl-connection-error",
    title="SSL/TLS connection failed on {asset}:{port}",
    description="Could not establish an SSL/TLS connection. The port may not serve HTTPS, may be firewalled, or the TLS stack may be misconfigured.",
    severity="info",
    category="ssl",
    tags=["ssl", "error"],
    tunable=False,
    summary="We couldn't establish a secure connection to this port.",
))

_r(FindingTemplate(
    template_id="ssl-tls10-enabled",
    title="TLS 1.0 enabled on {asset}",
    description=(
        "The server still accepts TLS 1.0 connections. TLS 1.0 was "
        "deprecated in 2020 and is vulnerable to BEAST and POODLE "
        "downgrade attacks. PCI DSS and most other compliance regimes "
        "explicitly prohibit TLS 1.0."
    ),
    remediation=(
        "Disable TLS 1.0 in your web-server / load-balancer / TLS-"
        "termination layer. Support only TLS 1.2 and TLS 1.3. Mozilla's "
        "SSL Configuration Generator produces ready-to-paste configs "
        "for nginx, Apache, HAProxy, AWS, etc."
    ),
    severity="high",
    category="ssl",
    cwe="CWE-326",
    tags=["ssl", "protocol", "tls1.0", "deprecated"],
    summary="Your server still supports TLS 1.0, which has known security vulnerabilities.",
    alert_name="TLS 1.0 Enabled",
    monitor_type="cert_change",
    references=[
        "RFC 8996 — Deprecating TLS 1.0 and TLS 1.1",
        "PCI DSS v4.0 §4.2.1",
        "Mozilla Server-Side TLS Configuration",
    ],
))

_r(FindingTemplate(
    template_id="ssl-tls11-enabled",
    title="TLS 1.1 enabled on {asset}",
    description=(
        "The server accepts TLS 1.1 connections. TLS 1.1 was deprecated "
        "in 2021 (RFC 8996), uses outdated cryptographic primitives, "
        "and modern browsers no longer negotiate it."
    ),
    remediation=(
        "Disable TLS 1.1 alongside TLS 1.0. Support only TLS 1.2 and "
        "TLS 1.3."
    ),
    severity="medium",
    category="ssl",
    cwe="CWE-326",
    tags=["ssl", "protocol", "tls1.1", "deprecated"],
    summary="Your server supports TLS 1.1, which is outdated and being dropped by browsers.",
    alert_name="TLS 1.1 Enabled",
    monitor_type="cert_change",
    references=[
        "RFC 8996 — Deprecating TLS 1.0 and TLS 1.1",
        "Mozilla Server-Side TLS Configuration",
    ],
))

_r(FindingTemplate(
    template_id="ssl-no-tls12",
    title="TLS 1.2 not supported on {asset}",
    description=(
        "TLS 1.2 isn't accepted on this endpoint. Older client libraries "
        "and embedded devices that don't yet speak TLS 1.3 will fail to "
        "connect."
    ),
    remediation=(
        "Enable TLS 1.2 alongside TLS 1.3 for the broadest compatibility "
        "without sacrificing security. Mozilla's 'intermediate' profile "
        "is the standard recommendation."
    ),
    severity="info",
    category="ssl",
    tags=["ssl", "protocol"],
    summary="Your server doesn't support TLS 1.2, which some older clients still need.",
    alert_name="TLS 1.2 Not Supported",
    monitor_type="cert_change",
    references=[
        "RFC 5246 — TLS 1.2",
        "Mozilla Server-Side TLS — Intermediate Profile",
    ],
))

_r(FindingTemplate(
    template_id="ssl-no-tls13",
    title="TLS 1.3 not supported on {asset}",
    description=(
        "The server doesn't support TLS 1.3. TLS 1.3 reduces handshake "
        "round-trips, removes cryptographic primitives that have caused "
        "real-world breaks (CBC, RC4, RSA key exchange), and is the "
        "default for most modern clients."
    ),
    remediation=(
        "Enable TLS 1.3. OpenSSL 1.1.1+ supports it natively; LibreSSL "
        "3.2+; BoringSSL; recent Microsoft Schannel. If you're behind a "
        "managed load balancer or CDN, enabling TLS 1.3 is usually a "
        "single setting."
    ),
    severity="low",
    category="ssl",
    tags=["ssl", "protocol", "tls1.3"],
    summary="Your server doesn't support TLS 1.3, the latest and most secure protocol version.",
    alert_name="TLS 1.3 Not Supported",
    monitor_type="cert_change",
    references=[
        "RFC 8446 — TLS 1.3",
        "Mozilla Server-Side TLS Configuration",
    ],
))

_r(FindingTemplate(
    template_id="ssl-only-deprecated-protocols",
    title="Only deprecated TLS versions supported on {asset}",
    description=(
        "The endpoint only accepts TLS 1.0 and/or TLS 1.1. Modern "
        "browsers (Chrome, Firefox, Safari, Edge) refuse to connect "
        "and most API clients have removed support entirely. The site "
        "is effectively offline for current clients."
    ),
    remediation=(
        "Enable TLS 1.2 and TLS 1.3 urgently — disable TLS 1.0 and 1.1 "
        "in the same change. This is high-priority remediation; "
        "customers on modern devices currently can't reach you."
    ),
    severity="high",
    category="ssl",
    cwe="CWE-326",
    tags=["ssl", "protocol", "critical"],
    summary="Your server only supports outdated encryption — modern browsers can't connect at all.",
    alert_name="Only Deprecated TLS",
    monitor_type="cert_change",
    references=[
        "RFC 8996 — Deprecating TLS 1.0 and TLS 1.1",
        "Mozilla Server-Side TLS Configuration",
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# HTTP Security Headers
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="header-missing-strict_transport_security",
    title="Missing Strict-Transport-Security header on {asset}:{port}",
    description=(
        "The HSTS header isn't set. Browsers will follow HTTP-to-HTTPS "
        "redirects on the first visit, but a network attacker between "
        "the user and your server can intercept that initial request "
        "and downgrade it to plain HTTP, then proxy unencrypted traffic."
    ),
    remediation=(
        "Add the header to every HTTPS response:\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\n\n"
        "Once you've verified everything works at one year and "
        "includeSubDomains, consider submitting your domain to the "
        "browser preload list so even first visits are protected."
    ),
    severity="medium",
    category="headers",
    cwe="CWE-319",
    tags=["headers", "security", "strict-transport-security"],
    summary="Your site doesn't force browsers to always use HTTPS, allowing downgrade attacks.",
    alert_name="HSTS Missing",
    monitor_type="header_change",
    references=[
        "RFC 6797 — HTTP Strict Transport Security",
        "OWASP Secure Headers Project",
        "hstspreload.org",
    ],
))

_r(FindingTemplate(
    template_id="header-missing-content_security_policy",
    title="Missing Content-Security-Policy header on {asset}:{port}",
    description=(
        "No Content-Security-Policy header is set. CSP is the strongest "
        "in-browser defence against XSS and data injection — it tells "
        "the browser exactly which scripts, styles, and connections are "
        "allowed. Without it, a single XSS bug becomes full account "
        "takeover."
    ),
    remediation=(
        "Start in report-only mode to surface what your site actually "
        "loads:\n"
        "Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report\n\n"
        "Tighten the directives based on the reports, then switch to "
        "the enforcing header. Use nonces or hashes for inline scripts "
        "rather than 'unsafe-inline'."
    ),
    severity="medium",
    category="headers",
    cwe="CWE-79",
    tags=["headers", "security", "content-security-policy"],
    summary="Your site has no Content Security Policy, leaving it more vulnerable to XSS attacks.",
    alert_name="CSP Missing",
    monitor_type="header_change",
    references=[
        "W3C Content Security Policy Level 3",
        "OWASP Secure Headers Project",
        "MDN — Content-Security-Policy",
    ],
))

_r(FindingTemplate(
    template_id="header-missing-x_frame_options",
    title="Missing X-Frame-Options header on {asset}:{port}",
    description=(
        "Neither X-Frame-Options nor a CSP frame-ancestors directive "
        "was set. The page can be embedded in an iframe on any other "
        "site, enabling clickjacking attacks where a victim is tricked "
        "into clicking inside your site through a transparent overlay."
    ),
    remediation=(
        "If you don't need to be framed: add X-Frame-Options: DENY. "
        "If you only frame yourself: SAMEORIGIN. The modern equivalent "
        "is Content-Security-Policy: frame-ancestors 'none' (or 'self'), "
        "which is preferred — set both for compatibility with older "
        "browsers."
    ),
    severity="medium",
    category="headers",
    cwe="CWE-1021",
    tags=["headers", "security", "x-frame-options"],
    summary="Your site can be embedded in malicious iframes, enabling clickjacking attacks.",
    alert_name="X-Frame-Options Missing",
    monitor_type="header_change",
    references=[
        "OWASP Clickjacking Defense Cheat Sheet",
        "MDN — X-Frame-Options",
        "W3C CSP — frame-ancestors",
    ],
))

_r(FindingTemplate(
    template_id="header-missing-x_content_type_options",
    title="Missing X-Content-Type-Options header on {asset}:{port}",
    description=(
        "X-Content-Type-Options: nosniff isn't set. Without it, browsers "
        "may MIME-sniff a response — guessing its real type from the "
        "first few bytes — and execute a file you intended to serve as "
        "data (e.g., a JSON response) as JavaScript. This is a known "
        "XSS vector when uploaded user content is served from your "
        "origin."
    ),
    remediation=(
        "Add to every response: X-Content-Type-Options: nosniff. This "
        "is universally safe — there's no compatibility cost — and is "
        "required if you have any user-uploaded content."
    ),
    severity="medium",
    category="headers",
    cwe="CWE-16",
    tags=["headers", "security", "x-content-type-options"],
    summary="Browsers may misinterpret file types on your site, which could enable script injection.",
    alert_name="X-Content-Type-Options Missing",
    monitor_type="header_change",
    references=[
        "OWASP Secure Headers Project",
        "MDN — X-Content-Type-Options",
    ],
))

_r(FindingTemplate(
    template_id="header-missing-referrer_policy",
    title="Missing Referrer-Policy header on {asset}:{port}",
    description=(
        "No Referrer-Policy is set. By default, browsers send the full "
        "URL — including query parameters and path — to any site your "
        "users navigate to or fetch resources from. Sensitive tokens, "
        "user IDs, or session data in URLs leak to third parties this "
        "way."
    ),
    remediation=(
        "Add: Referrer-Policy: strict-origin-when-cross-origin. This "
        "sends the full URL only on same-origin navigations, the origin "
        "(no path or query) on cross-origin HTTPS requests, and nothing "
        "on HTTPS-to-HTTP downgrades."
    ),
    severity="medium",
    category="headers",
    cwe="CWE-200",
    tags=["headers", "security", "referrer-policy"],
    summary="Your site leaks full page URLs to third parties when users click links.",
    alert_name="Referrer-Policy Missing",
    monitor_type="header_change",
    references=[
        "W3C Referrer Policy",
        "OWASP Secure Headers Project",
    ],
))

_r(FindingTemplate(
    template_id="header-missing-permissions_policy",
    title="Missing Permissions-Policy header on {asset}:{port}",
    description=(
        "No Permissions-Policy header is set. Permissions-Policy "
        "controls which browser features (camera, microphone, "
        "geolocation, payment, USB, etc.) the page and its embedded "
        "frames are allowed to use. Without it, a compromised third-"
        "party script or framed widget can prompt for sensitive "
        "permissions."
    ),
    remediation=(
        "Add a deny-by-default policy listing only the features you "
        "actually use:\n"
        "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()\n\n"
        "Whitelist specific origins where features are needed:\n"
        'Permissions-Policy: camera=(self "https://video.example.com")'
    ),
    severity="medium",
    category="headers",
    tags=["headers", "security", "permissions-policy"],
    summary="Your site doesn't restrict browser features like camera and mic access for embedded content.",
    alert_name="Permissions-Policy Missing",
    monitor_type="header_change",
    references=[
        "W3C Permissions Policy",
        "MDN — Permissions-Policy",
    ],
))

_r(FindingTemplate(
    template_id="header-server-version-leak",
    title="Server header exposes version: {value}",
    description=(
        "The Server response header reveals the exact software and "
        "version running. This isn't a vulnerability on its own, but "
        "it shortens the reconnaissance step — an attacker can match "
        "the version against known CVE databases without probing."
    ),
    remediation=(
        "Suppress or minimise the Server header.\n"
        "  • nginx: server_tokens off;\n"
        "  • Apache: ServerTokens Prod and ServerSignature Off\n"
        "  • IIS: remove via URL Rewrite outbound rule\n"
        "  • Express: app.disable('x-powered-by') (also covers X-Powered-By)\n\n"
        "Removing the header isn't a substitute for patching — but it "
        "raises the bar for opportunistic scanning."
    ),
    severity="low",
    category="headers",
    cwe="CWE-200",
    tags=["headers", "information-disclosure", "server"],
    summary="Your web server is advertising its exact software version, making it easier to attack.",
    alert_name="Server Version Exposed",
    monitor_type="header_change",
    references=[
        "OWASP Secure Headers Project",
        "MDN — Server header",
    ],
))

_r(FindingTemplate(
    template_id="header-powered-by-leak",
    title="X-Powered-By header exposes technology: {value}",
    description=(
        "X-Powered-By reveals the application framework or runtime "
        "(PHP version, Express, ASP.NET, etc.). Like Server: it "
        "shortens an attacker's reconnaissance step by giving them a "
        "specific version to match against known CVEs."
    ),
    remediation=(
        "Remove the header at the application or proxy layer.\n"
        "  • PHP: expose_php = Off in php.ini\n"
        "  • Express: app.disable('x-powered-by')\n"
        "  • ASP.NET: <httpProtocol><customHeaders><remove name=\"X-Powered-By\"/></customHeaders></httpProtocol>\n"
        "  • Generic: strip via reverse proxy"
    ),
    severity="low",
    category="headers",
    cwe="CWE-200",
    tags=["headers", "information-disclosure"],
    summary="Your site reveals what technology it runs on, giving attackers a head start.",
    alert_name="Technology Stack Exposed",
    monitor_type="header_change",
    references=[
        "OWASP Secure Headers Project",
    ],
))

_r(FindingTemplate(
    template_id="http-no-https-redirect",
    title="HTTP does not redirect to HTTPS on {asset}",
    description=(
        "Plain HTTP requests aren't redirected to HTTPS. Anyone typing "
        "the bare hostname into a browser, or following an old http:// "
        "link, gets an unencrypted connection — credentials, cookies, "
        "and traffic content travel in clear text. Network attackers "
        "between the user and your server can read or rewrite the "
        "response."
    ),
    remediation=(
        "Configure a permanent redirect (HTTP 301) from every plain "
        "HTTP path to its HTTPS equivalent. Combined with HSTS, this "
        "removes the downgrade window after the first secure visit. "
        "Don't return content over HTTP at all — redirect from / "
        "onward."
    ),
    severity="high",
    category="headers",
    cwe="CWE-319",
    tags=["http", "redirect", "https"],
    summary="Visitors who don't type 'https://' get an unencrypted, insecure connection.",
    alert_name="No HTTPS Redirect",
    monitor_type="header_change",
    references=[
        "RFC 6797 — HTTP Strict Transport Security",
        "OWASP Transport Layer Protection Cheat Sheet",
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Cookie Security
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="cookie-missing-secure",
    title="Cookie '{value}' missing Secure flag",
    description=(
        "The cookie is set without the Secure attribute. It can be "
        "transmitted over plain HTTP — including on automatic "
        "downgrade or mixed-content fetches — exposing the cookie "
        "value to any network observer between the user and your "
        "server."
    ),
    remediation=(
        "Set the Secure attribute on this cookie. If the cookie is "
        "session-related, also set HttpOnly and an explicit SameSite "
        "value. Most frameworks default to Secure in production — "
        "check the cookie-issuance configuration in your app."
    ),
    severity="medium",
    category="headers",
    cwe="CWE-614",
    tags=["cookie", "secure"],
    summary="A cookie on your site can be stolen by anyone on the same network.",
    alert_name="Insecure Cookie",
    monitor_type="header_change",
    references=[
        "RFC 6265bis — HTTP Cookies",
        "OWASP Session Management Cheat Sheet",
    ],
))

_r(FindingTemplate(
    template_id="cookie-missing-httponly",
    title="Cookie '{value}' missing HttpOnly flag",
    description=(
        "The cookie is readable by client-side JavaScript via "
        "document.cookie. If your site has any XSS vulnerability — "
        "even in third-party widgets — that bug becomes session "
        "theft because attacker JavaScript can simply exfiltrate the "
        "cookie."
    ),
    remediation=(
        "Set the HttpOnly attribute on this cookie. There's no "
        "compatibility cost for session and authentication cookies — "
        "they should always be HttpOnly."
    ),
    severity="medium",
    category="headers",
    cwe="CWE-1004",
    tags=["cookie", "httponly"],
    summary="A cookie on your site can be stolen through JavaScript injection attacks.",
    alert_name="Cookie Missing HttpOnly",
    monitor_type="header_change",
    references=[
        "OWASP Session Management Cheat Sheet",
    ],
))

_r(FindingTemplate(
    template_id="cookie-missing-samesite",
    title="Cookie '{value}' missing SameSite attribute",
    description=(
        "The cookie has no SameSite attribute. Browsers treat the "
        "cookie as Lax by default in modern versions, but older "
        "browsers and some embedded webviews still send it on "
        "cross-site requests, enabling cross-site request forgery "
        "(CSRF) attacks."
    ),
    remediation=(
        "Set SameSite=Lax for most cookies. Use SameSite=Strict for "
        "sensitive operations where the cookie should never travel "
        "with cross-site requests. Use SameSite=None; Secure only when "
        "you genuinely need cross-site cookies (e.g., third-party SSO)."
    ),
    severity="medium",
    category="headers",
    cwe="CWE-1275",
    tags=["cookie", "samesite"],
    summary="A cookie on your site is sent with cross-site requests, which could enable forgery attacks.",
    alert_name="Cookie Missing SameSite",
    monitor_type="header_change",
    references=[
        "RFC 6265bis §4.1.2.7 — SameSite",
        "OWASP CSRF Prevention Cheat Sheet",
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ports / Services (common entries — port_risk generates dynamic template IDs)
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="port-rdp-exposed",
    title="RDP (Remote Desktop) exposed on {asset}:{port}",
    description=(
        "Microsoft RDP is reachable from the public internet. RDP is "
        "the single most common ransomware entry point — attackers "
        "spray credential-stuffing attacks against exposed RDP at "
        "internet scale, and historic RDP CVEs (BlueKeep, DejaBlue) "
        "remain widely exploited."
    ),
    remediation=(
        "Block port 3389 from the internet at your firewall or "
        "security group. Reach RDP through a VPN, an SSH tunnel, or a "
        "zero-trust access service (Cloudflare Access, Tailscale, "
        "AWS SSM Session Manager). If RDP must be exposed temporarily, "
        "restrict the source IPs and enforce Network Level "
        "Authentication."
    ),
    severity="critical",
    category="ports",
    cwe="CWE-1327",
    tags=["port", "rdp", "remote_access"],
    summary="Remote Desktop is open to the internet — this is a primary ransomware entry point.",
    alert_name="RDP Exposed",
    monitor_type="port_change",
    references=[
        "CISA — Securing Remote Desktop (RDP)",
        "Microsoft — Securing remote access",
    ],
))

_r(FindingTemplate(
    template_id="port-docker-api-exposed",
    title="Docker API (unencrypted) exposed on {asset}:{port}",
    description=(
        "The Docker daemon API is reachable on port 2375 without TLS "
        "or authentication. Anyone who can reach this port can launch "
        "containers, mount the host filesystem, and trivially escape "
        "to root on the host — this is equivalent to an unauthenticated "
        "remote shell."
    ),
    remediation=(
        "Block port 2375 immediately at the firewall. If remote Docker "
        "access is required, use port 2376 with mutual TLS "
        "authentication. Better: don't expose the Docker socket "
        "directly — manage containers through an orchestrator "
        "(Kubernetes, Nomad, ECS) with proper RBAC."
    ),
    severity="critical",
    category="ports",
    cwe="CWE-1327",
    tags=["port", "docker", "container"],
    summary="Your Docker API is wide open to the internet — anyone can take full control of your server.",
    alert_name="Docker API Exposed",
    monitor_type="port_change",
    references=[
        "Docker — Protect the Docker daemon socket",
        "CIS Docker Benchmark §2.8",
    ],
))

_r(FindingTemplate(
    template_id="port-mysql-exposed",
    title="MySQL exposed on {asset}:{port}",
    description=(
        "A MySQL/MariaDB database server is reachable from the public "
        "internet. Even with authentication enabled, this exposes the "
        "service to credential stuffing, version-specific exploits, and "
        "data exfiltration if any account is weakly secured."
    ),
    remediation=(
        "Block port 3306 from the internet. Bind MySQL to 127.0.0.1 or "
        "an internal subnet (bind-address in my.cnf). If application "
        "servers need remote access, put them on a private network or "
        "use SSH tunnelling / a managed VPN — never expose the "
        "database to the internet."
    ),
    severity="critical",
    category="ports",
    cwe="CWE-1327",
    tags=["port", "mysql", "database"],
    summary="Your MySQL database is directly accessible from the internet.",
    alert_name="MySQL Exposed",
    monitor_type="port_change",
    references=[
        "CIS MySQL Benchmark",
        "MySQL — Securing the Initial MySQL Account",
    ],
))

_r(FindingTemplate(
    template_id="port-redis-exposed",
    title="Redis exposed on {asset}:{port}",
    description=(
        "Redis is reachable from the public internet. Older versions "
        "ship with no authentication by default, and even with AUTH "
        "configured, an attacker who reaches port 6379 can write "
        "arbitrary files via CONFIG SET — including authorized_keys for "
        "remote shell access. Exposed Redis instances are routinely "
        "compromised within hours."
    ),
    remediation=(
        "Block port 6379 from the internet. Bind Redis to 127.0.0.1 or "
        "a private interface. Enable AUTH with a strong password (or "
        "ACL users in Redis 6+), enable protected-mode, and run Redis "
        "as a non-root user."
    ),
    severity="critical",
    category="ports",
    cwe="CWE-1327",
    tags=["port", "redis", "database"],
    summary="Your Redis cache is open to the internet — attackers can read all your data or take over the server.",
    alert_name="Redis Exposed",
    monitor_type="port_change",
    references=[
        "Redis — Security",
        "CIS Redis Benchmark",
    ],
))

_r(FindingTemplate(
    template_id="port-mongodb-exposed",
    title="MongoDB exposed on {asset}:{port}",
    description=(
        "MongoDB is reachable from the public internet. Pre-3.6 builds "
        "didn't enable authentication by default and were the subject "
        "of mass-ransom campaigns. Modern builds bind to localhost out "
        "of the box, so an internet-exposed instance has been "
        "deliberately reconfigured."
    ),
    remediation=(
        "Block port 27017 from the internet. Confirm authorization is "
        "enabled in mongod.conf (security.authorization: enabled), "
        "create per-user accounts with least privilege, and bind to "
        "an internal interface."
    ),
    severity="critical",
    category="ports",
    cwe="CWE-1327",
    tags=["port", "mongodb", "database"],
    summary="Your MongoDB database is accessible from the internet.",
    alert_name="MongoDB Exposed",
    monitor_type="port_change",
    references=[
        "MongoDB — Security Checklist",
        "CIS MongoDB Benchmark",
    ],
))

_r(FindingTemplate(
    template_id="port-elasticsearch-exposed",
    title="Elasticsearch exposed on {asset}:{port}",
    description=(
        "Elasticsearch is reachable from the public internet. Pre-8.0 "
        "open-source builds have no built-in authentication; bots "
        "routinely scrape exposed instances and either steal data or "
        "ransom-wipe indexes. Even authenticated instances expose "
        "version information that maps to specific CVEs."
    ),
    remediation=(
        "Block port 9200 (and 9300) from the internet. Enable the "
        "free Elastic security features (8.0+ has them on by default) "
        "or front the cluster with a reverse proxy enforcing "
        "authentication. Bind to a private interface."
    ),
    severity="critical",
    category="ports",
    cwe="CWE-1327",
    tags=["port", "elasticsearch", "database"],
    summary="Your Elasticsearch instance is open to the internet — bots routinely scrape exposed instances.",
    alert_name="Elasticsearch Exposed",
    monitor_type="port_change",
    references=[
        "Elastic — Securing Elasticsearch",
    ],
))

_r(FindingTemplate(
    template_id="port-telnet-exposed",
    title="Telnet exposed on {asset}:{port}",
    description=(
        "Telnet is reachable on the public internet. Telnet transmits "
        "all traffic — including username and password during login — "
        "in plain text. Anyone on the network path can capture "
        "credentials passively. There is no legitimate reason to expose "
        "Telnet on the internet."
    ),
    remediation=(
        "Disable telnetd entirely. Use SSH (port 22) with key-based "
        "authentication for shell access. Network device management "
        "should also use SSH or HTTPS-based platforms (NETCONF, "
        "RESTCONF) — never Telnet."
    ),
    severity="critical",
    category="ports",
    cwe="CWE-319",
    tags=["port", "telnet", "unencrypted"],
    summary="Telnet is running on your server — all logins and data are sent in plaintext.",
    alert_name="Telnet Exposed",
    monitor_type="port_change",
    references=[
        "RFC 4250 — SSH Architecture (replacement for Telnet)",
        "NIST SP 800-53 SC-8 — Transmission Confidentiality and Integrity",
    ],
))

_r(FindingTemplate(
    template_id="port-ftp-exposed",
    title="FTP exposed on {asset}:{port}",
    description=(
        "FTP is reachable on the public internet. FTP transmits "
        "credentials and data in plain text and is frequently "
        "configured with anonymous access still enabled. The protocol "
        "was designed before the internet had adversaries; it has no "
        "modern protections."
    ),
    remediation=(
        "Disable FTP. Use SFTP (over SSH) or FTPS (FTP over TLS) for "
        "file transfer, or move to HTTPS-based alternatives like S3 "
        "presigned URLs, Box, or managed file-transfer services. "
        "Confirm anonymous access is disabled even on internal FTP."
    ),
    severity="critical",
    category="ports",
    cwe="CWE-319",
    tags=["port", "ftp", "unencrypted"],
    summary="FTP is running on your server — login credentials are sent without encryption.",
    alert_name="FTP Exposed",
    monitor_type="port_change",
    references=[
        "RFC 4217 — Securing FTP with TLS",
        "NIST SP 800-53 SC-8",
    ],
))

_r(FindingTemplate(
    template_id="port-smb-exposed",
    title="SMB exposed on {asset}:{port}",
    description=(
        "SMB (Windows file sharing) is reachable from the public "
        "internet. SMB has a long, ongoing history of critical "
        "vulnerabilities — EternalBlue (MS17-010, used by WannaCry "
        "and NotPetya), SMBGhost (CVE-2020-0796), and others. There "
        "is no scenario where SMB should be internet-facing."
    ),
    remediation=(
        "Block port 445 (and 139) from the internet at the firewall, "
        "without exception. For remote file access, use a VPN or "
        "modern alternatives (OneDrive, SharePoint, S3, Nextcloud). "
        "Internally, ensure SMBv1 is disabled and SMB signing is "
        "enforced."
    ),
    severity="critical",
    category="ports",
    cwe="CWE-1327",
    tags=["port", "smb", "file_sharing"],
    summary="Windows file sharing (SMB) is exposed — this is how WannaCry ransomware spread.",
    alert_name="SMB Exposed",
    monitor_type="port_change",
    references=[
        "CISA Alert TA17-132A — EternalBlue / WannaCry",
        "Microsoft — SMB security best practices",
    ],
))

# Generic port templates (for dynamic generation)
_r(FindingTemplate(
    template_id="port-generic-open",
    title="Open port {port}/{value} on {asset}",
    description=(
        "An open port was detected. We don't classify it as inherently "
        "risky on its own, but every internet-facing service is part "
        "of your attack surface — if this service isn't required from "
        "the public internet, close the port."
    ),
    remediation=(
        "Confirm the port needs to be publicly accessible. Close it at "
        "the host firewall or cloud security group if not. Restrict to "
        "known source IP ranges where possible."
    ),
    severity="info",
    category="ports",
    tags=["port", "exposure"],
    summary="An open port was found on your server.",
    alert_name="New Port Detected",
    monitor_type="port_change",
    references=[
        "CIS Critical Security Controls v8 — Control 4: Secure Configuration",
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# CVE / Vulnerabilities
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="cve-generic",
    title="Known vulnerability: {value}",
    description=(
        "A known CVE was matched against software running on this host. "
        "The CVE record describes the affected versions and impact "
        "(remote code execution, information disclosure, denial of "
        "service, etc.). Per-finding severity comes from the CVE's "
        "CVSS score."
    ),
    remediation=(
        "Look up the CVE ID at nvd.nist.gov for the full advisory and "
        "vendor-fixed versions. Apply the vendor patch or upgrade to "
        "the fixed release. If no patch is available yet, apply any "
        "documented mitigations (configuration changes, network "
        "controls, WAF rules) and track the CVE for resolution."
    ),
    severity="high",
    category="cve",
    tags=["cve"],
    summary="A known security vulnerability was found on your server.",
    alert_name="CVE Detected",
    monitor_type="vuln_change",
    references=[
        "NIST National Vulnerability Database (NVD)",
        "MITRE CVE",
        "FIRST CVSS v3.1 Specification",
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Technology Detection
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="tech-detected",
    title="Technology detected: {value}",
    description=(
        "We identified a technology component (web server, framework, "
        "CMS, library) running on this asset. Recorded for inventory "
        "and to drive version-aware vulnerability matching during "
        "future scans."
    ),
    severity="info",
    category="technology",
    tags=["technology"],
    tunable=False,
    summary="We identified a technology running on your server.",
    alert_name="Technology Detected",
    monitor_type="tech_change",
))

_r(FindingTemplate(
    template_id="tech-eol",
    title="End-of-life software: {value} on {asset}",
    description=(
        "{value} is end-of-life — the vendor no longer ships security "
        "patches. Any vulnerability discovered from this point on stays "
        "unpatched in your environment, and CVE-driven vulnerability "
        "scanners will flag this host as exposed indefinitely until you "
        "upgrade."
    ),
    remediation=(
        "Plan a migration to a supported version. Test in staging "
        "first; some major-version upgrades have breaking changes "
        "(PHP 7→8, Python 2→3, .NET Framework→.NET, Ubuntu 18.04→22.04). "
        "Where an immediate upgrade isn't possible, isolate the EOL "
        "host on a private network and limit its blast radius."
    ),
    severity="medium",
    category="technology",
    cwe="CWE-1104",
    tags=["technology", "outdated"],
    summary="You're running end-of-life software that no longer gets security updates.",
    alert_name="End-of-Life Software",
    monitor_type="tech_change",
    references=[
        "CIS Critical Security Controls v8 — Control 7: Continuous Vulnerability Management",
        "endoflife.date",
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Exposure Score
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="exposure-score",
    title="Exposure Score: {value}/100 (Grade {grade})",
    description="Overall security exposure score based on all open findings, weighted by severity and asset criticality.",
    severity="info",
    category="exposure",
    tags=["exposure", "score"],
    tunable=False,
    summary="Your overall security exposure score based on all scan findings.",
    alert_name="Exposure Score Updated",
    monitor_type="exposure_change",
))

# ───────────────────────────────────────────────────────────────────────────
# Monitoring / Change Detection
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="monitor-new-port",
    title="New port {port} detected on {asset}",
    description=(
        "A port that wasn't open in the previous monitoring run is now "
        "responding. This may be a planned change, but it can also be "
        "a misconfiguration, an unauthorised service, or a sign of "
        "compromise."
    ),
    remediation=(
        "Confirm the new port is expected. If it is, decide whether it "
        "should be reachable from the public internet — if not, close "
        "it at the firewall. If it isn't expected, investigate what "
        "process is listening."
    ),
    severity="medium",
    category="ports",
    tags=["monitoring", "port", "change"],
    summary="A new port just opened on your server that wasn't there before.",
    alert_name="New Port Opened",
    monitor_type="port_change",
    references=[
        "CIS Critical Security Controls v8 — Control 4: Secure Configuration",
    ],
))

_r(FindingTemplate(
    template_id="monitor-port-closed",
    title="Port {port} closed on {asset}",
    description="A previously open port is no longer responding. Recorded for change history.",
    severity="info",
    category="ports",
    tags=["monitoring", "port", "change"],
    tunable=False,
    summary="A port that was previously open on your server has been closed.",
    alert_name="Port Closed",
    monitor_type="port_change",
))

_r(FindingTemplate(
    template_id="monitor-new-service",
    title="New service detected on {asset}:{port}",
    description=(
        "A new service or different software is now responding on a "
        "port that was previously running something else. Could be a "
        "planned upgrade or an unexpected change."
    ),
    remediation=(
        "Confirm the change was authorised. If the new service is "
        "less hardened than the old one (e.g. moved from nginx behind "
        "WAF to a direct application server), revisit the security "
        "configuration."
    ),
    severity="medium",
    category="technology",
    tags=["monitoring", "service", "change"],
    summary="A new service appeared on your server that wasn't running before.",
    alert_name="New Service Detected",
    monitor_type="tech_change",
))

_r(FindingTemplate(
    template_id="monitor-cert-changed",
    title="SSL certificate changed on {asset}:{port}",
    description="The SSL/TLS certificate has been replaced with a different one. Recorded for change history.",
    severity="info",
    category="ssl",
    tags=["monitoring", "ssl", "change"],
    tunable=False,
    summary="The SSL certificate on your server was just replaced.",
    alert_name="Certificate Changed",
    monitor_type="cert_change",
))

_r(FindingTemplate(
    template_id="monitor-dns-record-changed",
    title="DNS record changed for {asset}",
    description="A DNS record was added, removed, or modified. Recorded for change history.",
    severity="info",
    category="dns",
    tags=["monitoring", "dns", "change"],
    tunable=False,
    summary="A DNS record for your domain was just changed.",
    alert_name="DNS Record Changed",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="monitor-header-changed",
    title="Security header changed on {asset}",
    description="A security header (HSTS, CSP, X-Frame-Options, etc.) was added, removed, or modified. Recorded for change history.",
    severity="info",
    category="headers",
    tags=["monitoring", "header", "change"],
    tunable=False,
    summary="A security header on your site was just changed.",
    alert_name="Security Header Changed",
    monitor_type="header_change",
))

_r(FindingTemplate(
    template_id="monitor-tech-eol-detected",
    title="End-of-life software detected on {asset}",
    description=(
        "Continuous monitoring picked up software that has now reached "
        "end-of-life since the previous scan. Vendor patches have "
        "stopped or are about to."
    ),
    remediation=(
        "Plan an upgrade to a supported version. Where the EOL "
        "software is a base OS or core runtime, upgrade timelines "
        "often span weeks — start the planning now."
    ),
    severity="high",
    category="technology",
    tags=["monitoring", "technology", "eol"],
    summary="We detected end-of-life software on your server that no longer gets security patches.",
    alert_name="EOL Software Detected",
    monitor_type="tech_change",
    references=[
        "endoflife.date",
    ],
))

_r(FindingTemplate(
    template_id="monitor-new-subdomain",
    title="New subdomain discovered: {value}",
    description=(
        "A subdomain was discovered during continuous monitoring that "
        "wasn't in our previous inventory. Could be a planned launch, "
        "shadow IT, or an attacker setting up a phishing page on a "
        "dangling DNS record."
    ),
    remediation=(
        "Confirm the subdomain is yours and intentional. Add it to the "
        "appropriate asset group so it's covered by future scans. If "
        "you don't recognise it, investigate ownership and consider "
        "removing the DNS record."
    ),
    severity="low",
    category="dns",
    tags=["monitoring", "dns", "subdomain", "discovery"],
    summary="A new subdomain was found for your domain that we hadn't seen before.",
    alert_name="New Subdomain Discovered",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="monitor-spf-changed",
    title="SPF record changed for {asset}",
    description="The SPF TXT record was modified since the last scan. Verify the changes were authorised.",
    severity="medium",
    category="dns",
    tags=["monitoring", "dns", "spf", "change"],
    summary="Your email SPF record was just changed — make sure it was authorized.",
    alert_name="SPF Record Changed",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="monitor-dmarc-changed",
    title="DMARC record changed for {asset}",
    description="The DMARC TXT record was modified since the last scan. Verify the changes were authorised.",
    severity="medium",
    category="dns",
    tags=["monitoring", "dns", "dmarc", "change"],
    summary="Your DMARC email security record was just changed.",
    alert_name="DMARC Record Changed",
    monitor_type="dns_change",
))


# ───────────────────────────────────────────────────────────────────────────
# Public Quick-Scan Explainer
# ───────────────────────────────────────────────────────────────────────────
# These three templates back the unauthenticated /assistant/public-explain
# endpoint. The unified quick-scan engine emits a coarse taxonomy
# (service_exposure, risky_port, cve) rather than the granular template IDs
# the authenticated scanner uses, so we keep one curated entry per type.
# Improving the copy here automatically improves what unauth visitors see
# on the landing page.

_r(FindingTemplate(
    template_id="quick-scan-service-exposure",
    title="Open network service detected on {asset}",
    description=(
        "A network service was found reachable from the public internet on "
        "{asset}. Every internet-exposed service is a potential entry point "
        "— even a fully patched, legitimately public service still has to "
        "defend itself against credential stuffing, denial of service, "
        "scraping, and newly disclosed vulnerabilities. The fewer services "
        "you expose, the smaller the surface attackers can probe."
    ),
    remediation=(
        "First, decide whether this service is meant to be reachable from "
        "the public internet at all. If the answer is no, restrict it: a "
        "firewall or security-group rule, a VPN, or a Zero Trust access "
        "proxy are all good options.\n\n"
        "If the service does need to be public, harden it: keep it on a "
        "supported and patched version, require strong authentication, "
        "enable rate limiting, and forward access logs to a SIEM. Subscribe "
        "to the vendor's advisories so you hear about new CVEs early.\n\n"
        "Finally, monitor the host so a new service appearing here triggers "
        "an alert rather than waiting for the next scan."
    ),
    severity="info",
    category="ports",
    cwe="CWE-200",
    tags=["quick-scan", "public-explainer", "exposure"],
    summary="A network service is publicly reachable. Confirm whether it should be, and either restrict it or make sure it's hardened.",
    alert_name="Public Service Detected",
    monitor_type="port_change",
    references=[
        "OWASP — Network Segmentation Cheat Sheet",
        "CIS Critical Security Controls — Asset Inventory",
        "NIST SP 800-41 — Guidelines on Firewalls and Firewall Policy",
    ],
))

_r(FindingTemplate(
    template_id="quick-scan-risky-port",
    title="Risky service exposed on {asset} (port {port})",
    description=(
        "A service known to attract attackers is reachable from the public "
        "internet on {asset}. Ports like RDP (3389), SMB (445), telnet (23), "
        "Redis (6379), MongoDB (27017), and bare database ports are "
        "constantly scanned for default credentials, known vulnerabilities, "
        "and misconfigurations. Even when the service is fully patched, "
        "exposing it directly to the internet is widely treated as a "
        "security anti-pattern."
    ),
    remediation=(
        "Move the service behind a network boundary so it isn't reachable "
        "from the public internet. Standard options: a corporate VPN, a "
        "bastion / jump host, a Zero Trust access proxy (Cloudflare Access, "
        "Tailscale, Twingate, AWS Verified Access), or a tightly scoped "
        "firewall rule limiting source IPs.\n\n"
        "If the service genuinely has to be public, require multi-factor "
        "authentication, disable any default accounts, rotate credentials, "
        "and enable account lockout after repeated failed logins. Subscribe "
        "to the vendor's security advisories so a new CVE on this service "
        "doesn't surprise you."
    ),
    severity="medium",
    category="ports",
    cwe="CWE-284",
    tags=["quick-scan", "public-explainer", "risky-port", "exposure"],
    summary="A high-risk service like RDP, SMB, or a database is open to the internet. Move it behind a VPN or restrict source IPs.",
    alert_name="Risky Port Exposed",
    monitor_type="port_change",
    references=[
        "CISA — Guidance on Reducing the Significant Risk of Known Exploited Vulnerabilities",
        "Microsoft — Best Practices for Securing RDP",
        "NSA — Network Infrastructure Security Guide",
    ],
))

_r(FindingTemplate(
    template_id="quick-scan-cve",
    title="Known vulnerability ({cve}) on {asset}",
    description=(
        "A software version detected on {asset} matches a published CVE "
        "({cve}). Public CVEs are catalogued, indexed, and actively scanned "
        "for by both researchers and attackers — often within hours of "
        "disclosure. Depending on the vulnerability, an attacker may be "
        "able to execute code, leak data, escalate privileges, or crash "
        "the service. Exploit code for popular CVEs is frequently published "
        "alongside the advisory."
    ),
    remediation=(
        "Patch to a version of the software that includes the fix. The "
        "CVE entry on NVD or the vendor's advisory lists the fixed "
        "version.\n\n"
        "If a patch isn't available yet, apply the vendor's mitigation: "
        "disable the affected feature, restrict access via firewall rules, "
        "deploy WAF signatures that detect exploitation attempts, or "
        "isolate the host. Treat CVSS 9.0+ as same-day work, 7.0–8.9 "
        "within the week, 4.0–6.9 within the month."
    ),
    severity="high",
    category="cve",
    cwe="CWE-1395",
    tags=["quick-scan", "public-explainer", "cve", "vulnerability"],
    summary="The host is running software with a known security flaw. Patch to the fixed version, or apply the vendor's mitigation if no patch is available.",
    alert_name="Known Vulnerability Detected",
    monitor_type="vuln_change",
    references=[
        "NIST National Vulnerability Database (NVD)",
        "MITRE CVE List",
        "FIRST.org — Common Vulnerability Scoring System v3.1",
    ],
))


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════

def get_template(template_id: str) -> Optional[FindingTemplate]:
    """
    Look up a template by ID.

    Tries exact match first, then prefix match for dynamic template IDs.
    e.g. "tech-eol-php" → tries exact, then matches "tech-eol"
         "cve-cve-2021-1234" → tries exact, then matches "cve-generic"
         "port-3306-open" → tries exact, then matches "port-generic-open"
    """
    # Exact match
    if template_id in _TEMPLATES:
        return _TEMPLATES[template_id]

    # Prefix match: find the longest matching prefix
    best: Optional[FindingTemplate] = None
    best_len = 0
    for tid, tmpl in _TEMPLATES.items():
        if template_id.startswith(tid) and len(tid) > best_len:
            best = tmpl
            best_len = len(tid)

    if best:
        return best

    # Category-based fallback for known prefixes
    _FALLBACK_MAP = {
        "tech-eol-": "tech-eol",
        "tech-": "tech-detected",
        "cve-": "cve-generic",
        "port-": "port-generic-open",
        "nuclei-": "nuclei-uncategorized",
    }
    for prefix, fallback_id in _FALLBACK_MAP.items():
        if template_id.startswith(prefix):
            return _TEMPLATES.get(fallback_id)

    return None


def get_all_templates() -> Dict[str, FindingTemplate]:
    """Return the full registry (read-only copy)."""
    return dict(_TEMPLATES)


def get_templates_by_category(category: str) -> List[FindingTemplate]:
    """Return all templates in a given category."""
    return [t for t in _TEMPLATES.values() if t.category == category]


def get_templates_by_monitor_type(monitor_type: str) -> List[FindingTemplate]:
    """Return all templates for a given monitor type."""
    return [t for t in _TEMPLATES.values() if t.monitor_type == monitor_type]


def get_tunable_templates() -> List[FindingTemplate]:
    """Return all templates that can be suppressed via tuning rules."""
    return [t for t in _TEMPLATES.values() if t.tunable]


def get_alert_names() -> Dict[str, str]:
    """Return a mapping of template_id → alert_name for all templates."""
    return {
        t.template_id: t.alert_name
        for t in _TEMPLATES.values()
        if t.alert_name
    }


def render_title(template_id: str, **kwargs: str) -> str:
    """
    Render a template title with placeholder values.

    Usage:
        render_title("dns-no-spf", asset="example.com")
        → "No SPF record for example.com"
    """
    tmpl = _TEMPLATES.get(template_id)
    if not tmpl:
        return kwargs.get("title", f"Finding: {template_id}")
    try:
        return tmpl.title.format(**kwargs)
    except KeyError:
        return tmpl.title


def render_summary(template_id: str) -> Optional[str]:
    """Get the human-readable summary for a template."""
    tmpl = _TEMPLATES.get(template_id)
    return tmpl.summary if tmpl else None
