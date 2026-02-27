# app/scanner/analyzers/dns_analyzer.py
"""
DNS Security Analyzer.

Reads DNS record data from the DNS engine and produces findings for
email security, DNS configuration, zone security, and subdomain takeover.

Checks performed:
    CRITICAL:
        - Zone transfer (AXFR) successful — full zone exposed
        - Subdomain takeover confirmed — dangling CNAME to decommissioned service

    HIGH:
        - No SPF record (email spoofing possible)
        - SPF with +all (allows anyone to send)
        - No DMARC record (no email auth enforcement)
        - DMARC policy set to "none" (monitoring only)
        - Subdomain takeover likely — CNAME target NXDOMAIN on vulnerable service

    MEDIUM:
        - SPF with ~all (softfail — not enforcing)
        - DMARC without rua (no aggregate reports)
        - Single nameserver (no redundancy)
        - No MX record for domain with mail indicators
        - Subdomain takeover suspicious — CNAME target NXDOMAIN, unconfirmed service

    LOW:
        - No DKIM selectors found
        - No IPv6 (AAAA) records
        - SPF includes more than 10 lookups (may exceed limit)

    INFO:
        - DNS configuration summary
        - Subdomain inventory
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext

logger = logging.getLogger(__name__)


class DNSAnalyzer(BaseAnalyzer):
    """
    Analyzes DNS records for security misconfigurations.

    Focuses on:
        1. Email security (SPF, DKIM, DMARC)
        2. Zone security (zone transfers, NS redundancy)
        3. DNS hygiene (IPv6, record completeness)
        4. Subdomain takeover (dangling CNAME detection)
    """

    @property
    def name(self) -> str:
        return "dns_analyzer"

    @property
    def required_engines(self) -> List[str]:
        return ["dns"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []

        dns_data = ctx.get_engine_data("dns")
        if not dns_data:
            return drafts

        domain = dns_data.get("domain", ctx.asset_value)
        records = dns_data.get("records", {})

        # --- Email security ---
        drafts.extend(self._check_spf(dns_data, domain))
        drafts.extend(self._check_dmarc(dns_data, domain))
        drafts.extend(self._check_dkim(dns_data, domain))

        # --- Zone security ---
        drafts.extend(self._check_zone_transfer(dns_data, domain))
        drafts.extend(self._check_nameservers(dns_data, domain))

        # --- DNS hygiene ---
        drafts.extend(self._check_ipv6(dns_data, domain))

        # --- Subdomain takeover ---
        drafts.extend(self._check_subdomain_takeover(dns_data, domain))

        return drafts

    # -------------------------------------------------------------------
    # SPF checks
    # -------------------------------------------------------------------

    def _check_spf(
        self, dns_data: Dict[str, Any], domain: str
    ) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []
        spf = dns_data.get("spf")

        if not spf:
            drafts.append(FindingDraft(
                template_id="dns-no-spf",
                title=f"No SPF record for {domain}",
                severity="high",
                category="dns",
                description=(
                    f"No SPF (Sender Policy Framework) record was found for {domain}. "
                    "Without SPF, anyone can send email pretending to be from your "
                    "domain. This enables phishing attacks and can damage your "
                    "domain's email reputation."
                ),
                remediation=(
                    "Add an SPF TXT record to your DNS. A basic record looks like: "
                    f'"v=spf1 include:_spf.google.com -all" (adjust for your email provider). '
                    "Use -all (hardfail) to reject unauthorized senders."
                ),
                finding_type="dns_email_security",
                cwe="CWE-290",
                tags=["dns", "email", "spf"],
                engine="dns",
                details={"domain": domain, "txt_records": dns_data.get("records", {}).get("TXT", [])},
                dedupe_fields={"check": "spf_missing"},
            ))
            return drafts

        # SPF exists — check the "all" qualifier
        all_qual = spf.get("all_qualifier", "")
        mechanisms = spf.get("mechanisms", [])

        if all_qual == "+":
            drafts.append(FindingDraft(
                template_id="dns-spf-plus-all",
                title=f"SPF record allows all senders (+all) for {domain}",
                severity="high",
                category="dns",
                description=(
                    f"The SPF record for {domain} ends with '+all', which means "
                    "ANY server is authorized to send email as your domain. "
                    "This completely defeats the purpose of SPF."
                ),
                remediation=(
                    "Change +all to -all (hardfail) or ~all (softfail) in your SPF record. "
                    f"Current record: {spf.get('raw', '')}"
                ),
                finding_type="dns_email_security",
                cwe="CWE-290",
                tags=["dns", "email", "spf", "misconfigured"],
                engine="dns",
                details={"spf": spf, "domain": domain},
                dedupe_fields={"check": "spf_plus_all"},
            ))

        elif all_qual == "~":
            drafts.append(FindingDraft(
                template_id="dns-spf-softfail",
                title=f"SPF uses softfail (~all) for {domain}",
                severity="medium",
                category="dns",
                description=(
                    f"The SPF record for {domain} uses ~all (softfail). This means "
                    "unauthorized emails are marked as suspicious but not rejected. "
                    "For stronger protection, use -all (hardfail)."
                ),
                remediation=(
                    "Consider changing ~all to -all once you've verified all "
                    "legitimate email sources are included in the SPF record. "
                    f"Current record: {spf.get('raw', '')}"
                ),
                finding_type="dns_email_security",
                tags=["dns", "email", "spf"],
                engine="dns",
                details={"spf": spf, "domain": domain},
                dedupe_fields={"check": "spf_softfail"},
            ))

        elif all_qual == "?":
            drafts.append(FindingDraft(
                template_id="dns-spf-neutral",
                title=f"SPF uses neutral (?all) for {domain}",
                severity="medium",
                category="dns",
                description=(
                    f"The SPF record for {domain} uses ?all (neutral). This provides "
                    "no protection — unauthorized emails are neither accepted nor rejected."
                ),
                remediation=(
                    "Change ?all to -all (hardfail) for proper email protection. "
                    f"Current record: {spf.get('raw', '')}"
                ),
                finding_type="dns_email_security",
                tags=["dns", "email", "spf"],
                engine="dns",
                details={"spf": spf, "domain": domain},
                dedupe_fields={"check": "spf_neutral"},
            ))

        # Check for too many DNS lookups (SPF 10-lookup limit)
        lookup_mechanisms = [
            m for m in mechanisms
            if any(m.lower().startswith(p) for p in
                   ("include:", "a:", "mx:", "ptr:", "redirect="))
        ]
        if len(lookup_mechanisms) > 10:
            drafts.append(FindingDraft(
                template_id="dns-spf-too-many-lookups",
                title=f"SPF record may exceed 10-lookup limit for {domain}",
                severity="low",
                category="dns",
                description=(
                    f"The SPF record for {domain} contains {len(lookup_mechanisms)} "
                    "mechanisms that require DNS lookups. SPF has a limit of 10 "
                    "DNS lookups. Exceeding this causes a permerror and SPF fails."
                ),
                remediation=(
                    "Reduce SPF lookups by flattening includes or using ip4:/ip6: "
                    "mechanisms instead. Tools like SPF flattening services can help."
                ),
                finding_type="dns_email_security",
                tags=["dns", "email", "spf"],
                engine="dns",
                details={"spf": spf, "lookup_count": len(lookup_mechanisms)},
                dedupe_fields={"check": "spf_lookups"},
            ))

        return drafts

    # -------------------------------------------------------------------
    # DMARC checks
    # -------------------------------------------------------------------

    def _check_dmarc(
        self, dns_data: Dict[str, Any], domain: str
    ) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []
        dmarc = dns_data.get("dmarc")

        if not dmarc:
            drafts.append(FindingDraft(
                template_id="dns-no-dmarc",
                title=f"No DMARC record for {domain}",
                severity="high",
                category="dns",
                description=(
                    f"No DMARC record was found for {domain}. DMARC (Domain-based "
                    "Message Authentication, Reporting & Conformance) tells receiving "
                    "servers what to do when SPF/DKIM checks fail. Without DMARC, "
                    "there's no enforcement policy for email authentication."
                ),
                remediation=(
                    "Add a DMARC TXT record at _dmarc." + domain + ". Start with: "
                    '"v=DMARC1; p=none; rua=mailto:dmarc-reports@' + domain + '" '
                    "to collect reports, then move to p=quarantine or p=reject."
                ),
                finding_type="dns_email_security",
                cwe="CWE-290",
                tags=["dns", "email", "dmarc"],
                engine="dns",
                details={"domain": domain},
                dedupe_fields={"check": "dmarc_missing"},
            ))
            return drafts

        # DMARC exists — check policy
        policy = dmarc.get("policy", "none")

        if policy == "none":
            drafts.append(FindingDraft(
                template_id="dns-dmarc-none",
                title=f"DMARC policy is 'none' (monitoring only) for {domain}",
                severity="high",
                category="dns",
                description=(
                    f"The DMARC policy for {domain} is set to 'none'. This means "
                    "failed emails are delivered normally — DMARC is only collecting "
                    "reports but not enforcing. This does not prevent email spoofing."
                ),
                remediation=(
                    "After reviewing DMARC reports and confirming legitimate sources "
                    "pass SPF/DKIM, upgrade to p=quarantine (suspicious emails go to spam) "
                    "or p=reject (unauthorized emails are blocked)."
                ),
                finding_type="dns_email_security",
                tags=["dns", "email", "dmarc"],
                engine="dns",
                details={"dmarc": dmarc, "domain": domain},
                dedupe_fields={"check": "dmarc_none"},
            ))

        # Check for missing rua (reporting address)
        if not dmarc.get("rua"):
            drafts.append(FindingDraft(
                template_id="dns-dmarc-no-rua",
                title=f"DMARC record has no reporting address (rua) for {domain}",
                severity="medium",
                category="dns",
                description=(
                    f"The DMARC record for {domain} does not specify an rua "
                    "(reporting) address. Without it, you won't receive aggregate "
                    "reports about email authentication failures."
                ),
                remediation=(
                    "Add rua=mailto:dmarc-reports@" + domain + " to your DMARC record "
                    "to receive aggregate reports."
                ),
                finding_type="dns_email_security",
                tags=["dns", "email", "dmarc"],
                engine="dns",
                details={"dmarc": dmarc, "domain": domain},
                dedupe_fields={"check": "dmarc_no_rua"},
            ))

        return drafts

    # -------------------------------------------------------------------
    # DKIM checks
    # -------------------------------------------------------------------

    def _check_dkim(
        self, dns_data: Dict[str, Any], domain: str
    ) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []
        dkim_found = dns_data.get("dkim_selectors_found", [])

        if not dkim_found:
            drafts.append(FindingDraft(
                template_id="dns-no-dkim",
                title=f"No DKIM records found for {domain}",
                severity="low",
                category="dns",
                description=(
                    f"No DKIM (DomainKeys Identified Mail) records were found for "
                    f"common selectors on {domain}. DKIM adds a digital signature "
                    "to outgoing emails, proving they haven't been tampered with. "
                    "Note: DKIM selectors vary by provider and may use custom names "
                    "not covered by this check."
                ),
                remediation=(
                    "Configure DKIM signing for your email provider. Most providers "
                    "(Google Workspace, Microsoft 365, etc.) have guides for setting "
                    "up DKIM DNS records."
                ),
                finding_type="dns_email_security",
                tags=["dns", "email", "dkim"],
                engine="dns",
                details={"domain": domain, "selectors_checked": True},
                dedupe_fields={"check": "dkim_missing"},
            ))

        return drafts

    # -------------------------------------------------------------------
    # Zone security checks
    # -------------------------------------------------------------------

    def _check_zone_transfer(
        self, dns_data: Dict[str, Any], domain: str
    ) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []
        zt = dns_data.get("zone_transfer", {})

        if zt.get("successful"):
            drafts.append(FindingDraft(
                template_id="dns-zone-transfer-open",
                title=f"DNS zone transfer (AXFR) successful for {domain}",
                severity="critical",
                category="dns",
                description=(
                    f"A DNS zone transfer was successfully completed from "
                    f"{zt.get('server', 'a nameserver')} for {domain}. "
                    f"This exposed {zt.get('records_count', 'all')} DNS records. "
                    "Zone transfers reveal the complete DNS zone including all "
                    "subdomains, IP addresses, and internal hostnames — giving "
                    "attackers a detailed map of the infrastructure."
                ),
                remediation=(
                    "Restrict zone transfers (AXFR) to authorized secondary "
                    "nameservers only. In BIND: allow-transfer { trusted-servers; }; "
                    "Most DNS providers block zone transfers by default."
                ),
                finding_type="dns_zone_security",
                cwe="CWE-200",
                tags=["dns", "zone-transfer", "critical"],
                engine="dns",
                details={
                    "zone_transfer": zt,
                    "domain": domain,
                },
                dedupe_fields={"check": "zone_transfer"},
            ))

        return drafts

    def _check_nameservers(
        self, dns_data: Dict[str, Any], domain: str
    ) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []
        ns_count = dns_data.get("nameserver_count", 0)
        ns_list = dns_data.get("records", {}).get("NS", [])

        if ns_count == 1:
            drafts.append(FindingDraft(
                template_id="dns-single-nameserver",
                title=f"Only one nameserver for {domain}",
                severity="medium",
                category="dns",
                description=(
                    f"Only one nameserver ({ns_list[0] if ns_list else 'unknown'}) "
                    f"was found for {domain}. If this nameserver goes down, "
                    "the domain becomes completely unresolvable. RFC 2182 "
                    "recommends at least two nameservers."
                ),
                remediation=(
                    "Add at least one additional nameserver for redundancy. "
                    "Most DNS providers offer multiple nameservers by default."
                ),
                finding_type="dns_config",
                tags=["dns", "nameserver", "redundancy"],
                engine="dns",
                details={"nameservers": ns_list, "count": ns_count},
                dedupe_fields={"check": "single_ns"},
            ))

        return drafts

    # -------------------------------------------------------------------
    # DNS hygiene
    # -------------------------------------------------------------------

    def _check_ipv6(
        self, dns_data: Dict[str, Any], domain: str
    ) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []

        if not dns_data.get("has_ipv6"):
            drafts.append(FindingDraft(
                template_id="dns-no-ipv6",
                title=f"No IPv6 (AAAA) records for {domain}",
                severity="low",
                category="dns",
                description=(
                    f"No AAAA records were found for {domain}. IPv6 adoption is "
                    "growing, and some networks are IPv6-only. Not having AAAA "
                    "records means the domain is not accessible over IPv6."
                ),
                remediation=(
                    "If your hosting provider supports IPv6, add AAAA records "
                    "pointing to the IPv6 address. Most modern providers support dual-stack."
                ),
                finding_type="dns_config",
                tags=["dns", "ipv6"],
                engine="dns",
                details={"domain": domain},
                dedupe_fields={"check": "no_ipv6"},
            ))

        return drafts

    # -------------------------------------------------------------------
    # Subdomain takeover checks
    # -------------------------------------------------------------------

    def _check_subdomain_takeover(
        self, dns_data: Dict[str, Any], domain: str
    ) -> List[FindingDraft]:
        """
        Analyze subdomain takeover check results from the DNS engine.

        Produces findings at different severity levels based on confidence:
            - critical: HTTP fingerprint confirmed the service is decommissioned
            - critical: CNAME target NXDOMAIN on a service known to be claimable
            - medium:   CNAME target NXDOMAIN but service takeover not confirmed
        """
        drafts: List[FindingDraft] = []
        takeover_checks = dns_data.get("subdomain_takeover_checks", [])

        if not takeover_checks:
            return drafts

        for check in takeover_checks:
            cname_target = check.get("cname_target", "unknown")
            service = check.get("service", "unknown service")
            vulnerable = check.get("vulnerable", False)
            evidence = check.get("evidence", "")
            detection_method = check.get("detection_method", "")
            checked_domain = check.get("domain", domain)

            if vulnerable and detection_method == "http_fingerprint":
                # Confirmed via HTTP response body fingerprint
                drafts.append(FindingDraft(
                    template_id="dns-subdomain-takeover-confirmed",
                    title=f"Subdomain takeover vulnerability on {checked_domain} ({service})",
                    severity="critical",
                    category="dns",
                    description=(
                        f"The subdomain {checked_domain} has a CNAME record pointing to "
                        f"{cname_target} ({service}), but the service has been "
                        f"decommissioned. The HTTP response from {checked_domain} contains "
                        f"a known error page fingerprint for {service}, confirming the "
                        f"service is no longer active. An attacker can register the same "
                        f"resource on {service} and take full control of {checked_domain}, "
                        f"enabling phishing, cookie theft, and reputation damage."
                    ),
                    remediation=(
                        f"Immediately remove the CNAME record for {checked_domain} that "
                        f"points to {cname_target}. If the {service} resource is still "
                        f"needed, reclaim it before removing the DNS record. Until fixed, "
                        f"this subdomain can be hijacked by anyone."
                    ),
                    finding_type="dns_subdomain_takeover",
                    cwe="CWE-284",
                    tags=["dns", "subdomain-takeover", "dangling-cname", service.lower().replace(" ", "-")],
                    engine="dns",
                    confidence="high",
                    details={
                        "domain": checked_domain,
                        "cname_target": cname_target,
                        "service": service,
                        "detection_method": detection_method,
                        "evidence": evidence,
                        "http_status": check.get("http_status"),
                        "pattern_matched": check.get("pattern_matched"),
                    },
                    dedupe_fields={
                        "check": "subdomain_takeover",
                        "domain": checked_domain,
                        "cname": cname_target,
                    },
                ))

            elif vulnerable and detection_method == "nxdomain":
                # CNAME target does not resolve and service is known claimable
                drafts.append(FindingDraft(
                    template_id="dns-subdomain-takeover-nxdomain",
                    title=f"Subdomain takeover likely on {checked_domain} ({service})",
                    severity="critical",
                    category="dns",
                    description=(
                        f"The subdomain {checked_domain} has a CNAME record pointing to "
                        f"{cname_target} ({service}), but the CNAME target does not "
                        f"resolve (NXDOMAIN). This service is known to allow registration "
                        f"of unclaimed resources, meaning an attacker can claim "
                        f"{cname_target} and take control of {checked_domain}."
                    ),
                    remediation=(
                        f"Remove the CNAME record for {checked_domain} pointing to "
                        f"{cname_target}. If the {service} resource is still needed, "
                        f"reclaim it immediately — the NXDOMAIN response confirms it "
                        f"is currently unclaimed and available for takeover."
                    ),
                    finding_type="dns_subdomain_takeover",
                    cwe="CWE-284",
                    tags=["dns", "subdomain-takeover", "dangling-cname", "nxdomain", service.lower().replace(" ", "-")],
                    engine="dns",
                    confidence="high",
                    details={
                        "domain": checked_domain,
                        "cname_target": cname_target,
                        "service": service,
                        "detection_method": detection_method,
                        "evidence": evidence,
                        "pattern_matched": check.get("pattern_matched"),
                    },
                    dedupe_fields={
                        "check": "subdomain_takeover",
                        "domain": checked_domain,
                        "cname": cname_target,
                    },
                ))

            elif detection_method == "nxdomain_unconfirmed":
                # CNAME target doesn't resolve but we can't confirm takeover
                drafts.append(FindingDraft(
                    template_id="dns-subdomain-takeover-suspicious",
                    title=f"Suspicious dangling CNAME on {checked_domain} ({service})",
                    severity="medium",
                    category="dns",
                    description=(
                        f"The subdomain {checked_domain} has a CNAME record pointing to "
                        f"{cname_target} ({service}), but the CNAME target does not "
                        f"resolve (NXDOMAIN). While this service's takeover status could "
                        f"not be automatically confirmed, a dangling CNAME record is a "
                        f"security risk that should be investigated. The DNS record may "
                        f"be pointing to a decommissioned resource."
                    ),
                    remediation=(
                        f"Investigate whether {cname_target} is still a valid resource. "
                        f"If the {service} service is no longer in use, remove the CNAME "
                        f"record for {checked_domain} to eliminate the risk."
                    ),
                    finding_type="dns_subdomain_takeover",
                    cwe="CWE-284",
                    tags=["dns", "subdomain-takeover", "dangling-cname", "investigate", service.lower().replace(" ", "-")],
                    engine="dns",
                    confidence="medium",
                    details={
                        "domain": checked_domain,
                        "cname_target": cname_target,
                        "service": service,
                        "detection_method": detection_method,
                        "evidence": evidence,
                        "pattern_matched": check.get("pattern_matched"),
                    },
                    dedupe_fields={
                        "check": "subdomain_takeover",
                        "domain": checked_domain,
                        "cname": cname_target,
                    },
                ))

            elif detection_method == "http_error":
                # Matched a known service pattern but couldn't connect to verify
                drafts.append(FindingDraft(
                    template_id="dns-subdomain-takeover-check-failed",
                    title=f"Dangling CNAME detected on {checked_domain} ({service}) — verification failed",
                    severity="medium",
                    category="dns",
                    description=(
                        f"The subdomain {checked_domain} has a CNAME record pointing to "
                        f"{cname_target} ({service}). This matches a known service that "
                        f"may be vulnerable to subdomain takeover, but the automated "
                        f"verification check could not connect to confirm. "
                        f"Error: {evidence}"
                    ),
                    remediation=(
                        f"Manually verify that {cname_target} is still an active resource "
                        f"on {service}. If it is no longer in use, remove the CNAME record "
                        f"for {checked_domain}."
                    ),
                    finding_type="dns_subdomain_takeover",
                    cwe="CWE-284",
                    tags=["dns", "subdomain-takeover", "dangling-cname", "needs-verification", service.lower().replace(" ", "-")],
                    engine="dns",
                    confidence="low",
                    details={
                        "domain": checked_domain,
                        "cname_target": cname_target,
                        "service": service,
                        "detection_method": detection_method,
                        "evidence": evidence,
                        "pattern_matched": check.get("pattern_matched"),
                    },
                    dedupe_fields={
                        "check": "subdomain_takeover",
                        "domain": checked_domain,
                        "cname": cname_target,
                    },
                ))

        return drafts