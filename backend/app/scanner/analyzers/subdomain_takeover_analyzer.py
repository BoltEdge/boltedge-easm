# app/scanner/analyzers/subdomain_takeover.py
"""
Subdomain Takeover Analyzer.

Reads subdomain_takeover_checks from the DNS engine and produces
properly classified FindingDrafts for dangling CNAME records that
point to claimable third-party services.

Severity classification:
    CRITICAL — Confirmed vulnerable (HTTP fingerprint matched or NXDOMAIN
               on a service known to be claimable). An attacker can register
               the service and serve content on your domain.
    HIGH     — CNAME target does not resolve (NXDOMAIN) but the service
               pattern doesn't have confirmed claimability. Still very likely
               exploitable.
    MEDIUM   — CNAME points to a known service pattern but the target is
               still active. Could become vulnerable if the service is
               decommissioned without removing the DNS record.
    INFO     — CNAME checked, no issues found.

Required engine: dns
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext

logger = logging.getLogger(__name__)


class SubdomainTakeoverAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "subdomain_takeover"

    @property
    def required_engines(self) -> List[str]:
        return ["dns"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        dns_data = ctx.get_engine_data("dns")
        checks = dns_data.get("subdomain_takeover_checks", [])

        if not checks:
            return []

        drafts: List[FindingDraft] = []
        domain = dns_data.get("domain", ctx.asset_value)

        for check in checks:
            cname_target = check.get("cname_target", "")
            service = check.get("service", "Unknown")
            vulnerable = check.get("vulnerable", False)
            evidence = check.get("evidence", "")
            detection_method = check.get("detection_method", "")
            check_domain = check.get("domain", domain)
            http_status = check.get("http_status")

            # ── Confirmed vulnerable: fingerprint match or NXDOMAIN-claimable ──
            if vulnerable:
                severity = "critical"
                title = f"Subdomain takeover possible: {check_domain} → {service}"
                description = (
                    f"The subdomain {check_domain} has a CNAME record pointing to "
                    f"{cname_target}, which belongs to {service}. "
                    f"The service appears to be decommissioned or unclaimed. "
                    f"An attacker could register this resource on {service} and "
                    f"serve arbitrary content under your domain, enabling phishing, "
                    f"cookie theft, and reputation damage."
                )
                if detection_method == "nxdomain":
                    description += (
                        f"\n\nDetection: The CNAME target does not resolve (NXDOMAIN), "
                        f"and {service} is known to allow registration of unclaimed resources."
                    )
                elif detection_method == "http_fingerprint":
                    description += (
                        f"\n\nDetection: An HTTP request to {check_domain} returned a "
                        f"response matching the {service} \"unclaimed\" error page."
                    )

                remediation = (
                    f"Immediately remove the dangling CNAME record for {check_domain} "
                    f"from your DNS configuration, or reclaim the resource on {service}.\n\n"
                    f"Steps:\n"
                    f"1. Remove the CNAME record: {check_domain} → {cname_target}\n"
                    f"2. Alternatively, re-register the resource on {service} to prevent "
                    f"third-party claim\n"
                    f"3. Audit all CNAME records for similar dangling references\n"
                    f"4. Implement a DNS hygiene process: when decommissioning services, "
                    f"always remove associated DNS records first"
                )

                drafts.append(FindingDraft(
                    template_id=f"takeover-confirmed-{service.lower().replace(' ', '-').replace('/', '-')}",
                    title=title,
                    severity=severity,
                    category="dns",
                    description=description,
                    remediation=remediation,
                    engine="dns",
                    confidence="high" if detection_method in ("http_fingerprint", "nxdomain") else "medium",
                    cwe="CWE-284",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                        "https://github.com/EdOverflow/can-i-take-over-xyz",
                    ],
                    tags=["subdomain-takeover", "dangling-cname", service.lower().replace(" ", "-")],
                    details={
                        "domain": check_domain,
                        "cname_target": cname_target,
                        "service": service,
                        "detection_method": detection_method,
                        "evidence": evidence,
                        "http_status": http_status,
                        "vulnerable": True,
                    },
                    dedupe_fields={
                        "domain": check_domain,
                        "cname_target": cname_target,
                        "service": service,
                    },
                ))

            # ── NXDOMAIN but service claimability not confirmed ──
            elif detection_method == "nxdomain_unconfirmed":
                severity = "high"
                title = f"Dangling CNAME detected: {check_domain} → {cname_target}"
                description = (
                    f"The subdomain {check_domain} has a CNAME record pointing to "
                    f"{cname_target} ({service}), but the CNAME target does not resolve. "
                    f"This is a strong indicator that the service has been decommissioned "
                    f"without removing the DNS record. While we could not confirm "
                    f"claimability via HTTP fingerprinting, this is still a high-risk "
                    f"configuration that may allow subdomain takeover."
                )
                remediation = (
                    f"Remove the dangling CNAME record for {check_domain} → {cname_target} "
                    f"from your DNS configuration.\n\n"
                    f"The CNAME target no longer resolves, meaning the service it pointed to "
                    f"has been removed. Leaving this record creates a takeover risk if the "
                    f"resource name becomes available for registration on {service}."
                )

                drafts.append(FindingDraft(
                    template_id=f"takeover-dangling-cname-{service.lower().replace(' ', '-').replace('/', '-')}",
                    title=title,
                    severity=severity,
                    category="dns",
                    description=description,
                    remediation=remediation,
                    engine="dns",
                    confidence="medium",
                    cwe="CWE-284",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                    ],
                    tags=["subdomain-takeover", "dangling-cname", "nxdomain", service.lower().replace(" ", "-")],
                    details={
                        "domain": check_domain,
                        "cname_target": cname_target,
                        "service": service,
                        "detection_method": detection_method,
                        "evidence": evidence,
                        "vulnerable": False,
                        "nxdomain": True,
                    },
                    dedupe_fields={
                        "domain": check_domain,
                        "cname_target": cname_target,
                        "service": service,
                    },
                ))

            # ── HTTP error connecting to the domain (service may be flaky) ──
            elif detection_method == "http_error":
                severity = "medium"
                title = f"CNAME to {service} may be vulnerable: {check_domain}"
                description = (
                    f"The subdomain {check_domain} has a CNAME record pointing to "
                    f"{cname_target} ({service}). An HTTP check returned an error, "
                    f"which may indicate the service is misconfigured or partially "
                    f"decommissioned. This warrants manual investigation."
                )
                remediation = (
                    f"Investigate the CNAME record {check_domain} → {cname_target}.\n\n"
                    f"Verify that the resource on {service} is still active and properly "
                    f"configured. If the service has been decommissioned, remove the "
                    f"CNAME record to prevent potential subdomain takeover."
                )

                drafts.append(FindingDraft(
                    template_id=f"takeover-suspicious-{service.lower().replace(' ', '-').replace('/', '-')}",
                    title=title,
                    severity=severity,
                    category="dns",
                    description=description,
                    remediation=remediation,
                    engine="dns",
                    confidence="low",
                    cwe="CWE-284",
                    tags=["subdomain-takeover", "cname-check", service.lower().replace(" ", "-")],
                    details={
                        "domain": check_domain,
                        "cname_target": cname_target,
                        "service": service,
                        "detection_method": detection_method,
                        "evidence": evidence,
                        "http_status": http_status,
                        "vulnerable": False,
                    },
                    dedupe_fields={
                        "domain": check_domain,
                        "cname_target": cname_target,
                        "service": service,
                    },
                ))

        if drafts:
            logger.info(
                f"SubdomainTakeoverAnalyzer: {len(drafts)} finding(s) for {domain} — "
                f"{sum(1 for d in drafts if d.severity == 'critical')} critical, "
                f"{sum(1 for d in drafts if d.severity == 'high')} high, "
                f"{sum(1 for d in drafts if d.severity == 'medium')} medium"
            )

        return drafts