# app/scanner/analyzers/lookalike_analyzer.py
"""
LookalikeAnalyzer — converts verified_hits from the LookalikeEngine
into FindingDrafts on the parent root-domain asset.

Severity heuristic (see design spec
docs/superpowers/specs/2026-05-14-lookalike-domain-detection-design.md):

    HTTP 2xx/3xx + recent cert            → high
    DNS resolves + any cert seen          → medium
    DNS resolves, no HTTP or cert         → low
    Cert observed but no DNS              → low
    No DNS, no HTTP, no cert              → not emitted (engine drops these)

Findings are dedupe'd on (parent asset, variant domain) so the same
variant detected across weekly scans updates the existing Finding
rather than creating duplicates.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext


logger = logging.getLogger(__name__)


class LookalikeAnalyzer(BaseAnalyzer):
    """Turn verified lookalike hits into FindingDrafts."""

    @property
    def name(self) -> str:
        return "lookalike_analyzer"

    @property
    def required_engines(self) -> List[str]:
        return ["lookalike"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        engine_data = ctx.get_engine_data("lookalike")
        hits = engine_data.get("verified_hits") or []
        parent_domain = engine_data.get("parent_domain") or ctx.asset_value

        drafts: List[FindingDraft] = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            draft = _build_finding(parent_domain, hit)
            if draft is not None:
                drafts.append(draft)
        return drafts


def _classify_severity(hit: Dict[str, Any]) -> str:
    dns_a = hit.get("dns_a_records") or []
    http_80 = hit.get("http_80_status")
    http_443 = hit.get("http_443_status")
    cert_count = hit.get("cert_seen_count") or 0
    cert_first_seen = hit.get("cert_first_seen")

    has_live_http = (
        (isinstance(http_80, int) and 200 <= http_80 < 400)
        or (isinstance(http_443, int) and 200 <= http_443 < 400)
    )
    has_recent_cert = cert_count > 0 and cert_first_seen is not None
    has_dns = bool(dns_a)
    has_any_cert = cert_count > 0

    if has_live_http and has_recent_cert:
        return "high"
    if has_dns and has_any_cert:
        return "medium"
    if has_dns:
        return "low"
    if has_any_cert:
        return "low"
    return "info"


def _state_summary(hit: Dict[str, Any]) -> str:
    bits: List[str] = []
    dns_a = hit.get("dns_a_records") or []
    if dns_a:
        bits.append(
            f"resolves to {len(dns_a)} IP{'s' if len(dns_a) != 1 else ''}"
            f" ({', '.join(dns_a[:3])}{', …' if len(dns_a) > 3 else ''})"
        )
    http_80 = hit.get("http_80_status")
    http_443 = hit.get("http_443_status")
    if isinstance(http_443, int):
        bits.append(f"HTTPS responds {http_443}")
    elif isinstance(http_80, int):
        bits.append(f"HTTP responds {http_80}")
    cert_count = hit.get("cert_seen_count") or 0
    if cert_count > 0:
        bits.append(f"{cert_count} cert{'s' if cert_count != 1 else ''} observed in CT logs")
    if not bits:
        return "no live signals beyond registration"
    return "; ".join(bits)


def _build_finding(parent_domain: str, hit: Dict[str, Any]) -> FindingDraft | None:
    variant_domain = hit.get("variant_domain")
    family = hit.get("variant_family") or "unknown"
    if not variant_domain:
        return None

    severity = _classify_severity(hit)
    if severity == "info":
        # Belt-and-braces — engine should already drop these.
        return None

    state = _state_summary(hit)
    description = (
        f"{variant_domain} resembles {parent_domain} via the {family} variant family. "
        f"Currently {state}."
    )
    remediation = (
        "1. Look up the WHOIS / registrant for this domain to assess whether it is authorised. "
        "2. If unauthorised, file a domain-abuse complaint with the registrar. "
        "3. Consider a UDRP or trademark complaint if the variant is being used commercially. "
        "4. Report active phishing content to Google Safe Browsing or PhishTank."
    )

    dns_resolves = bool(hit.get("dns_a_records"))
    confidence = "high" if dns_resolves else "medium"

    return FindingDraft(
        template_id=f"lookalike-{variant_domain}",
        title=f"Lookalike domain: {variant_domain}",
        severity=severity,
        category="lookalike",
        description=description[:2000],
        remediation=remediation,
        finding_type="lookalike",
        references=[
            f"https://crt.sh/?q={variant_domain}",
            f"https://www.whois.com/whois/{variant_domain}",
        ],
        tags=["lookalike", family, severity, variant_domain.lower()],
        engine="lookalike",
        confidence=confidence,
        details={
            "variant_domain": variant_domain,
            "parent_domain": parent_domain,
            "variant_family": family,
            "dns_a_records": hit.get("dns_a_records") or [],
            "http_80_status": hit.get("http_80_status"),
            "http_443_status": hit.get("http_443_status"),
            "cert_seen_count": hit.get("cert_seen_count") or 0,
            "cert_first_seen": hit.get("cert_first_seen"),
        },
        dedupe_fields={"variant_domain": variant_domain},
    )
