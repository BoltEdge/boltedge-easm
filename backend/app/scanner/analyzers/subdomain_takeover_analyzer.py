# app/scanner/analyzers/subdomain_takeover.py
"""
Subdomain Takeover Analyzer.

Reads `subdomain_takeover_checks` from the DNS engine and produces
FindingDrafts whose copy comes from the curated registry in
app/scanner/templates.py.

Three tiers, by detection_method:
    confirmed       — fingerprint match or NXDOMAIN-claimable (severity: critical)
    dangling cname  — NXDOMAIN unconfirmed (severity: high)
    suspicious      — HTTP error connecting to the service (severity: medium)

Registry IDs we look up:
    takeover-confirmed-{service-slug}        e.g. takeover-confirmed-aws-s3-cloudfront
    takeover-dangling-cname-{service-slug}
    takeover-suspicious-{service-slug}

The registry's prefix-match falls back to `takeover-confirmed`,
`takeover-dangling-cname`, and `takeover-suspicious` (no service
suffix) when an exact per-service template isn't registered.

Required engine: dns
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext
from app.scanner.templates import FindingTemplate, get_template

logger = logging.getLogger(__name__)


def _slug(label: str) -> str:
    """Slugify a service label for use in a template_id.

    Mirrors the helper in port_risk.py — drops parenthetical detail,
    collapses non-alphanumeric runs to dashes, strips leading/trailing
    dashes. "AWS S3 / CloudFront" → "aws-s3-cloudfront".
    """
    s = label.lower()
    s = re.sub(r"\([^)]*\)", "", s)
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-") or "service"


def _render(text: Optional[str], **subs: Any) -> Optional[str]:
    """Replace {key} placeholders in template strings with runtime values.

    Uses str.replace rather than str.format so curly braces inside
    Markdown / code snippets in the template don't blow up when the
    placeholder dict doesn't cover every brace pair.
    """
    if not text:
        return text
    out = text
    for k, v in subs.items():
        if v is None or v == "":
            continue
        out = out.replace("{" + k + "}", str(v))
    return out


def _draft_from_template(
    template: FindingTemplate,
    *,
    template_id: str,
    fallback_severity: str,
    asset: str,
    cname_target: str,
    service: str,
    detection_method: str,
    evidence: str,
    http_status: Any,
    confidence: str,
    extra_tags: List[str],
    extra_details: Dict[str, Any],
) -> FindingDraft:
    """Build a FindingDraft by rendering the registered template's copy.

    Per-finding context (evidence, detection method, http status) is
    placed in details_json so the assistant's evidence section can
    surface it; it's not appended to the curated description.
    """
    title = _render(template.title, asset=asset, cname_target=cname_target, value=service)
    description = _render(template.description, asset=asset, cname_target=cname_target, value=service)
    remediation = _render(template.remediation, asset=asset, cname_target=cname_target, value=service)

    return FindingDraft(
        template_id=template_id,
        title=title or f"Subdomain takeover finding for {asset}",
        severity=template.severity or fallback_severity,
        category=template.category or "dns",
        description=description or "",
        remediation=remediation,
        engine="dns",
        confidence=confidence,
        cwe=template.cwe,
        references=list(template.references),
        tags=list(template.tags) + extra_tags,
        details={
            "domain": asset,
            "cname_target": cname_target,
            "service": service,
            "detection_method": detection_method,
            "evidence": evidence,
            "http_status": http_status,
            **extra_details,
        },
        dedupe_fields={
            "domain": asset,
            "cname_target": cname_target,
            "service": service,
        },
    )


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
            slug = _slug(service)

            # ── Confirmed vulnerable: fingerprint match or NXDOMAIN-claimable ──
            if vulnerable:
                template_id = f"takeover-confirmed-{slug}"
                template = get_template(template_id)
                if template is None:
                    # Defensive — generic "takeover-confirmed" should always
                    # match via prefix-fallback. If we somehow miss, skip
                    # rather than emit garbage.
                    logger.warning(
                        "No takeover-confirmed template resolved for service=%s slug=%s",
                        service, slug,
                    )
                    continue

                drafts.append(_draft_from_template(
                    template,
                    template_id=template_id,
                    fallback_severity="critical",
                    asset=check_domain,
                    cname_target=cname_target,
                    service=service,
                    detection_method=detection_method,
                    evidence=evidence,
                    http_status=http_status,
                    confidence=("high" if detection_method in ("http_fingerprint", "nxdomain")
                                else "medium"),
                    extra_tags=[],
                    extra_details={"vulnerable": True},
                ))

            # ── NXDOMAIN but service claimability not confirmed ──
            elif detection_method == "nxdomain_unconfirmed":
                template_id = f"takeover-dangling-cname-{slug}"
                template = get_template(template_id)
                if template is None:
                    logger.warning(
                        "No takeover-dangling-cname template resolved for service=%s slug=%s",
                        service, slug,
                    )
                    continue

                drafts.append(_draft_from_template(
                    template,
                    template_id=template_id,
                    fallback_severity="high",
                    asset=check_domain,
                    cname_target=cname_target,
                    service=service,
                    detection_method=detection_method,
                    evidence=evidence,
                    http_status=http_status,
                    confidence="medium",
                    extra_tags=["nxdomain"],
                    extra_details={"vulnerable": False, "nxdomain": True},
                ))

            # ── HTTP error connecting to the domain (service may be flaky) ──
            elif detection_method == "http_error":
                template_id = f"takeover-suspicious-{slug}"
                template = get_template(template_id)
                if template is None:
                    logger.warning(
                        "No takeover-suspicious template resolved for service=%s slug=%s",
                        service, slug,
                    )
                    continue

                drafts.append(_draft_from_template(
                    template,
                    template_id=template_id,
                    fallback_severity="medium",
                    asset=check_domain,
                    cname_target=cname_target,
                    service=service,
                    detection_method=detection_method,
                    evidence=evidence,
                    http_status=http_status,
                    confidence="low",
                    extra_tags=["cname-check"],
                    extra_details={"vulnerable": False},
                ))

        if drafts:
            logger.info(
                "SubdomainTakeoverAnalyzer: %d finding(s) for %s — %d critical, %d high, %d medium",
                len(drafts), domain,
                sum(1 for d in drafts if d.severity == "critical"),
                sum(1 for d in drafts if d.severity == "high"),
                sum(1 for d in drafts if d.severity == "medium"),
            )

        return drafts
