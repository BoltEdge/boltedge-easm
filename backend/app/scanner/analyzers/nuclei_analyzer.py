# app/scanner/analyzers/nuclei_analyzer.py
"""
Nuclei Findings Analyzer.

Converts Nuclei engine output into FindingDrafts whose copy comes from
the curated FindingTemplate registry where available, with a generic
wrapper (`nuclei-uncategorized`) handling templates we haven't
specifically curated.

Two rendering paths:
    - Curated:        Nuclei template_id matches a registered template
                      (exact or prefix). Use the registered template's
                      title / description / remediation / severity / CWE
                      / references / summary verbatim, with placeholder
                      substitution.
    - Uncategorized:  Falls through to nuclei-uncategorized. Use the
                      wrapper's framing copy but interpolate Nuclei's
                      own runtime metadata (template_name, description,
                      remediation, references, CVE/CVSS).

Required engine: nuclei
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext
from app.scanner.templates import FindingTemplate, get_template

logger = logging.getLogger(__name__)


# Nuclei tag → our finding category mapping. The registered template's
# category wins for curated findings; this map is consulted only when
# rendering uncategorized findings.
TAG_TO_CATEGORY = {
    "cve": "cve",
    "rce": "cve",
    "sqli": "cve",
    "xss": "cve",
    "lfi": "cve",
    "ssrf": "cve",
    "misconfig": "misconfiguration",
    "misconfiguration": "misconfiguration",
    "exposure": "exposure",
    "default-login": "misconfiguration",
    "default-credentials": "misconfiguration",
    "panel": "exposure",
    "tech": "technology",
    "technology": "technology",
    "ssl": "ssl",
    "tls": "ssl",
    "dns": "dns",
    "file": "exposure",
    "token": "exposure",
    "takeover": "exposure",
    "redirect": "misconfiguration",
    "cors": "headers",
    "headers": "headers",
}


def _render(text: Optional[str], **subs: Any) -> Optional[str]:
    """Replace {key} placeholders with runtime values via str.replace.

    Uses replace rather than format so curly braces in Markdown / code
    snippets in template copy don't blow up when a placeholder dict
    doesn't cover every brace pair.
    """
    if not text:
        return text
    out = text
    for k, v in subs.items():
        if v is None or v == "":
            continue
        out = out.replace("{" + k + "}", str(v))
    return out


class NucleiAnalyzer(BaseAnalyzer):
    """Convert Nuclei scan results into FindingDrafts.

    Nuclei provides rich template metadata (severity, description,
    remediation, CVE/CWE IDs, references). When we have a curated
    template registered for the matched Nuclei ID, we use the curated
    copy; otherwise we wrap Nuclei's own metadata in our generic
    template.
    """

    @property
    def name(self) -> str:
        return "nuclei_analyzer"

    @property
    def required_engines(self) -> List[str]:
        return ["nuclei"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []
        nuclei_data = ctx.get_engine_data("nuclei") or {}

        findings = nuclei_data.get("findings", [])
        if not findings:
            return drafts

        seen: set = set()  # dedupe by (template_id, matched_at)
        for finding in findings:
            template_id = finding.get("template_id", "unknown")
            matched_at = finding.get("matched_at", "")
            key = (template_id, matched_at)
            if key in seen:
                continue
            seen.add(key)

            drafts.append(self._build_finding(finding, ctx))

        if drafts:
            curated = sum(1 for d in drafts if d.details
                          and d.details.get("rendering") == "curated")
            uncategorized = len(drafts) - curated
            logger.info(
                "NucleiAnalyzer: %d finding(s) for %s — %d curated, %d uncategorized",
                len(drafts), ctx.asset_value, curated, uncategorized,
            )
        return drafts

    # ─── Routing ──────────────────────────────────────────────────────────

    def _build_finding(self, finding: Dict[str, Any], ctx: ScanContext) -> FindingDraft:
        nuclei_template_id = finding.get("template_id", "unknown")
        our_template_id = f"nuclei-{nuclei_template_id}"

        # Look up in registry — prefix matching resolves
        # `nuclei-cve-2021-44228-apache-log4j-rce` to the curated short
        # form `nuclei-cve-2021-44228`, and unknown IDs fall through to
        # `nuclei-uncategorized` via the FALLBACK_MAP entry we added.
        template = get_template(our_template_id)
        is_curated = (
            template is not None
            and template.template_id != "nuclei-uncategorized"
        )

        if is_curated:
            return self._render_curated(template, our_template_id, finding, ctx)
        return self._render_uncategorized(template, our_template_id, finding, ctx)

    # ─── Curated path: registered template wins ───────────────────────────

    def _render_curated(
        self,
        template: FindingTemplate,
        our_template_id: str,
        finding: Dict[str, Any],
        ctx: ScanContext,
    ) -> FindingDraft:
        """Use the registered template's curated copy verbatim."""
        asset = ctx.asset_value
        matched_at = finding.get("matched_at", "")
        # Template name from Nuclei is sometimes more descriptive than
        # the ID — used as {value} for templates that include it.
        template_name = finding.get("template_name") or finding.get("template_id") or ""

        title = _render(template.title, asset=asset, value=template_name, url=matched_at)
        description = _render(template.description, asset=asset, value=template_name, url=matched_at)
        remediation = _render(template.remediation, asset=asset, value=template_name, url=matched_at)

        # Pull CVE / CVSS from Nuclei's classification; useful in the
        # evidence section even when not in the rendered copy.
        classification = finding.get("classification") or {}
        cve_id = classification.get("cve_id")
        cvss_score = classification.get("cvss_score")

        # Severity: prefer registered template (we calibrated). For CVE-
        # specific findings, escalate to Nuclei's severity if it's higher
        # (e.g., a CVE that's been bumped to critical post-disclosure).
        severity = template.severity or finding.get("severity") or "medium"
        nuclei_severity = (finding.get("severity") or "").lower()
        if (cve_id and nuclei_severity == "critical"
                and severity not in ("critical",)):
            severity = "critical"

        # References: registered + Nuclei's own. Dedupe and cap.
        references = list(template.references or [])
        for r in finding.get("reference") or []:
            if r and r not in references:
                references.append(r)
        if cve_id:
            nvd = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            if nvd not in references:
                references.append(nvd)
        references = references[:10]

        return FindingDraft(
            template_id=our_template_id,
            title=(title or f"{cve_id or template_name} on {asset}")[:255],
            severity=severity,
            category=template.category or "vulnerability",
            description=(description or "")[:2000],
            remediation=(remediation or None) if remediation else None,
            finding_type="nuclei_cve" if cve_id else "nuclei_finding",
            cwe=template.cwe or classification.get("cwe_id"),
            references=references,
            tags=list(template.tags) + ["nuclei"] + (finding.get("tags") or [])[:8],
            engine="nuclei",
            confidence="high",
            details={
                "rendering": "curated",
                "nuclei_template_id": finding.get("template_id"),
                "nuclei_template_name": template_name,
                "matched_at": matched_at,
                "host": finding.get("host", ""),
                "type": finding.get("type", ""),
                "matcher_name": finding.get("matcher_name", ""),
                "extracted_results": (finding.get("extracted_results") or [])[:10],
                "cve": cve_id,
                "cvss_score": cvss_score,
                "curl_command": (finding.get("curl_command") or "")[:500],
            },
            dedupe_fields={
                "template_id": finding.get("template_id"),
                "matched_at": matched_at,
            },
        )

    # ─── Uncategorized path: Nuclei's metadata fills the wrapper ──────────

    def _render_uncategorized(
        self,
        template: Optional[FindingTemplate],
        our_template_id: str,
        finding: Dict[str, Any],
        ctx: ScanContext,
    ) -> FindingDraft:
        """Fall through to the generic wrapper, interpolating Nuclei's
        runtime data into the framing copy. Severity, references, and
        CVE/CVSS come from Nuclei; the wrapper only provides the
        intro/outro framing so the finding still reads as a polished
        Nano EASM finding rather than raw upstream output.
        """
        asset = ctx.asset_value
        nuclei_template_id = finding.get("template_id", "unknown")
        template_name = finding.get("template_name") or nuclei_template_id
        matched_at = finding.get("matched_at", "")
        nuclei_description = (finding.get("description") or "").strip()
        nuclei_remediation = (finding.get("remediation") or "").strip()

        classification = finding.get("classification") or {}
        cve_id = classification.get("cve_id")
        cwe_id = classification.get("cwe_id")
        cvss_score = classification.get("cvss_score")

        severity = (finding.get("severity") or "info").lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "info"

        # Title — name-led, fall back to ID for unnamed templates.
        if cve_id:
            title = f"{cve_id}: {template_name} on {asset}"
        else:
            title = f"Nuclei: {template_name} on {asset}"
        if matched_at and matched_at != asset:
            short_url = matched_at if len(matched_at) <= 60 else matched_at[:57] + "..."
            title = f"{title} (matched {short_url})"

        # Description — combine wrapper framing with Nuclei's own copy.
        # The wrapper's first paragraph reads as Nano EASM context; the
        # second paragraph is whatever Nuclei provided. If Nuclei's
        # description is empty, just include the wrapper.
        wrapper_description = (
            f"Nuclei matched a template ({nuclei_template_id}) against "
            f"{asset}. We don't ship a curated explanation for this "
            f"specific template — the upstream Nuclei metadata below "
            f"describes the issue and recommends a fix. Severity, "
            f"matched URL, and any CVE/CWE classification come from "
            f"Nuclei's own template definition."
        )
        if nuclei_description:
            description = wrapper_description + "\n\n**From Nuclei:**\n" + nuclei_description
        else:
            description = wrapper_description
        if cvss_score:
            description += f"\n\n_CVSS Score: {cvss_score}._"

        # Remediation — prefer Nuclei's; fall back to a CVE-aware default
        # or the wrapper's generic guidance.
        if nuclei_remediation:
            remediation = nuclei_remediation
        elif cve_id:
            remediation = (
                f"Apply the vendor patch for {cve_id}. "
                f"See https://nvd.nist.gov/vuln/detail/{cve_id} for "
                f"affected versions and the official advisory."
            )
        elif template and template.remediation:
            remediation = _render(
                template.remediation, asset=asset, value=template_name,
            )
        else:
            remediation = None

        # References — Nuclei's plus NVD when we have a CVE.
        references: List[str] = list((finding.get("reference") or []))
        if cve_id:
            nvd = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            if nvd not in references:
                references.append(nvd)
        if template and template.references:
            for r in template.references:
                if r and r not in references:
                    references.append(r)
        references = references[:10]

        # Category — Nuclei's tags drive routing here since we don't
        # have a curated category to fall back on.
        category = self._determine_category(finding.get("tags") or [])

        return FindingDraft(
            template_id=our_template_id,
            title=title[:255],
            severity=severity,
            category=category,
            description=description[:2000],
            remediation=(remediation or None),
            finding_type="nuclei_cve" if cve_id else "nuclei_finding",
            cwe=cwe_id,
            references=references,
            tags=["nuclei", "uncategorized"] + (finding.get("tags") or [])[:8],
            engine="nuclei",
            confidence="high",
            details={
                "rendering": "uncategorized",
                "nuclei_template_id": nuclei_template_id,
                "nuclei_template_name": template_name,
                "matched_at": matched_at,
                "host": finding.get("host", ""),
                "type": finding.get("type", ""),
                "matcher_name": finding.get("matcher_name", ""),
                "extracted_results": (finding.get("extracted_results") or [])[:10],
                "cve": cve_id,
                "cvss_score": cvss_score,
                "curl_command": (finding.get("curl_command") or "")[:500],
            },
            dedupe_fields={
                "template_id": nuclei_template_id,
                "matched_at": matched_at,
            },
        )

    # ─── Helpers ──────────────────────────────────────────────────────────

    def _determine_category(self, tags: List[str]) -> str:
        """Map Nuclei tags to our finding category."""
        for tag in tags or []:
            tag_lower = tag.lower()
            if tag_lower in TAG_TO_CATEGORY:
                return TAG_TO_CATEGORY[tag_lower]
        return "vulnerability"
