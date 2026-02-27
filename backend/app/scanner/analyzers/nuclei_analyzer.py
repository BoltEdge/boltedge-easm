# app/scanner/analyzers/nuclei_analyzer.py
"""
Nuclei Findings Analyzer.

Reads template match results from the Nuclei engine and converts them
into enriched FindingDrafts.

Nuclei already classifies severity, so this analyzer primarily:
    1. Normalizes Nuclei's output into our FindingDraft format
    2. Enriches findings with CVE/CWE references
    3. Adds remediation guidance from Nuclei's template metadata
    4. Deduplicates by template_id + matched URL
    5. Maps Nuclei tags to our finding categories
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext

logger = logging.getLogger(__name__)

# Map Nuclei tags to our finding categories
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


class NucleiAnalyzer(BaseAnalyzer):
    """
    Converts Nuclei scan results into FindingDrafts.

    Nuclei provides rich template metadata including severity,
    description, remediation, CVE/CWE IDs, and references.
    This analyzer maps that into our standard FindingDraft format.
    """

    @property
    def name(self) -> str:
        return "nuclei_analyzer"

    @property
    def required_engines(self) -> List[str]:
        return ["nuclei"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []
        nuclei_data = ctx.get_engine_data("nuclei")

        findings = nuclei_data.get("findings", [])
        if not findings:
            return drafts

        # Deduplicate by (template_id, matched_at)
        seen: set = set()

        for finding in findings:
            template_id = finding.get("template_id", "unknown")
            matched_at = finding.get("matched_at", "")

            dedup_key = (template_id, matched_at)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            drafts.append(self._build_finding(finding, ctx))

        return drafts

    def _build_finding(
        self, finding: Dict[str, Any], ctx: ScanContext
    ) -> FindingDraft:
        """Convert a single Nuclei finding into a FindingDraft."""
        template_id = finding.get("template_id", "unknown")
        template_name = finding.get("template_name", "Unknown")
        severity = finding.get("severity", "info")
        matched_at = finding.get("matched_at", ctx.asset_value)

        # Classification
        classification = finding.get("classification", {})
        cve_id = classification.get("cve_id")
        cwe_id = classification.get("cwe_id")
        cvss_score = classification.get("cvss_score")

        # Build title
        title = f"Nuclei: {template_name}"
        if cve_id:
            title = f"{cve_id}: {template_name}"
        if matched_at and matched_at != ctx.asset_value:
            # Shorten URL for title
            short_url = matched_at
            if len(short_url) > 60:
                short_url = short_url[:57] + "..."
            title += f" at {short_url}"

        # Description
        description = finding.get("description", "")
        if not description:
            description = (
                f"Nuclei template '{template_id}' matched on {ctx.asset_value}. "
                f"Matched at: {matched_at}."
            )
        if cvss_score:
            description += f" CVSS Score: {cvss_score}."

        # Remediation
        remediation = finding.get("remediation", "")
        if not remediation and cve_id:
            remediation = (
                f"Apply the vendor patch for {cve_id}. "
                f"See https://nvd.nist.gov/vuln/detail/{cve_id} for details."
            )

        # References
        references = finding.get("reference", [])
        if cve_id and f"https://nvd.nist.gov/vuln/detail/{cve_id}" not in references:
            references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")

        # Category from tags
        tags = finding.get("tags", [])
        category = self._determine_category(tags)

        # Finding type
        finding_type = "nuclei_cve" if cve_id else "nuclei_finding"

        return FindingDraft(
            template_id=f"nuclei-{template_id}",
            title=title[:255],
            severity=severity,
            category=category,
            description=description[:2000],
            remediation=remediation[:1000] if remediation else None,
            finding_type=finding_type,
            cwe=cwe_id,
            references=references[:10],
            tags=["nuclei"] + tags[:10],
            engine="nuclei",
            confidence="high",  # Nuclei template matches are high confidence
            details={
                "nuclei_template_id": template_id,
                "nuclei_template_name": template_name,
                "matched_at": matched_at,
                "host": finding.get("host", ""),
                "type": finding.get("type", ""),
                "matcher_name": finding.get("matcher_name", ""),
                "extracted_results": finding.get("extracted_results", [])[:10],
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "curl_command": finding.get("curl_command", "")[:500],
            },
            dedupe_fields={
                "template_id": template_id,
                "matched_at": matched_at,
            },
        )

    def _determine_category(self, tags: List[str]) -> str:
        """Map Nuclei tags to our finding category."""
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in TAG_TO_CATEGORY:
                return TAG_TO_CATEGORY[tag_lower]

        # Default to "vulnerability" for unrecognized tags
        return "vulnerability"