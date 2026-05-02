"""Finding explainer.

Builds the 5-section "Nano AI Explanation" payload from a Finding row.

Source of truth is the FindingTemplate registry in app/scanner/templates.py
— each template already carries a `description`, `remediation`, and `summary`
that an analyst (or Claude!) wrote when the template was authored. We just
fill in the {asset} / {port} / {value} placeholders with the live finding
data, render evidence from whitelisted details_json keys, and emit a
client-friendly variant.

When a finding has no matching template_id (legacy or analyzer fallback),
a category-level generic explanation is used.

Nothing here calls out to an LLM. Phase 1 is deterministic on purpose —
templates can't hallucinate CVEs or fabricate remediation steps.
"""
from __future__ import annotations

import re
from typing import Any

try:
    from app.scanner.templates import _TEMPLATES, FindingTemplate
except ImportError:  # pragma: no cover - defensive
    _TEMPLATES = {}
    FindingTemplate = None  # type: ignore


# ---------------------------------------------------------------------------
# Placeholder rendering
# ---------------------------------------------------------------------------

def _render(text: str | None, **subs: Any) -> str | None:
    """Fill {asset}, {port}, {value} style placeholders. Missing keys
    leave the placeholder text in place rather than crashing — better
    to show "{port}" once than to 500 the request."""
    if not text:
        return text
    out = text
    for key, val in subs.items():
        if val is None or val == "":
            continue
        out = out.replace("{" + key + "}", str(val))
    return out


# ---------------------------------------------------------------------------
# Evidence — pulled from a whitelist of keys in details_json
# ---------------------------------------------------------------------------

# Keys that are safe to surface in the evidence section. Anything not in
# this list is silently dropped — keeps internal/secret fields out of the
# user-facing UI even if an analyzer accidentally writes one in.
_SAFE_EVIDENCE_KEYS = (
    "ip",
    "port",
    "transport",
    "protocol",
    "service",
    "service_label",
    "product",
    "version",
    "banner",
    "hostname",
    "header_name",
    "header_value",
    "cve",
    "cvss",
    "tls_version",
    "cipher",
    "subject",
    "issuer",
    "not_before",
    "not_after",
    "days_until_expiry",
    "record",
    "selector",
    "policy",
    "subdomain_policy",
    "qualifier",
    "lookup_count",
    "url",
    "path",
    "status_code",
    "method",
    "matched_pattern",
    "tech",
    "technology",
)

# Keys that should be aggressively truncated even when whitelisted
_LONG_KEYS = {"banner", "record", "header_value", "matched_pattern"}


def _evidence_lines(finding) -> list[str]:
    """Render details_json into a flat list of human-friendly evidence lines."""
    details = finding.details_json or {}
    if not isinstance(details, dict):
        return []

    lines: list[str] = []

    # Headline evidence: where it was seen
    asset_value = finding.asset.value if finding.asset else None
    ip = details.get("ip")
    port = details.get("port")
    transport = (details.get("transport") or "tcp").lower()

    if ip and port:
        lines.append(f"Host: {ip}, port {port}/{transport}")
    elif ip:
        lines.append(f"Host: {ip}")
    elif asset_value:
        lines.append(f"Host: {asset_value}")

    # Service / product / version
    product = details.get("product")
    version = details.get("version")
    service = details.get("service") or details.get("service_label")
    if service or product or version:
        bits = []
        if service:
            bits.append(str(service))
        if product:
            bits.append(str(product))
        if version:
            bits.append(f"v{version}")
        lines.append("Service: " + " · ".join(bits))

    # CVE info
    cve = details.get("cve")
    if cve:
        cvss = details.get("cvss")
        lines.append(f"CVE: {cve}" + (f" (CVSS {cvss})" if cvss else ""))

    # TLS info
    tls_version = details.get("tls_version")
    cipher = details.get("cipher")
    if tls_version or cipher:
        bits = []
        if tls_version:
            bits.append(str(tls_version))
        if cipher:
            bits.append(str(cipher))
        lines.append("TLS: " + " · ".join(bits))

    # Cert dates
    not_after = details.get("not_after")
    if not_after:
        days = details.get("days_until_expiry")
        suffix = f" ({days} days remaining)" if days is not None else ""
        lines.append(f"Certificate expires: {not_after}{suffix}")

    # DNS records
    record = details.get("record")
    if record:
        truncated = str(record)[:200]
        lines.append(f"Record: {truncated}")

    # HTTP path / status
    path = details.get("path")
    status_code = details.get("status_code")
    if path:
        lines.append(f"Path: {path}" + (f" → HTTP {status_code}" if status_code else ""))

    # Matched pattern
    pattern = details.get("matched_pattern")
    if pattern:
        lines.append(f"Matched: {str(pattern)[:120]}")

    # Banner — last because it's noisy
    banner = details.get("banner")
    if banner:
        lines.append(f"Banner: {str(banner)[:160]}")

    # Sighting timestamps
    if finding.first_seen_at and finding.last_seen_at:
        if finding.first_seen_at == finding.last_seen_at:
            lines.append(f"Seen: {finding.first_seen_at.strftime('%Y-%m-%d %H:%M UTC')}")
        else:
            lines.append(
                f"First seen: {finding.first_seen_at.strftime('%Y-%m-%d')} · "
                f"Last seen: {finding.last_seen_at.strftime('%Y-%m-%d')}"
            )

    return lines


# ---------------------------------------------------------------------------
# Generic per-category fallback for findings without a template_id
# ---------------------------------------------------------------------------

_CATEGORY_FALLBACK = {
    "ssl": {
        "summary": "An SSL/TLS configuration issue was detected on this asset.",
        "technical": (
            "SSL/TLS issues weaken the encrypted channel between the server and its clients. "
            "Depending on the specific defect (weak cipher, expired certificate, hostname "
            "mismatch, etc.), an attacker may be able to intercept, downgrade, or impersonate "
            "the connection."
        ),
        "remediation": (
            "Update the server's TLS configuration to require TLS 1.2 or 1.3 with modern "
            "cipher suites. Renew or reissue the certificate if it's expired, self-signed, "
            "or scoped to the wrong hostname. Test with online scanners or `openssl s_client`."
        ),
        "client": "An issue with the website's encryption was detected. The server team should update the certificate or encryption settings.",
    },
    "ports": {
        "summary": "An exposed network service was detected on this asset.",
        "technical": (
            "Exposing services to the public internet expands the attack surface. Even when "
            "the service is patched, brute-force, exploitation, or misconfiguration risks "
            "remain. Services intended only for internal use should not be reachable from "
            "the open internet."
        ),
        "remediation": (
            "Confirm whether the exposed port is required publicly. If not, restrict access "
            "via firewall, security group, or VPN. If it must be exposed, ensure strong "
            "authentication, current patches, and monitoring."
        ),
        "client": "A network service is open to the internet that probably shouldn't be. The infrastructure team should check whether it needs to be public.",
    },
    "headers": {
        "summary": "A missing or misconfigured HTTP security header was detected.",
        "technical": (
            "HTTP security headers tell browsers how to safely render and load your site. "
            "Missing headers (HSTS, CSP, X-Frame-Options, etc.) leave users exposed to "
            "downgrade, clickjacking, MIME-sniffing, or cross-site scripting attacks that "
            "could otherwise be blocked by the browser."
        ),
        "remediation": (
            "Add the missing header(s) at the web server / CDN / application layer. Start "
            "with HSTS and X-Content-Type-Options as easy wins; CSP needs more careful "
            "tuning to avoid breaking legitimate scripts."
        ),
        "client": "A web security header is missing. The web team should add it — it's a one-line config change in most cases.",
    },
    "dns": {
        "summary": "A DNS or email-authentication issue was detected on this domain.",
        "technical": (
            "DNS-based controls (SPF, DKIM, DMARC, DNSSEC) protect your domain from being "
            "spoofed in phishing campaigns and from DNS-layer tampering. Missing or weak "
            "records make impersonation easier and damage email deliverability."
        ),
        "remediation": (
            "Add or fix the relevant DNS record. For email, publish SPF, DKIM, and DMARC. "
            "For zone integrity, enable DNSSEC. Roll changes carefully — test with online "
            "tools (mxtoolbox, Google Postmaster) before tightening enforcement."
        ),
        "client": "A DNS configuration issue was found. The email/DNS administrator should publish or update the affected record.",
    },
    "cve": {
        "summary": "A known software vulnerability (CVE) was detected on this asset.",
        "technical": (
            "The detected service version matches a published CVE. Depending on the CVE's "
            "severity, an attacker may be able to crash, compromise, or steal data from the "
            "service. Public exploit code often becomes available within days."
        ),
        "remediation": (
            "Patch to a fixed version or disable the affected feature. If patching is "
            "blocked, mitigate via firewall rules, WAF signatures, or network segmentation "
            "until an upgrade is feasible."
        ),
        "client": "The asset is running a software version with a known security flaw. The platform team should patch or upgrade it.",
    },
    "tech": {
        "summary": "A technology fingerprint was detected on this asset.",
        "technical": (
            "Detected technology fingerprints are not vulnerabilities by themselves but "
            "they help attackers tailor exploitation attempts. Outdated or end-of-life "
            "components are particularly worth investigating."
        ),
        "remediation": (
            "Confirm the component is intended to be public, on a supported version, and "
            "configured correctly. Suppress this finding if the disclosure is acceptable "
            "for your threat model."
        ),
        "client": "A specific technology was detected. It's not necessarily a problem, but worth verifying it's the right version.",
    },
    "exposure": {
        "summary": "An exposure-scoring or surface-related finding was detected.",
        "technical": (
            "This finding contributes to the asset's overall exposure score. Reducing the "
            "external attack surface — fewer exposed services, tighter auth, current "
            "components — is the most reliable way to lower long-term risk."
        ),
        "remediation": (
            "Review the exposure detail, decide whether the exposure is required, and "
            "either reduce/restrict it or accept the risk explicitly via the tuning UI."
        ),
        "client": "An exposure-related issue was found that contributes to your overall risk score. Worth a review.",
    },
    "api": {
        "summary": "A potentially sensitive API endpoint or interface was exposed.",
        "technical": (
            "Endpoints like /actuator, /swagger, /graphql, /.git, /.env can leak internal "
            "configuration, source code, environment variables, or admin functionality. "
            "Discovery of such endpoints is often the first step in a real intrusion."
        ),
        "remediation": (
            "Confirm whether the endpoint should be reachable from the internet. If not, "
            "remove it, restrict access, or move it behind authentication. If it's a "
            "framework default (Spring Actuator, etc.), follow the framework's lockdown "
            "guide."
        ),
        "client": "A developer-facing endpoint is exposed publicly. The dev team should restrict access.",
    },
    "cloud": {
        "summary": "A cloud-resource exposure was detected.",
        "technical": (
            "Cloud storage buckets, container registries, serverless functions, and CDN "
            "origins can leak data when their access policies are too permissive or when "
            "they're directly reachable without authentication."
        ),
        "remediation": (
            "Audit the resource's access policy. Make buckets private by default, scope "
            "registry pulls to authenticated principals, and protect serverless URLs "
            "behind an authenticator or API gateway."
        ),
        "client": "A cloud resource appears to be exposed publicly. The cloud/devops team should review its access controls.",
    },
    "misconfiguration": {
        "summary": "A configuration issue was detected on this asset.",
        "technical": (
            "Configuration drift, defaults left in place, or overly permissive settings "
            "frequently lead to real incidents even when no software vulnerability exists."
        ),
        "remediation": "Review the specific configuration noted in the evidence and apply your hardening baseline.",
        "client": "A configuration issue was detected. Your platform team should review and tighten the relevant setting.",
    },
}


# ---------------------------------------------------------------------------
# Client-friendly summary fallback
# ---------------------------------------------------------------------------

def _client_summary(template, finding) -> str:
    """If the template has a `summary` (we wrote it as plain English already),
    use that. Otherwise derive one from the title without jargon."""
    if template and template.summary:
        return template.summary

    title = finding.title or "Security finding"
    # Strip placeholder leftovers
    title = re.sub(r"\{[a-z]+\}", "", title).strip()
    return f"{title}. Worth reviewing with the team responsible for the affected asset."


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def explain_finding(finding) -> dict:
    """
    Build the 5-section explanation payload for a Finding row.

    Returns a dict matching the API contract:
        {
          "summary":              str,
          "technicalExplanation": str,
          "evidence":             str   (multi-line, '\\n'-joined),
          "remediation":          str,
          "clientSummary":        str,
        }
    """
    template_id = finding.template_id or ""
    template = _TEMPLATES.get(template_id) if _TEMPLATES else None

    asset_value = finding.asset.value if finding.asset else "this asset"
    details = finding.details_json or {}
    placeholders = {
        "asset": asset_value,
        "port": details.get("port") if isinstance(details, dict) else None,
        "value": details.get("value") if isinstance(details, dict) else None,
    }

    # ── Summary (one-liner) ──────────────────────────────────────────────
    if template and template.summary:
        summary = _render(template.summary, **placeholders)
    elif template and template.description:
        # First sentence of description as a fallback
        summary = (_render(template.description, **placeholders) or "").split(". ")[0].rstrip(".") + "."
    else:
        cat = (finding.category or "").lower()
        summary = _CATEGORY_FALLBACK.get(cat, _CATEGORY_FALLBACK["misconfiguration"])["summary"]

    # ── Technical explanation ────────────────────────────────────────────
    if template and template.description:
        technical = _render(template.description, **placeholders) or ""
    else:
        cat = (finding.category or "").lower()
        technical = _CATEGORY_FALLBACK.get(cat, _CATEGORY_FALLBACK["misconfiguration"])["technical"]

    # Append references when available — security teams trust authoritative sources.
    if template:
        if template.cwe:
            technical = f"{technical}\n\nClassification: {template.cwe}"
        if template.references:
            refs = "\n".join(f"  • {r}" for r in template.references[:5])
            technical = f"{technical}\n\nReferences:\n{refs}"

    # ── Evidence ─────────────────────────────────────────────────────────
    evidence_lines = _evidence_lines(finding)
    if evidence_lines:
        evidence = "\n".join(f"• {line}" for line in evidence_lines)
    else:
        evidence = "No structured evidence was captured for this finding beyond its title and description."

    # ── Remediation ──────────────────────────────────────────────────────
    if template and template.remediation:
        remediation = _render(template.remediation, **placeholders) or ""
    else:
        cat = (finding.category or "").lower()
        remediation = _CATEGORY_FALLBACK.get(cat, _CATEGORY_FALLBACK["misconfiguration"])["remediation"]

    # If there's an analyst-curated remediation override on the finding, prefer it.
    override = None
    if isinstance(details, dict):
        override = details.get("_remediation") or details.get("remediation")
    if override and isinstance(override, str):
        remediation = override.strip()

    # ── Client-friendly summary ──────────────────────────────────────────
    if template and template.summary:
        client_summary = _render(template.summary, **placeholders) or ""
    else:
        cat = (finding.category or "").lower()
        client_summary = _CATEGORY_FALLBACK.get(cat, _CATEGORY_FALLBACK["misconfiguration"])["client"]

    return {
        "summary": (summary or "").strip(),
        "technicalExplanation": (technical or "").strip(),
        "evidence": evidence.strip(),
        "remediation": (remediation or "").strip(),
        "clientSummary": (client_summary or "").strip(),
    }
