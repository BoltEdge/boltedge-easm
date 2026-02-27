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

from dataclasses import dataclass, field
from typing import Dict, List, Optional


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

    @property
    def effective_tuning_key(self) -> str:
        return self.tuning_key or self.template_id


# ═══════════════════════════════════════════════════════════════════════════
# REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

_TEMPLATES: Dict[str, FindingTemplate] = {}


def _r(tmpl: FindingTemplate) -> FindingTemplate:
    """Register a template."""
    _TEMPLATES[tmpl.template_id] = tmpl
    return tmpl


# ───────────────────────────────────────────────────────────────────────────
# DNS / Email Security
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="dns-no-spf",
    title="No SPF record for {asset}",
    description=(
        "No SPF (Sender Policy Framework) record was found for {asset}. "
        "Without SPF, anyone can send email pretending to be from your "
        "domain, enabling phishing attacks and damaging email reputation."
    ),
    remediation=(
        'Add an SPF TXT record to your DNS. A basic record: '
        '"v=spf1 include:_spf.google.com -all" (adjust for your provider). '
        "Use -all (hardfail) to reject unauthorized senders."
    ),
    severity="high",
    category="dns",
    cwe="CWE-290",
    tags=["dns", "email", "spf"],
    summary="Your domain has no SPF record, so anyone can send emails pretending to be you.",
    alert_name="SPF Record Missing",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="dns-spf-plus-all",
    title="SPF record allows all senders (+all) for {asset}",
    description=(
        "The SPF record for {asset} ends with '+all', which means "
        "ANY server is authorized to send email as your domain. "
        "This completely defeats the purpose of SPF."
    ),
    remediation=(
        "Change +all to -all (hardfail) or ~all (softfail) in your SPF record."
    ),
    severity="high",
    category="dns",
    cwe="CWE-290",
    tags=["dns", "email", "spf", "misconfigured"],
    summary="Your SPF record allows anyone to send email as your domain — it's wide open.",
    alert_name="SPF Allows All Senders",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="dns-spf-softfail",
    title="SPF uses softfail (~all) for {asset}",
    description=(
        "The SPF record for {asset} uses ~all (softfail). Unauthorized emails "
        "are marked suspicious but not rejected. Use -all for stronger protection."
    ),
    remediation=(
        "Change ~all to -all once you've verified all legitimate email sources "
        "are included in the SPF record."
    ),
    severity="medium",
    category="dns",
    tags=["dns", "email", "spf"],
    summary="Your SPF record flags unauthorized emails but doesn't block them.",
    alert_name="SPF Softfail Only",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="dns-spf-neutral",
    title="SPF uses neutral (?all) for {asset}",
    description=(
        "The SPF record for {asset} uses ?all (neutral). This provides "
        "no protection — unauthorized emails are neither accepted nor rejected."
    ),
    remediation="Change ?all to -all (hardfail) for proper email protection.",
    severity="medium",
    category="dns",
    tags=["dns", "email", "spf"],
    summary="Your SPF record is set to neutral, which provides no email protection at all.",
    alert_name="SPF Neutral Policy",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="dns-spf-too-many-lookups",
    title="SPF record may exceed 10-lookup limit for {asset}",
    description=(
        "The SPF record for {asset} contains too many DNS lookups. "
        "SPF has a hard limit of 10 DNS lookups. Exceeding this causes "
        "a permerror and SPF fails entirely."
    ),
    remediation=(
        "Reduce SPF lookups by flattening includes or using ip4:/ip6: "
        "mechanisms. SPF flattening tools can automate this."
    ),
    severity="low",
    category="dns",
    tags=["dns", "email", "spf"],
    summary="Your SPF record has too many lookups and may break email authentication.",
    alert_name="SPF Lookup Limit Exceeded",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="dns-no-dmarc",
    title="No DMARC record for {asset}",
    description=(
        "No DMARC record was found for {asset}. DMARC tells receiving servers "
        "what to do when SPF/DKIM checks fail. Without it, there's no "
        "enforcement policy for email authentication."
    ),
    remediation=(
        'Add a DMARC TXT record at _dmarc.{asset}. Start with: '
        '"v=DMARC1; p=none; rua=mailto:dmarc-reports@{asset}" '
        "to collect reports, then move to p=quarantine or p=reject."
    ),
    severity="high",
    category="dns",
    cwe="CWE-290",
    tags=["dns", "email", "dmarc"],
    summary="Your domain has no DMARC record, leaving email authentication unenforced.",
    alert_name="DMARC Record Missing",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="dns-dmarc-none",
    title="DMARC policy is 'none' (monitoring only) for {asset}",
    description=(
        "The DMARC policy for {asset} is set to 'none'. Failed emails are "
        "delivered normally — DMARC is only collecting reports but not enforcing."
    ),
    remediation=(
        "After reviewing DMARC reports, upgrade to p=quarantine or p=reject "
        "to actively block spoofed emails."
    ),
    severity="high",
    category="dns",
    tags=["dns", "email", "dmarc"],
    summary="DMARC is in monitor-only mode — spoofed emails still get delivered.",
    alert_name="DMARC Not Enforcing",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="dns-dmarc-no-rua",
    title="DMARC record has no reporting address (rua) for {asset}",
    description=(
        "The DMARC record for {asset} has no rua (reporting) address. "
        "Without it, you won't receive reports about email auth failures."
    ),
    remediation="Add rua=mailto:dmarc-reports@{asset} to your DMARC record.",
    severity="medium",
    category="dns",
    tags=["dns", "email", "dmarc"],
    summary="You're not receiving DMARC reports because no reporting address is set.",
    alert_name="DMARC No Reporting",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="dns-no-dkim",
    title="No DKIM records found for {asset}",
    description=(
        "No DKIM (DomainKeys Identified Mail) records were found for common "
        "selectors on {asset}. DKIM adds a digital signature to outgoing emails, "
        "proving they haven't been tampered with."
    ),
    remediation=(
        "Configure DKIM signing for your email provider. Most providers "
        "(Google Workspace, Microsoft 365) have setup guides for DKIM DNS records."
    ),
    severity="low",
    category="dns",
    tags=["dns", "email", "dkim"],
    summary="No DKIM email signing was found, so recipients can't verify your emails are genuine.",
    alert_name="DKIM Not Configured",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="dns-zone-transfer-open",
    title="DNS zone transfer (AXFR) successful for {asset}",
    description=(
        "A DNS zone transfer was completed, exposing all DNS records including "
        "subdomains, IP addresses, and internal hostnames. This gives attackers "
        "a detailed map of the infrastructure."
    ),
    remediation=(
        "Restrict zone transfers (AXFR) to authorized secondary nameservers only. "
        "In BIND: allow-transfer { trusted-servers; };"
    ),
    severity="critical",
    category="dns",
    cwe="CWE-200",
    tags=["dns", "zone-transfer", "critical"],
    summary="Your entire DNS zone is publicly downloadable, exposing your full infrastructure map.",
    alert_name="Zone Transfer Exposed",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="dns-single-nameserver",
    title="Only one nameserver for {asset}",
    description=(
        "Only one nameserver was found for {asset}. If it goes down, "
        "the domain becomes completely unresolvable."
    ),
    remediation="Add at least one additional nameserver for redundancy.",
    severity="medium",
    category="dns",
    tags=["dns", "nameserver", "redundancy"],
    summary="Your domain relies on a single nameserver — if it fails, your site goes offline.",
    alert_name="Single Nameserver",
    monitor_type="dns_change",
))

_r(FindingTemplate(
    template_id="dns-no-ipv6",
    title="No IPv6 (AAAA) records for {asset}",
    description=(
        "No AAAA records were found for {asset}. IPv6 adoption is growing "
        "and some networks are IPv6-only."
    ),
    remediation="Add AAAA records pointing to IPv6 addresses if your hosting supports it.",
    severity="low",
    category="dns",
    tags=["dns", "ipv6"],
    summary="Your domain isn't reachable over IPv6, which a growing number of networks use.",
    alert_name="No IPv6 Support",
    monitor_type="dns_change",
))

# ───────────────────────────────────────────────────────────────────────────
# SSL / TLS
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="ssl-cert-expired",
    title="SSL certificate expired on {asset}:{port}",
    description=(
        "The SSL/TLS certificate has expired. Visitors will see browser "
        "security warnings and may be unable to connect."
    ),
    remediation=(
        "Renew the SSL certificate immediately. If using Let's Encrypt, "
        "check that auto-renewal is configured."
    ),
    severity="critical",
    category="ssl",
    cwe="CWE-295",
    tags=["ssl", "certificate", "expired"],
    summary="Your SSL certificate has expired — visitors see security warnings and can't connect safely.",
    alert_name="SSL Certificate Expired",
    monitor_type="cert_expiry",
))

_r(FindingTemplate(
    template_id="ssl-cert-expiring-7d",
    title="SSL certificate expires in {value} days on {asset}:{port}",
    description="The SSL certificate expires within 7 days. Renew urgently to avoid disruption.",
    remediation="Renew the SSL certificate within the next few days. Set up automated renewal.",
    severity="high",
    category="ssl",
    cwe="CWE-298",
    tags=["ssl", "certificate", "expiring"],
    summary="Your SSL certificate expires in less than a week — renew it now to avoid downtime.",
    alert_name="SSL Certificate Expiring Soon",
    monitor_type="cert_expiry",
))

_r(FindingTemplate(
    template_id="ssl-cert-expiring-30d",
    title="SSL certificate expires in {value} days on {asset}:{port}",
    description="The SSL certificate expires within 30 days. Plan renewal soon.",
    remediation="Schedule certificate renewal. Consider Let's Encrypt with automatic renewal.",
    severity="medium",
    category="ssl",
    tags=["ssl", "certificate", "expiring"],
    summary="Your SSL certificate expires within a month — plan to renew it soon.",
    alert_name="SSL Certificate Expiring",
    monitor_type="cert_expiry",
))

_r(FindingTemplate(
    template_id="ssl-cert-expiring-90d",
    title="SSL certificate expires in {value} days on {asset}:{port}",
    description="The SSL certificate expires within 90 days. Not urgent but worth planning.",
    remediation="Ensure automated renewal is configured. Add a reminder 30 days before expiry.",
    severity="low",
    category="ssl",
    tags=["ssl", "certificate"],
    summary="Your SSL certificate expires within 3 months — a good time to set up auto-renewal.",
    alert_name="SSL Certificate Expiry Notice",
    monitor_type="cert_expiry",
))

_r(FindingTemplate(
    template_id="ssl-self-signed",
    title="Self-signed SSL certificate on {asset}:{port}",
    description=(
        "The SSL certificate is self-signed. Browsers will show a security warning "
        "and users cannot verify the server's identity."
    ),
    remediation=(
        "Replace with a certificate from a trusted CA. Let's Encrypt provides free, "
        "trusted certificates."
    ),
    severity="high",
    category="ssl",
    cwe="CWE-295",
    tags=["ssl", "certificate", "self-signed"],
    summary="Your site uses a self-signed certificate — browsers will warn visitors it's not trusted.",
    alert_name="Self-Signed Certificate",
    monitor_type="cert_change",
))

_r(FindingTemplate(
    template_id="ssl-hostname-mismatch",
    title="SSL certificate hostname mismatch on {asset}:{port}",
    description=(
        "The SSL certificate does not match the target hostname. "
        "Browsers will show a security warning."
    ),
    remediation="Reissue the SSL certificate to include the correct hostname as CN or SAN.",
    severity="high",
    category="ssl",
    cwe="CWE-297",
    tags=["ssl", "certificate", "hostname"],
    summary="Your SSL certificate was issued for a different domain — browsers show a mismatch warning.",
    alert_name="SSL Hostname Mismatch",
    monitor_type="cert_change",
))

_r(FindingTemplate(
    template_id="ssl-cert-info",
    title="SSL certificate on {asset}:{port}: {value}",
    description="SSL/TLS certificate details for the endpoint.",
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
    description="Could not establish an SSL/TLS connection. The port may not serve HTTPS.",
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
        "TLS 1.0 is enabled. It was deprecated in 2020 due to known vulnerabilities "
        "including BEAST and POODLE. PCI DSS prohibits TLS 1.0."
    ),
    remediation="Disable TLS 1.0. Only support TLS 1.2 and TLS 1.3.",
    severity="high",
    category="ssl",
    cwe="CWE-326",
    tags=["ssl", "protocol", "tls1.0", "deprecated"],
    summary="Your server still supports TLS 1.0, which has known security vulnerabilities.",
    alert_name="TLS 1.0 Enabled",
    monitor_type="cert_change",
))

_r(FindingTemplate(
    template_id="ssl-tls11-enabled",
    title="TLS 1.1 enabled on {asset}",
    description="TLS 1.1 is enabled. It was deprecated in 2021 and lacks modern security features.",
    remediation="Disable TLS 1.1. Support only TLS 1.2 and TLS 1.3.",
    severity="medium",
    category="ssl",
    cwe="CWE-326",
    tags=["ssl", "protocol", "tls1.1", "deprecated"],
    summary="Your server supports TLS 1.1, which is outdated and being dropped by browsers.",
    alert_name="TLS 1.1 Enabled",
    monitor_type="cert_change",
))

_r(FindingTemplate(
    template_id="ssl-no-tls12",
    title="TLS 1.2 not supported on {asset}",
    description="TLS 1.2 is not supported. Some older clients may not support TLS 1.3 yet.",
    remediation="Enable TLS 1.2 alongside TLS 1.3 for broader compatibility.",
    severity="info",
    category="ssl",
    tags=["ssl", "protocol"],
    summary="Your server doesn't support TLS 1.2, which some older clients still need.",
    alert_name="TLS 1.2 Not Supported",
    monitor_type="cert_change",
))

_r(FindingTemplate(
    template_id="ssl-no-tls13",
    title="TLS 1.3 not supported on {asset}",
    description="TLS 1.3 is not supported. It provides improved security and faster handshakes.",
    remediation="Enable TLS 1.3. Requires OpenSSL 1.1.1+ or equivalent.",
    severity="low",
    category="ssl",
    tags=["ssl", "protocol", "tls1.3"],
    summary="Your server doesn't support TLS 1.3, the latest and most secure protocol version.",
    alert_name="TLS 1.3 Not Supported",
    monitor_type="cert_change",
))

_r(FindingTemplate(
    template_id="ssl-only-deprecated-protocols",
    title="Only deprecated TLS versions supported on {asset}",
    description=(
        "Only TLS 1.0 and/or 1.1 are supported. Modern browsers will refuse to connect."
    ),
    remediation="Enable TLS 1.2 and TLS 1.3 urgently. Disable TLS 1.0 and 1.1.",
    severity="high",
    category="ssl",
    cwe="CWE-326",
    tags=["ssl", "protocol", "critical"],
    summary="Your server only supports outdated encryption — modern browsers can't connect at all.",
    alert_name="Only Deprecated TLS",
    monitor_type="cert_change",
))

# ───────────────────────────────────────────────────────────────────────────
# HTTP Security Headers
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="header-missing-strict_transport_security",
    title="Missing Strict-Transport-Security header on {asset}:{port}",
    description=(
        "The HSTS header is missing. Without it, users can be downgraded "
        "from HTTPS to HTTP via man-in-the-middle attacks."
    ),
    remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    severity="medium",
    category="headers",
    cwe="CWE-319",
    tags=["headers", "security", "strict-transport-security"],
    summary="Your site doesn't force browsers to always use HTTPS, allowing downgrade attacks.",
    alert_name="HSTS Missing",
    monitor_type="header_change",
))

_r(FindingTemplate(
    template_id="header-missing-content_security_policy",
    title="Missing Content-Security-Policy header on {asset}:{port}",
    description=(
        "CSP is missing. It prevents XSS and data injection by controlling "
        "which resources the browser can load."
    ),
    remediation="Add a Content-Security-Policy header. Start with report-only mode to identify issues.",
    severity="medium",
    category="headers",
    cwe="CWE-79",
    tags=["headers", "security", "content-security-policy"],
    summary="Your site has no Content Security Policy, leaving it more vulnerable to XSS attacks.",
    alert_name="CSP Missing",
    monitor_type="header_change",
))

_r(FindingTemplate(
    template_id="header-missing-x_frame_options",
    title="Missing X-Frame-Options header on {asset}:{port}",
    description=(
        "X-Frame-Options is missing. The page can be embedded in iframes "
        "on other sites, enabling clickjacking attacks."
    ),
    remediation="Add: X-Frame-Options: DENY (or SAMEORIGIN). CSP frame-ancestors is the modern replacement.",
    severity="high",
    category="headers",
    cwe="CWE-1021",
    tags=["headers", "security", "x-frame-options"],
    summary="Your site can be embedded in malicious iframes, enabling clickjacking attacks.",
    alert_name="X-Frame-Options Missing",
    monitor_type="header_change",
))

_r(FindingTemplate(
    template_id="header-missing-x_content_type_options",
    title="Missing X-Content-Type-Options header on {asset}:{port}",
    description=(
        "Without this header, browsers may MIME-sniff responses, potentially "
        "treating non-script files as scripts."
    ),
    remediation="Add: X-Content-Type-Options: nosniff",
    severity="medium",
    category="headers",
    cwe="CWE-16",
    tags=["headers", "security", "x-content-type-options"],
    summary="Browsers may misinterpret file types on your site, which could enable script injection.",
    alert_name="X-Content-Type-Options Missing",
    monitor_type="header_change",
))

_r(FindingTemplate(
    template_id="header-missing-referrer_policy",
    title="Missing Referrer-Policy header on {asset}:{port}",
    description=(
        "By default, browsers send the full URL as the Referer header, "
        "potentially leaking sensitive data in query parameters."
    ),
    remediation="Add: Referrer-Policy: strict-origin-when-cross-origin",
    severity="medium",
    category="headers",
    tags=["headers", "security", "referrer-policy"],
    summary="Your site leaks full page URLs to third parties when users click links.",
    alert_name="Referrer-Policy Missing",
    monitor_type="header_change",
))

_r(FindingTemplate(
    template_id="header-missing-permissions_policy",
    title="Missing Permissions-Policy header on {asset}:{port}",
    description=(
        "Permissions-Policy controls which browser features (camera, microphone, "
        "geolocation) can be used by the page and embedded content."
    ),
    remediation="Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    severity="medium",
    category="headers",
    tags=["headers", "security", "permissions-policy"],
    summary="Your site doesn't restrict browser features like camera and mic access for embedded content.",
    alert_name="Permissions-Policy Missing",
    monitor_type="header_change",
))

_r(FindingTemplate(
    template_id="header-server-version-leak",
    title="Server header exposes version: {value}",
    description=(
        "The Server header reveals software and version information, "
        "helping attackers identify known vulnerabilities."
    ),
    remediation="Remove or minimize the Server header. nginx: server_tokens off; Apache: ServerTokens Prod",
    severity="high",
    category="headers",
    cwe="CWE-200",
    tags=["headers", "information-disclosure", "server"],
    summary="Your web server is advertising its exact software version, making it easier to attack.",
    alert_name="Server Version Exposed",
    monitor_type="header_change",
))

_r(FindingTemplate(
    template_id="header-powered-by-leak",
    title="X-Powered-By header exposes technology: {value}",
    description=(
        "The X-Powered-By header reveals the technology stack, which can be "
        "used to find version-specific vulnerabilities."
    ),
    remediation="Remove X-Powered-By. PHP: expose_php=Off. Express: app.disable('x-powered-by').",
    severity="low",
    category="headers",
    cwe="CWE-200",
    tags=["headers", "information-disclosure"],
    summary="Your site reveals what technology it runs on, giving attackers a head start.",
    alert_name="Technology Stack Exposed",
    monitor_type="header_change",
))

_r(FindingTemplate(
    template_id="http-no-https-redirect",
    title="HTTP does not redirect to HTTPS on {asset}",
    description=(
        "HTTP traffic is not redirected to HTTPS. Users who type the URL "
        "without 'https://' use an unencrypted connection."
    ),
    remediation="Configure your web server to redirect all HTTP to HTTPS (301 redirect).",
    severity="high",
    category="headers",
    cwe="CWE-319",
    tags=["http", "redirect", "https"],
    summary="Visitors who don't type 'https://' get an unencrypted, insecure connection.",
    alert_name="No HTTPS Redirect",
    monitor_type="header_change",
))

# ───────────────────────────────────────────────────────────────────────────
# Cookie Security
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="cookie-missing-secure",
    title="Cookie '{value}' missing Secure flag",
    description="The cookie can be sent over unencrypted HTTP, exposing it to network sniffing.",
    remediation="Set the Secure flag on this cookie.",
    severity="medium",
    category="headers",
    cwe="CWE-614",
    tags=["cookie", "secure"],
    summary="A cookie on your site can be stolen by anyone on the same network.",
    alert_name="Insecure Cookie",
    monitor_type="header_change",
))

_r(FindingTemplate(
    template_id="cookie-missing-httponly",
    title="Cookie '{value}' missing HttpOnly flag",
    description="The cookie can be read by client-side JavaScript, making it vulnerable to XSS theft.",
    remediation="Set the HttpOnly flag on this cookie.",
    severity="medium",
    category="headers",
    cwe="CWE-1004",
    tags=["cookie", "httponly"],
    summary="A cookie on your site can be stolen through JavaScript injection attacks.",
    alert_name="Cookie Missing HttpOnly",
    monitor_type="header_change",
))

_r(FindingTemplate(
    template_id="cookie-missing-samesite",
    title="Cookie '{value}' missing SameSite attribute",
    description="Without SameSite, the cookie is sent with cross-site requests, enabling CSRF attacks.",
    remediation="Set SameSite=Lax or SameSite=Strict on this cookie.",
    severity="medium",
    category="headers",
    cwe="CWE-1275",
    tags=["cookie", "samesite"],
    summary="A cookie on your site is sent with cross-site requests, which could enable forgery attacks.",
    alert_name="Cookie Missing SameSite",
    monitor_type="header_change",
))

# ───────────────────────────────────────────────────────────────────────────
# Ports / Services (common entries — port_risk generates dynamic template IDs)
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="port-rdp-(remote-desktop)-exposed",
    title="RDP (Remote Desktop) exposed on {asset}:{port}",
    description="RDP is a top target for brute-force and ransomware. Multiple critical RDP vulnerabilities exist.",
    remediation="Block port 3389 from the internet. Use VPN or SSH tunnel for remote access.",
    severity="critical",
    category="ports",
    tags=["port", "rdp", "remote_access"],
    summary="Remote Desktop is open to the internet — this is a primary ransomware entry point.",
    alert_name="RDP Exposed",
    monitor_type="port_change",
))

_r(FindingTemplate(
    template_id="port-docker-api-(unencrypted)-exposed",
    title="Docker API (unencrypted) exposed on {asset}:{port}",
    description="Docker daemon API without TLS gives any attacker full control — equivalent to root access.",
    remediation="Block port 2375 immediately. Use port 2376 with TLS or SSH.",
    severity="critical",
    category="ports",
    tags=["port", "docker", "container"],
    summary="Your Docker API is wide open to the internet — anyone can take full control of your server.",
    alert_name="Docker API Exposed",
    monitor_type="port_change",
))

_r(FindingTemplate(
    template_id="port-mysql-exposed",
    title="MySQL exposed on {asset}:{port}",
    description="MySQL database port is exposed, allowing brute-force login attempts and data extraction.",
    remediation="Block port 3306 from the internet. Bind MySQL to 127.0.0.1.",
    severity="critical",
    category="ports",
    tags=["port", "mysql", "database"],
    summary="Your MySQL database is directly accessible from the internet.",
    alert_name="MySQL Exposed",
    monitor_type="port_change",
))

_r(FindingTemplate(
    template_id="port-redis-exposed",
    title="Redis exposed on {asset}:{port}",
    description="Redis has no authentication by default. Exposed instances are routinely compromised.",
    remediation="Block port 6379. Bind Redis to 127.0.0.1. Enable AUTH.",
    severity="critical",
    category="ports",
    tags=["port", "redis", "database"],
    summary="Your Redis cache is open to the internet — attackers can read all your data or take over the server.",
    alert_name="Redis Exposed",
    monitor_type="port_change",
))

_r(FindingTemplate(
    template_id="port-mongodb-exposed",
    title="MongoDB exposed on {asset}:{port}",
    description="MongoDB exposed to the internet. Older versions had no authentication by default.",
    remediation="Block port 27017. Enable auth in mongod.conf. Bind to 127.0.0.1.",
    severity="critical",
    category="ports",
    tags=["port", "mongodb", "database"],
    summary="Your MongoDB database is accessible from the internet.",
    alert_name="MongoDB Exposed",
    monitor_type="port_change",
))

_r(FindingTemplate(
    template_id="port-elasticsearch-exposed",
    title="Elasticsearch exposed on {asset}:{port}",
    description="Elasticsearch has no built-in auth in the open-source version. Routinely scraped by bots.",
    remediation="Block port 9200. Use X-Pack security or a reverse proxy with auth.",
    severity="critical",
    category="ports",
    tags=["port", "elasticsearch", "database"],
    summary="Your Elasticsearch instance is open to the internet — bots routinely scrape exposed instances.",
    alert_name="Elasticsearch Exposed",
    monitor_type="port_change",
))

_r(FindingTemplate(
    template_id="port-telnet-exposed",
    title="Telnet exposed on {asset}:{port}",
    description="Telnet transmits all data including credentials in plaintext.",
    remediation="Disable Telnet. Use SSH instead.",
    severity="high",
    category="ports",
    tags=["port", "telnet", "unencrypted"],
    summary="Telnet is running on your server — all logins and data are sent in plaintext.",
    alert_name="Telnet Exposed",
    monitor_type="port_change",
))

_r(FindingTemplate(
    template_id="port-ftp-exposed",
    title="FTP exposed on {asset}:{port}",
    description="FTP transmits credentials and data in plaintext. Anonymous access may be enabled.",
    remediation="Replace FTP with SFTP or FTPS. Disable anonymous access.",
    severity="high",
    category="ports",
    tags=["port", "ftp", "unencrypted"],
    summary="FTP is running on your server — login credentials are sent without encryption.",
    alert_name="FTP Exposed",
    monitor_type="port_change",
))

_r(FindingTemplate(
    template_id="port-smb-exposed",
    title="SMB exposed on {asset}:{port}",
    description="SMB has a long history of critical vulnerabilities (EternalBlue/WannaCry).",
    remediation="Block port 445 from the internet. Use VPN for remote file access.",
    severity="high",
    category="ports",
    tags=["port", "smb", "file_sharing"],
    summary="Windows file sharing (SMB) is exposed — this is how WannaCry ransomware spread.",
    alert_name="SMB Exposed",
    monitor_type="port_change",
))

# Generic port templates (for dynamic generation)
_r(FindingTemplate(
    template_id="port-generic-open",
    title="Open port {port}/{value} on {asset}",
    description="An open port was detected. Review whether this service needs to be internet-facing.",
    remediation="Verify the port needs to be publicly accessible. Close unnecessary ports.",
    severity="info",
    category="ports",
    tags=["port", "exposure"],
    summary="An open port was found on your server.",
    alert_name="New Port Detected",
    monitor_type="port_change",
))

# ───────────────────────────────────────────────────────────────────────────
# CVE / Vulnerabilities
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="cve-generic",
    title="Known vulnerability: {value}",
    description="A known CVE was detected on this host. It may allow unauthorized access or data exposure.",
    remediation="Research the CVE and apply the vendor's patch or update.",
    severity="high",
    category="cve",
    tags=["cve"],
    summary="A known security vulnerability was found on your server.",
    alert_name="CVE Detected",
    monitor_type="vuln_change",
))

# ───────────────────────────────────────────────────────────────────────────
# Technology Detection
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="tech-detected",
    title="Technology detected: {value}",
    description="A technology was identified running on the target.",
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
    title="Outdated {value} on {asset}",
    description="This software version is end-of-life and no longer receives security patches.",
    remediation="Update to the latest supported version. Test in staging first.",
    severity="medium",
    category="technology",
    cwe="CWE-1104",
    tags=["technology", "outdated"],
    summary="You're running end-of-life software that no longer gets security updates.",
    alert_name="End-of-Life Software",
    monitor_type="tech_change",
))

# ───────────────────────────────────────────────────────────────────────────
# Exposure Score
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="exposure-score",
    title="Exposure Score: {value}/100 (Grade {asset})",
    description="Overall security exposure score based on all findings.",
    severity="info",
    category="exposure",
    tags=["exposure", "score"],
    tunable=False,
    summary="Your overall security exposure score based on all scan findings.",
    alert_name="Exposure Score Updated",
    monitor_type="exposure_change",
))

# ───────────────────────────────────────────────────────────────────────────
# Monitoring / Change Detection (future — placeholders)
# ───────────────────────────────────────────────────────────────────────────

_r(FindingTemplate(
    template_id="monitor-new-port",
    title="New port {port} detected on {asset}",
    description="A port that was not previously open has been detected.",
    remediation="Verify whether this new service is authorized and properly secured.",
    severity="medium",
    category="ports",
    tags=["monitoring", "port", "change"],
    summary="A new port just opened on your server that wasn't there before.",
    alert_name="New Port Opened",
    monitor_type="port_change",
))

_r(FindingTemplate(
    template_id="monitor-port-closed",
    title="Port {port} closed on {asset}",
    description="A previously open port is no longer responding.",
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
    description="A new service or software was detected on an existing port.",
    remediation="Verify the new service is authorized and properly configured.",
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
    description="The SSL certificate has been replaced with a different one.",
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
    description="A DNS record was added, removed, or modified.",
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
    description="A security header was added, removed, or modified.",
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
    description="Software that has reached end-of-life was detected during monitoring.",
    remediation="Plan an upgrade to a supported version as soon as possible.",
    severity="high",
    category="technology",
    tags=["monitoring", "technology", "eol"],
    summary="We detected end-of-life software on your server that no longer gets security patches.",
    alert_name="EOL Software Detected",
    monitor_type="tech_change",
))

_r(FindingTemplate(
    template_id="monitor-new-subdomain",
    title="New subdomain discovered: {value}",
    description="A subdomain was discovered that was not previously known.",
    remediation="Verify this subdomain is authorized and properly secured.",
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
    description="The SPF record was modified. Verify the changes are authorized.",
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
    description="The DMARC record was modified. Verify the changes are authorized.",
    severity="medium",
    category="dns",
    tags=["monitoring", "dns", "dmarc", "change"],
    summary="Your DMARC email security record was just changed.",
    alert_name="DMARC Record Changed",
    monitor_type="dns_change",
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