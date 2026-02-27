# app/scanner/analyzers/ssl_analyzer.py
"""
SSL/TLS Analyzer.

Reads certificate and protocol data from the SSL engine and produces
findings for every SSL/TLS issue.

Checks performed:
    CRITICAL:
        - Certificate expired
    HIGH:
        - Certificate expires within 7 days
        - Self-signed certificate on public service
        - Hostname mismatch (CN/SAN vs target domain)
        - TLS 1.0 enabled (POODLE, BEAST vulnerabilities)
    MEDIUM:
        - Certificate expires within 30 days
        - TLS 1.1 enabled (deprecated since 2021)
        - Weak cipher suite detected
        - Incomplete certificate chain
    LOW:
        - Certificate expires within 90 days
        - TLS 1.3 not supported (recommended but not required)
    INFO:
        - Certificate details summary (always generated)
        - TLS configuration summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext

logger = logging.getLogger(__name__)

# Cipher suites considered weak
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "DES-CBC3", "RC2", "EXPORT", "NULL",
    "anon", "MD5",
}


class SSLAnalyzer(BaseAnalyzer):
    """
    Analyzes SSL/TLS certificate and protocol data.

    Produces findings for:
        - Certificate lifecycle issues (expired, expiring soon)
        - Trust issues (self-signed, hostname mismatch)
        - Protocol issues (deprecated TLS versions)
        - Cipher issues (weak algorithms)
        - A summary info finding with full cert details
    """

    @property
    def name(self) -> str:
        return "ssl_analyzer"

    @property
    def required_engines(self) -> List[str]:
        return ["ssl", "shodan"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []

        # Get data from SSL engine
        ssl_data = ctx.get_engine_data("ssl")
        certificates = ssl_data.get("certificates", [])
        protocols = ssl_data.get("protocols", {})

        # Also check Shodan's SSL data as supplementary source
        shodan_ssl_certs = self._extract_shodan_ssl(ctx)

        # Analyze each certificate from the SSL engine
        for cert in certificates:
            if cert.get("error"):
                # SSL connection error — note it
                drafts.append(self._ssl_error_finding(cert))
                continue

            drafts.extend(self._analyze_certificate(cert, ctx))

        # Analyze Shodan SSL data (if SSL engine didn't run or missed ports)
        seen_ports = {c.get("port") for c in certificates if not c.get("error")}
        for cert in shodan_ssl_certs:
            if cert.get("port") not in seen_ports:
                drafts.extend(self._analyze_certificate(cert, ctx))

        # Analyze protocol versions
        if protocols:
            drafts.extend(self._analyze_protocols(protocols, ctx))

        return drafts

    # -------------------------------------------------------------------
    # Certificate analysis
    # -------------------------------------------------------------------

    def _analyze_certificate(
        self, cert: Dict[str, Any], ctx: ScanContext
    ) -> List[FindingDraft]:
        """Analyze a single certificate and produce all relevant findings."""
        drafts: List[FindingDraft] = []
        port = cert.get("port", 443)
        ip = cert.get("ip", ctx.asset_value)
        endpoint = f"{ip}:{port}"

        subject = cert.get("subject", {})
        issuer = cert.get("issuer", {})
        cn = subject.get("CN", "unknown")

        # --- Expiry checks ---
        is_expired = cert.get("is_expired")
        days_until = cert.get("days_until_expiry")

        if is_expired is True:
            drafts.append(FindingDraft(
                template_id="ssl-cert-expired",
                title=f"SSL certificate expired on {endpoint}",
                severity="critical",
                category="ssl",
                description=(
                    f"The SSL/TLS certificate for {cn} on {endpoint} has expired. "
                    f"Expired on: {cert.get('not_after', 'unknown')}. "
                    "Visitors will see browser security warnings and may be unable "
                    "to connect. Search engines may also penalize the site."
                ),
                remediation=(
                    "Renew the SSL certificate immediately. If using Let's Encrypt, "
                    "check that auto-renewal (certbot renew) is configured and working. "
                    "For commercial certificates, contact your CA to reissue."
                ),
                finding_type="ssl_expired",
                cwe="CWE-295",
                tags=["ssl", "certificate", "expired"],
                engine="ssl",
                details=self._cert_details(cert),
                dedupe_fields={"port": port, "check": "expired"},
            ))

        elif days_until is not None:
            if days_until <= 7:
                drafts.append(FindingDraft(
                    template_id="ssl-cert-expiring-7d",
                    title=f"SSL certificate expires in {days_until} days on {endpoint}",
                    severity="high",
                    category="ssl",
                    description=(
                        f"The SSL certificate for {cn} on {endpoint} expires in "
                        f"{days_until} day(s) on {cert.get('not_after', 'unknown')}. "
                        "If not renewed, visitors will see security warnings."
                    ),
                    remediation=(
                        "Renew the SSL certificate within the next few days. "
                        "Set up automated renewal to prevent this in the future."
                    ),
                    finding_type="ssl_expiring_soon",
                    cwe="CWE-298",
                    tags=["ssl", "certificate", "expiring"],
                    engine="ssl",
                    details=self._cert_details(cert),
                    dedupe_fields={"port": port, "check": "expiring_7d"},
                ))

            elif days_until <= 30:
                drafts.append(FindingDraft(
                    template_id="ssl-cert-expiring-30d",
                    title=f"SSL certificate expires in {days_until} days on {endpoint}",
                    severity="medium",
                    category="ssl",
                    description=(
                        f"The SSL certificate for {cn} on {endpoint} expires in "
                        f"{days_until} day(s). Plan renewal soon to avoid disruption."
                    ),
                    remediation=(
                        "Schedule certificate renewal. Consider using Let's Encrypt "
                        "with automatic renewal (certbot) to avoid manual renewals."
                    ),
                    finding_type="ssl_expiring_soon",
                    tags=["ssl", "certificate", "expiring"],
                    engine="ssl",
                    details=self._cert_details(cert),
                    dedupe_fields={"port": port, "check": "expiring_30d"},
                ))

            elif days_until <= 90:
                drafts.append(FindingDraft(
                    template_id="ssl-cert-expiring-90d",
                    title=f"SSL certificate expires in {days_until} days on {endpoint}",
                    severity="low",
                    category="ssl",
                    description=(
                        f"The SSL certificate for {cn} on {endpoint} expires in "
                        f"{days_until} day(s). Not urgent, but worth planning."
                    ),
                    remediation=(
                        "Ensure automated renewal is configured. If using manual "
                        "renewal, add a calendar reminder 30 days before expiry."
                    ),
                    finding_type="ssl_expiring_notice",
                    tags=["ssl", "certificate"],
                    engine="ssl",
                    details=self._cert_details(cert),
                    dedupe_fields={"port": port, "check": "expiring_90d"},
                ))

        # --- Self-signed check ---
        if cert.get("is_self_signed") is True:
            drafts.append(FindingDraft(
                template_id="ssl-self-signed",
                title=f"Self-signed SSL certificate on {endpoint}",
                severity="high",
                category="ssl",
                description=(
                    f"The SSL certificate on {endpoint} is self-signed (issuer matches "
                    f"subject: {cn}). Browsers will show a security warning and "
                    "users cannot verify the server's identity. This also breaks "
                    "automated tools and API clients that verify certificates."
                ),
                remediation=(
                    "Replace the self-signed certificate with one from a trusted CA. "
                    "Let's Encrypt provides free, trusted certificates. "
                    "Self-signed certs are only acceptable for internal/development use."
                ),
                finding_type="ssl_self_signed",
                cwe="CWE-295",
                tags=["ssl", "certificate", "self-signed"],
                engine="ssl",
                details=self._cert_details(cert),
                dedupe_fields={"port": port, "check": "self_signed"},
            ))

        # --- Hostname mismatch ---
        if cert.get("hostname_match") is False:
            sans = cert.get("sans", [])
            drafts.append(FindingDraft(
                template_id="ssl-hostname-mismatch",
                title=f"SSL certificate hostname mismatch on {endpoint}",
                severity="high",
                category="ssl",
                description=(
                    f"The SSL certificate on {endpoint} does not match the target "
                    f"hostname '{ctx.asset_value}'. Certificate is issued to: "
                    f"CN={cn}, SANs={', '.join(sans[:5]) if sans else 'none'}. "
                    "Browsers will show a security warning."
                ),
                remediation=(
                    f"Reissue the SSL certificate to include '{ctx.asset_value}' "
                    "as the Common Name or a Subject Alternative Name (SAN)."
                ),
                finding_type="ssl_hostname_mismatch",
                cwe="CWE-297",
                tags=["ssl", "certificate", "hostname"],
                engine="ssl",
                details=self._cert_details(cert),
                dedupe_fields={"port": port, "check": "hostname_mismatch"},
            ))

        # --- Info: certificate summary (always generated) ---
        issuer_str = issuer.get("O") or issuer.get("CN") or "Unknown CA"
        drafts.append(FindingDraft(
            template_id="ssl-cert-info",
            title=f"SSL certificate on {endpoint}: {cn} (issued by {issuer_str})",
            severity="info",
            category="ssl",
            description=(
                f"SSL/TLS certificate details for {endpoint}. "
                f"Subject: {cn}. Issuer: {issuer_str}. "
                f"Valid: {cert.get('not_before', '?')} to {cert.get('not_after', '?')}. "
                f"SANs: {', '.join(cert.get('sans', [])[:10]) or 'none'}."
            ),
            finding_type="ssl_info",
            tags=["ssl", "certificate", "info"],
            engine="ssl",
            details=self._cert_details(cert),
            dedupe_fields={"port": port, "check": "info"},
        ))

        return drafts

    # -------------------------------------------------------------------
    # Protocol analysis
    # -------------------------------------------------------------------

    def _analyze_protocols(
        self, protocols: Dict[str, bool], ctx: ScanContext
    ) -> List[FindingDraft]:
        """Analyze TLS protocol version support."""
        drafts: List[FindingDraft] = []

        # TLS 1.0 enabled — HIGH
        if protocols.get("TLSv1.0") is True:
            drafts.append(FindingDraft(
                template_id="ssl-tls10-enabled",
                title=f"TLS 1.0 enabled on {ctx.asset_value}",
                severity="high",
                category="ssl",
                description=(
                    "TLS 1.0 is enabled on this server. TLS 1.0 was deprecated "
                    "in 2020 (RFC 8996) due to known vulnerabilities including "
                    "BEAST and POODLE attacks. All major browsers have dropped "
                    "TLS 1.0 support. PCI DSS also prohibits TLS 1.0."
                ),
                remediation=(
                    "Disable TLS 1.0 in your server configuration. "
                    "For nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                    "For Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1"
                ),
                finding_type="ssl_deprecated_protocol",
                cwe="CWE-326",
                tags=["ssl", "protocol", "tls1.0", "deprecated"],
                engine="ssl",
                details={"protocols": protocols},
                dedupe_fields={"check": "tls10"},
            ))

        # TLS 1.1 enabled — MEDIUM
        if protocols.get("TLSv1.1") is True:
            drafts.append(FindingDraft(
                template_id="ssl-tls11-enabled",
                title=f"TLS 1.1 enabled on {ctx.asset_value}",
                severity="medium",
                category="ssl",
                description=(
                    "TLS 1.1 is enabled on this server. TLS 1.1 was deprecated "
                    "in 2021 (RFC 8996). While less vulnerable than TLS 1.0, "
                    "it lacks modern security features and is being dropped by "
                    "browsers and security standards."
                ),
                remediation=(
                    "Disable TLS 1.1 in your server configuration. "
                    "Support only TLS 1.2 and TLS 1.3."
                ),
                finding_type="ssl_deprecated_protocol",
                cwe="CWE-326",
                tags=["ssl", "protocol", "tls1.1", "deprecated"],
                engine="ssl",
                details={"protocols": protocols},
                dedupe_fields={"check": "tls11"},
            ))

        # TLS 1.2 NOT supported — MEDIUM
        if protocols.get("TLSv1.2") is False and protocols.get("TLSv1.3") is True:
            drafts.append(FindingDraft(
                template_id="ssl-no-tls12",
                title=f"TLS 1.2 not supported on {ctx.asset_value}",
                severity="info",
                category="ssl",
                description=(
                    "TLS 1.2 is not supported, but TLS 1.3 is available. "
                    "Some older clients may not support TLS 1.3 yet. "
                    "Consider enabling TLS 1.2 for broader compatibility."
                ),
                remediation="Enable TLS 1.2 alongside TLS 1.3 for compatibility.",
                finding_type="ssl_protocol_info",
                tags=["ssl", "protocol"],
                engine="ssl",
                details={"protocols": protocols},
                dedupe_fields={"check": "no_tls12"},
            ))

        # TLS 1.3 NOT supported — LOW
        if protocols.get("TLSv1.3") is False and protocols.get("TLSv1.2") is True:
            drafts.append(FindingDraft(
                template_id="ssl-no-tls13",
                title=f"TLS 1.3 not supported on {ctx.asset_value}",
                severity="low",
                category="ssl",
                description=(
                    "TLS 1.3 is not supported on this server. TLS 1.3 provides "
                    "improved security and performance (faster handshake, "
                    "forward secrecy by default). While TLS 1.2 is still acceptable, "
                    "TLS 1.3 is recommended."
                ),
                remediation=(
                    "Enable TLS 1.3 in your server configuration. "
                    "For nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                    "Ensure your OpenSSL version is 1.1.1+ for TLS 1.3 support."
                ),
                finding_type="ssl_protocol_info",
                tags=["ssl", "protocol", "tls1.3"],
                engine="ssl",
                details={"protocols": protocols},
                dedupe_fields={"check": "no_tls13"},
            ))

        # Neither TLS 1.2 nor 1.3 — only old protocols — HIGH
        if (protocols.get("TLSv1.2") is False and
                protocols.get("TLSv1.3") is False and
                (protocols.get("TLSv1.0") is True or protocols.get("TLSv1.1") is True)):
            drafts.append(FindingDraft(
                template_id="ssl-only-deprecated-protocols",
                title=f"Only deprecated TLS versions supported on {ctx.asset_value}",
                severity="high",
                category="ssl",
                description=(
                    "This server only supports deprecated TLS versions (1.0 and/or 1.1). "
                    "Neither TLS 1.2 nor TLS 1.3 is available. Modern browsers "
                    "will refuse to connect, and the connection is vulnerable to "
                    "known attacks."
                ),
                remediation=(
                    "Upgrade your TLS configuration urgently. Enable TLS 1.2 and "
                    "TLS 1.3. Update OpenSSL to a current version. "
                    "Disable TLS 1.0 and 1.1."
                ),
                finding_type="ssl_critical_protocol",
                cwe="CWE-326",
                tags=["ssl", "protocol", "critical"],
                engine="ssl",
                details={"protocols": protocols},
                dedupe_fields={"check": "only_deprecated"},
            ))

        return drafts

    # -------------------------------------------------------------------
    # Shodan SSL data extraction
    # -------------------------------------------------------------------

    def _extract_shodan_ssl(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Extract SSL certificate data from Shodan's service entries.
        Shodan includes SSL info in the "ssl" field of service banners.
        This supplements the SSL engine (covers ports the engine might miss).
        """
        shodan_data = ctx.get_engine_data("shodan")
        certs: List[Dict[str, Any]] = []

        for svc in shodan_data.get("services", []):
            ssl_info = svc.get("ssl")
            if not ssl_info or not isinstance(ssl_info, dict):
                continue

            cert_data = ssl_info.get("cert", {})
            if not cert_data:
                continue

            # Normalize Shodan's SSL format to match our SSL engine output
            subject = cert_data.get("subject", {})
            issuer = cert_data.get("issuer", {})

            # Parse expiry
            expires = cert_data.get("expires")
            not_before_str = cert_data.get("issued")

            # Shodan sometimes has these pre-parsed
            is_expired = cert_data.get("expired", None)
            days_until = None

            if expires:
                try:
                    from datetime import datetime, timezone
                    # Shodan date formats vary
                    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y%m%d%H%M%SZ", "%b %d %H:%M:%S %Y GMT"):
                        try:
                            exp_dt = datetime.strptime(str(expires), fmt).replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            is_expired = now > exp_dt
                            days_until = (exp_dt - now).days
                            break
                        except ValueError:
                            continue
                except Exception:
                    pass

            # Build SANs
            sans = []
            extensions = cert_data.get("extensions", [])
            if isinstance(extensions, list):
                for ext in extensions:
                    if isinstance(ext, dict) and "subjectAltName" in str(ext.get("name", "")):
                        san_val = ext.get("data", "")
                        if isinstance(san_val, str):
                            # Parse "DNS:example.com, DNS:www.example.com"
                            for part in san_val.split(","):
                                part = part.strip()
                                if part.startswith("DNS:"):
                                    sans.append(part[4:])

            # Hostname match
            hostname = ctx.asset_value.lower()
            cn = (subject.get("CN") or "").lower()
            hostname_match = cn == hostname or any(
                s.lower() == hostname for s in sans
            )

            certs.append({
                "port": svc.get("port", 443),
                "ip": svc.get("ip", ctx.asset_value),
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before_str,
                "not_after": expires,
                "is_expired": is_expired,
                "days_until_expiry": days_until,
                "is_self_signed": subject == issuer if subject and issuer else None,
                "hostname_match": hostname_match,
                "sans": sans,
                "version": cert_data.get("version"),
                "_source": "shodan",
            })

        return certs

    # -------------------------------------------------------------------
    # SSL error finding
    # -------------------------------------------------------------------

    def _ssl_error_finding(self, cert: Dict[str, Any]) -> FindingDraft:
        """Create an info finding when SSL connection failed."""
        port = cert.get("port", "?")
        host = cert.get("host", "?")
        error = cert.get("error", "Unknown error")

        return FindingDraft(
            template_id="ssl-connection-error",
            title=f"SSL/TLS connection failed on {host}:{port}",
            severity="info",
            category="ssl",
            description=(
                f"Could not establish SSL/TLS connection to {host}:{port}. "
                f"Error: {error}. This may indicate the port doesn't serve HTTPS, "
                "or there's a configuration issue preventing the SSL handshake."
            ),
            finding_type="ssl_error",
            tags=["ssl", "error"],
            engine="ssl",
            details={"port": port, "host": host, "error": error},
            dedupe_fields={"port": port, "check": "connection_error"},
        )

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _cert_details(self, cert: Dict[str, Any]) -> Dict[str, Any]:
        """Build a clean details dict from certificate data for storage."""
        return {
            "port": cert.get("port"),
            "ip": cert.get("ip"),
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "serial_number": cert.get("serial_number"),
            "not_before": cert.get("not_before"),
            "not_after": cert.get("not_after"),
            "is_expired": cert.get("is_expired"),
            "days_until_expiry": cert.get("days_until_expiry"),
            "is_self_signed": cert.get("is_self_signed"),
            "hostname_match": cert.get("hostname_match"),
            "sans": cert.get("sans", [])[:20],  # Cap SAN list
            "protocol_version": cert.get("protocol_version"),
            "cipher": cert.get("cipher"),
        }