# app/scanner/analyzers/port_risk.py
"""
Port Risk Analyzer.

Reads raw service/port data from engines (Shodan, future Nmap) and classifies
each open port by security risk level.

This replaces the old RISKY_PORTS dict and detect_service_exposure() /
detect_risky_ports() functions from app/engine.py.

Classification logic:
    CRITICAL — Services that should NEVER be internet-facing (databases, RDP, Docker API)
    HIGH     — Services commonly exploited (Telnet, FTP, SMB, unauthed caches)
    MEDIUM   — Services that need careful configuration (SSH with password, SMTP relay)
    LOW      — Expected services noted for completeness (SSH with keys, HTTP)
    INFO     — Standard web ports, expected services

Each finding includes:
    - Clear title explaining what was found
    - Description of the risk
    - Specific remediation steps
    - Deduplication fields so rescans don't create duplicate findings
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Port risk classification table
#
# Each entry maps a port number to its risk profile.
# The analyzer checks this table for every open port found by engines.
#
# Fields:
#   label:       Human-readable service name
#   severity:    Default severity when this port is exposed
#   category:    Why it's risky (database, remote_access, admin, etc.)
#   description: Risk explanation
#   remediation: What the user should do
# ---------------------------------------------------------------------------

PORT_RISK_TABLE: Dict[int, Dict[str, str]] = {
    # === CRITICAL: Should NEVER be internet-facing ===

    # Remote desktop / remote access
    3389: {
        "label": "RDP (Remote Desktop)",
        "severity": "critical",
        "category": "remote_access",
        "description": (
            "Remote Desktop Protocol is exposed to the internet. "
            "RDP is a top target for brute-force attacks and ransomware. "
            "Multiple critical RDP vulnerabilities (BlueKeep, DejaBlue) "
            "allow unauthenticated remote code execution."
        ),
        "remediation": (
            "Block port 3389 from the internet immediately. Use a VPN or "
            "SSH tunnel for remote access. If RDP must be accessible, use "
            "Network Level Authentication (NLA) and IP allowlisting."
        ),
    },
    5900: {
        "label": "VNC",
        "severity": "critical",
        "category": "remote_access",
        "description": (
            "VNC remote desktop is exposed to the internet. VNC often lacks "
            "encryption and strong authentication, making it trivial to "
            "intercept credentials or brute-force access."
        ),
        "remediation": (
            "Block VNC ports (5900-5910) from the internet. Use SSH tunneling "
            "or a VPN for remote access instead."
        ),
    },
    5901: {"label": "VNC :1", "severity": "critical", "category": "remote_access",
           "description": "VNC display :1 exposed to the internet.",
           "remediation": "Block port 5901 and use VPN/SSH tunnel for remote access."},
    5902: {"label": "VNC :2", "severity": "critical", "category": "remote_access",
           "description": "VNC display :2 exposed to the internet.",
           "remediation": "Block port 5902 and use VPN/SSH tunnel for remote access."},

    # Databases
    3306: {
        "label": "MySQL",
        "severity": "critical",
        "category": "database",
        "description": (
            "MySQL database port is exposed to the internet. This allows "
            "attackers to attempt brute-force login, exploit known MySQL "
            "vulnerabilities, or extract data if credentials are weak."
        ),
        "remediation": (
            "Block port 3306 from the internet. Bind MySQL to 127.0.0.1 or "
            "a private network interface. Use SSH tunneling for remote DB access."
        ),
    },
    5432: {
        "label": "PostgreSQL",
        "severity": "critical",
        "category": "database",
        "description": (
            "PostgreSQL database port is exposed to the internet. "
            "Direct database exposure allows brute-force attacks and "
            "exploitation of any unpatched PostgreSQL vulnerabilities."
        ),
        "remediation": (
            "Block port 5432 from the internet. Configure pg_hba.conf to "
            "reject non-local connections. Use SSH tunneling for remote access."
        ),
    },
    1433: {
        "label": "Microsoft SQL Server",
        "severity": "critical",
        "category": "database",
        "description": (
            "Microsoft SQL Server is exposed to the internet. MSSQL is "
            "frequently targeted for brute-force attacks, and the xp_cmdshell "
            "stored procedure can allow OS command execution if compromised."
        ),
        "remediation": (
            "Block port 1433 from the internet. Use Windows Firewall rules "
            "or network security groups to restrict access to trusted IPs only."
        ),
    },
    1434: {"label": "MSSQL Browser", "severity": "critical", "category": "database",
           "description": "MSSQL Browser service exposed — reveals instance details to attackers.",
           "remediation": "Block port 1434. Disable SQL Server Browser service if not needed."},
    6379: {
        "label": "Redis",
        "severity": "critical",
        "category": "database",
        "description": (
            "Redis is exposed to the internet. Redis has no authentication "
            "by default, meaning anyone can read/write data. Attackers "
            "commonly exploit exposed Redis to write SSH keys or crontabs "
            "for full server compromise."
        ),
        "remediation": (
            "Block port 6379 from the internet immediately. Bind Redis to "
            "127.0.0.1 in redis.conf. Enable AUTH with a strong password. "
            "Disable dangerous commands (FLUSHALL, CONFIG, DEBUG)."
        ),
    },
    27017: {
        "label": "MongoDB",
        "severity": "critical",
        "category": "database",
        "description": (
            "MongoDB is exposed to the internet. Older MongoDB versions had "
            "no authentication by default. Even with auth, direct internet "
            "exposure invites brute-force attacks and data exfiltration."
        ),
        "remediation": (
            "Block port 27017 from the internet. Enable authentication in "
            "mongod.conf. Bind to 127.0.0.1 or a private network interface."
        ),
    },
    9200: {
        "label": "Elasticsearch",
        "severity": "critical",
        "category": "database",
        "description": (
            "Elasticsearch is exposed to the internet. Elasticsearch has no "
            "built-in authentication in the open-source version. Exposed "
            "instances are routinely scraped for sensitive data by automated bots."
        ),
        "remediation": (
            "Block port 9200 from the internet. Use Elasticsearch security "
            "features (X-Pack) or a reverse proxy with authentication."
        ),
    },
    9300: {"label": "Elasticsearch Transport", "severity": "critical", "category": "database",
           "description": "Elasticsearch inter-node transport port exposed.",
           "remediation": "Block port 9300 from the internet. This is an internal cluster port."},
    5984: {"label": "CouchDB", "severity": "critical", "category": "database",
           "description": "CouchDB HTTP API exposed to the internet.",
           "remediation": "Block port 5984. Use authentication and bind to localhost."},

    # Container / orchestration
    2375: {
        "label": "Docker API (unencrypted)",
        "severity": "critical",
        "category": "container",
        "description": (
            "Docker daemon API is exposed without TLS. This gives any attacker "
            "full control over all containers and the host system — equivalent "
            "to root access. This is one of the most dangerous exposures possible."
        ),
        "remediation": (
            "Block port 2375 immediately. If remote Docker access is needed, "
            "use port 2376 with TLS client certificates. Better yet, use SSH."
        ),
    },
    2376: {"label": "Docker API (TLS)", "severity": "high", "category": "container",
           "description": "Docker API with TLS is exposed. While encrypted, direct API exposure is risky.",
           "remediation": "Restrict Docker API to trusted IPs. Use SSH instead if possible."},
    10250: {"label": "Kubernetes Kubelet", "severity": "critical", "category": "container",
            "description": "Kubernetes Kubelet API exposed — allows container execution.",
            "remediation": "Block port 10250 from the internet. Use RBAC and network policies."},
    2379: {"label": "etcd", "severity": "critical", "category": "container",
           "description": "etcd key-value store exposed — contains Kubernetes secrets.",
           "remediation": "Block port 2379. etcd should never be internet-accessible."},

    # === HIGH: Commonly exploited services ===

    23: {
        "label": "Telnet",
        "severity": "high",
        "category": "unencrypted",
        "description": (
            "Telnet transmits all data including credentials in plaintext. "
            "It provides no encryption, making it trivial to intercept "
            "passwords via network sniffing."
        ),
        "remediation": (
            "Disable Telnet and use SSH instead. If Telnet is required for "
            "legacy devices, restrict access to a management VLAN."
        ),
    },
    21: {
        "label": "FTP",
        "severity": "high",
        "category": "unencrypted",
        "description": (
            "FTP transmits credentials and data in plaintext. Anonymous FTP "
            "may also be enabled, allowing unauthenticated file access."
        ),
        "remediation": (
            "Replace FTP with SFTP (SSH File Transfer) or FTPS (FTP over TLS). "
            "If FTP must run, disable anonymous access and enforce strong passwords."
        ),
    },
    445: {
        "label": "SMB",
        "severity": "high",
        "category": "file_sharing",
        "description": (
            "SMB file sharing is exposed to the internet. SMB has a long "
            "history of critical vulnerabilities (EternalBlue/WannaCry, "
            "SMBGhost). It should never be internet-facing."
        ),
        "remediation": (
            "Block port 445 at the firewall. SMB should only be accessible "
            "on internal networks. Use VPN for remote file access."
        ),
    },
    139: {"label": "NetBIOS/SMB", "severity": "high", "category": "file_sharing",
          "description": "NetBIOS session service exposed — often used with SMB.",
          "remediation": "Block ports 137-139 from the internet."},
    11211: {
        "label": "Memcached",
        "severity": "high",
        "category": "cache",
        "description": (
            "Memcached is exposed to the internet. Memcached has no "
            "authentication and is commonly abused for DDoS amplification "
            "attacks (amplification factor up to 51,000x)."
        ),
        "remediation": (
            "Block port 11211 from the internet. Bind Memcached to "
            "127.0.0.1 or disable UDP (memcached -U 0)."
        ),
    },
    161: {
        "label": "SNMP",
        "severity": "high",
        "category": "management",
        "description": (
            "SNMP is exposed to the internet. Default community strings "
            "(public/private) allow reading or modifying device configuration. "
            "SNMPv1 and v2c transmit community strings in plaintext."
        ),
        "remediation": (
            "Block SNMP from the internet. If needed, use SNMPv3 with "
            "authentication and encryption. Change default community strings."
        ),
    },
    111: {"label": "RPCbind/Portmapper", "severity": "high", "category": "management",
          "description": "RPCbind exposed — reveals available RPC services to attackers.",
          "remediation": "Block port 111 from the internet. Restrict to internal networks."},
    2049: {"label": "NFS", "severity": "high", "category": "file_sharing",
           "description": "Network File System exposed to the internet.",
           "remediation": "Block NFS from the internet. Use VPN for remote file access."},
    512: {"label": "rexec", "severity": "high", "category": "remote_access",
          "description": "Remote execution service (rexec) exposed — legacy, no encryption.",
          "remediation": "Disable rexec. Use SSH instead."},
    513: {"label": "rlogin", "severity": "high", "category": "remote_access",
          "description": "Remote login service (rlogin) exposed — no encryption.",
          "remediation": "Disable rlogin. Use SSH instead."},

    # === MEDIUM: Needs careful configuration ===

    22: {
        "label": "SSH",
        "severity": "low",
        "category": "remote_access",
        "description": (
            "SSH is exposed to the internet. While SSH is encrypted, "
            "it is a common target for brute-force attacks. Password "
            "authentication should be disabled in favor of key-based auth."
        ),
        "remediation": (
            "Disable password authentication (PasswordAuthentication no). "
            "Use key-based auth only. Consider changing the default port "
            "and using fail2ban to block brute-force attempts."
        ),
    },
    25: {
        "label": "SMTP",
        "severity": "medium",
        "category": "email",
        "description": (
            "SMTP mail server is exposed. If misconfigured as an open relay, "
            "it can be abused to send spam. Even properly configured, SMTP "
            "exposure increases attack surface."
        ),
        "remediation": (
            "Ensure SMTP is not an open relay. Require authentication for "
            "sending. Use STARTTLS for encryption. Consider using a managed "
            "email service instead."
        ),
    },
    8080: {
        "label": "HTTP Proxy/Alt",
        "severity": "medium",
        "category": "web",
        "description": (
            "An HTTP service is running on a non-standard port (8080). "
            "This is often an admin panel, development server, or proxy "
            "that may have weaker security than the main site."
        ),
        "remediation": (
            "Determine what service is running on 8080. If it's an admin "
            "panel, restrict access by IP. If it's a development server, "
            "take it offline or move behind authentication."
        ),
    },
    8443: {"label": "HTTPS Alt", "severity": "medium", "category": "web",
           "description": "HTTPS on non-standard port — often admin panel or API.",
           "remediation": "Verify what's running on 8443. Restrict admin interfaces by IP."},
    9090: {"label": "Web Admin", "severity": "medium", "category": "admin",
           "description": "Common admin panel port (Cockpit, Prometheus, etc.) exposed.",
           "remediation": "Restrict admin panels to internal networks or VPN."},
    8888: {"label": "HTTP Alt/Jupyter", "severity": "medium", "category": "admin",
           "description": "Port 8888 often hosts Jupyter notebooks or dev servers.",
           "remediation": "If running Jupyter, add authentication and restrict access."},
    3000: {"label": "Dev Server/Grafana", "severity": "medium", "category": "admin",
           "description": "Port 3000 commonly used by Grafana, dev servers, or Node.js apps.",
           "remediation": "Ensure proper authentication. Don't expose development servers."},

    # === LOW: Expected but noted ===

    80: {
        "label": "HTTP",
        "severity": "info",
        "category": "web",
        "description": "Standard HTTP web server. Check that HTTPS redirect is in place.",
        "remediation": "Ensure HTTP redirects to HTTPS. Check security headers.",
    },
    443: {
        "label": "HTTPS",
        "severity": "info",
        "category": "web",
        "description": "Standard HTTPS web server.",
        "remediation": "Verify SSL/TLS configuration is secure. Check security headers.",
    },
    53: {
        "label": "DNS",
        "severity": "low",
        "category": "infrastructure",
        "description": (
            "DNS server is exposed. If this is intentional (authoritative DNS), "
            "ensure zone transfers are restricted. Open recursive resolvers "
            "can be abused for DNS amplification attacks."
        ),
        "remediation": (
            "Disable recursion if this is an authoritative-only server. "
            "Restrict zone transfers (AXFR) to known secondaries."
        ),
    },
    993: {"label": "IMAPS", "severity": "info", "category": "email",
          "description": "IMAP over SSL — encrypted email retrieval.",
          "remediation": "Ensure valid SSL certificate and strong TLS configuration."},
    995: {"label": "POP3S", "severity": "info", "category": "email",
          "description": "POP3 over SSL — encrypted email retrieval.",
          "remediation": "Ensure valid SSL certificate and strong TLS configuration."},
    587: {"label": "SMTP Submission", "severity": "info", "category": "email",
          "description": "SMTP submission port — requires authentication.",
          "remediation": "Ensure STARTTLS is enforced and auth is required."},
    143: {"label": "IMAP", "severity": "medium", "category": "email",
          "description": "Unencrypted IMAP email service. Credentials sent in plaintext.",
          "remediation": "Use IMAPS (port 993) instead, or enforce STARTTLS."},
    110: {"label": "POP3", "severity": "medium", "category": "email",
          "description": "Unencrypted POP3 email service. Credentials sent in plaintext.",
          "remediation": "Use POP3S (port 995) instead, or enforce STARTTLS."},
}


class PortRiskAnalyzer(BaseAnalyzer):
    """
    Classifies open ports by security risk.

    Reads service data from Shodan (and future Nmap) engine results.
    For each open port, produces a FindingDraft with:
      - Risk-appropriate severity from the PORT_RISK_TABLE
      - Clear description of why it's risky
      - Specific remediation steps
      - Deduplication on (ip, port, transport)

    Also produces a general "service_exposure" finding for any port
    not in the risk table (info severity) so the user has a complete
    picture of their attack surface.
    """

    @property
    def name(self) -> str:
        return "port_risk"

    @property
    def required_engines(self) -> List[str]:
        # Runs if Shodan OR Nmap has data
        return ["shodan", "nmap"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []

        # Collect services from all available engines
        services = self._collect_services(ctx)

        # Deduplicate by (ip, port, transport) — multiple engines may see same port
        seen: set = set()

        for svc in services:
            ip = svc.get("ip", "unknown")
            port = svc.get("port")
            transport = svc.get("transport", "tcp")

            if port is None:
                continue

            dedup_key = (ip, int(port), transport)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Check the risk table
            risk_entry = PORT_RISK_TABLE.get(int(port))

            if risk_entry:
                drafts.append(self._classified_finding(svc, risk_entry))
            else:
                # Unknown port — still report as service exposure
                drafts.append(self._generic_exposure_finding(svc))

        return drafts

    def _collect_services(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Gather service lists from all engines that report port data.
        Shodan + Nmap. The dedup in analyze() handles overlapping ports.
        """
        services: List[Dict[str, Any]] = []

        # From Shodan
        shodan_data = ctx.get_engine_data("shodan")
        services.extend(shodan_data.get("services", []))

        # From Nmap
        nmap_data = ctx.get_engine_data("nmap")
        services.extend(nmap_data.get("services", []))

        return services

    def _classified_finding(
        self, svc: Dict[str, Any], risk: Dict[str, str]
    ) -> FindingDraft:
        """Create a finding for a port that's in our risk classification table."""
        ip = svc.get("ip", "unknown")
        port = svc.get("port")
        transport = svc.get("transport", "tcp")
        product = svc.get("product") or ""
        version = svc.get("version") or ""
        prod_str = f"{product} {version}".strip()

        severity = risk["severity"]
        label = risk["label"]

        title = f"{label} exposed on {ip}:{port}/{transport}"
        if prod_str:
            title += f" ({prod_str})"

        return FindingDraft(
            template_id=f"port-{label.lower().replace(' ', '-').replace('/', '-')}-exposed",
            title=title,
            severity=severity,
            category="ports",
            description=risk["description"],
            remediation=risk.get("remediation"),
            finding_type="risky_port" if severity in ("critical", "high") else "open_port",
            tags=["port", label.lower(), risk.get("category", "")],
            engine="shodan",
            details={
                "ip": ip,
                "port": port,
                "transport": transport,
                "product": product or None,
                "version": version or None,
                "service_label": label,
                "risk_category": risk.get("category"),
                "banner": (svc.get("banner") or "")[:500],
            },
            dedupe_fields={
                "ip": ip,
                "port": port,
                "transport": transport,
            },
        )

    def _generic_exposure_finding(self, svc: Dict[str, Any]) -> FindingDraft:
        """Create an info-level finding for a port not in our risk table."""
        ip = svc.get("ip", "unknown")
        port = svc.get("port")
        transport = svc.get("transport", "tcp")
        product = svc.get("product") or ""
        version = svc.get("version") or ""
        prod_str = f"{product} {version}".strip()

        # If we know the product, it's slightly more interesting than a bare port
        severity = "low" if prod_str else "info"

        title = f"Open port {port}/{transport} on {ip}"
        if prod_str:
            title += f" ({prod_str})"

        return FindingDraft(
            template_id=f"port-{port}-open",
            title=title,
            severity=severity,
            category="ports",
            description=(
                f"Port {port}/{transport} is open on {ip}. "
                + (f"Running {prod_str}. " if prod_str else "")
                + "Review whether this service needs to be internet-facing."
            ),
            remediation=(
                f"Verify that port {port} needs to be publicly accessible. "
                "Close unnecessary ports using firewall rules."
            ),
            finding_type="service_exposure",
            tags=["port", "exposure"],
            engine="shodan",
            details={
                "ip": ip,
                "port": port,
                "transport": transport,
                "product": product or None,
                "version": version or None,
                "banner": (svc.get("banner") or "")[:500],
            },
            dedupe_fields={
                "ip": ip,
                "port": port,
                "transport": transport,
            },
        )