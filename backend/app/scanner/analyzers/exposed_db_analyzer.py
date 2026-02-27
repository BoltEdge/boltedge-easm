# app/scanner/analyzers/exposed_db_analyzer.py
"""
Exposed Database Analyzer.

Reads database probe results from the db_probe engine and produces
findings for databases accessible without authentication.

Checks performed:
    CRITICAL:
        - Elasticsearch accessible without authentication
        - MongoDB accessible without authentication
        - Redis accessible without authentication

    LOW:
        - Database port open but authentication required (informational,
          confirms the service exists — auth is properly configured)

Exposed databases are always critical because:
    - Elasticsearch: full data read/write, cluster control, potential RCE
    - MongoDB: full data read/write, potential admin access
    - Redis: data read/write, potential RCE via EVAL/CONFIG/MODULE
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional




from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext

logger = logging.getLogger(__name__)


# Service-specific finding metadata
SERVICE_FINDINGS = {
    "elasticsearch": {
        "template_id": "db-elasticsearch-exposed",
        "title_unauthenticated": "Elasticsearch accessible without authentication on {ip}:{port}",
        "title_authenticated": "Elasticsearch detected on {ip}:{port} (authentication enabled)",
        "description_unauthenticated": (
            "An Elasticsearch instance on {ip}:{port} is accessible without any "
            "authentication. {evidence} "
            "An attacker can read, modify, or delete all indexed data, access "
            "cluster settings, and potentially execute code via scripting features. "
            "Exposed Elasticsearch instances are a frequent target for ransomware "
            "and data theft."
        ),
        "description_authenticated": (
            "An Elasticsearch instance was detected on {ip}:{port} with "
            "authentication enabled. While the service requires credentials to "
            "access, the port is publicly reachable. Consider restricting network "
            "access to reduce the attack surface."
        ),
        "remediation": (
            "1. Enable Elasticsearch security features: set xpack.security.enabled=true "
            "in elasticsearch.yml.\n"
            "2. Configure authentication (native realm, LDAP, or SAML).\n"
            "3. Enable TLS for transport and HTTP layers.\n"
            "4. Restrict network access: bind to localhost or use firewall rules "
            "to allow only trusted IPs.\n"
            "5. If using cloud hosting, ensure the instance is not bound to 0.0.0.0."
        ),
        "cwe": "CWE-306",
        "tags_base": ["database", "elasticsearch", "unauthenticated", "exposed"],
    },
    "mongodb": {
        "template_id": "db-mongodb-exposed",
        "title_unauthenticated": "MongoDB accessible without authentication on {ip}:{port}",
        "title_authenticated": "MongoDB detected on {ip}:{port} (authentication enabled)",
        "description_unauthenticated": (
            "A MongoDB instance on {ip}:{port} is accessible without any "
            "authentication. {evidence} "
            "An attacker can read, modify, or delete all databases, create admin "
            "users, and potentially execute server-side JavaScript. Exposed MongoDB "
            "instances are one of the most common causes of large-scale data breaches."
        ),
        "description_authenticated": (
            "A MongoDB instance was detected on {ip}:{port} with authentication "
            "enabled. While the service requires credentials to access, the port "
            "is publicly reachable. Consider restricting network access."
        ),
        "remediation": (
            "1. Enable authentication: add authorization: enabled to mongod.conf "
            "under the security section.\n"
            "2. Create an admin user with a strong password.\n"
            "3. Bind to localhost: set bindIp: 127.0.0.1 in mongod.conf.\n"
            "4. Use firewall rules to restrict access to trusted IPs only.\n"
            "5. Enable TLS for all connections.\n"
            "6. If using MongoDB Atlas, verify network access list settings."
        ),
        "cwe": "CWE-306",
        "tags_base": ["database", "mongodb", "unauthenticated", "exposed"],
    },
    "redis": {
        "template_id": "db-redis-exposed",
        "title_unauthenticated": "Redis accessible without authentication on {ip}:{port}",
        "title_authenticated": "Redis detected on {ip}:{port} (authentication enabled)",
        "description_unauthenticated": (
            "A Redis instance on {ip}:{port} is accessible without any "
            "authentication. {evidence} "
            "An attacker can read and modify all cached data, flush databases, "
            "and potentially achieve remote code execution via CONFIG SET, "
            "MODULE LOAD, or Lua scripting (EVAL). Exposed Redis instances are "
            "frequently exploited for cryptocurrency mining and lateral movement."
        ),
        "description_authenticated": (
            "A Redis instance was detected on {ip}:{port} with authentication "
            "enabled (requirepass or ACL). While the service requires credentials, "
            "the port is publicly reachable. Consider restricting network access."
        ),
        "remediation": (
            "1. Set a strong password: add requirepass <password> to redis.conf.\n"
            "2. Use Redis ACLs (Redis 6+) for fine-grained access control.\n"
            "3. Bind to localhost: set bind 127.0.0.1 in redis.conf.\n"
            "4. Disable dangerous commands: rename-command CONFIG \"\", "
            "rename-command EVAL \"\", rename-command FLUSHALL \"\".\n"
            "5. Enable TLS: set tls-port and tls-cert-file in redis.conf.\n"
            "6. Use firewall rules to restrict access to trusted IPs only."
        ),
        "cwe": "CWE-306",
        "tags_base": ["database", "redis", "unauthenticated", "exposed"],
    },
}


class ExposedDBAnalyzer(BaseAnalyzer):
    """
    Analyzes database probe results for security issues.

    Produces critical findings for databases accessible without
    authentication, and low-severity informational findings for
    databases with authentication properly configured.
    """

    @property
    def name(self) -> str:
        return "exposed_db_analyzer"

    @property
    def required_engines(self) -> List[str]:
        return ["db_probe"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []

        db_data = ctx.get_engine_data("db_probe")
        if not db_data:
            return drafts

        probes = db_data.get("probes", [])
        if not probes:
            return drafts

        for probe in probes:
            service = probe.get("service", "")
            service_cfg = SERVICE_FINDINGS.get(service)
            if not service_cfg:
                continue

            ip = probe.get("ip", "unknown")
            port = probe.get("port", 0)
            accessible = probe.get("accessible", False)
            auth_required = probe.get("auth_required", False)
            evidence = probe.get("evidence", "")
            version = probe.get("version")

            if accessible and not auth_required:
                # CRITICAL: Database accessible without authentication
                drafts.append(self._build_unauthenticated_finding(
                    service_cfg=service_cfg,
                    probe=probe,
                    ip=ip,
                    port=port,
                    evidence=evidence,
                    version=version,
                ))

            elif auth_required:
                # LOW: Database exists but auth is configured (good)
                drafts.append(self._build_authenticated_finding(
                    service_cfg=service_cfg,
                    probe=probe,
                    ip=ip,
                    port=port,
                    version=version,
                ))

        return drafts

    def _build_unauthenticated_finding(
        self,
        service_cfg: Dict[str, Any],
        probe: Dict[str, Any],
        ip: str,
        port: int,
        evidence: str,
        version: Optional[str],
    ) -> FindingDraft:
        """Build a critical finding for an unauthenticated database."""
        title = service_cfg["title_unauthenticated"].format(ip=ip, port=port)
        description = service_cfg["description_unauthenticated"].format(
            ip=ip, port=port, evidence=evidence,
        )

        tags = list(service_cfg["tags_base"])
        if version:
            tags.append(f"v{version}")

        # Build detailed evidence
        details: Dict[str, Any] = {
            "ip": ip,
            "port": port,
            "service": probe.get("service"),
            "version": version,
            "accessible": True,
            "auth_required": False,
            "evidence": evidence,
        }

        # Add service-specific details
        if probe.get("cluster_name"):
            details["cluster_name"] = probe["cluster_name"]
        if probe.get("indices_count") is not None:
            details["indices_count"] = probe["indices_count"]
        if probe.get("database_count") is not None:
            details["database_count"] = probe["database_count"]
        if probe.get("details", {}).get("databases"):
            details["databases_sample"] = probe["details"]["databases"][:10]
        if probe.get("details", {}).get("sample_indices"):
            details["indices_sample"] = probe["details"]["sample_indices"][:10]
        if probe.get("details", {}).get("server_info"):
            details["server_info"] = probe["details"]["server_info"]

        return FindingDraft(
            template_id=service_cfg["template_id"],
            title=title,
            severity="critical",
            category="exposure",
            description=description,
            remediation=service_cfg["remediation"],
            finding_type="exposed_database",
            cwe=service_cfg["cwe"],
            tags=tags,
            engine="db_probe",
            confidence="high",
            details=details,
            dedupe_fields={
                "check": "exposed_database",
                "service": probe.get("service"),
                "ip": ip,
                "port": port,
            },
        )

    def _build_authenticated_finding(
        self,
        service_cfg: Dict[str, Any],
        probe: Dict[str, Any],
        ip: str,
        port: int,
        version: Optional[str],
    ) -> FindingDraft:
        """Build a low-severity finding for a database with auth enabled."""
        title = service_cfg["title_authenticated"].format(ip=ip, port=port)
        description = service_cfg["description_authenticated"].format(
            ip=ip, port=port,
        )

        tags = [t for t in service_cfg["tags_base"] if t != "unauthenticated"]
        tags.append("authenticated")

        return FindingDraft(
            template_id=f"{service_cfg['template_id']}-auth",
            title=title,
            severity="low",
            category="exposure",
            description=description,
            remediation=(
                "The database has authentication enabled, which is good. "
                "Consider also restricting network access so the port is not "
                "publicly reachable. Use firewall rules or security groups to "
                "limit access to trusted IPs only."
            ),
            finding_type="database_detected",
            cwe=None,
            tags=tags,
            engine="db_probe",
            confidence="high",
            details={
                "ip": ip,
                "port": port,
                "service": probe.get("service"),
                "version": version,
                "accessible": False,
                "auth_required": True,
            },
            dedupe_fields={
                "check": "database_detected",
                "service": probe.get("service"),
                "ip": ip,
                "port": port,
            },
        )