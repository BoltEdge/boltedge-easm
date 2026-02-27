# app/scanner/engines/db_probe_engine.py
"""
Database Exposure Probe engine.

Checks for unauthenticated access to databases on ports that nmap
confirmed are open. This engine runs AFTER nmap and reads nmap results
from ScanContext to determine which ports to probe.

Supported databases:
    - Elasticsearch (port 9200) — HTTP GET to / and /_cat/indices
    - MongoDB (port 27017) — unauthenticated connection attempt
    - Redis (port 6379) — unauthenticated PING and INFO

This engine is designed to be safe:
    - Only probes ports already confirmed open by nmap
    - Read-only operations only (no writes, no data exfiltration)
    - Short timeouts to avoid hanging on unresponsive services
    - Does NOT brute-force credentials

Output data structure (stored in EngineResult.data):
    {
        "probes": [
            {
                "ip": "1.2.3.4",
                "port": 9200,
                "service": "elasticsearch",
                "accessible": true,
                "auth_required": false,
                "version": "8.12.0",
                "cluster_name": "production",
                "indices_count": 47,
                "evidence": "Cluster 'production' accessible without authentication",
                "details": { ... }
            }
        ],
        "ports_checked": [9200, 27017, 6379],
        "errors": []
    }

Dependencies:
    - pymongo (for MongoDB probing)
    - redis (for Redis probing)
    - urllib (stdlib, for Elasticsearch probing)

Profile config options:
    timeout:  int — connection timeout per probe (default: 5)
"""

from __future__ import annotations

import json
import logging
import ssl
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from app.scanner.base import BaseEngine, EngineResult, ScanContext

logger = logging.getLogger(__name__)

# Database ports to check — only probed if nmap confirmed them open
DB_PORT_MAP = {
    9200: "elasticsearch",
    9201: "elasticsearch",
    27017: "mongodb",
    27018: "mongodb",
    27019: "mongodb",
    6379: "redis",
    6380: "redis",
}


class DBProbeEngine(BaseEngine):
    """
    Probes open database ports for unauthenticated access.

    Reads nmap results from ScanContext to determine which IPs/ports
    have database services. Only probes ports that nmap confirmed open.
    If nmap didn't run or found no database ports, this engine returns
    immediately with an empty result.

    Profile config:
        timeout: int — per-probe timeout in seconds (default: 5)
    """

    @property
    def name(self) -> str:
        return "db_probe"

    @property
    def supported_asset_types(self) -> List[str]:
        return ["domain", "ip"]

    def execute(self, ctx: ScanContext, config: Dict[str, Any]) -> EngineResult:
        result = EngineResult(engine_name=self.name)
        timeout = config.get("timeout", 5)

        # Find open database ports from nmap results
        db_targets = self._find_db_targets(ctx)

        if not db_targets:
            logger.info("DB Probe: no open database ports found in nmap results")
            result.data = {
                "probes": [],
                "ports_checked": [],
                "errors": [],
            }
            return result

        logger.info(
            f"DB Probe: found {len(db_targets)} database target(s) to probe"
        )

        probes: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []
        ports_checked = set()

        for target in db_targets:
            ip = target["ip"]
            port = target["port"]
            service = target["service"]
            ports_checked.add(port)

            try:
                if service == "elasticsearch":
                    probe = self._probe_elasticsearch(ip, port, timeout)
                elif service == "mongodb":
                    probe = self._probe_mongodb(ip, port, timeout)
                elif service == "redis":
                    probe = self._probe_redis(ip, port, timeout)
                else:
                    continue

                if probe:
                    probes.append(probe)

            except Exception as e:
                logger.debug(f"DB Probe error for {ip}:{port}: {e}")
                errors.append({
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "error": f"{type(e).__name__}: {str(e)}",
                })

        result.data = {
            "probes": probes,
            "ports_checked": sorted(ports_checked),
            "errors": errors,
        }

        result.metadata = {
            "targets_found": len(db_targets),
            "probes_completed": len(probes),
            "accessible_count": sum(1 for p in probes if p.get("accessible")),
        }

        if probes:
            accessible = sum(1 for p in probes if p.get("accessible"))
            logger.info(
                f"DB Probe: {len(probes)} probe(s) completed, "
                f"{accessible} database(s) accessible without auth"
            )

        return result

    # -------------------------------------------------------------------
    # Target discovery from nmap results
    # -------------------------------------------------------------------

    def _find_db_targets(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Extract open database ports from nmap engine results.

        Looks at nmap's port scan results for ports matching DB_PORT_MAP.
        Also checks Shodan results as a fallback if nmap didn't run.
        """
        targets: List[Dict[str, Any]] = []
        seen = set()  # (ip, port) dedup

        # Primary: nmap results
        nmap_data = ctx.get_engine_data("nmap")
        if nmap_data:
            # nmap_engine stores results in different formats depending
            # on implementation. Handle common structures:
            hosts = nmap_data.get("hosts", [])
            for host in hosts:
                ip = host.get("ip", "")
                for port_info in host.get("ports", []):
                    port = port_info.get("port")
                    state = port_info.get("state", "")
                    if port in DB_PORT_MAP and state == "open":
                        key = (ip, port)
                        if key not in seen:
                            seen.add(key)
                            targets.append({
                                "ip": ip,
                                "port": port,
                                "service": DB_PORT_MAP[port],
                                "nmap_service": port_info.get("service", ""),
                            })

            # Also check flat port list format
            ports_list = nmap_data.get("ports", [])
            for port_info in ports_list:
                port = port_info.get("port") or port_info.get("portid")
                state = port_info.get("state", "")
                if isinstance(port, str):
                    try:
                        port = int(port)
                    except ValueError:
                        continue

                if port in DB_PORT_MAP and state == "open":
                    # Use resolved IPs from context
                    for ip in (ctx.resolved_ips or [ctx.asset_value]):
                        key = (ip, port)
                        if key not in seen:
                            seen.add(key)
                            targets.append({
                                "ip": ip,
                                "port": port,
                                "service": DB_PORT_MAP[port],
                                "nmap_service": port_info.get("service", ""),
                            })

        # Fallback: Shodan results (if nmap didn't run)
        if not targets:
            shodan_data = ctx.get_engine_data("shodan")
            if shodan_data:
                for svc in shodan_data.get("services", []):
                    port = svc.get("port")
                    if port in DB_PORT_MAP:
                        ip = svc.get("ip", ctx.asset_value)
                        key = (ip, port)
                        if key not in seen:
                            seen.add(key)
                            targets.append({
                                "ip": ip,
                                "port": port,
                                "service": DB_PORT_MAP[port],
                                "nmap_service": svc.get("product", ""),
                            })

        return targets

    # -------------------------------------------------------------------
    # Elasticsearch probe
    # -------------------------------------------------------------------

    def _probe_elasticsearch(
        self, ip: str, port: int, timeout: int
    ) -> Optional[Dict[str, Any]]:
        """
        Probe Elasticsearch for unauthenticated access.

        1. GET http://ip:port/ — check for cluster info
        2. GET http://ip:port/_cat/indices?v — check index listing
        """
        probe: Dict[str, Any] = {
            "ip": ip,
            "port": port,
            "service": "elasticsearch",
            "accessible": False,
            "auth_required": False,
            "version": None,
            "details": {},
        }

        base_url = f"http://{ip}:{port}"

        # Step 1: Root endpoint — cluster info
        root_data = self._http_get_json(f"{base_url}/", timeout)

        if root_data is None:
            # Try HTTPS
            base_url = f"https://{ip}:{port}"
            root_data = self._http_get_json(f"{base_url}/", timeout, verify_ssl=False)

        if root_data is None:
            return probe  # Can't connect

        if isinstance(root_data, dict) and root_data.get("_auth_required"):
            probe["auth_required"] = True
            probe["evidence"] = f"Elasticsearch on {ip}:{port} requires authentication (HTTP 401/403)"
            return probe

        # Parse cluster info
        if isinstance(root_data, dict):
            probe["accessible"] = True
            probe["version"] = root_data.get("version", {}).get("number")
            probe["cluster_name"] = root_data.get("cluster_name")
            probe["details"]["cluster_info"] = {
                "name": root_data.get("name"),
                "cluster_name": root_data.get("cluster_name"),
                "cluster_uuid": root_data.get("cluster_uuid"),
                "version": root_data.get("version", {}).get("number"),
                "tagline": root_data.get("tagline"),
            }

        # Step 2: Index listing
        indices_data = self._http_get_text(f"{base_url}/_cat/indices?v&s=store.size:desc", timeout)
        if indices_data:
            lines = [l.strip() for l in indices_data.strip().split("\n") if l.strip()]
            # First line is header, rest are indices
            index_count = max(0, len(lines) - 1)
            probe["indices_count"] = index_count
            # Store first 20 index names as sample
            index_names = []
            for line in lines[1:21]:
                parts = line.split()
                if len(parts) >= 3:
                    index_names.append(parts[2])  # Index name is typically 3rd column
            probe["details"]["sample_indices"] = index_names

        # Build evidence
        cluster = probe.get("cluster_name", "unknown")
        version = probe.get("version", "unknown")
        idx_count = probe.get("indices_count", 0)
        probe["evidence"] = (
            f"Elasticsearch cluster '{cluster}' (v{version}) accessible without "
            f"authentication on {ip}:{port}"
        )
        if idx_count:
            probe["evidence"] += f" — {idx_count} indices exposed"

        return probe

    # -------------------------------------------------------------------
    # MongoDB probe
    # -------------------------------------------------------------------

    def _probe_mongodb(
        self, ip: str, port: int, timeout: int
    ) -> Optional[Dict[str, Any]]:
        """
        Probe MongoDB for unauthenticated access.

        Attempts to connect without credentials and list databases.
        """
        probe: Dict[str, Any] = {
            "ip": ip,
            "port": port,
            "service": "mongodb",
            "accessible": False,
            "auth_required": False,
            "version": None,
            "details": {},
        }

        try:
            from pymongo import MongoClient
            from pymongo.errors import (
                ConnectionFailure,
                OperationFailure,
                ServerSelectionTimeoutError,
            )
        except ImportError:
            logger.debug("pymongo not installed — skipping MongoDB probe")
            probe["details"]["error"] = "pymongo not installed"
            return probe

        try:
            client = MongoClient(
                host=ip,
                port=port,
                serverSelectionTimeoutMS=timeout * 1000,
                connectTimeoutMS=timeout * 1000,
                socketTimeoutMS=timeout * 1000,
                directConnection=True,
            )

            # Attempt to list databases — this requires no auth if MongoDB
            # has no authentication enabled
            try:
                db_names = client.list_database_names()
                probe["accessible"] = True
                probe["database_count"] = len(db_names)
                probe["details"]["databases"] = db_names[:20]  # Sample

                # Get server info
                try:
                    server_info = client.server_info()
                    probe["version"] = server_info.get("version")
                    probe["details"]["server_info"] = {
                        "version": server_info.get("version"),
                        "git_version": server_info.get("gitVersion"),
                        "os": server_info.get("buildEnvironment", {}).get("target_os"),
                    }
                except Exception:
                    pass

                probe["evidence"] = (
                    f"MongoDB on {ip}:{port} accessible without authentication — "
                    f"{len(db_names)} database(s) exposed: "
                    f"{', '.join(db_names[:5])}"
                )
                if len(db_names) > 5:
                    probe["evidence"] += f" (and {len(db_names) - 5} more)"

            except OperationFailure as e:
                # Auth required — MongoDB responded but denied access
                if "Authentication failed" in str(e) or "unauthorized" in str(e).lower():
                    probe["auth_required"] = True
                    probe["evidence"] = f"MongoDB on {ip}:{port} requires authentication"
                else:
                    probe["details"]["error"] = str(e)

            finally:
                client.close()

        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            probe["details"]["error"] = f"Connection failed: {str(e)}"
        except Exception as e:
            probe["details"]["error"] = f"{type(e).__name__}: {str(e)}"

        return probe

    # -------------------------------------------------------------------
    # Redis probe
    # -------------------------------------------------------------------

    def _probe_redis(
        self, ip: str, port: int, timeout: int
    ) -> Optional[Dict[str, Any]]:
        """
        Probe Redis for unauthenticated access.

        Attempts PING and INFO commands without credentials.
        """
        probe: Dict[str, Any] = {
            "ip": ip,
            "port": port,
            "service": "redis",
            "accessible": False,
            "auth_required": False,
            "version": None,
            "details": {},
        }

        try:
            import redis as redis_lib
            from redis.exceptions import (
                AuthenticationError,
                ConnectionError as RedisConnectionError,
                ResponseError,
                TimeoutError as RedisTimeoutError,
            )
        except ImportError:
            logger.debug("redis-py not installed — skipping Redis probe")
            probe["details"]["error"] = "redis-py not installed"
            return probe

        try:
            r = redis_lib.Redis(
                host=ip,
                port=port,
                socket_timeout=timeout,
                socket_connect_timeout=timeout,
                decode_responses=True,
            )

            # Try PING
            try:
                pong = r.ping()
                if pong:
                    probe["accessible"] = True

                    # Get INFO
                    try:
                        info = r.info()
                        probe["version"] = info.get("redis_version")
                        probe["details"]["server_info"] = {
                            "version": info.get("redis_version"),
                            "os": info.get("os"),
                            "uptime_days": info.get("uptime_in_days"),
                            "connected_clients": info.get("connected_clients"),
                            "used_memory_human": info.get("used_memory_human"),
                            "total_keys": sum(
                                info.get(f"db{i}", {}).get("keys", 0)
                                for i in range(16)
                                if isinstance(info.get(f"db{i}"), dict)
                            ),
                        }
                    except Exception:
                        pass

                    # Get database key counts
                    try:
                        db_sizes = {}
                        for i in range(16):
                            db_key = f"db{i}"
                            if db_key in (r.info("keyspace") or {}):
                                db_info = r.info("keyspace")[db_key]
                                if isinstance(db_info, dict):
                                    db_sizes[db_key] = db_info.get("keys", 0)
                        if db_sizes:
                            probe["details"]["databases"] = db_sizes
                    except Exception:
                        pass

                    version = probe.get("version", "unknown")
                    total_keys = probe.get("details", {}).get("server_info", {}).get("total_keys", 0)
                    memory = probe.get("details", {}).get("server_info", {}).get("used_memory_human", "unknown")

                    probe["evidence"] = (
                        f"Redis (v{version}) on {ip}:{port} accessible without "
                        f"authentication — {total_keys} key(s), {memory} memory used"
                    )

            except AuthenticationError:
                probe["auth_required"] = True
                probe["evidence"] = f"Redis on {ip}:{port} requires authentication (AUTH required)"

            except (ResponseError, RedisConnectionError, RedisTimeoutError) as e:
                err_str = str(e).lower()
                if "noauth" in err_str or "auth" in err_str:
                    probe["auth_required"] = True
                    probe["evidence"] = f"Redis on {ip}:{port} requires authentication"
                else:
                    probe["details"]["error"] = str(e)

            finally:
                try:
                    r.close()
                except Exception:
                    pass

        except Exception as e:
            probe["details"]["error"] = f"{type(e).__name__}: {str(e)}"

        return probe

    # -------------------------------------------------------------------
    # HTTP helpers
    # -------------------------------------------------------------------

    def _http_get_json(
        self, url: str, timeout: int, verify_ssl: bool = True
    ) -> Optional[dict]:
        """Make an HTTP GET and parse JSON response. Returns None on failure."""
        try:
            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; BoltEdge EASM Scanner)",
                "Accept": "application/json",
            })

            ssl_ctx = None
            if url.startswith("https://") and not verify_ssl:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            response = urlopen(req, timeout=timeout, context=ssl_ctx)
            body = response.read(65536).decode("utf-8", errors="replace")
            return json.loads(body)

        except HTTPError as e:
            if e.code in (401, 403):
                return {"_auth_required": True}
            return None
        except (URLError, json.JSONDecodeError, Exception):
            return None

    def _http_get_text(
        self, url: str, timeout: int, verify_ssl: bool = True
    ) -> Optional[str]:
        """Make an HTTP GET and return response body as text. Returns None on failure."""
        try:
            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; BoltEdge EASM Scanner)",
                "Accept": "text/plain, */*",
            })

            ssl_ctx = None
            if url.startswith("https://") and not verify_ssl:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            response = urlopen(req, timeout=timeout, context=ssl_ctx)
            return response.read(65536).decode("utf-8", errors="replace")

        except (HTTPError, URLError, Exception):
            return None