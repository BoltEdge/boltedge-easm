from __future__ import annotations

import os
from typing import Dict, Any, Optional
import shodan

from app.models import ScanProfile, Asset


class ProfileBasedScanner:
    """
    Scanner that executes scans based on profile configuration
    Abstracts away the specific tools (Shodan, Nmap, etc.) from the user
    """
    
    def __init__(self):
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        if self.shodan_api_key:
            self.shodan_client = shodan.Shodan(self.shodan_api_key)
        else:
            self.shodan_client = None
    
    def scan_with_profile(
        self, 
        asset: Asset, 
        profile: ScanProfile
    ) -> Dict[str, Any]:
        """
        Execute a scan using the specified profile
        Returns combined results from all enabled engines
        """
        results = {
            "profileId": profile.id,
            "profileName": profile.name,
            "engines": {},
            "success": True,
            "errors": []
        }
        
        # Execute Shodan scan if enabled
        if profile.use_shodan:
            try:
                shodan_results = self._scan_shodan(
                    asset, 
                    include_history=profile.shodan_include_history,
                    include_cves=profile.shodan_include_cves,
                    include_dns=profile.shodan_include_dns
                )
                results["engines"]["shodan"] = shodan_results
            except Exception as e:
                results["errors"].append(f"Shodan: {str(e)}")
                results["success"] = False
        
        # Execute Nmap scan if enabled (placeholder for future)
        if profile.use_nmap:
            results["engines"]["nmap"] = {"status": "not_implemented"}
        
        # Execute Nuclei scan if enabled (placeholder for future)
        if profile.use_nuclei:
            results["engines"]["nuclei"] = {"status": "not_implemented"}
        
        # Execute SSLyze scan if enabled (placeholder for future)
        if profile.use_sslyze:
            results["engines"]["sslyze"] = {"status": "not_implemented"}
        
        return results
    
    def _scan_shodan(
        self,
        asset: Asset,
        include_history: bool = False,
        include_cves: bool = False,
        include_dns: bool = False
    ) -> Dict[str, Any]:
        """
        Scan using Shodan API with configurable depth
        """
        if not self.shodan_client:
            raise Exception("Shodan API key not configured")
        
        results = {
            "engine": "shodan",
            "asset_value": asset.value,
            "asset_type": asset.asset_type,
            "current": {},
            "history": [],
            "cves": [],
            "dns": {}
        }
        
        # Get IP address to scan
        target_ip = asset.value if asset.asset_type == "ip" else None
        
        if asset.asset_type == "domain":
            # Resolve domain to IP
            try:
                import socket
                target_ip = socket.gethostbyname(asset.value)
                results["resolved_ip"] = target_ip
            except Exception as e:
                raise Exception(f"Failed to resolve domain: {str(e)}")
        
        if not target_ip:
            raise Exception("No valid IP address to scan")
        
        # Query Shodan for host info
        try:
            host_data = self.shodan_client.host(target_ip)
        except shodan.APIError as e:
            raise Exception(f"Shodan API error: {str(e)}")
        
        # Extract current state
        results["current"] = {
            "ip": host_data.get("ip_str"),
            "hostnames": host_data.get("hostnames", []),
            "domains": host_data.get("domains", []),
            "ports": host_data.get("ports", []),
            "os": host_data.get("os"),
            "org": host_data.get("org"),
            "isp": host_data.get("isp"),
            "asn": host_data.get("asn"),
            "last_update": host_data.get("last_update"),
            "tags": host_data.get("tags", []),
        }
        
        # Extract services
        services = []
        for item in host_data.get("data", []):
            service = {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "timestamp": item.get("timestamp"),
            }
            
            # Add banner if available
            if "data" in item:
                service["banner"] = item["data"][:500]  # Limit banner size
            
            services.append(service)
        
        results["current"]["services"] = services
        
        # Include historical data if requested
        if include_history:
            history = []
            for item in host_data.get("data", []):
                history.append({
                    "timestamp": item.get("timestamp"),
                    "port": item.get("port"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                })
            results["history"] = history
        
        # Include CVEs if requested
        if include_cves:
            vulns = host_data.get("vulns", [])
            cves = []
            for cve_id in vulns:
                cve_data = vulns.get(cve_id, {}) if isinstance(vulns, dict) else {}
                cves.append({
                    "cve_id": cve_id,
                    "cvss": cve_data.get("cvss") if isinstance(cve_data, dict) else None,
                    "summary": cve_data.get("summary") if isinstance(cve_data, dict) else None,
                })
            results["cves"] = cves
        
        # Include DNS info if requested (for domains)
        if include_dns and asset.asset_type == "domain":
            try:
                dns_data = self.shodan_client.dns.domain_info(asset.value)
                results["dns"] = {
                    "domain": dns_data.get("domain"),
                    "subdomains": dns_data.get("subdomains", []),
                    "tags": dns_data.get("tags", []),
                }
            except Exception as e:
                results["dns"] = {"error": str(e)}
        
        return results


# Global scanner instance
scanner = ProfileBasedScanner()