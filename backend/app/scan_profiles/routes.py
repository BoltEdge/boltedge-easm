# =============================================================================
# File: app/scan_profiles/routes.py
# Description: Scan profile routes for listing and viewing available scan
#   profiles (system + org-specific). Profiles control which engines run
#   (Shodan, Nmap, Nuclei, SSLyze) and their configuration.
#
# Permissions Integration (based on permissions integration guide):
#   - GET /scan-profiles: all roles can view
#     (results should be filtered by plan's allowed profiles)
#   - GET /scan-profiles/<id>: all roles can view
#   - GET /scan-profiles/default: all roles can view
#   - No role/permission/limit decorators needed for any route in this file.
#
# NOTE: The integration guide suggests filtering GET /scan-profiles results
#   by the plan's allowed profiles using:
#     limits = get_effective_limits(g.current_organization)
#     allowed = limits["scan_profiles"]
#   This is left as a TODO for when plan-based filtering is wired up.
# =============================================================================

from __future__ import annotations

from flask import Blueprint, request, jsonify
from sqlalchemy import func

from app.extensions import db
from app.models import ScanProfile
from app.auth.decorators import require_auth, current_user_id, current_organization_id

scan_profiles_bp = Blueprint("scan_profiles", __name__, url_prefix="")  

@scan_profiles_bp.get("/test")
def test_route():
    """Test route to verify blueprint is registered"""
    return jsonify(message="Scan profiles blueprint is working!"), 200

# GET /scan-profiles — all roles can view
@scan_profiles_bp.get("/scan-profiles")
@require_auth
def list_scan_profiles():
    """
    Get all scan profiles available to the organization
    Returns system profiles + organization's custom profiles
    
    TODO: Filter results by plan's allowed profiles:
        from app.billing.routes import get_effective_limits
        limits = get_effective_limits(g.current_organization)
        allowed = limits["scan_profiles"]
    """
    org_id = current_organization_id()
    
    # Get system profiles (available to all) + org-specific profiles
    profiles = (
        ScanProfile.query
        .filter(
            (ScanProfile.is_system == True) | 
            (ScanProfile.organization_id == org_id)
        )
        .filter(ScanProfile.is_active == True)
        .order_by(ScanProfile.is_system.desc(), ScanProfile.is_default.desc(), ScanProfile.name)
        .all()
    )
    
    result = []
    for profile in profiles:
        result.append({
            "id": str(profile.id),
            "name": profile.name,
            "description": profile.description,
            "isSystem": profile.is_system,
            "isDefault": profile.is_default,
            "isActive": profile.is_active,
            
            # Engines
            "useShodan": profile.use_shodan,
            "useNmap": profile.use_nmap,
            "useNuclei": profile.use_nuclei,
            "useSslyze": profile.use_sslyze,
            
            # Shodan settings
            "shodanIncludeHistory": profile.shodan_include_history,
            "shodanIncludeCves": profile.shodan_include_cves,
            "shodanIncludeDns": profile.shodan_include_dns,
            
            # Nmap settings
            "nmapScanType": profile.nmap_scan_type,
            "nmapPortRange": profile.nmap_port_range,
            
            # Nuclei settings
            "nucleiSeverityFilter": profile.nuclei_severity_filter,
            "nucleiTemplates": profile.nuclei_templates,
            
            # General
            "timeoutSeconds": profile.timeout_seconds,
            "createdAt": profile.created_at.isoformat() if profile.created_at else None,
        })
    
    return jsonify(result), 200


# GET /scan-profiles/<id> — all roles can view
@scan_profiles_bp.get("/scan-profiles/<profile_id>")
@require_auth
def get_scan_profile(profile_id: str):
    """
    Get a specific scan profile
    """
    org_id = current_organization_id()
    
    profile = ScanProfile.query.filter_by(id=int(profile_id)).first()
    
    if not profile:
        return jsonify(error="Profile not found"), 404
    
    # Check access: system profiles are available to all, custom profiles only to their org
    if not profile.is_system and profile.organization_id != org_id:
        return jsonify(error="Access denied"), 403
    
    return jsonify({
        "id": str(profile.id),
        "name": profile.name,
        "description": profile.description,
        "isSystem": profile.is_system,
        "isDefault": profile.is_default,
        "isActive": profile.is_active,
        
        # Engines
        "useShodan": profile.use_shodan,
        "useNmap": profile.use_nmap,
        "useNuclei": profile.use_nuclei,
        "useSslyze": profile.use_sslyze,
        
        # Shodan settings
        "shodanIncludeHistory": profile.shodan_include_history,
        "shodanIncludeCves": profile.shodan_include_cves,
        "shodanIncludeDns": profile.shodan_include_dns,
        
        # Nmap settings
        "nmapScanType": profile.nmap_scan_type,
        "nmapPortRange": profile.nmap_port_range,
        
        # Nuclei settings
        "nucleiSeverityFilter": profile.nuclei_severity_filter,
        "nucleiTemplates": profile.nuclei_templates,
        
        # General
        "timeoutSeconds": profile.timeout_seconds,
        "createdAt": profile.created_at.isoformat() if profile.created_at else None,
    }), 200


# GET /scan-profiles/default — all roles can view
@scan_profiles_bp.get("/scan-profiles/default")
@require_auth
def get_default_profile():
    """
    Get the default scan profile for quick scans
    """
    org_id = current_organization_id()
    
    # Try to find org-specific default first
    profile = (
        ScanProfile.query
        .filter_by(organization_id=org_id, is_default=True, is_active=True)
        .first()
    )
    
    # Fall back to system default (Quick Scan)
    if not profile:
        profile = (
            ScanProfile.query
            .filter_by(is_system=True, is_default=True, is_active=True)
            .first()
        )
    
    if not profile:
        return jsonify(error="No default profile found"), 404
    
    return jsonify({
        "id": str(profile.id),
        "name": profile.name,
        "description": profile.description,
        "isSystem": profile.is_system,
        "isDefault": profile.is_default,
    }), 200