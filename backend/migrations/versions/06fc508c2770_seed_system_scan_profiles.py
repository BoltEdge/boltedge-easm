"""seed system scan profiles

Revision ID: 06fc508c2770
Revises: bda233dcf660
Create Date: 2026-05-01 08:39:46.015821

The 029c573fe4a1 migration tried to seed Quick / Standard / Deep system
profiles but used SQLite-only syntax (`datetime('now')`, integer-literal
booleans), so on PostgreSQL the INSERT failed and `scan_profile` was left
empty. That's why the profile dropdowns are empty everywhere (scan page,
scan scheduling, etc.). This migration seeds the three system profiles
idempotently with portable SQL.
"""
from alembic import op


revision = '06fc508c2770'
down_revision = 'bda233dcf660'
branch_labels = None
depends_on = None


_SYSTEM_PROFILES = [
    {
        "name": "Quick Scan",
        "description": "Fast Shodan host lookup — basic information only",
        "is_default": False,
        "use_shodan": True, "use_nmap": False, "use_nuclei": False, "use_sslyze": False,
        "shodan_include_history": False, "shodan_include_cves": False, "shodan_include_dns": False,
        "nmap_port_range": "1-1000",
        "nuclei_severity_filter": None,
        "timeout_seconds": 60,
    },
    {
        "name": "Standard Scan",
        "description": "Shodan + Nmap top-1000 port scan with CVE enrichment",
        "is_default": True,
        "use_shodan": True, "use_nmap": True, "use_nuclei": False, "use_sslyze": False,
        "shodan_include_history": True, "shodan_include_cves": True, "shodan_include_dns": False,
        "nmap_port_range": "1-1000",
        "nuclei_severity_filter": None,
        "timeout_seconds": 600,
    },
    {
        "name": "Deep Scan",
        "description": "Shodan + wider Nmap port range + Nuclei vulnerability templates",
        "is_default": False,
        "use_shodan": True, "use_nmap": True, "use_nuclei": True, "use_sslyze": False,
        "shodan_include_history": True, "shodan_include_cves": True, "shodan_include_dns": True,
        "nmap_port_range": "1-5000",
        "nuclei_severity_filter": "critical,high,medium",
        "timeout_seconds": 1800,
    },
    {
        "name": "Full Scan",
        "description": "Comprehensive scan — every engine (Shodan, Nmap, Nuclei, SSLyze) on the full port range",
        "is_default": False,
        "use_shodan": True, "use_nmap": True, "use_nuclei": True, "use_sslyze": True,
        "shodan_include_history": True, "shodan_include_cves": True, "shodan_include_dns": True,
        "nmap_port_range": "1-65535",
        "nuclei_severity_filter": "critical,high,medium",
        "timeout_seconds": 3600,
    },
]


def upgrade():
    for p in _SYSTEM_PROFILES:
        op.execute(
            f"""
            INSERT INTO scan_profile (
                organization_id, user_id, name, description,
                is_system, is_default, is_active,
                use_shodan, use_nmap, use_nuclei, use_sslyze,
                shodan_include_history, shodan_include_cves, shodan_include_dns,
                nmap_scan_type, nmap_port_range, nuclei_severity_filter,
                timeout_seconds, created_at, updated_at
            )
            SELECT
                NULL, NULL, '{p["name"]}', '{p["description"]}',
                TRUE, {str(p["is_default"]).upper()}, TRUE,
                {str(p["use_shodan"]).upper()}, {str(p["use_nmap"]).upper()},
                {str(p["use_nuclei"]).upper()}, {str(p["use_sslyze"]).upper()},
                {str(p["shodan_include_history"]).upper()},
                {str(p["shodan_include_cves"]).upper()},
                {str(p["shodan_include_dns"]).upper()},
                'standard', '{p["nmap_port_range"]}',
                {f"'{p['nuclei_severity_filter']}'" if p["nuclei_severity_filter"] else "NULL"},
                {p["timeout_seconds"]}, NOW(), NOW()
            WHERE NOT EXISTS (
                SELECT 1 FROM scan_profile
                WHERE name = '{p["name"]}' AND is_system = TRUE
            );
            """
        )

    # Make Standard Scan the only system default — corrects environments
    # that were already seeded with a different default and is a no-op
    # otherwise. Idempotent.
    op.execute(
        "UPDATE scan_profile SET is_default = FALSE "
        "WHERE is_system = TRUE AND name <> 'Standard Scan';"
    )
    op.execute(
        "UPDATE scan_profile SET is_default = TRUE "
        "WHERE is_system = TRUE AND name = 'Standard Scan';"
    )


def downgrade():
    op.execute(
        "DELETE FROM scan_profile WHERE is_system = TRUE "
        "AND name IN ('Quick Scan', 'Standard Scan', 'Deep Scan', 'Full Scan');"
    )
