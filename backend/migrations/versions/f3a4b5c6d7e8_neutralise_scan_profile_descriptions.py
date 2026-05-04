"""neutralise customer-facing scan profile descriptions

Revision ID: f3a4b5c6d7e8
Revises: e2f3a4b5c6d7
Create Date: 2026-05-04 16:30:00.000000

The seeded system scan-profile descriptions named the underlying
scanner tools (Shodan, Nmap, Nuclei, SSLyze) explicitly. Those
descriptions reach the customer-facing scan-profile picker in the
UI. We don't expose third-party tool names anywhere else (they're
mapped to friendly labels via frontend/app/lib/scanner-labels.ts),
so keeping them in profile descriptions was an inconsistency.

This migration updates existing system-profile rows in place so
deployed environments get the clean copy on the next
`flask db upgrade`. The 06fc508c2770 seed migration is also
edited so new installs come up correct from the start.
"""
from alembic import op


revision = 'f3a4b5c6d7e8'
down_revision = 'e2f3a4b5c6d7'
branch_labels = None
depends_on = None


_NEUTRAL_DESCRIPTIONS = {
    "Quick Scan":    "Fast surface-level check — basic asset reconnaissance",
    "Standard Scan": "Port scan with CVE enrichment for everyday monitoring",
    "Deep Scan":     "Wider port range plus comprehensive vulnerability scanning",
    "Full Scan":     "Comprehensive scan covering every engine — port scanning, vulnerability checks, and TLS analysis",
}


def upgrade():
    for name, description in _NEUTRAL_DESCRIPTIONS.items():
        op.execute(
            "UPDATE scan_profile "
            f"SET description = '{description}' "
            f"WHERE name = '{name}' AND is_system = TRUE;"
        )


def downgrade():
    # Restore the original tool-named descriptions for traceability.
    _ORIGINAL = {
        "Quick Scan":    "Fast Shodan host lookup — basic information only",
        "Standard Scan": "Shodan + Nmap top-1000 port scan with CVE enrichment",
        "Deep Scan":     "Shodan + wider Nmap port range + Nuclei vulnerability templates",
        "Full Scan":     "Comprehensive scan — every engine (Shodan, Nmap, Nuclei, SSLyze) on the full port range",
    }
    for name, description in _ORIGINAL.items():
        op.execute(
            "UPDATE scan_profile "
            f"SET description = '{description}' "
            f"WHERE name = '{name}' AND is_system = TRUE;"
        )
