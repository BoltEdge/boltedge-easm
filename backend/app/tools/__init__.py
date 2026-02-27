# app/tools/__init__.py
"""
Quick-check tools — lightweight on-demand lookups.

These are NOT scan jobs. They don't create assets, findings, or persist anything.
They run synchronously and return results immediately.

Endpoints:
    PUBLIC (no auth required — available on marketing site for lead gen):
        POST /tools/public/cert-lookup
        POST /tools/public/dns-lookup
        POST /tools/public/header-check

    AUTHENTICATED (full results, available in EASM UI):
        POST /tools/cert-lookup
        POST /tools/dns-lookup
        POST /tools/header-check
"""

from app.tools.routes import tools_bp

__all__ = ["tools_bp"]