"""
One-time backfill: enrich every unresolved CVE Finding with KEV + EPSS data.

Run once per environment after deploying the threat-intel migration:

    docker compose exec easm-backend python -m scripts.backfill_threat_intel

Idempotent — re-running just refreshes any stale data. The KEV feed is
re-fetched at the start of every run so the cache is hot before iterating.

See docs/superpowers/specs/2026-05-13-kev-epss-enrichment-design.md for
the design rationale.
"""
from __future__ import annotations

import logging
import sys
import time

from app import create_app
from app.extensions import db
from app.models import Finding
from app.scanner.threat_intel import enrich_cve, refresh_kev_feed


logger = logging.getLogger("backfill_threat_intel")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def _cve_id_for(finding: Finding) -> str | None:
    """Best-effort: pull the CVE ID from details_json or template_id."""
    details = finding.details_json or {}
    cve = details.get("cve_id")
    if cve and isinstance(cve, str):
        return cve.strip().upper()
    # Fall back to template_id pattern "cve-cve-yyyy-nnnn"
    tid = (finding.template_id or "").lower()
    if tid.startswith("cve-cve-"):
        return tid[4:].upper()
    return None


def backfill() -> int:
    """Returns count of findings updated."""
    logger.info("Refreshing KEV cache before iterating findings...")
    n = refresh_kev_feed()
    logger.info("KEV refreshed: %d entries", n)

    q = (
        Finding.query
        .filter(Finding.finding_type == "cve")
        .filter(Finding.resolved.is_(False))
        .filter(Finding.ignored.is_(False))
        .order_by(Finding.id)
    )
    total = q.count()
    logger.info("Found %d unresolved CVE findings to backfill", total)
    if total == 0:
        return 0

    updated = 0
    skipped = 0
    batch_size = 100
    start_time = time.time()

    for finding in q.yield_per(batch_size):
        cve_id = _cve_id_for(finding)
        if not cve_id:
            skipped += 1
            continue

        enrichment = enrich_cve(cve_id)
        kev = enrichment.get("kev")
        epss = enrichment.get("epss")

        finding.kev_listed = bool(kev)
        finding.epss_score = epss.get("score") if epss else None
        finding.epss_percentile = epss.get("percentile") if epss else None

        details = dict(finding.details_json or {})
        if kev:
            details["kev"] = kev
        else:
            details.pop("kev", None)
        if epss:
            details["epss"] = epss
        else:
            details.pop("epss", None)
        finding.details_json = details

        # Tags: preserve existing, append kev / epss-high when newly applicable.
        tags = list(finding.tags_json or [])
        if kev and "kev" not in tags:
            tags.append("kev")
        if (
            epss
            and epss.get("percentile") is not None
            and epss["percentile"] >= 0.9
            and "epss-high" not in tags
        ):
            tags.append("epss-high")
        finding.tags_json = tags

        updated += 1
        if updated % batch_size == 0:
            db.session.commit()
            elapsed = time.time() - start_time
            logger.info(
                "Progress: %d/%d updated (%.1fs, %.2f/s); skipped %d",
                updated, total, elapsed, updated / max(elapsed, 0.001), skipped,
            )

    db.session.commit()
    elapsed = time.time() - start_time
    logger.info(
        "Backfill complete: %d updated, %d skipped (no CVE id), %.1fs total",
        updated, skipped, elapsed,
    )
    return updated


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        try:
            backfill()
        except Exception:
            logger.exception("Backfill crashed")
            sys.exit(1)
