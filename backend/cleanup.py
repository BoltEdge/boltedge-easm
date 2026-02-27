#!/usr/bin/env python3
"""
cleanup_duplicate_findings.py

Removes duplicate findings from the database caused by the dedup bug.
For each (asset_id, dedupe_key) pair with multiple rows, keeps the OLDEST
finding (preserving first_seen_at) and deletes the rest.

Usage:
    # Dry run (shows what would be deleted, no changes):
    python cleanup_duplicate_findings.py

    # Actually delete:
    python cleanup_duplicate_findings.py --commit

Run from your project root (where app/ lives).
"""

import sys
import os

# Ensure the app is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.extensions import db
from app.models import Finding
from sqlalchemy import func

def cleanup(commit=False):
    app = create_app()

    with app.app_context():
        # Find all (asset_id, dedupe_key) combos that have more than 1 row
        dupes = (
            db.session.query(
                Finding.asset_id,
                Finding.dedupe_key,
                func.count(Finding.id).label("cnt"),
                func.min(Finding.id).label("keep_id"),
            )
            .filter(Finding.dedupe_key.isnot(None))
            .group_by(Finding.asset_id, Finding.dedupe_key)
            .having(func.count(Finding.id) > 1)
            .all()
        )

        if not dupes:
            print("No duplicate findings found. Database is clean.")
            return

        total_dupes = sum(row.cnt - 1 for row in dupes)
        total_groups = len(dupes)

        print(f"Found {total_groups} dedupe groups with {total_dupes} duplicate rows to remove.\n")

        deleted = 0
        for row in dupes:
            asset_id = row.asset_id
            dedupe_key = row.dedupe_key
            keep_id = row.keep_id  # oldest row (lowest ID)
            count = row.cnt

            # Get the row we're keeping to update its last_seen_at
            keeper = db.session.get(Finding, keep_id)

            # Get all duplicates (everything except the keeper)
            extras = (
                Finding.query
                .filter(
                    Finding.asset_id == asset_id,
                    Finding.dedupe_key == dedupe_key,
                    Finding.id != keep_id,
                )
                .order_by(Finding.id.desc())
                .all()
            )

            if keeper and extras:
                # Carry forward the latest last_seen_at from any duplicate
                latest_seen = keeper.last_seen_at
                latest_severity = keeper.severity
                for extra in extras:
                    if extra.last_seen_at and (not latest_seen or extra.last_seen_at > latest_seen):
                        latest_seen = extra.last_seen_at
                    # Keep the highest severity if it changed
                    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                    if sev_order.get(extra.severity, 5) < sev_order.get(latest_severity, 5):
                        latest_severity = extra.severity

                keeper.last_seen_at = latest_seen
                keeper.severity = latest_severity

                print(f"  [{asset_id}] {keeper.title[:60]:<60} — keeping #{keep_id}, deleting {len(extras)} dupes")

                for extra in extras:
                    db.session.delete(extra)
                    deleted += 1

        print(f"\n{'=' * 60}")
        print(f"Total: {deleted} duplicate findings to remove")
        print(f"       {total_groups} unique findings preserved")

        if commit:
            db.session.commit()
            print(f"\nDONE — {deleted} duplicates deleted and committed.")
        else:
            db.session.rollback()
            print(f"\nDRY RUN — no changes made. Run with --commit to apply.")


if __name__ == "__main__":
    do_commit = "--commit" in sys.argv
    cleanup(commit=do_commit)