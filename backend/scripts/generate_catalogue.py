#!/usr/bin/env python3
"""
Regenerate the finding-template catalogue (docs/finding-templates.md)
from the live registry in app/scanner/templates.py.

Usage:
    # Regenerate the catalogue file
    python backend/scripts/generate_catalogue.py

    # CI / drift detection — exit 1 if the file is out of sync
    python backend/scripts/generate_catalogue.py --check

The script intentionally avoids importing the Flask app context so it
works in lightweight CI environments without a database, secrets, or
full dependency tree. It loads only `templates.py`.
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import sys


# Resolve repo paths relative to this script. Works regardless of cwd.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SCRIPT_DIR)
REPO_ROOT = os.path.dirname(BACKEND_DIR)
TEMPLATES_PATH = os.path.join(BACKEND_DIR, "app", "scanner", "templates.py")
CATALOGUE_PATH = os.path.join(REPO_ROOT, "docs", "finding-templates.md")
# Emitted alongside the catalogue and read at build time by the
# frontend /coverage page. Living under frontend/data/ rather than
# frontend/public/ means it's baked into the bundle at build time
# (SSR-friendly, no runtime fetch, no runtime backend dependency for
# a marketing page).
COVERAGE_JSON_PATH = os.path.join(REPO_ROOT, "frontend", "data", "coverage.json")


# Section keying — prefix-based grouping with display order. Mirrors the
# section comments in templates.py so the doc structure tracks the source.
SECTIONS = [
    ("dns-",        "DNS / Email Security"),
    ("takeover-",   "Subdomain Takeover"),
    ("cloud-",      "Cloud Asset Exposure"),
    ("leak-",       "Sensitive Path / Leak Detection"),
    ("nuclei-cve-", "Nuclei — Marquee CVEs"),
    ("nuclei-",     "Nuclei — Other (panels, default-creds, misconfig, info-disclosure, generic)"),
    ("ssl-",        "SSL / TLS"),
    ("header-",     "HTTP Security Headers"),
    ("http-",       "HTTP / Redirects"),
    ("cookie-",     "Cookie Security"),
    ("port-",       "Ports / Services"),
    ("cve-",        "CVE / Vulnerabilities"),
    ("tech-",       "Technology Detection"),
    ("exposure-",   "Exposure Score"),
    ("monitor-",    "Monitoring / Change Detection"),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _load_templates_module():
    """Load templates.py without going through the Flask app package init."""
    spec = importlib.util.spec_from_file_location("templates", TEMPLATES_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {TEMPLATES_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["templates"] = mod
    spec.loader.exec_module(mod)
    return mod


def _bucket_templates(templates: dict) -> dict:
    """Group templates by section key, in declared order."""
    buckets: dict = {label: [] for _, label in SECTIONS}
    for tid, t in sorted(templates.items()):
        matched = False
        for prefix, label in SECTIONS:
            if tid.startswith(prefix):
                buckets[label].append(t)
                matched = True
                break
        if not matched:
            buckets.setdefault("Other", []).append(t)
    return buckets


def _sev_rank(t):
    return (SEVERITY_ORDER.get((t.severity or "info").lower(), 5), t.template_id)


def _fmt_block(text: str | None) -> str:
    """Render a body block as a Markdown blockquote."""
    if not text:
        return "_(none)_"
    return "\n".join(
        "> " + line if line.strip() else ">"
        for line in text.splitlines()
    )


def render_catalogue(mod) -> str:
    """Render the complete catalogue Markdown."""
    templates = mod.get_all_templates()
    buckets = _bucket_templates(templates)
    today = datetime.date.today().isoformat()

    lines: list[str] = []
    lines.append("# Nano EASM — Finding Template Catalogue")
    lines.append("")
    lines.append(f"_Auto-generated from `backend/app/scanner/templates.py` on {today}._")
    lines.append("")
    lines.append(f"**Total templates registered: {len(templates)}**")
    lines.append("")
    lines.append(
        "This catalogue is the single source of truth for every finding "
        "the platform produces. Each template carries the title, "
        "description, remediation, severity, CWE, references, and "
        "monitoring metadata that gets surfaced in the UI, in PDF "
        "reports, in email alerts, and inside the Nano EASM Assistant "
        "explainer."
    )
    lines.append("")
    lines.append(
        "Placeholders rendered at scan time: `{asset}`, `{value}`, "
        "`{port}`, `{provider}`, `{url}`, `{cname_target}`, `{service}`, "
        "`{cve}`, `{header_name}`, `{path}`. Missing placeholders are "
        "left intact rather than blanked out."
    )
    lines.append("")
    lines.append("## Index")
    lines.append("")
    for prefix, label in SECTIONS:
        items = buckets.get(label, [])
        if items:
            anchor = (
                label.lower()
                .replace(" / ", "--")
                .replace(" — ", "--")
                .replace(" ", "-")
                .replace("(", "")
                .replace(")", "")
                .replace(",", "")
            )
            plural = "s" if len(items) != 1 else ""
            lines.append(f"- [{label}](#{anchor}) — {len(items)} template{plural}")
    lines.append("")
    lines.append("## Severity legend")
    lines.append("")
    lines.append("- **critical** — Immediate-action exposure. Active credential leaks, ransomware vectors, takeover-confirmed.")
    lines.append("- **high** — Material risk that should be fixed in the current sprint.")
    lines.append("- **medium** — Should be fixed but lower priority. Hardening gaps, weak-but-not-broken configs.")
    lines.append("- **low** — Information disclosure or minor misconfiguration. Often a hardening win, not a vulnerability.")
    lines.append("- **info** — Not a problem. Inventory or change-detection records.")
    lines.append("")
    lines.append("---")
    lines.append("")

    for prefix, label in SECTIONS:
        items = buckets.get(label, [])
        if not items:
            continue
        items_sorted = sorted(items, key=_sev_rank)
        lines.append(f"## {label}")
        lines.append("")
        plural = "s" if len(items_sorted) != 1 else ""
        lines.append(f"_{len(items_sorted)} template{plural}_")
        lines.append("")
        for t in items_sorted:
            sev = (t.severity or "info").upper()
            cwe = t.cwe or "—"
            lines.append(f"### `{t.template_id}`")
            lines.append("")
            customer_cat = getattr(t, "effective_customer_category", None) or "—"
            meta_bits = [
                f"**Severity:** {sev}",
                f"**CWE:** {cwe}",
                f"**Category:** {customer_cat}",
            ]
            if t.confidence and t.confidence != "high":
                meta_bits.append(f"**Confidence:** {t.confidence}")
            if not t.tunable:
                meta_bits.append("**Tunable:** no")
            lines.append(" · ".join(meta_bits))
            lines.append("")
            lines.append(f"**Title:** {t.title}")
            lines.append("")
            if t.summary:
                lines.append(f"**Summary:** {t.summary}")
                lines.append("")
            lines.append("**Description:**")
            lines.append("")
            lines.append(_fmt_block(t.description))
            lines.append("")
            if t.remediation:
                lines.append("**Remediation:**")
                lines.append("")
                lines.append(_fmt_block(t.remediation))
                lines.append("")
            meta_lines: list[str] = []
            if t.tags:
                meta_lines.append(f"**Tags:** {', '.join(f'`{tag}`' for tag in t.tags)}")
            if t.alert_name:
                meta_lines.append(f"**Alert name:** {t.alert_name}")
            if t.monitor_type:
                meta_lines.append(f"**Monitor type:** `{t.monitor_type}`")
            if meta_lines:
                lines.extend(meta_lines)
                lines.append("")
            if t.references:
                lines.append("**References:**")
                for r in t.references:
                    lines.append(f"- {r}")
                lines.append("")
            lines.append("---")
            lines.append("")

    return "\n".join(lines)


def render_coverage_json(mod) -> str:
    """Render coverage.json — what the public /coverage page renders.

    Schema:
        {
          "totalTemplates": 341,
          "generatedOn": "2026-05-08",
          "categories": [
            {
              "id": "vulnerabilities",
              "label": "Vulnerabilities",
              "blurb": "Known CVEs and software flaws...",
              "totalCount": 53,
              "severityCounts": {"critical": 23, "high": 18, ...},
              "templates": [
                {"id": "nuclei-cve-2021-44228", "title": "Apache Log4j RCE",
                 "severity": "critical", "summary": "..."},
                ...
              ]
            },
            ...
          ]
        }

    Templates are sorted critical → info, then alphabetically by id, so
    the frontend can render them as-is without further work.
    """
    templates = mod.get_all_templates()
    customer_categories = mod.CUSTOMER_CATEGORIES
    grouped = mod.templates_by_customer_category()

    categories_payload = []
    for cid, cmeta in customer_categories.items():
        items = sorted(grouped.get(cid, []), key=_sev_rank)
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for t in items:
            sev = (t.severity or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        categories_payload.append({
            "id": cid,
            "label": cmeta["label"],
            "blurb": cmeta["blurb"],
            "totalCount": len(items),
            "severityCounts": sev_counts,
            "templates": [
                {
                    "id": t.template_id,
                    "title": t.title,
                    "severity": (t.severity or "info").lower(),
                    "summary": t.summary or "",
                    "alertName": t.alert_name or "",
                    "cwe": t.cwe or "",
                }
                for t in items
            ],
        })

    return json.dumps(
        {
            "totalTemplates": len(templates),
            "generatedOn": datetime.date.today().isoformat(),
            "categories": categories_payload,
        },
        indent=2,
        ensure_ascii=False,
    )


def _read_existing(path: str) -> str | None:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _strip_generated_date(content: str) -> str:
    """Drop the "_Auto-generated ... on YYYY-MM-DD._" line.

    Drift detection compares semantic content; the date stamp shouldn't
    fail the check just because today is different. The date will be
    refreshed on the next regen anyway.
    """
    return "\n".join(
        line for line in content.splitlines()
        if not line.startswith("_Auto-generated from")
    )


def _strip_generated_date_json(content: str) -> str:
    """Drop the `generatedOn` field from coverage.json drift comparison.

    Same idea as the markdown version — the date stamp shouldn't fail
    drift detection just because today is a different day.
    """
    try:
        parsed = json.loads(content)
        parsed.pop("generatedOn", None)
        return json.dumps(parsed, indent=2, ensure_ascii=False, sort_keys=True)
    except Exception:
        return content


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the catalogue or coverage.json is out of sync. Doesn't write.",
    )
    args = parser.parse_args()

    mod = _load_templates_module()
    rendered_md = render_catalogue(mod)
    rendered_json = render_coverage_json(mod)

    if args.check:
        existing_md = _read_existing(CATALOGUE_PATH)
        if existing_md is None:
            print(f"ERROR: {CATALOGUE_PATH} does not exist; run without --check to create.")
            return 1
        existing_json = _read_existing(COVERAGE_JSON_PATH)
        md_ok = _strip_generated_date(existing_md) == _strip_generated_date(rendered_md)
        json_ok = (
            existing_json is not None
            and _strip_generated_date_json(existing_json) == _strip_generated_date_json(rendered_json)
        )
        if md_ok and json_ok:
            print(f"OK: {CATALOGUE_PATH} and {COVERAGE_JSON_PATH} are in sync with the registry.")
            return 0
        if not md_ok:
            print(f"DRIFT: {CATALOGUE_PATH} is out of sync.", file=sys.stderr)
        if not json_ok:
            print(f"DRIFT: {COVERAGE_JSON_PATH} is out of sync.", file=sys.stderr)
        print(
            "Run `python backend/scripts/generate_catalogue.py` to update.",
            file=sys.stderr,
        )
        return 1

    os.makedirs(os.path.dirname(CATALOGUE_PATH), exist_ok=True)
    with open(CATALOGUE_PATH, "w", encoding="utf-8") as f:
        f.write(rendered_md)
    print(f"Wrote {CATALOGUE_PATH}")
    print(f"  size:  {len(rendered_md):,} chars")
    print(f"  lines: {len(rendered_md.splitlines()):,}")
    print(f"  templates: {len(mod.get_all_templates())}")

    os.makedirs(os.path.dirname(COVERAGE_JSON_PATH), exist_ok=True)
    with open(COVERAGE_JSON_PATH, "w", encoding="utf-8") as f:
        f.write(rendered_json)
    print(f"Wrote {COVERAGE_JSON_PATH}")
    print(f"  size:  {len(rendered_json):,} chars")
    return 0


if __name__ == "__main__":
    sys.exit(main())
