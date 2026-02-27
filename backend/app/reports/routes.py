# =============================================================================
# File: app/reports/routes.py
# Description: Report generation and management routes.
#   Supports two scopes: organization-wide and group-level reports.
#   Supports two templates: executive summary and full technical report.
#   PDF generation uses xhtml2pdf with Matplotlib charts embedded as base64.
#
# Permissions (following existing RBAC pattern):
#   - GET /reports: viewer+ (list reports)
#   - GET /reports/<id>: viewer+ (view report details)
#   - GET /reports/<id>/download: viewer+ (download PDF)
#   - POST /reports/generate: analyst+ (generate new report)
#   - DELETE /reports/<id>: admin+ (delete report)
#   - GET /reports/schedules: viewer+ (list schedules)
#   - POST /reports/schedules: admin+ (create schedule)
#   - PATCH /reports/schedules/<id>: admin+ (update schedule)
#   - DELETE /reports/schedules/<id>: admin+ (delete schedule)
# =============================================================================

from __future__ import annotations

import os
import io
import math
import uuid
import base64
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, send_file, current_app
from sqlalchemy import desc
from app.extensions import db
from app.models import (
    Report, ReportSchedule, Organization, AssetGroup, Asset, Finding,
    OrganizationMember, User,
)
from app.auth.decorators import (
    require_auth, current_user_id, current_organization_id, current_role,
)
from app.auth.permissions import require_role, require_permission
from app.audit.routes import log_audit

# Matplotlib — use non-interactive backend for server-side rendering
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import numpy as np

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


# ────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────

def _reports_dir() -> str:
    """Get the reports storage directory, creating it if needed."""
    base = current_app.config.get("REPORTS_DIR", os.path.join(current_app.instance_path, "reports"))
    os.makedirs(base, exist_ok=True)
    return base


def _sid(x) -> str:
    return str(x) if x is not None else ""


from app.utils.scoring import calc_exposure_score as _calc_exposure_score


# ────────────────────────────────────────────────────────────
# Chart Generation (Matplotlib → base64 PNG)
# ────────────────────────────────────────────────────────────

SEV_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#f59e0b",
    "low": "#3b82f6",
    "info": "#94a3b8",
}

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _fig_to_base64(fig) -> str:
    """Convert a matplotlib figure to a base64-encoded PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight", transparent=False, facecolor="#ffffff")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


def _chart_severity_pie(severity_counts: dict) -> str:
    """Generate a severity breakdown pie chart."""
    labels = []
    sizes = []
    colors = []
    for sev in SEV_ORDER:
        count = severity_counts.get(sev, 0)
        if count > 0:
            labels.append(f"{sev.title()} ({count})")
            sizes.append(count)
            colors.append(SEV_COLORS[sev])

    if not sizes:
        # Empty state
        fig, ax = plt.subplots(figsize=(4, 3))
        ax.text(0.5, 0.5, "No Findings", ha="center", va="center", fontsize=14, color="#94a3b8")
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis("off")
        return _fig_to_base64(fig)

    fig, ax = plt.subplots(figsize=(4, 3))
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=None,
        colors=colors,
        autopct=lambda pct: f"{pct:.0f}%" if pct > 5 else "",
        startangle=90,
        pctdistance=0.75,
        wedgeprops={"linewidth": 2, "edgecolor": "white"},
    )
    for t in autotexts:
        t.set_fontsize(9)
        t.set_fontweight("bold")
        t.set_color("white")

    ax.legend(
        labels,
        loc="center left",
        bbox_to_anchor=(1, 0.5),
        fontsize=8,
        frameon=False,
    )
    ax.set_title("Findings by Severity", fontsize=11, fontweight="bold", pad=12, color="#1e293b")

    return _fig_to_base64(fig)


def _chart_findings_by_group(findings_by_group: dict) -> str:
    """Generate a horizontal bar chart of findings by group."""
    if not findings_by_group:
        fig, ax = plt.subplots(figsize=(5, 2))
        ax.text(0.5, 0.5, "No Group Data", ha="center", va="center", fontsize=14, color="#94a3b8")
        ax.axis("off")
        return _fig_to_base64(fig)

    # Sort by total findings descending, take top 8
    sorted_groups = sorted(findings_by_group.items(), key=lambda x: x[1].get("total", 0), reverse=True)[:8]
    sorted_groups.reverse()  # Reverse for horizontal bar (top = highest)

    group_names = [g[0][:25] + ("..." if len(g[0]) > 25 else "") for g in sorted_groups]
    n = len(group_names)
    bar_height = max(2.5, n * 0.5 + 1)

    fig, ax = plt.subplots(figsize=(5, bar_height))
    y_pos = np.arange(n)

    # Stacked horizontal bars
    left = np.zeros(n)
    for sev in SEV_ORDER:
        values = [g[1].get(sev, 0) for g in sorted_groups]
        if sum(values) > 0:
            ax.barh(y_pos, values, left=left, color=SEV_COLORS[sev], label=sev.title(), height=0.6, edgecolor="white", linewidth=0.5)
            left += np.array(values)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(group_names, fontsize=8, color="#475569")
    ax.set_xlabel("Findings", fontsize=9, color="#64748b")
    ax.set_title("Findings by Group", fontsize=11, fontweight="bold", color="#1e293b", pad=12)
    ax.legend(fontsize=7, loc="lower right", frameon=False)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#e2e8f0")
    ax.spines["bottom"].set_color("#e2e8f0")
    ax.tick_params(axis="x", colors="#94a3b8", labelsize=8)

    return _fig_to_base64(fig)


def _chart_exposure_gauge(score: float) -> str:
    """Generate an exposure score gauge chart."""
    fig, ax = plt.subplots(figsize=(3.5, 2.2))

    # Draw arc
    theta = np.linspace(np.pi, 0, 100)
    r_outer = 1.0
    r_inner = 0.65

    # Background arc (gray)
    for i in range(len(theta) - 1):
        ax.fill_between(
            [r_outer * np.cos(theta[i]), r_outer * np.cos(theta[i + 1])],
            [r_outer * np.sin(theta[i]), r_outer * np.sin(theta[i + 1])],
            [r_inner * np.sin(theta[i]), r_inner * np.sin(theta[i + 1])],
            color="#e2e8f0",
        )

    # Colored arc based on score
    score_pct = min(score / 100.0, 1.0)
    n_filled = int(score_pct * (len(theta) - 1))

    for i in range(n_filled):
        pct = i / (len(theta) - 1)
        if pct < 0.4:
            color = "#10b981"
        elif pct < 0.7:
            color = "#f59e0b"
        else:
            color = "#ef4444"

        x = [r_outer * np.cos(theta[i]), r_outer * np.cos(theta[i + 1]),
             r_inner * np.cos(theta[i + 1]), r_inner * np.cos(theta[i])]
        y = [r_outer * np.sin(theta[i]), r_outer * np.sin(theta[i + 1]),
             r_inner * np.sin(theta[i + 1]), r_inner * np.sin(theta[i])]
        ax.fill(x, y, color=color)

    # Score text in center
    score_color = "#10b981" if score < 40 else "#f59e0b" if score < 70 else "#ef4444"
    ax.text(0, 0.35, f"{score:.0f}", ha="center", va="center", fontsize=28, fontweight="bold", color=score_color)
    ax.text(0, 0.08, "/ 100", ha="center", va="center", fontsize=9, color="#94a3b8")
    ax.text(0, -0.15, "EXPOSURE SCORE", ha="center", va="center", fontsize=7, fontweight="bold", color="#64748b")

    ax.set_xlim(-1.3, 1.3)
    ax.set_ylim(-0.35, 1.15)
    ax.set_aspect("equal")
    ax.axis("off")

    return _fig_to_base64(fig)


def _chart_category_bar(category_counts: dict) -> str:
    """Generate a vertical bar chart of findings by category."""
    if not category_counts:
        fig, ax = plt.subplots(figsize=(4, 2.5))
        ax.text(0.5, 0.5, "No Category Data", ha="center", va="center", fontsize=14, color="#94a3b8")
        ax.axis("off")
        return _fig_to_base64(fig)

    # Sort by count descending, top 8
    sorted_cats = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    cat_names = [c[0].title()[:15] for c in sorted_cats]
    cat_values = [c[1] for c in sorted_cats]

    fig, ax = plt.subplots(figsize=(5, 3))
    bars = ax.bar(
        range(len(cat_names)), cat_values,
        color="#0d9488", edgecolor="white", linewidth=0.5, width=0.6,
    )
    ax.set_xticks(range(len(cat_names)))
    ax.set_xticklabels(cat_names, fontsize=7, rotation=35, ha="right", color="#475569")
    ax.set_ylabel("Count", fontsize=9, color="#64748b")
    ax.set_title("Findings by Category", fontsize=11, fontweight="bold", color="#1e293b", pad=12)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#e2e8f0")
    ax.spines["bottom"].set_color("#e2e8f0")
    ax.tick_params(axis="y", colors="#94a3b8", labelsize=8)

    # Value labels on bars
    for bar, val in zip(bars, cat_values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                str(val), ha="center", va="bottom", fontsize=8, fontweight="bold", color="#475569")

    return _fig_to_base64(fig)


# ────────────────────────────────────────────────────────────
# Data Gathering
# ────────────────────────────────────────────────────────────

def _gather_report_data(org_id: int, scope: str, group_id: int | None, config: dict | None) -> dict:
    """
    Gather all data needed to populate a report.
    Scoped to organization or a single group.
    Returns a dict with all sections for the WH Framework.
    """
    config = config or {}
    include_ignored = config.get("includeIgnored", False)

    # ── Base queries scoped by org ──
    asset_query = Asset.query.filter(Asset.organization_id == org_id)
    finding_query = (
        db.session.query(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id)
    )

    # ── Scope to group if needed ──
    if scope == "group" and group_id:
        asset_query = asset_query.filter(Asset.group_id == group_id)
        finding_query = finding_query.filter(Asset.group_id == group_id)

    # ── Count suppressed findings before filtering ──
    suppressed_query = finding_query.filter(Finding.ignored == True)
    if scope == "group" and group_id:
        suppressed_count = suppressed_query.count()
    else:
        suppressed_count = suppressed_query.count()

    # ── Filter suppressed findings ──
    if not include_ignored:
        finding_query = finding_query.filter(
            db.or_(Finding.ignored == False, Finding.ignored == None)
        )

    # ── Severity filter from config ──
    severity_filter = config.get("severity")
    if severity_filter and severity_filter != "all":
        severities = [s.strip() for s in severity_filter.split(",")]
        finding_query = finding_query.filter(Finding.severity.in_(severities))

    # ── Assets ──
    assets = asset_query.all()
    asset_count = len(assets)

    # ── Groups ──
    if scope == "group" and group_id:
        groups = AssetGroup.query.filter_by(id=group_id, organization_id=org_id).all()
    else:
        groups = AssetGroup.query.filter_by(organization_id=org_id, is_active=True).all()
    group_count = len(groups)

    # ── Findings ──
    findings = finding_query.all()
    total_findings = len(findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    category_counts = {}
    findings_by_group = {}
    findings_by_asset = {}

    for f in findings:
        sev = f.severity or "info"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        cat = getattr(f, "category", None) or "uncategorized"
        category_counts[cat] = category_counts.get(cat, 0) + 1

        # Group breakdown
        a = f.asset
        g = a.group if a else None
        gname = g.name if g else "Ungrouped"
        if gname not in findings_by_group:
            findings_by_group[gname] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        findings_by_group[gname][sev] = findings_by_group[gname].get(sev, 0) + 1
        findings_by_group[gname]["total"] += 1

        # Asset breakdown
        aval = a.value if a else "Unknown"
        if aval not in findings_by_asset:
            findings_by_asset[aval] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "type": a.asset_type if a else ""}
        findings_by_asset[aval][sev] = findings_by_asset[aval].get(sev, 0) + 1
        findings_by_asset[aval]["total"] += 1

    # ── Exposure Score ──
    exposure_score = _calc_exposure_score(
        severity_counts["critical"],
        severity_counts["high"],
        severity_counts["medium"],
        severity_counts["low"],
    )

    # ── Top risky assets (by weighted score) ──
    asset_risk_list = []
    for aval, data in findings_by_asset.items():
        weighted = (data["critical"] * 10) + (data["high"] * 4) + (data["medium"] * 1.5) + (data["low"] * 0.3)
        asset_risk_list.append({"value": aval, "type": data["type"], **data, "weightedScore": round(weighted, 1)})
    asset_risk_list.sort(key=lambda x: x["weightedScore"], reverse=True)
    top_risky_assets = asset_risk_list[:10]

    # ── Deduplicate findings by (title + asset + severity) ──
    # Multiple scans can produce the same finding — show each unique finding once
    seen_keys = set()

    def _dedupe_key(f) -> str:
        a = f.asset
        return f"{f.title}|{a.value if a else ''}|{f.severity or 'info'}"

    # ── Top findings (critical + high, for executive summary) ──
    top_findings = []
    seen_top = set()
    for f in findings:
        if f.severity in ("critical", "high"):
            dk = _dedupe_key(f)
            if dk in seen_top:
                continue
            seen_top.add(dk)
            a = f.asset
            top_findings.append({
                "id": _sid(f.id),
                "title": f.title,
                "severity": f.severity,
                "category": getattr(f, "category", None),
                "asset": a.value if a else "",
                "assetType": a.asset_type if a else "",
                "remediation": getattr(f, "remediation", None),
                "cwe": getattr(f, "cwe", None),
                "confidence": getattr(f, "confidence", None),
                "detectedAt": f.created_at.isoformat() if f.created_at else None,
            })
    top_findings.sort(key=lambda x: 0 if x["severity"] == "critical" else 1)
    top_findings = top_findings[:20]

    # ── All findings (for technical report) — deduplicated ──
    all_findings = []
    seen_all = set()
    for f in findings:
        dk = _dedupe_key(f)
        if dk in seen_all:
            continue
        seen_all.add(dk)
        a = f.asset
        g = a.group if a else None
        all_findings.append({
            "id": _sid(f.id),
            "title": f.title,
            "severity": f.severity or "info",
            "category": getattr(f, "category", None),
            "description": f.description or "",
            "remediation": getattr(f, "remediation", None),
            "cwe": getattr(f, "cwe", None),
            "confidence": getattr(f, "confidence", None),
            "engine": getattr(f, "engine", None),
            "templateId": getattr(f, "template_id", None),
            "asset": a.value if a else "",
            "assetType": a.asset_type if a else "",
            "group": g.name if g else "",
            "detectedAt": f.created_at.isoformat() if f.created_at else None,
            "ignored": bool(f.ignored),
        })
    # ── Organization info ──
    org = Organization.query.get(org_id)

    # ── Team members (WHO section) ──
    members = (
        db.session.query(OrganizationMember, User)
        .join(User, OrganizationMember.user_id == User.id)
        .filter(OrganizationMember.organization_id == org_id, OrganizationMember.is_active == True)
        .all()
    )
    team = [
        {"name": u.name or u.email, "email": u.email, "role": m.role}
        for m, u in members
    ]

    # ── Generate charts ──
    charts = {
        "severityPie": _chart_severity_pie(severity_counts),
        "findingsByGroup": _chart_findings_by_group(findings_by_group),
        "exposureGauge": _chart_exposure_gauge(exposure_score),
        "categoryBar": _chart_category_bar(category_counts),
    }

    return {
        "organization": {
            "name": org.name if org else "",
            "industry": org.industry if org else None,
            "website": org.website if org else None,
            "plan": org.plan if org else "free",
        },
        "scope": scope,
        "groupName": groups[0].name if scope == "group" and groups else None,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "exposureScore": exposure_score,
            "totalFindings": total_findings,
            "assetCount": asset_count,
            "groupCount": group_count,
            "severityCounts": severity_counts,
            "categoryCounts": category_counts,
            "suppressedCount": suppressed_count,
            "includeSuppressed": include_ignored,
        },
        "who": {
            "team": team,
            "findingsByGroup": findings_by_group,
        },
        "what": {
            "severityCounts": severity_counts,
            "categoryCounts": category_counts,
            "topFindings": top_findings,
            "allFindings": all_findings,
        },
        "where": {
            "assetCount": asset_count,
            "groupCount": group_count,
            "topRiskyAssets": top_risky_assets,
            "findingsByGroup": findings_by_group,
        },
        "when": {
            "reportDate": datetime.now(timezone.utc).isoformat(),
            "trending": None,
        },
        "how": {
            "engines": _get_engines_used(findings),
            "totalScanned": asset_count,
        },
        "charts": charts,
    }


def _get_engines_used(findings: list) -> list[str]:
    """Extract unique scan engines from findings."""
    engines = set()
    for f in findings:
        engine = getattr(f, "engine", None)
        if engine:
            engines.add(engine)
    return sorted(engines)


def _report_to_dict(r: Report) -> dict:
    """Serialize a Report model to a frontend-friendly dict."""
    return {
        "id": _sid(r.id),
        "title": r.title,
        "template": r.template,
        "format": r.format,
        "scope": r.scope,
        "groupId": _sid(r.group_id) if r.group_id else None,
        "groupName": r.group_name,
        "status": r.status,
        "errorMessage": r.error_message,
        "config": r.config,
        "fileSize": r.file_size,
        "summaryData": r.summary_data,
        "generatedBy": _sid(r.generated_by) if r.generated_by else None,
        "generatedAt": r.generated_at.isoformat() if r.generated_at else None,
        "createdAt": r.created_at.isoformat() if r.created_at else None,
    }


def _schedule_to_dict(s: ReportSchedule) -> dict:
    """Serialize a ReportSchedule model to a frontend-friendly dict."""
    return {
        "id": _sid(s.id),
        "name": s.name,
        "template": s.template,
        "scope": s.scope,
        "groupId": _sid(s.group_id) if s.group_id else None,
        "frequency": s.frequency,
        "dayOfWeek": s.day_of_week,
        "dayOfMonth": s.day_of_month,
        "hour": s.hour,
        "recipients": s.recipients or [],
        "includePdfAttachment": s.include_pdf_attachment,
        "enabled": s.enabled,
        "lastRunAt": s.last_run_at.isoformat() if s.last_run_at else None,
        "lastReportId": _sid(s.last_report_id) if s.last_report_id else None,
        "nextRunAt": s.next_run_at.isoformat() if s.next_run_at else None,
        "runCount": s.run_count,
        "createdAt": s.created_at.isoformat() if s.created_at else None,
    }


# ────────────────────────────────────────────────────────────
# PDF Generation
# ────────────────────────────────────────────────────────────

def _generate_pdf(report: Report, data: dict) -> str:
    """
    Generate a PDF file from report data.
    Uses xhtml2pdf (pure Python) with Matplotlib charts as base64 images.
    Falls back to WeasyPrint if available, then to plain HTML.
    Returns the file path of the generated file.
    """
    filename = f"report-{report.id}-{uuid.uuid4().hex[:8]}.pdf"
    filepath = os.path.join(_reports_dir(), filename)

    html_content = _render_report_html(report, data)

    # Try xhtml2pdf first (pure Python — no system deps)
    try:
        from xhtml2pdf import pisa
        with open(filepath, "w+b") as f:
            status = pisa.CreatePDF(html_content, dest=f)
            if status.err:
                raise RuntimeError(f"xhtml2pdf error count: {status.err}")
        return filepath
    except ImportError:
        pass

    # Try WeasyPrint (requires system libs)
    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(filepath)
        return filepath
    except ImportError:
        pass

    # Fallback: save as HTML
    filepath = filepath.replace(".pdf", ".html")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

    return filepath


# ────────────────────────────────────────────────────────────
# HTML Templates (xhtml2pdf compatible — no flexbox)
# ────────────────────────────────────────────────────────────

COMMON_STYLES = """
    @page { size: A4; margin: 1.8cm; }
    body { font-family: Helvetica, Arial, sans-serif; color: #1e293b; font-size: 10pt; line-height: 1.5; }
    .header { border-bottom: 3px solid #0d9488; padding-bottom: 12px; margin-bottom: 20px; }
    .header h1 { font-size: 20pt; color: #0f172a; margin: 0 0 4px 0; }
    .header .subtitle { font-size: 10pt; color: #64748b; }
    .header .org { font-size: 12pt; color: #0d9488; font-weight: bold; }
    h2 { font-size: 13pt; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 5px; margin-top: 24px; margin-bottom: 10px; }
    h3 { font-size: 11pt; color: #334155; margin-top: 16px; margin-bottom: 6px; }
    table { width: 100%; border-collapse: collapse; font-size: 9pt; margin: 8px 0; }
    th { background-color: #f1f5f9; color: #475569; font-weight: bold; text-align: left; padding: 7px 8px; border-bottom: 2px solid #e2e8f0; }
    td { padding: 6px 8px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
    .sev-critical { color: #ef4444; font-weight: bold; }
    .sev-high { color: #f97316; font-weight: bold; }
    .sev-medium { color: #f59e0b; font-weight: bold; }
    .sev-low { color: #3b82f6; font-weight: bold; }
    .sev-info { color: #94a3b8; }
    .metrics-table { width: 100%; margin: 16px 0; border-collapse: separate; border-spacing: 6px; }
    .metric-cell { background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 12px 8px; text-align: center; width: 20%; }
    .metric-value { font-size: 22pt; font-weight: bold; }
    .metric-label { font-size: 8pt; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }
    .chart-row { margin: 16px 0; }
    .chart-img { max-width: 100%; }
    .footer { margin-top: 28px; padding-top: 10px; border-top: 1px solid #e2e8f0; font-size: 8pt; color: #94a3b8; text-align: center; }
    .tag { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 8pt; font-weight: bold; text-transform: uppercase; }
    .tag-critical { background-color: #fef2f2; color: #ef4444; }
    .tag-high { background-color: #fff7ed; color: #f97316; }
    .tag-medium { background-color: #fffbeb; color: #f59e0b; }
    .tag-low { background-color: #eff6ff; color: #3b82f6; }
    .tag-info { background-color: #f8fafc; color: #94a3b8; }
    .page-break { page-break-before: always; }
"""


def _render_report_html(report: Report, data: dict) -> str:
    """Render the report HTML based on template type."""
    if report.template == "executive":
        return _render_executive_html(report, data)
    else:
        return _render_technical_html(report, data)


def _render_executive_html(report: Report, data: dict) -> str:
    """Render executive summary report — charts, key metrics, top risks."""
    org = data.get("organization", {})
    summary = data.get("summary", {})
    sev = summary.get("severityCounts", {})
    charts = data.get("charts", {})
    what = data.get("what", {})
    where = data.get("where", {})
    who = data.get("who", {})
    how = data.get("how", {})

    scope_label = data.get("groupName") or org.get("name", "Organization")
    exposure_score = summary.get("exposureScore", 0)
    score_color = "#10b981" if exposure_score < 40 else "#f59e0b" if exposure_score < 70 else "#ef4444"
    engines = how.get("engines", [])

    generated_at = data.get("generatedAt", "")
    if generated_at:
        try:
            dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
            generated_at = dt.strftime("%B %d, %Y at %H:%M UTC")
        except Exception:
            pass

    # Top findings rows
    top_findings = what.get("topFindings", [])[:10]
    finding_rows = ""
    for f in top_findings:
        sev_cls = f"sev-{f['severity']}"
        tag_cls = f"tag tag-{f['severity']}"
        finding_rows += f"""
        <tr>
            <td><span class="{tag_cls}">{f['severity']}</span></td>
            <td>{f['title']}</td>
            <td>{f.get('asset', '')}</td>
            <td>{f.get('category', '') or ''}</td>
        </tr>"""

    # Group breakdown rows
    fbg = who.get("findingsByGroup", {})
    group_rows = ""
    for gname, counts in sorted(fbg.items(), key=lambda x: x[1].get("total", 0), reverse=True):
        group_rows += f"""
        <tr>
            <td>{gname}</td>
            <td class="sev-critical">{counts.get('critical', 0)}</td>
            <td class="sev-high">{counts.get('high', 0)}</td>
            <td class="sev-medium">{counts.get('medium', 0)}</td>
            <td class="sev-low">{counts.get('low', 0)}</td>
            <td><strong>{counts.get('total', 0)}</strong></td>
        </tr>"""

    # Top risky assets rows
    top_risky = where.get("topRiskyAssets", [])[:5]
    risky_rows = ""
    for a in top_risky:
        risky_rows += f"""
        <tr>
            <td>{a['value']}</td>
            <td>{a.get('type', '')}</td>
            <td class="sev-critical">{a.get('critical', 0)}</td>
            <td class="sev-high">{a.get('high', 0)}</td>
            <td><strong>{a.get('total', 0)}</strong></td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>{COMMON_STYLES}</style></head>
<body>
    <div class="header">
        <div class="org">{org.get('name', '')}</div>
        <h1>Executive Security Summary</h1>
        <div class="subtitle">Scope: {scope_label} &nbsp;&bull;&nbsp; Generated: {generated_at}{f' &nbsp;&bull;&nbsp; Includes suppressed findings' if summary.get('includeSuppressed') else f" &nbsp;&bull;&nbsp; {summary.get('suppressedCount', 0)} suppressed findings excluded" if summary.get('suppressedCount', 0) > 0 else ''}</div>
    </div>

    <!-- Exposure Score Gauge + Severity Pie side by side -->
    <table class="chart-row" style="border:none;">
        <tr>
            <td style="width:40%;border:none;text-align:center;vertical-align:top;">
                <img src="data:image/png;base64,{charts.get('exposureGauge', '')}" class="chart-img" style="max-width:280px;" />
            </td>
            <td style="width:60%;border:none;text-align:center;vertical-align:top;">
                <img src="data:image/png;base64,{charts.get('severityPie', '')}" class="chart-img" style="max-width:380px;" />
            </td>
        </tr>
    </table>

    <!-- Key Metrics -->
    <table class="metrics-table">
        <tr>
            <td class="metric-cell">
                <div class="metric-value" style="color:{score_color}">{exposure_score}</div>
                <div class="metric-label">Exposure Score</div>
            </td>
            <td class="metric-cell">
                <div class="metric-value">{summary.get('totalFindings', 0)}</div>
                <div class="metric-label">Total Findings</div>
            </td>
            <td class="metric-cell">
                <div class="metric-value sev-critical">{sev.get('critical', 0)}</div>
                <div class="metric-label">Critical</div>
            </td>
            <td class="metric-cell">
                <div class="metric-value sev-high">{sev.get('high', 0)}</div>
                <div class="metric-label">High</div>
            </td>
            <td class="metric-cell">
                <div class="metric-value">{summary.get('assetCount', 0)}</div>
                <div class="metric-label">Assets</div>
            </td>
        </tr>
    </table>

    <!-- Top Risks -->
    <h2>Top Risks</h2>
    <table>
        <thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Category</th></tr></thead>
        <tbody>{finding_rows if finding_rows else '<tr><td colspan="4" style="text-align:center;color:#94a3b8">No critical or high findings</td></tr>'}</tbody>
    </table>

    <!-- Findings by Group Chart + Table -->
    <h2>Risk by Group</h2>
    <table class="chart-row" style="border:none;">
        <tr>
            <td style="border:none;text-align:center;">
                <img src="data:image/png;base64,{charts.get('findingsByGroup', '')}" class="chart-img" style="max-width:480px;" />
            </td>
        </tr>
    </table>
    <table>
        <thead><tr><th>Group</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr></thead>
        <tbody>{group_rows if group_rows else '<tr><td colspan="6" style="text-align:center;color:#94a3b8">No findings</td></tr>'}</tbody>
    </table>

    <!-- Most Exposed Assets -->
    <h2>Most Exposed Assets</h2>
    <table>
        <thead><tr><th>Asset</th><th>Type</th><th>Critical</th><th>High</th><th>Total</th></tr></thead>
        <tbody>{risky_rows if risky_rows else '<tr><td colspan="5" style="text-align:center;color:#94a3b8">No findings</td></tr>'}</tbody>
    </table>

    <!-- Category Breakdown -->
    <h2>Findings by Category</h2>
    <table class="chart-row" style="border:none;">
        <tr>
            <td style="border:none;text-align:center;">
                <img src="data:image/png;base64,{charts.get('categoryBar', '')}" class="chart-img" style="max-width:460px;" />
            </td>
        </tr>
    </table>

    <!-- Detection Coverage -->
    <h2>Detection Coverage</h2>
    <p>Scan engines used: <strong>{', '.join(engines) if engines else 'None recorded'}</strong></p>
    <p>Total assets scanned: <strong>{how.get('totalScanned', 0)}</strong></p>

    <div class="footer">
        Generated by BoltEdge EASM &nbsp;&bull;&nbsp; {org.get('name', '')} &nbsp;&bull;&nbsp; {generated_at}<br/>
        This is a confidential security report. Distribution should be limited to authorized personnel.
    </div>
</body>
</html>"""


def _render_technical_html(report: Report, data: dict) -> str:
    """Render full technical report — all findings with details and remediation."""
    org = data.get("organization", {})
    summary = data.get("summary", {})
    sev = summary.get("severityCounts", {})
    charts = data.get("charts", {})
    what = data.get("what", {})
    where = data.get("where", {})
    who = data.get("who", {})
    how = data.get("how", {})

    scope_label = data.get("groupName") or org.get("name", "Organization")
    exposure_score = summary.get("exposureScore", 0)
    score_color = "#10b981" if exposure_score < 40 else "#f59e0b" if exposure_score < 70 else "#ef4444"
    engines = how.get("engines", [])

    generated_at = data.get("generatedAt", "")
    if generated_at:
        try:
            dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
            generated_at = dt.strftime("%B %d, %Y at %H:%M UTC")
        except Exception:
            pass

    all_findings = what.get("allFindings", [])
    top_risky = where.get("topRiskyAssets", [])
    fbg = who.get("findingsByGroup", {})
    team = who.get("team", [])

    # Sort findings: critical first
    sev_order_map = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: sev_order_map.get(f.get("severity", "info"), 5))

    # ── Build finding rows ──
    finding_rows = ""
    for f in all_findings:
        sev_val = f.get("severity", "info")
        tag_cls = f"tag tag-{sev_val}"
        remediation = f.get("remediation") or "—"
        desc = (f.get("description") or "")[:150]
        cwe = f.get("cwe") or ""
        cwe_tag = f'<br/><span style="font-size:7pt;color:#6366f1;font-weight:bold">{cwe}</span>' if cwe else ""
        category = f.get("category") or ""
        cat_tag = f'<span style="font-size:7pt;color:#94a3b8">{category}</span>' if category else ""
        finding_rows += f"""
        <tr>
            <td><span class="{tag_cls}">{sev_val}</span></td>
            <td><strong>{f.get('title', '')}</strong>{cwe_tag}<br/><span style="font-size:8pt;color:#64748b">{desc}</span></td>
            <td>{f.get('asset', '')}<br/>{cat_tag}</td>
            <td>{f.get('group', '')}</td>
            <td style="font-size:8pt">{remediation[:250]}{'...' if len(remediation) > 250 else ''}</td>
        </tr>"""

    # ── Asset inventory rows ──
    risky_rows = ""
    for a in top_risky:
        risky_rows += f"""
        <tr>
            <td>{a['value']}</td>
            <td>{a.get('type', '')}</td>
            <td class="sev-critical">{a.get('critical', 0)}</td>
            <td class="sev-high">{a.get('high', 0)}</td>
            <td class="sev-medium">{a.get('medium', 0)}</td>
            <td class="sev-low">{a.get('low', 0)}</td>
            <td><strong>{a.get('total', 0)}</strong></td>
        </tr>"""

    # ── Group breakdown rows ──
    group_rows = ""
    for gname, counts in sorted(fbg.items(), key=lambda x: x[1].get("total", 0), reverse=True):
        group_rows += f"""
        <tr>
            <td>{gname}</td>
            <td class="sev-critical">{counts.get('critical', 0)}</td>
            <td class="sev-high">{counts.get('high', 0)}</td>
            <td class="sev-medium">{counts.get('medium', 0)}</td>
            <td class="sev-low">{counts.get('low', 0)}</td>
            <td><strong>{counts.get('total', 0)}</strong></td>
        </tr>"""

    # ── Team members rows ──
    team_rows = ""
    for t in team:
        team_rows += f"""
        <tr>
            <td>{t.get('name', '')}</td>
            <td>{t.get('email', '')}</td>
            <td>{t.get('role', '').title()}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>{COMMON_STYLES}</style></head>
<body>
    <div class="header">
        <div class="org">{org.get('name', '')}</div>
        <h1>Technical Security Report</h1>
        <div class="subtitle">Scope: {scope_label} &nbsp;&bull;&nbsp; Generated: {generated_at}{f' &nbsp;&bull;&nbsp; Includes suppressed findings' if summary.get('includeSuppressed') else f" &nbsp;&bull;&nbsp; {summary.get('suppressedCount', 0)} suppressed findings excluded" if summary.get('suppressedCount', 0) > 0 else ''}</div>
    </div>

    <!-- ══════════════ OVERVIEW ══════════════ -->

    <!-- Charts: Gauge + Severity Pie -->
    <table class="chart-row" style="border:none;">
        <tr>
            <td style="width:35%;border:none;text-align:center;vertical-align:top;">
                <img src="data:image/png;base64,{charts.get('exposureGauge', '')}" class="chart-img" style="max-width:260px;" />
            </td>
            <td style="width:65%;border:none;text-align:center;vertical-align:top;">
                <img src="data:image/png;base64,{charts.get('severityPie', '')}" class="chart-img" style="max-width:360px;" />
            </td>
        </tr>
    </table>

    <!-- Key Metrics -->
    <table class="metrics-table">
        <tr>
            <td class="metric-cell">
                <div class="metric-value" style="color:{score_color}">{exposure_score}</div>
                <div class="metric-label">Exposure Score</div>
            </td>
            <td class="metric-cell">
                <div class="metric-value">{summary.get('totalFindings', 0)}</div>
                <div class="metric-label">Total Findings</div>
            </td>
            <td class="metric-cell">
                <div class="metric-value sev-critical">{sev.get('critical', 0)}</div>
                <div class="metric-label">Critical</div>
            </td>
            <td class="metric-cell">
                <div class="metric-value sev-high">{sev.get('high', 0)}</div>
                <div class="metric-label">High</div>
            </td>
            <td class="metric-cell">
                <div class="metric-value">{summary.get('assetCount', 0)}</div>
                <div class="metric-label">Assets</div>
            </td>
        </tr>
    </table>

    <!-- ══════════════ WHO ══════════════ -->
    <h2>WHO — Team &amp; Responsibility</h2>
    <table>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th></tr></thead>
        <tbody>{team_rows if team_rows else '<tr><td colspan="3" style="text-align:center;color:#94a3b8">No team members</td></tr>'}</tbody>
    </table>

    <h3>Findings Ownership by Group</h3>
    <table>
        <thead><tr><th>Group</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr></thead>
        <tbody>{group_rows if group_rows else '<tr><td colspan="6" style="text-align:center;color:#94a3b8">No data</td></tr>'}</tbody>
    </table>

    <!-- ══════════════ WHAT ══════════════ -->
    <div class="page-break"></div>
    <h2>WHAT — Findings &amp; Vulnerabilities</h2>

    <!-- Category Chart -->
    <table class="chart-row" style="border:none;">
        <tr>
            <td style="border:none;text-align:center;">
                <img src="data:image/png;base64,{charts.get('categoryBar', '')}" class="chart-img" style="max-width:460px;" />
            </td>
        </tr>
    </table>

    <h3>All Findings ({len(all_findings)} total)</h3>
    <table>
        <thead><tr><th style="width:8%">Sev</th><th style="width:30%">Finding</th><th style="width:18%">Asset</th><th style="width:12%">Group</th><th style="width:32%">Remediation</th></tr></thead>
        <tbody>{finding_rows if finding_rows else '<tr><td colspan="7" style="text-align:center;color:#94a3b8">No findings</td></tr>'}</tbody>
    </table>

    <!-- ══════════════ WHERE ══════════════ -->
    <div class="page-break"></div>
    <h2>WHERE — Asset Inventory</h2>

    <!-- Findings by Group Chart -->
    <table class="chart-row" style="border:none;">
        <tr>
            <td style="border:none;text-align:center;">
                <img src="data:image/png;base64,{charts.get('findingsByGroup', '')}" class="chart-img" style="max-width:480px;" />
            </td>
        </tr>
    </table>

    <h3>Assets by Risk ({summary.get('assetCount', 0)} assets across {summary.get('groupCount', 0)} groups)</h3>
    <table>
        <thead><tr><th>Asset</th><th>Type</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr></thead>
        <tbody>{risky_rows if risky_rows else '<tr><td colspan="7" style="text-align:center;color:#94a3b8">No assets</td></tr>'}</tbody>
    </table>

    <!-- ══════════════ WHEN ══════════════ -->
    <h2>WHEN — Timeline</h2>
    <p>Report generated: <strong>{generated_at}</strong></p>
    <p style="color:#94a3b8;font-size:9pt">Historical trending data (MTTR, findings over time) will be available once the Historical Trending module is implemented.</p>

    <!-- ══════════════ HOW ══════════════ -->
    <h2>HOW — Detection Methods</h2>
    <p>Scan engines deployed: <strong>{', '.join(engines) if engines else 'None recorded'}</strong></p>
    <p>Total assets scanned: <strong>{how.get('totalScanned', 0)}</strong></p>

    <div class="footer">
        Generated by XternSec &nbsp;&bull;&nbsp; {org.get('name', '')} &nbsp;&bull;&nbsp; {generated_at}<br/>
        This is a confidential security report. Distribution should be limited to authorized personnel.
    </div>
</body>
</html>"""


# ────────────────────────────────────────────────────────────
# Routes — Reports
# ────────────────────────────────────────────────────────────

# GET /reports — viewer+ (list reports)
@reports_bp.get("")
@require_auth
def list_reports():
    org_id = current_organization_id()

    scope = request.args.get("scope")
    group_id = request.args.get("group_id")
    template = request.args.get("template")
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 100)

    query = Report.query.filter_by(organization_id=org_id)

    if scope:
        query = query.filter(Report.scope == scope)
    if group_id:
        query = query.filter(Report.group_id == int(group_id))
    if template:
        query = query.filter(Report.template == template)

    total = query.count()
    reports = (
        query.order_by(desc(Report.created_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return jsonify(
        reports=[_report_to_dict(r) for r in reports],
        total=total,
        page=page,
        perPage=per_page,
    ), 200


# GET /reports/<id> — viewer+ (view report details)
@reports_bp.get("/<int:report_id>")
@require_auth
def get_report(report_id: int):
    org_id = current_organization_id()
    r = Report.query.filter_by(id=report_id, organization_id=org_id).first()
    if not r:
        return jsonify(error="Report not found"), 404
    return jsonify(_report_to_dict(r)), 200


# GET /reports/<id>/download — viewer+ (download PDF)
@reports_bp.get("/<int:report_id>/download")
@require_auth
def download_report(report_id: int):
    org_id = current_organization_id()
    r = Report.query.filter_by(id=report_id, organization_id=org_id).first()
    if not r:
        return jsonify(error="Report not found"), 404
    if r.status != "ready":
        return jsonify(error="Report is not ready for download", status=r.status), 400
    if not r.file_path or not os.path.exists(r.file_path):
        return jsonify(error="Report file not found on disk"), 404

    mimetype = "application/pdf" if r.file_path.endswith(".pdf") else "text/html"
    ext = "pdf" if mimetype == "application/pdf" else "html"
    download_name = f"{r.title.replace(' ', '_')}_{r.id}.{ext}"

    return send_file(
        r.file_path,
        mimetype=mimetype,
        as_attachment=True,
        download_name=download_name,
    )


# POST /reports/generate — analyst+ (generate new report)
@reports_bp.post("/generate")
@require_auth
@require_role("analyst")
def generate_report():
    org_id = current_organization_id()
    user_id = current_user_id()
    body = request.get_json(silent=True) or {}

    # Validate template
    template = body.get("template", "executive")
    if template not in ("executive", "technical"):
        return jsonify(error="template must be 'executive' or 'technical'"), 400

    # Validate scope
    scope = body.get("scope", "organization")
    if scope not in ("organization", "group"):
        return jsonify(error="scope must be 'organization' or 'group'"), 400

    group_id = None
    group_name = None
    if scope == "group":
        group_id = body.get("groupId") or body.get("group_id")
        if not group_id:
            return jsonify(error="groupId is required when scope is 'group'"), 400
        group_id = int(group_id)
        group = AssetGroup.query.filter_by(id=group_id, organization_id=org_id, is_active=True).first()
        if not group:
            return jsonify(error="Group not found"), 404
        group_name = group.name

    # Build title
    org = Organization.query.get(org_id)
    org_name = org.name if org else "Organization"
    if scope == "group":
        title = body.get("title") or f"{template.title()} Report — {group_name}"
    else:
        title = body.get("title") or f"{template.title()} Report — {org_name}"

    config = body.get("config") or {}

    # Create report record
    report = Report(
        organization_id=org_id,
        title=title,
        template=template,
        format="pdf",
        scope=scope,
        group_id=group_id,
        group_name=group_name,
        status="generating",
        config=config,
        generated_by=user_id,
    )
    db.session.add(report)
    db.session.commit()  # first commit — create the report record

    # Generate report synchronously
    try:
        data = _gather_report_data(org_id, scope, group_id, config)
        filepath = _generate_pdf(report, data)

        file_size = os.path.getsize(filepath) if os.path.exists(filepath) else None

        report.status = "ready"
        report.file_path = filepath
        report.file_size = file_size
        report.generated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        report.summary_data = data.get("summary")

        log_audit(
            organization_id=org_id,
            user_id=user_id,
            action="export.report_generated",
            category="export",
            target_type="report",
            target_id=str(report.id),
            target_label=title,
            description=f"Generated {template} report: {title}",
            metadata={"template": template, "scope": scope, "group_name": group_name, "file_size": file_size},
        )

        db.session.commit()

    except Exception as e:
        report.status = "failed"
        report.error_message = str(e)[:1000]

        log_audit(
            organization_id=org_id,
            user_id=user_id,
            action="export.report_failed",
            category="export",
            target_type="report",
            target_id=str(report.id),
            target_label=title,
            description=f"Report generation failed: {str(e)[:200]}",
            metadata={"template": template, "scope": scope, "error": str(e)[:500]},
        )

        db.session.commit()

        return jsonify(error="Report generation failed", details=str(e)[:500]), 500

    return jsonify(_report_to_dict(report)), 201


# DELETE /reports/<id> — admin+ (delete report)
@reports_bp.delete("/<int:report_id>")
@require_auth
@require_role("admin")
def delete_report(report_id: int):
    org_id = current_organization_id()
    r = Report.query.filter_by(id=report_id, organization_id=org_id).first()
    if not r:
        return jsonify(error="Report not found"), 404

    report_title = r.title
    report_id_str = str(r.id)

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="export.report_deleted",
        category="export",
        target_type="report",
        target_id=report_id_str,
        target_label=report_title,
        description=f"Deleted report: {report_title}",
    )

    if r.file_path and os.path.exists(r.file_path):
        try:
            os.remove(r.file_path)
        except OSError:
            pass

    db.session.delete(r)
    db.session.commit()

    return jsonify(message="Report deleted"), 200


# ────────────────────────────────────────────────────────────
# Routes — Report Schedules
# ────────────────────────────────────────────────────────────

# GET /reports/schedules — viewer+ (list schedules)
@reports_bp.get("/schedules")
@require_auth
def list_schedules():
    org_id = current_organization_id()
    schedules = (
        ReportSchedule.query
        .filter_by(organization_id=org_id)
        .order_by(desc(ReportSchedule.created_at))
        .all()
    )
    return jsonify(schedules=[_schedule_to_dict(s) for s in schedules]), 200


# POST /reports/schedules — admin+ (create schedule)
@reports_bp.post("/schedules")
@require_auth
@require_role("admin")
def create_schedule():
    org_id = current_organization_id()
    user_id = current_user_id()
    body = request.get_json(silent=True) or {}

    name = (body.get("name") or "").strip()
    if not name:
        return jsonify(error="name is required"), 400

    template = body.get("template", "executive")
    if template not in ("executive", "technical"):
        return jsonify(error="template must be 'executive' or 'technical'"), 400

    scope = body.get("scope", "organization")
    if scope not in ("organization", "group"):
        return jsonify(error="scope must be 'organization' or 'group'"), 400

    group_id = None
    if scope == "group":
        group_id = body.get("groupId") or body.get("group_id")
        if not group_id:
            return jsonify(error="groupId is required when scope is 'group'"), 400
        group_id = int(group_id)
        group = AssetGroup.query.filter_by(id=group_id, organization_id=org_id, is_active=True).first()
        if not group:
            return jsonify(error="Group not found"), 404

    frequency = body.get("frequency", "monthly")
    if frequency not in ("weekly", "monthly"):
        return jsonify(error="frequency must be 'weekly' or 'monthly'"), 400

    schedule = ReportSchedule(
        organization_id=org_id,
        name=name,
        template=template,
        scope=scope,
        group_id=group_id,
        config=body.get("config"),
        frequency=frequency,
        day_of_week=body.get("dayOfWeek") or body.get("day_of_week"),
        day_of_month=body.get("dayOfMonth") or body.get("day_of_month"),
        hour=body.get("hour", 6),
        recipients=body.get("recipients", []),
        include_pdf_attachment=body.get("includePdfAttachment", True),
        enabled=body.get("enabled", True),
        created_by=user_id,
    )
    db.session.add(schedule)
    db.session.flush()  # get schedule.id

    log_audit(
        organization_id=org_id,
        user_id=user_id,
        action="settings.report_schedule_created",
        category="settings",
        target_type="report_schedule",
        target_id=str(schedule.id),
        target_label=name,
        description=f"Created report schedule '{name}' ({frequency} {template})",
        metadata={"template": template, "scope": scope, "frequency": frequency},
    )

    db.session.commit()

    return jsonify(_schedule_to_dict(schedule)), 201


# PATCH /reports/schedules/<id> — admin+ (update schedule)
@reports_bp.patch("/schedules/<int:schedule_id>")
@require_auth
@require_role("admin")
def update_schedule(schedule_id: int):
    org_id = current_organization_id()
    s = ReportSchedule.query.filter_by(id=schedule_id, organization_id=org_id).first()
    if not s:
        return jsonify(error="Schedule not found"), 404

    body = request.get_json(silent=True) or {}
    updated_fields = []

    if "name" in body:
        s.name = (body["name"] or "").strip() or s.name
        updated_fields.append("name")
    if "template" in body and body["template"] in ("executive", "technical"):
        s.template = body["template"]
        updated_fields.append("template")
    if "frequency" in body and body["frequency"] in ("weekly", "monthly"):
        s.frequency = body["frequency"]
        updated_fields.append("frequency")
    if "dayOfWeek" in body or "day_of_week" in body:
        s.day_of_week = body.get("dayOfWeek") or body.get("day_of_week")
        updated_fields.append("dayOfWeek")
    if "dayOfMonth" in body or "day_of_month" in body:
        s.day_of_month = body.get("dayOfMonth") or body.get("day_of_month")
        updated_fields.append("dayOfMonth")
    if "hour" in body:
        s.hour = body["hour"]
        updated_fields.append("hour")
    if "recipients" in body:
        s.recipients = body["recipients"]
        updated_fields.append("recipients")
    if "includePdfAttachment" in body:
        s.include_pdf_attachment = body["includePdfAttachment"]
        updated_fields.append("includePdfAttachment")
    if "enabled" in body:
        s.enabled = bool(body["enabled"])
        updated_fields.append("enabled")
    if "config" in body:
        s.config = body["config"]
        updated_fields.append("config")

    if updated_fields:
        log_audit(
            organization_id=org_id,
            user_id=current_user_id(),
            action="settings.report_schedule_updated",
            category="settings",
            target_type="report_schedule",
            target_id=str(s.id),
            target_label=s.name,
            description=f"Updated report schedule '{s.name}'",
            metadata={"fields": updated_fields},
        )

    db.session.commit()

    return jsonify(_schedule_to_dict(s)), 200


# DELETE /reports/schedules/<id> — admin+ (delete schedule)
@reports_bp.delete("/schedules/<int:schedule_id>")
@require_auth
@require_role("admin")
def delete_schedule(schedule_id: int):
    org_id = current_organization_id()
    s = ReportSchedule.query.filter_by(id=schedule_id, organization_id=org_id).first()
    if not s:
        return jsonify(error="Schedule not found"), 404

    schedule_name = s.name

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="settings.report_schedule_deleted",
        category="settings",
        target_type="report_schedule",
        target_id=str(schedule_id),
        target_label=schedule_name,
        description=f"Deleted report schedule '{schedule_name}'",
    )

    db.session.delete(s)
    db.session.commit()

    return jsonify(message="Schedule deleted"), 200