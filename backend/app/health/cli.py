"""
`flask health` CLI subcommands.

Usage examples:
    flask health                  # Full report — all sections.
    flask health quick            # DB + migrations + schedulers (<1s).
    flask health db               # DB pool, ping, migration drift.
    flask health schedulers       # Scheduler heartbeats.
    flask health engines          # Last engine probe results.
    flask health engines --probe  # Re-run engine probes now, then show.
    flask health external         # Last external-API probe results.
    flask health external --probe # Re-run external-API probes now.
    flask health probe            # Re-run all probe kinds, persist, summarise.
    flask health -j               # Any subcommand: emit JSON instead.

Designed for two callers:
  - Operators ssh'ing in to debug ("is anything broken?")
  - Cron/CI scripts (`flask health quick -j | jq …`).
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

import click
from flask import Flask
from flask.cli import AppGroup


health_cli = AppGroup("health", help="Platform health checks.")


_STATUS_COLOR = {
    "healthy": "green",
    "degraded": "yellow",
    "down": "red",
    "unknown": "white",
    "critical": "red",
}


def _color(status: str) -> str:
    return _STATUS_COLOR.get(status, "white")


def _emit(payload: Dict[str, Any], as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps(payload, default=str, indent=2))
        return

    overall = payload.get("overall") or payload.get("status") or "unknown"
    click.secho(f"Overall: {overall}", fg=_color(overall), bold=True)

    for section_name, section in (payload.get("sections") or {}).items():
        click.echo("")
        click.secho(section_name, bold=True, underline=True)
        items = section.get("items") if isinstance(section, dict) else section
        if isinstance(section, dict) and "overall" in section:
            click.secho(
                f"  Rollup: {section['overall']} ({section.get('counts', {})})",
                fg=_color(section["overall"]),
            )
        if not items:
            click.echo("  (no items)")
            continue
        for it in items:
            status = it.get("status", "unknown")
            name = it.get("name", "?")
            msg = it.get("message") or ""
            dur = it.get("durationMs")
            dur_s = f" [{dur}ms]" if dur is not None else ""
            click.secho(f"  {status:9s}", fg=_color(status), nl=False)
            click.echo(f" {name:25s} {msg}{dur_s}")


def _build_full_report(probe: bool = False) -> Dict[str, Any]:
    """Snapshot every section. If probe=True, refresh probe results first."""
    from app.health.framework import fetch_all, serialize as _hc_serialize
    from app.health.probes.system_probe import run_system_probes
    from app.health.runner import run_subset, PROBE_KINDS

    if probe:
        run_subset(PROBE_KINDS)

    rows = fetch_all()
    by_kind: Dict[str, List[Dict[str, Any]]] = {
        "engine": [], "analyzer": [], "discovery": [],
        "scheduler": [], "external_api": [], "system": [],
    }
    for row in rows:
        if row.kind in by_kind:
            by_kind[row.kind].append(_hc_serialize(row))

    system_results = run_system_probes()
    system_items = [{
        "kind": r.kind,
        "name": r.name,
        "status": r.status.value,
        "message": r.message,
        "metadata": r.metadata,
        "durationMs": r.duration_ms,
    } for r in system_results]

    def _rollup(items: List[Dict[str, Any]]) -> Dict[str, Any]:
        counts = {"healthy": 0, "degraded": 0, "down": 0, "unknown": 0}
        for it in items:
            counts[it["status"]] = counts.get(it["status"], 0) + 1
        if counts["down"] > 0:
            overall = "down"
        elif counts["degraded"] > 0:
            overall = "degraded"
        elif counts["unknown"] > 0 and counts["healthy"] == 0:
            overall = "unknown"
        else:
            overall = "healthy"
        return {"overall": overall, "counts": counts, "items": items}

    sections = {
        "System": {"items": [it for it in system_items if it["kind"] == "system"]},
        "Schedulers": {"items": [it for it in system_items if it["kind"] == "scheduler"]},
        "Engines": _rollup(by_kind["engine"]),
        "Analyzers": _rollup(by_kind["analyzer"]),
        "Discovery": _rollup(by_kind["discovery"]),
        "External APIs": _rollup(by_kind["external_api"]),
    }

    # Overall = worst section.
    statuses = []
    for section in sections.values():
        if isinstance(section, dict) and "overall" in section:
            statuses.append(section["overall"])
        else:
            for it in section.get("items", []):
                statuses.append(it["status"])
    if "down" in statuses:
        overall = "down"
    elif "degraded" in statuses:
        overall = "degraded"
    elif statuses and all(s == "healthy" for s in statuses):
        overall = "healthy"
    else:
        overall = "unknown"

    return {"overall": overall, "sections": sections}


def _exit_code(report: Dict[str, Any]) -> int:
    """0 healthy, 1 degraded, 2 down/critical/unknown — for scripting."""
    overall = report.get("overall") or report.get("status") or "unknown"
    return {"healthy": 0, "degraded": 1, "down": 2, "critical": 2}.get(overall, 2)


@health_cli.command("status")
@click.option("-j", "--json", "as_json", is_flag=True, help="Emit JSON.")
def health_status(as_json: bool):
    """Full health report (default if no subcommand)."""
    report = _build_full_report(probe=False)
    _emit(report, as_json=as_json)
    sys.exit(_exit_code(report))


@health_cli.command("quick")
@click.option("-j", "--json", "as_json", is_flag=True, help="Emit JSON.")
def health_quick(as_json: bool):
    """Fast checks only: DB, migrations, scheduler heartbeats. <1s."""
    from app.health.probes.system_probe import run_system_probes
    results = run_system_probes()
    items = [{
        "kind": r.kind, "name": r.name, "status": r.status.value,
        "message": r.message, "metadata": r.metadata, "durationMs": r.duration_ms,
    } for r in results]
    statuses = {it["status"] for it in items}
    if "down" in statuses:
        overall = "down"
    elif "degraded" in statuses:
        overall = "degraded"
    elif statuses and "unknown" not in statuses:
        overall = "healthy"
    else:
        overall = "unknown"
    payload = {
        "overall": overall,
        "sections": {
            "System": {"items": [it for it in items if it["kind"] == "system"]},
            "Schedulers": {"items": [it for it in items if it["kind"] == "scheduler"]},
        },
    }
    _emit(payload, as_json=as_json)
    sys.exit(_exit_code(payload))


@health_cli.command("db")
@click.option("-j", "--json", "as_json", is_flag=True, help="Emit JSON.")
def health_db(as_json: bool):
    """DB ping, pool stats, migration drift."""
    from app.health.probes.system_probe import db_ping, migration_drift
    results = [db_ping(), migration_drift()]
    items = [{
        "kind": r.kind, "name": r.name, "status": r.status.value,
        "message": r.message, "metadata": r.metadata, "durationMs": r.duration_ms,
    } for r in results]
    statuses = {it["status"] for it in items}
    overall = ("down" if "down" in statuses
               else "degraded" if "degraded" in statuses
               else "healthy")
    payload = {"overall": overall, "sections": {"Database": {"items": items}}}
    _emit(payload, as_json=as_json)
    sys.exit(_exit_code(payload))


@health_cli.command("schedulers")
@click.option("-j", "--json", "as_json", is_flag=True, help="Emit JSON.")
def health_schedulers(as_json: bool):
    """Scheduler heartbeat status."""
    from app.health.probes.system_probe import scheduler_status
    results = scheduler_status()
    items = [{
        "kind": r.kind, "name": r.name, "status": r.status.value,
        "message": r.message, "metadata": r.metadata, "durationMs": r.duration_ms,
    } for r in results]
    statuses = {it["status"] for it in items}
    overall = ("down" if "down" in statuses
               else "degraded" if "degraded" in statuses
               else "unknown" if "unknown" in statuses and "healthy" not in statuses
               else "healthy")
    payload = {"overall": overall, "sections": {"Schedulers": {"items": items}}}
    _emit(payload, as_json=as_json)
    sys.exit(_exit_code(payload))


def _show_kind(kind_label: str, kind_key: str, probe: bool, as_json: bool) -> None:
    from app.health.framework import fetch_by_kind, serialize as _hc_serialize
    from app.health.runner import run_subset

    if probe:
        run_subset([kind_key])

    rows = fetch_by_kind(kind_key)
    items = [_hc_serialize(r) for r in rows]
    counts = {"healthy": 0, "degraded": 0, "down": 0, "unknown": 0}
    for it in items:
        counts[it["status"]] = counts.get(it["status"], 0) + 1
    if counts["down"] > 0:
        overall = "down"
    elif counts["degraded"] > 0:
        overall = "degraded"
    elif counts["unknown"] > 0 and counts["healthy"] == 0:
        overall = "unknown"
    else:
        overall = "healthy" if items else "unknown"
    payload = {
        "overall": overall,
        "sections": {kind_label: {"overall": overall, "counts": counts, "items": items}},
    }
    _emit(payload, as_json=as_json)
    sys.exit(_exit_code(payload))


@health_cli.command("engines")
@click.option("--probe", is_flag=True, help="Re-run probes before reading.")
@click.option("-j", "--json", "as_json", is_flag=True, help="Emit JSON.")
def health_engines(probe: bool, as_json: bool):
    """Scan engine status (cached unless --probe)."""
    _show_kind("Engines", "engine", probe=probe, as_json=as_json)


@health_cli.command("analyzers")
@click.option("--probe", is_flag=True, help="Re-run probes before reading.")
@click.option("-j", "--json", "as_json", is_flag=True, help="Emit JSON.")
def health_analyzers(probe: bool, as_json: bool):
    """Analyzer status (cached unless --probe)."""
    _show_kind("Analyzers", "analyzer", probe=probe, as_json=as_json)


@health_cli.command("discovery")
@click.option("--probe", is_flag=True, help="Re-run probes before reading.")
@click.option("-j", "--json", "as_json", is_flag=True, help="Emit JSON.")
def health_discovery(probe: bool, as_json: bool):
    """Discovery module status (cached unless --probe)."""
    _show_kind("Discovery", "discovery", probe=probe, as_json=as_json)


@health_cli.command("external")
@click.option("--probe", is_flag=True, help="Re-run probes before reading.")
@click.option("-j", "--json", "as_json", is_flag=True, help="Emit JSON.")
def health_external(probe: bool, as_json: bool):
    """External API status (Shodan, GitHub, GitLab, Resend, Stripe)."""
    _show_kind("External APIs", "external_api", probe=probe, as_json=as_json)


@health_cli.command("probe")
@click.option(
    "--kinds",
    default="",
    help="Comma-separated kinds to probe (default: all). Options: engine, analyzer, discovery, external_api.",
)
@click.option("-j", "--json", "as_json", is_flag=True, help="Emit JSON.")
def health_probe(kinds: str, as_json: bool):
    """Run probes now and persist. Same logic the 6h scheduler runs."""
    from app.health.runner import run_subset, PROBE_KINDS
    selected = [k.strip() for k in kinds.split(",") if k.strip()] if kinds else list(PROBE_KINDS)
    selected = [k for k in selected if k in PROBE_KINDS]
    if not selected:
        click.echo("No valid kinds. Choose from: " + ", ".join(PROBE_KINDS))
        sys.exit(2)
    summary = run_subset(selected)
    if as_json:
        click.echo(json.dumps({"kinds": selected, "summary": summary}, indent=2))
    else:
        click.echo(f"Probed: {', '.join(selected)}")
        for k, v in summary.items():
            click.echo(f"  {k}: {v}")


def register_health_cli(app: Flask) -> None:
    app.cli.add_command(health_cli)
