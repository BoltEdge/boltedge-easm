"""Admin UI backend for the agent platform.

URL prefix: /admin/agents
Auth: require_root_admin decorator (404s for everyone except root admins —
this is more restrictive than the rest of /admin/* which uses superadmin,
because the agent platform can spend Anthropic credits and produce
customer-facing drafts).
"""
from __future__ import annotations
from flask import Blueprint, jsonify, request

from app.auth.decorators import require_root_admin
from app.extensions import db
from app.models import AgentRun, AgentThread, AgentMessage, PendingAction

from .profile_loader import PROFILES_DIR, load_profile
from .runtime import run_agent
from .approvals import list_pending, approve, reject


bp = Blueprint("agents_admin", __name__, url_prefix="/admin/agents")


def _list_profiles():
    out = []
    for child in PROFILES_DIR.iterdir():
        if not child.is_dir():
            continue
        f = child / "agent.md"
        if not f.exists():
            continue
        try:
            p = load_profile(f)
        except Exception:
            continue
        out.append({
            "name": p.name,
            "display_name": p.display_name,
            "external_writes": p.external_writes,
            "cost_cap_monthly_usd": p.cost_cap_monthly_usd,
            "default_model": p.default_model,
        })
    return sorted(out, key=lambda r: r["name"])


@bp.route("", methods=["GET"])
@require_root_admin
def list_agents():
    return jsonify({"agents": _list_profiles()})


@bp.route("/<agent_name>", methods=["GET"])
@require_root_admin
def agent_detail(agent_name: str):
    f = PROFILES_DIR / agent_name / "agent.md"
    if not f.exists():
        return jsonify({"error": "not_found"}), 404
    p = load_profile(f)

    runs = (
        AgentRun.query.filter_by(agent_id=agent_name)
        .order_by(AgentRun.started_at.desc())
        .limit(20).all()
    )
    threads = (
        AgentThread.query.filter_by(agent_id=agent_name)
        .order_by(AgentThread.created_at.desc())
        .limit(20).all()
    )

    return jsonify({
        "name": p.name,
        "display_name": p.display_name,
        "system_prompt": p.system_prompt,
        "allowed_tools": p.allowed_tools,
        "external_writes": p.external_writes,
        "cost_cap_monthly_usd": p.cost_cap_monthly_usd,
        "default_model": p.default_model,
        "runs": [
            {"id": r.id, "skill": r.skill, "status": r.status,
             "cost_usd": float(r.cost_usd) if r.cost_usd else None,
             "started_at": r.started_at.isoformat() + "Z",
             "duration_ms": r.duration_ms}
            for r in runs
        ],
        "threads": [
            {"id": t.id, "title": t.title,
             "created_at": t.created_at.isoformat() + "Z",
             "message_count": len(t.messages)}
            for t in threads
        ],
    })


@bp.route("/<agent_name>/run", methods=["POST"])
@require_root_admin
def trigger_run(agent_name: str):
    body = request.get_json(force=True) or {}
    prompt = body.get("prompt")
    skill = body.get("skill")
    memory_tags = body.get("memory_tags", [])
    thread_id = body.get("thread_id")
    if not prompt:
        return jsonify({"error": "prompt is required"}), 400

    result = run_agent(
        agent_name=agent_name,
        user_prompt=prompt,
        skill=skill,
        memory_tags=memory_tags,
        thread_id=thread_id,
    )
    db.session.commit()  # request handler owns the transaction boundary
    return jsonify({
        "run_id": result.run.id,
        "thread_id": result.thread.id,
        "status": result.run.status,
        "text": result.text,
        "cost_usd": float(result.run.cost_usd) if result.run.cost_usd else None,
    })


@bp.route("/approvals", methods=["GET"])
@require_root_admin
def approvals_list():
    return jsonify({
        "pending": [
            {"id": p.id, "agent_id": p.agent_id, "action_type": p.action_type,
             "target": p.target, "payload": p.payload,
             "rationale": p.rationale, "skill": p.skill,
             "proposed_at": p.proposed_at.isoformat() + "Z",
             "expires_at": p.expires_at.isoformat() + "Z"}
            for p in list_pending()
        ]
    })


@bp.route("/approvals/<int:pending_id>/approve", methods=["POST"])
@require_root_admin
def approvals_approve(pending_id: int):
    body = request.get_json(silent=True) or {}
    edited = body.get("edited_payload")
    decided_by = body.get("decided_by", "founder")
    p = approve(pending_id, decided_by=decided_by, edited_payload=edited)
    db.session.commit()
    return jsonify({"id": p.id, "decision": p.decision})


@bp.route("/approvals/<int:pending_id>/reject", methods=["POST"])
@require_root_admin
def approvals_reject(pending_id: int):
    body = request.get_json(silent=True) or {}
    note = body.get("note")
    decided_by = body.get("decided_by", "founder")
    p = reject(pending_id, decided_by=decided_by, note=note)
    db.session.commit()
    return jsonify({"id": p.id, "decision": p.decision})
