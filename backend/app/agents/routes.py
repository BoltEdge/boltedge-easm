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
from .skills import get_skill, skills_for_agent, invoke_skill


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

    agent_skills = skills_for_agent(agent_name)

    return jsonify({
        "name": p.name,
        "display_name": p.display_name,
        "system_prompt": p.system_prompt,
        "allowed_tools": p.allowed_tools,
        "external_writes": p.external_writes,
        "cost_cap_monthly_usd": p.cost_cap_monthly_usd,
        "default_model": p.default_model,
        "skills": [
            {
                "name": s.name,
                "display_name": s.display_name,
                "description": s.description,
                "schedule": s.schedule,
            }
            for s in agent_skills
        ],
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


@bp.route("/threads/<int:thread_id>", methods=["GET"])
@require_root_admin
def thread_detail(thread_id: int):
    thread = AgentThread.query.get(thread_id)
    if thread is None:
        return jsonify({"error": "not_found"}), 404

    messages = (
        AgentMessage.query.filter_by(thread_id=thread_id)
        .order_by(AgentMessage.created_at)
        .all()
    )
    runs = (
        AgentRun.query.filter_by(thread_id=thread_id)
        .order_by(AgentRun.started_at)
        .all()
    )

    # Enrich thread with display_name from the agent profile so the
    # frontend back-link can show "<display_name> (<agent_id>)" without
    # a second round-trip.
    display_name: str | None = None
    try:
        from .profile_loader import load_profile_by_name
        p = load_profile_by_name(thread.agent_id)
        display_name = p.display_name
    except Exception:
        pass

    return jsonify({
        "thread": {
            "id": thread.id,
            "agent_id": thread.agent_id,
            "display_name": display_name,
            "title": thread.title,
            "created_at": thread.created_at.isoformat() + "Z",
        },
        "messages": [
            {
                "id": m.id,
                "role": m.role,
                "created_at": m.created_at.isoformat() + "Z",
                "content": m.content,
                **({"tokens_used": m.tokens_used} if m.tokens_used is not None else {}),
            }
            for m in messages
        ],
        "runs": [
            {
                "id": r.id,
                "skill": r.skill,
                "status": r.status,
                "cost_usd": float(r.cost_usd) if r.cost_usd is not None else None,
                "duration_ms": r.duration_ms,
                "started_at": r.started_at.isoformat() + "Z",
                "finished_at": r.finished_at.isoformat() + "Z" if r.finished_at else None,
            }
            for r in runs
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


@bp.route("/<agent_name>/run-skill", methods=["POST"])
@require_root_admin
def trigger_skill_run(agent_name: str):
    body = request.get_json(force=True) or {}
    skill_name = body.get("skill")
    send = bool(body.get("send", True))

    if not skill_name:
        return jsonify({"error": "skill is required"}), 400

    spec = get_skill(skill_name)
    if spec is None:
        return jsonify({"error": f"unknown skill: {skill_name}"}), 404
    if spec.agent_id != agent_name:
        return jsonify({
            "error": f"skill {skill_name} belongs to {spec.agent_id}, not {agent_name}"
        }), 400

    try:
        result = invoke_skill(skill_name, send=send)
    except Exception as e:
        return jsonify({"error": f"skill failed: {type(e).__name__}: {e}"}), 500

    db.session.commit()
    return jsonify({
        "run_id": result.run.id,
        "thread_id": result.thread.id,
        "status": result.run.status,
        "text": result.text,
        "cost_usd": float(result.run.cost_usd) if result.run.cost_usd else None,
        "skill": skill_name,
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
             "expires_at": p.expires_at.isoformat() + "Z",
             "applied_result": p.applied_result}
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
    return jsonify({"id": p.id, "decision": p.decision, "applied_result": p.applied_result})


@bp.route("/approvals/<int:pending_id>/reject", methods=["POST"])
@require_root_admin
def approvals_reject(pending_id: int):
    body = request.get_json(silent=True) or {}
    note = body.get("note")
    decided_by = body.get("decided_by", "founder")
    p = reject(pending_id, decided_by=decided_by, note=note)
    db.session.commit()
    return jsonify({"id": p.id, "decision": p.decision, "applied_result": p.applied_result})
