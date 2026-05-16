"""Founder Ops :: weekly-summary skill.

Calls the internal stats API, asks the LLM to summarise in brand voice,
emails the digest to the founder. Writes a memory entry capturing this
week's headline numbers (proposed via approval queue).
"""
from __future__ import annotations
import os

import requests

from app.agents.runtime import run_agent, RunResult
from app.agents.send_service import send_digest_email
from app.agents.approvals import propose_action
from app.agents.slack.publisher import broadcast_brief


SKILL_NAME = "weekly-summary"
SKILL_PROMPT_TEMPLATE = """\
Produce a weekly summary for the founder of Nano EASM in markdown.

Stats for the past 7 days:

{stats_block}

Format:
1. One-sentence punchline (the headline number).
2. Bulleted facts (signups, scans, plan mix).
3. One observation worth flagging (delta vs. last week if obvious).

Voice: terse, factual. No filler. The founder wants signal."""


def _fetch_weekly_stats() -> dict:
    """Calls /api/internal/stats/weekly. The agent platform is co-hosted,
    but goes through HTTP to preserve the seam."""
    base = os.environ.get("INTERNAL_API_BASE", "http://localhost:5000")
    key = os.environ["NANOEASM_API_KEY_AGENTS_FOUNDER_OPS"]
    resp = requests.get(
        f"{base}/api/internal/stats/weekly",
        headers={"Authorization": f"Bearer {key}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def _format_stats_block(s: dict) -> str:
    return (
        f"- Window: {s['window']['from']} → {s['window']['to']} "
        f"({s['window']['days']}d)\n"
        f"- Orgs total: {s['orgs_total']}\n"
        f"- Users total: {s['users_total']}\n"
        f"- Signups in window: {s['signups_in_window']}\n"
        f"- Scans in window: {s['scans_in_window']}\n"
        f"- Plan mix: {s['plan_mix']}"
    )


def run_weekly_summary(client=None, send: bool = False) -> RunResult:
    stats = _fetch_weekly_stats()
    user_prompt = SKILL_PROMPT_TEMPLATE.format(
        stats_block=_format_stats_block(stats),
    )

    result = run_agent(
        agent_name="founder-ops",
        user_prompt=user_prompt,
        skill=SKILL_NAME,
        memory_tags=["topic:metrics", "skill:weekly-summary"],
        client=client,
    )

    if send and result.text:
        subject = (
            f"Weekly Summary — "
            f"{stats['signups_in_window']} signups, "
            f"{stats['scans_in_window']} scans"
        )
        founder_email = os.environ.get("FOUNDER_EMAIL")
        if founder_email:
            send_digest_email(
                to=founder_email,
                subject=subject,
                markdown=result.text,
            )
        try:
            broadcast_brief(
                agent_id="founder-ops",
                subject=subject,
                body=result.text,
            )
        except Exception:
            import logging
            logging.getLogger("agents.skills.weekly_summary").exception(
                "slack broadcast failed"
            )

    if result.text and result.run.status == "success":
        propose_action(
            agent_id="founder-ops",
            action_type="memory-write",
            target=f"weekly:{stats['window']['to'][:10]}",
            payload={
                "value": {
                    "signups": stats["signups_in_window"],
                    "scans": stats["scans_in_window"],
                    "summary_excerpt": result.text[:500],
                },
                "tags": ["skill:weekly-summary", "topic:metrics"],
                "source": "skill-output",
            },
            rationale="weekly-summary headline numbers",
            skill=SKILL_NAME,
            run_id=result.run.id,
        )

    return result
