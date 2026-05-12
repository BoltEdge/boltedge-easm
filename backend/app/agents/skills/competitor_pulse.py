"""Ava :: competitor-pulse skill.

Ava surveys the ASM/EASM competitive landscape weekly. Unlike Sam's
weekly summary (which pulls internal data), Ava's input comes from the
public web — she uses web_search and web_fetch to look at competitor
sites, recent announcements, and content. Output is a markdown brief
emailed to the founder.

Trigger: Tuesday 08:00 (scheduled) or manual.
"""
from __future__ import annotations
import os

from app.agents.runtime import run_agent, RunResult
from app.agents.send_service import send_digest_email
from app.agents.approvals import propose_action


SKILL_NAME = "competitor-pulse"
SKILL_PROMPT = """\
Produce a weekly competitor pulse for the founder of Nano EASM in markdown.

Your job: survey the ASM/EASM competitive landscape and report what changed this week. Specifically:

1. Identify 3–5 competitors in the ASM/EASM space (Detectify, CyCognito, Censys ASM, Bishop Fox CAST, etc. — but pick what's actually current; use web_search to check). Use web_search if you don't know which competitors are most relevant right now.

2. For each, use web_fetch to read their main product / pricing / blog page. Note what's new (last 30 days if possible): announcements, new features, pricing changes, notable content.

3. Summarise themes — what's the field moving toward? Is anyone positioning in a way Nano EASM should respond to?

4. Flag anything worth the director's attention: a competitor's move that changes our positioning, a content angle worth borrowing, a market signal.

Format:
- One-sentence punchline (the most important thing this week)
- Per-competitor bullet (name + 1-2 lines on what changed)
- Themes paragraph (2-3 lines)
- Action items (if any)

Voice: direct, market-aware, evidence-backed. Cite a URL for any specific claim. If a competitor didn't change anything this week, say so — don't manufacture activity.
"""


def run_competitor_pulse(client=None, send: bool = False) -> RunResult:
    result = run_agent(
        agent_name="strategy",
        user_prompt=SKILL_PROMPT,
        skill=SKILL_NAME,
        memory_tags=["topic:competitor", "skill:competitor-pulse"],
        client=client,
    )

    if send and result.text:
        founder_email = os.environ.get("FOUNDER_EMAIL")
        if founder_email:
            send_digest_email(
                to=founder_email,
                subject="Weekly Competitor Pulse — Ava",
                markdown=result.text,
            )

    if result.text and result.run.status == "success":
        from datetime import date
        propose_action(
            agent_id="strategy",
            action_type="memory-write",
            target=f"competitor-pulse:{date.today().isoformat()}",
            payload={
                "value": {"summary_excerpt": result.text[:600]},
                "tags": ["skill:competitor-pulse", "topic:competitor"],
                "source": "skill-output",
            },
            rationale="competitor-pulse weekly snapshot",
            skill=SKILL_NAME,
            run_id=result.run.id,
        )

    return result
