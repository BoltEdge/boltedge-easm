"""Maya :: weekly-finding-brief skill.

Maya pulls recent findings (last 7 days) from /api/internal/findings/recent,
groups them by theme, identifies anything noteworthy. For findings that
reference CVEs, she uses web_fetch to add threat-intel context. Output
is a markdown brief emailed to the founder.

Trigger: Wednesday 08:00 (scheduled) or manual.
"""
from __future__ import annotations
import os

from app.agents.runtime import run_agent, RunResult
from app.agents.send_service import send_digest_email
from app.agents.approvals import propose_action


SKILL_NAME = "weekly-finding-brief"
SKILL_PROMPT = """\
Produce the weekly security findings brief for the director of Nano EASM in markdown.

Your job: review what showed up in our scans this week and tell the director what matters.

1. Use read_internal_api with endpoint='findings/recent' to pull the last 7 days of findings. Optionally filter by severity if there are too many.

2. Identify themes: are multiple orgs hitting the same finding? Is one CVE family appearing repeatedly? Any unusual spike?

3. For findings referencing a specific CVE, use web_fetch on the NVD entry (https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNN) to add: known exploits, severity context, recent activity. Cite the URL.

4. Pick the 3–5 findings (or themes) most worth the director's time.

Format:
- One-sentence punchline (the most important security signal of the week)
- Top findings list (3–5 items: severity + title + brief description + which org(s))
- Themes paragraph (what's happening across the fleet)
- Threat-intel notes (CVE-level context for anything that warranted it)
- Recommendation (if any)

Voice: factual, technical when needed, plain when not. Distinguish observed-true from likely-true. Never invent CVE numbers or severity ratings.
"""


def run_weekly_finding_brief(client=None, send: bool = False) -> RunResult:
    result = run_agent(
        agent_name="security-analyst",
        user_prompt=SKILL_PROMPT,
        skill=SKILL_NAME,
        memory_tags=["topic:findings", "skill:weekly-finding-brief"],
        client=client,
    )

    if send and result.text:
        founder_email = os.environ.get("FOUNDER_EMAIL")
        if founder_email:
            send_digest_email(
                to=founder_email,
                subject="Weekly Security Findings Brief — Maya",
                markdown=result.text,
            )

    if result.text and result.run.status == "success":
        from datetime import date
        propose_action(
            agent_id="security-analyst",
            action_type="memory-write",
            target=f"finding-brief:{date.today().isoformat()}",
            payload={
                "value": {"summary_excerpt": result.text[:600]},
                "tags": ["skill:weekly-finding-brief", "topic:findings"],
                "source": "skill-output",
            },
            rationale="weekly finding brief snapshot",
            skill=SKILL_NAME,
            run_id=result.run.id,
        )

    return result
