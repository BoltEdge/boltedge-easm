"""Registry of named skills owned by agents.

Each entry: skill_name -> SkillSpec(agent_id, module, function, display_name, description, schedule).
"""
from __future__ import annotations
import dataclasses
import importlib
from typing import Callable


@dataclasses.dataclass(frozen=True)
class SkillSpec:
    name: str
    agent_id: str
    module: str
    function: str
    display_name: str
    description: str
    schedule: str | None = None  # human-readable, e.g. "Monday 08:00"


SKILL_REGISTRY: dict[str, SkillSpec] = {
    "weekly-summary": SkillSpec(
        name="weekly-summary",
        agent_id="founder-ops",
        module="app.agents.skills.weekly_summary",
        function="run_weekly_summary",
        display_name="Weekly Summary",
        description=(
            "Pulls last 7 days of Nano EASM stats + audit log highlights, "
            "summarises into a markdown digest, emails to the founder."
        ),
        schedule="Monday 08:00",
    ),
    "competitor-pulse": SkillSpec(
        name="competitor-pulse",
        agent_id="strategy",
        module="app.agents.skills.competitor_pulse",
        function="run_competitor_pulse",
        display_name="Competitor Pulse",
        description=(
            "Surveys 3–5 ASM/EASM competitors via web_search + web_fetch, "
            "summarises what changed this week, emails to the founder."
        ),
        schedule="Tuesday 08:00",
    ),
    "weekly-finding-brief": SkillSpec(
        name="weekly-finding-brief",
        agent_id="security-analyst",
        module="app.agents.skills.weekly_finding_brief",
        function="run_weekly_finding_brief",
        display_name="Weekly Finding Brief",
        description=(
            "Pulls last 7 days of findings via the internal API, optionally "
            "fetches NVD entries for CVE-referenced ones, surfaces themes, "
            "emails to the founder."
        ),
        schedule="Wednesday 08:00",
    ),
}


def get_skill(name: str) -> SkillSpec | None:
    return SKILL_REGISTRY.get(name)


def skills_for_agent(agent_id: str) -> list[SkillSpec]:
    return [s for s in SKILL_REGISTRY.values() if s.agent_id == agent_id]


def invoke_skill(skill_name: str, send: bool = True):
    """Dynamic import + call the skill's run_X function. Returns the
    RunResult dataclass the skill module produces."""
    spec = get_skill(skill_name)
    if spec is None:
        raise ValueError(f"unknown skill: {skill_name!r}")
    module = importlib.import_module(spec.module)
    fn: Callable = getattr(module, spec.function)
    return fn(send=send)
