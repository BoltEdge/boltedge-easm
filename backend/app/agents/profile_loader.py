"""Loads agent identity from a markdown file with YAML frontmatter.

Profile path convention:
    backend/app/agents/profiles/<agent-name>/agent.md

The frontmatter declares: name, display_name, allowed_tools,
secrets_allowed, external_writes, hand_off_to, hand_off_from,
cost_cap_monthly_usd, runtime_cap_seconds, tool_call_cap_per_run,
default_model. The markdown body below the frontmatter is the
system prompt.
"""
from __future__ import annotations
import dataclasses
from pathlib import Path
from typing import Any

import yaml


REQUIRED = (
    "name", "display_name", "allowed_tools", "secrets_allowed",
    "cost_cap_monthly_usd", "runtime_cap_seconds",
    "tool_call_cap_per_run", "default_model",
)


@dataclasses.dataclass(frozen=True)
class AgentProfile:
    name: str
    display_name: str
    allowed_tools: list[str]
    secrets_allowed: list[str]
    external_writes: bool
    hand_off_to: list[str]
    hand_off_from: list[str]
    cost_cap_monthly_usd: int
    runtime_cap_seconds: int
    tool_call_cap_per_run: int
    default_model: str
    system_prompt: str
    source_path: str
    slack_display_name: str = ""
    slack_icon_url: str = ""
    slack_send_ack: bool = True


def load_profile(path: Path) -> AgentProfile:
    text = Path(path).read_text(encoding="utf-8")
    if not text.startswith("---"):
        raise ValueError(f"{path}: missing frontmatter")

    _, fm, body = text.split("---", 2)
    meta: dict[str, Any] = yaml.safe_load(fm) or {}

    for r in REQUIRED:
        if r not in meta:
            raise ValueError(f"{path}: missing required field '{r}'")

    return AgentProfile(
        name=meta["name"],
        display_name=meta["display_name"],
        allowed_tools=list(meta["allowed_tools"]),
        secrets_allowed=list(meta["secrets_allowed"]),
        external_writes=bool(meta.get("external_writes", False)),
        hand_off_to=list(meta.get("hand_off_to", [])),
        hand_off_from=list(meta.get("hand_off_from", [])),
        cost_cap_monthly_usd=int(meta["cost_cap_monthly_usd"]),
        runtime_cap_seconds=int(meta["runtime_cap_seconds"]),
        tool_call_cap_per_run=int(meta["tool_call_cap_per_run"]),
        default_model=str(meta["default_model"]),
        system_prompt=body.strip(),
        source_path=str(path),
        slack_display_name=str(
            meta.get("slack_display_name") or meta["display_name"]
        ),
        slack_icon_url=str(meta.get("slack_icon_url", "")),
        slack_send_ack=bool(meta.get("slack_send_ack", True)),
    )


PROFILES_DIR = Path(__file__).parent / "profiles"


def load_profile_by_name(agent_name: str) -> AgentProfile:
    p = PROFILES_DIR / agent_name / "agent.md"
    if not p.exists():
        raise FileNotFoundError(f"no profile at {p}")
    return load_profile(p)
