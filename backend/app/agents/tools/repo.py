"""Repo access tools: git_read (Phase 2A Stage C, this task) and
read_repo_file (next task).

git_read runs read-only git subcommands against the bind-mounted repo
at /repo. Subcommand allowlist enforced; args passed as a list (no
shell). Stderr surfaced on non-zero exit so the agent can recover.
"""
from __future__ import annotations
import subprocess

from . import ToolDef, register_tool


REPO_PATH = "/repo"
GIT_READ_TIMEOUT_SECONDS = 10
GIT_READ_RESULT_CAP_BYTES = 50_000

ALLOWED_GIT_SUBCOMMANDS = {
    "log", "show", "diff", "blame", "status", "ls-tree", "branch",
}


def _truncate(s: str, cap_bytes: int) -> str:
    b = s.encode("utf-8")
    if len(b) <= cap_bytes:
        return s
    return b[:cap_bytes].decode("utf-8", errors="ignore") + (
        f"\n\n…[truncated at {cap_bytes} bytes]"
    )


def git_read_handler(command: str, args: list[str] | None = None) -> str:
    if command not in ALLOWED_GIT_SUBCOMMANDS:
        return (f"[rejected: subcommand '{command}' not allowed. "
                f"Allowed: {', '.join(sorted(ALLOWED_GIT_SUBCOMMANDS))}]")

    args = args or []
    for a in args:
        if not isinstance(a, str):
            return f"[rejected: non-string arg {a!r}]"
        if any(ch in a for ch in (";", "&&", "||", "|", "`", "\n")):
            return f"[rejected: arg contains shell metacharacter: {a!r}]"

    cmd = ["git", "-C", REPO_PATH, command, *args]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=GIT_READ_TIMEOUT_SECONDS,
            check=False,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return f"[git_read timeout after {GIT_READ_TIMEOUT_SECONDS}s]"
    except FileNotFoundError:
        return "[rejected: git is not installed in this container]"

    if proc.returncode != 0:
        return f"[git exit {proc.returncode}]\nstderr: {proc.stderr}"

    return _truncate(proc.stdout, GIT_READ_RESULT_CAP_BYTES)


register_tool(ToolDef(
    name="git_read",
    description=(
        "Run a read-only git command against the Nano EASM repo. "
        "Allowed subcommands: log, show, diff, blame, status, ls-tree, "
        "branch. Pass args as a list (e.g. command='log', args=['-5', "
        "'--oneline']). Output truncated to 50 KB."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "enum": sorted(ALLOWED_GIT_SUBCOMMANDS),
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional arguments to pass to the subcommand.",
            },
        },
        "required": ["command"],
    },
    handler=git_read_handler,
    idempotent=True,
    result_cap_bytes=GIT_READ_RESULT_CAP_BYTES,
))
