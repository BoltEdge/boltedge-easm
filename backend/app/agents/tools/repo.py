"""Repo access tools: git_read and read_repo_file (Phase 2A).

git_read runs read-only git subcommands against the bind-mounted repo
at /repo. Subcommand allowlist enforced; args passed as a list (no
shell). Stderr surfaced on non-zero exit so the agent can recover.

read_repo_file reads arbitrary files from the repo by relative path.
Denylist blocks .git/, .env*, *.key, *.pem, *.p12. Symlinks rejected.
Path traversal blocked. 100 KB cap on returned content.
"""
from __future__ import annotations
import fnmatch
import os
import subprocess
from pathlib import Path

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


# ---------------------------------------------------------------------------
# read_repo_file — safe direct file reader
# ---------------------------------------------------------------------------

READ_REPO_FILE_RESULT_CAP_BYTES = 100_000

DENYLIST_PATTERNS = (
    ".git/*",
    ".env",
    ".env.*",
    "*.key",
    "*.pem",
    "*.p12",
)


def _matches_denylist(rel_path: str) -> bool:
    """Check the relative path against the denylist patterns. Each segment
    is also checked so '.env' anywhere in the path matches."""
    rel = rel_path.replace("\\", "/")
    for pattern in DENYLIST_PATTERNS:
        if fnmatch.fnmatch(rel, pattern):
            return True
        for seg in rel.split("/"):
            if fnmatch.fnmatch(seg, pattern):
                return True
    return False


def read_repo_file_handler(path: str) -> str:
    if os.path.isabs(path):
        return f"[rejected: absolute paths not allowed; got '{path}']"
    if ".." in Path(path).parts:
        return f"[rejected: path traversal not allowed; got '{path}']"
    if _matches_denylist(path):
        return (f"[rejected: '{path}' matches denylist "
                f"(.git/, .env*, *.key, *.pem, *.p12)]")

    full = (Path(REPO_PATH) / path).resolve()
    try:
        full.relative_to(Path(REPO_PATH).resolve())
    except ValueError:
        return f"[rejected: resolved path is outside repo root]"

    if not full.exists():
        return f"[file not found: '{path}']"
    if full.is_symlink():
        return f"[rejected: symlinks not allowed; '{path}' is a symlink]"
    if not full.is_file():
        return f"[rejected: '{path}' is not a regular file]"

    try:
        data = full.read_bytes()
    except OSError as e:
        return f"[read error: {e}]"

    if len(data) > READ_REPO_FILE_RESULT_CAP_BYTES:
        excerpt = data[:READ_REPO_FILE_RESULT_CAP_BYTES].decode(
            "utf-8", errors="replace",
        )
        return (excerpt + f"\n\n…[file too large; truncated at "
                f"{READ_REPO_FILE_RESULT_CAP_BYTES} bytes. Use git_read "
                f"'show HEAD:{path}' for a specific revision or ask for "
                f"a smaller range.]")

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace") + (
            "\n\n…[file is not valid UTF-8; rendered with replacement chars]"
        )


register_tool(ToolDef(
    name="read_repo_file",
    description=(
        "Read a file from the Nano EASM repo by its path relative to "
        "repo root. Example: 'backend/app/agents/runtime.py'. Returns "
        "file text. Denylist blocks .git/, .env*, *.key, *.pem, *.p12. "
        "Symlinks rejected. 100 KB cap; larger files return a truncation "
        "notice."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path relative to the repo root.",
            },
        },
        "required": ["path"],
    },
    handler=read_repo_file_handler,
    idempotent=True,
    result_cap_bytes=READ_REPO_FILE_RESULT_CAP_BYTES,
))
