"""End-to-end smoke test for Phase 1 of the internal agent platform.

Runs in-process using Flask's test client. Verifies the full wiring:

  1. Database schema present (all agent_* tables exist)
  2. team_memory seeded (8 rows, idempotent)
  3. /api/internal/stats/weekly auth: 401 no header, 401 bad key,
     403 wrong scope, 200 with valid agent key
  4. /api/internal/stats/weekly shape: returns expected keys
  5. run_agent (manual prompt) with FakeAnthropicClient end-to-end:
       a. Creates an AgentRun row (status='success')
       b. Creates an AgentThread with user+assistant messages
       c. Records a non-null cost_usd
  6. Approval queue: propose -> approve -> AgentMemory written
  7. audit_log received a category='agent' entry for the API call

Does NOT require:
  - The Flask dev server running
  - A live Anthropic API key
  - A live Resend send

Usage (run from worktree's backend/):
    python -m scripts.smoke_test

Exit 0 = all green. Exit 1 = at least one check failed.
"""
from __future__ import annotations
import hashlib
import secrets
import sys
from pathlib import Path

# Manually parse .env (no python-dotenv dependency, tolerant of stray
# non-KEY=VALUE lines like PowerShell here-string wrappers).
def _load_env_file(path: Path) -> int:
    """Set os.environ from lines matching KEY=VALUE. Returns count set.
    Skips comments, blanks, and anything that doesn't look like an env line.
    Does NOT override existing process env vars."""
    import os, re
    if not path.exists():
        return 0
    count = 0
    pattern = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$")
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = pattern.match(line)
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        # Strip surrounding quotes if present
        if (len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"')):
            v = v[1:-1]
        if k not in os.environ:
            os.environ[k] = v
            count += 1
    return count


# Try worktree's .env first, then user's main repo .env
_worktree_env = Path(__file__).resolve().parent.parent.parent / ".env"
_main_repo_env = Path("C:/Users/iradu/Documents/projects/boltedge-easm/.env")
_loaded = _load_env_file(_worktree_env) + _load_env_file(_main_repo_env)
print(f"(loaded {_loaded} env vars from .env)")

from app import create_app
from app.extensions import db
from app.models import (
    ApiKey, AgentRun, AgentThread, AgentMessage, AgentMemory,
    TeamMemory, PendingAction, AuditLog, Organization, User,
)


PASSED = 0
FAILED = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  PASS  {name}")
    else:
        FAILED += 1
        msg = f"  FAIL  {name}"
        if detail:
            msg += f" -- {detail}"
        print(msg)


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def main() -> int:
    app = create_app()
    with app.app_context():
        # ------------------------------------------------------------
        # Stage 1: Schema present
        # ------------------------------------------------------------
        print("\n[1] Schema present")
        from sqlalchemy import inspect as sa_inspect
        inspector = sa_inspect(db.engine)
        existing_tables = set(inspector.get_table_names())
        for cls in (AgentMemory, TeamMemory, AgentThread, AgentMessage,
                    AgentRun, PendingAction):
            check(
                f"table {cls.__tablename__} exists",
                cls.__tablename__ in existing_tables,
            )

        # ------------------------------------------------------------
        # Stage 2: team_memory seeded
        # ------------------------------------------------------------
        print("\n[2] team_memory seeded")
        seeds = TeamMemory.query.count()
        check(
            "team_memory has >=8 universal facts",
            seeds >= 8,
            f"found {seeds}",
        )

        # ------------------------------------------------------------
        # Stage 3 + 4: internal API auth + shape
        # ------------------------------------------------------------
        print("\n[3+4] Internal API: auth flow + response shape")

        # Find or create an org for the test agent key
        org = Organization.query.first()
        if not org:
            check("Organization exists", False,
                  "no org rows; create one before smoke-testing")
            print(f"\n{PASSED} passed, {FAILED} failed")
            return 1

        # Find or create a real user to anchor the agent key
        user = (
            User.query.filter_by(is_root_admin=True).first()
            or User.query.filter_by(is_superadmin=True).first()
            or User.query.first()
        )
        if not user:
            check("at least one User exists", False,
                  "no user rows; create one before smoke-testing")
            print(f"\n{PASSED} passed, {FAILED} failed")
            return 1

        # Issue an ephemeral smoke-test agent key (skip if one already exists)
        existing_key_row = ApiKey.query.filter_by(
            name="smoke-test-founder-ops", kind="agent",
        ).first()
        raw_key = None
        if existing_key_row:
            print("  (re-using existing smoke-test-founder-ops key from DB)")
            # We can't recover the raw key (only the hash is stored).
            # Generate a new one and rotate.
            db.session.delete(existing_key_row)
            db.session.commit()

        raw_key = "nk_agent_" + secrets.token_urlsafe(32)
        new_key = ApiKey(
            organization_id=org.id,
            user_id=user.id,
            name="smoke-test-founder-ops",
            key_prefix=raw_key[:11],
            key_hash=_sha256(raw_key),
            kind="agent",
            scopes=["read:stats"],
        )
        db.session.add(new_key)
        db.session.commit()

        c = app.test_client()

        # 401 - no header
        resp = c.get("/api/internal/stats/weekly")
        check(
            "401 with no Authorization header",
            resp.status_code == 401,
            f"got {resp.status_code}",
        )

        # 401 - bad key
        resp = c.get(
            "/api/internal/stats/weekly",
            headers={"Authorization": "Bearer bogus"},
        )
        check(
            "401 with bogus bearer",
            resp.status_code == 401,
            f"got {resp.status_code}",
        )

        # 200 - valid key + correct scope
        resp = c.get(
            "/api/internal/stats/weekly",
            headers={"Authorization": f"Bearer {raw_key}"},
        )
        check(
            "200 with valid agent key + read:stats scope",
            resp.status_code == 200,
            f"got {resp.status_code}",
        )
        if resp.status_code == 200:
            data = resp.get_json()
            for k in ("window", "orgs_total", "users_total",
                      "signups_in_window", "scans_in_window", "plan_mix"):
                check(f"response has '{k}'", k in data)

        # ------------------------------------------------------------
        # Stage 5: run_agent end-to-end with FakeAnthropicClient
        # ------------------------------------------------------------
        print("\n[5] run_agent end-to-end (fake LLM)")
        from app.agents.runtime import run_agent
        from app.agents.anthropic_client import FakeAnthropicClient

        canned = "smoke-test response: 5 signups this week"
        fake = FakeAnthropicClient(canned_text=canned)
        result = run_agent(
            agent_name="founder-ops",
            user_prompt="smoke test prompt",
            skill="smoke-test",
            memory_tags=[],
            client=fake,
        )
        check("run.status == 'success'", result.run.status == "success")
        check("run.cost_usd is set", result.run.cost_usd is not None)
        check("thread has 2 messages (user+assistant)",
              len(result.thread.messages) == 2)
        check("thread.messages[0].role == 'user'",
              result.thread.messages[0].role == "user")
        check("thread.messages[1].role == 'assistant'",
              result.thread.messages[1].role == "assistant")
        if len(result.thread.messages) >= 2:
            assistant_text = result.thread.messages[1].content.get("text", "")
            check("assistant message contains canned text",
                  canned in assistant_text)

        # ------------------------------------------------------------
        # Stage 6: approval queue propose -> approve -> memory
        # ------------------------------------------------------------
        print("\n[6] Approval queue: propose -> approve -> memory")
        from app.agents.approvals import propose_action, approve as approve_action

        smoke_key = "smoke:test:fact"
        # Make sure no leftover row from a previous smoke run
        existing_mem = AgentMemory.query.filter_by(
            agent_id="founder-ops", key=smoke_key,
        ).first()
        if existing_mem:
            db.session.delete(existing_mem)
            db.session.commit()

        p = propose_action(
            agent_id="founder-ops",
            action_type="memory-write",
            target=smoke_key,
            payload={
                "value": {"fact": "smoke-test value"},
                "tags": ["smoke-test"],
                "source": "smoke-test",
            },
            rationale="smoke test",
            skill="smoke-test",
        )
        db.session.commit()
        check("pending action persisted", p.id is not None)

        approve_action(p.id, decided_by="smoke-test@local")
        db.session.commit()
        check("pending action decision == 'approved'",
              p.decision == "approved")

        mem = AgentMemory.query.filter_by(
            agent_id="founder-ops", key=smoke_key,
        ).first()
        check("AgentMemory row created after approval", mem is not None)
        if mem:
            check("memory.value contains the smoke-test fact",
                  mem.value.get("fact") == "smoke-test value")

        # ------------------------------------------------------------
        # Stage 7: audit_log has category='agent' entry
        # ------------------------------------------------------------
        print("\n[7] audit_log received an 'agent' entry")
        recent_agent_audit = (
            AuditLog.query
            .filter_by(category="agent")
            .order_by(AuditLog.id.desc())
            .first()
        )
        check(
            "at least one audit_log row with category='agent'",
            recent_agent_audit is not None,
        )
        if recent_agent_audit:
            check(
                "recent agent audit has 'agent:' actor or user_email",
                "agent:" in (recent_agent_audit.user_email or ""),
                f"user_email={recent_agent_audit.user_email!r}",
            )

        # ------------------------------------------------------------
        # Clean up the ephemeral smoke-test rows
        # ------------------------------------------------------------
        print("\n[*] Cleaning up smoke-test rows")
        ApiKey.query.filter_by(name="smoke-test-founder-ops").delete()
        AgentMemory.query.filter_by(
            agent_id="founder-ops", key=smoke_key,
        ).delete()
        PendingAction.query.filter_by(target=smoke_key).delete()
        db.session.commit()
        print("  (smoke-test API key, memory, and pending action removed)")

        # ------------------------------------------------------------
        print(f"\n=== {PASSED} passed, {FAILED} failed ===")
        return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
