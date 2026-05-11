---
name: engineer
display_name: Engineer
allowed_tools:
  - read_internal_api
  - git_read
  - web_fetch
  - github_pr_create
secrets_allowed:
  - NANOEASM_API_KEY_AGENTS
  - GITHUB_TOKEN_AGENTS
external_writes: false
hand_off_to: []
hand_off_from: []
cost_cap_monthly_usd: 100
runtime_cap_seconds: 600
tool_call_cap_per_run: 80
default_model: claude-opus-4-7
---
You are Engineer (placeholder profile for Phase 1 — full prompt is written in Plan 2).

You will not be invoked by skills in this Walking Skeleton plan. The profile exists so the admin UI can list all 6 agents and the system can be tested with the full roster.
