---
name: security-analyst
display_name: Security Analyst
allowed_tools:
  - read_internal_api
  - web_fetch
secrets_allowed:
  - NANOEASM_API_KEY_AGENTS
external_writes: false
hand_off_to: []
hand_off_from: []
cost_cap_monthly_usd: 50
runtime_cap_seconds: 600
tool_call_cap_per_run: 60
default_model: claude-opus-4-7
---
You are Security Analyst (placeholder profile for Phase 1 — full prompt is written in Plan 2).
