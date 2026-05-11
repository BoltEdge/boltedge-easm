import textwrap
from app.agents.profile_loader import AgentProfile, load_profile


def test_load_profile_parses_frontmatter_and_body(tmp_path):
    p = tmp_path / "founder-ops" / "agent.md"
    p.parent.mkdir(parents=True)
    p.write_text(textwrap.dedent("""\
        ---
        name: founder-ops
        display_name: Founder Ops
        allowed_tools:
          - read_internal_api
        secrets_allowed:
          - NANOEASM_API_KEY_RO
        external_writes: false
        cost_cap_monthly_usd: 50
        runtime_cap_seconds: 300
        tool_call_cap_per_run: 50
        default_model: claude-opus-4-7
        ---
        You are Founder Ops, the operational assistant.
        """))

    prof = load_profile(p)
    assert isinstance(prof, AgentProfile)
    assert prof.name == "founder-ops"
    assert prof.display_name == "Founder Ops"
    assert prof.allowed_tools == ["read_internal_api"]
    assert prof.external_writes is False
    assert prof.cost_cap_monthly_usd == 50
    assert "Founder Ops" in prof.system_prompt


def test_load_profile_missing_required_raises(tmp_path):
    p = tmp_path / "broken" / "agent.md"
    p.parent.mkdir(parents=True)
    p.write_text("---\nfoo: bar\n---\nbody\n")
    import pytest
    with pytest.raises(ValueError, match="missing required field"):
        load_profile(p)


def test_load_profile_external_writes_default_false(tmp_path):
    p = tmp_path / "min" / "agent.md"
    p.parent.mkdir(parents=True)
    p.write_text(textwrap.dedent("""\
        ---
        name: min
        display_name: Min
        allowed_tools: []
        secrets_allowed: []
        cost_cap_monthly_usd: 10
        runtime_cap_seconds: 60
        tool_call_cap_per_run: 10
        default_model: claude-opus-4-7
        ---
        body
        """))
    prof = load_profile(p)
    assert prof.external_writes is False
