from app.agents.skills.weekly_finding_brief import run_weekly_finding_brief
from app.agents.anthropic_client import FakeAnthropicClient


def test_run_weekly_finding_brief_persists_run_and_returns_text(db_session):
    fake_llm = FakeAnthropicClient(canned_text="### Findings Brief\n\nNothing critical this week.")
    result = run_weekly_finding_brief(client=fake_llm)
    assert result.text and "Findings Brief" in result.text
    assert result.run.skill == "weekly-finding-brief"
    assert result.run.status == "success"
