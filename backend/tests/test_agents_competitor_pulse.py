from app.agents.skills.competitor_pulse import run_competitor_pulse
from app.agents.anthropic_client import FakeAnthropicClient


def test_run_competitor_pulse_persists_run_and_returns_text(db_session):
    fake_llm = FakeAnthropicClient(canned_text="### Competitor Pulse\n\nNothing notable this week.")
    result = run_competitor_pulse(client=fake_llm)
    assert result.text and "Competitor Pulse" in result.text
    assert result.run.skill == "competitor-pulse"
    assert result.run.status == "success"
