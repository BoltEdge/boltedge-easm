from app.agents.skills.weekly_summary import run_weekly_summary
from app.agents.anthropic_client import FakeAnthropicClient


def test_run_weekly_summary_persists_run_and_returns_text(db_session,
                                                          monkeypatch):
    # Stub the internal-API caller so the test doesn't depend on
    # /api/internal/stats/weekly being callable from in-process.
    fake_stats = {
        "window": {"from": "2026-05-04T00:00:00Z",
                    "to": "2026-05-11T00:00:00Z", "days": 7},
        "orgs_total": 42, "users_total": 75,
        "signups_in_window": 5, "scans_in_window": 130,
        "plan_mix": {"Free": 30, "Starter": 8, "Pro": 4},
    }
    monkeypatch.setattr(
        "app.agents.skills.weekly_summary._fetch_weekly_stats",
        lambda: fake_stats,
    )

    fake_llm = FakeAnthropicClient(
        canned_text="**This week:** 5 signups, 130 scans. Plan mix: 30/8/4.",
    )
    result = run_weekly_summary(client=fake_llm)
    assert result.text and "5 signups" in result.text
    assert result.run.skill == "weekly-summary"
    assert result.run.status == "success"
