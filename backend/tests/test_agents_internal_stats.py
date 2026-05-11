import hashlib
import uuid
from app.models import ApiKey


def _sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _make_agent_key(db_session, test_org, test_user, scopes):
    # Use a unique suffix per call to avoid key_hash uniqueness collisions
    # across tests. Use flush() not commit() to stay inside the SAVEPOINT.
    raw = "nk_agent_" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    db_session.add(ApiKey(
        organization_id=test_org.id, user_id=test_user.id, name="founder-ops",
        key_prefix="nk_agent_", key_hash=_sha256(raw),
        kind="agent", scopes=scopes,
    ))
    db_session.flush()
    return raw


def test_weekly_stats_requires_read_stats_scope(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user, scopes=["read:findings"])
    resp = client.get("/api/internal/stats/weekly",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 403


def test_weekly_stats_returns_expected_shape(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user, scopes=["read:stats"])
    resp = client.get("/api/internal/stats/weekly",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "window" in data
    assert "from" in data["window"]
    assert "to" in data["window"]
    for k in ("orgs_total", "users_total", "signups_in_window",
              "scans_in_window", "plan_mix"):
        assert k in data, f"missing key {k}"
    assert isinstance(data["plan_mix"], dict)
