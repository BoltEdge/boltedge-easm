import hashlib
from uuid import uuid4
from app.models import ApiKey


def _sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _make_agent_key(db_session, test_org, test_user, scopes):
    raw = "nk_agent_" + uuid4().hex + uuid4().hex[:8]
    db_session.add(ApiKey(
        organization_id=test_org.id, user_id=test_user.id, name="phase2a",
        key_prefix="nk_agent_", key_hash=_sha256(raw),
        kind="agent", scopes=scopes,
    ))
    db_session.flush()
    return raw


def test_findings_recent_requires_scope(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user, ["read:stats"])
    resp = client.get("/api/internal/findings/recent",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 403


def test_findings_recent_returns_list(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user, ["read:findings"])
    resp = client.get("/api/internal/findings/recent",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_contact_requests_recent(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user,
                           ["read:contact_requests"])
    resp = client.get("/api/internal/contact-requests/recent",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "contact_requests" in data
    assert isinstance(data["contact_requests"], list)


def test_audit_log_recent(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user, ["read:audit_log"])
    resp = client.get("/api/internal/audit-log/recent",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "entries" in data
    assert isinstance(data["entries"], list)


def test_scans_recent(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user, ["read:scans"])
    resp = client.get("/api/internal/scans/recent",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "scans" in data
    assert isinstance(data["scans"], list)


def test_findings_recent_limit_capped(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user, ["read:findings"])
    resp = client.get("/api/internal/findings/recent?limit=9999",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["findings"]) <= 200
