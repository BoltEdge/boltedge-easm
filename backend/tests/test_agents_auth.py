from flask import jsonify
from app.agents.auth import require_agent_key
from app.models import ApiKey
import hashlib


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def test_missing_header_returns_401(app, client):
    @app.route("/_test_internal")
    @require_agent_key(scope="read:stats")
    def view():
        return jsonify(ok=True)

    resp = client.get("/_test_internal")
    assert resp.status_code == 401


def test_invalid_key_returns_401(app, client):
    @app.route("/_test_internal2")
    @require_agent_key(scope="read:stats")
    def view():
        return jsonify(ok=True)

    resp = client.get("/_test_internal2",
                       headers={"Authorization": "Bearer bogus"})
    assert resp.status_code == 401


def test_customer_kind_key_rejected(app, client, db_session, test_org, test_user):
    # An ordinary customer key must not be usable as an agent key
    raw = "nk_test_" + "a" * 32
    db_session.add(ApiKey(
        organization_id=test_org.id, user_id=test_user.id, name="cust",
        key_prefix="nk_test_", key_hash=_sha256(raw),
        kind="customer",
    ))
    db_session.flush()

    @app.route("/_test_internal3")
    @require_agent_key(scope="read:stats")
    def view():
        return jsonify(ok=True)

    resp = client.get("/_test_internal3",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 401


def test_agent_kind_key_with_scope_allowed(app, client, db_session, test_org, test_user):
    raw = "nk_agent_" + "b" * 32
    db_session.add(ApiKey(
        organization_id=test_org.id, user_id=test_user.id, name="founder-ops",
        key_prefix="nk_agent_", key_hash=_sha256(raw),
        kind="agent", scopes=["read:stats", "read:findings"],
    ))
    db_session.flush()

    @app.route("/_test_internal4")
    @require_agent_key(scope="read:stats")
    def view():
        return jsonify(ok=True)

    resp = client.get("/_test_internal4",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200


def test_agent_key_missing_scope_rejected(app, client, db_session, test_org, test_user):
    raw = "nk_agent_" + "c" * 32
    db_session.add(ApiKey(
        organization_id=test_org.id, user_id=test_user.id, name="founder-ops",
        key_prefix="nk_agent_", key_hash=_sha256(raw),
        kind="agent", scopes=["read:findings"],   # missing read:stats
    ))
    db_session.flush()

    @app.route("/_test_internal5")
    @require_agent_key(scope="read:stats")
    def view():
        return jsonify(ok=True)

    resp = client.get("/_test_internal5",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 403
