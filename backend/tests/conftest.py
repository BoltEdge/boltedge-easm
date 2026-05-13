"""
Test fixtures for backend/tests/.

Uses the real PostgreSQL database but wraps every test in a SAVEPOINT
(nested transaction) so no test data persists after the test exits.

Each test gets a **fresh Flask app instance** because tests in
test_agents_auth.py register routes at runtime via @app.route(...).
Flask blocks new route registrations after the first request on a given
app instance, so a session-scoped app fixture would cause
AssertionError on the second test. function scope is required here.

Fixtures:
    app        — Flask application (function-scoped — fresh per test)
    client     — Flask test client bound to the per-test app
    db_session — SQLAlchemy session with a SAVEPOINT; rolls back after test
    test_org   — Organisation row created for the test; flushed but not committed
    test_user  — User row created for the test; flushed but not committed
"""
from __future__ import annotations

import os
import sys
import pytest

# Ensure `app` package is importable (mirrors the root conftest.py).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault(
    "SQLALCHEMY_DATABASE_URI",
    "postgresql://easm_user:localdevpassword@localhost:5432/easm",
)
os.environ.setdefault("SECRET_KEY", "local-dev-secret-key-tests")
os.environ.setdefault("CORS_ORIGINS", "http://localhost:3000")


@pytest.fixture()
def app():
    """
    Fresh Flask application per test.

    Function scope is required because tests register routes via
    @app.route(...) inside the test body. Flask raises AssertionError
    if a route is registered after the first request, so each test must
    start with an app that has never served a request.
    """
    from app import create_app as _create_app

    flask_app = _create_app()
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    yield flask_app
    # Dispose the engine so its connections are released back to the
    # postgres server. Without this, each function-scoped app accumulates
    # a fresh connection pool, and CI hits "FATAL: sorry, too many
    # clients already" once the test count crosses ~20.
    from app.extensions import db as _db
    with flask_app.app_context():
        _db.engine.dispose()


@pytest.fixture()
def db_session(app):
    """
    Yield a SQLAlchemy scoped session wrapped in a SAVEPOINT.

    Uses a connection-level transaction so all ORM flushes/queries go
    through the same connection. The SAVEPOINT is rolled back after the
    test so the database is left in exactly its pre-test state.
    """
    from app.extensions import db as _db

    with app.app_context():
        connection = _db.engine.connect()
        transaction = connection.begin()

        # Redirect the scoped session to this specific connection.
        _db.session.bind = connection  # type: ignore[attr-defined]

        # Nested (SAVEPOINT) so the session itself can also use
        # begin_nested() internally without disrupting our outer rollback.
        nested = connection.begin_nested()

        yield _db.session

        # Teardown: roll back all changes made during the test.
        _db.session.remove()
        if nested.is_active:
            nested.rollback()
        if transaction.is_active:
            transaction.rollback()
        connection.close()

        _db.session.bind = None  # type: ignore[attr-defined]


@pytest.fixture()
def test_org(db_session):
    """Ephemeral Organisation, flushed (has a PK) but never committed."""
    import uuid
    from app.models import Organization

    org = Organization(
        name="Test Org",
        slug=f"test-org-{uuid.uuid4().hex[:8]}",
        plan="free",
        plan_status="active",
    )
    db_session.add(org)
    db_session.flush()
    return org


@pytest.fixture()
def test_user(db_session, test_org):
    """Ephemeral User in test_org, flushed but never committed."""
    import uuid
    from app.models import User, OrganizationMember

    user = User(
        email=f"testuser-{uuid.uuid4().hex[:8]}@example.com",
        name="Test User",
        email_verified=True,
    )
    db_session.add(user)
    db_session.flush()

    member = OrganizationMember(
        organization_id=test_org.id,
        user_id=user.id,
        role="owner",
    )
    db_session.add(member)
    db_session.flush()

    return user


@pytest.fixture()
def client(app):
    """Flask test client bound to the per-test app."""
    with app.app_context():
        with app.test_client() as c:
            yield c
