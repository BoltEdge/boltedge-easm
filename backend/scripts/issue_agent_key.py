"""Issue (or rotate) an API key for one agent.

Usage:
    cd backend && python -m scripts.issue_agent_key founder-ops read:stats read:findings

Prints the raw key to stdout ONCE. Save it immediately — it will not be
shown again. The DB stores only the SHA-256 hash.
"""
from __future__ import annotations
import hashlib
import secrets
import sys

from app import create_app
from app.extensions import db
from app.models import ApiKey, Organization, User


def main():
    if len(sys.argv) < 3:
        print("usage: python -m scripts.issue_agent_key <agent-name> <scope> [<scope> ...]")
        sys.exit(1)

    agent = sys.argv[1]
    scopes = list(sys.argv[2:])

    app = create_app()
    with app.app_context():
        # Use the founder/superadmin's org as the holder.
        org = Organization.query.first()
        if not org:
            print("no Organization rows; create one first")
            sys.exit(1)

        # ApiKey.user_id is nullable=False, so we must bind to a real user.
        # Prefer a superadmin (root admin first, then any superadmin).
        user = (
            User.query.filter_by(is_root_admin=True).first()
            or User.query.filter_by(is_superadmin=True).first()
            or User.query.filter_by(organization_id=org.id).first()
        )
        if not user:
            print("no User rows; create a superadmin first")
            sys.exit(1)

        # Revoke any existing agent keys for this agent (idempotent rotate).
        existing = ApiKey.query.filter_by(name=agent, kind="agent").all()
        for k in existing:
            db.session.delete(k)
        db.session.flush()

        # Generate.
        raw = "nk_agent_" + secrets.token_urlsafe(32)
        rec = ApiKey(
            organization_id=org.id,
            user_id=user.id,  # bound to the superadmin user (ApiKey.user_id is NOT NULL)
            name=agent,
            key_prefix=raw[:11],
            key_hash=hashlib.sha256(raw.encode()).hexdigest(),
            kind="agent",
            scopes=scopes,
        )
        db.session.add(rec)
        db.session.commit()

        print(f"\n  Agent:     {agent}")
        print(f"  Scopes:    {scopes}")
        print(f"  Bound to:  {user.email} (id={user.id})")
        print(f"  KEY (save now — shown only once):\n\n    {raw}\n")


if __name__ == "__main__":
    main()
