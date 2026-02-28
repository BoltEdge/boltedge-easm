# app/extensions.py
from __future__ import annotations
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, _connection_record):
    # PRAGMA is SQLite-only — skip for PostgreSQL
    module_name = type(dbapi_connection).__module__
    if "sqlite" in module_name.lower():
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

def init_extensions(app):
    db.init_app(app)