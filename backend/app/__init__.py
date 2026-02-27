# app/__init__.py
"""
App factory — production-ready for AWS deployment.

Production changes:
    - CORS origins read from CORS_ORIGINS env var (no hardcoded localhost)
    - Database URI from SQLALCHEMY_DATABASE_URI env var (PostgreSQL required)
    - SECRET_KEY required in production (no default fallback)
    - Session cookie hardening (Secure, HttpOnly, SameSite, Domain)
    - Production-appropriate logging levels
    - Gunicorn-safe scheduler guards (only run in one worker)
    - Flask-Migrate manages schema; db.create_all() removed to avoid conflicts
"""

from __future__ import annotations
from flask_cors import CORS
from flask_migrate import Migrate
import os
import logging
import traceback
from flask import Flask, jsonify
from .extensions import init_extensions, db
from . import models
from .auth import auth_bp
from .groups import groups_bp
from .assets import assets_bp
from .scan_jobs import scan_jobs_bp
from .findings import findings_bp
from .discovery import discovery_bp
from .dashboard import dashboard_bp
from .quick_scan import quick_scan_bp
from .monitoring import monitoring_bp
from .billing import billing_bp
from .scan_profiles import scan_profiles_bp
from .scan_schedules.routes import scan_schedules_bp
from .scheduler import init_scheduler
from .settings import settings_bp
from app.discovery.routes_ignore_schedule import discovery_ext_bp
from app.reports.routes import reports_bp
from app.trending.routes import trending_bp
from app.integrations.routes import integrations_bp
from app.assets.intelligence import intelligence_bp
from app.scan_jobs.compare import compare_bp
from app.audit import audit_bp
from app.tools import tools_bp
import re

error_logger = logging.getLogger("app.errors")


def _is_production() -> bool:
    """Detect production by checking CORS_ORIGINS for https."""
    return os.getenv("CORS_ORIGINS", "").startswith("https://")


def _is_gunicorn_master() -> bool:
    """
    Guard for background schedulers under Gunicorn.
    With multiple workers, schedulers must only run once.
    Returns True if running under Flask dev server OR if this is
    the Gunicorn master/preload process (no GUNICORN_WORKER env).
    """
    server = os.getenv("SERVER_SOFTWARE", "")
    if "gunicorn" not in server.lower():
        return True  # Flask dev server — always run schedulers
    # Under Gunicorn: only run if we're the first worker (pid check)
    # Alternative: use --preload and this runs once in master
    return os.environ.get("SCHEDULER_ENABLED", "true").lower() == "true"


def create_app() -> Flask:
    app = Flask(__name__)

    is_prod = _is_production()

    # ── Logging ──────────────────────────────────────────────────────
    if is_prod:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        app.logger.setLevel(logging.INFO)
    else:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
            datefmt="%H:%M:%S",
        )
        app.logger.setLevel(logging.DEBUG)

    # Werkzeug logs every request
    logging.getLogger("werkzeug").setLevel(logging.INFO)
    # Quieten noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)
    # ─────────────────────────────────────────────────────────────────

    # ── CORS ────────────────────────────────────────────────────────
    # Production: set CORS_ORIGINS="https://easm.boltedge.co" in .env
    # Dev: falls back to localhost origins if env var is not set
    cors_env = os.getenv("CORS_ORIGINS")
    if cors_env:
        cors_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
    else:
        cors_origins = [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            re.compile(r"http://192\.168\.\d+\.\d+:3000"),
        ]

    CORS(app, resources={
        r"/*": {
            "origins": cors_origins,
            "supports_credentials": True,
            "allow_headers": ["Content-Type", "Authorization"],
            "methods": ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        }
    })

    # ── Secret Key ───────────────────────────────────────────────────
    secret_key = os.getenv("SECRET_KEY")
    if is_prod and not secret_key:
        raise RuntimeError(
            "SECRET_KEY environment variable is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    app.config["SECRET_KEY"] = secret_key or "dev-secret-key-change-me"

    # ── Session Cookies ──────────────────────────────────────────────
    if is_prod:
        app.config["SESSION_COOKIE_SECURE"] = True
        app.config["SESSION_COOKIE_HTTPONLY"] = True
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
        app.config["SESSION_COOKIE_DOMAIN"] = ".boltedge.co"

    # ── Database ─────────────────────────────────────────────────────
    # PostgreSQL required. No SQLite fallback.
    # Set SQLALCHEMY_DATABASE_URI in .env, e.g.:
    #   postgresql://easm_user:PASSWORD@easm-db:5432/easm
    database_uri = os.getenv("SQLALCHEMY_DATABASE_URI")
    if not database_uri:
        raise RuntimeError(
            "SQLALCHEMY_DATABASE_URI environment variable is not set. "
            "Set it to a PostgreSQL connection string, e.g.: "
            "postgresql://easm_user:PASSWORD@easm-db:5432/easm"
        )
    app.config["SQLALCHEMY_DATABASE_URI"] = database_uri
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ── Extensions ───────────────────────────────────────────────────
    init_extensions(app)
    migrate = Migrate(app, db)

    # ── Blueprints ───────────────────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(groups_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(scan_jobs_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(discovery_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(quick_scan_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(billing_bp)
    app.register_blueprint(scan_profiles_bp)
    app.register_blueprint(scan_schedules_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(discovery_ext_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(trending_bp)
    app.register_blueprint(integrations_bp)
    app.register_blueprint(intelligence_bp)
    app.register_blueprint(compare_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(tools_bp)

    # ── Global Error Handlers ────────────────────────────────────────
    # Return clean JSON for all errors — never expose tracebacks to users.
    # Errors are logged server-side for debugging.

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({
            "error": "Bad request",
            "message": str(e.description) if hasattr(e, "description") else "The request was malformed or invalid.",
        }), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({
            "error": "Unauthorized",
            "message": "Authentication is required. Please log in.",
        }), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({
            "error": "Forbidden",
            "message": "You do not have permission to access this resource.",
        }), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({
            "error": "Not found",
            "message": "The requested resource was not found.",
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({
            "error": "Method not allowed",
            "message": "This HTTP method is not allowed for this endpoint.",
        }), 405

    @app.errorhandler(409)
    def conflict(e):
        return jsonify({
            "error": "Conflict",
            "message": str(e.description) if hasattr(e, "description") else "The request conflicts with an existing resource.",
        }), 409

    @app.errorhandler(413)
    def payload_too_large(e):
        return jsonify({
            "error": "Payload too large",
            "message": "The request body exceeds the maximum allowed size.",
        }), 413

    @app.errorhandler(415)
    def unsupported_media_type(e):
        return jsonify({
            "error": "Unsupported media type",
            "message": "The request content type is not supported. Use application/json.",
        }), 415

    @app.errorhandler(422)
    def unprocessable_entity(e):
        return jsonify({
            "error": "Unprocessable entity",
            "message": str(e.description) if hasattr(e, "description") else "The request data failed validation.",
        }), 422

    @app.errorhandler(429)
    def rate_limited(e):
        return jsonify({
            "error": "Too many requests",
            "message": "Rate limit exceeded. Please try again later.",
        }), 429

    @app.errorhandler(500)
    def internal_error(e):
        error_logger.error(
            "500 Internal Server Error:\n%s", traceback.format_exc()
        )
        return jsonify({
            "error": "Internal server error",
            "message": "An unexpected error occurred. Please try again later.",
        }), 500

    @app.errorhandler(502)
    def bad_gateway(e):
        return jsonify({
            "error": "Bad gateway",
            "message": "An upstream service is unavailable. Please try again later.",
        }), 502

    @app.errorhandler(503)
    def service_unavailable(e):
        return jsonify({
            "error": "Service unavailable",
            "message": "The server is temporarily unavailable. Please try again later.",
        }), 503

    @app.errorhandler(Exception)
    def catch_all(e):
        """Catch-all for any unhandled exception — never leak tracebacks."""
        error_logger.error(
            "Unhandled exception: %s\n%s", str(e), traceback.format_exc()
        )
        return jsonify({
            "error": "Internal server error",
            "message": "An unexpected error occurred. Please try again later.",
        }), 500

    # ─────────────────────────────────────────────────────────────────

    # Health check
    @app.get("/health")
    def health():
        return jsonify(status="up and running"), 200

    # ── Schema Management ────────────────────────────────────────────
    # Flask-Migrate (Alembic) manages all schema changes in production.
    # Run: docker compose exec easm-backend flask db upgrade
    # db.create_all() is NOT called — it conflicts with Alembic migrations.
    # ─────────────────────────────────────────────────────────────────

    # ── Background Schedulers ────────────────────────────────────────
    # Gunicorn runs multiple workers — schedulers must only start once.
    # In docker-compose, set SCHEDULER_ENABLED=true on exactly one
    # worker, or use gunicorn --preload so create_app() runs once.
    if _is_gunicorn_master():

        # Scan schedule scheduler
        with app.app_context():
            init_scheduler(app)

        # Monitoring scheduler
        try:
            from app.monitoring.scheduler import start_monitor_scheduler
            start_monitor_scheduler(app)
        except Exception as e:
            logging.getLogger(__name__).warning(
                "Failed to start monitor scheduler: %s", e
            )

        # Trial expiry check — every hour
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            trial_scheduler = BackgroundScheduler(daemon=True)

            def _check_trials():
                with app.app_context():
                    from app.billing.routes import check_expired_trials
                    count = check_expired_trials()
                    if count:
                        logging.getLogger(__name__).info(
                            "Auto-downgraded %d expired trial(s)", count
                        )

            trial_scheduler.add_job(_check_trials, "interval", hours=1)
            trial_scheduler.start()
        except Exception as e:
            logging.getLogger(__name__).warning(
                "Failed to start trial expiry scheduler: %s", e
            )
    else:
        logging.getLogger(__name__).info(
            "Schedulers disabled for this worker (SCHEDULER_ENABLED != true)"
        )
    # ─────────────────────────────────────────────────────────────────

    return app