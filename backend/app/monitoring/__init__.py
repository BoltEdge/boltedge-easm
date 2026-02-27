# app/monitoring/__init__.py
"""
Monitoring module — continuous security monitoring with change detection.

Components:
    routes.py          — API endpoints (monitors CRUD, alerts, settings, tuning)
    change_detector.py — Diffs scan results against baseline, generates alerts
    tuning_engine.py   — Evaluates findings against tuning rules
    scheduler.py       — Background thread that triggers due monitors

Blueprint registration:
    The app factory already imports monitoring_bp from this module:
        from .monitoring import monitoring_bp
        app.register_blueprint(monitoring_bp)

Scheduler startup:
    Add to create_app() after init_scheduler(app):
        from app.monitoring.scheduler import start_monitor_scheduler
        start_monitor_scheduler(app)
"""

from .routes import monitoring_bp

__all__ = ["monitoring_bp"]