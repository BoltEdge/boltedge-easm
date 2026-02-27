from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import UniqueConstraint
from .extensions import db


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True, index=True)
    name = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Optional profile fields
    job_title = db.Column(db.String(120), nullable=True)
    company = db.Column(db.String(255), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

class Organization(db.Model):
    __tablename__ = "organization"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    industry = db.Column(db.String(100), nullable=True)
    company_size = db.Column(db.String(20), nullable=True)
    website = db.Column(db.String(500), nullable=True)
    
    # Optional organization details
    country = db.Column(db.String(100), nullable=True)
    
    # ── Plan & Billing ──────────────────────────────────────────────
    # plan tiers: free, starter, professional, enterprise_silver, enterprise_gold
    plan = db.Column(db.String(50), nullable=False, default='free')
    # plan_status: active, trialing, cancelled, past_due, expired
    plan_status = db.Column(db.String(30), nullable=False, default='active')
    plan_started_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    plan_expires_at = db.Column(db.DateTime, nullable=True)
    
    # Trial tracking
    trial_ends_at = db.Column(db.DateTime, nullable=True)
    
    # Billing cycle: monthly, annual
    billing_cycle = db.Column(db.String(20), nullable=True)
    
    # Stripe-ready fields (null until payment integration)
    stripe_customer_id = db.Column(db.String(255), nullable=True)
    stripe_subscription_id = db.Column(db.String(255), nullable=True)
    
    # ── Usage Limits (cached for performance) ───────────────────────
    asset_limit = db.Column(db.Integer, nullable=False, default=2)
    assets_count = db.Column(db.Integer, nullable=False, default=0)
    scans_this_month = db.Column(db.Integer, nullable=False, default=0)
    last_scan_count_reset = db.Column(db.DateTime, nullable=False, default=now_utc)
    
    # Metadata
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)
    is_active = db.Column(db.Boolean, nullable=False, default=True)



    @property
    def is_trialing(self) -> bool:
        """Check if org is currently in a trial period."""
        if self.plan_status != 'trialing':
            return False
        if not self.trial_ends_at:
            return False
        return now_utc() < self.trial_ends_at

    @property
    def trial_expired(self) -> bool:
        """Check if trial has expired (but hasn't been downgraded yet)."""
        if self.plan_status != 'trialing':
            return False
        if not self.trial_ends_at:
            return False
        return now_utc() >= self.trial_ends_at

    @property
    def effective_plan(self) -> str:
        """
        Returns the plan that should be used for limit checks.
        If trialing and trial hasn't expired, return the trial plan.
        If trial expired, return 'free' (auto-downgrade should have run).
        """
        if self.plan_status == 'trialing':
            if self.trial_ends_at and now_utc() < self.trial_ends_at:
                return self.plan
            return 'free'
        if self.plan_status in ('cancelled', 'expired'):
            return 'free'
        return self.plan


class TrialHistory(db.Model):
    """
    Tracks which plan tiers an organization has trialed.
    One trial allowed per tier per organization.
    """
    __tablename__ = "trial_history"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    
    plan = db.Column(db.String(50), nullable=False)  # starter, professional, enterprise_silver, enterprise_gold
    started_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    ended_at = db.Column(db.DateTime, nullable=True)
    trial_days = db.Column(db.Integer, nullable=False)
    
    # Outcome: converted, expired, cancelled
    outcome = db.Column(db.String(20), nullable=True)
    
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    
    # Relationships
    organization = db.relationship("Organization", backref=db.backref("trial_history", cascade="all, delete-orphan"))
    
    __table_args__ = (
        UniqueConstraint("organization_id", "plan", name="uq_trial_history_org_plan"),
    )


class OrganizationMember(db.Model):
    __tablename__ = "organization_member"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    role = db.Column(db.String(20), nullable=False)  # owner, admin, analyst, viewer
    
    # Invitation tracking
    invited_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    invited_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    joined_at = db.Column(db.DateTime, nullable=True)
    
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    
    # Relationships
    user = db.relationship("User", foreign_keys=[user_id], backref=db.backref("organization_memberships", cascade="all, delete-orphan"))
    organization = db.relationship("Organization", backref=db.backref("members", cascade="all, delete-orphan"))
    invited_by = db.relationship("User", foreign_keys=[invited_by_user_id])
    
    __table_args__ = (
        UniqueConstraint("user_id", "organization_id", name="uq_user_organization"),
    )


class AssetGroup(db.Model):
    __tablename__ = "asset_group"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    
    name = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    is_active = db.Column(db.Boolean, nullable=False, default=True)
    deleted_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_asset_group_org_name"),
    )
    
    organization = db.relationship("Organization", backref=db.backref("asset_groups"))


class Asset(db.Model):
    __tablename__ = "asset"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)

    group_id = db.Column(
        db.Integer,
        db.ForeignKey("asset_group.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    asset_type = db.Column(db.String(20), nullable=False)
    value = db.Column(db.String(255), nullable=False)
    label = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)
    provider = db.Column(db.String(50), nullable=True)
    cloud_category = db.Column(db.String(30), nullable=True)
    metadata_json = db.Column(db.JSON, nullable=True)
    last_scan_at = db.Column(db.DateTime, nullable=True)
    scan_status = db.Column(db.String(20), nullable=True, default="never_scanned")
    # scan_status values: never_scanned, scan_pending, scanned, scan_failed

    __table_args__ = (
        UniqueConstraint("organization_id", "asset_type", "value", name="uq_org_asset_type_value"),
    )

    group = db.relationship(
        "AssetGroup",
        backref=db.backref("assets", cascade="all, delete-orphan"),
    )
    organization = db.relationship("Organization", backref=db.backref("assets"))

class ScanJob(db.Model):
    __tablename__ = "scan_job"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(
        db.Integer,
        db.ForeignKey("asset.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    status = db.Column(db.String(20), nullable=False, default="queued")
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)

    error_message = db.Column(db.String(500), nullable=True)
    result_json = db.Column(db.JSON, nullable=True)
    
    # Milestone 3: Profile & Schedule support
    profile_id = db.Column(db.Integer, db.ForeignKey("scan_profile.id", ondelete="SET NULL"), nullable=True)
    schedule_id = db.Column(db.Integer, db.ForeignKey("scan_schedule.id", ondelete="SET NULL"), nullable=True)
    scan_engines = db.Column(db.JSON, nullable=True)  # Track which engines were used

    # Relationships
    asset = db.relationship(
        "Asset",
        backref=db.backref("scan_jobs", cascade="all, delete-orphan"),
    )
    profile = db.relationship("ScanProfile")
    schedule = db.relationship("ScanSchedule", foreign_keys=[schedule_id])


class Finding(db.Model):
    __tablename__ = "finding"

    id = db.Column(db.Integer, primary_key=True)

    asset_id = db.Column(
        db.Integer,
        db.ForeignKey("asset.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_job_id = db.Column(
        db.Integer,
        db.ForeignKey("scan_job.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    source = db.Column(db.String(50), nullable=False, default="engine")

    finding_type = db.Column(db.String(80), nullable=True)
    dedupe_key = db.Column(db.String(64), nullable=True, index=True)
    first_seen_at = db.Column(db.DateTime, nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)

    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="info")
    description = db.Column(db.String(2000), nullable=False, default="")

    # ===================================================================
    # M7: Enrichment columns from the detection engine pipeline
    # These store data that was previously stuffed into details_json
    # ===================================================================
    category = db.Column(db.String(50), nullable=True)              # ssl, ports, headers, cve, dns, tech, exposure, misconfiguration, vulnerability
    remediation = db.Column(db.String(2000), nullable=True)         # How to fix it — shown as guidance in the UI
    cwe = db.Column(db.String(20), nullable=True)                   # CWE reference: CWE-295, CWE-327, etc.
    confidence = db.Column(db.String(20), nullable=True, default="high")  # high, medium, low
    tags_json = db.Column(db.JSON, nullable=True)                   # ["ssl", "expired", "tls1.0"]
    references_json = db.Column(db.JSON, nullable=True)             # ["https://nvd.nist.gov/vuln/detail/CVE-..."]
    engine = db.Column(db.String(50), nullable=True)                # Which engine collected the data: shodan, nmap, ssl, http, dns, nuclei
    analyzer = db.Column(db.String(50), nullable=True)              # Which analyzer produced the finding: port_risk, ssl_analyzer, etc.
    template_id = db.Column(db.String(100), nullable=True)          # Finding template key: port-rdp-exposed, ssl-cert-expired, etc.

    details_json = db.Column(db.JSON, nullable=True)

    # Suppress workflow (risk-accepted / false positive)
    ignored = db.Column(db.Boolean, default=False)
    ignored_at = db.Column(db.DateTime, nullable=True)
    ignored_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    ignored_reason = db.Column(db.String(500), nullable=True)

    # Resolve workflow
    resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    resolved_reason = db.Column(db.String(500), nullable=True)
    # In Progress workflow
    in_progress = db.Column(db.Boolean, default=False)
    in_progress_at = db.Column(db.DateTime, nullable=True)
    in_progress_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    in_progress_notes = db.Column(db.String(500), nullable=True)

    # Accepted Risk workflow
    accepted_risk = db.Column(db.Boolean, default=False)
    accepted_risk_at = db.Column(db.DateTime, nullable=True)
    accepted_risk_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    accepted_risk_justification = db.Column(db.String(1000), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    asset = db.relationship(
        "Asset",
        backref=db.backref("findings", cascade="all, delete-orphan"),
    )
    scan_job = db.relationship(
        "ScanJob",
        backref=db.backref("findings", cascade="all, delete-orphan"),

    )


# =============================================================================
# F2: Remediation Workflow — Model Additions
# INSTRUCTIONS: Append this to your existing app/models.py
# Then run f2_migration.sql against your database
# =============================================================================


class FindingComment(db.Model):
    """
    Threaded comments on findings. Supports both general discussion
    and status-change annotations (e.g. "Resolved because...").
    """
    __tablename__ = "finding_comment"

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey("finding.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)

    content = db.Column(db.Text, nullable=False)

    # Optional: link to a status change event type
    # NULL = general comment, otherwise e.g. "resolved", "assigned", "accepted_risk"
    event_type = db.Column(db.String(30), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    # Relationships
    finding = db.relationship("Finding", backref=db.backref("comments", cascade="all, delete-orphan", order_by="FindingComment.created_at"))
    organization = db.relationship("Organization")
    user = db.relationship("User")


# =============================================================================
# F2: Additional columns on Finding model
# INSTRUCTIONS: Add these columns to your existing Finding class in models.py
# Place them after the existing resolved_reason column.
# =============================================================================
#
# # Status workflow: open, in_progress, accepted_risk, resolved, suppressed
# status = db.Column(db.String(20), nullable=False, default="open", index=True)
#
# # Assignment
# assigned_to = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True, index=True)
# assigned_at = db.Column(db.DateTime, nullable=True)
# assigned_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
#
# # Accepted Risk
# accepted_risk_reason = db.Column(db.String(500), nullable=True)
# accepted_risk_at = db.Column(db.DateTime, nullable=True)
# accepted_risk_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
#
# # Add these relationships inside the Finding class:
# assignee = db.relationship("User", foreign_keys=[assigned_to], backref="assigned_findings")
# assigner = db.relationship("User", foreign_keys=[assigned_by])
# accepted_risk_user = db.relationship("User", foreign_keys=[accepted_risk_by])

class MonitoringEvent(db.Model):
    """DEPRECATED — kept for migration compatibility. Use Monitor + MonitorAlert instead."""
    __tablename__ = "monitoring_event"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, nullable=False, index=True)

    event_type = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False)

    status = db.Column(db.String(20), nullable=False, default="open")

    details_json = db.Column(db.JSON, nullable=True)

    first_seen_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Analyst actions
    acknowledged = db.Column(db.Boolean, nullable=False, default=False)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    acknowledged_by = db.Column(db.Integer, nullable=True)

    verdict = db.Column(db.String(20), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
    
    organization = db.relationship("Organization", backref=db.backref("monitoring_events"))


class AlertTuningRule(db.Model):
    """DEPRECATED — kept for migration compatibility. Use TuningRule instead."""
    __tablename__ = "alert_tuning_rule"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)

    event_type = db.Column(db.String(50), nullable=False)

    scope_type = db.Column(db.String(20), nullable=False)
    scope_id = db.Column(db.Integer, nullable=True)

    match_conditions = db.Column(db.JSON, nullable=True)

    reason = db.Column(db.String(255), nullable=True)

    enabled = db.Column(db.Boolean, nullable=False, default=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    organization = db.relationship("Organization", backref=db.backref("alert_tuning_rules"))


# ============================================
# Milestone 8: Monitoring System
# ============================================

class Monitor(db.Model):
    """
    A monitor watches a single asset or asset group for changes.
    Scheduled re-scans compare results against a baseline, generating
    alerts for new/changed/resolved findings.
    """
    __tablename__ = "monitor"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)

    # Target — one of asset_id or group_id must be set
    asset_id = db.Column(db.Integer, db.ForeignKey("asset.id", ondelete="CASCADE"), nullable=True, index=True)
    group_id = db.Column(db.Integer, db.ForeignKey("asset_group.id", ondelete="CASCADE"), nullable=True, index=True)

    # What to monitor — JSON array: ["dns","ssl","ports","headers","tech","cve","all"]
    monitor_types = db.Column(db.JSON, nullable=False, default=lambda: ["all"])

    # Schedule
    frequency = db.Column(db.String(20), nullable=False, default="every_2_days")  # daily, every_2_days, weekly
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    # Baseline & tracking
    baseline_scan_job_id = db.Column(db.Integer, db.ForeignKey("scan_job.id", ondelete="SET NULL"), nullable=True)
    last_scan_job_id = db.Column(db.Integer, db.ForeignKey("scan_job.id", ondelete="SET NULL"), nullable=True)
    last_checked_at = db.Column(db.DateTime, nullable=True)
    next_check_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("monitors"))
    creator = db.relationship("User")
    asset = db.relationship("Asset", backref=db.backref("monitors"))
    group = db.relationship("AssetGroup", backref=db.backref("monitors"))
    baseline_scan_job = db.relationship("ScanJob", foreign_keys=[baseline_scan_job_id])
    last_scan_job = db.relationship("ScanJob", foreign_keys=[last_scan_job_id])

    __table_args__ = (
        # Prevent duplicate monitors on the same asset or group
        UniqueConstraint("organization_id", "asset_id", name="uq_monitor_org_asset"),
        UniqueConstraint("organization_id", "group_id", name="uq_monitor_org_group"),
    )


class MonitorAlert(db.Model):
    """
    An alert generated when a monitor detects a new, changed, or resolved finding.
    """
    __tablename__ = "monitor_alert"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    monitor_id = db.Column(db.Integer, db.ForeignKey("monitor.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = db.Column(db.Integer, db.ForeignKey("finding.id", ondelete="SET NULL"), nullable=True, index=True)

    # Alert classification
    alert_type = db.Column(db.String(30), nullable=False)  # new_finding, severity_change, resolved
    template_id = db.Column(db.String(100), nullable=True)  # Finding template key
    alert_name = db.Column(db.String(255), nullable=True)   # From FindingTemplate.alert_name

    # Content
    title = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.String(1000), nullable=True)
    severity = db.Column(db.String(20), nullable=False, default="info")

    # Context
    asset_value = db.Column(db.String(255), nullable=True)   # Denormalized for quick display
    group_name = db.Column(db.String(255), nullable=True)

    # Status workflow: open → acknowledged → resolved
    status = db.Column(db.String(20), nullable=False, default="open", index=True)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    acknowledged_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)

    # Notification tracking
    notified_via = db.Column(db.JSON, nullable=True)  # ["email", "in_app", "webhook"]

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("monitor_alerts"))
    monitor = db.relationship("Monitor", backref=db.backref("alerts", cascade="all, delete-orphan"))
    finding = db.relationship("Finding")
    acknowledged_by_user = db.relationship("User", foreign_keys=[acknowledged_by])
    resolved_by_user = db.relationship("User", foreign_keys=[resolved_by])


class MonitorSettings(db.Model):
    """
    Organization-level notification preferences for monitoring alerts.
    One row per organization.
    """
    __tablename__ = "monitor_settings"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)

    # Notification channels
    email_enabled = db.Column(db.Boolean, nullable=False, default=True)
    in_app_enabled = db.Column(db.Boolean, nullable=False, default=True)
    webhook_enabled = db.Column(db.Boolean, nullable=False, default=False)
    webhook_url = db.Column(db.String(500), nullable=True)
    email_recipients = db.Column(db.JSON, nullable=False, default=list)  # ["alice@co.com", "bob@co.com"]

    # Filter preferences
    notify_on_severity = db.Column(db.JSON, nullable=False, default=lambda: ["critical", "high", "medium", "low", "info"])

    # Digest
    digest_frequency = db.Column(db.String(20), nullable=False, default="immediate")  # immediate, daily_digest, weekly_digest

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("monitor_settings", uselist=False))


class TuningRule(db.Model):
    """
    Rules that suppress, downgrade, upgrade, or snooze specific alerts.
    Match conditions combine to narrow the scope — more fields = narrower match.
    """
    __tablename__ = "tuning_rule"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)

    enabled = db.Column(db.Boolean, nullable=False, default=True)

    # ---- Match conditions (all optional — more fields = narrower match) ----
    template_id = db.Column(db.String(100), nullable=True)      # "port-redis-exposed", "dns-*", "*"
    category = db.Column(db.String(50), nullable=True)           # "ports", "dns", "ssl", etc.
    severity_match = db.Column(db.String(20), nullable=True)     # Only match this severity
    asset_id = db.Column(db.Integer, db.ForeignKey("asset.id", ondelete="CASCADE"), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey("asset_group.id", ondelete="CASCADE"), nullable=True)
    asset_pattern = db.Column(db.String(255), nullable=True)     # "*.staging.example.com"
    port = db.Column(db.Integer, nullable=True)
    service_name = db.Column(db.String(100), nullable=True)
    cwe = db.Column(db.String(20), nullable=True)
    title_contains = db.Column(db.String(255), nullable=True)

    # ---- Action ----
    action = db.Column(db.String(20), nullable=False)            # suppress, downgrade, upgrade, snooze
    target_severity = db.Column(db.String(20), nullable=True)    # For downgrade/upgrade
    snooze_until = db.Column(db.DateTime, nullable=True)         # For snooze

    # ---- Metadata ----
    reason = db.Column(db.String(500), nullable=True)
    dedupe_key = db.Column(db.String(64), nullable=True, unique=True)  # Hash of match fields

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("tuning_rules"))
    creator = db.relationship("User")
    asset = db.relationship("Asset")
    group = db.relationship("AssetGroup")


# ============================================
# Milestone 3: Scan Profiles & Scheduling
# ============================================

class ScanProfile(db.Model):
    __tablename__ = "scan_profile"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    
    # Profile info
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Profile type
    is_system = db.Column(db.Boolean, nullable=False, default=False)
    is_default = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    
    # Engine configuration
    use_shodan = db.Column(db.Boolean, nullable=False, default=True)
    use_nmap = db.Column(db.Boolean, nullable=False, default=False)
    use_nuclei = db.Column(db.Boolean, nullable=False, default=False)
    use_sslyze = db.Column(db.Boolean, nullable=False, default=False)
    
    # Shodan settings
    shodan_include_history = db.Column(db.Boolean, nullable=False, default=False)
    shodan_include_cves = db.Column(db.Boolean, nullable=False, default=False)
    shodan_include_dns = db.Column(db.Boolean, nullable=False, default=False)
    
    # Nmap settings
    nmap_scan_type = db.Column(db.String(20), nullable=True, default="standard")
    nmap_port_range = db.Column(db.String(50), nullable=True, default="1-1000")
    
    # Nuclei settings
    nuclei_severity_filter = db.Column(db.String(100), nullable=True)
    nuclei_templates = db.Column(db.JSON, nullable=True)
    
    # General settings
    timeout_seconds = db.Column(db.Integer, nullable=False, default=300)
    
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)
    
    # Relationships
    organization = db.relationship("Organization", backref=db.backref("scan_profiles"))
    user = db.relationship("User")
    
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_scan_profile_org_name"),
    )


class ScanSchedule(db.Model):
    __tablename__ = "scan_schedule"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("asset.id", ondelete="CASCADE"), nullable=True, index=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("scan_profile.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Schedule configuration
    name = db.Column(db.String(100), nullable=True)
    frequency = db.Column(db.String(20), nullable=False)
    time_of_day = db.Column(db.String(5), nullable=False, default="02:00")
    day_of_week = db.Column(db.Integer, nullable=True)
    day_of_month = db.Column(db.Integer, nullable=True)
    
    # Status
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    
    # Tracking
    last_run_at = db.Column(db.DateTime, nullable=True)
    next_run_at = db.Column(db.DateTime, nullable=True)
    last_scan_job_id = db.Column(db.Integer, db.ForeignKey("scan_job.id", ondelete="SET NULL"), nullable=True)
    
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)
    
    # Relationships
    organization = db.relationship("Organization", backref=db.backref("scan_schedules"))
    user = db.relationship("User")
    asset = db.relationship("Asset", backref=db.backref("scan_schedules"))
    profile = db.relationship("ScanProfile")
    last_scan_job = db.relationship("ScanJob", foreign_keys=[last_scan_job_id])
    schedule_type = db.Column(db.String(20), default="asset", nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("asset_group.id"), nullable=True)
    group = db.relationship("AssetGroup", backref="schedules")


class ScanHistoricalData(db.Model):
    __tablename__ = "scan_historical_data"
    
    id = db.Column(db.Integer, primary_key=True)
    scan_job_id = db.Column(db.Integer, db.ForeignKey("scan_job.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("asset.id"), nullable=True)
    
    # Data classification
    engine = db.Column(db.String(50), nullable=False)
    data_type = db.Column(db.String(50), nullable=False)
    
    # Temporal info
    timestamp = db.Column(db.DateTime, nullable=False)
    
    # Actual data
    data = db.Column(db.JSON, nullable=False)
    
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    
    # Relationships
    scan_job = db.relationship("ScanJob", backref=db.backref("historical_data"))
    asset = db.relationship("Asset")


class OrganizationUsage(db.Model):
    __tablename__ = "organization_usage"
    
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Time period
    month = db.Column(db.Date, nullable=False)
    
    # Scan counts
    quick_scans_count = db.Column(db.Integer, nullable=False, default=0)
    standard_scans_count = db.Column(db.Integer, nullable=False, default=0)
    deep_scans_count = db.Column(db.Integer, nullable=False, default=0)
    total_scans_count = db.Column(db.Integer, nullable=False, default=0)
    
    # Shodan API usage
    shodan_queries_used = db.Column(db.Integer, nullable=False, default=0)
    
    # Schedule usage
    active_schedules = db.Column(db.Integer, nullable=False, default=0)
    
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)
    
    # Relationships
    organization = db.relationship("Organization", backref=db.backref("usage_records"))
    
    __table_args__ = (
        UniqueConstraint("organization_id", "month", name="uq_org_usage_month"),
    )


# ============================================
# Milestone 4: Settings & Admin
# ============================================

class ApiKey(db.Model):
    __tablename__ = "api_key"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)

    name = db.Column(db.String(100), nullable=False)
    key_prefix = db.Column(db.String(12), nullable=False)
    key_hash = db.Column(db.String(255), nullable=False, unique=True)

    scopes = db.Column(db.JSON, nullable=True)
    last_used_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)

    is_active = db.Column(db.Boolean, nullable=False, default=True)
    revoked_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("api_keys"))
    user = db.relationship("User", backref=db.backref("api_keys"))


class PendingInvitation(db.Model):
    __tablename__ = "pending_invitation"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    invited_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)

    email = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")
    token = db.Column(db.String(255), nullable=False, unique=True)

    status = db.Column(db.String(20), nullable=False, default="pending")

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    expires_at = db.Column(db.DateTime, nullable=False)
    accepted_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("pending_invitations"))
    invited_by = db.relationship("User")

    __table_args__ = (
        UniqueConstraint("organization_id", "email", name="uq_invite_org_email"),
    )

# FILE: app/discovery/models_discovery.py
# ============================================
# Milestone 10: Discovery Engine v2
# ============================================
# INSTRUCTIONS: Append the contents of this file to your existing app/models.py
# The imports (db, now_utc, UniqueConstraint) are already present in models.py.
# ============================================


class DiscoveryJob(db.Model):
    """
    A discovery job runs multiple discovery modules against a target
    to find assets belonging to the organization's attack surface.
    """
    __tablename__ = "discovery_job"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)

    # Target
    target = db.Column(db.String(255), nullable=False)
    target_type = db.Column(db.String(30), nullable=False)       # domain / ip / cidr / org_name

    # Execution state
    status = db.Column(db.String(30), nullable=False, default="pending")  # pending / running / completed / partial / failed / cancelled
    modules_run = db.Column(db.JSON, nullable=True)              # ["ct_logs", "dns_enum", ...]
    config = db.Column(db.JSON, nullable=True)

    # Result summary (denormalized for fast list queries)
    total_found = db.Column(db.Integer, nullable=False, default=0)
    new_assets = db.Column(db.Integer, nullable=False, default=0)
    counts_by_type = db.Column(db.JSON, nullable=True)           # {"subdomain": 47, "ip": 12}

    # Timing
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)

    error_message = db.Column(db.String(1000), nullable=True)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("discovery_jobs"))
    creator = db.relationship("User")


class DiscoveredAsset(db.Model):
    """
    A single asset found during a discovery job.
    Deduplicated across modules — sources list tracks which modules found it.
    """
    __tablename__ = "discovered_asset"

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("discovery_job.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)

    asset_type = db.Column(db.String(30), nullable=False)        # domain / subdomain / ip / ip_range / cloud / url
    value = db.Column(db.String(500), nullable=False)
    original_value = db.Column(db.String(500), nullable=True)

    sources = db.Column(db.JSON, nullable=False, default=list)   # ["ct_logs", "virustotal"]
    confidence = db.Column(db.Float, nullable=False, default=1.0)
    # NOTE: "metadata" is reserved by SQLAlchemy Declarative — use "extra_info" as the
    # Python attribute, but keep "metadata" as the actual DB column name for clarity.
    extra_info = db.Column("metadata", db.JSON, nullable=True)

    is_new = db.Column(db.Boolean, nullable=False, default=True)
    added_to_inventory = db.Column(db.Boolean, nullable=False, default=False)
    added_asset_id = db.Column(db.Integer, db.ForeignKey("asset.id", ondelete="SET NULL"), nullable=True)

    # Tags: auto-generated + user-applied labels for filtering
    # Auto-tags: nameserver, cdn, mail, historical, out-of-scope, etc.
    # User tags: in-scope, investigate, false-positive, etc.
    tags = db.Column(db.JSON, nullable=False, default=list)

    discovered_at = db.Column(db.DateTime, nullable=False, default=now_utc)

    # Relationships
    job = db.relationship("DiscoveryJob", backref=db.backref("discovered_assets", cascade="all, delete-orphan"))
    organization = db.relationship("Organization")
    added_asset = db.relationship("Asset")

    __table_args__ = (
        UniqueConstraint("job_id", "asset_type", "value", name="uq_discovered_asset_job_type_value"),
    )


class DiscoveryModuleResult(db.Model):
    """
    Tracks the execution status of each module within a discovery job.
    Used for progress reporting to the frontend.
    """
    __tablename__ = "discovery_module_result"

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("discovery_job.id", ondelete="CASCADE"), nullable=False, index=True)

    module_name = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="pending")  # pending / running / completed / failed / skipped
    assets_found = db.Column(db.Integer, nullable=False, default=0)
    duration_ms = db.Column(db.Integer, nullable=True)
    error = db.Column(db.Text, nullable=True)

    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    job = db.relationship("DiscoveryJob", backref=db.backref("module_results", cascade="all, delete-orphan"))

    __table_args__ = (
        UniqueConstraint("job_id", "module_name", name="uq_module_result_job_module"),
    )  

    # FILE: app/discovery/models_ignore_schedule.py
# ============================================
# INSTRUCTIONS: Append the contents of this file to your existing app/models.py
# ============================================


class IgnoredDiscoveredAsset(db.Model):
    """
    Organization-level ignore list for discovered assets.
    When an asset is ignored, future discoveries will show it as 'Ignored'
    instead of 'New', helping users focus on genuinely new findings.
    """
    __tablename__ = "ignored_discovered_asset"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)

    asset_type = db.Column(db.String(30), nullable=False)        # domain / subdomain / ip / ip_range
    value = db.Column(db.String(500), nullable=False)             # normalized value

    reason = db.Column(db.String(500), nullable=True)             # optional: "CDN infrastructure", "Not our asset", etc.
    ignored_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    ignored_at = db.Column(db.DateTime, nullable=False, default=now_utc)

    organization = db.relationship("Organization", backref=db.backref("ignored_assets"))
    user = db.relationship("User")

    __table_args__ = (
        UniqueConstraint("organization_id", "asset_type", "value", name="uq_ignored_asset_org_type_value"),
    )


class DiscoverySchedule(db.Model):
    """
    Scheduled recurring discovery jobs.
    """
    __tablename__ = "discovery_schedule"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)

    # What to discover
    name = db.Column(db.String(200), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    target_type = db.Column(db.String(30), nullable=False, default="domain")
    scan_depth = db.Column(db.String(30), nullable=False, default="standard")

    # Schedule (cron-style simplified)
    frequency = db.Column(db.String(30), nullable=False)  # daily / weekly / monthly
    day_of_week = db.Column(db.Integer, nullable=True)     # 0=Mon..6=Sun (for weekly)
    day_of_month = db.Column(db.Integer, nullable=True)    # 1-28 (for monthly)
    hour = db.Column(db.Integer, nullable=False, default=2) # Hour (UTC) to run, default 2 AM

    # State
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    last_run_at = db.Column(db.DateTime, nullable=True)
    last_job_id = db.Column(db.Integer, db.ForeignKey("discovery_job.id", ondelete="SET NULL"), nullable=True)
    next_run_at = db.Column(db.DateTime, nullable=True)
    run_count = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("discovery_schedules"))
    creator = db.relationship("User")
    last_job = db.relationship("DiscoveryJob", foreign_keys=[last_job_id])

    # ============================================
# Milestone 11: Reporting & PDF Export
# ============================================

class Report(db.Model):
    """
    A generated report (PDF) based on organization security data.
    Supports two scopes:
      - organization: full org-wide report across all groups
      - group: single group report (ideal for MSSP client/tenant delivery)
    Supports executive summary and full technical report templates
    using the WH Framework structure (WHO/WHAT/WHERE/WHEN/HOW).
    """
    __tablename__ = "report"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)

    # Report metadata
    title = db.Column(db.String(255), nullable=False)
    template = db.Column(db.String(30), nullable=False, default="executive")  # executive, technical
    format = db.Column(db.String(10), nullable=False, default="pdf")          # pdf (future: html, csv)

    # ── Scope ────────────────────────────────────────────────────
    # "organization" = full org report across all groups
    # "group" = single group report (MSSP tenant/client delivery)
    scope = db.Column(db.String(20), nullable=False, default="organization")  # organization, group
    group_id = db.Column(db.Integer, db.ForeignKey("asset_group.id", ondelete="SET NULL"), nullable=True, index=True)
    group_name = db.Column(db.String(120), nullable=True)  # Denormalized — preserved even if group is renamed/deleted

    # Generation status: pending → generating → ready → failed
    status = db.Column(db.String(20), nullable=False, default="pending", index=True)
    error_message = db.Column(db.String(1000), nullable=True)

    # Report configuration — stores filters/scope used to generate
    # e.g. {"severity": "critical,high", "dateRange": "last_30_days", "includeIgnored": false}
    config = db.Column(db.JSON, nullable=True)

    # Generated file path (relative to storage root)
    file_path = db.Column(db.String(500), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)  # bytes

    # Snapshot of key metrics at generation time
    # Stored so the report list can show summary without opening the PDF
    # e.g. {"exposureScore": 72, "totalFindings": 48, "critical": 5, "high": 12,
    #        "assetCount": 25, "groupCount": 4}
    summary_data = db.Column(db.JSON, nullable=True)

    # Who generated it
    generated_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    generated_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("reports"))
    group = db.relationship("AssetGroup")
    generator = db.relationship("User")


class ReportSchedule(db.Model):
    """
    Scheduled recurring report generation.
    Supports both organization-wide and group-scoped scheduled reports.
    Automatically generates and optionally emails reports on a cadence.
    """
    __tablename__ = "report_schedule"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)

    # What to generate
    name = db.Column(db.String(200), nullable=False)
    template = db.Column(db.String(30), nullable=False, default="executive")  # executive, technical

    # ── Scope ────────────────────────────────────────────────────
    scope = db.Column(db.String(20), nullable=False, default="organization")  # organization, group
    group_id = db.Column(db.Integer, db.ForeignKey("asset_group.id", ondelete="SET NULL"), nullable=True)

    config = db.Column(db.JSON, nullable=True)  # same structure as Report.config

    # Schedule
    frequency = db.Column(db.String(20), nullable=False, default="monthly")  # weekly, monthly
    day_of_week = db.Column(db.Integer, nullable=True)   # 0=Mon..6=Sun (for weekly)
    day_of_month = db.Column(db.Integer, nullable=True)  # 1-28 (for monthly)
    hour = db.Column(db.Integer, nullable=False, default=6)  # Hour (UTC), default 6 AM

    # Delivery
    recipients = db.Column(db.JSON, nullable=False, default=list)  # ["alice@co.com", "bob@co.com"]
    include_pdf_attachment = db.Column(db.Boolean, nullable=False, default=True)

    # State
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    last_run_at = db.Column(db.DateTime, nullable=True)
    last_report_id = db.Column(db.Integer, db.ForeignKey("report.id", ondelete="SET NULL"), nullable=True)
    next_run_at = db.Column(db.DateTime, nullable=True)
    run_count = db.Column(db.Integer, nullable=False, default=0)

    created_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("report_schedules"))
    group = db.relationship("AssetGroup")
    creator = db.relationship("User")
    last_report = db.relationship("Report", foreign_keys=[last_report_id])

    # ============================================
# Milestone 11: Historical Trending
# ============================================

class FindingEvent(db.Model):
    """
    Tracks lifecycle events for findings — opened, suppressed, resolved,
    severity changed, reopened. Powers the finding timeline and MTTR calculation.
    """
    __tablename__ = "finding_event"

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey("finding.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)

    # Event type: opened, resolved, suppressed, unsuppressed, reopened, severity_changed
    event_type = db.Column(db.String(30), nullable=False)

    # For severity_changed: stores old and new values
    old_value = db.Column(db.String(50), nullable=True)
    new_value = db.Column(db.String(50), nullable=True)

    # Who triggered this event (null for system-generated events like scan detection)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)

    # Optional context
    notes = db.Column(db.String(500), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)

    # Relationships
    finding = db.relationship("Finding", backref=db.backref("events", cascade="all, delete-orphan", order_by="FindingEvent.created_at"))
    organization = db.relationship("Organization", backref=db.backref("finding_events"))
    user = db.relationship("User")


class HistorySnapshot(db.Model):
    """
    Daily rollup of security posture metrics for an organization and optionally a group.
    Used for trend charts, MTTR calculation, and the WHEN section of reports.
    
    Scope:
      - group_id IS NULL → organization-wide snapshot
      - group_id IS NOT NULL → group-specific snapshot
    """
    __tablename__ = "history_snapshot"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)

    # Scope — null means org-wide, set means group-specific
    group_id = db.Column(db.Integer, db.ForeignKey("asset_group.id", ondelete="CASCADE"), nullable=True, index=True)

    # Snapshot date (one per org/group per day)
    snapshot_date = db.Column(db.Date, nullable=False, index=True)

    # ── Asset metrics ──
    asset_count = db.Column(db.Integer, nullable=False, default=0)

    # ── Finding metrics (active/open only — not suppressed) ──
    total_findings = db.Column(db.Integer, nullable=False, default=0)
    critical_count = db.Column(db.Integer, nullable=False, default=0)
    high_count = db.Column(db.Integer, nullable=False, default=0)
    medium_count = db.Column(db.Integer, nullable=False, default=0)
    low_count = db.Column(db.Integer, nullable=False, default=0)
    info_count = db.Column(db.Integer, nullable=False, default=0)

    # ── Suppressed findings ──
    suppressed_count = db.Column(db.Integer, nullable=False, default=0)

    # ── Exposure score at snapshot time ──
    exposure_score = db.Column(db.Float, nullable=False, default=0.0)

    # ── Activity metrics (what happened since last snapshot) ──
    new_findings = db.Column(db.Integer, nullable=False, default=0)
    resolved_findings = db.Column(db.Integer, nullable=False, default=0)
    suppressed_findings = db.Column(db.Integer, nullable=False, default=0)

    # ── MTTR (Mean Time To Remediate) in hours ──
    # Calculated from finding events: avg time from opened → resolved
    mttr_hours = db.Column(db.Float, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("history_snapshots"))
    group = db.relationship("AssetGroup")

    __table_args__ = (
        UniqueConstraint("organization_id", "group_id", "snapshot_date", name="uq_snapshot_org_group_date"),
    )

    # ============================================
# Integrations & Notification Rules
# ============================================

class Integration(db.Model):
    """
    A configured integration connection for an organization.
    Types: slack, jira, pagerduty, webhook, email
    """
    __tablename__ = "integration"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Integration type
    integration_type = db.Column(db.String(30), nullable=False)  # slack, jira, pagerduty, webhook, email
    
    # Display name (e.g. "Prod Slack Channel", "Security Jira Board")
    name = db.Column(db.String(200), nullable=False)
    
    # Connection config stored as JSON
    # Slack: {"webhook_url": "https://hooks.slack.com/..."}
    # Jira: {"base_url": "https://company.atlassian.net", "project_key": "SEC", "email": "...", "api_token": "..."}
    # PagerDuty: {"routing_key": "..."}
    # Webhook: {"url": "https://...", "secret": "...", "method": "POST"}
    # Email: {"recipients": "a@b.com,c@d.com", "smtp_host": "", "smtp_port": 587, "smtp_user": "", "smtp_pass": "", "from_email": ""}
    config_json = db.Column(db.JSON, nullable=False, default=dict)
    
    enabled = db.Column(db.Boolean, default=True)
    
    # Last test/send status
    last_test_at = db.Column(db.DateTime, nullable=True)
    last_test_ok = db.Column(db.Boolean, nullable=True)
    last_error = db.Column(db.String(500), nullable=True)
    
    created_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("integrations", cascade="all, delete-orphan"))
    creator = db.relationship("User")
    notification_rules = db.relationship("NotificationRule", back_populates="integration", cascade="all, delete-orphan")


class NotificationRule(db.Model):
    """
    Defines what events trigger a notification on a specific integration.
    """
    __tablename__ = "notification_rule"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id", ondelete="CASCADE"), nullable=False, index=True)
    integration_id = db.Column(db.Integer, db.ForeignKey("integration.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Display name (e.g. "Alert on criticals", "Jira ticket for highs")
    name = db.Column(db.String(200), nullable=False)
    
    # Event type that triggers this rule
    # finding.critical, finding.high, finding.medium, finding.any
    # scan.completed, scan.failed
    # exposure.threshold
    # monitor.alert
    event_type = db.Column(db.String(50), nullable=False)
    
    # Optional filters (JSON)
    # e.g. {"group_ids": [1, 2], "min_severity": "high", "threshold": 70}
    filters_json = db.Column(db.JSON, nullable=True, default=dict)
    
    # For Jira: create_ticket mode vs notify mode
    # "notify" = just send a message, "create_ticket" = create a Jira issue
    action_mode = db.Column(db.String(30), nullable=False, default="notify")
    
    # Jira ticket config (only when action_mode = "create_ticket")
    # {"issue_type": "Bug", "priority": "High", "labels": ["security"], "assignee": ""}
    action_config_json = db.Column(db.JSON, nullable=True, default=dict)
    
    enabled = db.Column(db.Boolean, default=True)
    
    # Stats
    last_triggered_at = db.Column(db.DateTime, nullable=True)
    trigger_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)

    # Relationships
    organization = db.relationship("Organization", backref=db.backref("notification_rules", cascade="all, delete-orphan"))
    integration = db.relationship("Integration", back_populates="notification_rules")


    # =============================================================================
# F7: AuditLog Model
# Add this class to your app/models.py file
# =============================================================================

class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    organization_id = db.Column(db.Integer, nullable=False, index=True)
    user_id = db.Column(db.Integer, nullable=True)
    user_email = db.Column(db.String(255), nullable=True)

    # What happened
    action = db.Column(db.String(100), nullable=False)      # e.g. 'finding.resolved'
    category = db.Column(db.String(50), nullable=False)      # e.g. 'finding'

    # What it happened to
    target_type = db.Column(db.String(50), nullable=True)    # e.g. 'finding'
    target_id = db.Column(db.String(50), nullable=True)
    target_label = db.Column(db.String(500), nullable=True)

    # Details
    description = db.Column(db.Text, nullable=True)
    metadata_json = db.Column(db.JSON, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)

    # When
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    