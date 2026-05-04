// FILE: app/(authenticated)/settings/integrations/page.tsx
"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  Plus, Trash2, TestTube, Plug, Bell, ToggleLeft, ToggleRight,
  Pencil, X, Check, AlertCircle, Loader2, ExternalLink,
  MessageSquare, Ticket, Webhook, Mail, Siren, ChevronDown, Lock,
  Copy, RefreshCw, Send, FileText,
} from "lucide-react";
import {
  listIntegrations, createIntegration, updateIntegration, deleteIntegration, testIntegration,
  listNotificationRules, createNotificationRule, updateNotificationRule, deleteNotificationRule,
  getAuditWebhook, saveAuditWebhook, deleteAuditWebhook, testAuditWebhook,
  listAuditWebhookDeliveries,
  type Integration, type NotificationRule,
  type AuditWebhookConfig, type AuditWebhookDelivery,
} from "../../../lib/api";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../../ui/dialog";
import { useOrg } from "../../contexts/OrgContext";
import { PageHint, PageHintToggle } from "../../../ui/PageHint";

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

const INTEGRATION_TYPES = [
  { value: "slack", label: "Slack", icon: MessageSquare, color: "#4A154B", description: "Send notifications to Slack channels via webhooks" },
  { value: "jira", label: "Jira", icon: Ticket, color: "#0052CC", description: "Create tickets or send notifications to Jira projects" },
  { value: "pagerduty", label: "PagerDuty", icon: Siren, color: "#06AC38", description: "Trigger PagerDuty incidents via Events API v2" },
  { value: "webhook", label: "Webhook", icon: Webhook, color: "#f97316", description: "Send JSON payloads to any HTTP endpoint" },
  { value: "email", label: "Email", icon: Mail, color: "#3b82f6", description: "Send email notifications via SMTP" },
] as const;

const EVENT_TYPES = [
  { value: "finding.critical", label: "Critical Finding", description: "New critical severity finding detected" },
  { value: "finding.high", label: "High Finding", description: "New high severity finding detected" },
  { value: "finding.medium", label: "Medium Finding", description: "New medium severity finding detected" },
  { value: "finding.any", label: "Any Finding", description: "Any new finding detected (wildcard)" },
  { value: "scan.completed", label: "Scan Completed", description: "A scan job finished successfully" },
  { value: "scan.failed", label: "Scan Failed", description: "A scan job failed" },
  { value: "exposure.threshold", label: "Exposure Threshold", description: "Exposure score crosses a threshold" },
  { value: "monitor.alert", label: "Monitor Alert", description: "A monitoring alert was triggered" },
];

const CONFIG_FIELDS: Record<string, { key: string; label: string; type: string; placeholder: string; required?: boolean }[]> = {
  slack: [
    { key: "webhook_url", label: "Webhook URL", type: "url", placeholder: "https://hooks.slack.com/services/...", required: true },
  ],
  jira: [
    { key: "base_url", label: "Jira Base URL", type: "url", placeholder: "https://yourcompany.atlassian.net", required: true },
    { key: "project_key", label: "Project Key", type: "text", placeholder: "SEC", required: true },
    { key: "email", label: "Email", type: "email", placeholder: "you@company.com", required: true },
    { key: "api_token", label: "API Token", type: "password", placeholder: "Your Jira API token", required: true },
  ],
  pagerduty: [
    { key: "routing_key", label: "Routing Key", type: "password", placeholder: "Events API v2 routing key", required: true },
  ],
  webhook: [
    { key: "url", label: "Endpoint URL", type: "url", placeholder: "https://your-endpoint.com/webhook", required: true },
    { key: "secret", label: "HMAC Secret (optional)", type: "password", placeholder: "Shared secret for signature verification" },
    { key: "method", label: "HTTP Method", type: "text", placeholder: "POST" },
  ],
  email: [
    { key: "recipients", label: "Recipients", type: "text", placeholder: "a@company.com, b@company.com", required: true },
    { key: "from_email", label: "From Address (optional)", type: "email", placeholder: "contact@nanoasm.com" },
  ],
};

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

function getTypeInfo(type: string) {
  return INTEGRATION_TYPES.find((t) => t.value === type) || INTEGRATION_TYPES[0];
}

function timeAgo(iso: string | null): string {
  if (!iso) return "Never";
  const d = new Date(iso);
  const seconds = Math.floor((Date.now() - d.getTime()) / 1000);
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

// ═══════════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════════

type Banner = { kind: "ok" | "err"; text: string } | null;

export default function IntegrationsPage() {
  const [tab, setTab] = useState<"connections" | "rules" | "audit-stream">("connections");
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [rules, setRules] = useState<NotificationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [banner, setBanner] = useState<Banner>(null);

  const notify = useCallback((kind: "ok" | "err", text: string) => {
    setBanner({ kind, text });
  }, []);

  // auto-clear banner
  useEffect(() => {
    if (!banner) return;
    const t = setTimeout(() => setBanner(null), 5000);
    return () => clearTimeout(t);
  }, [banner]);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const [ints, rls] = await Promise.all([listIntegrations(), listNotificationRules()]);
      setIntegrations(ints);
      setRules(rls);
    } catch (e: any) {
      notify("err", e?.message || "Failed to load integrations");
    } finally {
      setLoading(false);
    }
  }, [notify]);

  useEffect(() => { load(); }, [load]);

  return (
    <main className="flex-1 p-6 lg:p-8 overflow-y-auto">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-3">
          <Plug className="w-7 h-7 text-primary" />
          Integrations
          <PageHintToggle pageKey="integrations" />
        </h1>
        <p className="text-muted-foreground mt-1">
          Connect external services and configure notification rules for security events.
        </p>
      </div>

      <PageHint
        pageKey="integrations"
        title="Integrations"
        body="Send security events to Slack, Jira, PagerDuty, email or any webhook. Configure connections, then create notification rules for the events you care about. Audit-log streaming is also configured here."
      />

      {/* Tabs */}
      <div className="flex items-center gap-1 mb-6 bg-card/50 rounded-xl p-1 w-fit border border-border/50">
        <button
          onClick={() => setTab("connections")}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            tab === "connections"
              ? "bg-primary text-primary-foreground"
              : "text-muted-foreground hover:text-foreground hover:bg-card"
          }`}
        >
          <span className="flex items-center gap-2">
            <Plug className="w-4 h-4" />
            Connections
            <span className="text-xs opacity-70">({integrations.length})</span>
          </span>
        </button>
        <button
          onClick={() => setTab("rules")}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            tab === "rules"
              ? "bg-primary text-primary-foreground"
              : "text-muted-foreground hover:text-foreground hover:bg-card"
          }`}
        >
          <span className="flex items-center gap-2">
            <Bell className="w-4 h-4" />
            Notification Rules
            <span className="text-xs opacity-70">({rules.length})</span>
          </span>
        </button>
        <button
          onClick={() => setTab("audit-stream")}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            tab === "audit-stream"
              ? "bg-primary text-primary-foreground"
              : "text-muted-foreground hover:text-foreground hover:bg-card"
          }`}
        >
          <span className="flex items-center gap-2">
            <FileText className="w-4 h-4" />
            Audit Log Stream
          </span>
        </button>
      </div>

      {/* Banner */}
      {banner && (
        <div className={`mb-4 p-3 rounded-lg border text-sm flex items-center justify-between gap-2 ${
          banner.kind === "ok"
            ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-300"
            : "bg-red-500/10 border-red-500/20 text-red-400"
        }`}>
          <span className="flex items-center gap-2">
            {banner.kind === "ok" ? <Check className="w-4 h-4 shrink-0" /> : <AlertCircle className="w-4 h-4 shrink-0" />}
            {banner.text}
          </span>
          <button onClick={() => setBanner(null)} className="hover:opacity-70 shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Loading */}
      {loading ? (
        <div className="flex items-center justify-center py-20 text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin mr-2" />
          Loading integrations...
        </div>
      ) : tab === "connections" ? (
        <ConnectionsTab integrations={integrations} onRefresh={load} notify={notify} />
      ) : tab === "rules" ? (
        <RulesTab rules={rules} integrations={integrations} onRefresh={load} notify={notify} />
      ) : (
        <AuditStreamTab notify={notify} />
      )}
    </main>
  );
}

// ═══════════════════════════════════════════════════════════════
// Connections Tab
// ═══════════════════════════════════════════════════════════════

function ConnectionsTab({ integrations, onRefresh, notify }: { integrations: Integration[]; onRefresh: () => void; notify: (kind: "ok" | "err", text: string) => void }) {
  const [showAdd, setShowAdd] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-muted-foreground">
          {integrations.length === 0 ? "No integrations configured yet." : `${integrations.length} integration${integrations.length === 1 ? "" : "s"} configured`}
        </p>
        <button
          onClick={() => { setShowAdd(true); setEditId(null); }}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Integration
        </button>
      </div>

      {/* Add/Edit modal */}
      {showAdd && (
        <IntegrationForm
          existing={editId ? integrations.find((i) => i.id === editId) : undefined}
          onClose={() => { setShowAdd(false); setEditId(null); }}
          onSaved={() => { setShowAdd(false); setEditId(null); onRefresh(); }}
          notify={notify}
        />
      )}

      {/* Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {integrations.map((integ) => (
          <IntegrationCard
            key={integ.id}
            integration={integ}
            onEdit={() => { setEditId(integ.id); setShowAdd(true); }}
            onRefresh={onRefresh}
            notify={notify}
          />
        ))}
      </div>

      {/* Empty state */}
      {integrations.length === 0 && !showAdd && (
        <div className="text-center py-16 border border-dashed border-border/50 rounded-xl">
          <Plug className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
          <p className="text-muted-foreground mb-4">Connect your first integration to start receiving notifications.</p>
          <button
            onClick={() => setShowAdd(true)}
            className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
          >
            Add Integration
          </button>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// Integration Card
// ═══════════════════════════════════════════════════════════════

function IntegrationCard({ integration, onEdit, onRefresh, notify }: { integration: Integration; onEdit: () => void; onRefresh: () => void; notify: (kind: "ok" | "err", text: string) => void }) {
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [toggling, setToggling] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  // auto-clear test result
  useEffect(() => {
    if (!testResult) return;
    const t = setTimeout(() => setTestResult(null), 5000);
    return () => clearTimeout(t);
  }, [testResult]);

  const info = getTypeInfo(integration.type);
  const Icon = info.icon;

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await testIntegration(integration.id);
      setTestResult({ ok: res.success, msg: res.success ? "Test passed!" : res.error || "Test failed" });
      onRefresh();
    } catch (e: any) {
      setTestResult({ ok: false, msg: e?.message || "Test failed" });
    } finally {
      setTesting(false);
    }
  }

  async function handleToggle() {
    setToggling(true);
    try {
      await updateIntegration(integration.id, { enabled: !integration.enabled });
      onRefresh();
    } catch (e: any) {
      notify("err", e?.message || "Failed to update integration");
    } finally { setToggling(false); }
  }

  async function handleDelete() {
    setDeleting(true);
    try {
      await deleteIntegration(integration.id);
      notify("ok", `Deleted integration "${integration.name}".`);
      setConfirmDelete(false);
      onRefresh();
    } catch (e: any) {
      notify("err", e?.message || "Failed to delete integration");
    } finally { setDeleting(false); }
  }

  return (
    <div className={`rounded-xl border p-5 transition-colors ${
      integration.enabled ? "bg-card border-border/50" : "bg-card/30 border-border/30 opacity-60"
    }`}>
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: info.color + "20" }}>
            <Icon className="w-5 h-5" style={{ color: info.color }} />
          </div>
          <div>
            <h3 className="font-semibold text-foreground text-sm">{integration.name}</h3>
            <span className="text-xs text-muted-foreground capitalize">{info.label}</span>
          </div>
        </div>
        <button
          onClick={handleToggle}
          disabled={toggling}
          className="text-muted-foreground hover:text-foreground transition-colors"
          title={integration.enabled ? "Disable" : "Enable"}
        >
          {integration.enabled
            ? <ToggleRight className="w-7 h-7 text-emerald-500" />
            : <ToggleLeft className="w-7 h-7" />
          }
        </button>
      </div>

      {/* Status row */}
      <div className="flex items-center gap-3 mb-4 text-xs text-muted-foreground">
        {integration.lastTestAt && (
          <span className="flex items-center gap-1">
            {integration.lastTestOk
              ? <Check className="w-3.5 h-3.5 text-emerald-500" />
              : <X className="w-3.5 h-3.5 text-red-400" />
            }
            Test {integration.lastTestOk ? "passed" : "failed"} {timeAgo(integration.lastTestAt)}
          </span>
        )}
        {integration.lastError && !integration.lastTestOk && (
          <span className="text-red-400 truncate max-w-[200px]" title={integration.lastError}>
            {integration.lastError}
          </span>
        )}
      </div>

      {/* Test result flash */}
      {testResult && (
        <div className={`mb-3 p-2 rounded-lg text-xs flex items-center gap-2 ${
          testResult.ok ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-red-500/10 text-red-400 border border-red-500/20"
        }`}>
          {testResult.ok ? <Check className="w-3.5 h-3.5" /> : <AlertCircle className="w-3.5 h-3.5" />}
          {testResult.msg}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-2 pt-2 border-t border-border/30">
        <button
          onClick={handleTest}
          disabled={testing || !integration.enabled}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-card hover:bg-accent border border-border/50 text-muted-foreground hover:text-foreground transition-colors disabled:opacity-40"
        >
          {testing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <TestTube className="w-3.5 h-3.5" />}
          Test
        </button>
        <button
          onClick={onEdit}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-card hover:bg-accent border border-border/50 text-muted-foreground hover:text-foreground transition-colors"
        >
          <Pencil className="w-3.5 h-3.5" />
          Edit
        </button>
        <button
          onClick={() => setConfirmDelete(true)}
          disabled={deleting}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-red-400 hover:text-red-300 hover:bg-red-500/10 border border-transparent hover:border-red-500/20 transition-colors ml-auto disabled:opacity-40"
        >
          {deleting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
          Delete
        </button>
      </div>

      {/* Delete confirmation dialog */}
      <Dialog open={confirmDelete} onOpenChange={(o) => { if (!o && !deleting) setConfirmDelete(false); }}>
        <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
          <DialogHeader><DialogTitle>Delete Integration</DialogTitle></DialogHeader>
          <p className="text-sm text-muted-foreground">
            Delete <span className="text-foreground font-semibold">{integration.name}</span>?
            All associated notification rules will be removed too. This cannot be undone.
          </p>
          <div className="flex gap-3 justify-end pt-4">
            <button
              type="button"
              onClick={() => setConfirmDelete(false)}
              disabled={deleting}
              className="px-4 py-2 rounded-lg border border-border/50 text-sm text-foreground hover:bg-accent transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleDelete}
              disabled={deleting}
              className="px-4 py-2 rounded-lg bg-red-500 hover:bg-red-600 text-white text-sm font-medium disabled:opacity-50 transition-colors"
            >
              {deleting ? "Deleting..." : "Delete"}
            </button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// Integration Form (Add / Edit)
// ═══════════════════════════════════════════════════════════════

function IntegrationForm({ existing, onClose, onSaved, notify }: { existing?: Integration; onClose: () => void; onSaved: () => void; notify: (kind: "ok" | "err", text: string) => void }) {
  const isEdit = !!existing;
  const { hasFeature } = useOrg();
  const webhooksAllowed = hasFeature("webhooks");
  const [type, setType] = useState(existing?.type || "");
  const [name, setName] = useState(existing?.name || "");
  const [config, setConfig] = useState<Record<string, any>>(existing?.config || {});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function updateConfig(key: string, value: any) {
    setConfig((c) => ({ ...c, [key]: value }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!type || !name) { setError("Type and name are required"); return; }

    setSaving(true);
    setError(null);
    try {
      // On edit, omit empty password-typed fields so we don't overwrite saved secrets
      const payloadConfig = isEdit
        ? Object.fromEntries(
            Object.entries(config).filter(([key, value]) => {
              const f = (CONFIG_FIELDS[type] || []).find((x) => x.key === key);
              if (f?.type === "password" && (value === "" || value == null)) return false;
              return true;
            })
          )
        : config;

      if (isEdit) {
        await updateIntegration(existing!.id, { name, config: payloadConfig });
        notify("ok", `Updated integration "${name}".`);
      } else {
        await createIntegration({ type, name, config: payloadConfig });
        notify("ok", `Created integration "${name}".`);
      }
      onSaved();
    } catch (e: any) {
      setError(e?.message || "Failed to save");
    } finally {
      setSaving(false);
    }
  }

  const fields = CONFIG_FIELDS[type] || [];

  return (
    <div className="mb-6 rounded-xl border border-border/50 bg-card p-6">
      <div className="flex items-center justify-between mb-5">
        <h3 className="font-semibold text-foreground">{isEdit ? "Edit Integration" : "Add Integration"}</h3>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
          <X className="w-5 h-5" />
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Type selector (only for new) */}
        {!isEdit && (
          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Integration Type</label>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
              {INTEGRATION_TYPES.map((t) => {
                const TIcon = t.icon;
                const locked = t.value === "webhook" && !webhooksAllowed;
                return (
                  <button
                    key={t.value}
                    type="button"
                    onClick={() => { if (locked) return; setType(t.value); setConfig({}); }}
                    disabled={locked}
                    title={locked ? "Webhooks require the Professional plan or higher" : t.description}
                    className={`relative flex flex-col items-center gap-2 p-3 rounded-lg border text-xs font-medium transition-all ${
                      locked
                        ? "border-border/30 bg-card/30 text-muted-foreground/50 cursor-not-allowed"
                        : type === t.value
                          ? "border-primary bg-primary/10 text-primary"
                          : "border-border/50 bg-card/50 text-muted-foreground hover:border-border hover:text-foreground"
                    }`}
                  >
                    {locked && (
                      <Lock className="absolute top-1.5 right-1.5 w-3 h-3 text-amber-400" />
                    )}
                    <TIcon className="w-5 h-5" />
                    {t.label}
                  </button>
                );
              })}
            </div>
            {type && (
              <p className="text-xs text-muted-foreground mt-2">{getTypeInfo(type).description}</p>
            )}
            {!webhooksAllowed && (
              <p className="text-xs text-amber-400/80 mt-2 flex items-center gap-1.5">
                <Lock className="w-3 h-3" />
                Webhooks require the Professional plan or higher.
              </p>
            )}
          </div>
        )}

        {/* Name */}
        {type && (
          <div>
            <label className="block text-sm font-medium text-foreground mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={`e.g. ${getTypeInfo(type).label} — Production`}
              className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
          </div>
        )}

        {/* Config fields */}
        {fields.map((f) => {
          const isPassword = f.type === "password";
          const placeholder = isEdit && isPassword
            ? "Leave blank to keep current value"
            : f.placeholder;
          return (
            <div key={f.key}>
              <label className="block text-sm font-medium text-foreground mb-1">
                {f.label}
                {f.required && !(isEdit && isPassword) && <span className="text-red-400 ml-1">*</span>}
              </label>
              <input
                type={f.type}
                value={config[f.key] || ""}
                onChange={(e) => updateConfig(f.key, e.target.value)}
                placeholder={placeholder}
                className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
          );
        })}

        {/* Error */}
        {error && (
          <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs flex items-center gap-2">
            <AlertCircle className="w-3.5 h-3.5" />
            {error}
          </div>
        )}

        {/* Actions */}
        {type && (
          <div className="flex items-center gap-3 pt-2">
            <button
              type="submit"
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
              {isEdit ? "Save Changes" : "Add Integration"}
            </button>
            <button type="button" onClick={onClose} className="px-4 py-2 rounded-lg text-sm text-muted-foreground hover:text-foreground transition-colors">
              Cancel
            </button>
          </div>
        )}
      </form>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// Rules Tab
// ═══════════════════════════════════════════════════════════════

function RulesTab({ rules, integrations, onRefresh, notify }: { rules: NotificationRule[]; integrations: Integration[]; onRefresh: () => void; notify: (kind: "ok" | "err", text: string) => void }) {
  const [showAdd, setShowAdd] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);

  if (integrations.length === 0) {
    return (
      <div className="text-center py-16 border border-dashed border-border/50 rounded-xl">
        <Bell className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
        <p className="text-muted-foreground mb-2">Add an integration first before creating notification rules.</p>
        <p className="text-xs text-muted-foreground/60">Go to the Connections tab to set one up.</p>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-muted-foreground">
          {rules.length === 0 ? "No rules configured yet." : `${rules.length} rule${rules.length === 1 ? "" : "s"} configured`}
        </p>
        <button
          onClick={() => { setShowAdd(true); setEditId(null); }}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Rule
        </button>
      </div>

      {/* Add/Edit form */}
      {showAdd && (
        <RuleForm
          existing={editId ? rules.find((r) => r.id === editId) : undefined}
          integrations={integrations}
          onClose={() => { setShowAdd(false); setEditId(null); }}
          onSaved={() => { setShowAdd(false); setEditId(null); onRefresh(); }}
          notify={notify}
        />
      )}

      {/* Rules table */}
      {rules.length > 0 && (
        <div className="rounded-xl border border-border/50 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-card/80">
              <tr className="text-left text-xs text-muted-foreground uppercase tracking-wider">
                <th className="px-4 py-3 font-medium">Rule</th>
                <th className="px-4 py-3 font-medium">Event</th>
                <th className="px-4 py-3 font-medium">Integration</th>
                <th className="px-4 py-3 font-medium">Action</th>
                <th className="px-4 py-3 font-medium">Triggered</th>
                <th className="px-4 py-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30">
              {rules.map((rule) => (
                <RuleRow
                  key={rule.id}
                  rule={rule}
                  onEdit={() => { setEditId(rule.id); setShowAdd(true); }}
                  onRefresh={onRefresh}
                  notify={notify}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Empty */}
      {rules.length === 0 && !showAdd && (
        <div className="text-center py-16 border border-dashed border-border/50 rounded-xl">
          <Bell className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
          <p className="text-muted-foreground mb-4">Create notification rules to get alerted when security events occur.</p>
          <button
            onClick={() => setShowAdd(true)}
            className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
          >
            Add Rule
          </button>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// Rule Row
// ═══════════════════════════════════════════════════════════════

function RuleRow({ rule, onEdit, onRefresh, notify }: { rule: NotificationRule; onEdit: () => void; onRefresh: () => void; notify: (kind: "ok" | "err", text: string) => void }) {
  const [deleting, setDeleting] = useState(false);
  const [toggling, setToggling] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const integrationDeleted = !rule.integrationType;
  const integInfo = integrationDeleted ? null : getTypeInfo(rule.integrationType!);
  const IntegIcon = integInfo?.icon;

  async function handleToggle() {
    setToggling(true);
    try {
      await updateNotificationRule(rule.id, { enabled: !rule.enabled });
      onRefresh();
    } catch (e: any) {
      notify("err", e?.message || "Failed to update rule");
    } finally { setToggling(false); }
  }

  async function handleDelete() {
    setDeleting(true);
    try {
      await deleteNotificationRule(rule.id);
      notify("ok", `Deleted rule "${rule.name}".`);
      setConfirmDelete(false);
      onRefresh();
    } catch (e: any) {
      notify("err", e?.message || "Failed to delete rule");
    } finally { setDeleting(false); }
  }

  return (
    <tr className={`transition-colors hover:bg-card/50 ${!rule.enabled ? "opacity-50" : ""}`}>
      <td className="px-4 py-3">
        <div className="font-medium text-foreground">{rule.name}</div>
      </td>
      <td className="px-4 py-3">
        <span className="inline-flex items-center px-2 py-0.5 rounded-md bg-card border border-border/50 text-xs font-mono">
          {rule.eventType}
        </span>
      </td>
      <td className="px-4 py-3">
        {integrationDeleted ? (
          <span className="inline-flex items-center gap-1.5 text-xs text-red-400">
            <AlertCircle className="w-3.5 h-3.5" />
            Integration deleted
          </span>
        ) : (
          <span className="inline-flex items-center gap-1.5 text-xs">
            {IntegIcon && <IntegIcon className="w-3.5 h-3.5" style={{ color: integInfo!.color }} />}
            {rule.integrationName || "Unknown"}
          </span>
        )}
      </td>
      <td className="px-4 py-3">
        <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium ${
          rule.actionMode === "create_ticket"
            ? "bg-blue-500/10 text-blue-400 border border-blue-500/20"
            : "bg-card border border-border/50 text-muted-foreground"
        }`}>
          {rule.actionMode === "create_ticket" ? "Create Ticket" : "Notify"}
        </span>
      </td>
      <td className="px-4 py-3 text-xs text-muted-foreground">
        {rule.triggerCount > 0 ? (
          <span>{rule.triggerCount}× — {timeAgo(rule.lastTriggeredAt)}</span>
        ) : (
          <span>Never</span>
        )}
      </td>
      <td className="px-4 py-3 text-right">
        <div className="flex items-center gap-1 justify-end">
          <button onClick={handleToggle} disabled={toggling} className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground transition-colors" title={rule.enabled ? "Disable" : "Enable"}>
            {rule.enabled ? <ToggleRight className="w-5 h-5 text-emerald-500" /> : <ToggleLeft className="w-5 h-5" />}
          </button>
          <button onClick={onEdit} className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground transition-colors">
            <Pencil className="w-4 h-4" />
          </button>
          <button onClick={() => setConfirmDelete(true)} disabled={deleting} className="p-1.5 rounded-lg text-red-400/60 hover:text-red-400 transition-colors">
            {deleting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
          </button>
        </div>

        {/* Delete confirmation dialog */}
        <Dialog open={confirmDelete} onOpenChange={(o) => { if (!o && !deleting) setConfirmDelete(false); }}>
          <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
            <DialogHeader><DialogTitle>Delete Rule</DialogTitle></DialogHeader>
            <p className="text-sm text-muted-foreground">
              Delete rule <span className="text-foreground font-semibold">{rule.name}</span>?
              No more notifications will be sent for this event/integration combination.
            </p>
            <div className="flex gap-3 justify-end pt-4">
              <button
                type="button"
                onClick={() => setConfirmDelete(false)}
                disabled={deleting}
                className="px-4 py-2 rounded-lg border border-border/50 text-sm text-foreground hover:bg-accent transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDelete}
                disabled={deleting}
                className="px-4 py-2 rounded-lg bg-red-500 hover:bg-red-600 text-white text-sm font-medium disabled:opacity-50 transition-colors"
              >
                {deleting ? "Deleting..." : "Delete"}
              </button>
            </div>
          </DialogContent>
        </Dialog>
      </td>
    </tr>
  );
}

// ═══════════════════════════════════════════════════════════════
// Rule Form
// ═══════════════════════════════════════════════════════════════

function RuleForm({ existing, integrations, onClose, onSaved, notify }: {
  existing?: NotificationRule;
  integrations: Integration[];
  onClose: () => void;
  onSaved: () => void;
  notify: (kind: "ok" | "err", text: string) => void;
}) {
  const isEdit = !!existing;
  const [name, setName] = useState(existing?.name || "");
  const [integrationId, setIntegrationId] = useState(existing?.integrationId || "");
  const [eventType, setEventType] = useState(existing?.eventType || "");
  const [actionMode, setActionMode] = useState(existing?.actionMode || "notify");
  const [filters, setFilters] = useState<Record<string, any>>(existing?.filters || {});
  const [actionConfig, setActionConfig] = useState<Record<string, any>>(existing?.actionConfig || {});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedIntegration = integrations.find((i) => i.id === integrationId);
  const isJira = selectedIntegration?.type === "jira";

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name || !integrationId || !eventType) {
      setError("Name, integration, and event type are required");
      return;
    }

    setSaving(true);
    setError(null);
    try {
      if (isEdit) {
        await updateNotificationRule(existing!.id, {
          name, integrationId, eventType, actionMode, filters, actionConfig,
        });
        notify("ok", `Updated rule "${name}".`);
      } else {
        await createNotificationRule({
          name, integrationId, eventType, actionMode, filters, actionConfig,
        });
        notify("ok", `Created rule "${name}".`);
      }
      onSaved();
    } catch (e: any) {
      setError(e?.message || "Failed to save rule");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="mb-6 rounded-xl border border-border/50 bg-card p-6">
      <div className="flex items-center justify-between mb-5">
        <h3 className="font-semibold text-foreground">{isEdit ? "Edit Rule" : "Add Notification Rule"}</h3>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
          <X className="w-5 h-5" />
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Name */}
        <div>
          <label className="block text-sm font-medium text-foreground mb-1">Rule Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Alert on critical findings"
            className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Integration */}
          <div>
            <label className="block text-sm font-medium text-foreground mb-1">Integration</label>
            <select
              value={integrationId}
              onChange={(e) => { setIntegrationId(e.target.value); setActionMode("notify"); }}
              className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
            >
              <option value="">Select integration...</option>
              {integrations.filter((i) => i.enabled).map((i) => {
                const info = getTypeInfo(i.type);
                return (
                  <option key={i.id} value={i.id}>{info.label} — {i.name}</option>
                );
              })}
            </select>
          </div>

          {/* Event Type */}
          <div>
            <label className="block text-sm font-medium text-foreground mb-1">Event Type</label>
            <select
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
            >
              <option value="">Select event...</option>
              {EVENT_TYPES.map((evt) => (
                <option key={evt.value} value={evt.value}>{evt.label} — {evt.description}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Action mode (Jira only) */}
        {isJira && (
          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Action Mode</label>
            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => setActionMode("notify")}
                className={`flex-1 p-3 rounded-lg border text-sm font-medium text-left transition-all ${
                  actionMode === "notify"
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border/50 text-muted-foreground hover:border-border"
                }`}
              >
                <Bell className="w-4 h-4 mb-1" />
                <div>Notify Only</div>
                <div className="text-xs font-normal opacity-70 mt-0.5">Validate connection, log event</div>
              </button>
              <button
                type="button"
                onClick={() => setActionMode("create_ticket")}
                className={`flex-1 p-3 rounded-lg border text-sm font-medium text-left transition-all ${
                  actionMode === "create_ticket"
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border/50 text-muted-foreground hover:border-border"
                }`}
              >
                <Ticket className="w-4 h-4 mb-1" />
                <div>Create Ticket</div>
                <div className="text-xs font-normal opacity-70 mt-0.5">Auto-create Jira issues from findings</div>
              </button>
            </div>
          </div>
        )}

        {/* Jira ticket config */}
        {isJira && actionMode === "create_ticket" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 rounded-lg bg-background/50 border border-border/30">
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1">Issue Type</label>
              <input
                type="text"
                value={actionConfig.issue_type || ""}
                onChange={(e) => setActionConfig((c) => ({ ...c, issue_type: e.target.value }))}
                placeholder="Bug"
                className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1">Priority (optional)</label>
              <input
                type="text"
                value={actionConfig.priority || ""}
                onChange={(e) => setActionConfig((c) => ({ ...c, priority: e.target.value }))}
                placeholder="Auto-mapped from severity"
                className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1">Labels (comma-separated)</label>
              <input
                type="text"
                value={actionConfig.labels || ""}
                onChange={(e) => setActionConfig((c) => ({ ...c, labels: e.target.value }))}
                placeholder="security, Nano EASM"
                className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1">Assignee Account ID (optional)</label>
              <input
                type="text"
                value={actionConfig.assignee || ""}
                onChange={(e) => setActionConfig((c) => ({ ...c, assignee: e.target.value }))}
                placeholder="Jira account ID"
                className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
          </div>
        )}

        {/* Exposure threshold filter */}
        {eventType === "exposure.threshold" && (
          <div>
            <label className="block text-sm font-medium text-foreground mb-1">Score Threshold</label>
            <input
              type="number"
              min={0}
              max={100}
              value={filters.threshold || 70}
              onChange={(e) => setFilters((f) => ({ ...f, threshold: parseInt(e.target.value) || 70 }))}
              className="w-32 px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
            <p className="text-xs text-muted-foreground mt-1">Trigger when exposure score exceeds this value</p>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs flex items-center gap-2">
            <AlertCircle className="w-3.5 h-3.5" />
            {error}
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-3 pt-2">
          <button
            type="submit"
            disabled={saving}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
          >
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
            {isEdit ? "Save Changes" : "Add Rule"}
          </button>
          <button type="button" onClick={onClose} className="px-4 py-2 rounded-lg text-sm text-muted-foreground hover:text-foreground transition-colors">
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// Audit Log Stream Tab
// ═══════════════════════════════════════════════════════════════
//
// Plan-gated to Enterprise Gold + Custom (PLAN_CONFIG.audit_log = True).
// Backend returns 403 FEATURE_NOT_AVAILABLE on lower tiers — we
// surface that as an upgrade prompt rather than an error toast.
//
// Critical UX: the signing secret is only ever shown once on
// creation/rotation. Customers must save it externally. After that,
// the GET endpoint only returns a masked preview (whsec_…last4).

const AUDIT_CATEGORIES: { value: string; label: string }[] = [
  { value: "finding", label: "Findings" },
  { value: "asset", label: "Assets" },
  { value: "group", label: "Groups" },
  { value: "scan", label: "Scans" },
  { value: "user", label: "Users" },
  { value: "settings", label: "Settings" },
  { value: "auth", label: "Authentication" },
  { value: "export", label: "Exports" },
];

type AuditStreamFeatureState = "loading" | "available" | "locked" | "error";

function AuditStreamTab({ notify }: { notify: (kind: "ok" | "err", text: string) => void }) {
  const [state, setState] = useState<AuditStreamFeatureState>("loading");
  const [config, setConfig] = useState<AuditWebhookConfig | null>(null);
  const [deliveries, setDeliveries] = useState<AuditWebhookDelivery[]>([]);
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const cfg = await getAuditWebhook();
      setConfig(cfg);
      setState("available");
      try {
        const { deliveries } = await listAuditWebhookDeliveries();
        setDeliveries(deliveries);
      } catch {
        // non-fatal
      }
    } catch (e: any) {
      const code = e?.code || e?.payload?.code;
      if (code === "FEATURE_NOT_AVAILABLE" || /not available/i.test(e?.message || "")) {
        setState("locked");
      } else {
        setErrorMsg(e?.message || "Failed to load audit webhook config");
        setState("error");
      }
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  if (state === "loading") {
    return (
      <div className="flex items-center justify-center py-20 text-muted-foreground">
        <Loader2 className="w-5 h-5 animate-spin mr-2" /> Loading…
      </div>
    );
  }

  if (state === "locked") {
    return (
      <div className="rounded-xl border border-border/50 bg-card/50 p-8 text-center">
        <Lock className="w-10 h-10 text-muted-foreground/50 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-foreground mb-2">Audit Log Stream</h3>
        <p className="text-sm text-muted-foreground max-w-xl mx-auto mb-4">
          Forward every audit-log event to your SIEM or generic webhook receiver in real time.
          HMAC-SHA256 signed payloads, per-category filtering, and a delivery log for debugging.
        </p>
        <p className="text-sm text-muted-foreground">
          Available on <span className="text-foreground font-medium">Enterprise Gold</span> and{" "}
          <span className="text-foreground font-medium">Custom</span> plans.
        </p>
      </div>
    );
  }

  if (state === "error") {
    return (
      <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-6 text-sm text-red-300">
        {errorMsg}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-border/50 bg-card/30 p-5">
        <div className="flex items-start gap-3">
          <FileText className="w-5 h-5 text-primary mt-0.5" />
          <div className="text-sm text-muted-foreground">
            <p className="text-foreground font-medium mb-1">Real-time audit-log forwarding</p>
            <p>
              Every audit event is POSTed to your endpoint as JSON, signed with{" "}
              <code className="text-xs bg-card px-1 py-0.5 rounded">X-Nano-Signature: sha256=…</code>{" "}
              over the raw body. Verify the signature on your side using the secret
              shown when you save the webhook.
            </p>
          </div>
        </div>
      </div>

      <AuditWebhookForm
        config={config}
        onSaved={(cfg, secret) => {
          setConfig(cfg);
          if (secret) setRevealedSecret(secret);
          notify("ok", secret ? "Webhook saved — copy the secret now." : "Webhook updated.");
          refresh();
        }}
        onDeleted={() => {
          setConfig(null);
          setRevealedSecret(null);
          notify("ok", "Webhook configuration removed.");
          refresh();
        }}
        onTestResult={(ok, msg) => notify(ok ? "ok" : "err", msg)}
        notify={notify}
      />

      {revealedSecret && (
        <SecretReveal secret={revealedSecret} onDismiss={() => setRevealedSecret(null)} />
      )}

      {config?.configured && <DeliveriesPanel deliveries={deliveries} onRefresh={refresh} />}
    </div>
  );
}

function AuditWebhookForm({
  config, onSaved, onDeleted, onTestResult, notify,
}: {
  config: AuditWebhookConfig | null;
  onSaved: (cfg: AuditWebhookConfig, newSecret?: string) => void;
  onDeleted: () => void;
  onTestResult: (ok: boolean, msg: string) => void;
  notify: (kind: "ok" | "err", text: string) => void;
}) {
  const configured = !!config?.configured;
  const [url, setUrl] = useState(config?.url || "");
  const [enabled, setEnabled] = useState(config?.enabled ?? true);
  const [allCategories, setAllCategories] = useState<boolean>(!config?.categories);
  const [selectedCats, setSelectedCats] = useState<Set<string>>(
    new Set(config?.categories || []),
  );
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  // Re-sync local form state when the parent reloads config (e.g. after save).
  useEffect(() => {
    setUrl(config?.url || "");
    setEnabled(config?.enabled ?? true);
    setAllCategories(!config?.categories);
    setSelectedCats(new Set(config?.categories || []));
  }, [config]);

  function toggleCat(cat: string) {
    const next = new Set(selectedCats);
    if (next.has(cat)) next.delete(cat); else next.add(cat);
    setSelectedCats(next);
  }

  async function handleSave(opts: { regenerate?: boolean } = {}) {
    if (!url.trim()) {
      notify("err", "Webhook URL is required.");
      return;
    }
    setSaving(true);
    try {
      const payload = {
        url: url.trim(),
        enabled,
        categories: allCategories ? null : Array.from(selectedCats),
        regenerateSecret: opts.regenerate,
      };
      const res = await saveAuditWebhook(payload);
      onSaved(res, res.secret);
    } catch (e: any) {
      notify("err", e?.message || "Failed to save webhook configuration.");
    } finally {
      setSaving(false);
    }
  }

  async function handleTest() {
    setTesting(true);
    try {
      const res = await testAuditWebhook();
      const code = res.delivery.statusCode;
      onTestResult(
        res.ok,
        res.ok
          ? `Test event delivered (${code} in ${res.delivery.durationMs ?? "?"}ms).`
          : `Test failed: ${res.delivery.errorMessage || `HTTP ${code ?? "?"}`}`,
      );
    } catch (e: any) {
      onTestResult(false, e?.message || "Test delivery failed.");
    } finally {
      setTesting(false);
    }
  }

  async function handleDelete() {
    setSaving(true);
    try {
      await deleteAuditWebhook();
      setConfirmDelete(false);
      onDeleted();
    } catch (e: any) {
      notify("err", e?.message || "Failed to delete webhook.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="rounded-xl border border-border/50 bg-card p-6 space-y-5">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-foreground">Webhook configuration</h3>
        {configured && (
          <span
            className={`text-xs px-2 py-1 rounded-full border ${
              config?.enabled
                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                : "bg-amber-500/10 border-amber-500/30 text-amber-300"
            }`}
          >
            {config?.enabled ? "Active" : "Disabled"}
          </span>
        )}
      </div>

      {/* URL */}
      <label className="block">
        <span className="text-sm font-medium text-foreground">Endpoint URL</span>
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://siem.example.com/ingest"
          className="mt-1 w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
        />
        <span className="text-xs text-muted-foreground mt-1 block">
          Must be reachable from our network. HTTPS recommended.
        </span>
      </label>

      {/* Enabled toggle */}
      <div className="flex items-center justify-between rounded-lg border border-border/40 bg-card/50 px-4 py-3">
        <div>
          <p className="text-sm font-medium text-foreground">Forwarding enabled</p>
          <p className="text-xs text-muted-foreground">
            Master kill-switch. When off, events are not delivered but configuration is preserved.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setEnabled(!enabled)}
          className="text-foreground"
          aria-pressed={enabled}
        >
          {enabled ? <ToggleRight className="w-9 h-9 text-primary" /> : <ToggleLeft className="w-9 h-9 text-muted-foreground" />}
        </button>
      </div>

      {/* Secret display */}
      {configured && config?.secretMasked && (
        <div className="rounded-lg border border-border/40 bg-card/50 px-4 py-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium text-foreground">Signing secret</p>
              <p className="text-xs text-muted-foreground font-mono mt-1">{config.secretMasked}</p>
            </div>
            <button
              type="button"
              onClick={() => handleSave({ regenerate: true })}
              disabled={saving}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border/50 text-xs hover:bg-card transition-colors disabled:opacity-50"
            >
              <RefreshCw className="w-3 h-3" />
              Rotate
            </button>
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            The full secret is only shown once when generated. Rotating immediately invalidates the old secret.
          </p>
        </div>
      )}

      {/* Categories */}
      <div>
        <p className="text-sm font-medium text-foreground mb-2">Event categories</p>
        <label className="flex items-center gap-2 mb-3 text-sm">
          <input
            type="checkbox"
            checked={allCategories}
            onChange={(e) => setAllCategories(e.target.checked)}
            className="rounded border-border bg-background"
          />
          Forward all categories
        </label>
        {!allCategories && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {AUDIT_CATEGORIES.map((c) => (
              <label
                key={c.value}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm cursor-pointer transition-colors ${
                  selectedCats.has(c.value)
                    ? "border-primary/50 bg-primary/5 text-foreground"
                    : "border-border/40 text-muted-foreground hover:bg-card/50"
                }`}
              >
                <input
                  type="checkbox"
                  checked={selectedCats.has(c.value)}
                  onChange={() => toggleCat(c.value)}
                  className="rounded border-border bg-background"
                />
                {c.label}
              </label>
            ))}
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex flex-wrap items-center gap-3 pt-2">
        <button
          type="button"
          onClick={() => handleSave()}
          disabled={saving}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
        >
          {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
          {configured ? "Save changes" : "Save and generate secret"}
        </button>

        {configured && (
          <button
            type="button"
            onClick={handleTest}
            disabled={testing || !config?.enabled}
            title={!config?.enabled ? "Enable the webhook to send a test event" : ""}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-border/50 text-sm hover:bg-card transition-colors disabled:opacity-50"
          >
            {testing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            Send test event
          </button>
        )}

        {configured && !confirmDelete && (
          <button
            type="button"
            onClick={() => setConfirmDelete(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-red-500/30 text-red-400 text-sm hover:bg-red-500/10 transition-colors ml-auto"
          >
            <Trash2 className="w-4 h-4" />
            Remove
          </button>
        )}
        {confirmDelete && (
          <div className="flex items-center gap-2 ml-auto">
            <span className="text-sm text-muted-foreground">Confirm removal?</span>
            <button
              type="button"
              onClick={handleDelete}
              disabled={saving}
              className="px-3 py-1.5 rounded-lg bg-red-500 text-white text-sm hover:bg-red-600 transition-colors disabled:opacity-50"
            >
              Yes, remove
            </button>
            <button
              type="button"
              onClick={() => setConfirmDelete(false)}
              className="px-3 py-1.5 rounded-lg border border-border/50 text-sm hover:bg-card transition-colors"
            >
              Cancel
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function SecretReveal({ secret, onDismiss }: { secret: string; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — user can select manually */
    }
  }
  return (
    <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-5">
      <div className="flex items-start gap-3">
        <AlertCircle className="w-5 h-5 text-amber-400 mt-0.5" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-foreground mb-1">
            Save this secret now — it won't be shown again.
          </p>
          <p className="text-xs text-muted-foreground mb-3">
            Use it to verify the <code className="bg-card px-1 rounded">X-Nano-Signature</code> header on
            incoming deliveries. If lost, rotate to generate a new one.
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 px-3 py-2 rounded-lg bg-background border border-border/50 text-xs font-mono break-all">
              {secret}
            </code>
            <button
              type="button"
              onClick={copy}
              className="flex items-center gap-1 px-3 py-2 rounded-lg border border-border/50 text-xs hover:bg-card transition-colors"
            >
              {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
        </div>
        <button onClick={onDismiss} className="text-muted-foreground hover:text-foreground">
          <X className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

function DeliveriesPanel({
  deliveries, onRefresh,
}: {
  deliveries: AuditWebhookDelivery[];
  onRefresh: () => void;
}) {
  return (
    <div className="rounded-xl border border-border/50 bg-card overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3 border-b border-border/40">
        <div>
          <h3 className="font-semibold text-foreground text-sm">Recent deliveries</h3>
          <p className="text-xs text-muted-foreground">Last {deliveries.length} attempts. Useful for debugging delivery failures.</p>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border/50 text-xs hover:bg-card/50 transition-colors"
        >
          <RefreshCw className="w-3 h-3" />
          Refresh
        </button>
      </div>
      {deliveries.length === 0 ? (
        <div className="px-5 py-8 text-center text-sm text-muted-foreground">
          No deliveries yet. Audit events will appear here as they're forwarded.
        </div>
      ) : (
        <div className="divide-y divide-border/40">
          {deliveries.map((d) => (
            <div key={d.id} className="px-5 py-3 flex items-center justify-between gap-4">
              <div className="flex items-center gap-3 min-w-0">
                {d.status === "success" ? (
                  <Check className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : d.status === "failed" ? (
                  <X className="w-4 h-4 text-red-400 shrink-0" />
                ) : (
                  <Loader2 className="w-4 h-4 text-muted-foreground shrink-0 animate-spin" />
                )}
                <div className="min-w-0">
                  <p className="text-xs font-mono text-muted-foreground truncate">{d.eventId}</p>
                  {d.errorMessage && (
                    <p className="text-xs text-red-400 truncate" title={d.errorMessage}>
                      {d.errorMessage}
                    </p>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-3 text-xs text-muted-foreground shrink-0">
                {d.statusCode != null && (
                  <span
                    className={`font-mono px-1.5 py-0.5 rounded ${
                      d.statusCode >= 200 && d.statusCode < 300
                        ? "bg-emerald-500/10 text-emerald-300"
                        : "bg-red-500/10 text-red-300"
                    }`}
                  >
                    {d.statusCode}
                  </span>
                )}
                {d.durationMs != null && <span>{d.durationMs}ms</span>}
                <span>{timeAgo(d.attemptedAt)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}