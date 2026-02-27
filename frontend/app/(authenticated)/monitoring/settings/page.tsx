// FILE: app/(authenticated)/monitoring/settings/page.tsx
// Notification Settings — email, in-app, webhook, severity filter, timing
// ✅ M9 RBAC: save gated by edit_monitors permission
"use client";

import React, { useEffect, useState } from "react";
import {
  Settings, Shield, Bell, Mail, Webhook, Filter, Clock, Check,
  ToggleLeft, ToggleRight, Loader2, X, Eye, Info,
} from "lucide-react";
import Link from "next/link";

import { Button } from "../../../ui/button";
import { Input } from "../../../ui/input";
import { useOrg } from "../../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../../ui/plan-limit-dialog";
import { isPlanError } from "../../../lib/api";
import {
  cn, monitoringFrequencyLabel, SEVERITY_ORDER,
  getMonitorSettings, updateMonitorSettings,
} from "../_lib";
import type { MonitorSettings } from "../_lib";

export default function MonitoringSettingsPage() {
  const [settings, setSettings] = useState<MonitorSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [newEmail, setNewEmail] = useState("");
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const { hasFeature, canDo, planLabel, billing } = useOrg();
  const planLimit = usePlanLimit();
  const hasMonitoring = hasFeature("monitoring");
  const canEdit = canDo("edit_monitors");
  const monitoringFrequency = billing?.limits?.monitoringFrequency || "every_2_days";

  useEffect(() => {
    if (hasMonitoring) {
      getMonitorSettings().then((s) => setSettings(s)).catch(() => {}).finally(() => setLoading(false));
    } else { setLoading(false); }
  }, [hasMonitoring]);

  useEffect(() => {
    if (!banner) return;
    const t = setTimeout(() => setBanner(null), 5000);
    return () => clearTimeout(t);
  }, [banner]);

  async function handleSave() {
    if (!settings) return;
    try {
      setSaving(true);
      const updated = await updateMonitorSettings(settings);
      setSettings(updated);
      setBanner({ kind: "ok", text: "Settings saved." });
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    } finally { setSaving(false); }
  }

  function addEmail() {
    if (!settings || !newEmail.trim() || !newEmail.includes("@")) return;
    if (settings.emailRecipients.includes(newEmail.trim())) return;
    setSettings({ ...settings, emailRecipients: [...settings.emailRecipients, newEmail.trim()] });
    setNewEmail("");
  }

  function removeEmail(email: string) {
    if (!settings) return;
    setSettings({ ...settings, emailRecipients: settings.emailRecipients.filter((e) => e !== email) });
  }

  function toggleSeverity(sev: string) {
    if (!settings) return;
    const has = settings.notifyOnSeverity.includes(sev);
    setSettings({
      ...settings,
      notifyOnSeverity: has
        ? settings.notifyOnSeverity.filter((s) => s !== sev)
        : [...settings.notifyOnSeverity, sev],
    });
  }

  /* ── Gate screens ── */

  if (!hasMonitoring) {
    return (
      <main className="flex-1 overflow-y-auto bg-background">
        <div className="p-8 text-center py-20">
          <p className="text-muted-foreground mb-4">Notification settings require an active monitoring plan.</p>
          <Link href="/monitoring"><Button variant="outline"><Eye className="w-4 h-4 mr-2" />Back to Monitoring</Button></Link>
        </div>
      </main>
    );
  }

  if (loading) {
    return (
      <main className="flex-1 overflow-y-auto bg-background">
        <div className="p-8 text-center text-muted-foreground flex items-center justify-center gap-2 py-20">
          <Loader2 className="w-4 h-4 animate-spin" />Loading settings...
        </div>
      </main>
    );
  }

  if (!settings) {
    return (
      <main className="flex-1 overflow-y-auto bg-background">
        <div className="p-8 text-center text-muted-foreground py-20">Failed to load settings.</div>
      </main>
    );
  }

  /* ── Main render ── */

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8">
        <div className="mb-8">
          <div className="flex items-center gap-2 mb-3">
            <Link href="/monitoring" className="text-muted-foreground hover:text-foreground transition-colors">
              <Eye className="w-5 h-5" />
            </Link>
            <span className="text-muted-foreground/40">/</span>
            <Settings className="w-5 h-5 text-primary" />
            <h1 className="text-2xl font-semibold text-foreground">Notification Settings</h1>
          </div>
          <p className="text-muted-foreground">Configure where and when you receive monitoring alerts.</p>
        </div>

        {banner && (
          <div className={cn("mb-6 rounded-xl border px-4 py-3 text-sm",
            banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>
            {banner.text}
          </div>
        )}

        {!canEdit && (
          <div className="mb-6 rounded-xl border border-border bg-muted/10 px-4 py-3 text-sm text-muted-foreground flex items-center gap-2">
            <Info className="w-4 h-4 shrink-0" />
            You have read-only access. Ask an admin or owner to change notification settings.
          </div>
        )}

        <div className="grid lg:grid-cols-2 gap-6">
          {/* ──── LEFT — Channels ──── */}
          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">Channels</h3>

            {/* Email */}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
              <div className="flex items-center justify-between p-5">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                    <Mail className="w-5 h-5 text-primary" />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-foreground">Email Notifications</div>
                    <div className="text-xs text-muted-foreground">Send alerts to email addresses</div>
                  </div>
                </div>
                {canEdit ? (
                  <button type="button" onClick={() => setSettings({ ...settings, emailEnabled: !settings.emailEnabled })}>
                    {settings.emailEnabled ? <ToggleRight className="w-8 h-8 text-[#10b981]" /> : <ToggleLeft className="w-8 h-8 text-muted-foreground" />}
                  </button>
                ) : (
                  <span className={cn("text-xs font-semibold", settings.emailEnabled ? "text-[#10b981]" : "text-muted-foreground")}>
                    {settings.emailEnabled ? "On" : "Off"}
                  </span>
                )}
              </div>
              {settings.emailEnabled && (
                <div className="border-t border-border p-5 space-y-3 bg-muted/10">
                  {canEdit && (
                    <div className="flex gap-2">
                      <Input placeholder="Add email address..." value={newEmail} onChange={(e) => setNewEmail(e.target.value)} onKeyDown={(e) => e.key === "Enter" && addEmail()} className="flex-1" />
                      <Button size="sm" onClick={addEmail} disabled={!newEmail.includes("@")} className="bg-primary hover:bg-primary/90">Add</Button>
                    </div>
                  )}
                  {settings.emailRecipients.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {settings.emailRecipients.map((email) => (
                        <span key={email} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs bg-muted/30 border border-border text-foreground">
                          {email}
                          {canEdit && (
                            <button type="button" onClick={() => removeEmail(email)} className="text-muted-foreground hover:text-red-400">
                              <X className="w-3 h-3" />
                            </button>
                          )}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">No recipients added yet.</p>
                  )}
                </div>
              )}
            </div>

            {/* In-app */}
            <div className="bg-card border border-border rounded-xl p-5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-[#00b8d4]/10 flex items-center justify-center shrink-0">
                    <Bell className="w-5 h-5 text-[#00b8d4]" />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-foreground">In-App Notifications</div>
                    <div className="text-xs text-muted-foreground">Show alerts in the notification bell</div>
                  </div>
                </div>
                {canEdit ? (
                  <button type="button" onClick={() => setSettings({ ...settings, inAppEnabled: !settings.inAppEnabled })}>
                    {settings.inAppEnabled ? <ToggleRight className="w-8 h-8 text-[#10b981]" /> : <ToggleLeft className="w-8 h-8 text-muted-foreground" />}
                  </button>
                ) : (
                  <span className={cn("text-xs font-semibold", settings.inAppEnabled ? "text-[#10b981]" : "text-muted-foreground")}>
                    {settings.inAppEnabled ? "On" : "Off"}
                  </span>
                )}
              </div>
            </div>

            {/* Webhook */}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
              <div className="flex items-center justify-between p-5">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-[#ff8800]/10 flex items-center justify-center shrink-0">
                    <Webhook className="w-5 h-5 text-[#ff8800]" />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-foreground">Webhook</div>
                    <div className="text-xs text-muted-foreground">POST alerts to Slack, Discord, PagerDuty, etc.</div>
                  </div>
                </div>
                {canEdit ? (
                  <button type="button" onClick={() => setSettings({ ...settings, webhookEnabled: !settings.webhookEnabled })}>
                    {settings.webhookEnabled ? <ToggleRight className="w-8 h-8 text-[#10b981]" /> : <ToggleLeft className="w-8 h-8 text-muted-foreground" />}
                  </button>
                ) : (
                  <span className={cn("text-xs font-semibold", settings.webhookEnabled ? "text-[#10b981]" : "text-muted-foreground")}>
                    {settings.webhookEnabled ? "On" : "Off"}
                  </span>
                )}
              </div>
              {settings.webhookEnabled && (
                <div className="border-t border-border p-5 bg-muted/10">
                  <label className="text-xs font-medium text-muted-foreground block mb-1.5">Webhook URL</label>
                  <Input
                    placeholder="https://hooks.slack.com/services/..."
                    value={settings.webhookUrl}
                    onChange={(e) => setSettings({ ...settings, webhookUrl: e.target.value })}
                    disabled={!canEdit}
                  />
                </div>
              )}
            </div>
          </div>

          {/* ──── RIGHT — Preferences ──── */}
          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">Preferences</h3>

            {/* Severity filter */}
            <div className="bg-card border border-border rounded-xl p-5 space-y-3">
              <div className="flex items-center gap-3 mb-1">
                <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0">
                  <Filter className="w-5 h-5 text-red-400" />
                </div>
                <div>
                  <div className="text-sm font-medium text-foreground">Severity Filter</div>
                  <div className="text-xs text-muted-foreground">Only notify for selected severity levels</div>
                </div>
              </div>
              <div className="flex flex-wrap gap-2 pt-1">
                {SEVERITY_ORDER.map((sev) => {
                  const active = settings.notifyOnSeverity.includes(sev);
                  return (
                    <button
                      key={sev}
                      type="button"
                      onClick={() => canEdit && toggleSeverity(sev)}
                      disabled={!canEdit}
                      className={cn(
                        "px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all",
                        active ? "bg-primary/10 text-primary border-primary/30" : "bg-muted/20 text-muted-foreground border-border hover:border-primary/30",
                        !canEdit && "cursor-default opacity-70"
                      )}
                    >
                      {active && <Check className="w-3 h-3 inline mr-1" />}
                      {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Timing */}
            <div className="bg-card border border-border rounded-xl p-5 space-y-3">
              <div className="flex items-center gap-3 mb-1">
                <div className="w-10 h-10 rounded-lg bg-[#a78bfa]/10 flex items-center justify-center shrink-0">
                  <Clock className="w-5 h-5 text-[#a78bfa]" />
                </div>
                <div>
                  <div className="text-sm font-medium text-foreground">Notification Timing</div>
                  <div className="text-xs text-muted-foreground">How often notifications are sent</div>
                </div>
              </div>
              <div className="space-y-2 pt-1">
                {([
                  ["immediate", "Immediate", "Send each alert as it happens"],
                  ["daily_digest", "Daily Digest", "Batch into one daily summary"],
                  ["weekly_digest", "Weekly Digest", "Summary once a week"],
                ] as const).map(([val, label, desc]) => (
                  <button
                    key={val}
                    type="button"
                    onClick={() => canEdit && setSettings({ ...settings, digestFrequency: val })}
                    disabled={!canEdit}
                    className={cn(
                      "w-full flex items-center gap-3 rounded-lg p-3 border text-left transition-all",
                      settings.digestFrequency === val
                        ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
                        : "border-border bg-muted/10 hover:border-primary/30",
                      !canEdit && "cursor-default"
                    )}
                  >
                    <div className={cn(
                      "w-4 h-4 rounded-full border-2 flex items-center justify-center shrink-0",
                      settings.digestFrequency === val ? "border-primary" : "border-muted-foreground/40"
                    )}>
                      {settings.digestFrequency === val && <div className="w-2 h-2 rounded-full bg-primary" />}
                    </div>
                    <div>
                      <div className={cn("text-sm font-medium", settings.digestFrequency === val ? "text-foreground" : "text-muted-foreground")}>{label}</div>
                      <div className="text-xs text-muted-foreground">{desc}</div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Plan info */}
            <div className="bg-card border border-border rounded-xl p-5">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-[#10b981]/10 flex items-center justify-center shrink-0">
                  <Shield className="w-5 h-5 text-[#10b981]" />
                </div>
                <div>
                  <div className="text-sm font-medium text-foreground">Monitoring Frequency</div>
                  <div className="text-xs text-muted-foreground">
                    {monitoringFrequencyLabel(monitoringFrequency)} scans — {planLabel}
                  </div>
                </div>
                <span className="ml-auto px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase bg-primary/10 text-primary">
                  {planLabel}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Save button */}
        {canEdit && (
          <div className="flex justify-end pt-8">
            <Button onClick={handleSave} disabled={saving} className="bg-primary hover:bg-primary/90">
              {saving ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Saving...</> : "Save Settings"}
            </Button>
          </div>
        )}
      </div>

      <PlanLimitDialog {...planLimit} />
    </main>
  );
}