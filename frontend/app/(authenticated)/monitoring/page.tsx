"use client";

import React, { useEffect, useMemo, useState, useCallback, useRef } from "react";
import Link from "next/link";
import {
  Eye, Plus, Search, RefreshCcw, Trash2, Shield, ShieldAlert, Pencil,
  BellRing, Settings, SlidersHorizontal, Clock, CheckCircle2,
  Globe, Lock, Server, FileCode, Zap, ToggleLeft, ToggleRight, Pause,
  X, Loader2, Target, Cpu, Calendar, ArrowUpDown, AlertCircle, Sparkles,
  ExternalLink,
} from "lucide-react";

import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../ui/dialog";
import { SeverityBadge } from "../../SeverityBadge";
import { useOrg } from "../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../ui/plan-limit-dialog";
import { isPlanError } from "../../lib/api";
import { friendlyScannerName } from "../../lib/scanner-labels";
import { getAllAssets, explainAlert } from "../../lib/api";
import { BILLING_ENABLED } from "../../lib/billing-config";
import { NanoAiBar, NanoAiPanel, type AiState } from "../../FindingDetailsDialog";
import {
  cn, timeAgo, formatWhen, monitoringFrequencyLabel,
  alertStatusBadge, MONITOR_TYPE_CONFIG, SEVERITY_ORDER,
  getMonitors, createMonitor, updateMonitor, deleteMonitor,
  getMonitorAlerts, acknowledgeAlert, resolveAlert,
  getGroups, getGroupAssets,
} from "./_lib";
import type { Monitor, MonitorAlert } from "./_lib";

// Source-specific label/style for non-monitor alerts (lookup_tool, finding, manual).
// Returns null for the default "monitor" source — badge is suppressed.
function sourceBadge(source?: string): { label: string; className: string } | null {
  switch (source) {
    case "lookup_tool":
      return { label: "Lookup Tool", className: "bg-[#00b8d4]/10 text-[#00b8d4] border-[#00b8d4]/30" };
    case "finding":
      return { label: "Escalated", className: "bg-amber-500/10 text-amber-400 border-amber-500/30" };
    case "manual":
      return { label: "Manual", className: "bg-muted/30 text-muted-foreground border-border" };
    default:
      return null;
  }
}

// Translate a backend tool/source ID to a customer-friendly label.
// Delegates to the shared scanner-labels mapper so we never leak
// third-party scanner names ("shodan", "nuclei", etc.) into the UI.
function prettySourceTool(toolId?: string): string {
  if (!toolId) return "";
  return friendlyScannerName(toolId);
}

// Icon lookup for monitor type badges
const ICON_MAP: Record<string, any> = {
  Shield, Globe, Lock, Server, FileCode, Cpu, ShieldAlert,
};

/* ================================================================
   UPGRADE PROMPT (shown when plan lacks monitoring)
   ================================================================ */

function UpgradePrompt() {
  const { refresh } = useOrg();
  const [starting, setStarting] = useState<string | null>(null);
  const [trialBanner, setTrialBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  // Trials are request-based across all paid plans — clicking "Request trial"
  // creates a typed contact_request the admin reviews from /admin/contact-requests.
  const plans = [
    { key: "starter",           label: "Starter",            price: "$19/mo",  freq: "Scans every 5 days", trialDays: 14, color: "#00b8d4", tags: ["DNS", "SSL", "Ports", "Headers"] },
    { key: "professional",      label: "Professional",       price: "$79/mo",  freq: "Scans every 2 days", trialDays: 21, color: "#7c5cfc", tags: ["Everything", "Webhooks", "Deep Discovery"] },
    { key: "enterprise_silver", label: "Enterprise Silver",  price: "$249/mo", freq: "Daily scans",        trialDays: 30, color: "#ff8800", tags: ["Everything", "Custom Profiles", "Priority"] },
    { key: "enterprise_gold",   label: "Enterprise Gold",    price: "Custom",  freq: "Real-time scans",    trialDays: 45, color: "#ffd700", tags: ["Unlimited", "SSO", "Dedicated Support"], needsApproval: true },
  ];

  async function handleStartTrial(planKey: string) {
    try {
      setStarting(planKey);
      const { apiFetch } = await import("../../lib/api");
      const res = await apiFetch<any>("/billing/start-trial", {
        method: "POST",
        body: JSON.stringify({ plan: planKey }),
      });
      // Trials are request-based now — no plan flip happens, the user just
      // gets confirmation that their request is queued for review.
      setTrialBanner({
        kind: "ok",
        text: res?.message || "Trial request submitted. We'll email you when it's approved.",
      });
    } catch (e: any) {
      setTrialBanner({ kind: "err", text: e?.message || "Failed to submit trial request." });
    } finally {
      setStarting(null);
    }
  }

  return (
    <div className="flex flex-col items-center justify-center py-20 px-8 text-center">
      <div className="w-20 h-20 rounded-2xl bg-primary/10 flex items-center justify-center mb-6">
        <Eye className="w-10 h-10 text-primary" />
      </div>
      <h2 className="text-2xl font-bold text-foreground mb-3">Continuous Monitoring</h2>
      <p className="text-muted-foreground max-w-lg mb-2">
        Get automated security scans with real-time alerts when something changes.
        Monitor your DNS records, SSL certificates, open ports, security headers, and more.
      </p>
      <p className="text-muted-foreground max-w-lg mb-8">
        Monitoring is available on Starter and above plans.
      </p>

      {trialBanner && (
        <div className={cn("mb-6 rounded-xl border px-4 py-3 text-sm max-w-2xl w-full",
          trialBanner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>
          {trialBanner.text}
        </div>
      )}

      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 max-w-4xl w-full mb-8">
        {plans.map((p: any) => (
          <div key={p.key} className="bg-card border rounded-xl p-5 flex flex-col" style={{ borderColor: `${p.color}30` }}>
            <div className="font-bold mb-1" style={{ color: p.color }}>{p.label}</div>
            {BILLING_ENABLED && <div className="text-xs text-muted-foreground mb-1">{p.price}</div>}
            <div className="text-sm text-muted-foreground mb-3">{p.freq}</div>
            <div className="flex flex-wrap gap-1.5 mb-5">
              {p.tags.map((t: string) => (
                <span key={t} className="px-2 py-0.5 rounded text-[10px] font-semibold" style={{ backgroundColor: `${p.color}15`, color: p.color }}>{t}</span>
              ))}
            </div>
            <div className="mt-auto space-y-2">
              {p.needsApproval ? (
                // Enterprise Gold — sales approval, route to contact form
                <>
                  <Link href="/?type=trial#contact" className="block">
                    <Button size="sm" className="w-full text-xs" variant="outline" style={{ borderColor: `${p.color}40`, color: p.color }}>
                      {BILLING_ENABLED ? "Contact Sales" : "Contact Us"}
                    </Button>
                  </Link>
                  {BILLING_ENABLED && <div className="text-[10px] text-muted-foreground text-center">Free trial with sales approval</div>}
                </>
              ) : BILLING_ENABLED ? (
                // All paid plans — request-based trial (creates a contact_request)
                <>
                  <Button
                    size="sm"
                    onClick={() => handleStartTrial(p.key)}
                    disabled={starting !== null}
                    className="w-full text-xs"
                    variant="outline"
                    style={{ borderColor: `${p.color}40`, color: p.color }}
                  >
                    {starting === p.key ? <Loader2 className="w-3 h-3 mr-1.5 animate-spin" /> : <Clock className="w-3 h-3 mr-1.5" />}
                    {starting === p.key ? "Submitting…" : "Request free trial"}
                  </Button>
                  <Link href="/settings/billing" className="block">
                    <Button size="sm" className="w-full text-xs" style={{ backgroundColor: `${p.color}20`, color: p.color, borderColor: `${p.color}40` }} variant="outline">
                      <Zap className="w-3 h-3 mr-1.5" />Upgrade to {p.label}
                    </Button>
                  </Link>
                </>
              ) : (
                <Link href="/settings/billing" className="block">
                  <Button size="sm" className="w-full text-xs" style={{ backgroundColor: `${p.color}20`, color: p.color, borderColor: `${p.color}40` }} variant="outline">
                    <Zap className="w-3 h-3 mr-1.5" />Switch to {p.label}
                  </Button>
                </Link>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ================================================================
   OVERVIEW TAB
   ================================================================ */

function OverviewTab({ monitors, loading, onRefresh, setBanner, monitoringFrequency, planLimit }: {
  monitors: Monitor[]; loading: boolean; onRefresh: () => void;
  setBanner: (b: { kind: "ok" | "err"; text: string } | null) => void;
  monitoringFrequency: string;
  planLimit: ReturnType<typeof usePlanLimit>;
}) {
  const { canDo } = useOrg();
  const canCreate = canDo("create_monitors");
  const canEdit = canDo("edit_monitors");
  const canDelete = canDo("delete_monitors");

  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [editingMonitor, setEditingMonitor] = useState<Monitor | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Monitor | null>(null);
  const [deleting, setDeleting] = useState(false);

  const stats = useMemo(() => ({
    total: monitors.length,
    active: monitors.filter((m) => m.enabled).length,
    paused: monitors.filter((m) => !m.enabled).length,
    openAlerts: monitors.reduce((sum, m) => sum + (m.openAlertCount || 0), 0),
  }), [monitors]);

  async function handleToggle(m: Monitor) {
    try {
      await updateMonitor(m.id, { enabled: !m.enabled });
      setBanner({ kind: "ok", text: `Monitor ${!m.enabled ? "enabled" : "paused"}.` });
      onRefresh();
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      setDeleting(true);
      await deleteMonitor(deleteTarget.id);
      setBanner({ kind: "ok", text: "Monitor deleted." });
      setDeleteTarget(null);
      onRefresh();
    } catch (e: any) {
      if (isPlanError(e)) { setDeleteTarget(null); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    } finally { setDeleting(false); }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
            <Eye className="w-5 h-5 text-primary" />Active Monitors
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            {monitoringFrequencyLabel(monitoringFrequency)} scans for opted-in assets.
          </p>
        </div>
        {canCreate && (
          <Button onClick={() => setIsCreateOpen(true)} className="bg-primary hover:bg-primary/90">
            <Plus className="w-4 h-4 mr-2" />Add Monitor
          </Button>
        )}
      </div>

      {/* Stats bar */}
      <div className="flex items-center gap-6 bg-card border border-border rounded-xl px-6 py-4">
        <div className="flex items-center gap-2">
          <span className="text-2xl font-bold text-foreground">{stats.total}</span>
          <span className="text-xs text-muted-foreground">Monitors</span>
        </div>
        <div className="w-px h-8 bg-border" />
        <div className="flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-[#10b981]" />
          <span className="text-2xl font-bold text-[#10b981]">{stats.active}</span>
          <span className="text-xs text-muted-foreground">Active</span>
        </div>
        <div className="w-px h-8 bg-border" />
        <div className="flex items-center gap-2">
          <Pause className="w-4 h-4 text-muted-foreground" />
          <span className="text-2xl font-bold text-muted-foreground">{stats.paused}</span>
          <span className="text-xs text-muted-foreground">Paused</span>
        </div>
        <div className="w-px h-8 bg-border" />
        <div className="flex items-center gap-2">
          <BellRing className="w-4 h-4 text-red-400" />
          <span className="text-2xl font-bold text-red-400">{stats.openAlerts}</span>
          <span className="text-xs text-muted-foreground">Open Alerts</span>
        </div>
      </div>

      {/* Monitors table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-muted-foreground text-sm flex items-center justify-center gap-2">
            <Loader2 className="w-4 h-4 animate-spin" />Loading monitors...
          </div>
        ) : monitors.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto mb-4">
              <Eye className="w-8 h-8 text-primary" />
            </div>
            <h3 className="text-foreground font-semibold mb-2">No monitors yet</h3>
            <p className="text-muted-foreground text-sm mb-6 max-w-md mx-auto">
              Add assets or groups to continuous monitoring. They must have at least one completed scan to establish a baseline.
            </p>
            {canCreate && (
              <Button onClick={() => setIsCreateOpen(true)} className="bg-primary hover:bg-primary/90">
                <Plus className="w-4 h-4 mr-2" />Add your first monitor
              </Button>
            )}
            {!canCreate && (
              <p className="text-sm text-muted-foreground">Ask an admin or owner to add monitors.</p>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-muted/30">
                <tr>
                  <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Status</th>
                  <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Target</th>
                  <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Monitoring</th>
                  <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Last Checked</th>
                  <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Next Check</th>
                  <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Alerts</th>
                  {(canEdit || canDelete) && <th className="text-right p-4 text-sm font-semibold text-muted-foreground">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {monitors.map((m) => (
                  <tr key={m.id} className={cn("hover:bg-accent/30 transition-colors", !m.enabled && "opacity-50")}>
                    <td className="p-4">
                      {canEdit ? (
                        <button type="button" onClick={() => handleToggle(m)} className="flex items-center gap-2">
                          {m.enabled ? <ToggleRight className="w-6 h-6 text-[#10b981]" /> : <ToggleLeft className="w-6 h-6 text-muted-foreground" />}
                          <span className={cn("text-xs font-semibold", m.enabled ? "text-[#10b981]" : "text-muted-foreground")}>
                            {m.enabled ? "Active" : "Paused"}
                          </span>
                        </button>
                      ) : (
                        <span className={cn("text-xs font-semibold", m.enabled ? "text-[#10b981]" : "text-muted-foreground")}>
                          {m.enabled ? "Active" : "Paused"}
                        </span>
                      )}
                    </td>
                    <td className="p-4">
                      <div className="flex flex-col gap-0.5">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm text-foreground">
                            {(m.groupId || m.group_id) ? (m.groupName || m.group_name || `Group #${m.groupId || m.group_id}`) : (m.assetValue || m.asset_value || `Asset #${m.assetId || m.asset_id}`)}
                          </span>
                          <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase",
                            m.groupId ? "bg-[#00b8d4]/10 text-[#00b8d4]" : "bg-primary/10 text-primary")}>
                            {m.groupId ? "Group" : "Asset"}
                          </span>
                        </div>
                        {!m.groupId && m.groupName && <span className="text-xs text-muted-foreground">{m.groupName}</span>}
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="flex flex-wrap gap-1">
                        {(m.monitorTypes || ["all"]).map((t) => {
                          const cfg = MONITOR_TYPE_CONFIG[t] || MONITOR_TYPE_CONFIG.all;
                          return (
                            <span key={t} className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border", cfg.bg, cfg.color, "border-current/20")}>
                              {cfg.label}
                            </span>
                          );
                        })}
                      </div>
                    </td>
                    <td className="p-4"><span className="text-sm text-muted-foreground">{timeAgo(m.lastCheckedAt)}</span></td>
                    <td className="p-4"><span className="text-sm text-muted-foreground">{m.enabled ? formatWhen(m.nextCheckAt) : "—"}</span></td>
                    <td className="p-4">
                      {(m.openAlertCount || 0) > 0 ? (
                        <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-semibold bg-red-500/10 text-red-400">
                          <BellRing className="w-3 h-3" />{m.openAlertCount}
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">None</span>
                      )}
                    </td>
                    {(canEdit || canDelete) && (
                      <td className="p-4">
                        <div className="flex items-center justify-end gap-2">
                          {canEdit && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => setEditingMonitor(m)}
                              className="border-border text-foreground hover:bg-accent"
                              title="Edit what to monitor on this entry"
                            >
                              <Pencil className="w-3 h-3" />
                            </Button>
                          )}
                          {canDelete && (
                            <Button size="sm" variant="outline" onClick={() => setDeleteTarget(m)}
                              className="border-red-500/50 text-red-500 hover:bg-red-500/10">
                              <Trash2 className="w-3 h-3" />
                            </Button>
                          )}
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create / Edit Monitor Dialog (same component, edit mode when
          `editingMonitor` is set — target is fixed in edit mode, only
          monitor types are mutable). */}
      <CreateMonitorDialog
        open={isCreateOpen}
        onOpenChange={setIsCreateOpen}
        monitoringFrequency={monitoringFrequency}
        setBanner={setBanner}
        onCreated={onRefresh}
        planLimit={planLimit}
      />
      <CreateMonitorDialog
        open={!!editingMonitor}
        onOpenChange={(o) => { if (!o) setEditingMonitor(null); }}
        monitoringFrequency={monitoringFrequency}
        setBanner={setBanner}
        onCreated={() => { setEditingMonitor(null); onRefresh(); }}
        planLimit={planLimit}
        editingMonitor={editingMonitor}
      />

      {/* Delete Confirmation */}
      <Dialog open={!!deleteTarget} onOpenChange={(o) => { if (!o) setDeleteTarget(null); }}>
        <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
          <DialogHeader><DialogTitle>Remove Monitor</DialogTitle></DialogHeader>
          <p className="text-sm text-muted-foreground">
            Stop monitoring <span className="font-mono text-foreground">
              {(deleteTarget?.groupId || deleteTarget?.group_id) ? (deleteTarget?.groupName || deleteTarget?.group_name || "this group") : (deleteTarget?.assetValue || deleteTarget?.asset_value || "this asset")}
            </span>? Existing alerts will be kept. You can re-add it later.
          </p>
          <div className="flex gap-3 justify-end pt-4">
            <Button variant="outline" onClick={() => setDeleteTarget(null)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
            <Button onClick={handleDelete} disabled={deleting} className="bg-[#ef4444] hover:bg-[#dc2626] text-white">
              {deleting ? "Removing..." : "Remove Monitor"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

/* ================================================================
   CREATE MONITOR DIALOG
   ================================================================ */

function CreateMonitorDialog({ open, onOpenChange, monitoringFrequency, setBanner, onCreated, planLimit, editingMonitor }: {
  open: boolean; onOpenChange: (v: boolean) => void; monitoringFrequency: string;
  setBanner: (b: { kind: "ok" | "err"; text: string } | null) => void;
  onCreated: () => void;
  planLimit: ReturnType<typeof usePlanLimit>;
  /** When set, the dialog operates in edit mode — target is fixed
      (read-only) and only `monitorTypes` is mutable. */
  editingMonitor?: Monitor | null;
}) {
  const isEdit = !!editingMonitor;
  const [targetType, setTargetType] = useState<"asset" | "group">("asset");
  const [groups, setGroups] = useState<Array<{ id: any; name: string }>>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [selGroupId, setSelGroupId] = useState("");
  const [selAssetId, setSelAssetId] = useState("");
  const [monitorTypes, setMonitorTypes] = useState<string[]>(["all"]);
  const [creating, setCreating] = useState(false);

  // When opening in edit mode, hydrate the form from the monitor.
  // Avoid running this in create mode, which would clobber user input.
  useEffect(() => {
    if (!open) return;
    if (editingMonitor) {
      setMonitorTypes(editingMonitor.monitorTypes && editingMonitor.monitorTypes.length > 0 ? editingMonitor.monitorTypes : ["all"]);
      const isGroup = !!(editingMonitor.groupId || editingMonitor.group_id);
      setTargetType(isGroup ? "group" : "asset");
    } else {
      // Fresh open in create mode — reset to defaults.
      setMonitorTypes(["all"]);
      setSelGroupId("");
      setSelAssetId("");
      setTargetType("asset");
    }
  }, [open, editingMonitor]);

  useEffect(() => { if (open) getGroups().then((gs) => setGroups(gs.map((g) => ({ id: g.id, name: g.name })))).catch(() => {}); }, [open]);

  useEffect(() => {
    if (!selGroupId || targetType !== "asset") { setAssets([]); setSelAssetId(""); return; }
    let c = false; setLoadingAssets(true);
    getGroupAssets(selGroupId).then((a) => { if (!c) { setAssets(a || []); setSelAssetId(""); } }).catch(() => { if (!c) setAssets([]); }).finally(() => { if (!c) setLoadingAssets(false); });
    return () => { c = true; };
  }, [selGroupId, targetType]);

  function toggleMonitorType(t: string) {
    if (t === "all") { setMonitorTypes(["all"]); return; }
    const next = monitorTypes.filter((x) => x !== "all");
    if (next.includes(t)) {
      const filtered = next.filter((x) => x !== t);
      setMonitorTypes(filtered.length === 0 ? ["all"] : filtered);
    } else {
      setMonitorTypes([...next, t]);
    }
  }

  async function handleCreate() {
    // ── Edit mode: only monitor types are mutable ──
    if (isEdit && editingMonitor) {
      try {
        setCreating(true);
        await updateMonitor(editingMonitor.id, { monitorTypes });
        setBanner({ kind: "ok", text: "Monitor updated." });
        onOpenChange(false);
        onCreated();
      } catch (e: any) {
        if (isPlanError(e)) { onOpenChange(false); planLimit.handle(e.planError); }
        else setBanner({ kind: "err", text: e?.message || "Failed." });
      } finally { setCreating(false); }
      return;
    }

    // ── Create mode ──
    if (targetType === "asset" && !selAssetId) { setBanner({ kind: "err", text: "Select an asset." }); return; }
    if (targetType === "group" && !selGroupId) { setBanner({ kind: "err", text: "Select a group." }); return; }
    try {
      setCreating(true);
      await createMonitor({
        targetType,
        assetId: targetType === "asset" ? selAssetId : undefined,
        groupId: targetType === "group" ? selGroupId : selGroupId || undefined,
        monitorTypes,
        frequency: monitoringFrequency,
      });
      setBanner({ kind: "ok", text: "Monitor created. Baseline scan will be used for change detection." });
      onOpenChange(false);
      onCreated();
      setSelAssetId(""); setSelGroupId(""); setMonitorTypes(["all"]);
    } catch (e: any) {
      if (isPlanError(e)) { onOpenChange(false); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    } finally { setCreating(false); }
  }

  const allTypes = Object.entries(MONITOR_TYPE_CONFIG);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border text-foreground sm:max-w-[540px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {isEdit
              ? <><Pencil className="w-5 h-5 text-primary" />Edit Monitor</>
              : <><Plus className="w-5 h-5 text-primary" />Add Monitor</>}
          </DialogTitle>
        </DialogHeader>
        <p className="text-sm text-muted-foreground -mt-2">
          {isEdit
            ? "Adjust what's monitored on this entry. The target itself can't be changed — remove and re-add to switch targets."
            : "Assets must have at least one completed scan to establish a baseline."}
        </p>
        <div className="space-y-4 pt-2">
          {/* Read-only target summary in edit mode */}
          {isEdit && editingMonitor && (
            <div className="rounded-lg border border-border bg-muted/20 px-4 py-3">
              <div className="text-[11px] uppercase tracking-wide text-muted-foreground mb-1">
                {(editingMonitor.groupId || editingMonitor.group_id) ? "Group" : "Asset"}
              </div>
              <div className="font-mono text-sm text-foreground">
                {(editingMonitor.groupId || editingMonitor.group_id)
                  ? (editingMonitor.groupName || editingMonitor.group_name || `Group #${editingMonitor.groupId || editingMonitor.group_id}`)
                  : (editingMonitor.assetValue || editingMonitor.asset_value || `Asset #${editingMonitor.assetId || editingMonitor.asset_id}`)}
              </div>
            </div>
          )}

          {/* Target type + selector — create mode only. Edit mode
              shows the read-only target summary above instead. */}
          {!isEdit && (
          <>
          <div className="space-y-1.5">
            <label className="text-sm font-medium text-foreground block">Monitor Target</label>
            <div className="grid grid-cols-2 gap-3">
              <button type="button" onClick={() => { setTargetType("asset"); setSelGroupId(""); setSelAssetId(""); }}
                className={cn("rounded-xl p-4 border text-left transition-all",
                  targetType === "asset" ? "border-primary/50 bg-primary/10 ring-1 ring-primary/30" : "border-border bg-muted/20 hover:border-primary/30")}>
                <div className="flex items-center gap-2 mb-1">
                  <Target className={cn("w-4 h-4", targetType === "asset" ? "text-primary" : "text-muted-foreground")} />
                  <span className={cn("text-sm font-semibold", targetType === "asset" ? "text-foreground" : "text-muted-foreground")}>Single Asset</span>
                </div>
                <p className="text-xs text-muted-foreground">Monitor one specific asset</p>
              </button>
              <button type="button" onClick={() => { setTargetType("group"); setSelAssetId(""); }}
                className={cn("rounded-xl p-4 border text-left transition-all",
                  targetType === "group" ? "border-[#00b8d4]/50 bg-[#00b8d4]/10 ring-1 ring-[#00b8d4]/30" : "border-border bg-muted/20 hover:border-[#00b8d4]/30")}>
                <div className="flex items-center gap-2 mb-1">
                  <Shield className={cn("w-4 h-4", targetType === "group" ? "text-[#00b8d4]" : "text-muted-foreground")} />
                  <span className={cn("text-sm font-semibold", targetType === "group" ? "text-foreground" : "text-muted-foreground")}>Asset Group</span>
                </div>
                <p className="text-xs text-muted-foreground">Monitor all assets in a group</p>
              </button>
            </div>
          </div>

          {/* Group / Asset selector */}
          {targetType === "asset" ? (
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-foreground block">Group</label>
                <select value={selGroupId} onChange={(e) => setSelGroupId(e.target.value)}
                  className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                  <option value="">Select group...</option>
                  {groups.map((g) => <option key={String(g.id)} value={String(g.id)}>{g.name}</option>)}
                </select>
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-foreground block">Asset</label>
                <select value={selAssetId} onChange={(e) => setSelAssetId(e.target.value)} disabled={!selGroupId || loadingAssets}
                  className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50">
                  <option value="">{loadingAssets ? "Loading..." : "Select asset..."}</option>
                  {assets.map((a: any) => <option key={String(a.id)} value={String(a.id)}>{a.value}</option>)}
                </select>
              </div>
            </div>
          ) : (
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-foreground block">Asset Group</label>
              <select value={selGroupId} onChange={(e) => setSelGroupId(e.target.value)}
                className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                <option value="">Select group...</option>
                {groups.map((g) => <option key={String(g.id)} value={String(g.id)}>{g.name}</option>)}
              </select>
            </div>
          )}
          </>
          )}

          {/* Monitor types */}
          <div className="space-y-1.5">
            <label className="text-sm font-medium text-foreground block">What to monitor</label>
            <div className="flex flex-wrap gap-2">
              {allTypes.map(([key, cfg]) => {
                const selected = monitorTypes.includes(key) || (key !== "all" && monitorTypes.includes("all"));
                const isAll = key === "all";
                return (
                  <button key={key} type="button" onClick={() => toggleMonitorType(key)}
                    className={cn("inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all",
                      selected ? cn(cfg.bg, cfg.color, "border-current/30") : "bg-muted/20 text-muted-foreground border-border hover:border-primary/30")}>
                    {cfg.label}
                    {selected && !isAll && !monitorTypes.includes("all") && <X className="w-3 h-3 ml-0.5 opacity-60" />}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Frequency info */}
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-muted/30 border border-border text-xs text-muted-foreground">
            <Clock className="w-3.5 h-3.5" />
            {monitoringFrequencyLabel(monitoringFrequency)} scans — based on your plan
          </div>

          {/* Actions */}
          <div className="flex gap-3 justify-end pt-2">
            <Button variant="outline" onClick={() => onOpenChange(false)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
            <Button
              onClick={handleCreate}
              disabled={creating || (!isEdit && (targetType === "asset" ? !selAssetId : !selGroupId)) || monitorTypes.length === 0}
              className="bg-primary hover:bg-primary/90"
            >
              {isEdit
                ? <><Pencil className="w-4 h-4 mr-2" />{creating ? "Saving…" : "Save changes"}</>
                : <><Eye className="w-4 h-4 mr-2" />{creating ? "Creating..." : "Start Monitoring"}</>}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/* ================================================================
   ALERTS TAB
   ================================================================ */

function AlertsTab({ setBanner, planLimit }: {
  setBanner: (b: { kind: "ok" | "err"; text: string } | null) => void;
  planLimit: ReturnType<typeof usePlanLimit>;
}) {
  const { canDo } = useOrg();
  const canAcknowledge = canDo("acknowledge_alerts");
  const canClose = canDo("close_alerts");

  const [alerts, setAlerts] = useState<MonitorAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchFilter, setSearchFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "open" | "acknowledged" | "resolved">("all");
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [sortOrder, setSortOrder] = useState<"desc" | "asc">("desc");

  // ── Selected alert for split-pane detail panel ──
  const [selected, setSelected] = useState<MonitorAlert | null>(null);

  // ── Resizable detail panel (lg+) — same pattern as findings page ──
  const PANEL_MIN = 30;
  const PANEL_MAX = 70;
  const PANEL_DEFAULT = 45;
  const [panelWidth, setPanelWidth] = useState<number>(() => {
    if (typeof window === "undefined") return PANEL_DEFAULT;
    const saved = parseFloat(localStorage.getItem("alerts-panel-width") || "");
    if (Number.isFinite(saved)) {
      return Math.max(PANEL_MIN, Math.min(PANEL_MAX, saved));
    }
    return PANEL_DEFAULT;
  });
  const splitContainerRef = useRef<HTMLDivElement>(null);
  const draggingRef = useRef(false);

  function startResize(e: React.MouseEvent) {
    e.preventDefault();
    draggingRef.current = true;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  }

  useEffect(() => {
    function onMove(e: MouseEvent) {
      if (!draggingRef.current || !splitContainerRef.current) return;
      const rect = splitContainerRef.current.getBoundingClientRect();
      const next = ((rect.right - e.clientX) / rect.width) * 100;
      const clamped = Math.max(PANEL_MIN, Math.min(PANEL_MAX, next));
      setPanelWidth(clamped);
    }
    function onUp() {
      if (!draggingRef.current) return;
      draggingRef.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      try { localStorage.setItem("alerts-panel-width", String(panelWidth)); } catch {}
    }
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [panelWidth]);

  // ── Nano EASM Assistant state for the selected alert ──
  const [aiState, setAiState] = useState<AiState>({
    loading: false, explanation: null, error: null, visible: false,
  });
  const selectedId = selected ? String(selected.id) : null;
  useEffect(() => {
    setAiState({ loading: false, explanation: null, error: null, visible: false });
  }, [selectedId]);

  async function loadAiExplanation(alertId: string) {
    if (aiState.explanation && !aiState.error) {
      setAiState((s) => ({ ...s, visible: !s.visible }));
      return;
    }
    setAiState({ loading: true, explanation: null, error: null, visible: true });
    try {
      const res = await explainAlert(alertId);
      setAiState({ loading: false, explanation: res.explanation, error: null, visible: true });
    } catch (e: any) {
      setAiState({
        loading: false,
        explanation: null,
        error: e?.message || "Could not generate an explanation right now.",
        visible: true,
      });
    }
  }

  const load = useCallback(async () => {
    try { setLoading(true); setAlerts(await getMonitorAlerts()); } catch {} finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  // Keep the selected alert in sync with the latest alerts list (e.g. after
  // acknowledge/resolve) so the detail panel updates without losing focus.
  useEffect(() => {
    if (!selected) return;
    const fresh = alerts.find((a) => a.id === selected.id);
    if (fresh && fresh !== selected) setSelected(fresh);
  }, [alerts, selected]);

  async function handleAcknowledge(alert: MonitorAlert) {
    try {
      await acknowledgeAlert(alert.id);
      setBanner({ kind: "ok", text: "Alert acknowledged." });
      load();
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    }
  }

  async function handleResolve(alert: MonitorAlert) {
    try {
      await resolveAlert(alert.id);
      setBanner({ kind: "ok", text: "Alert resolved." });
      load();
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    }
  }

  const filtered = useMemo(() => {
    let result = alerts;
    if (statusFilter !== "all") result = result.filter((a) => a.status === statusFilter);
    if (sevFilter !== "all") result = result.filter((a) => a.severity === sevFilter);
    if (dateFrom) {
      const fromTs = new Date(dateFrom).getTime();
      if (!Number.isNaN(fromTs)) result = result.filter((a) => new Date(a.createdAt as any).getTime() >= fromTs);
    }
    if (dateTo) {
      // include the entire "to" day (add 24h)
      const toTs = new Date(dateTo).getTime() + 86_400_000;
      if (!Number.isNaN(toTs)) result = result.filter((a) => new Date(a.createdAt as any).getTime() < toTs);
    }
    if (searchFilter.trim()) {
      const q = searchFilter.toLowerCase();
      result = result.filter((a) =>
        (a.title || "").toLowerCase().includes(q) ||
        (a.assetValue || "").toLowerCase().includes(q) ||
        (a.alertName || "").toLowerCase().includes(q)
      );
    }
    return [...result].sort((a, b) => {
      const ta = new Date(a.createdAt as any).getTime() || 0;
      const tb = new Date(b.createdAt as any).getTime() || 0;
      return sortOrder === "desc" ? tb - ta : ta - tb;
    });
  }, [alerts, statusFilter, sevFilter, searchFilter, dateFrom, dateTo, sortOrder]);

  const statusCounts = useMemo(() => ({
    open: alerts.filter((a) => a.status === "open").length,
    acknowledged: alerts.filter((a) => a.status === "acknowledged").length,
    resolved: alerts.filter((a) => a.status === "resolved").length,
  }), [alerts]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
          <BellRing className="w-5 h-5 text-primary" />Monitoring Alerts
        </h2>
        <Button variant="ghost" size="sm" onClick={load} className="text-primary hover:bg-primary/10">
          <RefreshCcw className="w-4 h-4 mr-2" />Refresh
        </Button>
      </div>

      {/* Integrations CTA — surfaces the route to /settings/integrations
          so users on the Alerts tab can find Slack / Jira / webhooks
          without having to discover the Settings menu. */}
      <Link
        href="/settings/integrations"
        className="group flex items-center gap-3 rounded-lg border border-border bg-card/40 hover:border-primary/30 hover:bg-card/70 transition-colors px-4 py-3"
      >
        <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
          <BellRing className="w-4 h-4 text-primary" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-foreground">
            Get alerts in Slack, Jira, or a webhook
          </div>
          <div className="text-xs text-muted-foreground">
            Alerts are saved here in-app. Connect a destination so your team gets notified outside Nano EASM.
          </div>
        </div>
        <span className="text-xs text-primary group-hover:translate-x-0.5 transition-transform shrink-0">
          Manage destinations →
        </span>
      </Link>

      {/* Filter bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input placeholder="Search alerts..." value={searchFilter} onChange={(e) => setSearchFilter(e.target.value)} className="pl-9" />
        </div>
        {(["all", "open", "acknowledged", "resolved"] as const).map((s) => (
          <button key={s} type="button" onClick={() => setStatusFilter(s)}
            className={cn("px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all",
              statusFilter === s ? "bg-primary/10 text-primary border-primary/30" : "bg-muted/20 text-muted-foreground border-border hover:border-primary/30")}>
            {s === "all" ? `All (${alerts.length})` : `${s.charAt(0).toUpperCase() + s.slice(1)} (${statusCounts[s]})`}
          </button>
        ))}
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}
          className="h-8 rounded-md px-2 bg-input-background border border-border text-foreground text-xs focus:outline-none focus:ring-2 focus:ring-ring">
          <option value="all">All Severities</option>
          {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
        </select>
      </div>

      {/* Date range + sort */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Calendar className="w-3.5 h-3.5" />
          <span>From</span>
          <input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)}
            className="h-8 rounded-md px-2 bg-input-background border border-border text-foreground text-xs focus:outline-none focus:ring-2 focus:ring-ring" />
          <span>To</span>
          <input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)}
            className="h-8 rounded-md px-2 bg-input-background border border-border text-foreground text-xs focus:outline-none focus:ring-2 focus:ring-ring" />
          {(dateFrom || dateTo) && (
            <button type="button" onClick={() => { setDateFrom(""); setDateTo(""); }}
              className="text-xs text-muted-foreground hover:text-foreground underline underline-offset-2">
              Clear
            </button>
          )}
        </div>
        <button type="button" onClick={() => setSortOrder(sortOrder === "desc" ? "asc" : "desc")}
          className="ml-auto inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-border bg-muted/20 text-muted-foreground hover:border-primary/30 hover:text-foreground transition-all">
          <ArrowUpDown className="w-3 h-3" />
          {sortOrder === "desc" ? "Newest first" : "Oldest first"}
        </button>
      </div>

      {/* ── Alerts list + detail panel (resizable split-pane on lg+) ── */}
      <div ref={splitContainerRef} className="flex flex-col lg:flex-row gap-4 lg:gap-0 items-start">

        {/* Left: alerts list */}
        <div className="w-full min-w-0 flex-1">
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            {loading ? (
              <div className="p-8 text-center text-muted-foreground text-sm flex items-center justify-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin" />Loading alerts...
              </div>
            ) : filtered.length === 0 ? (
              <div className="p-12 text-center">
                <div className="w-16 h-16 rounded-2xl bg-[#10b981]/10 flex items-center justify-center mx-auto mb-4">
                  <CheckCircle2 className="w-8 h-8 text-[#10b981]" />
                </div>
                <h3 className="text-foreground font-semibold mb-2">
                  {alerts.length === 0 ? "No alerts yet" : "No matching alerts"}
                </h3>
                <p className="text-muted-foreground text-sm max-w-md mx-auto">
                  {alerts.length === 0
                    ? "When monitors detect changes — new findings, resolved issues, or severity shifts — alerts will appear here."
                    : "Try adjusting your filters."}
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-muted/30 border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide w-[110px]">Time</th>
                      <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide w-[90px]">Severity</th>
                      <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Alert</th>
                      <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide w-[180px]">Asset</th>
                      <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide w-[100px]">Source</th>
                      <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide w-[100px]">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {filtered.map((alert) => {
                      const isSelected = selected?.id === alert.id;
                      const sb = sourceBadge(alert.source);
                      return (
                        <tr
                          key={alert.id}
                          onClick={() => setSelected(alert)}
                          className={cn(
                            "cursor-pointer transition-colors",
                            isSelected ? "bg-primary/5" : "hover:bg-accent/20",
                          )}
                        >
                          {/* Time */}
                          <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap" title={formatWhen(alert.createdAt)}>
                            {timeAgo(alert.createdAt)}
                          </td>

                          {/* Severity */}
                          <td className="px-4 py-3">
                            <SeverityBadge severity={alert.severity} />
                          </td>

                          {/* Alert (title + alert name as subtext) */}
                          <td className="px-4 py-3 max-w-0">
                            <div className="flex items-center gap-2 min-w-0">
                              {isSelected && <span className="w-1 h-4 bg-primary rounded-full shrink-0" />}
                              <div className="min-w-0">
                                <div className="text-sm font-medium text-foreground truncate" title={alert.title}>
                                  {alert.title}
                                </div>
                                {alert.alertName && alert.alertName !== alert.title && (
                                  <div className="text-[11px] text-muted-foreground truncate" title={alert.alertName}>
                                    {alert.alertName}
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>

                          {/* Asset */}
                          <td className="px-4 py-3">
                            <div className="min-w-0">
                              <div className="text-xs font-mono text-foreground/90 truncate" title={alert.assetValue || ""}>
                                {alert.assetValue || "—"}
                              </div>
                              {alert.groupName && (
                                <div className="text-[11px] text-muted-foreground truncate" title={alert.groupName}>
                                  {alert.groupName}
                                </div>
                              )}
                            </div>
                          </td>

                          {/* Source */}
                          <td className="px-4 py-3">
                            {sb ? (
                              <span className={cn("px-2 py-0.5 rounded text-[10px] font-semibold border whitespace-nowrap", sb.className)}>
                                {sb.label}
                              </span>
                            ) : (
                              <span className="text-[10px] text-muted-foreground">Monitor</span>
                            )}
                          </td>

                          {/* Status */}
                          <td className="px-4 py-3">
                            <span className={cn("px-2 py-0.5 rounded text-[10px] font-semibold border whitespace-nowrap", alertStatusBadge(alert.status))}>
                              {alert.status}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Drag handle — only when an alert is selected, only on lg+ */}
        {selected && (
          <div
            role="separator"
            aria-orientation="vertical"
            aria-label="Resize details panel"
            onMouseDown={startResize}
            className="hidden lg:flex shrink-0 self-stretch w-2 mx-1 cursor-col-resize group sticky top-4 lg:h-[calc(100vh-2rem)] items-center justify-center"
          >
            <div className="w-px h-12 bg-border group-hover:bg-primary/60 group-active:bg-primary transition-colors" />
          </div>
        )}

        {/* Right: alert details panel */}
        {selected && (
          <aside
            className="w-full shrink-0 lg:sticky lg:top-4 lg:self-start lg:h-[calc(100vh-2rem)] flex lg:w-[var(--panel-w)]"
            style={{ "--panel-w": `${panelWidth}%` } as React.CSSProperties}
          >
            <AlertDetailsPanel
              alert={selected}
              onClose={() => setSelected(null)}
              canAcknowledge={canAcknowledge}
              canClose={canClose}
              onAcknowledge={() => handleAcknowledge(selected)}
              onResolve={() => handleResolve(selected)}
              aiState={aiState}
              onLoadAi={() => loadAiExplanation(String(selected.id))}
              onRegenerateAi={() => {
                setAiState({ loading: false, explanation: null, error: null, visible: true });
                loadAiExplanation(String(selected.id));
              }}
              onHideAi={() => setAiState((s) => ({ ...s, visible: false }))}
            />
          </aside>
        )}
      </div>
    </div>
  );
}

/* ================================================================
   ALERT DETAILS PANEL
   ================================================================ */

function AlertDetailsPanel({
  alert,
  onClose,
  canAcknowledge,
  canClose,
  onAcknowledge,
  onResolve,
  aiState,
  onLoadAi,
  onRegenerateAi,
  onHideAi,
}: {
  alert: MonitorAlert;
  onClose: () => void;
  canAcknowledge: boolean;
  canClose: boolean;
  onAcknowledge: () => void;
  onResolve: () => void;
  aiState: AiState;
  onLoadAi: () => void;
  onRegenerateAi: () => void;
  onHideAi: () => void;
}) {
  const sb = sourceBadge(alert.source);

  return (
    <div className="bg-card border border-border rounded-xl flex flex-col h-full overflow-hidden w-full">
      {/* Header */}
      <div className="sticky top-0 z-10 bg-card border-b border-border pl-6 pr-6 pt-6 pb-4">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h2 className="text-xl font-semibold leading-snug text-foreground">{alert.title}</h2>

            <div className="mt-2.5 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <span className={cn("px-2 py-0.5 rounded text-[10px] font-semibold border", alertStatusBadge(alert.status))}>
                {alert.status}
              </span>
              {sb && (
                <span className={cn("px-2 py-0.5 rounded text-[10px] font-semibold border", sb.className)}>
                  {sb.label}
                </span>
              )}
              <span className="text-xs text-muted-foreground" title={formatWhen(alert.createdAt)}>
                {timeAgo(alert.createdAt)} · {formatWhen(alert.createdAt)}
              </span>
            </div>
          </div>

          <div className="shrink-0 flex items-center gap-2 flex-wrap">
            {canAcknowledge && alert.status === "open" && (
              <Button size="sm" variant="outline" onClick={onAcknowledge}
                className="border-[#ffcc00]/50 text-[#ffcc00] hover:bg-[#ffcc00]/10 text-xs">
                Acknowledge
              </Button>
            )}
            {canClose && (alert.status === "open" || alert.status === "acknowledged") && (
              <Button size="sm" variant="outline" onClick={onResolve}
                className="border-[#10b981]/50 text-[#10b981] hover:bg-[#10b981]/10 text-xs">
                Resolve
              </Button>
            )}
            <button
              type="button"
              onClick={onClose}
              aria-label="Close panel"
              className="p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent/30 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">

        {/* Alert metadata */}
        <div className="bg-card border border-border rounded-lg p-4">
          <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-3">Alert details</div>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2.5 text-sm">
            {alert.assetValue && (
              <>
                <dt className="text-xs text-muted-foreground">Asset</dt>
                <dd className="font-mono text-foreground">{alert.assetValue}</dd>
              </>
            )}
            {alert.groupName && (
              <>
                <dt className="text-xs text-muted-foreground">Group</dt>
                <dd className="text-foreground">{alert.groupName}</dd>
              </>
            )}
            {alert.alertName && (
              <>
                <dt className="text-xs text-muted-foreground">Alert</dt>
                <dd className="text-foreground">{alert.alertName}</dd>
              </>
            )}
            {alert.alertType && (
              <>
                <dt className="text-xs text-muted-foreground">Type</dt>
                <dd className="text-foreground">{alert.alertType.replace(/_/g, " ")}</dd>
              </>
            )}
            {alert.source === "lookup_tool" && alert.sourceTool && (
              <>
                <dt className="text-xs text-muted-foreground">From</dt>
                <dd className="text-foreground">
                  {prettySourceTool(alert.sourceTool)}
                  {alert.sourceTarget && <span className="text-muted-foreground"> · {alert.sourceTarget}</span>}
                </dd>
              </>
            )}
            {alert.source === "finding" && alert.findingId && (
              <>
                <dt className="text-xs text-muted-foreground">Finding</dt>
                <dd className="text-foreground">
                  <Link href={`/findings?selected=${alert.findingId}`} className="text-primary hover:underline inline-flex items-center gap-1">
                    Finding #{alert.findingId}
                    <ExternalLink className="w-3 h-3" />
                  </Link>
                </dd>
              </>
            )}
            {alert.acknowledgedAt && (
              <>
                <dt className="text-xs text-muted-foreground">Acknowledged</dt>
                <dd className="text-foreground">{formatWhen(alert.acknowledgedAt)}</dd>
              </>
            )}
            {alert.resolvedAt && (
              <>
                <dt className="text-xs text-muted-foreground">Resolved</dt>
                <dd className="text-foreground">{formatWhen(alert.resolvedAt)}</dd>
              </>
            )}
            {alert.notifiedVia && alert.notifiedVia.length > 0 && (
              <>
                <dt className="text-xs text-muted-foreground">Notified via</dt>
                <dd className="text-foreground">{alert.notifiedVia.join(", ")}</dd>
              </>
            )}
          </dl>
        </div>

        {/* Reported summary (analyst-curated text from the alert row) */}
        {alert.summary && (
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">Summary</div>
            <pre className="whitespace-pre-wrap break-words font-sans text-sm text-foreground/85 leading-relaxed">
              {alert.summary}
            </pre>
          </div>
        )}

        {/* Nano EASM Assistant */}
        <NanoAiBar state={aiState} onLoad={onLoadAi} />
        <NanoAiPanel state={aiState} onRegenerate={onRegenerateAi} onHide={onHideAi} />
      </div>
    </div>
  );
}

/* ================================================================
   MAIN PAGE — Overview + Alerts tabs, uses useOrg()
   ================================================================ */

type TabKey = "alerts" | "overview";

export default function MonitoringPage() {
  const [activeTab, setActiveTab] = useState<TabKey>("alerts");
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [monitors, setMonitors] = useState<Monitor[]>([]);
  const [loadingMonitors, setLoadingMonitors] = useState(true);
  const [showEndTrial, setShowEndTrial] = useState(false);
  const [endingTrial, setEndingTrial] = useState(false);

  const { plan, planLabel, hasFeature, billing, isTrialing, trialDaysRemaining, refresh } = useOrg();
  const planLimit = usePlanLimit();
  const hasMonitoring = hasFeature("monitoring");
  const monitoringFrequency = billing?.limits?.monitoringFrequency || "every_2_days";

  const loadMonitors = useCallback(async () => {
    try {
      setLoadingMonitors(true);
      const [rawMonitors, grps, allAssets] = await Promise.all([getMonitors(), getGroups(), getAllAssets().catch(() => [])]);
      const groupMap = new Map(grps.map((g) => [String(g.id), g.name]));
      const assetMap = new Map((allAssets || []).map((a: any) => [String(a.id), a.value || a.name || a.domain]));
      const enriched = rawMonitors.map((m: any) => {
        const mAssetId = String(m.assetId ?? m.asset_id ?? "");
        const mGroupId = String(m.groupId ?? m.group_id ?? "");
        return {
          ...m,
          groupName: m.groupName || m.group_name || (mGroupId ? groupMap.get(mGroupId) : undefined),
          assetValue: m.assetValue || m.asset_value || (mAssetId ? assetMap.get(mAssetId) : undefined),
        };
      });
      setMonitors(enriched);
    }
    catch {}
    finally { setLoadingMonitors(false); }
  }, []);

  async function handleEndTrial() {
    try {
      setEndingTrial(true);
      const { apiFetch } = await import("../../lib/api");
      await apiFetch<any>("/billing/cancel", { method: "POST" });
      await refresh();
      setShowEndTrial(false);
      setBanner({ kind: "ok", text: "Trial ended. You've been moved back to the Free plan." });
      setTimeout(() => window.location.reload(), 1500);
    } catch (e: any) {
      if (isPlanError(e)) { setShowEndTrial(false); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed to end trial." });
    } finally {
      setEndingTrial(false);
    }
  }

  useEffect(() => {
    if (hasMonitoring) { loadMonitors(); } else { setLoadingMonitors(false); }
  }, [loadMonitors, hasMonitoring]);

  useEffect(() => {
    if (!banner) return;
    const t = setTimeout(() => setBanner(null), 5000);
    return () => clearTimeout(t);
  }, [banner]);

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Eye className="w-8 h-8 text-primary" />
            <h1 className="text-2xl font-semibold text-foreground">Monitoring</h1>
          </div>
          <p className="text-muted-foreground">
            Continuous security monitoring with automated scans and real-time alerts.
          </p>
        </div>

        {!hasMonitoring ? <UpgradePrompt /> : (
          <>
            {/* Trial banner */}
            {isTrialing && trialDaysRemaining !== null && (
              <div className="mb-6 rounded-xl border border-[#ff8800]/30 bg-[#ff8800]/10 px-4 py-3 text-sm text-[#ffcc00] flex items-center justify-between">
                <span>You&apos;re on a {planLabel} trial — {trialDaysRemaining} day{trialDaysRemaining !== 1 ? "s" : ""} remaining.</span>
                <div className="flex items-center gap-2">
                  <button type="button" onClick={() => setShowEndTrial(true)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-muted-foreground border border-border hover:bg-muted/30 transition-colors">
                    End Trial
                  </button>
                  <Link href="/settings/billing" className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#ff8800]/20 text-[#ff8800] border border-[#ff8800]/30 hover:bg-[#ff8800]/30 transition-colors">
                    <Zap className="w-3 h-3" />Upgrade Now
                  </Link>
                </div>
              </div>
            )}

            {/* End Trial Confirmation */}
            <Dialog open={showEndTrial} onOpenChange={setShowEndTrial}>
              <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
                <DialogHeader><DialogTitle>End Trial?</DialogTitle></DialogHeader>
                <p className="text-sm text-muted-foreground">
                  Your {planLabel} trial still has <span className="text-foreground font-medium">{trialDaysRemaining} day{trialDaysRemaining !== 1 ? "s" : ""}</span> remaining.
                  Ending it will move you back to the <span className="text-foreground font-medium">Free plan</span> immediately.
                  You won&apos;t be able to start another {planLabel} trial.
                </p>
                <div className="flex gap-3 justify-end pt-4">
                  <Button variant="outline" onClick={() => setShowEndTrial(false)} className="border-border text-foreground hover:bg-accent">Keep Trial</Button>
                  <Button onClick={handleEndTrial} disabled={endingTrial} className="bg-[#ef4444] hover:bg-[#dc2626] text-white">
                    {endingTrial ? "Ending..." : "End Trial"}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>

            {banner && (
              <div className={cn("mb-6 rounded-xl border px-4 py-3 text-sm",
                banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>
                {banner.text}
              </div>
            )}

            {/* Tabs */}
            <div className="inline-flex items-center mb-8 rounded-xl bg-muted/30 p-1 gap-1">
              {([["alerts", BellRing, "Alerts"], ["overview", Plus, "Add Monitor"]] as const).map(([key, Icon, label]) => (
                <button key={key} type="button" onClick={() => setActiveTab(key as TabKey)}
                  className={cn("h-10 px-5 rounded-lg text-sm font-medium inline-flex items-center justify-center gap-2 transition whitespace-nowrap",
                    activeTab === key ? "bg-background/40 border border-border text-foreground" : "text-muted-foreground hover:text-foreground")}>
                  <Icon className="w-4 h-4" />{label}
                </button>
              ))}
            </div>

            {activeTab === "overview" && <OverviewTab monitors={monitors} loading={loadingMonitors} onRefresh={loadMonitors} setBanner={setBanner} monitoringFrequency={monitoringFrequency} planLimit={planLimit} />}
            {activeTab === "alerts" && <AlertsTab setBanner={setBanner} planLimit={planLimit} />}
          </>
        )}
      </div>

      <PlanLimitDialog {...planLimit} />
    </main>
  );
}