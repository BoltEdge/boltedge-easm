// FILE: app/(authenticated)/monitoring/page.tsx
// Monitoring page — Overview tab, Alerts tab, trial banner, upgrade prompt
// ✅ M9 RBAC: permission-gated actions via useOrg().canDo()
"use client";

import React, { useEffect, useMemo, useState, useCallback } from "react";
import Link from "next/link";
import {
  Eye, Plus, Search, RefreshCcw, Trash2, Shield, ShieldAlert,
  BellRing, Settings, SlidersHorizontal, Clock, CheckCircle2,
  Globe, Lock, Server, FileCode, Zap, ToggleLeft, ToggleRight, Pause,
  X, Loader2, Target, Cpu,
} from "lucide-react";

import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../ui/dialog";
import { SeverityBadge } from "../../SeverityBadge";
import { useOrg } from "../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../ui/plan-limit-dialog";
import { isPlanError } from "../../lib/api";
import { getAllAssets } from "../../lib/api";
import {
  cn, timeAgo, formatWhen, monitoringFrequencyLabel,
  alertStatusBadge, MONITOR_TYPE_CONFIG, SEVERITY_ORDER,
  getMonitors, createMonitor, updateMonitor, deleteMonitor,
  getMonitorAlerts, acknowledgeAlert, resolveAlert,
  getGroups, getGroupAssets,
} from "./_lib";
import type { Monitor, MonitorAlert } from "./_lib";

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

  const plans = [
    { key: "starter", label: "Starter", price: "$19/mo", freq: "Scans every 5 days", trialDays: 14, color: "#00b8d4", tags: ["DNS", "SSL", "Ports", "Headers"] },
    { key: "professional", label: "Professional", price: "$79/mo", freq: "Scans every 2 days", trialDays: 21, color: "#7c5cfc", tags: ["Everything", "Webhooks", "Deep Discovery"] },
    { key: "enterprise_silver", label: "Enterprise Silver", price: "$249/mo", freq: "Daily scans", trialDays: 30, color: "#ff8800", tags: ["Everything", "Custom Profiles", "Priority"] },
    { key: "enterprise_gold", label: "Enterprise Gold", price: "Custom", freq: "Real-time scans", trialDays: 45, color: "#ffd700", tags: ["Unlimited", "SSO", "Dedicated Support"], needsApproval: true },
  ];

  async function handleStartTrial(planKey: string) {
    try {
      setStarting(planKey);
      const { apiFetch } = await import("../../lib/api");
      await apiFetch<any>("/billing/start-trial", {
        method: "POST",
        body: JSON.stringify({ plan: planKey }),
      });
      await refresh();
      const p = plans.find((x) => x.key === planKey);
      setTrialBanner({ kind: "ok", text: `${p?.label || planKey} trial started! Refreshing...` });
      setTimeout(() => window.location.reload(), 1200);
    } catch (e: any) {
      setTrialBanner({ kind: "err", text: e?.message || "Failed to start trial." });
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
            <div className="text-xs text-muted-foreground mb-1">{p.price}</div>
            <div className="text-sm text-muted-foreground mb-3">{p.freq}</div>
            <div className="flex flex-wrap gap-1.5 mb-5">
              {p.tags.map((t: string) => (
                <span key={t} className="px-2 py-0.5 rounded text-[10px] font-semibold" style={{ backgroundColor: `${p.color}15`, color: p.color }}>{t}</span>
              ))}
            </div>
            <div className="mt-auto space-y-2">
              {p.needsApproval ? (
                <>
                  <Link href="/settings/billing" className="block">
                    <Button size="sm" className="w-full text-xs" variant="outline" style={{ borderColor: `${p.color}40`, color: p.color }}>
                      Contact Sales
                    </Button>
                  </Link>
                  <div className="text-[10px] text-muted-foreground text-center">{p.trialDays}-day trial with sales approval</div>
                </>
              ) : (
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
                    {starting === p.key ? "Starting..." : `Start ${p.trialDays}-Day Free Trial`}
                  </Button>
                  <Link href="/settings/billing" className="block">
                    <Button size="sm" className="w-full text-xs" style={{ backgroundColor: `${p.color}20`, color: p.color, borderColor: `${p.color}40` }} variant="outline">
                      <Zap className="w-3 h-3 mr-1.5" />Upgrade to {p.label}
                    </Button>
                  </Link>
                </>
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

      {/* Create Monitor Dialog */}
      <CreateMonitorDialog open={isCreateOpen} onOpenChange={setIsCreateOpen} monitoringFrequency={monitoringFrequency} setBanner={setBanner} onCreated={onRefresh} planLimit={planLimit} />

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

function CreateMonitorDialog({ open, onOpenChange, monitoringFrequency, setBanner, onCreated, planLimit }: {
  open: boolean; onOpenChange: (v: boolean) => void; monitoringFrequency: string;
  setBanner: (b: { kind: "ok" | "err"; text: string } | null) => void;
  onCreated: () => void;
  planLimit: ReturnType<typeof usePlanLimit>;
}) {
  const [targetType, setTargetType] = useState<"asset" | "group">("asset");
  const [groups, setGroups] = useState<Array<{ id: any; name: string }>>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [selGroupId, setSelGroupId] = useState("");
  const [selAssetId, setSelAssetId] = useState("");
  const [monitorTypes, setMonitorTypes] = useState<string[]>(["all"]);
  const [creating, setCreating] = useState(false);

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
            <Plus className="w-5 h-5 text-primary" />Add Monitor
          </DialogTitle>
        </DialogHeader>
        <p className="text-sm text-muted-foreground -mt-2">
          Assets must have at least one completed scan to establish a baseline.
        </p>
        <div className="space-y-4 pt-2">
          {/* Target type */}
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
            <Button onClick={handleCreate} disabled={creating || (targetType === "asset" ? !selAssetId : !selGroupId)} className="bg-primary hover:bg-primary/90">
              <Eye className="w-4 h-4 mr-2" />{creating ? "Creating..." : "Start Monitoring"}
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

  const load = useCallback(async () => {
    try { setLoading(true); setAlerts(await getMonitorAlerts()); } catch {} finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

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
    if (searchFilter.trim()) {
      const q = searchFilter.toLowerCase();
      result = result.filter((a) =>
        (a.title || "").toLowerCase().includes(q) ||
        (a.assetValue || "").toLowerCase().includes(q) ||
        (a.alertName || "").toLowerCase().includes(q)
      );
    }
    return result;
  }, [alerts, statusFilter, sevFilter, searchFilter]);

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

      {/* Alerts list */}
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
          <div className="divide-y divide-border">
            {filtered.map((alert) => (
              <div key={alert.id} className="p-4 hover:bg-accent/20 transition-colors">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={alert.severity} />
                      <span className={cn("px-2 py-0.5 rounded text-[10px] font-semibold border", alertStatusBadge(alert.status))}>
                        {alert.status}
                      </span>
                      <span className="text-xs text-muted-foreground">{timeAgo(alert.createdAt)}</span>
                    </div>
                    <h4 className="text-sm font-medium text-foreground mb-0.5">{alert.title}</h4>
                    {alert.summary && <p className="text-xs text-muted-foreground mb-1">{alert.summary}</p>}
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      {alert.assetValue && <span className="font-mono">{alert.assetValue}</span>}
                      {alert.alertName && <span>· {alert.alertName}</span>}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {canAcknowledge && alert.status === "open" && (
                      <Button size="sm" variant="outline" onClick={() => handleAcknowledge(alert)}
                        className="border-[#ffcc00]/50 text-[#ffcc00] hover:bg-[#ffcc00]/10 text-xs">
                        Acknowledge
                      </Button>
                    )}
                    {canClose && (alert.status === "open" || alert.status === "acknowledged") && (
                      <Button size="sm" variant="outline" onClick={() => handleResolve(alert)}
                        className="border-[#10b981]/50 text-[#10b981] hover:bg-[#10b981]/10 text-xs">
                        Resolve
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ================================================================
   MAIN PAGE — Overview + Alerts tabs, uses useOrg()
   ================================================================ */

type TabKey = "overview" | "alerts";

export default function MonitoringPage() {
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
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
              {([["overview", Eye, "Overview"], ["alerts", BellRing, "Alerts"]] as const).map(([key, Icon, label]) => (
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