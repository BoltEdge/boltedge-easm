// FILE: app/(authenticated)/monitoring/tuning/page.tsx
// Tuning Rules — create, toggle, delete tuning rules
// ✅ M9 RBAC: permission-gated actions via useOrg().canDo()
"use client";

import React, { useEffect, useMemo, useState, useCallback } from "react";
import {
  Plus, Search, Trash2, SlidersHorizontal, Check,
  ToggleLeft, ToggleRight, Loader2, Eye, ArrowLeft, RefreshCcw,
} from "lucide-react";
import Link from "next/link";

import { Button } from "../../../ui/button";
import { Input } from "../../../ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../../ui/dialog";
import { SeverityBadge } from "../../../SeverityBadge";
import { useOrg } from "../../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../../ui/plan-limit-dialog";
import { isPlanError } from "../../../lib/api";
import {
  cn, SEVERITY_ORDER,
  getTuningRules, createTuningRule, updateTuningRule, deleteTuningRule, getGroups,
} from "../_lib";
import type { TuningRule } from "../_lib";

/* ================================================================
   TUNING RULES PAGE
   ================================================================ */

function actionLabel(action: string) {
  switch (action) {
    case "suppress": return { text: "Suppress", color: "bg-red-500/10 text-red-400 border-red-500/30" };
    case "downgrade": return { text: "Downgrade", color: "bg-[#ffcc00]/10 text-[#ffcc00] border-[#ffcc00]/30" };
    case "upgrade": return { text: "Upgrade", color: "bg-[#ff8800]/10 text-[#ff8800] border-[#ff8800]/30" };
    case "snooze": return { text: "Snooze", color: "bg-[#00b8d4]/10 text-[#00b8d4] border-[#00b8d4]/30" };
    default: return { text: action, color: "bg-muted/30 text-muted-foreground border-border" };
  }
}

export default function TuningPage() {
  const { hasFeature, canDo } = useOrg();
  const planLimit = usePlanLimit();
  const hasMonitoring = hasFeature("monitoring");
  const canCreate = canDo("create_tuning_rules");
  const canEdit = canDo("edit_tuning_rules");
  const canDelete = canDo("edit_tuning_rules"); // delete uses same permission

  const [rules, setRules] = useState<TuningRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchFilter, setSearchFilter] = useState("");
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<TuningRule | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const load = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true); else setLoading(true);
    try { setRules(await getTuningRules()); }
    catch {}
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { if (hasMonitoring) load(); else setLoading(false); }, [load, hasMonitoring]);

  useEffect(() => {
    if (!banner) return;
    const t = setTimeout(() => setBanner(null), 5000);
    return () => clearTimeout(t);
  }, [banner]);

  async function handleToggle(rule: TuningRule) {
    try {
      await updateTuningRule(rule.id, { enabled: !rule.enabled });
      setBanner({ kind: "ok", text: `Rule ${!rule.enabled ? "enabled" : "disabled"}.` });
      load(true);
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      setDeleting(true);
      await deleteTuningRule(deleteTarget.id);
      setBanner({ kind: "ok", text: "Rule deleted." });
      setDeleteTarget(null);
      load(true);
    } catch (e: any) {
      if (isPlanError(e)) { setDeleteTarget(null); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    } finally { setDeleting(false); }
  }

  const filtered = useMemo(() => {
    if (!searchFilter.trim()) return rules;
    const q = searchFilter.toLowerCase();
    return rules.filter((r) =>
      (r.templateId || "").toLowerCase().includes(q) ||
      (r.assetValue || "").toLowerCase().includes(q) ||
      (r.assetPattern || "").toLowerCase().includes(q) ||
      (r.serviceName || "").toLowerCase().includes(q) ||
      (r.reason || "").toLowerCase().includes(q)
    );
  }, [rules, searchFilter]);

  if (!hasMonitoring) {
    return (
      <main className="flex-1 overflow-y-auto bg-background">
        <div className="p-8 text-center py-20">
          <p className="text-muted-foreground mb-4">Tuning rules require an active monitoring plan.</p>
          <Link href="/monitoring"><Button variant="outline"><ArrowLeft className="w-4 h-4 mr-2" />Back to Monitoring</Button></Link>
        </div>
      </main>
    );
  }

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-2 mb-3">
            <Link href="/monitoring" className="text-muted-foreground hover:text-foreground transition-colors">
              <Eye className="w-5 h-5" />
            </Link>
            <span className="text-muted-foreground/40">/</span>
            <SlidersHorizontal className="w-5 h-5 text-primary" />
            <h1 className="text-2xl font-semibold text-foreground">Tuning Rules</h1>
          </div>
          <p className="text-muted-foreground">
            Suppress, adjust severity, or snooze specific findings across your organization.
          </p>
        </div>

        {/* Banner */}
        {banner && (
          <div className={cn("mb-6 rounded-xl border px-4 py-3 text-sm",
            banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>
            {banner.text}
          </div>
        )}

        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <Button variant="outline" size="sm" onClick={() => load(true)} disabled={refreshing} className="border-border text-foreground hover:bg-accent">
              <RefreshCcw className={cn("w-3.5 h-3.5 mr-1.5", refreshing && "animate-spin")} />
              {refreshing ? "Refreshing…" : "Refresh"}
            </Button>
            {canCreate && (
              <Button onClick={() => setIsCreateOpen(true)} className="bg-primary hover:bg-primary/90">
                <Plus className="w-4 h-4 mr-2" />New Rule
              </Button>
            )}
          </div>

          {/* Search */}
          <div className="relative max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input placeholder="Search rules..." value={searchFilter} onChange={(e) => setSearchFilter(e.target.value)} className="pl-9" />
          </div>

          {/* Rules list */}
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            {loading ? (
              <div className="p-8 text-center text-muted-foreground text-sm flex items-center justify-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin" />Loading rules...
              </div>
            ) : filtered.length === 0 ? (
              <div className="p-12 text-center">
                <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto mb-4">
                  <SlidersHorizontal className="w-8 h-8 text-primary" />
                </div>
                <h3 className="text-foreground font-semibold mb-2">{rules.length === 0 ? "No tuning rules yet" : "No matching rules"}</h3>
                <p className="text-muted-foreground text-sm mb-6 max-w-md mx-auto">
                  {rules.length === 0
                    ? "Create rules to suppress known acceptable risks, adjust severity levels, or snooze alerts temporarily."
                    : "Try adjusting your search."}
                </p>
                {rules.length === 0 && canCreate && (
                  <Button onClick={() => setIsCreateOpen(true)} className="bg-primary hover:bg-primary/90">
                    <Plus className="w-4 h-4 mr-2" />Create your first rule
                  </Button>
                )}
                {rules.length === 0 && !canCreate && (
                  <p className="text-sm text-muted-foreground">Ask an admin or owner to create tuning rules.</p>
                )}
              </div>
            ) : (
              <div className="divide-y divide-border">
                {filtered.map((rule) => {
                  const al = actionLabel(rule.action);
                  return (
                    <div key={rule.id} className={cn("p-4 hover:bg-accent/20 transition-colors", !rule.enabled && "opacity-50")}>
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2 mb-2 flex-wrap">
                            <span className={cn("px-2 py-0.5 rounded text-[10px] font-semibold border", al.color)}>{al.text}</span>
                            {rule.templateId && <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-muted/30 border border-border text-foreground">{rule.templateId}</span>}
                            {rule.category && <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-primary/10 text-primary border border-primary/30">{rule.category}</span>}
                            {rule.action === "downgrade" && rule.targetSeverity && <span className="text-[10px] text-muted-foreground">→ <SeverityBadge severity={rule.targetSeverity} /></span>}
                            {rule.action === "snooze" && rule.snoozeUntil && <span className="text-[10px] text-muted-foreground">until {new Date(rule.snoozeUntil).toLocaleDateString()}</span>}
                          </div>
                          <div className="flex items-center gap-3 text-xs text-muted-foreground flex-wrap">
                            {rule.assetValue && <span className="font-mono">{rule.assetValue}</span>}
                            {rule.assetPattern && <span className="font-mono">{rule.assetPattern}</span>}
                            {rule.groupName && <span>Group: {rule.groupName}</span>}
                            {!rule.assetValue && !rule.assetPattern && !rule.groupName && <span>All assets</span>}
                            {rule.port && <span>· Port {rule.port}</span>}
                            {rule.serviceName && <span>· {rule.serviceName}</span>}
                            {rule.cwe && <span>· {rule.cwe}</span>}
                            {rule.titleContains && <span>· title contains &quot;{rule.titleContains}&quot;</span>}
                          </div>
                          {rule.reason && <div className="text-xs text-muted-foreground mt-1.5 italic">&quot;{rule.reason}&quot;</div>}
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {canEdit && (
                            <button type="button" onClick={() => handleToggle(rule)}>
                              {rule.enabled ? <ToggleRight className="w-6 h-6 text-[#10b981]" /> : <ToggleLeft className="w-6 h-6 text-muted-foreground" />}
                            </button>
                          )}
                          {canDelete && (
                            <Button size="sm" variant="outline" onClick={() => setDeleteTarget(rule)} className="border-red-500/50 text-red-500 hover:bg-red-500/10">
                              <Trash2 className="w-3 h-3" />
                            </Button>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Create Dialog */}
        <CreateTuningRuleDialog open={isCreateOpen} onOpenChange={setIsCreateOpen} setBanner={setBanner} onCreated={() => load(true)} planLimit={planLimit} />

        {/* Delete Confirmation */}
        <Dialog open={!!deleteTarget} onOpenChange={(o) => { if (!o) setDeleteTarget(null); }}>
          <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
            <DialogHeader><DialogTitle>Delete Tuning Rule</DialogTitle></DialogHeader>
            <p className="text-sm text-muted-foreground">Delete this rule? Suppressed findings will start appearing again.</p>
            <div className="flex gap-3 justify-end pt-4">
              <Button variant="outline" onClick={() => setDeleteTarget(null)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
              <Button onClick={handleDelete} disabled={deleting} className="bg-[#ef4444] hover:bg-[#dc2626] text-white">{deleting ? "Deleting..." : "Delete"}</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <PlanLimitDialog {...planLimit} />
    </main>
  );
}

/* ================================================================
   CREATE TUNING RULE DIALOG
   ================================================================ */

function CreateTuningRuleDialog({ open, onOpenChange, setBanner, onCreated, planLimit }: {
  open: boolean; onOpenChange: (v: boolean) => void;
  setBanner: (b: { kind: "ok" | "err"; text: string } | null) => void;
  onCreated: () => void;
  planLimit: ReturnType<typeof usePlanLimit>;
}) {
  const [action, setAction] = useState<"suppress" | "downgrade" | "upgrade" | "snooze">("suppress");
  const [templateId, setTemplateId] = useState("");
  const [category, setCategory] = useState("");
  const [sevMatch, setSevMatch] = useState("");
  const [assetPattern, setAssetPattern] = useState("");
  const [port, setPort] = useState("");
  const [serviceName, setServiceName] = useState("");
  const [cwe, setCwe] = useState("");
  const [titleContains, setTitleContains] = useState("");
  const [targetSeverity, setTargetSeverity] = useState("low");
  const [snoozeUntil, setSnoozeUntil] = useState("");
  const [reason, setReason] = useState("");
  const [groups, setGroups] = useState<Array<{ id: any; name: string }>>([]);
  const [selGroupId, setSelGroupId] = useState("");
  const [creating, setCreating] = useState(false);

  useEffect(() => { if (open) getGroups().then(setGroups).catch(() => {}); }, [open]);

  async function handleCreate() {
    if (!templateId && !category && !sevMatch && !assetPattern && !port && !serviceName && !cwe && !titleContains) {
      setBanner({ kind: "err", text: "Add at least one matching condition." }); return;
    }
    try {
      setCreating(true);
      await createTuningRule({
        action, templateId: templateId || undefined, category: category || undefined,
        severityMatch: sevMatch || undefined, groupId: selGroupId || undefined,
        assetPattern: assetPattern || undefined, port: port ? parseInt(port, 10) : undefined,
        serviceName: serviceName || undefined, cwe: cwe || undefined,
        titleContains: titleContains || undefined,
        targetSeverity: (action === "downgrade" || action === "upgrade") ? targetSeverity : undefined,
        snoozeUntil: action === "snooze" ? snoozeUntil : undefined,
        reason: reason || undefined,
      });
      setBanner({ kind: "ok", text: "Tuning rule created." });
      onOpenChange(false); onCreated();
      setAction("suppress"); setTemplateId(""); setCategory(""); setSevMatch(""); setAssetPattern("");
      setPort(""); setServiceName(""); setCwe(""); setTitleContains(""); setTargetSeverity("low");
      setSnoozeUntil(""); setReason(""); setSelGroupId("");
    } catch (e: any) {
      if (isPlanError(e)) { onOpenChange(false); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    } finally { setCreating(false); }
  }

  const categories = ["dns", "ssl", "ports", "headers", "technology", "cve"];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border text-foreground sm:max-w-[580px] max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <SlidersHorizontal className="w-5 h-5 text-primary" />Create Tuning Rule
          </DialogTitle>
        </DialogHeader>
        <p className="text-sm text-muted-foreground -mt-2">Define conditions to match findings and choose what action to take.</p>
        <div className="space-y-5 pt-2">
          {/* Action */}
          <div className="space-y-1.5">
            <label className="text-sm font-semibold text-foreground block">Action</label>
            <div className="grid grid-cols-4 gap-2">
              {([
                ["suppress", "Suppress", "Hide finding entirely", "text-red-400 border-red-500/30 bg-red-500/10"],
                ["downgrade", "Downgrade", "Lower the severity", "text-[#ffcc00] border-[#ffcc00]/30 bg-[#ffcc00]/10"],
                ["upgrade", "Upgrade", "Raise the severity", "text-[#ff8800] border-[#ff8800]/30 bg-[#ff8800]/10"],
                ["snooze", "Snooze", "Hide until a date", "text-[#00b8d4] border-[#00b8d4]/30 bg-[#00b8d4]/10"],
              ] as const).map(([val, label, desc, colors]) => (
                <button key={val} type="button" onClick={() => setAction(val)}
                  className={cn("rounded-lg p-3 border text-left transition-all text-center",
                    action === val ? cn(colors, "ring-1 ring-current/30") : "border-border bg-muted/20 hover:border-primary/30")}>
                  <div className={cn("text-xs font-semibold mb-0.5", action === val ? "" : "text-muted-foreground")}>{label}</div>
                  <div className="text-[10px] text-muted-foreground">{desc}</div>
                </button>
              ))}
            </div>
          </div>
          {(action === "downgrade" || action === "upgrade") && (
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-foreground block">Target Severity</label>
              <select value={targetSeverity} onChange={(e) => setTargetSeverity(e.target.value)}
                className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
              </select>
            </div>
          )}
          {action === "snooze" && (
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-foreground block">Snooze Until</label>
              <Input type="date" value={snoozeUntil} onChange={(e) => setSnoozeUntil(e.target.value)} />
            </div>
          )}
          <div className="flex items-center gap-3">
            <div className="flex-1 h-px bg-border" />
            <span className="text-xs text-muted-foreground uppercase font-semibold">Match Conditions</span>
            <div className="flex-1 h-px bg-border" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground block">Template ID</label>
              <Input placeholder="e.g. dns-no-dkim or dns-*" value={templateId} onChange={(e) => setTemplateId(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground block">Category</label>
              <select value={category} onChange={(e) => setCategory(e.target.value)}
                className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                <option value="">Any category</option>
                {categories.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground block">Asset Pattern</label>
              <Input placeholder="e.g. *.staging.example.com" value={assetPattern} onChange={(e) => setAssetPattern(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground block">Asset Group</label>
              <select value={selGroupId} onChange={(e) => setSelGroupId(e.target.value)}
                className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                <option value="">Any group</option>
                {groups.map((g) => <option key={String(g.id)} value={String(g.id)}>{g.name}</option>)}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground block">Port</label>
              <Input placeholder="e.g. 6380" type="number" value={port} onChange={(e) => setPort(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground block">Service Name</label>
              <Input placeholder="e.g. redis, nginx" value={serviceName} onChange={(e) => setServiceName(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground block">CWE</label>
              <Input placeholder="e.g. CWE-200" value={cwe} onChange={(e) => setCwe(e.target.value)} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground block">Severity</label>
              <select value={sevMatch} onChange={(e) => setSevMatch(e.target.value)}
                className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                <option value="">Any severity</option>
                {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground block">Title Contains</label>
              <Input placeholder="e.g. Redis, self-signed" value={titleContains} onChange={(e) => setTitleContains(e.target.value)} />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="text-sm font-medium text-foreground block">Reason <span className="text-muted-foreground font-normal">(recommended)</span></label>
            <Input placeholder="e.g. Accepted risk — internal Redis behind VPN" value={reason} onChange={(e) => setReason(e.target.value)} />
          </div>
          <div className="flex gap-3 justify-end pt-2">
            <Button variant="outline" onClick={() => onOpenChange(false)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
            <Button onClick={handleCreate} disabled={creating} className="bg-primary hover:bg-primary/90">
              <SlidersHorizontal className="w-4 h-4 mr-2" />{creating ? "Creating..." : "Create Rule"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}