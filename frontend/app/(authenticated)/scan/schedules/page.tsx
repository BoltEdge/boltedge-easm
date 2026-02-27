// FILE: app/(authenticated)/scan/schedules/page.tsx
// Scan Schedules — create, toggle, delete, run-now scheduled scans
// ✅ M9 RBAC: permission-gated actions via useOrg().canDo()
"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  Calendar, Play, Clock, Search, RefreshCcw, Trash2, Plus, Info,
  Shield, ShieldCheck, ShieldAlert, Target, Zap, Timer, Check,
  ToggleLeft, ToggleRight, Pause, CheckCircle2,
} from "lucide-react";
import { Button } from "../../../ui/button";
import { Input } from "../../../ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../../ui/dialog";
import { useOrg } from "../../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../../ui/plan-limit-dialog";
import {
  getScanProfiles, getGroups, getGroupAssets,
  getScanSchedules, createScanSchedule, updateScanSchedule, deleteScanSchedule, runScheduleNow,
  isPlanError,
} from "../../../lib/api";
import type { ScanProfile, ScanSchedule } from "../../../types";

function cn(...parts: Array<string | false | null | undefined>) { return parts.filter(Boolean).join(" "); }

function formatWhen(iso?: string | null) {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
}

function timeAgo(iso?: string | null) {
  if (!iso) return "Never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 60) return "just now";
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

function getProfileMetaByName(name?: string) {
  const n = (name || "").toLowerCase();
  if (n.includes("deep")) return { icon: ShieldAlert, color: "text-[#ff8800]", bg: "bg-[#ff8800]/10" };
  if (n.includes("standard")) return { icon: ShieldCheck, color: "text-primary", bg: "bg-primary/10" };
  return { icon: Zap, color: "text-[#00b8d4]", bg: "bg-[#00b8d4]/10" };
}

function frequencyLabel(sch: ScanSchedule): string {
  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  if (sch.frequency === "daily") return `Daily at ${sch.timeOfDay} UTC`;
  if (sch.frequency === "weekly" && sch.dayOfWeek != null) return `${days[sch.dayOfWeek]} at ${sch.timeOfDay} UTC`;
  if (sch.frequency === "monthly" && sch.dayOfMonth != null) return `Day ${sch.dayOfMonth} at ${sch.timeOfDay} UTC`;
  return `${sch.frequency} at ${sch.timeOfDay} UTC`;
}

/* ── Create Schedule Modal ── */

function ScheduleModal({ open, onOpenChange, groups, profiles, setBanner, onCreated, planLimit }: {
  open: boolean; onOpenChange: (v: boolean) => void;
  groups: Array<{ id: any; name: string }>; profiles: ScanProfile[];
  setBanner: (b: { kind: "ok" | "err"; text: string } | null) => void;
  onCreated: () => void;
  planLimit: ReturnType<typeof usePlanLimit>;
}) {
  const [scheduleType, setScheduleType] = useState<"asset" | "group">("asset");
  const [assets, setAssets] = useState<any[]>([]);
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [selGroupId, setSelGroupId] = useState("");
  const [selAssetId, setSelAssetId] = useState("");
  const [selProfileId, setSelProfileId] = useState("");
  const [frequency, setFrequency] = useState<"daily" | "weekly" | "monthly">("daily");
  const [timeOfDay, setTimeOfDay] = useState("02:00");
  const [dayOfWeek, setDayOfWeek] = useState(0);
  const [dayOfMonth, setDayOfMonth] = useState(1);
  const [scheduleName, setScheduleName] = useState("");
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    if (!selGroupId || scheduleType !== "asset") { setAssets([]); setSelAssetId(""); return; }
    let c = false; setLoadingAssets(true);
    getGroupAssets(selGroupId).then((a) => { if (!c) { setAssets(a); setSelAssetId(""); } }).catch(() => { if (!c) setAssets([]); }).finally(() => { if (!c) setLoadingAssets(false); });
    return () => { c = true; };
  }, [selGroupId, scheduleType]);

  useEffect(() => { if (!selProfileId && profiles.length) { const d = profiles.find((p) => p.isDefault); setSelProfileId(d ? d.id : profiles[0].id); } }, [profiles, selProfileId]);

  const dayNames = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  const nextRunPreview = useMemo(() => {
    if (frequency === "daily") return `Runs daily at ${timeOfDay} UTC`;
    if (frequency === "weekly") return `Every ${dayNames[dayOfWeek]} at ${timeOfDay} UTC`;
    return `Day ${dayOfMonth} at ${timeOfDay} UTC`;
  }, [frequency, timeOfDay, dayOfWeek, dayOfMonth]);

  const selectedGroupName = groups.find((g) => String(g.id) === selGroupId)?.name;

  async function handleCreate() {
    if (scheduleType === "asset" && !selAssetId) { setBanner({ kind: "err", text: "Select an asset." }); return; }
    if (scheduleType === "group" && !selGroupId) { setBanner({ kind: "err", text: "Select a group." }); return; }
    try {
      setCreating(true);
      const payload: any = { scheduleType, profileId: selProfileId || undefined, name: scheduleName.trim() || undefined, frequency, timeOfDay, dayOfWeek: frequency === "weekly" ? dayOfWeek : undefined, dayOfMonth: frequency === "monthly" ? dayOfMonth : undefined };
      if (scheduleType === "asset") payload.assetId = selAssetId; else payload.groupId = selGroupId;
      await createScanSchedule(payload);
      setBanner({ kind: "ok", text: "Schedule created." });
      onOpenChange(false); onCreated();
    } catch (e: any) {
      if (isPlanError(e)) { onOpenChange(false); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    } finally { setCreating(false); }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border text-foreground sm:max-w-[540px]">
        <DialogHeader><DialogTitle className="flex items-center gap-2"><Calendar className="w-5 h-5 text-primary" />Create Scan Schedule</DialogTitle></DialogHeader>
        <div className="space-y-4 pt-2">
          <div className="grid grid-cols-2 gap-3">
            <button type="button" onClick={() => setScheduleType("asset")} className={cn("rounded-xl p-4 border text-left transition-all", scheduleType === "asset" ? "border-primary/50 bg-primary/10 ring-1 ring-primary/30" : "border-border bg-muted/20 hover:border-primary/30")}>
              <div className="flex items-center gap-2 mb-1"><Target className={cn("w-4 h-4", scheduleType === "asset" ? "text-primary" : "text-muted-foreground")} /><span className="text-sm font-semibold text-foreground">Single Asset</span></div>
              <p className="text-xs text-muted-foreground">Schedule scans for one asset</p>
            </button>
            <button type="button" onClick={() => setScheduleType("group")} className={cn("rounded-xl p-4 border text-left transition-all", scheduleType === "group" ? "border-[#00b8d4]/50 bg-[#00b8d4]/10 ring-1 ring-[#00b8d4]/30" : "border-border bg-muted/20 hover:border-[#00b8d4]/30")}>
              <div className="flex items-center gap-2 mb-1"><Shield className={cn("w-4 h-4", scheduleType === "group" ? "text-[#00b8d4]" : "text-muted-foreground")} /><span className="text-sm font-semibold text-foreground">Asset Group</span></div>
              <p className="text-xs text-muted-foreground">Schedule scans for all in a group</p>
            </button>
          </div>
          <div className="space-y-1.5"><label className="text-sm font-medium text-foreground block">Name (optional)</label><Input placeholder="e.g., Production daily" value={scheduleName} onChange={(e) => setScheduleName(e.target.value)} /></div>
          {scheduleType === "asset" ? (
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5"><label className="text-sm font-medium text-foreground block">Group</label><select value={selGroupId} onChange={(e) => setSelGroupId(e.target.value)} className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm"><option value="">Select...</option>{groups.map((g) => <option key={String(g.id)} value={String(g.id)}>{g.name}</option>)}</select></div>
              <div className="space-y-1.5"><label className="text-sm font-medium text-foreground block">Asset</label><select value={selAssetId} onChange={(e) => setSelAssetId(e.target.value)} disabled={!selGroupId || loadingAssets} className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm disabled:opacity-50"><option value="">{loadingAssets ? "Loading..." : "Select..."}</option>{assets.map((a: any) => <option key={String(a.id)} value={String(a.id)}>{a.value}</option>)}</select></div>
            </div>
          ) : (
            <div className="space-y-1.5"><label className="text-sm font-medium text-foreground block">Group</label><select value={selGroupId} onChange={(e) => setSelGroupId(e.target.value)} className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm"><option value="">Select...</option>{groups.map((g) => <option key={String(g.id)} value={String(g.id)}>{g.name}</option>)}</select>
              {selGroupId && <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#00b8d4]/5 border border-[#00b8d4]/20 text-xs text-muted-foreground"><Info className="w-3.5 h-3.5 text-[#00b8d4]" />All assets in <span className="font-semibold text-foreground">{selectedGroupName}</span> will be scanned.</div>}
            </div>
          )}
          <div className="space-y-1.5"><label className="text-sm font-medium text-foreground block">Profile</label><select value={selProfileId} onChange={(e) => setSelProfileId(e.target.value)} className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm">{profiles.map((p) => <option key={p.id} value={p.id}>{p.name}{p.isDefault ? " (Default)" : ""}</option>)}</select></div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5"><label className="text-sm font-medium text-foreground block">Frequency</label><select value={frequency} onChange={(e) => setFrequency(e.target.value as any)} className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm"><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option></select></div>
            <div className="space-y-1.5"><label className="text-sm font-medium text-foreground block">Time (UTC)</label><Input type="time" value={timeOfDay} onChange={(e) => setTimeOfDay(e.target.value)} /></div>
          </div>
          {frequency === "weekly" && <div className="space-y-1.5"><label className="text-sm font-medium text-foreground block">Day</label><select value={dayOfWeek} onChange={(e) => setDayOfWeek(Number(e.target.value))} className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm">{dayNames.map((n, i) => <option key={i} value={i}>{n}</option>)}</select></div>}
          {frequency === "monthly" && <div className="space-y-1.5"><label className="text-sm font-medium text-foreground block">Day of Month</label><select value={dayOfMonth} onChange={(e) => setDayOfMonth(Number(e.target.value))} className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm">{Array.from({ length: 28 }, (_, i) => i + 1).map((d) => <option key={d} value={d}>{d}</option>)}</select></div>}
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-muted/30 border border-border text-xs text-muted-foreground"><Clock className="w-3.5 h-3.5" />{nextRunPreview}</div>
          <div className="flex gap-3 justify-end pt-2">
            <Button variant="outline" onClick={() => onOpenChange(false)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
            <Button onClick={handleCreate} disabled={creating || (scheduleType === "asset" ? !selAssetId : !selGroupId)} className="bg-primary hover:bg-primary/90"><Calendar className="w-4 h-4 mr-2" />{creating ? "Creating..." : "Create Schedule"}</Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/* ── Main Page ── */

export default function SchedulesPage() {
  const { canDo } = useOrg();
  const planLimit = usePlanLimit();
  const canCreate = canDo("create_schedules");
  const canEdit = canDo("edit_schedules");
  const canDelete = canDo("delete_schedules");
  const canRunNow = canDo("start_scans");

  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [groups, setGroups] = useState<Array<{ id: any; name: string }>>([]);
  const [loading, setLoading] = useState(true);
  const [searchFilter, setSearchFilter] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<ScanSchedule | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  async function load() { try { setLoading(true); setSchedules(await getScanSchedules()); } catch {} finally { setLoading(false); } }

  useEffect(() => {
    Promise.all([getScanSchedules(), getScanProfiles(), getGroups()]).then(([s, p, g]) => {
      setSchedules(s); setProfiles(p); setGroups(g.map((x) => ({ id: x.id, name: x.name })));
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 5000); return () => clearTimeout(t); } }, [banner]);

  async function handleToggle(sch: ScanSchedule) {
    try {
      await updateScanSchedule(sch.id, { enabled: !sch.enabled });
      setSchedules((p) => p.map((s) => s.id === sch.id ? { ...s, enabled: !s.enabled } : s));
      setBanner({ kind: "ok", text: `Schedule ${!sch.enabled ? "enabled" : "paused"}.` });
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    }
  }

  async function handleRunNow(sch: ScanSchedule) {
    try {
      const r = await runScheduleNow(sch.id);
      setBanner({ kind: "ok", text: `Scan triggered (Job #${r.jobId}).` });
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      setDeleting(true);
      await deleteScanSchedule(deleteTarget.id);
      setSchedules((p) => p.filter((s) => s.id !== deleteTarget.id));
      setBanner({ kind: "ok", text: "Deleted." });
      setDeleteTarget(null);
    } catch (e: any) {
      if (isPlanError(e)) { setDeleteTarget(null); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    } finally { setDeleting(false); }
  }

  const filtered = useMemo(() => { if (!searchFilter.trim()) return schedules; const s = searchFilter.toLowerCase(); return schedules.filter((x) => (x.assetValue || "").toLowerCase().includes(s) || (x.name || "").toLowerCase().includes(s) || (x.profileName || "").toLowerCase().includes(s) || (x.groupName || "").toLowerCase().includes(s)); }, [schedules, searchFilter]);
  const enabledCount = schedules.filter((s) => s.enabled).length;
  const pausedCount = schedules.filter((s) => !s.enabled).length;
  const hasActions = canEdit || canDelete || canRunNow;

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-foreground flex items-center gap-3"><Calendar className="w-7 h-7 text-primary" />Scheduled Scans</h1>
            <p className="text-muted-foreground mt-1">Automate recurring scans to continuously monitor your assets.</p>
          </div>
          {canCreate && (
            <Button onClick={() => setIsCreateOpen(true)} className="bg-primary hover:bg-primary/90"><Plus className="w-4 h-4 mr-2" />New Schedule</Button>
          )}
        </div>

        {banner && <div className={cn("rounded-xl border px-4 py-3 text-sm", banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>{banner.text}</div>}

        <div className="grid grid-cols-3 gap-4">
          <div className="bg-card border border-border rounded-xl p-5"><div className="flex items-center justify-between"><div><div className="text-2xl font-bold text-foreground">{schedules.length}</div><div className="text-xs text-muted-foreground mt-1">Total</div></div><div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center"><Calendar className="w-5 h-5 text-primary" /></div></div></div>
          <div className="bg-card border border-border rounded-xl p-5"><div className="flex items-center justify-between"><div><div className="text-2xl font-bold text-[#10b981]">{enabledCount}</div><div className="text-xs text-muted-foreground mt-1">Active</div></div><div className="w-10 h-10 rounded-lg bg-[#10b981]/10 flex items-center justify-center"><CheckCircle2 className="w-5 h-5 text-[#10b981]" /></div></div></div>
          <div className="bg-card border border-border rounded-xl p-5"><div className="flex items-center justify-between"><div><div className="text-2xl font-bold text-muted-foreground">{pausedCount}</div><div className="text-xs text-muted-foreground mt-1">Paused</div></div><div className="w-10 h-10 rounded-lg bg-muted/30 flex items-center justify-center"><Pause className="w-5 h-5 text-muted-foreground" /></div></div></div>
        </div>

        <div className="flex items-center justify-between gap-4">
          <div className="relative flex-1 max-w-md"><Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" /><Input placeholder="Search..." value={searchFilter} onChange={(e) => setSearchFilter(e.target.value)} className="pl-9" /></div>
          <Button variant="ghost" size="sm" onClick={load} className="text-primary hover:bg-primary/10"><RefreshCcw className="w-4 h-4 mr-2" />Refresh</Button>
        </div>

        <div className="bg-card border border-border rounded-xl overflow-hidden">
          {loading ? <div className="p-8 text-center text-muted-foreground text-sm">Loading...</div> : filtered.length === 0 ? (
            <div className="p-12 text-center">
              <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto mb-4"><Calendar className="w-8 h-8 text-primary" /></div>
              <h3 className="text-foreground font-semibold mb-2">{schedules.length === 0 ? "No scheduled scans yet" : "No matches"}</h3>
              <p className="text-muted-foreground text-sm mb-6">{schedules.length === 0 ? "Set up automated scans to monitor continuously." : `No schedules match "${searchFilter}".`}</p>
              {schedules.length === 0 && canCreate && <Button onClick={() => setIsCreateOpen(true)} className="bg-primary hover:bg-primary/90"><Plus className="w-4 h-4 mr-2" />Create your first schedule</Button>}
              {schedules.length === 0 && !canCreate && <p className="text-sm text-muted-foreground">Ask an admin or owner to create scan schedules.</p>}
            </div>
          ) : (
            <div className="overflow-x-auto"><table className="w-full">
              <thead className="bg-muted/30"><tr>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Status</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Asset</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Profile</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Frequency</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Next Run</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Last Run</th>
                {hasActions && <th className="text-right p-4 text-sm font-semibold text-muted-foreground">Actions</th>}
              </tr></thead>
              <tbody className="divide-y divide-border">
                {filtered.map((sch) => {
                  const pm = getProfileMetaByName(sch.profileName); const PI = pm.icon;
                  return (
                    <tr key={sch.id} className={cn("hover:bg-accent/30 transition-colors", !sch.enabled && "opacity-60")}>
                      <td className="p-4">
                        {canEdit ? (
                          <button type="button" onClick={() => handleToggle(sch)} className="flex items-center gap-2">
                            {sch.enabled ? <ToggleRight className="w-6 h-6 text-[#10b981]" /> : <ToggleLeft className="w-6 h-6 text-muted-foreground" />}
                            <span className={cn("text-xs font-semibold", sch.enabled ? "text-[#10b981]" : "text-muted-foreground")}>{sch.enabled ? "Active" : "Paused"}</span>
                          </button>
                        ) : (
                          <span className={cn("text-xs font-semibold", sch.enabled ? "text-[#10b981]" : "text-muted-foreground")}>{sch.enabled ? "Active" : "Paused"}</span>
                        )}
                      </td>
                      <td className="p-4"><div className="flex flex-col gap-0.5"><div className="flex items-center gap-2"><span className="font-mono text-sm text-foreground">{sch.scheduleType === "group" ? (sch.groupName || `Group #${sch.groupId}`) : (sch.assetValue || `Asset #${sch.assetId}`)}</span><span className={cn("px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase", sch.scheduleType === "group" ? "bg-[#00b8d4]/10 text-[#00b8d4]" : "bg-primary/10 text-primary")}>{sch.scheduleType}</span></div>{sch.name && <span className="text-xs text-primary/70 italic">{sch.name}</span>}</div></td>
                      <td className="p-4"><div className="flex items-center gap-2"><div className={cn("w-6 h-6 rounded flex items-center justify-center", pm.bg)}><PI className={cn("w-3.5 h-3.5", pm.color)} /></div><span className="text-sm text-foreground">{sch.profileName || "Default"}</span></div></td>
                      <td className="p-4"><span className="text-sm text-foreground flex items-center gap-1.5"><Clock className="w-3.5 h-3.5 text-muted-foreground" />{frequencyLabel(sch)}</span></td>
                      <td className="p-4"><span className="text-sm text-muted-foreground">{sch.enabled ? formatWhen(sch.nextRunAt) : "-"}</span></td>
                      <td className="p-4"><span className="text-sm text-muted-foreground">{timeAgo(sch.lastRunAt)}</span></td>
                      {hasActions && (
                        <td className="p-4"><div className="flex items-center justify-end gap-2">
                          {canRunNow && <Button size="sm" variant="outline" onClick={() => handleRunNow(sch)} className="border-primary/50 text-primary hover:bg-primary/10"><Play className="w-3 h-3 mr-1" />Run Now</Button>}
                          {canDelete && <Button size="sm" variant="outline" onClick={() => setDeleteTarget(sch)} className="border-red-500/50 text-red-500 hover:bg-red-500/10"><Trash2 className="w-3 h-3" /></Button>}
                        </div></td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table></div>
          )}
        </div>

        <Dialog open={!!deleteTarget} onOpenChange={(o) => { if (!o) setDeleteTarget(null); }}>
          <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
            <DialogHeader><DialogTitle>Delete Schedule</DialogTitle></DialogHeader>
            <p className="text-sm text-muted-foreground">Delete schedule for <span className="font-mono text-foreground">{deleteTarget?.scheduleType === "group" ? (deleteTarget?.groupName || "this group") : (deleteTarget?.assetValue || "this asset")}</span>?</p>
            <div className="flex gap-3 justify-end pt-4">
              <Button variant="outline" onClick={() => setDeleteTarget(null)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
              <Button onClick={handleDelete} disabled={deleting} className="bg-[#ef4444] hover:bg-[#dc2626] text-white">{deleting ? "Deleting..." : "Delete"}</Button>
            </div>
          </DialogContent>
        </Dialog>

        <ScheduleModal open={isCreateOpen} onOpenChange={setIsCreateOpen} groups={groups} profiles={profiles} setBanner={setBanner} onCreated={() => { setIsCreateOpen(false); load(); }} planLimit={planLimit} />
      </div>

      <PlanLimitDialog {...planLimit} />
    </main>
  );
}