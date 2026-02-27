"use client";

import React, { useEffect, useMemo, useState, useCallback } from "react";
import {
  Radar, Search, Globe, Network, Server, CheckCircle2, Plus, FolderPlus,
  Check, Activity, Play, Clock, Target, Zap, Settings, RefreshCcw, Trash2,
  Calendar, Shield, ShieldCheck, ShieldAlert, Timer, ChevronRight, Info,
} from "lucide-react";

import { Button } from "../../../../ui/button";
import { Input } from "../../../../ui/input";
import { Label } from "../../../../ui/label";
import {
  Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle,
} from "../../../../ui/dialog";

import {
  discoveryDomain, getDiscoveryRuns, getDiscoveryRun, deleteDiscoveryRun,
  getGroups, addAssetToGroup, addAssetToGroupAndScan,
  getScanJobs, createScanJob, runScanJob, getAllAssets, getGroupAssets,
  getScanProfiles, createScanSchedule,
  type DiscoveryRunDetail, type DiscoveryRunListItem, type DiscoveryDomainResponse,
} from "../../../../lib/api";

import type { ScanProfile } from "../../../../types";

/* ── Helpers ──────────────────────────────────────────── */

type TabKey = "discover" | "scan";
type DiscoveryType = "organization" | "domain" | "ip";

function cn(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(" ");
}

function formatWhen(iso?: string) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function statusBadgeClass(status: string) {
  const s = (status || "").toLowerCase();
  if (s.includes("new")) return "bg-[#00b8d4]/10 text-[#00b8d4]";
  if (s.includes("added")) return "bg-[#10b981]/10 text-[#10b981]";
  if (s.includes("running")) return "bg-[#00b8d4]/10 text-[#00b8d4]";
  if (s.includes("completed")) return "bg-[#10b981]/10 text-[#10b981]";
  return "bg-muted/30 text-muted-foreground";
}

function getProfileMeta(profile: ScanProfile) {
  const name = (profile.name || "").toLowerCase();
  if (name.includes("deep")) {
    return {
      icon: ShieldAlert, accent: "text-[#ff8800]",
      accentBg: "bg-[#ff8800]/10 border-[#ff8800]/30",
      accentGlow: "shadow-[0_0_20px_rgba(255,136,0,0.1)]",
      badge: "bg-[#ff8800]/10 text-[#ff8800]",
      duration: "2–4 hours", depth: "Maximum depth",
    };
  }
  if (name.includes("standard")) {
    return {
      icon: ShieldCheck, accent: "text-primary",
      accentBg: "bg-primary/10 border-primary/30",
      accentGlow: "shadow-[0_0_20px_rgba(139,92,246,0.1)]",
      badge: "bg-primary/10 text-primary",
      duration: "30–60 min", depth: "Full coverage",
    };
  }
  return {
    icon: Zap, accent: "text-[#00b8d4]",
    accentBg: "bg-[#00b8d4]/10 border-[#00b8d4]/30",
    accentGlow: "shadow-[0_0_20px_rgba(0,184,212,0.1)]",
    badge: "bg-[#00b8d4]/10 text-[#00b8d4]",
    duration: "5–10 min", depth: "Essential checks",
  };
}

function engineList(profile: ScanProfile): string[] {
  const engines: string[] = [];
  if (profile.useShodan) engines.push("Shodan");
  if (profile.useNmap) engines.push("Nmap");
  if (profile.useNuclei) engines.push("Nuclei");
  if (profile.useSslyze) engines.push("SSLyze");
  if (profile.shodanIncludeHistory) engines.push("History");
  if (profile.shodanIncludeCves) engines.push("CVEs");
  return engines;
}

/* ── Profile Card ─────────────────────────────────────── */
function ProfileCard({
  profile, selected, onSelect,
}: {
  profile: ScanProfile; selected: boolean; onSelect: () => void;
}) {
  const meta = getProfileMeta(profile);
  const Icon = meta.icon;
  const engines = engineList(profile);

  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "relative text-left rounded-xl p-5 border transition-all duration-200",
        "hover:scale-[1.02] active:scale-[0.98]",
        selected
          ? cn(meta.accentBg, meta.accentGlow, "ring-1", meta.accent.replace("text-", "ring-"))
          : "bg-muted/30 border-border hover:border-primary/30"
      )}
    >
      {profile.isDefault && (
        <span className="absolute top-3 right-3 text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-[#10b981]/10 text-[#10b981] border border-[#10b981]/20">
          Default
        </span>
      )}
      <div className="flex items-center gap-2.5 mb-3">
        <Icon className={cn("w-5 h-5", meta.accent)} />
        <h3 className="font-semibold text-foreground">{profile.name}</h3>
      </div>
      <p className="text-xs text-muted-foreground mb-4 line-clamp-2">
        {profile.description || "No description"}
      </p>
      <div className="flex flex-wrap gap-1.5 mb-4">
        {engines.map((e) => (
          <span key={e} className="px-2 py-0.5 rounded-md text-[10px] font-semibold bg-muted/50 text-muted-foreground border border-border/50">
            {e}
          </span>
        ))}
      </div>
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1"><Timer className="w-3 h-3" />{meta.duration}</span>
        <span className="flex items-center gap-1"><Target className="w-3 h-3" />{meta.depth}</span>
      </div>
      {selected && (
        <div className={cn("absolute bottom-3 right-3 w-5 h-5 rounded-full flex items-center justify-center", meta.badge)}>
          <Check className="w-3 h-3" />
        </div>
      )}
    </button>
  );
}

/* ── Schedule Modal ───────────────────────────────────── */
function ScheduleModal({
  open, onOpenChange, groups, profiles, setBanner,
}: {
  open: boolean; onOpenChange: (v: boolean) => void;
  groups: Array<{ id: any; name: string }>;
  profiles: ScanProfile[];
  setBanner: (b: { kind: "ok" | "err"; text: string } | null) => void;
}) {
  const [assets, setAssets] = useState<any[]>([]);
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [selectedGroupId, setSelectedGroupId] = useState("");
  const [selectedAssetId, setSelectedAssetId] = useState("");
  const [selectedProfileId, setSelectedProfileId] = useState("");
  const [frequency, setFrequency] = useState<"daily" | "weekly" | "monthly">("daily");
  const [timeOfDay, setTimeOfDay] = useState("02:00");
  const [dayOfWeek, setDayOfWeek] = useState(0);
  const [dayOfMonth, setDayOfMonth] = useState(1);
  const [scheduleName, setScheduleName] = useState("");
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    if (!selectedGroupId) { setAssets([]); setSelectedAssetId(""); return; }
    let cancelled = false;
    setLoadingAssets(true);
    getGroupAssets(selectedGroupId)
      .then((a) => { if (!cancelled) { setAssets(a); setSelectedAssetId(""); } })
      .catch(() => { if (!cancelled) setAssets([]); })
      .finally(() => { if (!cancelled) setLoadingAssets(false); });
    return () => { cancelled = true; };
  }, [selectedGroupId]);

  useEffect(() => {
    if (!selectedProfileId && profiles.length) {
      const def = profiles.find((p) => p.isDefault);
      setSelectedProfileId(def ? def.id : profiles[0].id);
    }
  }, [profiles, selectedProfileId]);

  async function handleCreate() {
    if (!selectedAssetId) { setBanner({ kind: "err", text: "Please select an asset." }); return; }
    try {
      setCreating(true);
      await createScanSchedule({
        assetId: selectedAssetId,
        profileId: selectedProfileId || undefined,
        name: scheduleName.trim() || undefined,
        frequency, timeOfDay,
        dayOfWeek: frequency === "weekly" ? dayOfWeek : undefined,
        dayOfMonth: frequency === "monthly" ? dayOfMonth : undefined,
      });
      setBanner({ kind: "ok", text: "Schedule created successfully." });
      onOpenChange(false);
      setSelectedAssetId(""); setScheduleName("");
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to create schedule." });
    } finally { setCreating(false); }
  }

  const dayNames = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

  const nextRunPreview = useMemo(() => {
    if (frequency === "daily") return `Runs daily at ${timeOfDay} UTC`;
    if (frequency === "weekly") return `Runs every ${dayNames[dayOfWeek]} at ${timeOfDay} UTC`;
    if (frequency === "monthly") return `Runs on day ${dayOfMonth} at ${timeOfDay} UTC`;
    return "";
  }, [frequency, timeOfDay, dayOfWeek, dayOfMonth]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border text-foreground sm:max-w-[540px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Calendar className="w-5 h-5 text-primary" />
            Create Scan Schedule
          </DialogTitle>
          <DialogDescription className="text-muted-foreground">
            Set up recurring automated scans for an asset.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-5 pt-2">
          <div className="space-y-1.5">
            <Label className="text-sm">Schedule Name (optional)</Label>
            <Input placeholder="e.g., Production daily scan" value={scheduleName} onChange={(e) => setScheduleName(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-sm">Asset Group</Label>
              <select value={selectedGroupId} onChange={(e) => setSelectedGroupId(e.target.value)}
                className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                <option value="">Select group…</option>
                {groups.map((g) => <option key={String(g.id)} value={String(g.id)}>{g.name}</option>)}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-sm">Asset</Label>
              <select value={selectedAssetId} onChange={(e) => setSelectedAssetId(e.target.value)}
                disabled={!selectedGroupId || loadingAssets}
                className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50">
                <option value="">{loadingAssets ? "Loading…" : "Select asset…"}</option>
                {assets.map((a: any) => <option key={String(a.id)} value={String(a.id)}>{a.value} ({a.type || a.asset_type})</option>)}
              </select>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label className="text-sm">Scan Profile</Label>
            <select value={selectedProfileId} onChange={(e) => setSelectedProfileId(e.target.value)}
              className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring">
              {profiles.map((p) => <option key={p.id} value={p.id}>{p.name}{p.isDefault ? " (Default)" : ""}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-sm">Frequency</Label>
              <select value={frequency} onChange={(e) => setFrequency(e.target.value as any)}
                className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-sm">Time (UTC)</Label>
              <Input type="time" value={timeOfDay} onChange={(e) => setTimeOfDay(e.target.value)} />
            </div>
          </div>
          {frequency === "weekly" && (
            <div className="space-y-1.5">
              <Label className="text-sm">Day of Week</Label>
              <select value={dayOfWeek} onChange={(e) => setDayOfWeek(Number(e.target.value))}
                className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                {dayNames.map((name, i) => <option key={i} value={i}>{name}</option>)}
              </select>
            </div>
          )}
          {frequency === "monthly" && (
            <div className="space-y-1.5">
              <Label className="text-sm">Day of Month</Label>
              <select value={dayOfMonth} onChange={(e) => setDayOfMonth(Number(e.target.value))}
                className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                {Array.from({ length: 28 }, (_, i) => i + 1).map((d) => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>
          )}
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-muted/30 border border-border text-xs text-muted-foreground">
            <Clock className="w-3.5 h-3.5" />{nextRunPreview}
          </div>
          <div className="flex gap-3 justify-end pt-2">
            <Button variant="outline" onClick={() => onOpenChange(false)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
            <Button onClick={handleCreate} disabled={creating || !selectedAssetId} className="bg-primary hover:bg-primary/90">
              <Calendar className="w-4 h-4 mr-2" />{creating ? "Creating…" : "Create Schedule"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/* ── Scanning Tab (M3 Revamp) ─────────────────────────── */
function ScanningTab({
  groups, setBanner,
}: {
  groups: Array<{ id: any; name: string }>;
  setBanner: (b: { kind: "ok" | "err"; text: string } | null) => void;
}) {
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [loadingProfiles, setLoadingProfiles] = useState(true);
  const [selectedProfileId, setSelectedProfileId] = useState<string>("");
  const [scanTarget, setScanTarget] = useState("");
  const [isScanDialogOpen, setIsScanDialogOpen] = useState(false);
  const [scanAssetGroup, setScanAssetGroup] = useState("");
  const [isScheduleOpen, setIsScheduleOpen] = useState(false);
  const [activeScans, setActiveScans] = useState<any[]>([]);
  const [loadingScans, setLoadingScans] = useState(true);

  useEffect(() => {
    getScanProfiles()
      .then((p) => {
        setProfiles(p);
        const def = p.find((x) => x.isDefault);
        if (def) setSelectedProfileId(def.id);
        else if (p.length) setSelectedProfileId(p[0].id);
      })
      .catch((e) => { console.error("Failed to load profiles:", e); })
      .finally(() => setLoadingProfiles(false));
  }, []);

  const selectedProfile = useMemo(
    () => profiles.find((p) => p.id === selectedProfileId) ?? null,
    [profiles, selectedProfileId]
  );

  const loadActiveScans = useCallback(async () => {
    try {
      setLoadingScans(true);
      const jobs = await getScanJobs();
      setActiveScans(jobs.filter((j: any) => j.status === "queued" || j.status === "running"));
    } catch { /* silent */ } finally { setLoadingScans(false); }
  }, []);

  useEffect(() => { loadActiveScans(); }, [loadActiveScans]);
  useEffect(() => {
    if (activeScans.length === 0) return;
    const iv = setInterval(loadActiveScans, 5000);
    return () => clearInterval(iv);
  }, [activeScans.length, loadActiveScans]);

  async function handleQuickScan() {
    if (!scanTarget.trim()) { setBanner({ kind: "err", text: "Please enter a target." }); return; }
    try {
      const assets = await getAllAssets();
      const asset = assets.find((a: any) => a.value.toLowerCase() === scanTarget.trim().toLowerCase());
      if (!asset) { setBanner({ kind: "err", text: "Asset not found. Add it to a group first." }); return; }
      const job = await createScanJob(String(asset.id), selectedProfileId || undefined);
      await runScanJob(String(job.id));
      setBanner({ kind: "ok", text: `Scan started for ${scanTarget} using ${selectedProfile?.name || "default"} profile (Job #${job.id})` });
      setScanTarget("");
      await loadActiveScans();
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed to start scan." }); }
  }

  async function handleGroupScan() {
    if (!scanAssetGroup) { setBanner({ kind: "err", text: "Select an asset group." }); return; }
    try {
      const assets = await getGroupAssets(scanAssetGroup);
      if (!assets?.length) { setBanner({ kind: "err", text: "No assets in group." }); return; }
      let created = 0;
      for (const asset of assets) {
        try {
          const job = await createScanJob(String(asset.id), selectedProfileId || undefined);
          await runScanJob(String(job.id));
          created++;
        } catch { /* continue */ }
      }
      setBanner({ kind: "ok", text: `Started ${created} scan(s) using ${selectedProfile?.name || "default"} profile.` });
      setIsScanDialogOpen(false);
      await loadActiveScans();
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed." }); }
  }

  return (
    <div className="space-y-8">
      {/* Profile Selector */}
      <div className="bg-card border border-border rounded-xl p-6">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            <h2 className="text-lg font-semibold text-foreground">Scan Profile</h2>
          </div>
          <span className="text-xs text-muted-foreground">{profiles.length} profile{profiles.length !== 1 ? "s" : ""} available</span>
        </div>
        {loadingProfiles ? (
          <div className="text-sm text-muted-foreground py-4">Loading profiles…</div>
        ) : profiles.length === 0 ? (
          <div className="text-sm text-muted-foreground py-4">No scan profiles found.</div>
        ) : (
          <div className="grid sm:grid-cols-3 gap-4">
            {profiles.map((p) => (
              <ProfileCard key={p.id} profile={p} selected={selectedProfileId === p.id} onSelect={() => setSelectedProfileId(p.id)} />
            ))}
          </div>
        )}
      </div>

      {/* Quick Scan */}
      <div className="bg-card border border-primary/20 rounded-xl p-6 shadow-[0_0_20px_rgba(139,92,246,0.1)]">
        <div className="flex items-center gap-2 mb-5">
          <Zap className="w-5 h-5 text-primary" />
          <h2 className="text-lg font-semibold text-foreground">Quick Scan</h2>
          {selectedProfile && (
            <span className={cn("ml-auto px-2 py-0.5 rounded text-[10px] font-bold", getProfileMeta(selectedProfile).badge)}>
              {selectedProfile.name}
            </span>
          )}
        </div>
        <div className="space-y-4">
          <div className="grid md:grid-cols-[1fr_auto] gap-3">
            <Input placeholder="Enter domain or IP (must be in your assets)" value={scanTarget}
              onChange={(e) => setScanTarget(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleQuickScan()} />
            <Button onClick={handleQuickScan} disabled={!scanTarget.trim()} className="bg-primary hover:bg-primary/90 whitespace-nowrap">
              <Play className="w-4 h-4 mr-2" />Start Scan
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">Run a scan using the selected profile. Results appear in Scan Jobs.</p>
        </div>
      </div>

      {/* Scan Operations */}
      <div className="bg-card border border-border rounded-xl p-6">
        <div className="flex items-center gap-2 mb-5">
          <Target className="w-5 h-5 text-primary" />
          <h2 className="text-lg font-semibold text-foreground">Scan Operations</h2>
        </div>
        <div className="grid sm:grid-cols-2 gap-4">
          <button type="button" onClick={() => setIsScanDialogOpen(true)}
            className="text-left rounded-xl p-5 border border-border bg-muted/20 hover:border-primary/40 transition-all group">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center"><Play className="w-5 h-5 text-primary" /></div>
              <div><h3 className="font-semibold text-foreground text-sm">Scan Asset Group</h3>
                <p className="text-xs text-muted-foreground">Scan all assets in a group</p></div>
              <ChevronRight className="w-4 h-4 text-muted-foreground ml-auto group-hover:text-primary transition-colors" />
            </div>
            <p className="text-xs text-muted-foreground">Uses the selected scan profile above.</p>
          </button>
          <button type="button" onClick={() => setIsScheduleOpen(true)}
            className="text-left rounded-xl p-5 border border-border bg-muted/20 hover:border-primary/40 transition-all group">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-[#00b8d4]/10 flex items-center justify-center"><Calendar className="w-5 h-5 text-[#00b8d4]" /></div>
              <div><h3 className="font-semibold text-foreground text-sm">Schedule Recurring Scan</h3>
                <p className="text-xs text-muted-foreground">Automate scans on a schedule</p></div>
              <ChevronRight className="w-4 h-4 text-muted-foreground ml-auto group-hover:text-[#00b8d4] transition-colors" />
            </div>
            <p className="text-xs text-muted-foreground">Set up daily, weekly, or monthly scans. <a href="/scheduled-scans" className="text-primary hover:underline">Manage schedules →</a></p>
          </button>
        </div>
      </div>

      {/* Active Scans */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="p-6 border-b border-border flex items-center justify-between">
          <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />Active Scans
          </h2>
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="sm" onClick={loadActiveScans} className="text-primary hover:text-primary hover:bg-primary/10">
              <RefreshCcw className="w-4 h-4 mr-2" />Refresh
            </Button>
            <a href="/scan-jobs" className="text-sm text-primary hover:underline">View All Scan Jobs →</a>
          </div>
        </div>
        {loadingScans ? (
          <div className="p-6 text-center text-muted-foreground text-sm">Loading…</div>
        ) : activeScans.length === 0 ? (
          <div className="p-6 bg-muted/20 flex items-center justify-between">
            <span className="text-sm text-muted-foreground">No active scans running</span>
            <Button size="sm" variant="outline" onClick={() => setIsScanDialogOpen(true)} className="border-primary/50 text-primary hover:bg-primary/10">Start New Scan</Button>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {activeScans.map((job) => {
              const assetValue = job.assetValue || `Asset #${job.assetId}`;
              const isRunning = job.status === "running";
              return (
                <div key={job.id} className="p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-foreground text-sm font-mono">{assetValue}</span>
                        {job.profileName && <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-primary/10 text-primary">{job.profileName}</span>}
                      </div>
                      <span className="text-xs text-muted-foreground">{job.groupName || "Unknown Group"}</span>
                    </div>
                    <span className={cn("px-2 py-1 rounded text-xs font-semibold", isRunning ? "bg-[#00b8d4]/10 text-[#00b8d4]" : "bg-muted/50 text-muted-foreground")}>
                      {job.status.toUpperCase()}
                    </span>
                  </div>
                  {isRunning && (
                    <><div className="w-full bg-muted rounded-full h-2 mb-2"><div className="bg-primary h-2 rounded-full transition-all duration-300 animate-pulse" style={{ width: "50%" }} /></div>
                    <div className="text-xs text-muted-foreground">Scanning in progress…</div></>
                  )}
                  {job.status === "queued" && <div className="text-xs text-muted-foreground">Waiting to start…</div>}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Group Scan Dialog */}
      <Dialog open={isScanDialogOpen} onOpenChange={setIsScanDialogOpen}>
        <DialogContent className="bg-card border-border text-foreground">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><Play className="w-5 h-5 text-primary" />Scan Asset Group</DialogTitle>
            <DialogDescription className="text-muted-foreground">All assets in the selected group will be scanned.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label className="text-sm">Target Asset Group</Label>
              <select value={scanAssetGroup} onChange={(e) => setScanAssetGroup(e.target.value)}
                className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                <option value="">Select a group…</option>
                {groups.map((g) => <option key={String(g.id)} value={String(g.id)}>{g.name}</option>)}
              </select>
            </div>
            {selectedProfile && (
              <div className={cn("rounded-lg p-4 border", getProfileMeta(selectedProfile).accentBg)}>
                <div className="flex items-center gap-2 mb-1.5">
                  {React.createElement(getProfileMeta(selectedProfile).icon, { className: cn("w-4 h-4", getProfileMeta(selectedProfile).accent) })}
                  <span className="text-sm font-semibold text-foreground">{selectedProfile.name}</span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {engineList(selectedProfile).map((e) => <span key={e} className="px-2 py-0.5 rounded text-[10px] font-semibold bg-background/50 text-muted-foreground">{e}</span>)}
                </div>
              </div>
            )}
            <div className="bg-muted/30 rounded-lg p-4 flex items-start gap-2">
              <Info className="w-4 h-4 text-muted-foreground mt-0.5 shrink-0" />
              <div className="text-xs text-muted-foreground space-y-1">
                <div>All assets in the selected group will be scanned.</div>
                <div>Change the profile in the Scan Profile section above.</div>
              </div>
            </div>
            <div className="flex gap-3 justify-end pt-2">
              <Button variant="outline" onClick={() => setIsScanDialogOpen(false)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
              <Button onClick={handleGroupScan} disabled={!scanAssetGroup} className="bg-primary hover:bg-primary/90">
                <Play className="w-4 h-4 mr-2" />Start Scan
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <ScheduleModal open={isScheduleOpen} onOpenChange={setIsScheduleOpen} groups={groups} profiles={profiles} setBanner={setBanner} />
    </div>
  );
}

/* ── Main Page ────────────────────────────────────────── */
export default function DiscoveryPage() {
  const [activeTab, setActiveTab] = useState<TabKey>("discover");
  const [discoveryType, setDiscoveryType] = useState<DiscoveryType>("organization");
  const [discoveryValue, setDiscoveryValue] = useState("");
  const [hasResults, setHasResults] = useState(false);
  const [runs, setRuns] = useState<DiscoveryRunListItem[]>([]);
  const [loadingRuns, setLoadingRuns] = useState<boolean>(true);
  const [runningDiscovery, setRunningDiscovery] = useState(false);
  const [selectedRunId, setSelectedRunId] = useState<string | number | null>(null);
  const [selectedRunDetail, setSelectedRunDetail] = useState<DiscoveryRunDetail | null>(null);
  const [searchFilter, setSearchFilter] = useState("");
  const [groups, setGroups] = useState<Array<{ id: any; name: string }>>([]);
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [isImportDialogOpen, setIsImportDialogOpen] = useState(false);
  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);
  const [importedAssets, setImportedAssets] = useState<string[]>([]);
  const [singleAssetToAdd, setSingleAssetToAdd] = useState<string | null>(null);
  const [selectedGroupId, setSelectedGroupId] = useState<string>("");
  const [dialogMode, setDialogMode] = useState<"add" | "scan">("add");
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  async function refreshRuns() {
    try { setLoadingRuns(true); const list = await getDiscoveryRuns(); setRuns(list); }
    catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed to load runs" }); }
    finally { setLoadingRuns(false); }
  }

  async function refreshGroups() {
    try {
      setLoadingGroups(true);
      const gs = await getGroups();
      const simple = gs.map((g) => ({ id: g.id, name: g.name }));
      setGroups(simple);
      if (!selectedGroupId && simple.length) setSelectedGroupId(String(simple[0].id));
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed to load groups" }); }
    finally { setLoadingGroups(false); }
  }

  async function loadRunDetail(runId: string | number) {
    try { const detail = await getDiscoveryRun(runId); setSelectedRunDetail(detail); setSelectedRunId(runId); }
    catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed to load run" }); }
  }

  async function handleDeleteRun(runId: string | number, e: React.MouseEvent) {
    e.stopPropagation();
    if (!confirm("Delete this discovery run?")) return;
    try {
      await deleteDiscoveryRun(runId);
      setBanner({ kind: "ok", text: "Deleted." });
      if (String(selectedRunId) === String(runId)) { setHasResults(false); setSelectedRunId(null); setSelectedRunDetail(null); }
      await refreshRuns();
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Delete failed" }); }
  }

  useEffect(() => { refreshRuns(); refreshGroups(); }, []);

  const derivedCounts = useMemo(() => {
    const base = (selectedRunDetail as any)?.result?.counts || (selectedRunDetail as any)?.counts || (selectedRunDetail as any)?.summary?.counts || runs.find((r) => String(r.id) === String(selectedRunId))?.counts || {};
    const subdomains = (selectedRunDetail as any)?.result?.subdomains?.length ?? (selectedRunDetail as any)?.result?.domains?.length ?? base.subdomains ?? base.total_subdomains ?? 0;
    const ips = base.uniqueIps ?? base.unique_ips ?? (() => { const resolved = (selectedRunDetail as any)?.result?.resolved || {}; const s = new Set<string>(); Object.values(resolved).forEach((ipList: any) => { if (Array.isArray(ipList)) ipList.forEach((ip) => s.add(ip)); }); return s.size; })();
    return { subdomains: Number(subdomains || 0), ips: Number(ips || 0) };
  }, [runs, selectedRunDetail, selectedRunId]);

  const totalAssets = useMemo(() => Number((selectedRunDetail as any)?.result?.subdomains?.length ?? derivedCounts.subdomains ?? 0), [derivedCounts.subdomains, selectedRunDetail]);
  const totalIPs = useMemo(() => Number(derivedCounts.ips || 0), [derivedCounts.ips]);

  function toggleAssetSelection(asset: string) { setSelectedAssets((prev) => prev.includes(asset) ? prev.filter((a) => a !== asset) : [...prev, asset]); }
  function openAddDialogForAssets(assets: string[]) { setDialogMode("add"); setSingleAssetToAdd(null); setSelectedAssets(assets); setIsImportDialogOpen(true); }
  function openAddDialogForSingle(asset: string) { setDialogMode("add"); setSingleAssetToAdd(asset); setIsImportDialogOpen(true); }
  function openScanDialogForSingle(asset: string) { setDialogMode("scan"); setSingleAssetToAdd(asset); setIsImportDialogOpen(true); }

  async function confirmImportOrScan() {
    setBanner(null);
    if (!selectedGroupId) { setBanner({ kind: "err", text: "No group selected." }); return; }
    const assetsToProcess = singleAssetToAdd ? [singleAssetToAdd] : selectedAssets;
    if (!assetsToProcess.length) { setBanner({ kind: "err", text: "No assets selected." }); return; }
    try {
      if (dialogMode === "add") {
        for (const value of assetsToProcess) await addAssetToGroup(selectedGroupId, { type: "domain", value });
        setImportedAssets((prev) => [...new Set([...prev, ...assetsToProcess])]);
        setBanner({ kind: "ok", text: `Added ${assetsToProcess.length} asset(s).` });
      } else {
        const { job } = await addAssetToGroupAndScan({ groupId: selectedGroupId, type: "domain", value: assetsToProcess[0] });
        setImportedAssets((prev) => [...new Set([...prev, assetsToProcess[0]])]);
        setBanner({ kind: "ok", text: `Scan started (Job #${job.id}).` });
      }
      setIsImportDialogOpen(false); setSelectedAssets([]); setSingleAssetToAdd(null);
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed." }); }
  }

  async function handleDiscover() {
    setBanner(null);
    if (!discoveryValue.trim()) return;
    if (discoveryType !== "domain") { setBanner({ kind: "err", text: 'Backend discovery supports "domain" only.' }); return; }
    setRunningDiscovery(true);
    try {
      const res: DiscoveryDomainResponse = await discoveryDomain({ domain: discoveryValue.trim(), options: { includeApex: true, resolveIps: true, resolveMaxNames: 300, useCt: true, useDnsBrute: true } });
      await refreshRuns();
      const newest = (await getDiscoveryRuns())[0];
      if (newest?.id != null) await loadRunDetail(newest.id);
      setHasResults(true);
      setBanner({ kind: "ok", text: res?.status ? String(res.status) : "Discovery completed." });
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Discovery failed" }); }
    finally { setRunningDiscovery(false); }
  }

  const recentDiscoveries = useMemo(() => {
    return runs.slice(0, 50).map((r) => {
      const asset = r.domain || (r as any)?.input?.value || "unknown";
      const counts = (r as any)?.counts || {};
      const subdomains = counts.subdomains ?? counts.total_subdomains ?? 0;
      let ipCount = counts.uniqueIps ?? counts.unique_ips ?? 0;
      if (ipCount === 0) { const resolved = (r as any)?.result?.resolved || {}; const s = new Set<string>(); Object.values(resolved).forEach((ipList: any) => { if (Array.isArray(ipList)) ipList.forEach((ip: string) => s.add(ip)); }); ipCount = s.size; }
      return { id: r.id, asset, subdomains: Number(subdomains || 0), ips: ipCount, discovered: r.createdAt ? formatWhen(r.createdAt) : "", status: (r.status || "").toLowerCase().includes("completed") ? "Added" : "New" };
    });
  }, [runs]);

  const filteredDiscoveries = useMemo(() => {
    if (!searchFilter.trim()) return recentDiscoveries;
    const s = searchFilter.toLowerCase();
    return recentDiscoveries.filter((item) => item.asset.toLowerCase().includes(s));
  }, [recentDiscoveries, searchFilter]);

  const discoveredSubdomains = useMemo(() => {
    const subs = (selectedRunDetail as any)?.result?.subdomains || [];
    const resolved = (selectedRunDetail as any)?.result?.resolved || {};
    return subs.map((domain: string) => ({ domain, ip: (resolved[domain] || []).join(", ") || "-" }));
  }, [selectedRunDetail]);

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8">
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Radar className="w-8 h-8 text-[#00b8d4]" />
            <h1 className="text-2xl font-semibold text-foreground">Discovery &amp; Scanning</h1>
          </div>
          <p className="text-muted-foreground">Discover new assets and scan your attack surface for vulnerabilities.</p>
        </div>

        {banner && (
          <div className={cn("mb-6 rounded-xl border px-4 py-3 text-sm", banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>
            {banner.text}
          </div>
        )}

        <div className="grid w-full max-w-md grid-cols-2 mb-8 rounded-xl bg-muted/30 p-1">
          <button type="button" onClick={() => setActiveTab("discover")}
            className={cn("h-10 rounded-lg text-sm font-medium inline-flex items-center justify-center gap-2 transition", activeTab === "discover" ? "bg-background/40 border border-border text-foreground" : "text-muted-foreground hover:text-foreground")}>
            <Radar className="w-4 h-4" />Asset Discovery
          </button>
          <button type="button" onClick={() => setActiveTab("scan")}
            className={cn("h-10 rounded-lg text-sm font-medium inline-flex items-center justify-center gap-2 transition", activeTab === "scan" ? "bg-background/40 border border-border text-foreground" : "text-muted-foreground hover:text-foreground")}>
            <Activity className="w-4 h-4" />Scanning
          </button>
        </div>

        {/* DISCOVER TAB */}
        {activeTab === "discover" && (
          <div className="space-y-8">
            <div className="bg-card border border-[#00b8d4]/20 rounded-xl p-6 shadow-[0_0_20px_rgba(0,184,212,0.1)]">
              <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-2"><Search className="w-5 h-5 text-[#00b8d4]" /><h2 className="text-lg font-semibold text-foreground">Discover Assets</h2></div>
                <Button variant="outline" onClick={refreshRuns} className="border-border text-foreground hover:bg-accent"><RefreshCcw className="w-4 h-4 mr-2" />Refresh</Button>
              </div>
              <div className="mt-6 space-y-4">
                <div className="grid md:grid-cols-[200px_1fr_auto] gap-3">
                  <select value={discoveryType} onChange={(e) => setDiscoveryType(e.target.value as DiscoveryType)}
                    className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-ring">
                    <option value="organization">Organization</option><option value="domain">Domain</option><option value="ip">IP</option>
                  </select>
                  <Input placeholder={discoveryType === "organization" ? "Acme Corp" : discoveryType === "domain" ? "example.com" : "8.8.8.8"}
                    value={discoveryValue} onChange={(e) => setDiscoveryValue(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleDiscover()} />
                  <Button onClick={handleDiscover} disabled={runningDiscovery || !discoveryValue.trim()} className="bg-[#00b8d4] hover:bg-[#00b8d4]/90 whitespace-nowrap">
                    <Radar className="w-4 h-4 mr-2" />{runningDiscovery ? "Discovering…" : "Discover"}
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">Discovery scans public records, DNS, and certificate transparency logs.</p>
              </div>
            </div>

            {hasResults ? (
              <>
                <div className="grid sm:grid-cols-3 gap-6">
                  <div className="bg-card border border-border rounded-xl p-6"><Globe className="w-8 h-8 text-primary mb-3" /><div className="text-3xl font-bold text-foreground mb-1">{totalAssets}</div><div className="text-sm text-muted-foreground">Total Assets</div></div>
                  <div className="bg-card border border-border rounded-xl p-6"><Network className="w-8 h-8 text-[#00b8d4] mb-3" /><div className="text-3xl font-bold text-foreground mb-1">{derivedCounts.subdomains}</div><div className="text-sm text-muted-foreground">Subdomains</div></div>
                  <div className="bg-card border border-border rounded-xl p-6"><Server className="w-8 h-8 text-[#ffcc00] mb-3" /><div className="text-3xl font-bold text-foreground mb-1">{totalIPs}</div><div className="text-sm text-muted-foreground">Unique IPs</div></div>
                </div>

                {selectedAssets.length > 0 && (
                  <div className="bg-primary/10 border border-primary/20 rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                    <span className="text-foreground font-medium">{selectedAssets.length} asset{selectedAssets.length !== 1 ? "s" : ""} selected</span>
                    <Button onClick={() => openAddDialogForAssets(selectedAssets)} className="bg-primary hover:bg-primary/90"><Plus className="w-4 h-4 mr-2" />Add to Asset Group</Button>
                  </div>
                )}

                <div className="bg-card border border-border rounded-xl overflow-hidden">
                  <div className="p-6 border-b border-border flex items-center justify-between">
                    <h2 className="text-lg font-semibold text-foreground flex items-center gap-2"><Network className="w-5 h-5 text-[#00b8d4]" />Discovered Subdomains</h2>
                    {selectedRunId && <Button variant="outline" onClick={() => loadRunDetail(selectedRunId)} className="border-border text-foreground hover:bg-accent">Refresh run #{String(selectedRunId)}</Button>}
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead className="bg-muted/30"><tr>
                        <th className="p-4 w-12"><input type="checkbox" className="w-4 h-4 rounded border-border" onChange={(e) => { if (e.target.checked) setSelectedAssets(discoveredSubdomains.map((s: any) => s.domain).filter(Boolean)); else setSelectedAssets([]); }} /></th>
                        <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Domain</th>
                        <th className="text-left p-4 text-sm font-semibold text-muted-foreground">IP Address</th>
                        <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Status</th>
                        <th className="text-right p-4 text-sm font-semibold text-muted-foreground">Actions</th>
                      </tr></thead>
                      <tbody className="divide-y divide-border">
                        {discoveredSubdomains.map((sub: { domain: string; ip: string }, idx: number) => {
                          const domain = sub.domain || `asset-${idx}`;
                          const isAdded = importedAssets.includes(domain);
                          return (
                            <tr key={domain + idx} className="hover:bg-accent/30 transition-colors">
                              <td className="p-4"><input type="checkbox" className="w-4 h-4 rounded border-border" checked={selectedAssets.includes(domain)} onChange={() => toggleAssetSelection(domain)} /></td>
                              <td className="p-4 text-foreground font-mono text-sm">{domain}</td>
                              <td className="p-4 text-muted-foreground font-mono text-sm">{sub.ip}</td>
                              <td className="p-4"><span className="inline-flex items-center gap-1 px-2 py-1 bg-[#10b981]/10 text-[#10b981] rounded text-xs font-semibold"><CheckCircle2 className="w-3 h-3" />Active</span></td>
                              <td className="p-4 text-right">
                                <div className="inline-flex items-center gap-2">
                                  {isAdded ? (
                                    <span className="inline-flex items-center gap-1 px-3 py-1.5 bg-[#10b981]/10 text-[#10b981] rounded text-xs font-semibold"><Check className="w-3 h-3" />Added</span>
                                  ) : (
                                    <Button size="sm" variant="outline" onClick={() => openAddDialogForSingle(domain)} className="border-primary/50 text-primary hover:bg-primary/10"><FolderPlus className="w-3 h-3 mr-1" />Add to Group</Button>
                                  )}
                                  <Button size="sm" onClick={() => openScanDialogForSingle(domain)} className="bg-primary hover:bg-primary/90"><Play className="w-3 h-3 mr-1" />Scan</Button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            ) : (
              <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="p-6 border-b border-border flex items-center justify-between gap-4">
                  <h2 className="text-lg font-semibold text-foreground flex items-center gap-2"><Clock className="w-5 h-5 text-[#00b8d4]" />Recent Discoveries</h2>
                  <div className="flex items-center gap-3">
                    <div className="relative"><Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" /><Input placeholder="Search…" value={searchFilter} onChange={(e) => setSearchFilter(e.target.value)} className="pl-9 w-64 h-9" /></div>
                    <div className="text-xs text-muted-foreground">{loadingRuns ? "Loading…" : `${filteredDiscoveries.length} of ${runs.length} run(s)`}</div>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-muted/30"><tr>
                      <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Asset</th>
                      <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Subdomains</th>
                      <th className="text-left p-4 text-sm font-semibold text-muted-foreground">IP Addresses</th>
                      <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Discovered</th>
                      <th className="text-right p-4 text-sm font-semibold text-muted-foreground">Actions</th>
                    </tr></thead>
                    <tbody className="divide-y divide-border">
                      {filteredDiscoveries.map((item) => (
                        <tr key={String(item.id)} onClick={() => { loadRunDetail(item.id); setHasResults(true); }} className="cursor-pointer hover:bg-accent/30 transition-colors">
                          <td className="p-4"><div className="flex flex-col gap-1"><span className="font-mono text-sm text-foreground">{item.asset}</span><span className={cn("w-fit px-2 py-0.5 rounded text-xs font-semibold", statusBadgeClass(item.status))}>{item.status}</span></div></td>
                          <td className="p-4">{item.subdomains > 0 ? <span className="inline-flex items-center gap-1 px-2 py-1 bg-[#00b8d4]/10 text-[#00b8d4] rounded text-xs font-semibold"><Network className="w-3 h-3" />{item.subdomains}</span> : <span className="text-xs text-muted-foreground">-</span>}</td>
                          <td className="p-4">{item.ips > 0 ? <span className="inline-flex items-center gap-1 px-2 py-1 bg-[#ffcc00]/10 text-[#ffcc00] rounded text-xs font-semibold"><Server className="w-3 h-3" />{item.ips}</span> : <span className="text-xs text-muted-foreground">-</span>}</td>
                          <td className="p-4"><span className="text-xs text-muted-foreground flex items-center gap-1"><Clock className="w-3 h-3" />{item.discovered}</span></td>
                          <td className="p-4"><div className="flex items-center justify-end gap-2">
                            <Button size="sm" variant="outline" onClick={(e) => { e.stopPropagation(); openAddDialogForSingle(item.asset); }} className="border-primary/50 text-primary hover:bg-primary/10"><FolderPlus className="w-3 h-3 mr-1" />Add to Group</Button>
                            <Button size="sm" onClick={(e) => { e.stopPropagation(); openScanDialogForSingle(item.asset); }} className="bg-primary hover:bg-primary/90"><Play className="w-3 h-3 mr-1" />Scan</Button>
                            <Button size="sm" variant="outline" onClick={(e) => handleDeleteRun(item.id, e)} className="border-red-500/50 text-red-500 hover:bg-red-500/10"><Trash2 className="w-3 h-3" /></Button>
                          </div></td>
                        </tr>
                      ))}
                      {!loadingRuns && filteredDiscoveries.length === 0 && searchFilter.trim() && <tr><td colSpan={5} className="p-6 text-sm text-muted-foreground text-center">No discoveries matching &quot;{searchFilter}&quot;</td></tr>}
                      {!loadingRuns && recentDiscoveries.length === 0 && <tr><td colSpan={5} className="p-6 text-sm text-muted-foreground text-center">No discovery runs yet.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* SCAN TAB */}
        {activeTab === "scan" && <ScanningTab groups={groups} setBanner={setBanner} />}

        {/* Import / Scan Dialog */}
        <Dialog open={isImportDialogOpen} onOpenChange={setIsImportDialogOpen}>
          <DialogContent className="bg-card border-border text-foreground">
            <DialogHeader>
              <DialogTitle>{dialogMode === "scan" ? "Scan Asset" : "Add Asset to Group"}</DialogTitle>
              <DialogDescription className="text-muted-foreground">
                {singleAssetToAdd ? (<>{dialogMode === "scan" ? "Scan " : "Add "}<span className="font-mono text-foreground">{singleAssetToAdd}</span>{dialogMode === "scan" ? " (appears in Scan Jobs)." : " to an Asset Group."}</>) : (<>Add {selectedAssets.length} selected assets.</>)}
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label className="text-sm font-medium text-foreground mb-2 block">Select Asset Group</Label>
                <select value={selectedGroupId} onChange={(e) => setSelectedGroupId(e.target.value)} disabled={loadingGroups}
                  className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-60">
                  {groups.map((g) => <option key={String(g.id)} value={String(g.id)}>{g.name}</option>)}
                  {!groups.length && <option value="">No groups found</option>}
                </select>
                {!loadingGroups && !groups.length && <div className="mt-2 text-xs text-muted-foreground">Create a group on the Assets page first.</div>}
              </div>
              <div className="flex gap-3 justify-end pt-4">
                <Button variant="outline" onClick={() => { setIsImportDialogOpen(false); setSingleAssetToAdd(null); }} className="border-border text-foreground hover:bg-accent">Cancel</Button>
                <Button onClick={confirmImportOrScan} disabled={!selectedGroupId || (!singleAssetToAdd && !selectedAssets.length)} className="bg-primary hover:bg-primary/90">
                  {dialogMode === "scan" ? <><Play className="w-4 h-4 mr-2" />Start Scan</> : <><FolderPlus className="w-4 h-4 mr-2" />Add to Group</>}
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </main>
  );
}