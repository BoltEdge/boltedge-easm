// FILE: app/(authenticated)/scan/initiate/page.tsx
// Initiate Scan — profile selector, asset search, group browse, start scan
// ✅ M9 RBAC: start_scans + bulk_scan permissions, isPlanError handling
"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Play, Search, Shield, ShieldCheck, ShieldAlert, Zap, Target,
  Timer, Check, Info, Loader2,
} from "lucide-react";
import { Button } from "../../../ui/button";
import { Input } from "../../../ui/input";
import { useOrg } from "../../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../../ui/plan-limit-dialog";
import {
  getScanProfiles, getAllAssets, getGroupAssets, getGroups,
  createScanJob, runScanJob, isPlanError,
} from "../../../lib/api";
import type { ScanProfile } from "../../../types";

function cn(...parts: Array<string | false | null | undefined>) { return parts.filter(Boolean).join(" "); }

function getProfileMeta(profile: ScanProfile) {
  const name = (profile.name || "").toLowerCase();
  if (name.includes("deep")) return { icon: ShieldAlert, accent: "text-[#ff8800]", accentBg: "bg-[#ff8800]/10 border-[#ff8800]/30", badge: "bg-[#ff8800]/10 text-[#ff8800]", duration: "2-4 hours", depth: "Maximum depth" };
  if (name.includes("standard")) return { icon: ShieldCheck, accent: "text-primary", accentBg: "bg-primary/10 border-primary/30", badge: "bg-primary/10 text-primary", duration: "30-60 min", depth: "Full coverage" };
  return { icon: Zap, accent: "text-[#00b8d4]", accentBg: "bg-[#00b8d4]/10 border-[#00b8d4]/30", badge: "bg-[#00b8d4]/10 text-[#00b8d4]", duration: "5-10 min", depth: "Essential checks" };
}

function engineList(profile: ScanProfile): string[] {
  const features: string[] = [];
  if (profile.useShodan) features.push("Host Intelligence");
  if (profile.useNmap) features.push("Port Scanning");
  if (profile.useNuclei) features.push("Vulnerability Detection");
  if (profile.useSslyze) features.push("SSL/TLS Analysis");
  if (profile.shodanIncludeHistory) features.push("Historical Data");
  if (profile.shodanIncludeCves) features.push("CVE Database");
  if (profile.shodanIncludeDns) features.push("DNS Records");
  return features;
}

function ProfileCard({ profile, selected, onSelect }: { profile: ScanProfile; selected: boolean; onSelect: () => void }) {
  const meta = getProfileMeta(profile);
  const Icon = meta.icon;
  const engines = engineList(profile);
  return (
    <button type="button" onClick={onSelect}
      className={cn("relative text-left rounded-xl p-5 border transition-all duration-200 hover:scale-[1.02] active:scale-[0.98]",
        selected ? cn(meta.accentBg, "ring-1", meta.accent.replace("text-", "ring-")) : "bg-muted/30 border-border hover:border-primary/30")}>
      <div className="flex items-center gap-2.5 mb-3"><Icon className={cn("w-5 h-5", meta.accent)} /><h3 className="font-semibold text-foreground">{profile.name}</h3></div>
      <p className="text-xs text-muted-foreground mb-4 line-clamp-2">{profile.description || "No description"}</p>
      <div className="flex flex-wrap gap-1.5 mb-4">{engines.map((e) => <span key={e} className="px-2 py-0.5 rounded-md text-[10px] font-semibold bg-muted/50 text-muted-foreground border border-border/50">{e}</span>)}</div>
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1"><Timer className="w-3 h-3" />{meta.duration}</span>
        <span className="flex items-center gap-1"><Target className="w-3 h-3" />{meta.depth}</span>
      </div>
      {selected && <div className={cn("absolute bottom-3 right-3 w-5 h-5 rounded-full flex items-center justify-center", meta.badge)}><Check className="w-3 h-3" /></div>}
    </button>
  );
}

export default function InitiateScanPage() {
  const router = useRouter();
  const { canDo } = useOrg();
  const planLimit = usePlanLimit();
  const canStart = canDo("start_scans");
  const canBulk = canDo("bulk_scan");

  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState("");
  const [groups, setGroups] = useState<Array<{ id: any; name: string }>>([]);
  const [loadingInit, setLoadingInit] = useState(true);
  const [selGroupId, setSelGroupId] = useState("");
  const [selAssetId, setSelAssetId] = useState("");
  const [assets, setAssets] = useState<any[]>([]);
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [allAssets, setAllAssets] = useState<any[]>([]);

  const selectedProfile = useMemo(() => profiles.find((p) => p.id === selectedProfileId) ?? null, [profiles, selectedProfileId]);

  useEffect(() => {
    Promise.all([getScanProfiles(), getGroups(), getAllAssets()]).then(([p, g, a]) => {
      const order = (name: string) => { const n = name.toLowerCase(); if (n.includes("quick")) return 0; if (n.includes("standard")) return 1; if (n.includes("deep")) return 2; return 3; };
      const sorted = [...p].sort((a, b) => order(a.name) - order(b.name));
      setProfiles(sorted);
      const def = sorted.find((x) => x.isDefault);
      setSelectedProfileId(def ? def.id : sorted.length ? sorted[0].id : "");
      setGroups(g.map((x) => ({ id: x.id, name: x.name })));
      setAllAssets(a || []);
    }).catch(() => {}).finally(() => setLoadingInit(false));
  }, []);

  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 5000); return () => clearTimeout(t); } }, [banner]);

  const searchResults = useMemo(() => {
    if (!searchQuery.trim() || searchQuery.trim().length < 2) return [];
    const q = searchQuery.toLowerCase();
    return allAssets.filter((a: any) => (a.value || "").toLowerCase().includes(q)).slice(0, 10);
  }, [searchQuery, allAssets]);

  useEffect(() => {
    if (!searchOpen) return;
    const handler = (e: MouseEvent) => { if (!(e.target as HTMLElement).closest("[data-search-container]")) setSearchOpen(false); };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [searchOpen]);

  useEffect(() => {
    if (!selGroupId) { setAssets([]); setSelAssetId(""); return; }
    let cancelled = false;
    setLoadingAssets(true); setSelAssetId("");
    getGroupAssets(selGroupId).then((a) => { if (!cancelled) setAssets(a || []); }).catch(() => { if (!cancelled) setAssets([]); }).finally(() => { if (!cancelled) setLoadingAssets(false); });
    return () => { cancelled = true; };
  }, [selGroupId]);

  async function handleScanSingle() {
    if (!selAssetId) { setBanner({ kind: "err", text: "Select an asset." }); return; }
    try {
      setScanning(true);
      const job = await createScanJob(selAssetId, selectedProfileId || undefined);
      await runScanJob(String(job.id));
      setBanner({ kind: "ok", text: `Scan started! Redirecting to Scan Jobs...` });
      setTimeout(() => router.push("/scan"), 1200);
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed to start scan." });
    } finally { setScanning(false); }
  }

  async function handleScanGroup() {
    if (!selGroupId) { setBanner({ kind: "err", text: "Select a group." }); return; }
    if (!assets.length) { setBanner({ kind: "err", text: "No assets in this group." }); return; }
    try {
      setScanning(true);
      let created = 0;
      for (const asset of assets) {
        try {
          const job = await createScanJob(String(asset.id), selectedProfileId || undefined);
          await runScanJob(String(job.id));
          created++;
        } catch (e: any) {
          if (isPlanError(e)) { planLimit.handle(e.planError); setScanning(false); return; }
        }
      }
      setBanner({ kind: "ok", text: `Started ${created} scan(s). Redirecting...` });
      setTimeout(() => router.push("/scan"), 1200);
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    } finally { setScanning(false); }
  }

  if (loadingInit) return <main className="flex-1 bg-background p-8"><div className="text-muted-foreground text-sm">Loading...</div></main>;

  if (!canStart) {
    return (
      <main className="flex-1 overflow-y-auto bg-background">
        <div className="p-8 text-center py-20">
          <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto mb-4">
            <Zap className="w-8 h-8 text-primary" />
          </div>
          <h2 className="text-xl font-semibold text-foreground mb-2">Scan Initiation</h2>
          <p className="text-muted-foreground text-sm">You don&apos;t have permission to start scans. Ask an admin or owner to initiate scans or upgrade your role.</p>
        </div>
      </main>
    );
  }

  const selectedGroupName = groups.find((g) => String(g.id) === selGroupId)?.name;

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8 space-y-8">
        <div>
          <h1 className="text-2xl font-semibold text-foreground flex items-center gap-3"><Zap className="w-7 h-7 text-primary" />Initiate Scan</h1>
          <p className="text-muted-foreground mt-1">Choose a profile, select a target, and start scanning.</p>
        </div>

        {banner && (
          <div className={cn("rounded-xl border px-4 py-3 text-sm", banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>{banner.text}</div>
        )}

        {/* Profile Selector */}
        <div className="bg-card border border-border rounded-xl p-6">
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-2"><Shield className="w-5 h-5 text-primary" /><h2 className="text-lg font-semibold text-foreground">Scan Profile</h2></div>
            <span className="text-xs text-muted-foreground">{profiles.length} profile{profiles.length !== 1 ? "s" : ""} available</span>
          </div>
          {profiles.length === 0 ? <div className="text-sm text-muted-foreground py-4">No scan profiles found.</div> : (
            <div className="grid sm:grid-cols-3 gap-4">{profiles.map((p) => <ProfileCard key={p.id} profile={p} selected={selectedProfileId === p.id} onSelect={() => setSelectedProfileId(p.id)} />)}</div>
          )}
        </div>

        {/* Scan Target */}
        <div className="bg-card border border-primary/20 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-5">
            <Zap className="w-5 h-5 text-primary" /><h2 className="text-lg font-semibold text-foreground">Scan Target</h2>
            {selectedProfile && <span className={cn("ml-auto px-2 py-0.5 rounded text-[10px] font-bold", getProfileMeta(selectedProfile).badge)}>{selectedProfile.name}</span>}
          </div>
          <div className="space-y-4">
            {/* Search */}
            <div className="space-y-1.5" data-search-container>
              <label className="text-sm font-medium text-foreground block">Search Asset</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                <Input placeholder="Search by domain, IP, or hostname..." value={searchQuery}
                  onChange={(e) => { setSearchQuery(e.target.value); setSelAssetId(""); setSelGroupId(""); }}
                  onFocus={() => setSearchOpen(true)} className="pl-9" />
                {searchOpen && searchQuery.trim().length >= 2 && (
                  <div className="absolute z-50 top-full left-0 right-0 mt-1 bg-card border border-border rounded-lg shadow-xl max-h-64 overflow-y-auto">
                    {searchResults.length === 0 ? (
                      <div className="px-4 py-3 text-sm text-muted-foreground">No assets match &quot;{searchQuery}&quot;</div>
                    ) : searchResults.map((a: any) => (
                      <button key={String(a.id)} type="button"
                        className="w-full text-left px-4 py-2.5 hover:bg-accent/30 transition-colors flex items-center justify-between gap-3 border-b border-border/50 last:border-0"
                        onClick={() => { setSelAssetId(String(a.id)); setSelGroupId(String(a.group_id || a.groupId || "")); setSearchQuery(a.value); setSearchOpen(false); }}>
                        <div className="min-w-0"><div className="text-sm font-mono text-foreground truncate">{a.value}</div><div className="text-xs text-muted-foreground">{a.groupName || a.group_name || "No group"} · {a.type || "domain"}</div></div>
                        <Target className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <div className="flex items-center gap-3"><div className="flex-1 h-px bg-border" /><span className="text-xs text-muted-foreground uppercase">or browse by group</span><div className="flex-1 h-px bg-border" /></div>
            <div className="grid md:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-foreground block">Asset Group</label>
                <select value={selGroupId} onChange={(e) => { setSelGroupId(e.target.value); setSelAssetId(""); setSearchQuery(""); }}
                  className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm">
                  <option value="">Select a group...</option>
                  {groups.map((g) => <option key={String(g.id)} value={String(g.id)}>{g.name}</option>)}
                </select>
              </div>
              {selGroupId && (
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-foreground block">Asset <span className="text-muted-foreground font-normal">(blank = scan all)</span></label>
                  <select value={selAssetId} onChange={(e) => { setSelAssetId(e.target.value); setSearchQuery(e.target.value ? (assets.find((a: any) => String(a.id) === e.target.value)?.value || "") : ""); }}
                    disabled={loadingAssets} className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm disabled:opacity-50">
                    <option value="">{loadingAssets ? "Loading..." : `All assets (${assets.length})`}</option>
                    {assets.map((a: any) => <option key={String(a.id)} value={String(a.id)}>{a.value}</option>)}
                  </select>
                </div>
              )}
            </div>

            {/* Bulk scan permission notice */}
            {selGroupId && !selAssetId && assets.length > 0 && !canBulk && (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#ff8800]/5 border border-[#ff8800]/20 text-xs text-muted-foreground">
                <Info className="w-3.5 h-3.5 text-[#ff8800] shrink-0" />
                Group scanning requires bulk scan permission. Select a single asset or ask an admin to upgrade your role.
              </div>
            )}

            {selGroupId && !selAssetId && assets.length > 0 && canBulk && (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#00b8d4]/5 border border-[#00b8d4]/20 text-xs text-muted-foreground">
                <Info className="w-3.5 h-3.5 text-[#00b8d4] shrink-0" />
                Scanning all <span className="font-semibold text-foreground">{assets.length}</span> asset{assets.length !== 1 ? "s" : ""} in <span className="font-semibold text-foreground">{selectedGroupName}</span>
              </div>
            )}

            <div className="flex items-center gap-3 pt-1">
              {selAssetId ? (
                <Button onClick={handleScanSingle} disabled={scanning} className="bg-primary hover:bg-primary/90"><Play className="w-4 h-4 mr-2" />{scanning ? "Starting..." : "Scan Asset"}</Button>
              ) : (
                <Button onClick={handleScanGroup} disabled={!selGroupId || scanning || assets.length === 0 || !canBulk} className="bg-primary hover:bg-primary/90"><Play className="w-4 h-4 mr-2" />{scanning ? "Starting..." : selGroupId ? `Scan Group (${assets.length})` : "Start Scan"}</Button>
              )}
              <p className="text-xs text-muted-foreground">Results appear in the Scan Jobs page.</p>
            </div>
          </div>
        </div>
      </div>

      <PlanLimitDialog {...planLimit} />
    </main>
  );
}