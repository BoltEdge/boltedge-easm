"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Play, Search, Shield, ShieldCheck, ShieldAlert, Zap, Target,
  Timer, Check, Info, Loader2, Shuffle, ChevronDown, ChevronUp,
} from "lucide-react";
import { Button } from "../../../ui/button";
import { Input } from "../../../ui/input";
import { useOrg } from "../../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../../ui/plan-limit-dialog";
import {
  getScanProfiles, getAllAssets, getGroupAssets, getGroups,
  createScanJob, runScanJob, isPlanError, apiFetch,
} from "../../../lib/api";
import type { ScanProfile } from "../../../types";

function cn(...parts: Array<string | false | null | undefined>) { return parts.filter(Boolean).join(" "); }

function getProfileMeta(profile: ScanProfile) {
  const name = (profile.name || "").toLowerCase();
  // Duration ranges reflect realistic typical scan durations against
  // a single asset, with the upper bound matching the per-profile
  // vulnerability-scanning cap configured in the orchestrator.
  if (name.includes("deep") || name.includes("full")) {
    return {
      icon: ShieldAlert,
      accent: "text-[#ff8800]",
      accentBg: "bg-[#ff8800]/10 border-[#ff8800]/30",
      badge: "bg-[#ff8800]/10 text-[#ff8800]",
      duration: "30 min – 2 hr",
      depth: "Full sweep — ports, services, CVEs, TLS, all severities",
    };
  }
  if (name.includes("standard")) {
    return {
      icon: ShieldCheck,
      accent: "text-primary",
      accentBg: "bg-primary/10 border-primary/30",
      badge: "bg-primary/10 text-primary",
      duration: "5 – 30 min",
      depth: "Critical / High / Medium severity",
    };
  }
  return {
    icon: Zap,
    accent: "text-[#00b8d4]",
    accentBg: "bg-[#00b8d4]/10 border-[#00b8d4]/30",
    badge: "bg-[#00b8d4]/10 text-[#00b8d4]",
    duration: "~2 min",
    depth: "Surface-level check",
  };
}

function engineList(profile: ScanProfile): string[] {
  const features: string[] = [];
  if (profile.useShodan) features.push("Host Intelligence");
  if (profile.useNmap) features.push("Port Scanning");
  if (profile.useNuclei) features.push("Vulnerability Detection");
  if (profile.useSslyze) features.push("SSL/TLS Analysis");
  // useLeak is a single backend toggle but covers three distinct
  // capabilities; surface them separately so users picking a profile
  // can see at a glance that the scan checks for GitHub-leaked
  // credentials, not just port/CVE vulnerabilities.
  if (profile.useLeak) {
    features.push("Exposed File Probe");
    features.push("GitHub Leak Scan");
    features.push("GitLab Leak Scan");
  }
  if (profile.shodanIncludeHistory) features.push("Historical Data");
  if (profile.shodanIncludeCves) features.push("CVE Database");
  if (profile.shodanIncludeDns) features.push("DNS Records");
  return features;
}

/** Plan-usage hint — only renders when org context has both billing
 *  usage and a finite scansPerMonth cap. Designed to slot inside the
 *  "What you'll get" card without forcing a layout shift when data
 *  isn't available. */
function ScansThisMonthHint() {
  const { billing } = useOrg();
  const used = billing?.usage?.scansThisMonth;
  const limit = billing?.limits?.scansPerMonth;
  if (used == null || limit == null) return null;
  if (limit === -1) return null; // unlimited — no need to surface
  const remaining = Math.max(0, limit - used);
  const pct = Math.round((used / limit) * 100);
  const warn = remaining <= 5 || pct >= 90;
  return (
    <div className={cn(
      "mt-3 pt-3 border-t flex items-center justify-between gap-3 text-[11px]",
      warn ? "border-amber-500/20" : "border-primary/15",
    )}>
      <span className={cn(warn ? "text-amber-300" : "text-muted-foreground")}>
        <span className="font-semibold text-foreground tabular-nums">{used.toLocaleString()}</span>
        <span className="text-muted-foreground"> / {limit.toLocaleString()} scans used this month</span>
        {warn && <span className="ml-2 text-amber-400">· nearly out</span>}
      </span>
      <span className="text-muted-foreground tabular-nums">{remaining.toLocaleString()} left</span>
    </div>
  );
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
  // When enabled, every scan launched from this page also enables
  // lookalike monitoring on the target asset and triggers an immediate
  // Lookalike Scan. Plan-limit errors surface; other failures are
  // silent so they never block the primary scan flow.
  const [alsoLookalike, setAlsoLookalike] = useState(false);
  // Collapsed by default — profile picking is a once-per-session
  // decision, no need to dominate the page after that. The user can
  // expand the section to switch profiles.
  const [profileOpen, setProfileOpen] = useState(false);
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
  // "Unscanned only" filter on the per-group asset picker. An asset
  // is unscanned when it has no lastScanAt — i.e., no scan job has
  // ever completed against it. Useful for surfacing newly-added assets
  // a user wants to onboard with a first scan.
  const [unscannedOnly, setUnscannedOnly] = useState(false);

  const selectedProfile = useMemo(() => profiles.find((p) => p.id === selectedProfileId) ?? null, [profiles, selectedProfileId]);

  // Asset list shown in the per-group dropdown — filtered by the
  // "unscanned only" toggle when active.
  const displayedAssets = useMemo(() => {
    if (!unscannedOnly) return assets;
    return assets.filter((a: any) => !(a?.lastScanAt || a?.last_scan_at));
  }, [assets, unscannedOnly]);

  const unscannedCount = useMemo(() => {
    return assets.filter((a: any) => !(a?.lastScanAt || a?.last_scan_at)).length;
  }, [assets]);

  // Org-wide pool of unscanned assets — used by the top-of-panel
  // "pick a random unscanned asset" button so users don't have to
  // hunt-and-peck through groups when they just want to onboard a
  // fresh asset. Computed from allAssets (loaded at mount), not the
  // per-group list.
  const globalUnscannedAssets = useMemo(() => {
    return allAssets.filter((a: any) => !(a?.lastScanAt || a?.last_scan_at));
  }, [allAssets]);

  function pickRandomAsset() {
    const pool = displayedAssets;
    if (pool.length === 0) {
      setBanner({ kind: "err", text: unscannedOnly ? "No unscanned assets in this group." : "No assets in this group." });
      return;
    }
    const picked = pool[Math.floor(Math.random() * pool.length)];
    setSelAssetId(String(picked.id));
    setSearchQuery(picked.value || "");
  }

  function pickRandomGlobalUnscannedAsset() {
    if (globalUnscannedAssets.length === 0) {
      setBanner({ kind: "err", text: "No unscanned assets in your organisation — every asset has been scanned at least once." });
      return;
    }
    const picked = globalUnscannedAssets[Math.floor(Math.random() * globalUnscannedAssets.length)];
    // Clear the group selection so the picked asset isn't filtered
    // out of view when this fires across-group. Search query is
    // populated with the asset value so the visible state matches
    // what got picked.
    setSelGroupId("");
    setSelAssetId(String(picked.id));
    setSearchQuery(picked.value || "");
    setSearchOpen(false);
  }

  // Reset the asset selection when the unscanned filter changes if the
  // currently-selected asset isn't in the new visible pool.
  useEffect(() => {
    if (!selAssetId) return;
    const stillVisible = displayedAssets.some((a: any) => String(a.id) === selAssetId);
    if (!stillVisible) {
      setSelAssetId("");
      setSearchQuery("");
    }
  }, [displayedAssets, selAssetId]);

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

  // Best-effort add of a lookalike scan alongside the normal scan job.
  // Returns true if a plan-limit dialog was raised (caller should stop
  // its loop). All other failures are swallowed — a broken lookalike
  // add must never block the user's intended scan.
  async function maybeAddLookalike(assetId: string, assetType?: string): Promise<boolean> {
    if (!alsoLookalike) return false;
    if (assetType && assetType !== "domain") return false; // engine is domain-only
    try {
      await apiFetch(`/assets/${assetId}/lookalike-watch`, { method: "POST" });
    } catch (e: any) {
      if (isPlanError(e)) { planLimit.handle(e.planError); return true; }
      // Already-watched / 4xx / network — swallow.
    }
    try {
      await apiFetch(`/assets/${assetId}/lookalike-scan`, { method: "POST" });
    } catch {
      // Best-effort; user can still trigger from asset detail page later.
    }
    return false;
  }

  async function handleScanSingle() {
    if (!selAssetId) { setBanner({ kind: "err", text: "Select an asset." }); return; }
    try {
      setScanning(true);
      const job = await createScanJob(selAssetId, selectedProfileId || undefined);
      await runScanJob(String(job.id));
      // Asset type isn't known on this path (only the id is). Pass
      // undefined so maybeAddLookalike attempts it and lets the backend
      // reject non-domains gracefully.
      const stopped = await maybeAddLookalike(selAssetId);
      if (stopped) { setScanning(false); return; }
      setBanner({
        kind: "ok",
        text: alsoLookalike
          ? "Scan started, lookalike monitoring enabled. Redirecting to Scan Jobs..."
          : "Scan started! Redirecting to Scan Jobs...",
      });
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
      let lookalikeEnabled = 0;
      for (const asset of assets) {
        try {
          const job = await createScanJob(String(asset.id), selectedProfileId || undefined);
          await runScanJob(String(job.id));
          created++;
          const stopped = await maybeAddLookalike(String(asset.id), asset.type || asset.asset_type);
          if (stopped) { setScanning(false); return; }
          if (alsoLookalike && (asset.type === "domain" || asset.asset_type === "domain")) {
            lookalikeEnabled++;
          }
        } catch (e: any) {
          if (isPlanError(e)) { planLimit.handle(e.planError); setScanning(false); return; }
        }
      }
      const tail = alsoLookalike && lookalikeEnabled > 0
        ? ` Lookalike monitoring enabled on ${lookalikeEnabled} domain${lookalikeEnabled === 1 ? "" : "s"}.`
        : "";
      setBanner({ kind: "ok", text: `Started ${created} scan(s).${tail} Redirecting...` });
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

        {/* Profile Selector — collapsible. Picking a profile is a
            once-per-session decision and shouldn't dominate the page,
            so this collapses by default into a one-line summary
            showing the current selection. Click the row (or the
            chevron) to expand the full picker grid and switch. */}
        <div className="bg-card border border-border rounded-xl">
          <button
            type="button"
            onClick={() => setProfileOpen((v) => !v)}
            className="w-full flex items-center justify-between gap-3 p-4 text-left hover:bg-accent/20 rounded-xl transition-colors"
          >
            <div className="flex items-center gap-3 min-w-0">
              <Shield className="w-5 h-5 text-primary shrink-0" />
              <div className="min-w-0">
                <div className="text-sm font-semibold text-foreground">Scan Profile</div>
                {selectedProfile ? (
                  <div className="text-xs text-muted-foreground mt-0.5 flex items-center gap-2 flex-wrap">
                    <span className={cn("px-2 py-0.5 rounded text-[10px] font-bold", getProfileMeta(selectedProfile).badge)}>
                      {selectedProfile.name}
                    </span>
                    <span className="text-muted-foreground/60">·</span>
                    <span className="inline-flex items-center gap-1">
                      <Timer className="w-3 h-3" />{getProfileMeta(selectedProfile).duration}
                    </span>
                    <span className="text-muted-foreground/60">·</span>
                    <span className="truncate">{getProfileMeta(selectedProfile).depth}</span>
                  </div>
                ) : (
                  <div className="text-xs text-muted-foreground mt-0.5">
                    {profiles.length === 0 ? "No scan profiles found." : "Choose a scan profile"}
                  </div>
                )}
              </div>
            </div>
            <div className="text-xs text-muted-foreground flex items-center gap-2 shrink-0">
              <span className="hidden sm:inline">{profileOpen ? "Hide" : "Change"}</span>
              {profileOpen
                ? <ChevronUp className="w-4 h-4" />
                : <ChevronDown className="w-4 h-4" />}
            </div>
          </button>
          {profileOpen && profiles.length > 0 && (
            <div className="px-4 pb-4">
              <div className="grid sm:grid-cols-3 gap-4">
                {profiles.map((p) => (
                  <ProfileCard
                    key={p.id}
                    profile={p}
                    selected={selectedProfileId === p.id}
                    onSelect={() => { setSelectedProfileId(p.id); setProfileOpen(false); }}
                  />
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Lookalike monitoring add-on — toggle applies to whichever
            target the user picks below. Plan-limited; non-domain assets
            in a group are silently skipped. */}
        <label className="bg-card border border-border rounded-xl p-4 flex items-start gap-3 cursor-pointer hover:border-primary/30 transition-colors">
          <input
            type="checkbox"
            checked={alsoLookalike}
            onChange={(e) => setAlsoLookalike(e.target.checked)}
            className="mt-0.5 w-4 h-4 rounded border-border bg-input-background text-primary focus:ring-2 focus:ring-ring"
          />
          <div className="min-w-0">
            <div className="text-sm font-semibold text-foreground">
              Also check for lookalike domains
            </div>
            <div className="text-xs text-muted-foreground mt-0.5 leading-relaxed max-w-2xl">
              Enables lookalike monitoring on each scanned root domain and
              triggers an immediate lookalike scan alongside the vulnerability
              scan. Detects typosquats, homoglyph confusables, and TLD swaps.
              Plan-limited; non-domain assets are skipped.
            </div>
          </div>
        </label>

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
                        onClick={() => { setSelAssetId(String(a.id)); setSearchQuery(a.value); setSearchOpen(false); }}>
                        <div className="min-w-0"><div className="text-sm font-mono text-foreground truncate">{a.value}</div><div className="text-xs text-muted-foreground">{a.groupName || a.group_name || "No group"} · {a.type || "domain"}</div></div>
                        <Target className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
            {/* Org-wide unscanned shortcut. Surfaces a count of assets
                that have never been scanned and lets the user pick one
                at random across the whole organisation — no group
                selection required. Hidden when there's nothing to
                pick, so it doesn't add noise once the inventory is
                fully onboarded. */}
            {globalUnscannedAssets.length > 0 && (
              <div className="flex items-center justify-between gap-3 px-4 py-2.5 rounded-lg border border-[#00b8d4]/20 bg-[#00b8d4]/[0.04]">
                <div className="text-xs text-muted-foreground">
                  <span className="font-semibold text-foreground">{globalUnscannedAssets.length}</span>
                  {" "}unscanned asset{globalUnscannedAssets.length === 1 ? "" : "s"} across all groups —{" "}
                  <span className="text-muted-foreground/70">never been scanned yet</span>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={pickRandomGlobalUnscannedAsset}
                  className="gap-1.5 text-xs border-[#00b8d4]/40 text-[#00b8d4] hover:bg-[#00b8d4]/10 shrink-0"
                  title="Pick a random unscanned asset across all groups"
                >
                  <Shuffle className="w-3.5 h-3.5" />
                  Pick random unscanned
                </Button>
              </div>
            )}
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
                  <select value={selAssetId} onChange={(e) => { setSelAssetId(e.target.value); setSearchQuery(e.target.value ? (displayedAssets.find((a: any) => String(a.id) === e.target.value)?.value || "") : ""); }}
                    disabled={loadingAssets} className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm disabled:opacity-50">
                    <option value="">
                      {loadingAssets
                        ? "Loading..."
                        : unscannedOnly
                          ? `All unscanned (${displayedAssets.length})`
                          : `All assets (${displayedAssets.length})`}
                    </option>
                    {displayedAssets.map((a: any) => (
                      <option key={String(a.id)} value={String(a.id)}>
                        {a.value}{!(a.lastScanAt || a.last_scan_at) ? "  •  unscanned" : ""}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            {/* Unscanned filter + random picker — only meaningful once a
                group has been selected and assets have loaded. Surfaces
                the count of never-scanned assets so users can quickly
                onboard newly-added inventory without hunting through
                a long dropdown. */}
            {selGroupId && !loadingAssets && assets.length > 0 && (
              <div className="flex items-center gap-3 flex-wrap">
                <label className="inline-flex items-center gap-2 text-sm text-muted-foreground cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={unscannedOnly}
                    onChange={(e) => setUnscannedOnly(e.target.checked)}
                    className="rounded border-border bg-background text-primary focus:ring-primary/40"
                  />
                  Show only unscanned assets
                  <span className="text-xs text-muted-foreground/70">
                    ({unscannedCount} of {assets.length})
                  </span>
                </label>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={pickRandomAsset}
                  disabled={displayedAssets.length === 0}
                  className="gap-1.5"
                  title={
                    unscannedOnly
                      ? "Pick a random unscanned asset from this group"
                      : "Pick a random asset from this group"
                  }
                >
                  <Shuffle className="w-3.5 h-3.5" />
                  Pick random
                </Button>
              </div>
            )}

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

            {/* "What you'll get" preview — only when the user has both a
                profile and a target ready. Avoids surprises right before
                the click that starts the work. */}
            {selectedProfile && (selAssetId || (selGroupId && canBulk && assets.length > 0)) && (
              <div className="rounded-xl border border-primary/20 bg-primary/[0.04] p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Info className="w-4 h-4 text-primary" />
                  <span className="text-xs font-semibold text-primary uppercase tracking-wider">What you'll get</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wide mb-0.5">Profile</div>
                    <div className="text-foreground font-medium">{selectedProfile.name}</div>
                    <div className="text-muted-foreground text-[11px] mt-0.5">{getProfileMeta(selectedProfile).depth}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wide mb-0.5">Expected duration</div>
                    <div className="text-foreground font-medium flex items-center gap-1.5"><Timer className="w-3 h-3" />{getProfileMeta(selectedProfile).duration}</div>
                    <div className="text-muted-foreground text-[11px] mt-0.5">{selAssetId ? "per asset" : `× ${assets.length} assets`}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wide mb-0.5">Engines</div>
                    <div className="text-foreground font-medium">{engineList(selectedProfile).length} engines run</div>
                    <div className="text-muted-foreground text-[11px] mt-0.5 truncate" title={engineList(selectedProfile).join(", ")}>
                      {engineList(selectedProfile).slice(0, 3).join(", ")}
                      {engineList(selectedProfile).length > 3 && ` +${engineList(selectedProfile).length - 3} more`}
                    </div>
                  </div>
                </div>
                {/* Plan-usage hint — only renders when org context has
                    billing data and a finite scan cap. Helps customers
                    see they're about to use up their monthly budget. */}
                <ScansThisMonthHint />
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