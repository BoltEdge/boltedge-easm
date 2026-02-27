// FILE: app/(authenticated)/discovery/page.tsx
// Discovery Engine v2 — async job-based discovery with multi-job tracking
"use client";

import React, { useEffect, useMemo, useState, useCallback, useRef } from "react";
import {
  Radar, Search, FolderPlus, Check, Clock, RefreshCcw, Trash2,
  Info, Loader2, ArrowLeft, ChevronRight, Eye, Play,
} from "lucide-react";
import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../ui/dialog";
import { useOrg } from "../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../ui/plan-limit-dialog";
import {
  getGroups, getGroupAssets, isPlanError,
  getScanProfiles, createScanJob, runScanJob,
} from "../../lib/api";
import {
  launchDiscovery, getDiscoveryJobs, getDiscoveryJobDetail,
  cancelDiscoveryJob, addDiscoveredAssetsToInventory, deleteDiscoveryJob,
  updateAssetTags, bulkUpdateAssetTags, createDiscoveryGroup,
  ignoreDiscoveredAssets,
  type DiscoveryJob,
} from "../../lib/discovery-api";
import { cn, timeAgo, StatusBadge, TypeBadge } from "./discovery-components";
import DiscoverySchedulesTab from "./schedules-tab";

export default function DiscoveryPage() {
  const { canDo } = useOrg();
  const planLimit = usePlanLimit();
  const canRun = canDo("run_discovery");
  const canCreate = canDo("create_assets");
  const canStartScans = canDo("start_scans");
  const canBulkScan = canDo("bulk_scan");

  // ── Tab ──
  const [activeTab, setActiveTab] = useState<"discover" | "schedules">("discover");

  // ── State ──
  const [targetType, setTargetType] = useState<"domain" | "ip" | "asn" | "cidr">("domain");
  const [targetValue, setTargetValue] = useState("");
  const [scanDepth, setScanDepth] = useState<"standard" | "deep">("standard");
  const [launching, setLaunching] = useState(false);

  const [jobs, setJobs] = useState<DiscoveryJob[]>([]);
  const [loadingJobs, setLoadingJobs] = useState(true);
  const [viewingJob, setViewingJob] = useState<DiscoveryJob | null>(null);

  const [groups, setGroups] = useState<Array<{ id: any; name: string }>>([]);
  const [selectedGroupId, setSelectedGroupId] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [addingAssets, setAddingAssets] = useState(false);
  const [dialogStep, setDialogStep] = useState<"select-group" | "scan-prompt">("select-group");
  const [newGroupName, setNewGroupName] = useState("");
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [addedCount, setAddedCount] = useState(0);
  const [addedGroupId, setAddedGroupId] = useState("");

  // Scan after add
  const [scanProfiles, setScanProfiles] = useState<any[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState("");
  const [scanningAfterAdd, setScanningAfterAdd] = useState(false);

  const [typeFilter, setTypeFilter] = useState("all");
  const [searchFilter, setSearchFilter] = useState("");
  const [showNewOnly, setShowNewOnly] = useState(false);
  const [showInScopeOnly, setShowInScopeOnly] = useState(false);
  const [hideSeen, setHideSeen] = useState(false);
  const [tagFilter, setTagFilter] = useState<string | null>(null);

  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (banner) { const t = setTimeout(() => setBanner(null), 6000); return () => clearTimeout(t); }
  }, [banner]);

  // ── Data loading ──
  const refreshJobs = useCallback(async () => {
    try { setLoadingJobs(true); setJobs((await getDiscoveryJobs({ limit: 50 })).items || []); }
    catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed" }); }
    finally { setLoadingJobs(false); }
  }, []);

  const refreshGroups = useCallback(async () => {
    try {
      const m = (await getGroups()).map((g) => ({ id: g.id, name: g.name }));
      setGroups(m);
      if (!selectedGroupId && m.length) setSelectedGroupId(String(m[0].id));
    } catch {}
  }, [selectedGroupId]);

  useEffect(() => { refreshJobs(); refreshGroups(); loadProfiles(); }, []);

  async function loadProfiles() {
    try {
      const p = await getScanProfiles();
      setScanProfiles(p);
      const def = p.find((x: any) => x.isDefault);
      setSelectedProfileId(def ? def.id : p.length ? p[0].id : "");
    } catch {}
  }

  // ── Running jobs from the jobs list ──
  const runningJobs = useMemo(
    () => jobs.filter((j) => j.status === "pending" || j.status === "running"),
    [jobs],
  );

  // ── Polling: refresh jobs list while any are running ──
  useEffect(() => {
    if (pollRef.current) clearInterval(pollRef.current);

    if (runningJobs.length > 0) {
      const poll = async () => {
        const updated = (await getDiscoveryJobs({ limit: 50 })).items || [];
        setJobs(updated);

        // Also refresh viewingJob if it's one of the running ones
        if (viewingJob && (viewingJob.status === "pending" || viewingJob.status === "running")) {
          try {
            const d = await getDiscoveryJobDetail(viewingJob.id);
            setViewingJob(d);
          } catch {}
        }

        // Stop polling if nothing is running anymore
        const stillRunning = updated.some((j) => j.status === "pending" || j.status === "running");
        if (!stillRunning && pollRef.current) {
          clearInterval(pollRef.current);
          pollRef.current = null;
        }
      };
      pollRef.current = setInterval(poll, 3000);
    }

    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [runningJobs.length, viewingJob?.id]);

  // ── Actions ──
  async function handleDiscover() {
    if (!targetValue.trim()) return;
    setLaunching(true);
    try {
      await launchDiscovery({ target: targetValue.trim(), targetType, scanDepth });
      setBanner({ kind: "ok", text: "Discovery started — finding your assets..." });
      setTargetValue("");
      refreshJobs();
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed" });
    } finally { setLaunching(false); }
  }

  async function handleViewJob(jobId: number) {
    setSelectedIds(new Set()); setTypeFilter("all"); setSearchFilter(""); setShowNewOnly(false); setShowInScopeOnly(false); setTagFilter(null);
    try {
      const d = await getDiscoveryJobDetail(jobId);
      setViewingJob(d);
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed" }); }
  }

  async function handleCancel(jobId: number) {
    try {
      await cancelDiscoveryJob(jobId);
      setBanner({ kind: "ok", text: "Cancelled." }); refreshJobs();
      if (viewingJob?.id === jobId) setViewingJob(await getDiscoveryJobDetail(jobId));
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed" }); }
  }

  async function handleDelete(jobId: number, e?: React.MouseEvent) {
    e?.stopPropagation();
    if (!confirm("Delete this discovery job and all its results?")) return;
    try {
      await deleteDiscoveryJob(jobId);
      setBanner({ kind: "ok", text: "Deleted." });
      if (viewingJob?.id === jobId) setViewingJob(null);
      refreshJobs();
    } catch (err: any) { setBanner({ kind: "err", text: err?.message || "Failed" }); }
  }

  async function handleAddToInventory() {
    if (!viewingJob) return;
    let groupId = selectedGroupId;

    // Create new group if needed
    if (groupId === "__new__" && newGroupName.trim()) {
      setCreatingGroup(true);
      try {
        const newGroup = await createDiscoveryGroup({ name: newGroupName.trim() });
        groupId = String(newGroup.id);
        setSelectedGroupId(groupId);
        refreshGroups();
      } catch (e: any) {
        setBanner({ kind: "err", text: e?.message || "Failed to create group" });
        setCreatingGroup(false);
        return;
      }
      setCreatingGroup(false);
    }

    if (!groupId || groupId === "__new__") return;

    setAddingAssets(true);
    try {
      const resp = await addDiscoveredAssetsToInventory(viewingJob.id, {
        assetIds: Array.from(selectedIds), groupId,
      });
      setAddedCount(resp.totalAdded);
      setAddedGroupId(groupId);
      setViewingJob(await getDiscoveryJobDetail(viewingJob.id));

      // Transition to scan prompt step
      if (canStartScans && resp.totalAdded > 0) {
        setDialogStep("scan-prompt");
      } else {
        const msg = `Added ${resp.totalAdded} asset(s)` + (resp.totalSkipped ? `, ${resp.totalSkipped} skipped` : "");
        setBanner({ kind: "ok", text: msg });
        setAddDialogOpen(false); setSelectedIds(new Set()); setDialogStep("select-group");
      }
    } catch (e: any) {
      if (isPlanError(e)) { setAddDialogOpen(false); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed" });
    } finally { setAddingAssets(false); }
  }

  async function handleScanAfterAdd() {
    if (!addedGroupId || !selectedProfileId) return;
    setScanningAfterAdd(true);
    try {
      const assets = await getGroupAssets(addedGroupId);
      let started = 0;
      for (const asset of assets) {
        try {
          const job = await createScanJob(String(asset.id), selectedProfileId);
          await runScanJob(String(job.id));
          started++;
        } catch (e: any) {
          if (isPlanError(e)) { planLimit.handle(e.planError); break; }
        }
      }
      setBanner({ kind: "ok", text: `Added ${addedCount} asset(s) and started ${started} scan(s). Check Scan Jobs for progress.` });
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to start scans" });
    } finally {
      setScanningAfterAdd(false);
      setAddDialogOpen(false); setSelectedIds(new Set()); setDialogStep("select-group");
    }
  }

  function handleSkipScan() {
    setBanner({ kind: "ok", text: `Added ${addedCount} asset(s) to inventory.` });
    setAddDialogOpen(false); setSelectedIds(new Set()); setDialogStep("select-group");
  }

  // ── Ignore handlers ──
  async function handleIgnoreSelected() {
    if (selectedIds.size === 0) return;
    try {
      await ignoreDiscoveredAssets({ assetIds: Array.from(selectedIds) });
      setBanner({ kind: "ok", text: `Marked ${selectedIds.size} asset(s) as seen. They won't show as "New" in future discoveries.` });
      setSelectedIds(new Set());
      // Refresh the job to show updated status
      if (viewingJob) {
        const updated = await getDiscoveryJobDetail(viewingJob.id);
        setViewingJob(updated);
      }
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to ignore assets" });
    }
  }

  async function handleIgnoreSingle(assetId: number) {
    try {
      await ignoreDiscoveredAssets({ assetIds: [assetId] });
      setBanner({ kind: "ok", text: "Asset marked as seen. It won't show as \"New\" in future discoveries." });
      if (viewingJob) {
        const updated = await getDiscoveryJobDetail(viewingJob.id);
        setViewingJob(updated);
      }
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to ignore asset" });
    }
  }

  // ── Derived data (for job detail view) ──
  const filteredAssets = useMemo(() => {
    if (!viewingJob?.discoveredAssets) return [];
    let items = [...viewingJob.discoveredAssets];
    if (typeFilter !== "all") items = items.filter((a) => a.assetType === typeFilter);
    if (showNewOnly) items = items.filter((a) => a.isNew);
    if (showInScopeOnly) items = items.filter((a) => (a.tags || []).includes("in-scope"));
    if (hideSeen) items = items.filter((a) => !(a.isIgnored || (a.tags || []).includes("ignored")));
    if (tagFilter) items = items.filter((a) => (a.tags || []).includes(tagFilter));
    if (searchFilter.trim()) {
      const s = searchFilter.toLowerCase();
      items = items.filter((a) => a.value.toLowerCase().includes(s));
    }
    return items;
  }, [viewingJob?.discoveredAssets, typeFilter, searchFilter, showNewOnly, showInScopeOnly, hideSeen, tagFilter]);

  const typeCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const a of viewingJob?.discoveredAssets || []) c[a.assetType] = (c[a.assetType] || 0) + 1;
    return c;
  }, [viewingJob?.discoveredAssets]);

  const allTags = useMemo(() => {
    const tags: Record<string, number> = {};
    for (const a of viewingJob?.discoveredAssets || []) {
      for (const t of a.tags || []) { if (t !== "ignored") tags[t] = (tags[t] || 0) + 1; }
    }
    return tags;
  }, [viewingJob?.discoveredAssets]);

  async function handleToggleTag(assetId: number, tag: string, currentTags: string[]) {
    const has = currentTags.includes(tag);
    try {
      await updateAssetTags(assetId, has ? { remove: [tag] } : { add: [tag] });
      // Refresh job detail
      if (viewingJob) setViewingJob(await getDiscoveryJobDetail(viewingJob.id));
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed to update tag" }); }
  }

  async function handleBulkTag(tag: string, mode: "add" | "remove") {
    if (selectedIds.size === 0) return;
    try {
      await bulkUpdateAssetTags({
        assetIds: Array.from(selectedIds),
        ...(mode === "add" ? { add: [tag] } : { remove: [tag] }),
      });
      if (viewingJob) setViewingJob(await getDiscoveryJobDetail(viewingJob.id));
      setBanner({ kind: "ok", text: `${mode === "add" ? "Added" : "Removed"} "${tag}" tag on ${selectedIds.size} asset(s)` });
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed" }); }
  }

  function toggleSelect(id: number) {
    setSelectedIds((p) => { const n = new Set(p); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  }
  function selectAll() {
    const addable = filteredAssets.filter((a) => !a.addedToInventory);
    setSelectedIds(selectedIds.size === addable.length ? new Set() : new Set(addable.map((a) => a.id)));
  }

  const viewingIsActive = viewingJob && (viewingJob.status === "pending" || viewingJob.status === "running");

  // ════════════════════════════════════════════════════════════
  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Radar className="w-8 h-8 text-[#00b8d4]" />
            <h1 className="text-2xl font-semibold text-foreground">Asset Discovery</h1>
          </div>
          <p className="text-muted-foreground">Discover new assets across your attack surface using multiple reconnaissance techniques.</p>
        </div>

        {/* Tab bar */}
        <div className="flex items-center gap-1 mb-6 border-b border-border">
          <button onClick={() => setActiveTab("discover")}
            className={cn("px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px",
              activeTab === "discover" ? "border-[#00b8d4] text-[#00b8d4]" : "border-transparent text-muted-foreground hover:text-foreground")}>
            Discoveries
          </button>
          <button onClick={() => setActiveTab("schedules")}
            className={cn("px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px",
              activeTab === "schedules" ? "border-[#00b8d4] text-[#00b8d4]" : "border-transparent text-muted-foreground hover:text-foreground")}>
            Schedules
          </button>
        </div>

        {banner && (
          <div className={cn("mb-6 rounded-xl border px-4 py-3 text-sm",
            banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>
            {banner.text}
          </div>
        )}

        {activeTab === "schedules" ? (
          <DiscoverySchedulesTab />
        ) : (
        <div className="space-y-6">
          {/* ── Input Card ── */}
          <div className="bg-card border border-[#00b8d4]/20 rounded-xl p-6">
            <div className="flex items-center justify-between gap-4 mb-4">
              <div className="flex items-center gap-2">
                <Search className="w-5 h-5 text-[#00b8d4]" />
                <h2 className="text-lg font-semibold text-foreground">Discover Assets</h2>
              </div>
              <Button variant="outline" onClick={refreshJobs} className="border-border text-foreground hover:bg-accent">
                <RefreshCcw className="w-4 h-4 mr-2" />Refresh
              </Button>
            </div>
            {canRun ? (
              <div className="space-y-3">
                <div className="grid md:grid-cols-[160px_140px_1fr_auto] gap-3">
                  <select value={targetType} onChange={(e) => setTargetType(e.target.value as any)}
                    className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-ring">
                    <option value="domain">Domain</option>
                    <option value="ip">IP Address</option>
                    <option value="cidr">CIDR Range (Starter+)</option>
                    <option value="asn">ASN (Starter+)</option>
                  </select>
                  <select value={scanDepth} onChange={(e) => setScanDepth(e.target.value as any)}
                    className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-ring">
                    <option value="standard">Standard</option>
                    <option value="deep">Deep (Starter+)</option>
                  </select>
                  <Input placeholder={
                    targetType === "domain" ? "example.com" :
                    targetType === "ip" ? "52.1.2.3" :
                    targetType === "cidr" ? "192.168.1.0/24" :
                    targetType === "asn" ? "AS13335" :
                    "Acme Corporation"
                  } value={targetValue}
                    onChange={(e) => setTargetValue(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleDiscover()} />
                  <Button onClick={handleDiscover} disabled={launching || !targetValue.trim()} className="bg-[#00b8d4] hover:bg-[#00b8d4]/90 whitespace-nowrap">
                    {launching ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Starting...</> : <><Radar className="w-4 h-4 mr-2" />Discover</>}
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">
                  {scanDepth === "standard" && "Standard discovery checks ~300 common subdomains using CT logs, DNS, and passive OSINT sources."}
                  {scanDepth === "deep" && "Deep discovery runs 1,300+ subdomain checks and extended reconnaissance. Takes longer but finds more."}
                </p>
              </div>
            ) : (
              <div className="flex items-center gap-2 px-3 py-3 rounded-lg bg-muted/10 border border-border text-sm text-muted-foreground">
                <Info className="w-4 h-4 shrink-0" />You don&apos;t have permission to run discovery.
              </div>
            )}
          </div>

          {/* ── Running Jobs Bar ── */}
          {runningJobs.length > 0 && (
            <div className="space-y-3">
              {runningJobs.map((rj) => (
                <div key={rj.id} className="bg-card border border-[#00b8d4]/30 rounded-xl p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Loader2 className="w-4 h-4 text-[#00b8d4] animate-spin shrink-0" />
                      <div>
                        <span className="text-foreground font-semibold font-mono text-sm">{rj.target}</span>
                        <span className="ml-2 text-xs text-muted-foreground uppercase">{rj.targetType.replace("_", " ")}</span>
                        <span className="ml-2 text-xs text-muted-foreground">· {rj.scanDepth || "standard"}</span>
                        <span className="ml-2 text-xs text-muted-foreground">· {rj.totalFound} found · {timeAgo(rj.startedAt || rj.createdAt)}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {rj.engineProgress && rj.engineProgress.total > 0 && (
                        <span className="text-xs text-muted-foreground">
                          {rj.engineProgress.completed}/{rj.engineProgress.total} engines
                        </span>
                      )}
                      <Button variant="outline" size="sm" onClick={() => handleViewJob(rj.id)}
                        className="border-border text-foreground hover:bg-accent">
                        <Eye className="w-3 h-3 mr-1" />View
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => handleCancel(rj.id)}
                        className="border-red-500/50 text-red-400 hover:bg-red-500/10">Cancel</Button>
                    </div>
                  </div>
                  {rj.engineProgress && rj.engineProgress.total > 0 && (
                    <div className="mt-3 w-full h-1.5 bg-muted/30 rounded-full overflow-hidden">
                      <div className="h-full bg-[#00b8d4] rounded-full transition-all duration-500"
                        style={{ width: `${Math.round((rj.engineProgress.completed / rj.engineProgress.total) * 100)}%` }} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* ── Job Detail View ── */}
          {viewingJob && <JobDetailView
            job={viewingJob} filteredAssets={filteredAssets} typeCounts={typeCounts}
            allTags={allTags} tagFilter={tagFilter} setTagFilter={setTagFilter}
            typeFilter={typeFilter} setTypeFilter={setTypeFilter}
            searchFilter={searchFilter} setSearchFilter={setSearchFilter}
            showNewOnly={showNewOnly} setShowNewOnly={setShowNewOnly}
            showInScopeOnly={showInScopeOnly} setShowInScopeOnly={setShowInScopeOnly}
            hideSeen={hideSeen} setHideSeen={setHideSeen}
            selectedIds={selectedIds} toggleSelect={toggleSelect} selectAll={selectAll}
            canCreate={canCreate}
            isActive={!!viewingIsActive}
            onBack={() => setViewingJob(null)}
            onDelete={() => handleDelete(viewingJob.id)}
            onCancel={() => handleCancel(viewingJob.id)}
            onOpenAddDialog={() => setAddDialogOpen(true)}
            onToggleTag={handleToggleTag}
            onBulkTag={handleBulkTag}
            onIgnoreSelected={handleIgnoreSelected}
          />}

          {/* ── Jobs History (always visible) ── */}
          {!viewingJob && <JobsList
            jobs={jobs} loading={loadingJobs}
            onView={handleViewJob} onDelete={handleDelete}
          />}

          {/* Add to Inventory Dialog (two-step) */}
          <Dialog open={addDialogOpen} onOpenChange={(open) => { setAddDialogOpen(open); if (!open) { setDialogStep("select-group"); setNewGroupName(""); } }}>
            <DialogContent className="bg-card border-border text-foreground sm:max-w-md">
              {dialogStep === "select-group" && (
                <>
                  <DialogHeader><DialogTitle>Add Assets to Inventory</DialogTitle></DialogHeader>
                  <p className="text-sm text-muted-foreground">Add {selectedIds.size} selected asset(s) to an asset group.</p>
                  <div className="space-y-4">
                    <div>
                      <Label className="text-sm font-medium text-foreground mb-2 block">Asset Group</Label>
                      <select value={selectedGroupId} onChange={(e) => { setSelectedGroupId(e.target.value); setNewGroupName(""); }}
                        className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-ring">
                        {groups.map((g) => <option key={String(g.id)} value={String(g.id)}>{g.name}</option>)}
                        <option value="__new__">+ Create new group</option>
                      </select>
                    </div>
                    {selectedGroupId === "__new__" && (
                      <div>
                        <Label className="text-sm font-medium text-foreground mb-2 block">New Group Name</Label>
                        <Input placeholder="e.g. Production Servers" value={newGroupName}
                          onChange={(e) => setNewGroupName(e.target.value)}
                          onKeyDown={(e) => e.key === "Enter" && handleAddToInventory()} />
                      </div>
                    )}
                    <div className="flex gap-3 justify-end pt-2">
                      <Button variant="outline" onClick={() => setAddDialogOpen(false)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
                      <Button onClick={handleAddToInventory}
                        disabled={(selectedGroupId === "__new__" ? !newGroupName.trim() : !selectedGroupId) || addingAssets || creatingGroup}
                        className="bg-primary hover:bg-primary/90">
                        {creatingGroup ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Creating...</>
                          : addingAssets ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Adding...</>
                          : <><FolderPlus className="w-4 h-4 mr-2" />Add to Group</>}
                      </Button>
                    </div>
                  </div>
                </>
              )}

              {dialogStep === "scan-prompt" && (
                <>
                  <DialogHeader><DialogTitle>Scan Added Assets?</DialogTitle></DialogHeader>
                  <p className="text-sm text-muted-foreground">
                    Successfully added <span className="font-semibold text-foreground">{addedCount}</span> asset(s) to inventory.
                    Would you like to scan them now?
                  </p>
                  <div className="space-y-4">
                    <div>
                      <Label className="text-sm font-medium text-foreground mb-2 block">Scan Profile</Label>
                      <select value={selectedProfileId} onChange={(e) => setSelectedProfileId(e.target.value)}
                        className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-ring">
                        {scanProfiles.map((p: any) => <option key={p.id} value={p.id}>{p.name}</option>)}
                      </select>
                    </div>
                    {addedCount > 1 && !canBulkScan && (
                      <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#ff8800]/5 border border-[#ff8800]/20 text-xs text-muted-foreground">
                        <Info className="w-3.5 h-3.5 text-[#ff8800] shrink-0" />
                        Bulk scanning requires admin permissions. Ask an admin to scan these assets.
                      </div>
                    )}
                    <div className="flex gap-3 justify-end pt-2">
                      <Button variant="outline" onClick={handleSkipScan} className="border-border text-foreground hover:bg-accent">Skip</Button>
                      <Button onClick={handleScanAfterAdd}
                        disabled={scanningAfterAdd || !selectedProfileId || (addedCount > 1 && !canBulkScan)}
                        className="bg-[#00b8d4] hover:bg-[#00b8d4]/90">
                        {scanningAfterAdd ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Starting scans...</>
                          : <><Play className="w-4 h-4 mr-2" />Scan Now ({addedCount})</>}
                      </Button>
                    </div>
                  </div>
                </>
              )}
            </DialogContent>
          </Dialog>
        </div>
        )}
      </div>
      <PlanLimitDialog {...planLimit} />
    </main>
  );
}

// ════════════════════════════════════════════════════════════
// Sub-components
// ════════════════════════════════════════════════════════════

function JobDetailView({ job, filteredAssets, typeCounts, allTags, tagFilter, setTagFilter,
  typeFilter, setTypeFilter,
  searchFilter, setSearchFilter, showNewOnly, setShowNewOnly,
  showInScopeOnly, setShowInScopeOnly, hideSeen, setHideSeen,
  selectedIds, toggleSelect, selectAll, canCreate, isActive,
  onBack, onDelete, onCancel, onOpenAddDialog,
  onToggleTag, onBulkTag, onIgnoreSelected,
}: any) {

  const TAG_COLORS: Record<string, string> = {
    "in-scope": "bg-emerald-500/20 text-emerald-400",
    "out-of-scope": "bg-zinc-500/20 text-zinc-400",
    "nameserver": "bg-blue-500/20 text-blue-400",
    "cdn": "bg-purple-500/20 text-purple-400",
    "mail": "bg-amber-500/20 text-amber-400",
    "historical": "bg-stone-500/20 text-stone-400",
    "dev-staging": "bg-orange-500/20 text-orange-400",
    "api": "bg-cyan-500/20 text-cyan-400",
    "investigate": "bg-yellow-500/20 text-yellow-300",
    "false-positive": "bg-red-500/20 text-red-400",
  };
  const DEFAULT_TAG_COLOR = "bg-muted/30 text-muted-foreground";

  return (
    <>
      <div className="flex items-center justify-between">
        <button onClick={onBack} className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft className="w-4 h-4" />Back to all discoveries
        </button>
        <div className="flex items-center gap-2">
          <StatusBadge status={job.status} />
          {isActive && (
            <Button variant="outline" size="sm" onClick={onCancel}
              className="border-red-500/50 text-red-400 hover:bg-red-500/10">Cancel</Button>
          )}
          {!isActive && (
            <Button variant="outline" size="sm" onClick={onDelete}
              className="border-red-500/30 text-red-400 hover:bg-red-500/10"><Trash2 className="w-3.5 h-3.5" /></Button>
          )}
        </div>
      </div>

      {/* Progress bar for active jobs */}
      {isActive && job.engineProgress && job.engineProgress.total > 0 && (
        <div className="bg-card border border-[#00b8d4]/30 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-muted-foreground mb-2">
            <span>{job.engineProgress.completed} of {job.engineProgress.total} engines complete</span>
            <span>{job.totalFound} assets found so far</span>
          </div>
          <div className="w-full h-2 bg-muted/30 rounded-full overflow-hidden">
            <div className="h-full bg-[#00b8d4] rounded-full transition-all duration-500"
              style={{ width: `${Math.round((job.engineProgress.completed / job.engineProgress.total) * 100)}%` }} />
          </div>
        </div>
      )}

      {/* Stats */}
      <div className="grid sm:grid-cols-4 gap-4">
        <div className="bg-card border border-border rounded-xl p-5">
          <div className="text-sm text-muted-foreground mb-1">Target</div>
          <div className="text-lg font-semibold text-foreground font-mono">{job.target}</div>
          <span className="mt-1 inline-block px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-muted/30 text-muted-foreground">{job.scanDepth || "standard"} discovery</span>
        </div>
        <div className="bg-card border border-border rounded-xl p-5">
          <div className="text-sm text-muted-foreground mb-1">Total Found</div>
          <div className="text-3xl font-bold text-foreground">{job.totalFound}</div>
        </div>
        <div className="bg-card border border-border rounded-xl p-5">
          <div className="text-sm text-muted-foreground mb-1">New Assets</div>
          <div className="text-3xl font-bold text-[#00b8d4]">{job.newAssets}</div>
        </div>
        <div className="bg-card border border-border rounded-xl p-5">
          <div className="text-sm text-muted-foreground mb-1">{isActive ? "Started" : "Completed"}</div>
          <div className="text-lg font-semibold text-foreground">{timeAgo(isActive ? (job.startedAt || job.createdAt) : job.completedAt)}</div>
        </div>
      </div>

      {/* Type filter chips */}
      {Object.keys(typeCounts).length > 0 && (
        <div className="flex flex-wrap gap-2">
          <button onClick={() => setTypeFilter("all")} className={cn("px-3 py-1.5 rounded-lg text-sm font-medium transition-all",
            typeFilter === "all" ? "bg-[#00b8d4]/20 text-[#00b8d4] ring-1 ring-[#00b8d4]/30" : "bg-muted/20 text-muted-foreground hover:bg-muted/30")}>
            All ({job.totalFound})
          </button>
          {Object.entries(typeCounts).map(([type, count]: [string, any]) => (
            <button key={type} onClick={() => setTypeFilter(type)} className={cn("px-3 py-1.5 rounded-lg text-sm font-medium transition-all",
              typeFilter === type ? "bg-[#00b8d4]/20 text-[#00b8d4] ring-1 ring-[#00b8d4]/30" : "bg-muted/20 text-muted-foreground hover:bg-muted/30")}>
              {type.replace("_", " ")} ({count})
            </button>
          ))}
        </div>
      )}

      {/* Tag filter chips */}
      {Object.keys(allTags).length > 0 && (
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs text-muted-foreground mr-1">Tags:</span>
          {tagFilter && (
            <button onClick={() => setTagFilter(null)} className="px-2.5 py-1 rounded-md text-xs font-medium bg-muted/20 text-muted-foreground hover:bg-muted/30">
              Clear filter ×
            </button>
          )}
          {Object.entries(allTags).map(([tag, count]: [string, any]) => (
            <button key={tag} onClick={() => setTagFilter(tagFilter === tag ? null : tag)}
              className={cn("px-2.5 py-1 rounded-md text-xs font-medium transition-all",
                tagFilter === tag ? "ring-1 ring-white/30 " + (TAG_COLORS[tag] || DEFAULT_TAG_COLOR) : TAG_COLORS[tag] || DEFAULT_TAG_COLOR,
                "hover:opacity-80")}>
              {tag} ({count})
            </button>
          ))}
        </div>
      )}

      {/* Toolbar */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input placeholder="Filter assets..." value={searchFilter} onChange={(e: any) => setSearchFilter(e.target.value)} className="pl-9 w-64 h-9" />
          </div>
          <button onClick={() => setShowNewOnly((v: boolean) => !v)} className={cn("px-3 py-1.5 rounded-lg text-xs font-medium transition-all",
            showNewOnly ? "bg-[#00b8d4]/20 text-[#00b8d4] ring-1 ring-[#00b8d4]/30" : "bg-muted/20 text-muted-foreground hover:bg-muted/30")}>
            New only
          </button>
          <button onClick={() => setShowInScopeOnly((v: boolean) => !v)} className={cn("px-3 py-1.5 rounded-lg text-xs font-medium transition-all",
            showInScopeOnly ? "bg-emerald-500/20 text-emerald-400 ring-1 ring-emerald-500/30" : "bg-muted/20 text-muted-foreground hover:bg-muted/30")}>
            In-scope only
          </button>
          <button onClick={() => setHideSeen((v: boolean) => !v)} className={cn("px-3 py-1.5 rounded-lg text-xs font-medium transition-all",
            hideSeen ? "bg-zinc-400/20 text-zinc-300 ring-1 ring-zinc-400/30" : "bg-muted/20 text-muted-foreground hover:bg-muted/30")}>
            Hide seen
          </button>
        </div>
        <div className="flex items-center gap-2">
          {canCreate && selectedIds.size > 0 && (
            <>
              <Button variant="outline" size="sm" onClick={onIgnoreSelected}
                className="border-zinc-500/30 text-zinc-400 hover:bg-zinc-500/10 text-xs h-8">
                Mark as Seen ({selectedIds.size})
              </Button>
              <Button onClick={onOpenAddDialog} className="bg-primary hover:bg-primary/90">
                <FolderPlus className="w-4 h-4 mr-2" />Add {selectedIds.size} to Inventory
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Assets table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-muted/30">
              <tr>
                {canCreate && <th className="p-4 w-12"><input type="checkbox" className="w-4 h-4 rounded border-border" onChange={selectAll}
                  checked={selectedIds.size > 0 && selectedIds.size === filteredAssets.filter((a: any) => !a.addedToInventory).length} /></th>}
                <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Type</th>
                <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Asset</th>
                <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Tags</th>
                <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">IPs</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredAssets.map((asset: any) => (
                <tr key={asset.id} className="hover:bg-accent/30 transition-colors">
                  {canCreate && (
                    <td className="p-4">
                      {asset.addedToInventory
                        ? <Check className="w-4 h-4 text-[#10b981]" />
                        : <input type="checkbox" className="w-4 h-4 rounded border-border" checked={selectedIds.has(asset.id)} onChange={() => toggleSelect(asset.id)} />}
                    </td>
                  )}
                  <td className="p-4"><TypeBadge type={asset.assetType} /></td>
                  <td className="p-4 font-mono text-sm text-foreground">{asset.value}</td>
                  <td className="p-4">
                    <div className="flex flex-wrap gap-1">
                      {(asset.tags || []).filter((t: string) => t !== "ignored").map((tag: string) => (
                        <span key={tag}
                          onClick={() => onToggleTag(asset.id, tag, asset.tags || [])}
                          className={cn("px-1.5 py-0.5 rounded text-[10px] font-semibold cursor-pointer hover:opacity-70 transition-opacity",
                            TAG_COLORS[tag] || DEFAULT_TAG_COLOR)}
                          title={`Click to remove "${tag}"`}>
                          {tag}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="p-4">
                    {asset.addedToInventory
                      ? <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-[#10b981]/10 text-[#10b981] rounded text-xs font-semibold"><Check className="w-3 h-3" />In inventory</span>
                      : (asset.isIgnored || (asset.tags || []).includes("ignored"))
                        ? <span className="px-2 py-0.5 bg-zinc-500/10 text-zinc-400 rounded text-xs font-semibold">Seen</span>
                        : asset.isNew
                          ? <span className="px-2 py-0.5 bg-[#00b8d4]/10 text-[#00b8d4] rounded text-xs font-semibold">New</span>
                          : <span className="text-xs text-muted-foreground">Known</span>}
                  </td>
                  <td className="p-4 text-xs text-muted-foreground font-mono">{(asset.resolvedIps || []).join(", ") || "—"}</td>
                </tr>
              ))}
              {filteredAssets.length === 0 && (
                <tr><td colSpan={canCreate ? 6 : 5} className="p-8 text-center text-sm text-muted-foreground">
                  {job.totalFound === 0 ? (isActive ? "Discovery in progress..." : "No assets discovered.") : "No assets match your filters."}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
        {filteredAssets.length > 0 && (
          <div className="px-4 py-3 border-t border-border text-xs text-muted-foreground">
            Showing {filteredAssets.length} of {job.totalFound} assets
          </div>
        )}
      </div>
    </>
  );
}

function JobsList({ jobs, loading, onView, onDelete }: {
  jobs: DiscoveryJob[]; loading: boolean;
  onView: (id: number) => void; onDelete: (id: number, e?: React.MouseEvent) => void;
}) {
  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <div className="p-6 border-b border-border flex items-center justify-between">
        <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
          <Clock className="w-5 h-5 text-[#00b8d4]" />Discovery History
        </h2>
        <span className="text-xs text-muted-foreground">{loading ? "Loading..." : `${jobs.length} job(s)`}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-muted/30">
            <tr>
              <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Target</th>
              <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
              <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Depth</th>
              <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Found</th>
              <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">New</th>
              <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Started</th>
              <th className="text-right p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {jobs.map((job) => (
              <tr key={job.id} onClick={() => onView(job.id)} className="cursor-pointer hover:bg-accent/30 transition-colors">
                <td className="p-4">
                  <span className="font-mono text-sm text-foreground">{job.target}</span>
                  <span className="ml-2 text-xs text-muted-foreground uppercase">{job.targetType.replace("_", " ")}</span>
                </td>
                <td className="p-4"><StatusBadge status={job.status} /></td>
                <td className="p-4">
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-muted/30 text-muted-foreground">
                    {job.scanDepth || "standard"}
                  </span>
                </td>
                <td className="p-4 text-foreground font-semibold">{job.totalFound}</td>
                <td className="p-4 text-[#00b8d4] font-semibold">{job.newAssets}</td>
                <td className="p-4 text-xs text-muted-foreground">{timeAgo(job.startedAt || job.createdAt)}</td>
                <td className="p-4">
                  <div className="flex items-center justify-end gap-2">
                    <Button size="sm" variant="outline" onClick={(e) => { e.stopPropagation(); onView(job.id); }}
                      className="border-border text-foreground hover:bg-accent">Details</Button>
                    {job.status !== "running" && job.status !== "pending" && (
                      <Button size="sm" variant="outline" onClick={(e) => onDelete(job.id, e)}
                        className="border-red-500/30 text-red-400 hover:bg-red-500/10"><Trash2 className="w-3 h-3" /></Button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {!loading && jobs.length === 0 && (
              <tr><td colSpan={7} className="p-8 text-center text-sm text-muted-foreground">
                No discovery jobs yet. Enter a target above to get started.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}