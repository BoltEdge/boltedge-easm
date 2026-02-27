// app/(authenticated)/assets/page.tsx
"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Plus, ChevronRight, Layers, MoreVertical, Pencil, Trash2,
  Search, X, List, AlertTriangle, Shield, Clock, RefreshCcw, Download,
} from "lucide-react";

import type { AssetGroup, Asset } from "../../types";
import { createGroup, deleteGroup, getGroups, renameGroup, getAllAssets, isPlanError } from "../../lib/api";
import { useOrg } from "../contexts/OrgContext";

import { Button } from "../../ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "../../ui/dialog";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "../../ui/dropdown-menu";
import { usePlanLimit, PlanLimitDialog } from "../../ui/plan-limit-dialog";
import { AssetsPageSkeleton } from "../../ui/skeleton";

function cn(...classes: Array<string | undefined | null | false>) {
  return classes.filter(Boolean).join(" ");
}

function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "Never";
  let d: Date;
  if (typeof iso === "string" && !iso.endsWith("Z") && !iso.includes("+")) d = new Date(iso + "Z");
  else d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 60) return "just now";
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-blue-500", info: "bg-zinc-500",
};

const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-500/15 text-red-300 border-red-500/30",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-300 border-blue-500/30",
  info: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
  clean: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
};

function SeverityBar({ findings }: { findings: any }) {
  const total = findings?.total || 0;
  const sevs = ["critical", "high", "medium", "low", "info"] as const;
  return (
    <div className="flex h-1.5 overflow-hidden bg-muted/30 w-full">
      {total > 0 && sevs.map((s) => {
        const count = findings[s] || 0;
        if (count === 0) return null;
        const pct = (count / total) * 100;
        return <div key={s} className={cn(SEV_COLORS[s], "h-full")} style={{ width: `${pct}%` }} />;
      })}
    </div>
  );
}

function exportGroupsCsv(groups: any[], assetsByGroupId: Map<string, Asset[]>) {
  const rows = [["Group", "Asset Type", "Asset Value", "Label", "Last Scan", "Max Severity", "Open Findings"]];
  for (const g of groups) {
    const groupAssets = assetsByGroupId.get(String(g.id)) || [];
    if (groupAssets.length === 0) {
      rows.push([g.name, "", "", "", "", "", ""]);
    } else {
      for (const a of groupAssets) {
        rows.push([
          g.name, (a as any).type || (a as any).asset_type || "", a.value || "",
          (a as any).label || "", (a as any).lastScanAt || "",
          (a as any).maxSeverity || "", String((a as any).openFindings ?? ""),
        ]);
      }
    }
  }
  const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `asset-groups-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

export default function Page() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [groups, setGroups] = useState<any[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [newGroupName, setNewGroupName] = useState("");
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [editingGroup, setEditingGroup] = useState<{ id: string; name: string } | null>(null);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [deletingGroup, setDeletingGroup] = useState<{ id: string; name: string } | null>(null);
  const planLimit = usePlanLimit();

  const { canDo } = useOrg();
  const canCreateGroups = canDo("create_groups");
  const canEditGroups = canDo("edit_groups");
  const canDeleteGroups = canDo("delete_groups");
  const canExport = canDo("export_assets");

  const loadData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true); else setLoading(true);
    setError(null);
    try {
      const [gRows, aRows] = await Promise.all([getGroups(), getAllAssets()]);
      setGroups(gRows); setAssets(aRows);
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setError(e?.message || "Failed to load data");
    } finally { setLoading(false); setRefreshing(false); }
  }, [planLimit]);

  useEffect(() => { loadData(); }, []);

  const assetsByGroupId = useMemo(() => {
    const map = new Map<string, Asset[]>();
    for (const a of assets) {
      const gid = String((a as any).groupId ?? (a as any).group_id ?? "");
      if (!gid) continue;
      if (!map.has(gid)) map.set(gid, []);
      map.get(gid)!.push(a);
    }
    return map;
  }, [assets]);

  const filteredGroups = useMemo(() => {
    const q = query.trim().toLowerCase();
    let result = groups;
    if (q) {
      result = groups.filter((g: any) => {
        if (String(g.name || "").toLowerCase().includes(q)) return true;
        const list = assetsByGroupId.get(String(g.id)) || [];
        return list.some((a: any) => {
          const v = String(a.value || "").toLowerCase();
          const l = String(a.label || "").toLowerCase();
          const t = String(a.type || a.asset_type || "").toLowerCase();
          return v.includes(q) || l.includes(q) || t.includes(q);
        });
      });
    }
    const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, clean: 5 };
    return [...result].sort((a: any, b: any) => {
      const aF = a.findings?.total || 0, bF = b.findings?.total || 0;
      if (aF > 0 && bF === 0) return -1;
      if (aF === 0 && bF > 0) return 1;
      if (aF > 0 && bF > 0) {
        const aS = sevOrder[a.maxSeverity || "clean"] ?? 5;
        const bS = sevOrder[b.maxSeverity || "clean"] ?? 5;
        if (aS !== bS) return aS - bS;
        return bF - aF;
      }
      const aScanned = Boolean(a.lastScanAt), bScanned = Boolean(b.lastScanAt);
      if (aScanned && !bScanned) return -1;
      if (!aScanned && bScanned) return 1;
      return 0;
    });
  }, [groups, query, assetsByGroupId]);

  const handleCreateGroup = async () => {
    const name = newGroupName.trim();
    if (!name) return;
    try {
      setError(null); await createGroup(name);
      setNewGroupName(""); setIsCreateOpen(false); await loadData();
    } catch (e: any) {
      if (isPlanError(e)) { setIsCreateOpen(false); planLimit.handle(e.planError); }
      else setError(e?.message || "Failed to create group");
    }
  };

  const confirmEdit = async () => {
    if (!editingGroup) return;
    const name = editingGroup.name.trim();
    if (!name) return;
    try {
      setError(null); await renameGroup(editingGroup.id, name);
      setEditingGroup(null); setIsEditOpen(false); await loadData();
    } catch (e: any) {
      if (isPlanError(e)) { setIsEditOpen(false); planLimit.handle(e.planError); }
      else setError(e?.message || "Failed to rename group");
    }
  };

  const confirmDelete = async () => {
    if (!deletingGroup) return;
    try {
      setError(null); await deleteGroup(deletingGroup.id);
      setDeletingGroup(null); setIsDeleteOpen(false); await loadData();
    } catch (e: any) {
      if (isPlanError(e)) { setIsDeleteOpen(false); planLimit.handle(e.planError); }
      else setError(e?.message || "Failed to delete group");
    }
  };

  if (loading) return <AssetsPageSkeleton />;

  if (groups.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center bg-background">
        <div className="text-center max-w-md">
          <div className="w-20 h-20 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto mb-6"><Layers className="w-10 h-10 text-primary" /></div>
          <h2 className="text-xl font-semibold text-foreground mb-2">No asset groups yet</h2>
          <p className="text-muted-foreground mb-6">Asset groups help you organize and monitor related assets together. Create your first group to get started.</p>
          {error && <p className="mb-4 text-sm text-red-300">{error}</p>}
          {canCreateGroups ? (
            <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
              <DialogTrigger asChild><Button className="bg-primary hover:bg-primary/90"><Plus className="w-4 h-4 mr-2" />Create your first group</Button></DialogTrigger>
              <DialogContent className="bg-card border-border">
                <DialogHeader><DialogTitle className="text-foreground">Create Asset Group</DialogTitle></DialogHeader>
                <div className="space-y-4 py-4">
                  <div className="space-y-2"><Label htmlFor="group-name" className="text-foreground">Group Name</Label><Input id="group-name" placeholder="e.g., Production Infrastructure" value={newGroupName} onChange={(e) => setNewGroupName(e.target.value)} className="bg-input-background border-border text-foreground" /></div>
                  <Button onClick={handleCreateGroup} className="w-full bg-primary hover:bg-primary/90" disabled={!newGroupName.trim()}>Create Group</Button>
                  {error && <p className="text-sm text-red-300">{error}</p>}
                </div>
              </DialogContent>
            </Dialog>
          ) : (<p className="text-sm text-muted-foreground">Ask an admin or owner to create asset groups.</p>)}
          <PlanLimitDialog {...planLimit} />
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 bg-background overflow-auto">
      <div className="p-8">
        {/* Header */}
        <div className="flex justify-between items-start mb-8 gap-6">
          <div>
            <h1 className="text-2xl font-semibold text-foreground mb-1">Asset Groups</h1>
            <p className="text-muted-foreground">Organize and manage your monitored assets</p>
            {error && <p className="mt-2 text-sm text-red-300">{error}</p>}
          </div>
          <div className="flex items-center gap-3">
            <Button variant="outline" onClick={() => loadData(true)} disabled={refreshing} className="border-border text-foreground hover:bg-accent">
              <RefreshCcw className={`w-4 h-4 mr-2 ${refreshing ? "animate-spin" : ""}`} />{refreshing ? "Refreshing…" : "Refresh"}
            </Button>
            {canExport && (<Button variant="outline" onClick={() => exportGroupsCsv(groups, assetsByGroupId)} className="border-border text-foreground hover:bg-accent"><Download className="w-4 h-4 mr-2" />Export</Button>)}
            <Link href="/assets/all"><Button variant="outline" className="gap-2"><List className="w-4 h-4" />View All Assets</Button></Link>
            {canCreateGroups && (
              <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
                <DialogTrigger asChild><Button className="bg-primary hover:bg-primary/90"><Plus className="w-4 h-4 mr-2" />New Group</Button></DialogTrigger>
                <DialogContent className="bg-card border-border">
                  <DialogHeader><DialogTitle className="text-foreground">Create Asset Group</DialogTitle></DialogHeader>
                  <div className="space-y-4 py-4">
                    <div className="space-y-2"><Label htmlFor="group-name-2" className="text-foreground">Group Name</Label><Input id="group-name-2" placeholder="e.g., Production Infrastructure" value={newGroupName} onChange={(e) => setNewGroupName(e.target.value)} className="bg-input-background border-border text-foreground" /></div>
                    <Button onClick={handleCreateGroup} className="w-full bg-primary hover:bg-primary/90" disabled={!newGroupName.trim()}>Create Group</Button>
                    {error && <p className="text-sm text-red-300">{error}</p>}
                  </div>
                </DialogContent>
              </Dialog>
            )}
          </div>
        </div>

        {/* Search */}
        <div className="flex items-center justify-between gap-3 mb-6">
          <div className="relative w-full max-w-lg">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input className="pl-9" placeholder="Search groups or assets (name, value, label, type)…" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          {query.trim() && <Button variant="outline" onClick={() => setQuery("")} className="gap-2"><X className="w-4 h-4" />Clear</Button>}
        </div>
        {query.trim() && <p className="text-sm text-muted-foreground mb-4">Showing {filteredGroups.length} of {groups.length} groups</p>}

        {/* Group Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredGroups.map((group: any) => {
            const findings = group.findings || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
            const maxSev = group.maxSeverity || "clean";
            const lastScan = group.lastScanAt;
            const hasFindings = findings.total > 0;
            const exposureScore = group.exposureScore;

            // Build asset type counts string (include cloud)
            const typeCounts = [
              group.domainCount > 0 && `${group.domainCount} domain${group.domainCount !== 1 ? "s" : ""}`,
              group.ipCount > 0 && `${group.ipCount} IP${group.ipCount !== 1 ? "s" : ""}`,
              group.emailCount > 0 && `${group.emailCount} email${group.emailCount !== 1 ? "s" : ""}`,
              group.cloudCount > 0 && `${group.cloudCount} cloud`,
            ].filter(Boolean).join(", ") || "0 assets";

            return (
              <div key={group.id} className="relative group/card">
                <Link href={`/groups/${group.id}`} className="block bg-card border border-border rounded-xl hover:border-primary/50 hover:shadow-lg hover:shadow-primary/5 transition-all overflow-hidden">
                  <SeverityBar findings={findings} />
                  <div className="p-5">
                    {/* Top row */}
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center shrink-0"><Layers className="w-5 h-5 text-primary" /></div>
                        <div className="min-w-0">
                          <h3 className="text-base font-semibold text-foreground truncate">{group.name}</h3>
                          <p className="text-xs text-muted-foreground mt-0.5">{typeCounts}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5">
                        {(canEditGroups || canDeleteGroups) && (
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <button className="p-1.5 rounded-md hover:bg-accent transition-colors opacity-0 group-hover/card:opacity-100" type="button" onClick={(e) => { e.preventDefault(); e.stopPropagation(); }}>
                                <MoreVertical className="w-4 h-4 text-muted-foreground" />
                              </button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              {canEditGroups && (<DropdownMenuItem onClick={(e) => { e.preventDefault(); e.stopPropagation(); setEditingGroup({ id: group.id, name: group.name }); setIsEditOpen(true); }}><Pencil className="w-4 h-4" />Edit</DropdownMenuItem>)}
                              {canDeleteGroups && (<DropdownMenuItem variant="destructive" onClick={(e) => { e.preventDefault(); e.stopPropagation(); setDeletingGroup({ id: group.id, name: group.name }); setIsDeleteOpen(true); }}><Trash2 className="w-4 h-4" />Delete</DropdownMenuItem>)}
                            </DropdownMenuContent>
                          </DropdownMenu>
                        )}
                        <ChevronRight className="w-4 h-4 text-muted-foreground group-hover/card:text-primary transition-colors" />
                      </div>
                    </div>

                    {/* Risk + Exposure + Last Scan row */}
                    <div className="flex items-center justify-between mt-3 pt-3 border-t border-border">
                      <div className="flex items-center gap-2">
                        {hasFindings ? (
                          <>
                            <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] font-bold uppercase", SEV_BADGE[maxSev] || SEV_BADGE.clean)}>
                              <AlertTriangle className="w-3 h-3" />{maxSev}
                            </span>
                            <span className="text-xs text-muted-foreground">{findings.total} finding{findings.total !== 1 ? "s" : ""}</span>
                          </>
                        ) : (
                          <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] font-bold uppercase", SEV_BADGE.clean)}>
                            <Shield className="w-3 h-3" />Clean
                          </span>
                        )}
                        {/* Exposure score pill */}
                        {exposureScore && exposureScore.score > 0 && (
                          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold"
                            style={{ color: exposureScore.color, backgroundColor: `${exposureScore.color}15`, border: `1px solid ${exposureScore.color}30` }}>
                            {exposureScore.score}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1 text-xs text-muted-foreground">
                        <Clock className="w-3 h-3" />{lastScan ? timeAgo(lastScan) : "Never scanned"}
                      </div>
                    </div>

                    {/* Mini severity breakdown */}
                    {hasFindings && (findings.critical > 0 || findings.high > 0) && (
                      <div className="flex items-center gap-3 mt-2 text-[10px]">
                        {findings.critical > 0 && <span className="text-red-300">{findings.critical} critical</span>}
                        {findings.high > 0 && <span className="text-orange-300">{findings.high} high</span>}
                        {findings.medium > 0 && <span className="text-yellow-300">{findings.medium} med</span>}
                      </div>
                    )}
                  </div>
                </Link>
              </div>
            );
          })}
        </div>

        {filteredGroups.length === 0 && (
          <div className="mt-10 text-center text-muted-foreground">{query.trim() ? "No matching groups/assets found." : "No groups found."}</div>
        )}
      </div>

      {/* Edit Dialog */}
      <Dialog open={isEditOpen} onOpenChange={setIsEditOpen}>
        <DialogContent className="bg-card border-border">
          <DialogHeader><DialogTitle className="text-foreground">Edit Asset Group</DialogTitle></DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2"><Label htmlFor="edit-group-name" className="text-foreground">Group Name</Label><Input id="edit-group-name" placeholder="e.g., Production Infrastructure" value={editingGroup?.name || ""} onChange={(e) => setEditingGroup(editingGroup ? { ...editingGroup, name: e.target.value } : null)} className="bg-input-background border-border text-foreground" /></div>
            <div className="flex gap-3">
              <Button variant="outline" onClick={() => { setEditingGroup(null); setIsEditOpen(false); }} className="flex-1 border-border text-foreground hover:bg-accent">Cancel</Button>
              <Button onClick={confirmEdit} className="flex-1 bg-primary hover:bg-primary/90" disabled={!editingGroup?.name?.trim()}>Save Changes</Button>
            </div>
            {error && <p className="text-sm text-red-300">{error}</p>}
          </div>
        </DialogContent>
      </Dialog>

      {/* Delete Dialog */}
      <Dialog open={isDeleteOpen} onOpenChange={setIsDeleteOpen}>
        <DialogContent className="bg-card border-border">
          <DialogHeader><DialogTitle className="text-foreground">Delete Asset Group</DialogTitle></DialogHeader>
          <div className="space-y-4 py-4">
            <p className="text-muted-foreground">Are you sure you want to delete <span className="text-foreground font-semibold">{deletingGroup?.name}</span>? This action cannot be undone.</p>
            <div className="flex gap-3">
              <Button variant="outline" onClick={() => { setDeletingGroup(null); setIsDeleteOpen(false); }} className="flex-1 border-border text-foreground hover:bg-accent">Cancel</Button>
              <Button onClick={confirmDelete} className="flex-1 bg-[#ef4444] hover:bg-[#dc2626] text-white">Delete Group</Button>
            </div>
            {error && <p className="text-sm text-red-300">{error}</p>}
          </div>
        </DialogContent>
      </Dialog>

      {/* Plan limit dialog */}
      <PlanLimitDialog {...planLimit} />
    </div>
  );
}