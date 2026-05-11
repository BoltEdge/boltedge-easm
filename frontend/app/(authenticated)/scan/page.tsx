"use client";

import React, { useEffect, useMemo, useState, useCallback } from "react";
import {
  Activity, Clock, RefreshCcw, Trash2, Search, Eye, Ban,
  CheckCircle2, XCircle, Loader2, AlertCircle, Shield,
} from "lucide-react";
import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../ui/dialog";
import { useOrg } from "../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../ui/plan-limit-dialog";
import { getScanJobs, deleteScanJob, cancelScanJob, isPlanError } from "../../lib/api";
import { PageHint, PageHintToggle } from "../../ui/PageHint";

function cn(...parts: Array<string | false | null | undefined>) { return parts.filter(Boolean).join(" "); }

function formatWhen(iso?: string | null) {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
}

function getProfileMetaByName(name?: string) {
  const n = (name || "").toLowerCase();
  if (n.includes("deep")) return { icon: Shield, color: "text-[#ff8800]", bg: "bg-[#ff8800]/10" };
  if (n.includes("standard")) return { icon: Shield, color: "text-primary", bg: "bg-primary/10" };
  return { icon: Shield, color: "text-[#00b8d4]", bg: "bg-[#00b8d4]/10" };
}

function jobStatusBadge(status: string) {
  switch (status) {
    case "completed": return "bg-[#10b981]/10 text-[#10b981]";
    case "running": return "bg-[#00b8d4]/10 text-[#00b8d4]";
    case "queued": return "bg-[#ffcc00]/10 text-[#ffcc00]";
    case "failed": return "bg-red-500/10 text-red-400";
    case "cancelled": return "bg-amber-500/10 text-amber-400";
    default: return "bg-muted/30 text-muted-foreground";
  }
}

function jobStatusIcon(status: string) {
  switch (status) {
    case "completed": return CheckCircle2;
    case "running": return Loader2;
    case "queued": return Clock;
    case "failed": return XCircle;
    case "cancelled": return Ban;
    default: return AlertCircle;
  }
}

export default function ScanJobsPage() {
  const { canDo } = useOrg();
  const planLimit = usePlanLimit();
  const canDelete = canDo("delete_scans");

  const [jobs, setJobs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchFilter, setSearchFilter] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; label: string } | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [cancellingId, setCancellingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try { setLoading(true); setJobs(await getScanJobs()); }
    catch {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (!jobs.some((j) => j.status === "running" || j.status === "queued")) return; const iv = setInterval(load, 5000); return () => clearInterval(iv); }, [jobs, load]);
  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 5000); return () => clearTimeout(t); } }, [banner]);

  async function handleCancel(jobId: string, label: string) {
    if (!confirm(`Cancel the scan for ${label}? The job will be marked cancelled and any in-progress results discarded.`)) return;
    try {
      setCancellingId(jobId);
      await cancelScanJob(jobId);
      setBanner({ kind: "ok", text: "Scan cancelled." });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to cancel scan." });
    } finally { setCancellingId(null); }
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    try {
      setDeleting(true);
      await deleteScanJob(deleteTarget.id);
      setJobs((p) => p.filter((j) => String(j.id) !== deleteTarget.id));
      setBanner({ kind: "ok", text: "Deleted." });
      setDeleteTarget(null);
    } catch (e: any) {
      if (isPlanError(e)) { setDeleteTarget(null); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    } finally { setDeleting(false); }
  }

  const [statusFilter, setStatusFilter] = useState<string>("all");

  const filtered = useMemo(() => {
    let result = jobs;
    if (statusFilter !== "all") result = result.filter((j) => j.status === statusFilter);
    if (searchFilter.trim()) {
      const s = searchFilter.toLowerCase();
      result = result.filter((j) => (j.assetValue || "").toLowerCase().includes(s) || (j.groupName || "").toLowerCase().includes(s) || (j.profileName || "").toLowerCase().includes(s));
    }
    return result;
  }, [jobs, searchFilter, statusFilter]);

  const stats = useMemo(() => ({
    total: jobs.length,
    running: jobs.filter((j) => j.status === "running").length,
    queued: jobs.filter((j) => j.status === "queued").length,
    completed: jobs.filter((j) => j.status === "completed").length,
    failed: jobs.filter((j) => j.status === "failed").length,
  }), [jobs]);

  // Failure-rate warning — surfaces when the failed-to-finished ratio
  // crosses 15%. The threshold is intentionally low: customers should
  // notice systemic failures (bad creds, API outage, plan throttle)
  // before they bury themselves in re-runs.
  const failureRate = useMemo(() => {
    const finished = stats.completed + stats.failed;
    if (finished === 0) return 0;
    return Math.round((stats.failed / finished) * 100);
  }, [stats]);
  const showFailureWarning = failureRate >= 15 && stats.failed >= 3;

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const failedJobs = useMemo(() => jobs.filter((j) => j.status === "failed"), [jobs]);
  const selectedFailed = useMemo(
    () => failedJobs.filter((j) => selectedIds.has(String(j.id))),
    [failedJobs, selectedIds]
  );
  function toggleSelected(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }
  function selectAllFailed() {
    setSelectedIds(new Set(failedJobs.map((j) => String(j.id))));
  }
  function clearSelection() {
    setSelectedIds(new Set());
  }
  async function deleteSelectedFailed() {
    if (selectedFailed.length === 0) return;
    if (!confirm(`Delete ${selectedFailed.length} failed scan job${selectedFailed.length === 1 ? "" : "s"}? This removes the jobs from history; assets are untouched.`)) return;
    let ok = 0, err = 0;
    for (const job of selectedFailed) {
      try { await deleteScanJob(String(job.id)); ok++; }
      catch { err++; }
    }
    setJobs((p) => p.filter((j) => !(j.status === "failed" && selectedIds.has(String(j.id)))));
    setSelectedIds(new Set());
    setBanner({
      kind: err === 0 ? "ok" : "err",
      text: err === 0
        ? `Deleted ${ok} failed scan${ok === 1 ? "" : "s"}.`
        : `Deleted ${ok}, ${err} failed to delete.`,
    });
  }

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8 space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-foreground flex items-center gap-3">
            <Activity className="w-7 h-7 text-primary" />
            Scan Jobs
            <PageHintToggle pageKey="scan-jobs" />
          </h1>
          <p className="text-muted-foreground mt-1">Track and manage your scan jobs.</p>
        </div>

        <PageHint
          pageKey="scan-jobs"
          title="Scan jobs"
          body="On-demand security scans — port scanning, exposure data, CVE enrichment, configuration and TLS checks. Pick a profile (Quick / Standard / Deep / Full), target an asset or group, then review the findings."
          action={{ label: "Start a new scan", href: "/scan/initiate" }}
        />

        {banner && (
          <div className={cn("rounded-xl border px-4 py-3 text-sm", banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>{banner.text}</div>
        )}

        {/* Stats — compact chip row instead of the previous full-bleed
            5-card layout. Same data, ~1/3 the vertical space, and
            clickable to filter by that status. */}
        <div className="flex items-center gap-2 flex-wrap">
          {[
            { key: "all",       label: "Total",     value: stats.total,     icon: Activity,     color: "text-foreground",    activeBg: "bg-foreground/10 border-foreground/30" },
            { key: "running",   label: "Running",   value: stats.running,   icon: Loader2,      color: "text-[#00b8d4]",     activeBg: "bg-[#00b8d4]/10 border-[#00b8d4]/40", spin: true },
            { key: "queued",    label: "Queued",    value: stats.queued,    icon: Clock,        color: "text-[#ffcc00]",     activeBg: "bg-[#ffcc00]/10 border-[#ffcc00]/40" },
            { key: "completed", label: "Completed", value: stats.completed, icon: CheckCircle2, color: "text-[#10b981]",     activeBg: "bg-[#10b981]/10 border-[#10b981]/40" },
            { key: "failed",    label: "Failed",    value: stats.failed,    icon: XCircle,      color: "text-red-400",       activeBg: "bg-red-500/10 border-red-500/40" },
          ].map(({ key, label, value, icon: Icon, color, activeBg, spin }) => {
            const active = statusFilter === key;
            return (
              <button
                key={key}
                onClick={() => setStatusFilter(key)}
                className={cn(
                  "inline-flex items-center gap-2 px-3 py-1.5 rounded-full border text-sm transition-colors",
                  active ? activeBg : "border-border bg-card/40 hover:bg-card/60"
                )}
              >
                <Icon className={cn("w-3.5 h-3.5", color, spin && value > 0 && "animate-spin")} />
                <span className={cn("font-bold tabular-nums", color)}>{value}</span>
                <span className="text-muted-foreground">{label}</span>
              </button>
            );
          })}
        </div>

        {/* High-failure-rate warning — surfaces only when something looks
            systemically wrong (>=15% failure rate AND >=3 failures). */}
        {showFailureWarning && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/[0.05] px-4 py-3 flex items-start gap-3">
            <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0">
              <p className="text-sm text-red-200">
                <span className="font-semibold">{failureRate}% failure rate</span> across {stats.completed + stats.failed} finished scans
                <span className="text-red-300/70"> · this is unusually high — check the failure reasons below or contact support.</span>
              </p>
            </div>
            <button
              onClick={() => setStatusFilter("failed")}
              className="shrink-0 text-xs font-medium text-red-300 hover:text-red-200 underline underline-offset-2"
            >
              Show failed only →
            </button>
          </div>
        )}

        {/* Bulk-action bar — surfaces when one or more failed scans are
            selected. Lives above the toolbar so it doesn't shift table
            rows when it appears/disappears. */}
        {selectedIds.size > 0 && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/[0.05] px-4 py-3 flex items-center gap-3 flex-wrap">
            <span className="text-sm text-foreground">
              <span className="font-semibold">{selectedFailed.length}</span> failed scan{selectedFailed.length === 1 ? "" : "s"} selected
            </span>
            <div className="flex-1" />
            <Button variant="outline" size="sm" onClick={clearSelection} className="border-border text-foreground hover:bg-accent">
              Clear
            </Button>
            <Button size="sm" onClick={deleteSelectedFailed} className="bg-red-500 hover:bg-red-600 text-white">
              <Trash2 className="w-3 h-3 mr-1.5" />Delete {selectedFailed.length} selected
            </Button>
          </div>
        )}

        {/* Toolbar — search + status dropdown (mirror of the chip row for
            keyboard / accessibility users) + select-all-failed shortcut +
            refresh. */}
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-2 flex-1 min-w-0 max-w-2xl">
            <div className="relative flex-1 min-w-0">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input placeholder="Search by asset, group, or profile..." value={searchFilter} onChange={(e) => setSearchFilter(e.target.value)} className="pl-9" />
            </div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="h-10 rounded-md border border-border bg-input-background px-3 text-sm text-foreground outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="all">All statuses</option>
              <option value="running">Running</option>
              <option value="queued">Queued</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            {failedJobs.length > 0 && statusFilter === "failed" && selectedIds.size === 0 && (
              <Button variant="outline" size="sm" onClick={selectAllFailed} className="border-border text-foreground hover:bg-accent">
                Select all failed ({failedJobs.length})
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={load} className="border-border text-foreground hover:bg-accent">
              <RefreshCcw className={cn("w-4 h-4 mr-2", loading && "animate-spin")} />Refresh
            </Button>
          </div>
        </div>

        {/* Table */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          {loading ? <div className="p-8 text-center text-muted-foreground text-sm">Loading...</div> : filtered.length === 0 ? (
            <div className="p-8 text-center"><Activity className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" /><p className="text-muted-foreground text-sm">{jobs.length === 0 ? "No scan jobs yet. Start a scan from the Initiate Scan page." : `No results for "${searchFilter}".`}</p></div>
          ) : (
            <div className="overflow-x-auto"><table className="w-full">
              <thead className="bg-muted/30"><tr>
                <th className="w-10 p-4"></th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Status</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Asset</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Profile</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Initiator</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Started</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Completed</th>
                <th className="text-right p-4 text-sm font-semibold text-muted-foreground">Actions</th>
              </tr></thead>
              <tbody className="divide-y divide-border">
                {filtered.map((job) => {
                  const StatusIcon = jobStatusIcon(job.status);
                  const pm = getProfileMetaByName(job.profileName);
                  const isFailed = job.status === "failed";
                  return (
                    <tr key={job.id} className="hover:bg-accent/30 transition-colors">
                      <td className="p-4 align-top pt-5">
                        {isFailed && canDelete && (
                          <input
                            type="checkbox"
                            aria-label="Select failed scan"
                            checked={selectedIds.has(String(job.id))}
                            onChange={() => toggleSelected(String(job.id))}
                            className="rounded border-border bg-background text-primary focus:ring-primary/40 cursor-pointer"
                          />
                        )}
                      </td>
                      <td className="p-4">
                        <span className={cn("inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-semibold", jobStatusBadge(job.status))}>
                          <StatusIcon className={cn("w-3 h-3", job.status === "running" && "animate-spin")} />{job.status}
                        </span>
                        {job.status === "failed" && job.error && (
                          <div className="mt-1.5 text-[11px] text-red-300/80 max-w-xs leading-snug" title={job.error}>
                            {job.error.length > 80 ? `${job.error.slice(0, 80)}…` : job.error}
                          </div>
                        )}
                      </td>
                      <td className="p-4"><div className="flex flex-col gap-0.5"><span className="font-mono text-sm text-foreground">{job.assetValue || `Asset #${job.assetId}`}</span>{job.groupName && <span className="text-xs text-muted-foreground">{job.groupName}</span>}</div></td>
                      <td className="p-4">{job.profileName ? <span className={cn("px-2 py-0.5 rounded text-xs font-semibold", pm.bg, pm.color)}>{job.profileName}</span> : <span className="text-xs text-muted-foreground">-</span>}</td>
                      <td className="p-4">
                        {(() => {
                          const init = (job as any).initiator || "manual";
                          const styles: Record<string, string> = {
                            manual:    "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
                            monitor:   "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
                            scheduled: "bg-indigo-500/15 text-indigo-300 border-indigo-500/30",
                          };
                          const labels: Record<string, string> = {
                            manual: "Manual", monitor: "Monitor", scheduled: "Scheduled",
                          };
                          return (
                            <span className={cn("inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border", styles[init] || styles.manual)}>
                              {labels[init] || init}
                            </span>
                          );
                        })()}
                      </td>
                      <td className="p-4"><span className="text-sm text-muted-foreground">{formatWhen(job.startedAt || job.createdAt)}</span></td>
                      <td className="p-4"><span className="text-sm text-muted-foreground">{job.finishedAt ? formatWhen(job.finishedAt) : job.status === "running" ? "In progress..." : "-"}</span></td>
                      <td className="p-4"><div className="flex items-center justify-end gap-2">
                        {(job.status === "completed" || job.status === "failed" || job.status === "cancelled") && (
                          <a href={`/scan-jobs/${job.id}`}>
                            <Button size="sm" variant="outline" className="border-primary/50 text-primary hover:bg-primary/10">
                              <Eye className="w-3 h-3 mr-1" />Details
                            </Button>
                          </a>
                        )}
                        {(job.status === "queued" || job.status === "running") && (
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={cancellingId === String(job.id)}
                            onClick={() => handleCancel(String(job.id), job.assetValue || `Asset #${job.assetId}`)}
                            className="border-amber-500/50 text-amber-400 hover:bg-amber-500/10"
                          >
                            <Ban className="w-3 h-3 mr-1" />{cancellingId === String(job.id) ? "Cancelling…" : "Cancel"}
                          </Button>
                        )}
                        {canDelete && (job.status === "completed" || job.status === "failed" || job.status === "cancelled") && <Button size="sm" variant="outline" onClick={() => setDeleteTarget({ id: String(job.id), label: job.assetValue || `Asset #${job.assetId}` })} className="border-red-500/50 text-red-500 hover:bg-red-500/10"><Trash2 className="w-3 h-3" /></Button>}
                      </div></td>
                    </tr>
                  );
                })}
              </tbody>
            </table></div>
          )}
        </div>
      </div>

      <Dialog open={!!deleteTarget} onOpenChange={(o) => { if (!o) setDeleteTarget(null); }}>
        <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
          <DialogHeader><DialogTitle>Delete Scan Job</DialogTitle></DialogHeader>
          <p className="text-sm text-muted-foreground">Delete the scan job for <span className="font-mono text-foreground">{deleteTarget?.label}</span>? This will remove all results.</p>
          <div className="flex gap-3 justify-end pt-4">
            <Button variant="outline" onClick={() => setDeleteTarget(null)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
            <Button onClick={confirmDelete} disabled={deleting} className="bg-[#ef4444] hover:bg-[#dc2626] text-white">{deleting ? "Deleting..." : "Delete"}</Button>
          </div>
        </DialogContent>
      </Dialog>

      <PlanLimitDialog {...planLimit} />
    </main>
  );
}