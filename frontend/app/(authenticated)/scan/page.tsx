// FILE: app/(authenticated)/scan/page.tsx
// Scan Jobs — list all scan jobs with status, search, auto-refresh
// ✅ M9 RBAC: permission-gated actions via useOrg().canDo()
"use client";

import React, { useEffect, useMemo, useState, useCallback } from "react";
import {
  Activity, Clock, RefreshCcw, Trash2, Search, ExternalLink,
  CheckCircle2, XCircle, Loader2, AlertCircle, Shield,
} from "lucide-react";
import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import { useOrg } from "../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../ui/plan-limit-dialog";
import { getScanJobs, deleteScanJob, isPlanError } from "../../lib/api";

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
    default: return "bg-muted/30 text-muted-foreground";
  }
}

function jobStatusIcon(status: string) {
  switch (status) {
    case "completed": return CheckCircle2;
    case "running": return Loader2;
    case "queued": return Clock;
    case "failed": return XCircle;
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
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const load = useCallback(async () => {
    try { setLoading(true); setJobs(await getScanJobs()); }
    catch {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (!jobs.some((j) => j.status === "running" || j.status === "queued")) return; const iv = setInterval(load, 5000); return () => clearInterval(iv); }, [jobs, load]);
  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 5000); return () => clearTimeout(t); } }, [banner]);

  async function handleDelete(jobId: string) {
    if (!confirm("Delete this scan job?")) return;
    try {
      await deleteScanJob(jobId);
      setJobs((p) => p.filter((j) => String(j.id) !== jobId));
      setBanner({ kind: "ok", text: "Deleted." });
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    }
  }

  const filtered = useMemo(() => {
    if (!searchFilter.trim()) return jobs;
    const s = searchFilter.toLowerCase();
    return jobs.filter((j) => (j.assetValue || "").toLowerCase().includes(s) || (j.groupName || "").toLowerCase().includes(s) || (j.profileName || "").toLowerCase().includes(s) || j.status.toLowerCase().includes(s));
  }, [jobs, searchFilter]);

  const stats = useMemo(() => ({
    total: jobs.length,
    running: jobs.filter((j) => j.status === "running").length,
    queued: jobs.filter((j) => j.status === "queued").length,
    completed: jobs.filter((j) => j.status === "completed").length,
    failed: jobs.filter((j) => j.status === "failed").length,
  }), [jobs]);

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8 space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-foreground flex items-center gap-3"><Activity className="w-7 h-7 text-primary" />Scan Jobs</h1>
          <p className="text-muted-foreground mt-1">Track and manage your vulnerability scan jobs.</p>
        </div>

        {banner && (
          <div className={cn("rounded-xl border px-4 py-3 text-sm", banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>{banner.text}</div>
        )}

        {/* Stats */}
        <div className="flex items-center gap-6 bg-card border border-border rounded-xl px-6 py-4">
          <div className="flex items-center gap-2"><span className="text-2xl font-bold text-foreground">{stats.total}</span><span className="text-xs text-muted-foreground">Total</span></div>
          <div className="w-px h-8 bg-border" />
          <div className="flex items-center gap-2"><Loader2 className="w-4 h-4 text-[#00b8d4]" /><span className="text-2xl font-bold text-[#00b8d4]">{stats.running}</span><span className="text-xs text-muted-foreground">Running</span></div>
          <div className="w-px h-8 bg-border" />
          <div className="flex items-center gap-2"><Clock className="w-4 h-4 text-[#ffcc00]" /><span className="text-2xl font-bold text-[#ffcc00]">{stats.queued}</span><span className="text-xs text-muted-foreground">Queued</span></div>
          <div className="w-px h-8 bg-border" />
          <div className="flex items-center gap-2"><CheckCircle2 className="w-4 h-4 text-[#10b981]" /><span className="text-2xl font-bold text-[#10b981]">{stats.completed}</span><span className="text-xs text-muted-foreground">Completed</span></div>
          <div className="w-px h-8 bg-border" />
          <div className="flex items-center gap-2"><XCircle className="w-4 h-4 text-red-400" /><span className="text-2xl font-bold text-red-400">{stats.failed}</span><span className="text-xs text-muted-foreground">Failed</span></div>
        </div>

        {/* Toolbar */}
        <div className="flex items-center justify-between gap-4">
          <div className="relative flex-1 max-w-md"><Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" /><Input placeholder="Search jobs..." value={searchFilter} onChange={(e) => setSearchFilter(e.target.value)} className="pl-9" /></div>
          <Button variant="ghost" size="sm" onClick={load} className="text-primary hover:bg-primary/10"><RefreshCcw className="w-4 h-4 mr-2" />Refresh</Button>
        </div>

        {/* Table */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          {loading ? <div className="p-8 text-center text-muted-foreground text-sm">Loading...</div> : filtered.length === 0 ? (
            <div className="p-8 text-center"><Activity className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" /><p className="text-muted-foreground text-sm">{jobs.length === 0 ? "No scan jobs yet. Start a scan from the Initiate Scan page." : `No results for "${searchFilter}".`}</p></div>
          ) : (
            <div className="overflow-x-auto"><table className="w-full">
              <thead className="bg-muted/30"><tr>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Status</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Asset</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Profile</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Started</th>
                <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Completed</th>
                <th className="text-right p-4 text-sm font-semibold text-muted-foreground">Actions</th>
              </tr></thead>
              <tbody className="divide-y divide-border">
                {filtered.map((job) => {
                  const StatusIcon = jobStatusIcon(job.status);
                  const pm = getProfileMetaByName(job.profileName);
                  return (
                    <tr key={job.id} className="hover:bg-accent/30 transition-colors">
                      <td className="p-4"><span className={cn("inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-semibold", jobStatusBadge(job.status))}><StatusIcon className={cn("w-3 h-3", job.status === "running" && "animate-spin")} />{job.status}</span></td>
                      <td className="p-4"><div className="flex flex-col gap-0.5"><span className="font-mono text-sm text-foreground">{job.assetValue || `Asset #${job.assetId}`}</span>{job.groupName && <span className="text-xs text-muted-foreground">{job.groupName}</span>}</div></td>
                      <td className="p-4">{job.profileName ? <span className={cn("px-2 py-0.5 rounded text-xs font-semibold", pm.bg, pm.color)}>{job.profileName}</span> : <span className="text-xs text-muted-foreground">-</span>}</td>
                      <td className="p-4"><span className="text-sm text-muted-foreground">{formatWhen(job.startedAt || job.createdAt)}</span></td>
                      <td className="p-4"><span className="text-sm text-muted-foreground">{job.finishedAt ? formatWhen(job.finishedAt) : job.status === "running" ? "In progress..." : "-"}</span></td>
                      <td className="p-4"><div className="flex items-center justify-end gap-2">
                        {job.status === "completed" && <a href={`/scan-jobs/${job.id}`}><Button size="sm" variant="outline" className="border-primary/50 text-primary hover:bg-primary/10"><ExternalLink className="w-3 h-3 mr-1" />Details</Button></a>}
                        {canDelete && (job.status === "completed" || job.status === "failed") && <Button size="sm" variant="outline" onClick={() => handleDelete(String(job.id))} className="border-red-500/50 text-red-500 hover:bg-red-500/10"><Trash2 className="w-3 h-3" /></Button>}
                      </div></td>
                    </tr>
                  );
                })}
              </tbody>
            </table></div>
          )}
        </div>
      </div>

      <PlanLimitDialog {...planLimit} />
    </main>
  );
}