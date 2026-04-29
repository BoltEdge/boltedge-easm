"use client";
import { useEffect, useState, useCallback, useRef } from "react";
import { getAdminScans } from "../../../lib/api";
import { RefreshCw, ScanLine, Globe, CheckCircle2, XCircle, Clock, Loader2, ChevronRight } from "lucide-react";
import Link from "next/link";

const STATUS_STYLES: Record<string, string> = {
  queued: "text-gray-300 bg-gray-500/10",
  pending: "text-gray-300 bg-gray-500/10",
  running: "text-teal-300 bg-teal-500/10",
  completed: "text-emerald-300 bg-emerald-500/10",
  partial: "text-amber-300 bg-amber-500/10",
  failed: "text-red-300 bg-red-500/10",
  cancelled: "text-gray-400 bg-gray-500/10",
};

function fmtDuration(secs: number | null): string {
  if (secs === null || secs === undefined) return "—";
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function fmtTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return d.toLocaleDateString();
}

function StatCard({ label, value, icon: Icon, color }: { label: string; value: number; icon: any; color: string }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 flex items-center gap-4">
      <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${color}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div>
        <div className="text-xl font-semibold text-white">{value}</div>
        <div className="text-xs text-white/40">{label}</div>
      </div>
    </div>
  );
}

export default function AdminScans() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<"" | "active" | "recent">("");
  const [typeFilter, setTypeFilter] = useState<"" | "scan" | "discovery">("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await getAdminScans({
        status: statusFilter || undefined,
        type: typeFilter || undefined,
      });
      setData(res);
      setLastRefresh(new Date());
    } catch (e: any) {
      setError(e?.message || "Failed to load");
    } finally {
      setLoading(false);
    }
  }, [statusFilter, typeFilter]);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (autoRefresh) {
      intervalRef.current = setInterval(load, 15000);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [autoRefresh, load]);

  const stats = data?.stats ?? { queued: 0, running: 0, failedToday: 0, completedToday: 0 };
  const jobs: any[] = data?.jobs ?? [];

  const active = jobs.filter((j) => ["queued", "pending", "running"].includes(j.status));
  const recent = jobs.filter((j) => !["queued", "pending", "running"].includes(j.status));

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Active Scans</h1>
          <p className="text-xs text-white/30 mt-0.5">
            Active jobs + last 24h across all organisations
          </p>
        </div>
        <div className="flex items-center gap-3">
          {lastRefresh && (
            <span className="text-[11px] text-white/25">Updated {fmtTime(lastRefresh.toISOString())}</span>
          )}
          <label className="flex items-center gap-1.5 text-xs text-white/40 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="accent-teal-500 w-3 h-3"
            />
            Auto-refresh (15s)
          </label>
          <button
            onClick={() => { setLoading(true); load(); }}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-white/50 hover:text-white bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] transition-colors disabled:opacity-40"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Queued" value={stats.queued} icon={Clock} color="bg-gray-500/10 text-gray-400" />
        <StatCard label="Running" value={stats.running} icon={Loader2} color="bg-teal-500/10 text-teal-400" />
        <StatCard label="Failed today" value={stats.failedToday} icon={XCircle} color="bg-red-500/10 text-red-400" />
        <StatCard label="Completed today" value={stats.completedToday} icon={CheckCircle2} color="bg-emerald-500/10 text-emerald-400" />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as any)}
          className="bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40"
        >
          <option value="">Active + recent</option>
          <option value="active">Active only</option>
          <option value="recent">Recent only</option>
        </select>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value as any)}
          className="bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40"
        >
          <option value="">All types</option>
          <option value="scan">Vulnerability scans</option>
          <option value="discovery">Discovery jobs</option>
        </select>
      </div>

      {error && (
        <div className="rounded-lg px-4 py-2.5 text-sm bg-red-500/10 text-red-300 border border-red-500/20">{error}</div>
      )}

      {loading && !data ? (
        <div className="text-center text-white/30 text-sm py-12">Loading…</div>
      ) : (
        <>
          {/* Active jobs */}
          {(statusFilter === "" || statusFilter === "active") && (
            <section>
              <h2 className="text-xs font-semibold text-white/40 uppercase tracking-wider mb-2 flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse inline-block" />
                Active ({active.length})
              </h2>
              <JobTable jobs={active} empty="No active jobs right now." />
            </section>
          )}

          {/* Recent jobs */}
          {(statusFilter === "" || statusFilter === "recent") && (
            <section>
              <h2 className="text-xs font-semibold text-white/40 uppercase tracking-wider mb-2">
                Recent — last 24h ({recent.length})
              </h2>
              <JobTable jobs={recent} empty="No finished jobs in the last 24 hours." />
            </section>
          )}
        </>
      )}
    </div>
  );
}

function JobTable({ jobs, empty }: { jobs: any[]; empty: string }) {
  if (!jobs.length) {
    return (
      <div className="rounded-xl border border-white/[0.06] px-4 py-8 text-center text-white/30 text-xs">
        {empty}
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-white/[0.06] overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-white/[0.06] bg-white/[0.02]">
            <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Type</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Organisation</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Target</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Status</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Started</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Duration</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Detail</th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((job) => (
            <JobRow key={`${job.type}-${job.id}`} job={job} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function JobRow({ job }: { job: any }) {
  const [expanded, setExpanded] = useState(false);
  const isDisc = job.type === "discovery";

  return (
    <>
      <tr
        className="border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-4 py-3">
          {isDisc ? (
            <span className="flex items-center gap-1.5 text-xs text-purple-300">
              <Globe className="w-3.5 h-3.5" /> Discovery
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-xs text-teal-300">
              <ScanLine className="w-3.5 h-3.5" /> Scan
            </span>
          )}
        </td>
        <td className="px-4 py-3">
          <Link
            href={`/admin/organizations/${job.org.id}`}
            onClick={(e) => e.stopPropagation()}
            className="text-white/70 hover:text-white text-xs transition-colors"
          >
            {job.org.name}
          </Link>
        </td>
        <td className="px-4 py-3">
          <span className="text-white text-xs font-mono">{job.target}</span>
          {job.targetType && (
            <span className="ml-1.5 text-[10px] text-white/30">{job.targetType}</span>
          )}
        </td>
        <td className="px-4 py-3">
          <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${STATUS_STYLES[job.status] || "text-white/40"}`}>
            {job.status === "running" && (
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse mr-1 align-middle" />
            )}
            {job.status}
          </span>
        </td>
        <td className="px-4 py-3 text-white/40 text-xs">{fmtTime(job.startedAt || job.createdAt)}</td>
        <td className="px-4 py-3 text-white/40 text-xs">{fmtDuration(job.durationSeconds)}</td>
        <td className="px-4 py-3">
          <ChevronRight className={`w-3.5 h-3.5 text-white/20 transition-transform ${expanded ? "rotate-90" : ""}`} />
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-white/[0.04] bg-white/[0.015]">
          <td colSpan={7} className="px-6 py-4">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs">
              <div>
                <div className="text-white/30 mb-1">Job ID</div>
                <div className="text-white/70 font-mono">#{job.id}</div>
              </div>
              {isDisc ? (
                <>
                  <div>
                    <div className="text-white/30 mb-1">Assets found</div>
                    <div className="text-white/70">{job.assetsFound ?? 0} <span className="text-teal-400">(+{job.newAssets ?? 0} new)</span></div>
                  </div>
                  {job.modules?.length > 0 && (
                    <div>
                      <div className="text-white/30 mb-1">Modules</div>
                      <div className="flex flex-wrap gap-1">
                        {job.modules.map((m: string) => (
                          <span key={m} className="px-1.5 py-0.5 rounded bg-white/[0.06] text-white/50 text-[10px]">{m}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <>
                  {job.engines?.length > 0 && (
                    <div>
                      <div className="text-white/30 mb-1">Engines</div>
                      <div className="flex flex-wrap gap-1">
                        {job.engines.map((e: string) => (
                          <span key={e} className="px-1.5 py-0.5 rounded bg-white/[0.06] text-white/50 text-[10px]">{e}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {job.errorMessage && (
                    <div className="col-span-2">
                      <div className="text-white/30 mb-1">Error</div>
                      <div className="text-red-400 font-mono text-[10px]">{job.errorMessage}</div>
                    </div>
                  )}
                </>
              )}
              <div>
                <div className="text-white/30 mb-1">Finished</div>
                <div className="text-white/70">{fmtTime(job.finishedAt)}</div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
