"use client";
import { useEffect, useState, useCallback, useRef } from "react";
import { getAdminHealth } from "../../../lib/api";
import {
  RefreshCw, CheckCircle2, AlertTriangle, XCircle,
  Database, Layers, Activity, TrendingUp, Clock, Users, Building2,
} from "lucide-react";

function fmtUptime(secs: number | null): string {
  if (secs === null || secs === undefined) return "—";
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

type StatusKind = "healthy" | "degraded" | "critical";

const STATUS_CONFIG: Record<StatusKind, { label: string; icon: any; pill: string; dot: string }> = {
  healthy:  { label: "Healthy",  icon: CheckCircle2,   pill: "bg-emerald-500/10 text-emerald-300 border-emerald-500/20", dot: "bg-emerald-400" },
  degraded: { label: "Degraded", icon: AlertTriangle,  pill: "bg-amber-500/10 text-amber-300 border-amber-500/20",       dot: "bg-amber-400" },
  critical: { label: "Critical", icon: XCircle,        pill: "bg-red-500/10 text-red-300 border-red-500/20",             dot: "bg-red-400 animate-pulse" },
};

function StatusPill({ status }: { status: StatusKind }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.healthy;
  const Icon = cfg.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-sm font-semibold ${cfg.pill}`}>
      <span className={`w-2 h-2 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

function Card({ title, icon: Icon, children }: { title: string; icon: any; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
      <div className="flex items-center gap-2 mb-4">
        <Icon className="w-4 h-4 text-teal-400" />
        <h3 className="text-sm font-semibold text-white">{title}</h3>
      </div>
      {children}
    </div>
  );
}

function Row({ label, value, sub, valueClass = "text-white" }: { label: string; value: React.ReactNode; sub?: string; valueClass?: string }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-white/[0.04] last:border-0">
      <span className="text-xs text-white/40">{label}</span>
      <div className="text-right">
        <span className={`text-sm font-medium ${valueClass}`}>{value}</span>
        {sub && <div className="text-[10px] text-white/25">{sub}</div>}
      </div>
    </div>
  );
}

function PoolBar({ checked, idle, overflow, total }: { checked: number; idle: number; overflow: number; total: number }) {
  const max = Math.max(total + overflow, 1);
  const checkedPct = (checked / max) * 100;
  const idlePct = (idle / max) * 100;
  return (
    <div className="mt-3">
      <div className="flex h-2 rounded-full overflow-hidden bg-white/[0.06] gap-px">
        <div className="bg-teal-400 transition-all" style={{ width: `${checkedPct}%` }} title={`${checked} checked out`} />
        <div className="bg-white/20 transition-all" style={{ width: `${idlePct}%` }} title={`${idle} idle`} />
      </div>
      <div className="flex items-center gap-4 mt-1.5 text-[10px] text-white/30">
        <span className="flex items-center gap-1"><span className="w-2 h-1.5 rounded-sm bg-teal-400 inline-block" />Checked out ({checked})</span>
        <span className="flex items-center gap-1"><span className="w-2 h-1.5 rounded-sm bg-white/20 inline-block" />Idle ({idle})</span>
        {overflow > 0 && <span className="text-amber-400">+{overflow} overflow</span>}
      </div>
    </div>
  );
}

export default function AdminHealth() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setData(await getAdminHealth());
      setLastRefresh(new Date());
    } catch (e: any) {
      setError(e?.message || "Failed to load health data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { setLoading(true); load(); }, [load]);

  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (autoRefresh) intervalRef.current = setInterval(load, 30000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [autoRefresh, load]);

  const status: StatusKind = data?.status ?? "healthy";
  const db = data?.db ?? {};
  const queues = data?.queues ?? {};
  const errors = data?.errors ?? {};
  const platform = data?.platform ?? {};
  const activity = data?.recentActivity ?? {};
  const uptime = data?.uptime ?? {};

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Platform Health</h1>
          <p className="text-xs text-white/30 mt-0.5">
            {lastRefresh ? `Updated ${lastRefresh.toLocaleTimeString()}` : "Loading…"}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {data && <StatusPill status={status} />}
          <label className="flex items-center gap-1.5 text-xs text-white/40 cursor-pointer select-none">
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} className="accent-teal-500 w-3 h-3" />
            Auto (30s)
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

      {error && (
        <div className="rounded-lg px-4 py-2.5 text-sm bg-red-500/10 text-red-300 border border-red-500/20">{error}</div>
      )}

      {loading && !data ? (
        <div className="text-center text-white/30 text-sm py-16">Loading…</div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">

          {/* Uptime */}
          <Card title="Server Uptime" icon={Clock}>
            <div className="text-3xl font-bold text-white mb-1">{fmtUptime(uptime.seconds)}</div>
            <div className="text-xs text-white/30">since last restart</div>
          </Card>

          {/* Database */}
          <Card title="Database" icon={Database}>
            <Row
              label="Connection"
              value={db.ok ? "Connected" : "Unreachable"}
              valueClass={db.ok ? "text-emerald-400" : "text-red-400"}
            />
            <Row label="Ping" value={db.pingMs !== null ? `${db.pingMs} ms` : "—"} />
            {db.poolSize !== null && (
              <>
                <Row label="Pool size" value={db.poolSize ?? "—"} sub={`${db.checkedOut ?? 0} out · ${db.idle ?? 0} idle`} />
                <PoolBar
                  checked={db.checkedOut ?? 0}
                  idle={db.idle ?? 0}
                  overflow={db.overflow ?? 0}
                  total={db.poolSize ?? 5}
                />
              </>
            )}
          </Card>

          {/* Queues */}
          <Card title="Job Queues" icon={Layers}>
            <Row
              label="Queued scans"
              value={queues.queuedScans ?? 0}
              valueClass={(queues.queuedScans ?? 0) > 20 ? "text-amber-400" : "text-white"}
            />
            <Row label="Running scans" value={queues.runningScans ?? 0} />
            <Row label="Active discovery" value={queues.activeDiscovery ?? 0} />
          </Card>

          {/* Error rate */}
          <Card title="Errors — Last 24h" icon={Activity}>
            <Row
              label="Error rate"
              value={`${errors.errorRatePct ?? 0}%`}
              valueClass={
                (errors.errorRatePct ?? 0) > 20 ? "text-red-400" :
                (errors.errorRatePct ?? 0) > 5 ? "text-amber-400" : "text-emerald-400"
              }
              sub={`${(errors.failedScans24h ?? 0) + (errors.failedDiscovery24h ?? 0)} failed of ${errors.completedJobs24h ?? 0} completed`}
            />
            <Row label="Failed scans" value={errors.failedScans24h ?? 0} valueClass={(errors.failedScans24h ?? 0) > 0 ? "text-red-400" : "text-white"} />
            <Row label="Failed discovery" value={errors.failedDiscovery24h ?? 0} valueClass={(errors.failedDiscovery24h ?? 0) > 0 ? "text-red-400" : "text-white"} />
          </Card>

          {/* Platform totals */}
          <Card title="Platform Totals" icon={Building2}>
            <Row label="Active organisations" value={(platform.totalOrgs ?? 0).toLocaleString()} />
            <Row label="Total users" value={(platform.totalUsers ?? 0).toLocaleString()} />
            <Row label="Total assets" value={(platform.totalAssets ?? 0).toLocaleString()} />
            <Row label="Total findings" value={(platform.totalFindings ?? 0).toLocaleString()} />
          </Card>

          {/* Recent activity */}
          <Card title="Recent Activity" icon={TrendingUp}>
            <Row label="New orgs (7d)" value={activity.newOrgs7d ?? 0} />
            <Row label="New users (7d)" value={activity.newUsers7d ?? 0} />
            <Row label="Scans started (24h)" value={activity.scansStarted24h ?? 0} />
            <Row label="Discovery started (24h)" value={activity.discoveryStarted24h ?? 0} />
          </Card>

        </div>
      )}
    </div>
  );
}
