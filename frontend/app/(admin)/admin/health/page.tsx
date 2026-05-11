"use client";
import { useEffect, useState, useCallback, useRef } from "react";
import { getAdminHealth, triggerAdminHealthProbe } from "../../../lib/api";
import {
  RefreshCw, CheckCircle2, AlertTriangle, XCircle,
  Database, Layers, Activity, TrendingUp, Clock, Building2,
  Cpu, Search, Plug, GitBranch, Zap,
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

type StatusKind = "healthy" | "degraded" | "critical" | "down" | "unknown";

const STATUS_CONFIG: Record<StatusKind, { label: string; icon: any; pill: string; dot: string }> = {
  healthy:  { label: "Healthy",  icon: CheckCircle2,   pill: "bg-emerald-500/10 text-emerald-300 border-emerald-500/20", dot: "bg-emerald-400" },
  degraded: { label: "Degraded", icon: AlertTriangle,  pill: "bg-amber-500/10 text-amber-300 border-amber-500/20",       dot: "bg-amber-400" },
  critical: { label: "Critical", icon: XCircle,        pill: "bg-red-500/10 text-red-300 border-red-500/20",             dot: "bg-red-400 animate-pulse" },
  down:     { label: "Down",     icon: XCircle,        pill: "bg-red-500/10 text-red-300 border-red-500/20",             dot: "bg-red-400" },
  unknown:  { label: "Unknown",  icon: AlertTriangle,  pill: "bg-white/[0.06] text-white/40 border-white/10",             dot: "bg-white/30" },
};

function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (!t || isNaN(t)) return "—";
  const seconds = Math.floor((Date.now() - t) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

type ProbeItem = {
  kind: string;
  name: string;
  status: StatusKind;
  message: string | null;
  metadata: Record<string, any>;
  durationMs: number | null;
  lastCheckedAt: string | null;
  lastHealthyAt: string | null;
};

type ProbeRollup = {
  overall: StatusKind;
  counts: Record<StatusKind, number>;
  items: ProbeItem[];
};

type RecentFailure = {
  kind: "scan" | "discovery";
  id: string;
  target: string;
  organizationName: string;
  message: string;
  finishedAt: string | null;
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

function ProbeStatusDot({ status }: { status: StatusKind }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.unknown;
  return <span className={`w-2 h-2 rounded-full ${cfg.dot} flex-shrink-0`} title={cfg.label} />;
}

function ProbeCard({
  title,
  icon: Icon,
  rollup,
  emptyText = "No probes recorded yet — run flask health probe or wait for the 6h scheduler.",
}: {
  title: string;
  icon: any;
  rollup: ProbeRollup | undefined;
  emptyText?: string;
}) {
  const counts = rollup?.counts ?? { healthy: 0, degraded: 0, down: 0, unknown: 0 };
  const items = rollup?.items ?? [];
  const overall: StatusKind = (rollup?.overall as StatusKind) ?? "unknown";
  const cfg = STATUS_CONFIG[overall];
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Icon className="w-4 h-4 text-teal-400" />
          <h3 className="text-sm font-semibold text-white">{title}</h3>
        </div>
        <span className={`text-[10px] px-2 py-0.5 rounded-full border font-semibold ${cfg.pill}`}>{cfg.label}</span>
      </div>
      <div className="flex items-center gap-3 text-[11px] text-white/40 mb-3">
        <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />{counts.healthy ?? 0}</span>
        <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-amber-400" />{counts.degraded ?? 0}</span>
        <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-red-400" />{counts.down ?? 0}</span>
        {(counts.unknown ?? 0) > 0 && <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-white/30" />{counts.unknown}</span>}
      </div>
      {items.length === 0 ? (
        <div className="text-xs text-white/30">{emptyText}</div>
      ) : (
        <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
          {items.map((it) => (
            <div key={`${it.kind}:${it.name}`} className="flex items-start gap-2 text-xs py-1 border-b border-white/[0.04] last:border-0">
              <ProbeStatusDot status={it.status} />
              <div className="flex-1 min-w-0">
                <div className="font-medium text-white/80 truncate">{it.name}</div>
                {it.message && <div className="text-[10px] text-white/40 truncate" title={it.message}>{it.message}</div>}
                <div className="text-[10px] text-white/25">{timeAgo(it.lastCheckedAt)}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SchedulerCard({ items }: { items: ProbeItem[] }) {
  const overall: StatusKind = items.some(i => i.status === "down")
    ? "down"
    : items.some(i => i.status === "degraded") ? "degraded"
    : items.some(i => i.status === "unknown") && !items.some(i => i.status === "healthy") ? "unknown"
    : "healthy";
  const cfg = STATUS_CONFIG[overall];
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-teal-400" />
          <h3 className="text-sm font-semibold text-white">Schedulers</h3>
        </div>
        <span className={`text-[10px] px-2 py-0.5 rounded-full border font-semibold ${cfg.pill}`}>{cfg.label}</span>
      </div>
      {items.length === 0 ? (
        <div className="text-xs text-white/30">No heartbeats recorded yet.</div>
      ) : (
        <div className="space-y-1.5">
          {items.map((it) => {
            const interval = it.metadata?.intervalSeconds ?? null;
            const intervalLabel = interval
              ? interval >= 3600 ? `every ${Math.round(interval / 3600)}h`
                : interval >= 60  ? `every ${Math.round(interval / 60)}m`
                : `every ${interval}s`
              : "";
            return (
              <div key={it.name} className="flex items-start gap-2 text-xs py-1.5 border-b border-white/[0.04] last:border-0">
                <ProbeStatusDot status={it.status} />
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-white/80 truncate">{it.name}<span className="text-white/30 font-normal"> {intervalLabel}</span></div>
                  {it.message && <div className="text-[10px] text-white/40 truncate" title={it.message}>{it.message}</div>}
                  <div className="text-[10px] text-white/25">last heartbeat {timeAgo(it.lastCheckedAt)}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function MigrationCard({ items }: { items: ProbeItem[] }) {
  const migration = items.find(i => i.name === "migrations");
  if (!migration) return null;
  const cfg = STATUS_CONFIG[migration.status];
  const md = migration.metadata || {};
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-teal-400" />
          <h3 className="text-sm font-semibold text-white">Migrations</h3>
        </div>
        <span className={`text-[10px] px-2 py-0.5 rounded-full border font-semibold ${cfg.pill}`}>{cfg.label}</span>
      </div>
      <div className="text-xs text-white/60 mb-2">{migration.message}</div>
      {md.current && (
        <div className="space-y-1 text-[11px]">
          <Row label="DB at" value={<span className="font-mono">{md.current?.slice(0, 12)}</span>} />
          <Row label="Code at" value={<span className="font-mono">{(md.head ?? "?").slice(0, 12)}</span>} />
        </div>
      )}
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
  const [probing, setProbing] = useState(false);
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

  const probeNow = useCallback(async () => {
    setProbing(true);
    setError(null);
    try {
      await triggerAdminHealthProbe();
      await load();
    } catch (e: any) {
      setError(e?.message || "Probe trigger failed");
    } finally {
      setProbing(false);
    }
  }, [load]);

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
  const engines: ProbeRollup | undefined = data?.engines;
  const analyzers: ProbeRollup | undefined = data?.analyzers;
  const discovery: ProbeRollup | undefined = data?.discovery;
  const externalApis: ProbeRollup | undefined = data?.externalApis;
  const schedulers: ProbeItem[] = data?.schedulers ?? [];
  const systemItems: ProbeItem[] = data?.system?.items ?? [];
  const recentFailures: RecentFailure[] = errors.recentFailures ?? [];

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
          <button
            onClick={probeNow}
            disabled={probing}
            title="Re-run all engine, analyzer, discovery, and external-API probes now."
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-teal-300 hover:text-teal-200 bg-teal-500/10 hover:bg-teal-500/20 border border-teal-500/20 transition-colors disabled:opacity-40"
          >
            <Zap className={`w-3.5 h-3.5 ${probing ? "animate-pulse" : ""}`} />
            {probing ? "Probing…" : "Probe now"}
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
          <Card title="Errors — Last 3 Days" icon={Activity}>
            <Row
              label="Error rate"
              value={`${errors.errorRatePct ?? 0}%`}
              valueClass={
                (errors.errorRatePct ?? 0) > 20 ? "text-red-400" :
                (errors.errorRatePct ?? 0) > 5 ? "text-amber-400" : "text-emerald-400"
              }
              sub={`${(errors.failedScans3d ?? 0) + (errors.failedDiscovery3d ?? 0)} failed of ${errors.completedJobs3d ?? 0} completed`}
            />
            <Row label="Failed scans" value={errors.failedScans3d ?? 0} valueClass={(errors.failedScans3d ?? 0) > 0 ? "text-red-400" : "text-white"} />
            <Row label="Failed discovery" value={errors.failedDiscovery3d ?? 0} valueClass={(errors.failedDiscovery3d ?? 0) > 0 ? "text-red-400" : "text-white"} />
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

          {/* Migrations */}
          <MigrationCard items={systemItems} />

          {/* Schedulers */}
          <SchedulerCard items={schedulers} />

          {/* Scan engines */}
          <ProbeCard title="Scan Engines" icon={Cpu} rollup={engines} />

          {/* Analyzers */}
          <ProbeCard title="Analyzers" icon={Layers} rollup={analyzers} />

          {/* Discovery modules */}
          <ProbeCard title="Discovery Modules" icon={Search} rollup={discovery} />

          {/* External APIs */}
          <ProbeCard title="External APIs" icon={Plug} rollup={externalApis} />

        </div>
      )}

      {/* Recent failure details — full width below the summary grid */}
      {!loading && data && (
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <XCircle className="w-4 h-4 text-red-400" />
              <h3 className="text-sm font-semibold text-white">
                Recent Failures
                <span className="ml-2 text-[10px] font-normal text-white/40">
                  Last 3 days · showing {recentFailures.length}{recentFailures.length === 50 ? "+" : ""}
                </span>
              </h3>
            </div>
          </div>
          {recentFailures.length === 0 ? (
            <div className="text-xs text-white/30 py-2">
              No failed scans or discovery jobs in the last 3 days.
            </div>
          ) : (
            <div className="space-y-1.5 max-h-[420px] overflow-y-auto pr-1">
              {recentFailures.map((f) => (
                <div
                  key={`${f.kind}:${f.id}`}
                  className="flex items-start gap-3 py-2 px-2 rounded-md hover:bg-white/[0.02] border-b border-white/[0.04] last:border-0"
                >
                  <span
                    className={`text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded border flex-shrink-0 ${
                      f.kind === "scan"
                        ? "bg-red-500/10 text-red-300 border-red-500/20"
                        : "bg-fuchsia-500/10 text-fuchsia-300 border-fuchsia-500/20"
                    }`}
                  >
                    {f.kind}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 text-xs text-white/80">
                      <span className="font-mono truncate" title={f.target}>{f.target}</span>
                      <span className="text-white/30">·</span>
                      <span className="text-white/50 truncate" title={f.organizationName}>{f.organizationName}</span>
                    </div>
                    <div
                      className="text-[11px] text-red-300/80 mt-0.5 break-words"
                      title={f.message}
                    >
                      {f.message}
                    </div>
                    <div className="text-[10px] text-white/30 mt-0.5">
                      {timeAgo(f.finishedAt)} · {f.kind === "scan" ? "scan" : "discovery"} {f.id}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
