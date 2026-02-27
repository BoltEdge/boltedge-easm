// app/(authenticated)/dashboard/page.tsx
// CLOUD: Added Cloud Assets summary card showing cloud finding counts by sub-type
"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  LayoutDashboard, Globe, AlertTriangle, Shield, ShieldAlert,
  ArrowUpRight, ArrowDown, ArrowUp, BellRing, Eye, CheckCircle2,
  Clock, RefreshCcw, Activity, TrendingUp, TrendingDown,
  Minus, Play, Zap, Search, Loader2, Target, Layers,
  Cloud, Database, Box, Cpu,
} from "lucide-react";

import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip,
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
} from "recharts";

import { getDashboardSummary, apiFetch, isPlanError } from "../../lib/api";
import { SeverityBadge } from "../../SeverityBadge";
import { Button } from "../../ui/button";
import { usePlanLimit, PlanLimitDialog } from "../../ui/plan-limit-dialog";
import { DashboardSkeleton } from "../../ui/skeleton";

function cn(...c: Array<string | false | null | undefined>) { return c.filter(Boolean).join(" "); }

/* ── Severity constants ── */

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#38bdf8",
};
const SEV_BG: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/25",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/25",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/25",
  low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/25",
  info: "bg-sky-500/15 text-sky-400 border-sky-500/25",
};

function prettySev(s: string) { return s.charAt(0).toUpperCase() + s.slice(1); }
function fmtDateShort(iso: string) { const [, m, d] = iso.split("-").map(Number); return `${String(d).padStart(2, "0")}/${String(m).padStart(2, "0")}`; }
function timeAgo(iso?: string | null) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 60) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

/* ── Exposure Score — from backend ── */

function exposureFallback(findings: any): { score: number; label: string; color: string } {
  const sev = findings?.bySeverity || {};
  const raw = (sev.critical || 0) * 10 + (sev.high || 0) * 4 + (sev.medium || 0) * 1.5 + (sev.low || 0) * 0.3;
  const score = raw > 0 ? Math.min(100, Math.round(Math.log2(raw + 1) * 10)) : 0;
  if (score === 0) return { score, label: "Secure", color: "#10b981" };
  if (score <= 25) return { score, label: "Low Risk", color: "#22c55e" };
  if (score <= 50) return { score, label: "Moderate", color: "#eab308" };
  if (score <= 75) return { score, label: "High Risk", color: "#f97316" };
  return { score, label: "Critical", color: "#ef4444" };
}

/* ── Components ── */

function ExposureGauge({ score, label, color }: { score: number; label: string; color: string }) {
  const radius = 54;
  const stroke = 8;
  const circumference = Math.PI * radius; // half circle
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="80" viewBox="0 0 140 80">
        {/* Background arc */}
        <path
          d="M 10 70 A 54 54 0 0 1 130 70"
          fill="none"
          stroke="rgba(148,163,184,0.15)"
          strokeWidth={stroke}
          strokeLinecap="round"
        />
        {/* Score arc */}
        <path
          d="M 10 70 A 54 54 0 0 1 130 70"
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${circumference}`}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1s ease-out" }}
        />
      </svg>
      <div className="-mt-12 text-center">
        <div className="text-3xl font-bold text-foreground">{score}</div>
        <div className="text-xs font-semibold" style={{ color }}>{label}</div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, sub, subColor, href, trend }: {
  icon: React.ReactNode; label: string; value: string | number;
  sub?: string; subColor?: string; href?: string; trend?: "up" | "down" | "flat";
}) {
  const inner = (
    <div className="rounded-2xl border border-border bg-card/40 p-5 hover:bg-card/60 transition-colors group">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <div className="h-9 w-9 rounded-xl border border-border bg-background/30 flex items-center justify-center">{icon}</div>
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">{label}</span>
          </div>
          <div className="text-3xl font-bold text-foreground">{value}</div>
          {sub && <p className={cn("text-xs mt-1", subColor || "text-muted-foreground")}>{sub}</p>}
        </div>
        <div className="flex flex-col items-end gap-1">
          {trend === "up" && <ArrowUp className="w-4 h-4 text-red-400" />}
          {trend === "down" && <ArrowDown className="w-4 h-4 text-emerald-400" />}
          {trend === "flat" && <Minus className="w-4 h-4 text-muted-foreground" />}
          {href && <ArrowUpRight className="w-4 h-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />}
        </div>
      </div>
    </div>
  );
  return href ? <Link href={href}>{inner}</Link> : inner;
}

function Panel({ title, icon, action, className: cls, children }: {
  title: string; icon?: React.ReactNode; action?: React.ReactNode; className?: string; children: React.ReactNode;
}) {
  return (
    <div className={cn("rounded-2xl border border-border bg-card/40 overflow-hidden", cls)}>
      <div className="px-5 py-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          {icon}
          <span className="text-sm font-semibold text-foreground">{title}</span>
        </div>
        {action}
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

function ScanStatusBadge({ status }: { status: string }) {
  const s = status?.toLowerCase() || "";
  const styles: Record<string, string> = {
    completed: "bg-emerald-500/15 text-emerald-400",
    running: "bg-sky-500/15 text-sky-400",
    queued: "bg-amber-500/15 text-amber-400",
    failed: "bg-red-500/15 text-red-400",
  };
  return <span className={cn("px-2 py-0.5 rounded text-[10px] font-semibold", styles[s] || "bg-muted/30 text-muted-foreground")}>{status}</span>;
}

/* ── Custom Tooltip ── */

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-xl border border-border bg-card/95 backdrop-blur-sm px-4 py-3 shadow-xl">
      <p className="text-xs text-muted-foreground mb-2">{label}</p>
      {payload.map((p: any) => (
        <div key={p.dataKey} className="flex items-center gap-2 text-xs">
          <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: p.color }} />
          <span className="text-muted-foreground capitalize">{p.dataKey}</span>
          <span className="font-semibold text-foreground ml-auto">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

/* ── Cloud Summary Card ── */

const CLOUD_SUB_ITEMS: { key: string; label: string; icon: typeof Cloud; color: string; bgColor: string }[] = [
  { key: "storage",    label: "Public Buckets",     icon: Database, color: "text-sky-400",    bgColor: "bg-sky-500/10" },
  { key: "registry",   label: "Exposed Registries", icon: Box,      color: "text-violet-400", bgColor: "bg-violet-500/10" },
  { key: "serverless", label: "Unauth Endpoints",   icon: Cpu,      color: "text-amber-400",  bgColor: "bg-amber-500/10" },
  { key: "cdn",        label: "CDN Origin Leaks",   icon: Shield,   color: "text-teal-400",   bgColor: "bg-teal-500/10" },
];

function CloudSummaryCard({ cloudAssets }: { cloudAssets: any }) {
  if (!cloudAssets) return null;

  const total = cloudAssets.total || 0;
  const bySub = cloudAssets.bySubType || {};

  return (
    <Panel title="Cloud Assets" icon={<Cloud className="w-4 h-4 text-sky-400" />}
      action={
        <Link href="/findings?category=cloud" className="text-xs text-primary flex items-center gap-1 hover:opacity-80">
          View all<ArrowUpRight className="w-3.5 h-3.5" />
        </Link>
      }>
      {total === 0 ? (
        <div className="py-6 text-center">
          <Cloud className="w-10 h-10 text-muted-foreground/20 mx-auto mb-2" />
          <p className="text-sm text-muted-foreground">No cloud findings</p>
          <p className="text-xs text-muted-foreground">Run a Deep Scan to discover cloud assets</p>
        </div>
      ) : (
        <div className="space-y-3">
          {/* Total cloud findings */}
          <div className="flex items-center justify-between pb-3 border-b border-border">
            <span className="text-sm text-muted-foreground">Total cloud findings</span>
            <span className="text-lg font-bold text-foreground">{total}</span>
          </div>

          {/* Sub-type breakdown */}
          {CLOUD_SUB_ITEMS.map(({ key, label, icon: SubIcon, color, bgColor }) => {
            const count = bySub[key] || 0;
            return (
              <div key={key} className="flex items-center gap-3">
                <div className={cn("h-8 w-8 rounded-lg flex items-center justify-center shrink-0", bgColor)}>
                  <SubIcon className={cn("w-4 h-4", color)} />
                </div>
                <span className="text-sm text-foreground flex-1">{label}</span>
                <span className={cn("text-sm font-semibold", count > 0 ? "text-foreground" : "text-muted-foreground")}>
                  {count}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </Panel>
  );
}

/* ── Main Page ── */

export default function DashboardPage() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [discoveryStats, setDiscoveryStats] = useState<any>(null);
  const planLimit = usePlanLimit();

  const loadDashboard = useCallback(async (isRefresh = false) => {
    try {
      if (isRefresh) setRefreshing(true); else setLoading(true);
      setError(null);

      const [summary] = await Promise.allSettled([
        getDashboardSummary(),
        (async () => {
          try {
            const res: any = await apiFetch("/monitoring/alerts?limit=5&status=open");
            setRecentAlerts(res?.alerts || (Array.isArray(res) ? res : []));
          } catch {}
        })(),
        (async () => {
          try {
            const res: any = await apiFetch("/discovery/jobs?limit=3");
            setDiscoveryStats(res);
          } catch {}
        })(),
      ]);

      if (summary.status === "fulfilled") setData(summary.value);
      else {
        const err = summary.reason;
        if (isPlanError(err)) planLimit.handle(err.planError);
        else setError(err?.message || "Failed to load dashboard");
      }
    } finally { setLoading(false); setRefreshing(false); }
  }, [planLimit]);

  useEffect(() => { loadDashboard(); }, []);

  // ── Derived data ──

  const pieData = useMemo(() => {
    const bySev = data?.findings?.bySeverity || {};
    return SEV_ORDER.map((k) => ({ name: prettySev(k), key: k, value: Number(bySev[k] || 0) })).filter((x) => x.value > 0);
  }, [data]);

  const trendData = useMemo(() => {
    const t = data?.findings?.trend7d || data?.findings?.trend7D || [];
    if (!Array.isArray(t)) return [];
    return t.map((row: any) => ({
      ...row,
      dateLabel: row?.date ? fmtDateShort(String(row.date)) : "",
      critical: Number(row.critical || 0),
      high: Number(row.high || 0),
      medium: Number(row.medium || 0),
      low: Number(row.low || 0),
      info: Number(row.info || 0),
      total: Number(row.critical || 0) + Number(row.high || 0) + Number(row.medium || 0) + Number(row.low || 0) + Number(row.info || 0),
    }));
  }, [data]);

  const exposure = useMemo(() => {
    if (data?.exposureScore) return data.exposureScore;
    return exposureFallback(data?.findings);
  }, [data]);

  const trendDirection = useMemo(() => {
    if (trendData.length < 2) return { dir: "flat" as const, label: "Stable" };
    const recent = trendData.slice(-3).reduce((s: number, r: any) => s + (r.critical || 0) + (r.high || 0), 0);
    const earlier = trendData.slice(0, 3).reduce((s: number, r: any) => s + (r.critical || 0) + (r.high || 0), 0);
    if (recent > earlier) return { dir: "up" as const, label: "Critical/High increasing" };
    if (recent < earlier) return { dir: "down" as const, label: "Critical/High decreasing" };
    return { dir: "flat" as const, label: "Stable" };
  }, [trendData]);

  // ── Cloud summary — derived from findings category counts or dedicated field ──
  const cloudAssets = useMemo(() => {
    // If backend provides cloudAssets summary directly, use it
    if (data?.cloudAssets) return data.cloudAssets;

    // Otherwise derive from categoryCounts if available
    const catCounts = data?.findings?.byCategory || data?.findings?.categoryCounts || {};
    const cloudTotal = catCounts.cloud || 0;

    if (cloudTotal === 0) return null;

    // Can't determine sub-type breakdown from just the category count,
    // but we show the total. Backend enhancement can provide bySubType later.
    return {
      total: cloudTotal,
      bySubType: {},
    };
  }, [data]);

  // ── Loading / Error states ──

  if (loading) return <DashboardSkeleton />;

  if (error || !data) {
    return (
      <div className="p-8">
        <div className="text-sm text-red-400 mb-3">{error || "No data"}</div>
        <Button variant="outline" onClick={() => loadDashboard()} className="border-border text-foreground hover:bg-accent">
          <RefreshCcw className="w-4 h-4 mr-2" />Retry
        </Button>
        <PlanLimitDialog {...planLimit} />
      </div>
    );
  }

  const assets = data.assets || { total: 0, groups: 0, distribution: {} };
  const scans = data.scans || { active: 0, coverage: 0 };
  const findings = data.findings || { total: 0, open: 0, bySeverity: {}, remediationRate: 0, trend7d: [] };
  const monitoring = data.monitoring || { openAlerts: 0, monitored: 0 };
  const topRisky = Array.isArray(data.topRiskyAssets) ? data.topRiskyAssets : [];
  const recentJobs = Array.isArray(data.recentScanJobs) ? data.recentScanJobs : [];
  const dist = assets.distribution || {};
  const critHigh = (findings.bySeverity?.critical || 0) + (findings.bySeverity?.high || 0);
  const coveragePct = Math.round((scans.coverage || 0) * 100);

  return (
    <div className="flex-1 overflow-y-auto bg-background">
      <div className="p-6 lg:p-8 max-w-[1600px] mx-auto">
        {/* Header */}
        <div className="mb-8 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3">
              <LayoutDashboard className="h-6 w-6 text-primary" />
              <h1 className="text-2xl font-semibold text-foreground">Security Dashboard</h1>
            </div>
            <p className="mt-1 text-sm text-muted-foreground">
              Real-time overview of your attack surface and security posture
            </p>
          </div>
          <Button variant="outline" onClick={() => loadDashboard(true)} disabled={refreshing}
            className="border-border text-foreground hover:bg-accent">
            <RefreshCcw className={cn("w-4 h-4 mr-2", refreshing && "animate-spin")} />
            {refreshing ? "Refreshing…" : "Refresh"}
          </Button>
        </div>

        {/* ═══ Row 1: Exposure Score + Stats ═══ */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 mb-6">
          {/* Exposure Score — larger card */}
          <div className="lg:col-span-1 rounded-2xl border border-border bg-card/40 p-5 flex flex-col items-center justify-center">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-3">Exposure Score</span>
            <ExposureGauge score={exposure.score} label={exposure.label} color={exposure.color} />
            {critHigh > 0 && (
              <p className="text-xs text-muted-foreground mt-3 text-center">
                <span className="text-red-400 font-semibold">{critHigh}</span> critical + high findings
              </p>
            )}
          </div>

          {/* Stat cards */}
          <div className="lg:col-span-4 grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              icon={<Globe className="h-5 w-5 text-primary" />}
              label="Assets"
              value={assets.total ?? 0}
              sub={`${assets.groups ?? 0} groups · ${coveragePct}% scanned`}
              href="/assets"
            />
            <StatCard
              icon={<AlertTriangle className="h-5 w-5 text-red-400" />}
              label="Open Findings"
              value={findings.open ?? 0}
              sub={critHigh > 0 ? `${findings.bySeverity?.critical || 0} critical · ${findings.bySeverity?.high || 0} high` : "No critical issues"}
              subColor={critHigh > 0 ? "text-red-400" : "text-emerald-400"}
              href="/findings"
              trend={trendDirection.dir}
            />
            <StatCard
              icon={<Eye className="h-5 w-5 text-cyan-400" />}
              label="Monitored"
              value={monitoring.monitored ?? 0}
              sub={monitoring.monitored > 0 ? `${monitoring.openAlerts || 0} open alerts` : "Set up monitoring →"}
              subColor={monitoring.openAlerts > 0 ? "text-amber-400" : undefined}
              href="/monitoring"
            />
            <StatCard
              icon={<Activity className="h-5 w-5 text-emerald-400" />}
              label="Scan Coverage"
              value={`${coveragePct}%`}
              sub={`${scans.active || 0} active scan${scans.active !== 1 ? "s" : ""}`}
              href="/scan"
            />
          </div>
        </div>

        {/* ═══ Row 2: Severity Breakdown + Trend ═══ */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          {/* Severity donut */}
          <Panel title="Findings by Severity" icon={<Shield className="w-4 h-4 text-primary" />}>
            {pieData.length === 0 ? (
              <div className="h-[280px] flex flex-col items-center justify-center text-muted-foreground">
                <CheckCircle2 className="w-12 h-12 text-emerald-500/30 mb-3" />
                <p className="text-sm">No open findings</p>
                <p className="text-xs text-muted-foreground">Run a scan to check your assets</p>
              </div>
            ) : (
              <>
                <div className="h-[240px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Tooltip content={<ChartTooltip />} />
                      <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={65} outerRadius={100} paddingAngle={3} strokeWidth={0}>
                        {pieData.map((e) => <Cell key={e.key} fill={SEV_COLORS[e.key]} />)}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                {/* Custom legend — severity order */}
                <div className="flex flex-wrap justify-center gap-x-4 gap-y-1 mt-2">
                  {pieData.map((e) => (
                    <div key={e.key} className="flex items-center gap-1.5 text-xs">
                      <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: SEV_COLORS[e.key] }} />
                      <span style={{ color: "rgba(226,232,240,0.85)" }}>{e.name}</span>
                    </div>
                  ))}
                </div>
                {/* Severity pills */}
                <div className="flex flex-wrap gap-2 mt-3">
                  {SEV_ORDER.map((k) => {
                    const count = findings.bySeverity?.[k] || 0;
                    if (!count) return null;
                    return (
                      <span key={k} className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border", SEV_BG[k])}>
                        {prettySev(k)}: {count}
                      </span>
                    );
                  })}
                </div>
              </>
            )}
          </Panel>

          {/* Findings trend — area chart */}
          <Panel title="Findings Trend (7 Days)" icon={<TrendingUp className="w-4 h-4 text-primary" />}
            action={
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                {trendDirection.dir === "down" && <><TrendingDown className="w-3.5 h-3.5 text-emerald-400" /><span className="text-emerald-400">{trendDirection.label}</span></>}
                {trendDirection.dir === "up" && <><TrendingUp className="w-3.5 h-3.5 text-red-400" /><span className="text-red-400">{trendDirection.label}</span></>}
                {trendDirection.dir === "flat" && <><Minus className="w-3.5 h-3.5" /><span>{trendDirection.label}</span></>}
              </div>
            }>
            {trendData.length === 0 ? (
              <div className="h-[280px] flex items-center justify-center text-xs text-muted-foreground">No trend data yet</div>
            ) : (
              <div className="h-[300px]">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trendData} margin={{ top: 10, right: 10, bottom: 0, left: -10 }}>
                    <defs>
                      {SEV_ORDER.map((k) => (
                        <linearGradient key={k} id={`grad-${k}`} x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor={SEV_COLORS[k]} stopOpacity={0.3} />
                          <stop offset="95%" stopColor={SEV_COLORS[k]} stopOpacity={0} />
                        </linearGradient>
                      ))}
                    </defs>
                    <CartesianGrid stroke="rgba(148,163,184,0.1)" strokeDasharray="4 4" />
                    <XAxis dataKey="dateLabel" tick={{ fill: "rgba(226,232,240,0.5)", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: "rgba(226,232,240,0.5)", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                    <Tooltip content={<ChartTooltip />} />
                    {SEV_ORDER.map((k) => (
                      <Area key={k} type="monotone" dataKey={k} stroke={SEV_COLORS[k]} strokeWidth={2}
                        fill={`url(#grad-${k})`} dot={false} />
                    ))}
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </Panel>
        </div>

        {/* ═══ Row 3: Top Risky Assets + Recent Activity ═══ */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          {/* Top Risky Assets */}
          <Panel title="Top Risky Assets" icon={<Target className="w-4 h-4 text-red-400" />}
            action={<Link href="/findings" className="text-xs text-primary flex items-center gap-1 hover:opacity-80">View all<ArrowUpRight className="w-3.5 h-3.5" /></Link>}>
            {topRisky.length === 0 ? (
              <div className="py-8 text-center">
                <CheckCircle2 className="w-10 h-10 text-emerald-500/30 mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No risky assets found</p>
              </div>
            ) : (
              <div className="space-y-2">
                {topRisky.slice(0, 5).map((a: any, i: number) => (
                  <Link key={a.assetId || i} href={`/assets/${a.assetId}`}
                    className="flex items-center gap-3 p-3 rounded-xl border border-border bg-background/10 hover:bg-background/20 transition-colors group">
                    <div className="h-7 w-7 rounded-lg border border-border bg-background/30 flex items-center justify-center text-xs text-muted-foreground font-semibold">
                      {i + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-mono text-foreground truncate">{a.value}</span>
                      </div>
                      <span className="text-xs text-muted-foreground capitalize">{a.type} · {a.openFindings} finding{a.openFindings !== 1 ? "s" : ""}</span>
                    </div>
                    <SeverityBadge severity={a.maxSeverity} />
                    <ArrowUpRight className="w-4 h-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                  </Link>
                ))}
              </div>
            )}
          </Panel>

          {/* Recent Activity */}
          <Panel title="Recent Activity" icon={<Activity className="w-4 h-4 text-cyan-400" />}>
            <div className="space-y-1">
              {/* Recent alerts */}
              {recentAlerts.slice(0, 3).map((alert: any) => (
                <Link key={alert.id} href="/monitoring"
                  className="flex items-start gap-3 p-3 rounded-xl hover:bg-background/15 transition-colors">
                  <div className="h-8 w-8 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0 mt-0.5">
                    <BellRing className="w-4 h-4 text-red-400" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm text-foreground truncate">{alert.title}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <SeverityBadge severity={alert.severity || "info"} />
                      {alert.assetValue && <span className="text-xs text-muted-foreground font-mono">{alert.assetValue}</span>}
                      <span className="text-xs text-muted-foreground">· {timeAgo(alert.createdAt)}</span>
                    </div>
                  </div>
                </Link>
              ))}

              {/* Recent scan jobs */}
              {recentJobs.slice(0, 3).map((j: any) => (
                <Link key={j.id} href="/scan"
                  className="flex items-start gap-3 p-3 rounded-xl hover:bg-background/15 transition-colors">
                  <div className="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0 mt-0.5">
                    <Zap className="w-4 h-4 text-primary" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className="text-sm text-foreground truncate">{j.assetValue || `Asset #${j.assetId}`}</p>
                      <ScanStatusBadge status={j.status} />
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {j.status === "completed" ? "Scan completed" : j.status === "running" ? "Scan in progress" : `Scan ${j.status}`}
                      {j.timeStarted && ` · ${timeAgo(j.timeStarted)}`}
                    </span>
                  </div>
                </Link>
              ))}

              {recentAlerts.length === 0 && recentJobs.length === 0 && (
                <div className="py-8 text-center">
                  <Activity className="w-10 h-10 text-muted-foreground/20 mx-auto mb-2" />
                  <p className="text-sm text-muted-foreground">No recent activity</p>
                  <p className="text-xs text-muted-foreground">Run a scan or set up monitoring to see activity here</p>
                </div>
              )}
            </div>
          </Panel>
        </div>

        {/* ═══ Row 4: Cloud Assets + Asset Distribution + Scan Coverage + Quick Actions ═══ */}
        <div className={cn(
          "grid grid-cols-1 gap-6",
          cloudAssets ? "lg:grid-cols-4" : "lg:grid-cols-3",
        )}>
          {/* Cloud Assets — only renders when cloud data exists */}
          <CloudSummaryCard cloudAssets={cloudAssets} />

          {/* Asset Distribution */}
          <Panel title="Asset Breakdown" icon={<Layers className="w-4 h-4 text-primary" />}>
            <div className="space-y-3">
              {Object.entries(dist).filter(([, v]) => (v as number) > 0).map(([type, count]) => {
                const pct = assets.total ? Math.round(((count as number) / assets.total) * 100) : 0;
                return (
                  <div key={type}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm text-foreground capitalize">{type}</span>
                      <span className="text-sm font-semibold text-foreground">{count as number}</span>
                    </div>
                    <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
                      <div className="h-full rounded-full bg-primary/60 transition-all" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
              {Object.values(dist).every((v) => !v) && (
                <p className="text-sm text-muted-foreground">No assets yet</p>
              )}
            </div>
            <div className="mt-4 pt-4 border-t border-border flex items-center justify-between text-xs text-muted-foreground">
              <span>{scans.active || 0} active scan{scans.active !== 1 ? "s" : ""}</span>
              <Link href="/scan/initiate" className="text-primary hover:opacity-80 flex items-center gap-1">
                <Play className="w-3 h-3" />Start scan
              </Link>
            </div>
          </Panel>

          {/* Scan Coverage */}
          <Panel title="Scan Coverage" icon={<ShieldAlert className="w-4 h-4 text-amber-400" />}>
            <div className="flex flex-col items-center py-4">
              <div className="relative w-28 h-28">
                <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
                  <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(148,163,184,0.15)" strokeWidth="10" />
                  <circle cx="60" cy="60" r="50" fill="none"
                    stroke={coveragePct >= 80 ? "#10b981" : coveragePct >= 50 ? "#eab308" : "#ef4444"}
                    strokeWidth="10" strokeLinecap="round"
                    strokeDasharray={`${Math.PI * 100}`}
                    strokeDashoffset={`${Math.PI * 100 * (1 - coveragePct / 100)}`}
                    style={{ transition: "stroke-dashoffset 1s ease-out" }} />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-2xl font-bold text-foreground">{coveragePct}%</span>
                </div>
              </div>
              <p className="text-xs text-muted-foreground mt-3 text-center">
                {coveragePct < 100
                  ? <>{assets.total - Math.round(assets.total * scans.coverage)} asset{assets.total - Math.round(assets.total * scans.coverage) !== 1 ? "s" : ""} never scanned</>
                  : "All assets have been scanned"}
              </p>
            </div>
            {coveragePct < 100 && (
              <div className="pt-3 border-t border-border">
                <Link href="/scan/initiate" className="flex items-center justify-center gap-2 text-xs text-primary hover:opacity-80">
                  <Play className="w-3 h-3" />Scan unscanned assets
                </Link>
              </div>
            )}
          </Panel>

          {/* Quick Actions */}
          <Panel title="Quick Actions" icon={<Zap className="w-4 h-4 text-amber-400" />}>
            <div className="space-y-2">
              <Link href="/discovery" className="flex items-center gap-3 p-3 rounded-xl border border-border hover:bg-background/15 transition-colors">
                <div className="h-9 w-9 rounded-lg bg-cyan-500/10 flex items-center justify-center">
                  <Globe className="w-5 h-5 text-cyan-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">Run Discovery</p>
                  <p className="text-xs text-muted-foreground">Find new assets in your attack surface</p>
                </div>
              </Link>
              <Link href="/scan/initiate" className="flex items-center gap-3 p-3 rounded-xl border border-border hover:bg-background/15 transition-colors">
                <div className="h-9 w-9 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Play className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">Start Scan</p>
                  <p className="text-xs text-muted-foreground">Scan assets for vulnerabilities</p>
                </div>
              </Link>
              <Link href="/monitoring" className="flex items-center gap-3 p-3 rounded-xl border border-border hover:bg-background/15 transition-colors">
                <div className="h-9 w-9 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                  <Eye className="w-5 h-5 text-emerald-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">Set Up Monitoring</p>
                  <p className="text-xs text-muted-foreground">Get alerts when things change</p>
                </div>
              </Link>
              <Link href="/findings" className="flex items-center gap-3 p-3 rounded-xl border border-border hover:bg-background/15 transition-colors">
                <div className="h-9 w-9 rounded-lg bg-red-500/10 flex items-center justify-center">
                  <Search className="w-5 h-5 text-red-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">View Findings</p>
                  <p className="text-xs text-muted-foreground">{findings.open || 0} open findings to review</p>
                </div>
              </Link>
            </div>
          </Panel>
        </div>
      </div>

      <PlanLimitDialog {...planLimit} />
    </div>
  );
}