"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  LayoutDashboard, Globe, AlertTriangle, Shield, ShieldAlert,
  ArrowUpRight, ArrowDown, ArrowUp, BellRing, Eye, CheckCircle2,
  RefreshCcw, Activity, TrendingUp, TrendingDown,
  Minus, Play, Zap, Search, Target, Layers,
  Cloud, Database, Box, Cpu,
} from "lucide-react";

import {
  ResponsiveContainer, Tooltip,
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
} from "recharts";

import { getDashboardSummary, apiFetch, isPlanError, getOnboardingProgress, type OnboardingProgress } from "../../lib/api";
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

  // Needle angle: -90deg (left) at score 0, +90deg (right) at score 100.
  const needleAngle = -90 + (score / 100) * 180;

  return (
    <div className="flex flex-col items-center">
      <svg width="160" height="92" viewBox="0 0 160 92">
        {/* Tick marks at 0/25/50/75/100 — drawn as short radials so the
            gauge reads as a calibrated dial rather than a half-loaded arc. */}
        {[0, 25, 50, 75, 100].map((tick) => {
          const angle = (-180 + (tick / 100) * 180) * (Math.PI / 180);
          const cx = 80;
          const cy = 78;
          const innerR = radius - 14;
          const outerR = radius - 4;
          const x1 = cx + innerR * Math.cos(angle);
          const y1 = cy + innerR * Math.sin(angle);
          const x2 = cx + outerR * Math.cos(angle);
          const y2 = cy + outerR * Math.sin(angle);
          return (
            <line
              key={tick}
              x1={x1} y1={y1} x2={x2} y2={y2}
              stroke="rgba(148,163,184,0.25)"
              strokeWidth={1.5}
              strokeLinecap="round"
            />
          );
        })}
        {/* Background arc */}
        <path
          d="M 20 78 A 54 54 0 0 1 140 78"
          fill="none"
          stroke="rgba(148,163,184,0.15)"
          strokeWidth={stroke}
          strokeLinecap="round"
        />
        {/* Score arc */}
        <path
          d="M 20 78 A 54 54 0 0 1 140 78"
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${circumference}`}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1s ease-out" }}
        />
        {/* End-of-arc dot — anchors the eye on the current value */}
        <circle
          cx={80 + radius * Math.cos((needleAngle - 90) * (Math.PI / 180))}
          cy={78 + radius * Math.sin((needleAngle - 90) * (Math.PI / 180))}
          r={4.5}
          fill={color}
          style={{ filter: `drop-shadow(0 0 4px ${color})` }}
        />
        {/* 0 / 100 endpoint labels for orientation */}
        <text x="20" y="90" fill="rgba(148,163,184,0.45)" fontSize="9" textAnchor="middle">0</text>
        <text x="140" y="90" fill="rgba(148,163,184,0.45)" fontSize="9" textAnchor="middle">100</text>
      </svg>
      <div className="-mt-10 text-center">
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
  const [onboarding, setOnboarding] = useState<OnboardingProgress | null>(null);
  const [lastRefreshAt, setLastRefreshAt] = useState<number | null>(null);
  const [tick, setTick] = useState(0); // re-render every minute to update "x ago" label
  const planLimit = usePlanLimit();

  // Tick once a minute so the "Updated Xm ago" timestamp stays fresh without
  // hammering the API. Cheap — only re-renders one span.
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 60_000);
    return () => clearInterval(id);
  }, []);

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
            const p = await getOnboardingProgress();
            setOnboarding(p);
          } catch {
            // non-fatal — checklist just won't render
          }
        })(),
      ]);

      if (summary.status === "fulfilled") {
        setData(summary.value);
        setLastRefreshAt(Date.now());
      } else {
        const err = summary.reason;
        if (isPlanError(err)) planLimit.handle(err.planError);
        else setError(err?.message || "Failed to load dashboard");
      }
    } finally { setLoading(false); setRefreshing(false); }
  }, [planLimit]);

  const freshnessLabel = useMemo(() => {
    void tick; // re-read on each tick
    if (!lastRefreshAt) return null;
    const sec = Math.floor((Date.now() - lastRefreshAt) / 1000);
    if (sec < 30) return "Updated just now";
    if (sec < 60) return `Updated ${sec}s ago`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `Updated ${min}m ago`;
    const hr = Math.floor(min / 60);
    return `Updated ${hr}h ago`;
  }, [lastRefreshAt, tick]);

  // eslint-disable-next-line react-hooks/exhaustive-deps
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

  // ── Getting started (no assets yet) ──
  if (assets.total === 0) {
    return (
      <div className="flex-1 overflow-y-auto bg-background">
        <div className="p-6 lg:p-8 max-w-[860px] mx-auto">
          <div className="mb-8">
            <div className="flex items-center gap-3">
              <LayoutDashboard className="h-6 w-6 text-primary" />
              <h1 className="text-2xl font-semibold text-foreground">Security Dashboard</h1>
            </div>
            <p className="mt-1 text-sm text-muted-foreground">Real-time overview of your attack surface and security posture</p>
          </div>

          <div className="rounded-2xl border border-border bg-card/40 overflow-hidden">
            <div className="px-8 pt-10 pb-6 text-center border-b border-border">
              <div className="w-14 h-14 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto mb-4">
                <Shield className="w-7 h-7 text-primary" />
              </div>
              <h2 className="text-xl font-semibold text-foreground">Welcome to Nano EASM</h2>
              <p className="mt-2 text-sm text-muted-foreground max-w-sm mx-auto">
                You're all set. Follow these three steps to start monitoring your attack surface.
              </p>
            </div>

            <div className="divide-y divide-border">
              {[
                {
                  step: 1,
                  icon: <Globe className="w-5 h-5 text-cyan-400" />,
                  bg: "bg-cyan-500/10",
                  title: "Add your first asset",
                  description: "Add a root domain (e.g. example.com) to start tracking your attack surface.",
                  href: "/assets",
                  cta: "Add asset",
                },
                {
                  step: 2,
                  icon: <Search className="w-5 h-5 text-violet-400" />,
                  bg: "bg-violet-500/10",
                  title: "Run discovery",
                  description: "Discover subdomains, IPs, and exposed services automatically.",
                  href: "/discovery",
                  cta: "Run discovery",
                },
                {
                  step: 3,
                  icon: <Zap className="w-5 h-5 text-primary" />,
                  bg: "bg-primary/10",
                  title: "Run a security scan",
                  description: "Scan an asset to surface open ports, exposed services, weak TLS, known CVEs and misconfigurations.",
                  href: "/scan/initiate",
                  cta: "Start scan",
                },
              ].map(({ step, icon, bg, title, description, href, cta }) => (
                <div key={step} className="flex items-center gap-5 px-8 py-5">
                  <div className={`w-11 h-11 rounded-xl ${bg} flex items-center justify-center shrink-0`}>
                    {icon}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Step {step}</span>
                    </div>
                    <p className="text-sm font-medium text-foreground">{title}</p>
                    <p className="text-xs text-muted-foreground mt-0.5">{description}</p>
                  </div>
                  <Link
                    href={href}
                    className="shrink-0 h-9 px-4 rounded-lg bg-primary/10 hover:bg-primary/20 text-primary text-sm font-medium transition-colors flex items-center gap-1.5"
                  >
                    {cta}
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              ))}
            </div>
          </div>
        </div>
        <PlanLimitDialog {...planLimit} />
      </div>
    );
  }
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
        <div className="mb-8 flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <LayoutDashboard className="h-6 w-6 text-primary" />
              <h1 className="text-2xl font-semibold text-foreground">Security Dashboard</h1>
            </div>
            <p className="mt-1 text-sm text-muted-foreground">
              Real-time overview of your attack surface and security posture
            </p>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
            {freshnessLabel && (
              <div className="hidden sm:flex items-center gap-1.5 text-xs text-muted-foreground">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                {freshnessLabel}
              </div>
            )}
            <Button variant="outline" onClick={() => loadDashboard(true)} disabled={refreshing}
              className="border-border text-foreground hover:bg-accent">
              <RefreshCcw className={cn("w-4 h-4 mr-2", refreshing && "animate-spin")} />
              {refreshing ? "Refreshing…" : "Refresh"}
            </Button>
          </div>
        </div>

        {onboarding && !onboarding.isComplete && (
          <OnboardingChecklist progress={onboarding} />
        )}

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
              sub={critHigh > 0 ? `${findings.bySeverity?.critical || 0} critical · ${findings.bySeverity?.high || 0} high` : findings.remediationRate > 0 ? `${Math.round(findings.remediationRate * 100)}% remediated` : "No critical issues"}
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
          {/* Severity stacked bar */}
          <Panel title="Findings by Severity" icon={<Shield className="w-4 h-4 text-primary" />}>
            {pieData.length === 0 ? (
              <div className="h-[280px] flex flex-col items-center justify-center text-muted-foreground">
                <CheckCircle2 className="w-12 h-12 text-emerald-500/30 mb-3" />
                <p className="text-sm">No open findings</p>
                <p className="text-xs text-muted-foreground">Run a scan to check your assets</p>
              </div>
            ) : (() => {
              // Stacked-bar replaces the old donut. A donut at this dataset
              // (~83% high) reads as a near-solid orange ring — proportion
              // is hard to see. A proportional bar shows the ratio clearly
              // and frees vertical space for per-severity breakdown rows.
              const total = pieData.reduce((s, e) => s + e.value, 0);
              return (
                <div className="space-y-5 py-2">
                  {/* Big number */}
                  <div className="flex items-baseline gap-3">
                    <div className="text-4xl font-bold text-foreground tabular-nums">{total}</div>
                    <div className="text-sm text-muted-foreground">open findings</div>
                  </div>

                  {/* Proportional stacked bar */}
                  <div className="space-y-2">
                    <div className="flex h-3 rounded-full overflow-hidden bg-muted/20 gap-px">
                      {pieData.map((e) => {
                        const pct = total ? (e.value / total) * 100 : 0;
                        return (
                          <div
                            key={e.key}
                            className="h-full transition-all hover:brightness-125"
                            style={{ width: `${pct}%`, backgroundColor: SEV_COLORS[e.key] }}
                            title={`${e.name}: ${e.value} (${pct.toFixed(1)}%)`}
                          />
                        );
                      })}
                    </div>
                  </div>

                  {/* Per-severity rows */}
                  <div className="space-y-2">
                    {SEV_ORDER.map((k) => {
                      const count = findings.bySeverity?.[k] || 0;
                      if (!count) return null;
                      const pct = total ? (count / total) * 100 : 0;
                      return (
                        <div key={k} className="flex items-center gap-3 text-sm">
                          <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: SEV_COLORS[k] }} />
                          <span className="text-foreground capitalize w-20">{k}</span>
                          <div className="flex-1 h-1 rounded-full bg-muted/20 overflow-hidden">
                            <div
                              className="h-full rounded-full transition-all"
                              style={{ width: `${pct}%`, backgroundColor: SEV_COLORS[k] }}
                            />
                          </div>
                          <span className="text-foreground font-semibold tabular-nums w-10 text-right">{count}</span>
                          <span className="text-muted-foreground text-xs tabular-nums w-12 text-right">{pct.toFixed(1)}%</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })()}
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
                    className="flex items-center gap-3 p-3 rounded-xl border border-border bg-background/10 hover:bg-background/25 hover:border-border/80 transition-all group">
                    <div className="h-7 w-7 rounded-lg border border-border bg-background/30 flex items-center justify-center text-xs text-muted-foreground font-semibold group-hover:text-foreground group-hover:border-primary/30 transition-colors">
                      {i + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-mono text-foreground truncate">{a.value}</span>
                      </div>
                      <span className="text-xs text-muted-foreground capitalize">{a.type} · {a.openFindings} finding{a.openFindings !== 1 ? "s" : ""}</span>
                    </div>
                    <SeverityBadge severity={a.maxSeverity} />
                    <ArrowUpRight className="w-4 h-4 text-muted-foreground/40 group-hover:text-primary group-hover:translate-x-0.5 transition-all" />
                  </Link>
                ))}
              </div>
            )}
          </Panel>

          {/* Recent Activity */}
          <Panel title="Recent Activity" icon={<Activity className="w-4 h-4 text-cyan-400" />}
            action={
              (recentAlerts.length > 0 || recentJobs.length > 0) ? (
                <Link href="/monitoring" className="text-xs text-primary flex items-center gap-1 hover:opacity-80">
                  View all<ArrowUpRight className="w-3.5 h-3.5" />
                </Link>
              ) : undefined
            }>
            {recentAlerts.length === 0 && recentJobs.length === 0 ? (
              <div className="py-8 text-center">
                <Activity className="w-10 h-10 text-muted-foreground/20 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground mb-1">No recent activity</p>
                <p className="text-xs text-muted-foreground mb-4 max-w-[260px] mx-auto">
                  Alerts, scan completions, and discoveries will appear here as your monitors run.
                </p>
                <div className="flex items-center justify-center gap-2">
                  <Link href="/scan/initiate" className="inline-flex items-center gap-1 text-xs font-medium text-primary hover:opacity-80">
                    <Play className="w-3 h-3" />Run a scan
                  </Link>
                  <span className="text-muted-foreground/40">·</span>
                  <Link href="/monitoring" className="inline-flex items-center gap-1 text-xs font-medium text-primary hover:opacity-80">
                    <Eye className="w-3 h-3" />Set up monitoring
                  </Link>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                {/* Alerts group */}
                {recentAlerts.length > 0 && (
                  <div>
                    <div className="flex items-center gap-2 mb-1.5 px-1">
                      <BellRing className="w-3 h-3 text-red-400/70" />
                      <span className="text-[10px] uppercase tracking-wider font-semibold text-muted-foreground">Monitoring alerts</span>
                    </div>
                    <div className="space-y-1">
                      {recentAlerts.slice(0, 3).map((alert: any) => (
                        <Link key={alert.id} href="/monitoring"
                          className="flex items-start gap-3 p-2.5 rounded-xl hover:bg-background/20 transition-colors group">
                          <div className="h-8 w-8 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0 mt-0.5">
                            <BellRing className="w-4 h-4 text-red-400" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <p className="text-sm text-foreground truncate">{alert.title}</p>
                            <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                              <SeverityBadge severity={alert.severity || "info"} />
                              {alert.assetValue && <span className="text-xs text-muted-foreground font-mono">{alert.assetValue}</span>}
                              <span className="text-xs text-muted-foreground">· {timeAgo(alert.createdAt)}</span>
                            </div>
                          </div>
                        </Link>
                      ))}
                    </div>
                  </div>
                )}

                {/* Scan jobs group */}
                {recentJobs.length > 0 && (
                  <div>
                    <div className="flex items-center gap-2 mb-1.5 px-1">
                      <Zap className="w-3 h-3 text-primary/70" />
                      <span className="text-[10px] uppercase tracking-wider font-semibold text-muted-foreground">Recent scans</span>
                    </div>
                    <div className="space-y-1">
                      {recentJobs.slice(0, 3).map((j: any) => (
                        <Link key={j.id} href="/scan"
                          className="flex items-start gap-3 p-2.5 rounded-xl hover:bg-background/20 transition-colors group">
                          <div className="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0 mt-0.5">
                            <Zap className="w-4 h-4 text-primary" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <p className="text-sm text-foreground truncate font-mono">{j.assetValue || `Asset #${j.assetId}`}</p>
                              <ScanStatusBadge status={j.status} />
                            </div>
                            <span className="text-xs text-muted-foreground">
                              {j.status === "completed" ? "Scan completed" : j.status === "running" ? "Scan in progress" : `Scan ${j.status}`}
                              {j.timeStarted && ` · ${timeAgo(j.timeStarted)}`}
                            </span>
                          </div>
                        </Link>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </Panel>
        </div>

        {/* ═══ Row 4: Cloud Assets (optional) + Asset Coverage (merged) + Quick Actions ═══ */}
        <div className={cn(
          "grid grid-cols-1 gap-6",
          cloudAssets ? "lg:grid-cols-3" : "lg:grid-cols-2",
        )}>
          {/* Cloud Assets — only renders when cloud data exists */}
          <CloudSummaryCard cloudAssets={cloudAssets} />

          {/* Asset Coverage — merged Asset Breakdown + Scan Coverage. Used to
              be two side-by-side panels; combined here so a single card tells
              the "what assets do I have, and have they been scanned?" story. */}
          <Panel title="Asset Coverage" icon={<Layers className="w-4 h-4 text-primary" />}
            action={
              <span className={cn(
                "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] font-semibold border",
                coveragePct >= 80
                  ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/20"
                  : coveragePct >= 50
                    ? "bg-amber-500/10 text-amber-300 border-amber-500/20"
                    : "bg-red-500/10 text-red-300 border-red-500/20"
              )}>
                <ShieldAlert className="w-3 h-3" />
                {coveragePct}% scanned
              </span>
            }>
            <div className="grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-5 items-center">
              {/* Distribution rows */}
              <div className="space-y-3 min-w-0">
                {Object.entries(dist).filter(([, v]) => (v as number) > 0).map(([type, count]) => {
                  const pct = assets.total ? Math.round(((count as number) / assets.total) * 100) : 0;
                  return (
                    <div key={type}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm text-foreground capitalize">{type}</span>
                        <span className="text-sm font-semibold text-foreground tabular-nums">{count as number}</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-muted/30 overflow-hidden">
                        <div className="h-full rounded-full bg-primary/60 transition-all" style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })}
                {Object.values(dist).every((v) => !v) && (
                  <p className="text-sm text-muted-foreground">No assets yet</p>
                )}
              </div>

              {/* Coverage ring — sized smaller than before; lives inline so
                  it doesn't claim a whole separate panel anymore. */}
              <div className="flex flex-col items-center sm:pl-3 sm:border-l sm:border-border">
                <div className="relative w-24 h-24">
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
                    <span className="text-xl font-bold text-foreground tabular-nums">{coveragePct}%</span>
                  </div>
                </div>
                <p className="text-[11px] text-muted-foreground mt-2 text-center max-w-[120px]">
                  {coveragePct < 100
                    ? `${assets.total - Math.round(assets.total * scans.coverage)} never scanned`
                    : "All scanned"}
                </p>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-border flex items-center justify-between text-xs text-muted-foreground">
              <span>{scans.active || 0} active scan{scans.active !== 1 ? "s" : ""}</span>
              <Link href="/scan/initiate" className="text-primary hover:opacity-80 flex items-center gap-1">
                <Play className="w-3 h-3" />
                {coveragePct < 100 ? "Scan unscanned assets" : "Start scan"}
              </Link>
            </div>
          </Panel>

          {/* Quick Actions — 2x2 grid replaces vertical stack. Same content,
              half the height, easier to scan at a glance. */}
          <Panel title="Quick Actions" icon={<Zap className="w-4 h-4 text-amber-400" />}>
            <div className="grid grid-cols-2 gap-2">
              <Link href="/discovery" className="flex flex-col gap-2 p-3 rounded-xl border border-border hover:bg-background/15 hover:border-cyan-500/30 transition-colors">
                <div className="h-9 w-9 rounded-lg bg-cyan-500/10 flex items-center justify-center">
                  <Globe className="w-5 h-5 text-cyan-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">Run Discovery</p>
                  <p className="text-[11px] text-muted-foreground leading-snug">Find new assets in your surface</p>
                </div>
              </Link>
              <Link href="/scan/initiate" className="flex flex-col gap-2 p-3 rounded-xl border border-border hover:bg-background/15 hover:border-primary/30 transition-colors">
                <div className="h-9 w-9 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Play className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">Start Scan</p>
                  <p className="text-[11px] text-muted-foreground leading-snug">Scan assets for vulnerabilities</p>
                </div>
              </Link>
              <Link href="/monitoring" className="flex flex-col gap-2 p-3 rounded-xl border border-border hover:bg-background/15 hover:border-emerald-500/30 transition-colors">
                <div className="h-9 w-9 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                  <Eye className="w-5 h-5 text-emerald-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">Set Up Monitoring</p>
                  <p className="text-[11px] text-muted-foreground leading-snug">Get alerts when things change</p>
                </div>
              </Link>
              <Link href="/findings" className="flex flex-col gap-2 p-3 rounded-xl border border-border hover:bg-background/15 hover:border-red-500/30 transition-colors">
                <div className="h-9 w-9 rounded-lg bg-red-500/10 flex items-center justify-center">
                  <Search className="w-5 h-5 text-red-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-foreground">View Findings</p>
                  <p className="text-[11px] text-muted-foreground leading-snug">{findings.open || 0} open to review</p>
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

// ─────────────────────────────────────────────────────────────
// Onboarding checklist — renders only while progress < 100%.
// Driven entirely by real org state (assets / scans / findings /
// monitor / team), so steps tick themselves off as the user uses
// the product. There's no manual "mark complete" button.
// ─────────────────────────────────────────────────────────────

function OnboardingChecklist({ progress }: { progress: OnboardingProgress }) {
  const items: { key: keyof OnboardingProgress["steps"]; label: string; href: string }[] = [
    { key: "addAsset",        label: "Add your first asset",        href: "/assets" },
    { key: "runScan",         label: "Run a scan",                  href: "/scan/initiate" },
    { key: "reviewFinding",   label: "Triage a finding",            href: "/findings" },
    { key: "enableMonitoring",label: "Enable continuous monitoring",href: "/monitoring" },
    { key: "inviteTeammate",  label: "Invite a teammate",           href: "/settings/account" },
  ];

  const pct = Math.round((progress.completed / progress.total) * 100);

  return (
    <div className="mb-6 rounded-xl border border-border/60 bg-card/40 p-5">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h2 className="text-sm font-semibold text-foreground">Get started with Nano EASM</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            {progress.completed} of {progress.total} done — this card disappears once you've finished.
          </p>
        </div>
        <span className="text-xs text-muted-foreground tabular-nums">{pct}%</span>
      </div>
      <div className="h-1 w-full bg-card rounded-full overflow-hidden mb-4">
        <div
          className="h-full bg-primary transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      <ul className="grid grid-cols-1 md:grid-cols-5 gap-2">
        {items.map((item) => {
          const done = progress.steps[item.key];
          return (
            <li key={item.key}>
              {done ? (
                <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-card/30 text-xs text-muted-foreground line-through">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span className="truncate">{item.label}</span>
                </div>
              ) : (
                <Link
                  href={item.href}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg bg-card hover:bg-card/70 border border-border/40 text-xs text-foreground transition-colors"
                >
                  <span className="w-3.5 h-3.5 rounded-full border border-muted-foreground/40 shrink-0" />
                  <span className="truncate">{item.label}</span>
                </Link>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}