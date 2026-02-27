// FILE: app/(authenticated)/trending/page.tsx
// Historical Trending page — exposure score, severity breakdown, opened vs resolved,
// MTTR, and group comparison. Supports org-wide and group-scoped views.
// Uses inline SVG charts — no external charting library needed.
"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import {
  TrendingUp, TrendingDown, Minus, Shield, Clock,
  RefreshCw, Loader2, ChevronDown, AlertCircle, Layers,
  X, BarChart3, Activity, AlertTriangle, Zap,
} from "lucide-react";
import { useOrg } from "../contexts/OrgContext";
import {
  getTrendData, getTrendSummary, getGroupTrends, generateSnapshot, getGroups,
} from "../../lib/api";
import type {
  TrendSnapshot, TrendSummaryResponse, TrendDelta, GroupTrendItem,
} from "../../lib/api";
import type { AssetGroup } from "../../types";

// ════════════════════════════════════════════════════════════════
// COLORS
// ════════════════════════════════════════════════════════════════

const SEV_COLORS: Record<string, { line: string; fill: string; text: string; dot: string }> = {
  critical: { line: "#ef4444", fill: "rgba(239,68,68,0.20)", text: "text-red-400", dot: "bg-red-500" },
  high:     { line: "#f97316", fill: "rgba(249,115,22,0.20)", text: "text-orange-400", dot: "bg-orange-500" },
  medium:   { line: "#f59e0b", fill: "rgba(245,158,11,0.20)", text: "text-amber-400", dot: "bg-amber-500" },
  low:      { line: "#3b82f6", fill: "rgba(59,130,246,0.20)", text: "text-blue-400", dot: "bg-blue-500" },
  info:     { line: "#94a3b8", fill: "rgba(148,163,184,0.10)", text: "text-slate-400", dot: "bg-slate-400" },
};

const EXPOSURE_COLOR = "#14b8a6";
const RESOLVED_COLOR = "#10b981";
const NEW_COLOR = "#f97316";
const MTTR_COLOR = "#8b5cf6";
const SUPPRESSED_COLOR = "#6366f1";

// ════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════

function fmtDate(iso: string): string {
  try { return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric" }); }
  catch { return iso; }
}

function fmtMTTR(hours: number | null | undefined): string {
  if (hours === null || hours === undefined) return "—";
  if (hours < 1) return `${Math.round(hours * 60)}m`;
  if (hours < 24) return `${hours.toFixed(1)}h`;
  return `${(hours / 24).toFixed(1)}d`;
}

function scoreColor(score: number): string {
  if (score < 40) return "text-emerald-400";
  if (score < 70) return "text-amber-400";
  return "text-red-400";
}

function scoreBg(score: number): string {
  if (score < 40) return "bg-emerald-500/10";
  if (score < 70) return "bg-amber-500/10";
  return "bg-red-500/10";
}

// ════════════════════════════════════════════════════════════════
// DELTA BADGE
// ════════════════════════════════════════════════════════════════

function DeltaBadge({ delta, inverse = false }: { delta: TrendDelta | null | undefined; inverse?: boolean }) {
  if (!delta || delta.direction === "flat") {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-white/25">
        <Minus className="w-3 h-3" /> 0%
      </span>
    );
  }
  const isGood = inverse ? delta.direction === "up" : delta.direction === "down";
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-semibold ${isGood ? "text-emerald-400" : "text-red-400"}`}>
      {delta.direction === "up" ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
      {delta.percent > 0 ? "+" : ""}{delta.percent}%
    </span>
  );
}

// ════════════════════════════════════════════════════════════════
// SVG CHART COMPONENTS
// ════════════════════════════════════════════════════════════════

const CHART_W = 600;
const CHART_H = 200;
const PAD = { top: 20, right: 20, bottom: 30, left: 50 };
const INNER_W = CHART_W - PAD.left - PAD.right;
const INNER_H = CHART_H - PAD.top - PAD.bottom;

function buildXScale(data: TrendSnapshot[]): (i: number) => number {
  const n = data.length;
  if (n <= 1) return () => PAD.left + INNER_W / 2;
  return (i: number) => PAD.left + (i / (n - 1)) * INNER_W;
}

function buildYScale(maxVal: number): (v: number) => number {
  const max = maxVal > 0 ? maxVal : 1;
  return (v: number) => PAD.top + INNER_H - (v / max) * INNER_H;
}

function YAxis({ max, steps = 4 }: { max: number; steps?: number }) {
  const yScale = buildYScale(max);
  const stepVal = max / steps;
  return (
    <>
      {Array.from({ length: steps + 1 }, (_, i) => {
        const v = Math.round(stepVal * i);
        const y = yScale(v);
        return (
          <g key={i}>
            <line x1={PAD.left} x2={CHART_W - PAD.right} y1={y} y2={y} stroke="rgba(255,255,255,0.05)" strokeWidth={1} />
            <text x={PAD.left - 8} y={y + 3} textAnchor="end" fill="rgba(255,255,255,0.25)" fontSize={10}>{v}</text>
          </g>
        );
      })}
    </>
  );
}

function XLabels({ data, xScale }: { data: TrendSnapshot[]; xScale: (i: number) => number }) {
  if (data.length === 0) return null;
  const step = Math.max(1, Math.floor(data.length / 6));
  return (
    <>
      {data.map((s, i) => {
        if (i % step !== 0 && i !== data.length - 1) return null;
        return (
          <text key={i} x={xScale(i)} y={CHART_H - 5} textAnchor="middle" fill="rgba(255,255,255,0.25)" fontSize={10}>
            {fmtDate(s.date)}
          </text>
        );
      })}
    </>
  );
}

function LinePath({ data, xScale, yScale, color, fillColor, accessor }: {
  data: TrendSnapshot[];
  xScale: (i: number) => number;
  yScale: (v: number) => number;
  color: string;
  fillColor?: string;
  accessor: (s: TrendSnapshot) => number;
}) {
  if (data.length === 0) return null;
  const points = data.map((s, i) => `${xScale(i)},${yScale(accessor(s))}`);
  const linePath = `M${points.join(" L")}`;

  const areaPath = fillColor
    ? `M${PAD.left},${yScale(0)} L${points.join(" L")} L${xScale(data.length - 1)},${yScale(0)} Z`
    : undefined;

  return (
    <>
      {areaPath && <path d={areaPath} fill={fillColor} />}
      <path d={linePath} fill="none" stroke={color} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
      {data.map((s, i) => (
        <circle key={i} cx={xScale(i)} cy={yScale(accessor(s))} r={data.length < 30 ? 3 : 0} fill={color} opacity={0.8}>
          <title>{fmtDate(s.date)}: {accessor(s)}</title>
        </circle>
      ))}
    </>
  );
}

function BarGroup({ data, xScale, yScale, color1, color2, accessor1, accessor2, label1, label2 }: {
  data: TrendSnapshot[];
  xScale: (i: number) => number;
  yScale: (v: number) => number;
  color1: string;
  color2: string;
  accessor1: (s: TrendSnapshot) => number;
  accessor2: (s: TrendSnapshot) => number;
  label1: string;
  label2: string;
}) {
  if (data.length === 0) return null;
  const barW = Math.max(3, Math.min(16, INNER_W / data.length / 2.5));

  return (
    <>
      {data.map((s, i) => {
        const x = xScale(i);
        const v1 = accessor1(s);
        const v2 = accessor2(s);
        return (
          <g key={i}>
            <rect x={x - barW - 1} y={yScale(v1)} width={barW} height={yScale(0) - yScale(v1)} fill={color1} rx={1.5} opacity={0.85}>
              <title>{fmtDate(s.date)} — {label1}: {v1}</title>
            </rect>
            <rect x={x + 1} y={yScale(v2)} width={barW} height={yScale(0) - yScale(v2)} fill={color2} rx={1.5} opacity={0.85}>
              <title>{fmtDate(s.date)} — {label2}: {v2}</title>
            </rect>
          </g>
        );
      })}
    </>
  );
}

function ChartLegend({ items }: { items: { color: string; label: string }[] }) {
  return (
    <div className="flex items-center gap-4 mt-2">
      {items.map((it) => (
        <div key={it.label} className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: it.color }} />
          <span className="text-xs text-white/40">{it.label}</span>
        </div>
      ))}
    </div>
  );
}

function EmptyChart({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center h-[200px] text-white/20 text-sm">
      <BarChart3 className="w-5 h-5 mr-2" />
      {message}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// CHART SECTIONS
// ════════════════════════════════════════════════════════════════

function ExposureChart({ data }: { data: TrendSnapshot[] }) {
  if (data.length < 2) return <EmptyChart message="Need at least 2 snapshots to chart exposure trend" />;

  const xScale = buildXScale(data);
  const yScale = buildYScale(100);

  return (
    <svg viewBox={`0 0 ${CHART_W} ${CHART_H}`} className="w-full" preserveAspectRatio="xMidYMid meet">
      <YAxis max={100} />
      <XLabels data={data} xScale={xScale} />
      {/* Danger zone background */}
      <rect x={PAD.left} y={yScale(100)} width={INNER_W} height={yScale(70) - yScale(100)} fill="rgba(239,68,68,0.04)" />
      <rect x={PAD.left} y={yScale(70)} width={INNER_W} height={yScale(40) - yScale(70)} fill="rgba(245,158,11,0.04)" />
      <rect x={PAD.left} y={yScale(40)} width={INNER_W} height={yScale(0) - yScale(40)} fill="rgba(16,185,129,0.04)" />
      {/* Threshold lines */}
      <line x1={PAD.left} x2={CHART_W - PAD.right} y1={yScale(70)} y2={yScale(70)} stroke="rgba(239,68,68,0.2)" strokeDasharray="4 4" />
      <line x1={PAD.left} x2={CHART_W - PAD.right} y1={yScale(40)} y2={yScale(40)} stroke="rgba(245,158,11,0.2)" strokeDasharray="4 4" />
      <LinePath data={data} xScale={xScale} yScale={yScale} color={EXPOSURE_COLOR} fillColor="rgba(20,184,166,0.08)" accessor={(s) => s.exposureScore} />
    </svg>
  );
}

function SeverityChart({ data }: { data: TrendSnapshot[] }) {
  if (data.length < 2) return <EmptyChart message="Need at least 2 snapshots to chart severity trend" />;

  const xScale = buildXScale(data);
  const maxTotal = Math.max(...data.map((s) => s.critical + s.high + s.medium + s.low));
  const yScale = buildYScale(Math.max(maxTotal, 1));

  const sevKeys = ["critical", "high", "medium", "low"] as const;

  return (
    <>
      <svg viewBox={`0 0 ${CHART_W} ${CHART_H}`} className="w-full" preserveAspectRatio="xMidYMid meet">
        <YAxis max={Math.max(maxTotal, 1)} />
        <XLabels data={data} xScale={xScale} />
        {sevKeys.map((sev) => (
          <LinePath
            key={sev}
            data={data}
            xScale={xScale}
            yScale={yScale}
            color={SEV_COLORS[sev].line}
            accessor={(s) => s[sev]}
          />
        ))}
      </svg>
      <ChartLegend items={sevKeys.map((s) => ({ color: SEV_COLORS[s].line, label: s.charAt(0).toUpperCase() + s.slice(1) }))} />
    </>
  );
}

function ActivityChart({ data }: { data: TrendSnapshot[] }) {
  if (data.length < 2) return <EmptyChart message="Need at least 2 snapshots to chart activity" />;

  const xScale = buildXScale(data);
  const maxVal = Math.max(...data.map((s) => Math.max(s.newFindings, s.resolvedFindings, 1)));
  const yScale = buildYScale(maxVal);

  return (
    <>
      <svg viewBox={`0 0 ${CHART_W} ${CHART_H}`} className="w-full" preserveAspectRatio="xMidYMid meet">
        <YAxis max={maxVal} />
        <XLabels data={data} xScale={xScale} />
        <BarGroup
          data={data}
          xScale={xScale}
          yScale={yScale}
          color1={NEW_COLOR}
          color2={RESOLVED_COLOR}
          accessor1={(s) => s.newFindings}
          accessor2={(s) => s.resolvedFindings}
          label1="New"
          label2="Resolved"
        />
      </svg>
      <ChartLegend items={[
        { color: NEW_COLOR, label: "New Findings" },
        { color: RESOLVED_COLOR, label: "Resolved" },
      ]} />
    </>
  );
}

function MTTRChart({ data }: { data: TrendSnapshot[] }) {
  const filtered = data.filter((s) => s.mttrHours !== null && s.mttrHours !== undefined);
  if (filtered.length < 2) return <EmptyChart message="Not enough MTTR data yet — resolve some findings to see this chart" />;

  const xScale = buildXScale(filtered);
  const maxVal = Math.max(...filtered.map((s) => s.mttrHours || 0), 1);
  const yScale = buildYScale(maxVal);

  return (
    <>
      <svg viewBox={`0 0 ${CHART_W} ${CHART_H}`} className="w-full" preserveAspectRatio="xMidYMid meet">
        <YAxis max={maxVal} />
        <XLabels data={filtered} xScale={xScale} />
        <LinePath data={filtered} xScale={xScale} yScale={yScale} color={MTTR_COLOR} fillColor="rgba(139,92,246,0.08)" accessor={(s) => s.mttrHours || 0} />
      </svg>
      <ChartLegend items={[{ color: MTTR_COLOR, label: "MTTR (hours)" }]} />
    </>
  );
}

// ════════════════════════════════════════════════════════════════
// GROUP COMPARISON TABLE
// ════════════════════════════════════════════════════════════════

function GroupComparisonTable({ groups }: { groups: GroupTrendItem[] }) {
  if (groups.length === 0) {
    return (
      <div className="text-center py-8 text-white/20 text-sm">
        No group data available. Generate snapshots first.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-white/5">
            <th className="text-left px-4 py-3 text-xs font-semibold text-white/40 uppercase tracking-wider">Group</th>
            <th className="text-center px-4 py-3 text-xs font-semibold text-white/40 uppercase tracking-wider">Exposure</th>
            <th className="text-center px-4 py-3 text-xs font-semibold text-white/40 uppercase tracking-wider">Findings</th>
            <th className="text-center px-4 py-3 text-xs font-semibold text-red-400/60 uppercase tracking-wider">Crit</th>
            <th className="text-center px-4 py-3 text-xs font-semibold text-orange-400/60 uppercase tracking-wider">High</th>
            <th className="text-center px-4 py-3 text-xs font-semibold text-amber-400/60 uppercase tracking-wider">Med</th>
            <th className="text-center px-4 py-3 text-xs font-semibold text-blue-400/60 uppercase tracking-wider">Low</th>
            <th className="text-center px-4 py-3 text-xs font-semibold text-white/40 uppercase tracking-wider">Assets</th>
            <th className="text-center px-4 py-3 text-xs font-semibold text-white/40 uppercase tracking-wider">MTTR</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/5">
          {groups.map((g) => {
            const s = g.snapshot;
            if (!s) {
              return (
                <tr key={g.groupId} className="hover:bg-white/[0.02]">
                  <td className="px-4 py-3 text-sm font-medium text-white/80">{g.groupName}</td>
                  <td colSpan={8} className="px-4 py-3 text-center text-xs text-white/20">No snapshot data</td>
                </tr>
              );
            }
            return (
              <tr key={g.groupId} className="hover:bg-white/[0.02] transition-colors">
                <td className="px-4 py-3 text-sm font-medium text-white/80">{g.groupName}</td>
                <td className="px-4 py-3 text-center">
                  <span className={`text-sm font-bold ${scoreColor(s.exposureScore)}`}>{s.exposureScore}</span>
                </td>
                <td className="px-4 py-3 text-center text-sm text-white/60">{s.totalFindings}</td>
                <td className="px-4 py-3 text-center text-sm font-semibold text-red-400">{s.critical || "—"}</td>
                <td className="px-4 py-3 text-center text-sm font-semibold text-orange-400">{s.high || "—"}</td>
                <td className="px-4 py-3 text-center text-sm font-semibold text-amber-400">{s.medium || "—"}</td>
                <td className="px-4 py-3 text-center text-sm font-semibold text-blue-400">{s.low || "—"}</td>
                <td className="px-4 py-3 text-center text-sm text-white/50">{s.assetCount}</td>
                <td className="px-4 py-3 text-center text-sm text-purple-400 font-medium">{fmtMTTR(s.mttrHours)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// MAIN PAGE
// ════════════════════════════════════════════════════════════════

export default function TrendingPage() {
  const { role } = useOrg();

  const [snapshots, setSnapshots] = useState<TrendSnapshot[]>([]);
  const [summary, setSummary] = useState<TrendSummaryResponse | null>(null);
  const [groupTrends, setGroupTrends] = useState<GroupTrendItem[]>([]);
  const [groups, setGroups] = useState<AssetGroup[]>([]);

  const [loading, setLoading] = useState(true);
  const [snapshotLoading, setSnapshotLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ type: "success" | "error"; message: string } | null>(null);

  // Filters
  const [scopeGroupId, setScopeGroupId] = useState<string>("all");
  const [days, setDays] = useState<number>(30);

  const isAdmin = role === "admin" || role === "owner";

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const gid = scopeGroupId !== "all" ? scopeGroupId : undefined;

      const [trendRes, summaryRes, groupsRes, groupTrendsRes] = await Promise.allSettled([
        getTrendData({ groupId: gid, days }),
        getTrendSummary({ groupId: gid }),
        getGroups(),
        getGroupTrends(),
      ]);

      if (trendRes.status === "fulfilled") setSnapshots(trendRes.value.snapshots);
      if (summaryRes.status === "fulfilled") setSummary(summaryRes.value);
      if (groupsRes.status === "fulfilled") setGroups(groupsRes.value);
      if (groupTrendsRes.status === "fulfilled") setGroupTrends(groupTrendsRes.value.groups);

    } catch (e: any) {
      setError(e?.message || "Failed to load trend data");
    } finally {
      setLoading(false);
    }
  }, [scopeGroupId, days]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleGenerateSnapshot = async (backfill?: number) => {
    setSnapshotLoading(true);
    try {
      const res = await generateSnapshot(backfill ? { backfill } : undefined);
      setBanner({ type: "success", message: res.message });
      setTimeout(() => setBanner(null), 5000);
      fetchData();
    } catch (e: any) {
      setBanner({ type: "error", message: e?.message || "Failed to generate snapshot" });
      setTimeout(() => setBanner(null), 5000);
    } finally {
      setSnapshotLoading(false);
    }
  };

  const current = summary?.current;
  const deltas = summary?.deltas;

  return (
    <div className="p-6 md:p-10 max-w-7xl mx-auto space-y-6">
      {/* Banner */}
      {banner && (
        <div className={`p-4 rounded-lg border text-sm flex items-center justify-between ${
          banner.type === "success"
            ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
            : "bg-red-500/10 border-red-500/20 text-red-400"
        }`}>
          <span>{banner.message}</span>
          <button onClick={() => setBanner(null)} className="hover:opacity-70"><X className="w-4 h-4" /></button>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Trending</h1>
          <p className="text-sm text-white/50 mt-1">
            Track your security posture over time. Are things getting better or worse?
          </p>
        </div>
        <div className="flex items-center gap-3">
          {isAdmin && (
            <>
              <button
                onClick={() => handleGenerateSnapshot()}
                disabled={snapshotLoading}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border border-white/10 text-white/60 hover:text-white/80 hover:bg-white/5 transition-colors disabled:opacity-50"
              >
                {snapshotLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                Snapshot Today
              </button>
              <button
                onClick={() => handleGenerateSnapshot(30)}
                disabled={snapshotLoading}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border border-white/10 text-white/60 hover:text-white/80 hover:bg-white/5 transition-colors disabled:opacity-50"
              >
                {snapshotLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <BarChart3 className="w-4 h-4" />}
                Backfill 30d
              </button>
            </>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative">
          <select
            value={scopeGroupId}
            onChange={(e) => setScopeGroupId(e.target.value)}
            className="appearance-none bg-white/5 border border-white/10 rounded-lg px-4 py-2 pr-9 text-sm text-white focus:outline-none focus:ring-1 focus:ring-teal-500"
          >
            <option value="all" className="bg-[#0f1729]">Organization-wide</option>
            {groups.map((g) => (
              <option key={g.id} value={String(g.id)} className="bg-[#0f1729]">{g.name}</option>
            ))}
          </select>
          <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30 pointer-events-none" />
        </div>

        <div className="flex items-center bg-white/5 border border-white/10 rounded-lg overflow-hidden">
          {[7, 30, 60, 90].map((d) => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={`px-3 py-2 text-xs font-medium transition-colors ${
                days === d
                  ? "bg-teal-600 text-white"
                  : "text-white/40 hover:text-white/60 hover:bg-white/5"
              }`}
            >
              {d}d
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="p-6 rounded-xl bg-red-500/5 border border-red-500/10 text-center">
          <AlertCircle className="w-8 h-8 text-red-400 mx-auto mb-2" />
          <p className="text-red-400 text-sm">{error}</p>
          <button onClick={fetchData} className="mt-3 text-sm text-teal-400 hover:text-teal-300">Retry</button>
        </div>
      )}

      {/* Loading */}
      {loading && !error && (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-teal-400 animate-spin" />
          <span className="ml-3 text-white/50 text-sm">Loading trend data...</span>
        </div>
      )}

      {/* No Data State */}
      {!loading && !error && snapshots.length === 0 && !current && (
        <div className="p-12 rounded-xl bg-[#0f1729]/60 border border-white/5 text-center">
          <BarChart3 className="w-12 h-12 text-white/20 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-white/80 mb-2">No trend data yet</h3>
          <p className="text-sm text-white/40 mb-6 max-w-md mx-auto">
            Generate your first snapshot to start tracking security posture over time.
            Use "Backfill 30d" to create historical data from your existing findings.
          </p>
          {isAdmin && (
            <button
              onClick={() => handleGenerateSnapshot(30)}
              disabled={snapshotLoading}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold bg-teal-600 hover:bg-teal-500 text-white transition-colors disabled:opacity-50"
            >
              {snapshotLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <BarChart3 className="w-4 h-4" />}
              Generate 30-Day Backfill
            </button>
          )}
        </div>
      )}

      {/* Main Content */}
      {!loading && !error && (current || snapshots.length > 0) && (
        <>
          {/* ────── Summary Cards ────── */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            {/* Exposure Score */}
            <div className={`rounded-xl border border-white/5 p-4 ${current ? scoreBg(current.exposureScore) : "bg-[#0f1729]/60"}`}>
              <div className="flex items-center justify-between mb-2">
                <Shield className={`w-4 h-4 ${current ? scoreColor(current.exposureScore) : "text-white/30"}`} />
                <DeltaBadge delta={deltas?.exposureScore} />
              </div>
              <div className={`text-2xl font-bold ${current ? scoreColor(current.exposureScore) : "text-white/30"}`}>
                {current?.exposureScore ?? "—"}
              </div>
              <div className="text-xs text-white/40 mt-1">Exposure Score</div>
            </div>

            {/* Total Findings */}
            <div className="bg-[#0f1729]/60 border border-white/5 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <AlertTriangle className="w-4 h-4 text-white/40" />
                <DeltaBadge delta={deltas?.totalFindings} />
              </div>
              <div className="text-2xl font-bold text-white">{current?.totalFindings ?? "—"}</div>
              <div className="text-xs text-white/40 mt-1">Total Findings</div>
            </div>

            {/* Critical */}
            <div className="bg-[#0f1729]/60 border border-white/5 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
                <DeltaBadge delta={deltas?.critical} />
              </div>
              <div className="text-2xl font-bold text-red-400">{current?.critical ?? "—"}</div>
              <div className="text-xs text-white/40 mt-1">Critical</div>
            </div>

            {/* High */}
            <div className="bg-[#0f1729]/60 border border-white/5 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="w-2.5 h-2.5 rounded-full bg-orange-500" />
                <DeltaBadge delta={deltas?.high} />
              </div>
              <div className="text-2xl font-bold text-orange-400">{current?.high ?? "—"}</div>
              <div className="text-xs text-white/40 mt-1">High</div>
            </div>

            {/* MTTR */}
            <div className="bg-[#0f1729]/60 border border-white/5 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <Clock className="w-4 h-4 text-purple-400" />
              </div>
              <div className="text-2xl font-bold text-purple-400">{current ? fmtMTTR(current.mttrHours) : "—"}</div>
              <div className="text-xs text-white/40 mt-1">Avg MTTR</div>
            </div>

            {/* Assets */}
            <div className="bg-[#0f1729]/60 border border-white/5 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <Layers className="w-4 h-4 text-white/40" />
                <DeltaBadge delta={deltas?.assetCount} inverse />
              </div>
              <div className="text-2xl font-bold text-white">{current?.assetCount ?? "—"}</div>
              <div className="text-xs text-white/40 mt-1">Assets</div>
            </div>
          </div>

          {/* ────── Charts Grid ────── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Exposure Score Trend */}
            <div className="bg-[#0f1729]/60 border border-white/5 rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-white/80">Exposure Score</h3>
                  <p className="text-xs text-white/30 mt-0.5">Lower is better — track your risk reduction</p>
                </div>
                <Shield className="w-4 h-4 text-teal-400/50" />
              </div>
              <ExposureChart data={snapshots} />
              <ChartLegend items={[
                { color: EXPOSURE_COLOR, label: "Exposure Score" },
                { color: "rgba(239,68,68,0.3)", label: "High Risk Zone (>70)" },
              ]} />
            </div>

            {/* Severity Breakdown */}
            <div className="bg-[#0f1729]/60 border border-white/5 rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-white/80">Severity Breakdown</h3>
                  <p className="text-xs text-white/30 mt-0.5">Active findings by severity over time</p>
                </div>
                <AlertTriangle className="w-4 h-4 text-amber-400/50" />
              </div>
              <SeverityChart data={snapshots} />
            </div>

            {/* Opened vs Resolved */}
            <div className="bg-[#0f1729]/60 border border-white/5 rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-white/80">New vs Resolved</h3>
                  <p className="text-xs text-white/30 mt-0.5">Are you closing faster than you&apos;re finding?</p>
                </div>
                <Activity className="w-4 h-4 text-emerald-400/50" />
              </div>
              <ActivityChart data={snapshots} />
            </div>

            {/* MTTR Trend */}
            <div className="bg-[#0f1729]/60 border border-white/5 rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-white/80">Mean Time to Remediate</h3>
                  <p className="text-xs text-white/30 mt-0.5">Average hours from detection to resolution</p>
                </div>
                <Clock className="w-4 h-4 text-purple-400/50" />
              </div>
              <MTTRChart data={snapshots} />
            </div>
          </div>

          {/* ────── Group Comparison ────── */}
          {scopeGroupId === "all" && groupTrends.length > 0 && (
            <div className="bg-[#0f1729]/60 border border-white/5 rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-white/80">Group Comparison</h3>
                  <p className="text-xs text-white/30 mt-0.5">Security posture across all groups — sorted by exposure</p>
                </div>
                <Layers className="w-4 h-4 text-white/30" />
              </div>
              <GroupComparisonTable groups={groupTrends} />
            </div>
          )}
        </>
      )}
    </div>
  );
}