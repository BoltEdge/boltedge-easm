"use client";
import { useEffect, useState } from "react";
import { getAdminStats } from "../../../lib/api";
import { Building2, Users, HardDrive, Zap, TrendingUp, RefreshCcw } from "lucide-react";

const PLAN_COLORS: Record<string, string> = {
  free: "#6b7280", starter: "#00b8d4", professional: "#7c5cfc",
  enterprise_silver: "#ff8800", enterprise_gold: "#ffd700",
};
const PLAN_LABELS: Record<string, string> = {
  free: "Free", starter: "Starter", professional: "Professional",
  enterprise_silver: "Enterprise Silver", enterprise_gold: "Enterprise Gold",
};

export default function AdminDashboard() {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try { setStats(await getAdminStats()); }
    catch (e: any) { setError(e?.message || "Failed to load stats"); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  if (loading) return <div className="text-white/40 text-sm">Loading…</div>;
  if (error) return <div className="text-red-400 text-sm">{error}</div>;
  if (!stats) return null;

  const statCards = [
    { label: "Total Organizations", value: stats.totalOrgs, icon: Building2, color: "#14b8a6" },
    { label: "Total Users", value: stats.totalUsers, icon: Users, color: "#7c5cfc" },
    { label: "New Orgs (30d)", value: stats.newOrgs30d, icon: TrendingUp, color: "#10b981" },
    { label: "Total Assets", value: stats.totalAssets, icon: HardDrive, color: "#ff8800" },
    { label: "Scans This Month", value: stats.totalScansThisMonth, icon: Zap, color: "#00b8d4" },
  ];

  const planDist: Record<string, number> = stats.planDistribution || {};
  const totalOrgs = stats.totalOrgs || 1;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Platform Dashboard</h1>
          <p className="text-xs text-white/30 mt-0.5">Live counts across all tenants</p>
        </div>
        <button onClick={load} className="flex items-center gap-1.5 text-xs text-white/40 hover:text-white transition-colors">
          <RefreshCcw className="w-3.5 h-3.5" />Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {statCards.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${color}15` }}>
                <Icon className="w-3.5 h-3.5" style={{ color }} />
              </div>
              <span className="text-[11px] text-white/40">{label}</span>
            </div>
            <div className="text-2xl font-bold text-white">{value?.toLocaleString()}</div>
          </div>
        ))}
      </div>

      <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
        <h2 className="text-sm font-semibold text-white mb-4">Plan Distribution</h2>
        <div className="space-y-3">
          {["free", "starter", "professional", "enterprise_silver", "enterprise_gold"].map((plan) => {
            const count = planDist[plan] || 0;
            const pct = totalOrgs > 0 ? (count / totalOrgs) * 100 : 0;
            const color = PLAN_COLORS[plan];
            return (
              <div key={plan}>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span style={{ color }}>{PLAN_LABELS[plan]}</span>
                  <span className="text-white/40">{count} org{count !== 1 ? "s" : ""} ({pct.toFixed(0)}%)</span>
                </div>
                <div className="h-1.5 bg-white/[0.04] rounded-full overflow-hidden">
                  <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
