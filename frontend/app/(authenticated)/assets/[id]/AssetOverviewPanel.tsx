// FILE: app/(authenticated)/assets/[id]/AssetOverviewPanel.tsx
//
// "At a glance" overview card for an asset. Shows:
//   - 4 quick stats (open findings, total scans, last scan, monitoring status)
//   - Top 3 open findings with severity
//   - Up to 5 deterministic recommendations
//
// Pure templated rendering of the /assets/<id>/overview payload. No
// new analysis happens client-side — all rules and counts come from
// the backend.

"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Sparkles, Activity, Shield, Eye, Clock, AlertCircle, ChevronRight, Loader2 } from "lucide-react";
import { getAssetOverview, type AssetOverview } from "../../../lib/api";

const SEV_BG: Record<string, string> = {
  critical: "bg-red-500/10 text-red-300 border-red-500/30",
  high:     "bg-orange-500/10 text-orange-300 border-orange-500/30",
  medium:   "bg-yellow-500/10 text-yellow-300 border-yellow-500/30",
  low:      "bg-blue-500/10 text-blue-300 border-blue-500/30",
  info:     "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  const diffMs = Date.now() - d.getTime();
  const days = Math.floor(diffMs / 86400000);
  if (days < 1) return "today";
  if (days === 1) return "yesterday";
  if (days < 30) return `${days} days ago`;
  const months = Math.floor(days / 30);
  if (months === 1) return "1 month ago";
  if (months < 12) return `${months} months ago`;
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function formatFreq(freq: string | null | undefined): string {
  if (!freq) return "—";
  return freq.replace(/_/g, " ");
}

export default function AssetOverviewPanel({ assetId }: { assetId: string | number }) {
  const [data, setData] = useState<AssetOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    getAssetOverview(assetId)
      .then((d) => { if (!cancelled) setData(d); })
      .catch((e) => { if (!cancelled) setError(e?.message || "Failed to load overview"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [assetId]);

  if (loading) {
    return (
      <div className="rounded-xl border border-border bg-card p-5 flex items-center gap-3 text-muted-foreground text-sm">
        <Loader2 className="w-4 h-4 animate-spin" />
        Loading overview…
      </div>
    );
  }

  if (error || !data) return null;  // Silent fail — page works without us.

  const { asset, scan, findings, monitor, recommendations } = data;

  const stats = [
    {
      icon: AlertCircle,
      label: "Open findings",
      value: findings.open,
      sub: findings.bySeverity.critical > 0
        ? `${findings.bySeverity.critical} critical`
        : findings.bySeverity.high > 0
          ? `${findings.bySeverity.high} high`
          : "no critical/high",
      color: findings.bySeverity.critical > 0 ? "#ef4444"
        : findings.bySeverity.high > 0 ? "#f97316"
        : findings.open > 0 ? "#eab308" : "#10b981",
    },
    {
      icon: Activity,
      label: "Scans run",
      value: scan.totalScans,
      sub: scan.lastScanProfile ? `last: ${scan.lastScanProfile}` : "never scanned",
      color: "#00b8d4",
    },
    {
      icon: Clock,
      label: "Last scan",
      value: formatRelative(scan.lastScanAt),
      sub: scan.scanStatus.replace(/_/g, " "),
      color: "#7c5cfc",
    },
    {
      icon: Eye,
      label: "Monitoring",
      value: monitor?.enabled ? "On" : "Off",
      sub: monitor?.enabled ? formatFreq(monitor.frequency) : "not enabled",
      color: monitor?.enabled ? "#10b981" : "#6b7280",
    },
  ];

  return (
    <div className="rounded-xl border border-primary/20 bg-card p-5 space-y-5">
      {/* Header */}
      <div className="flex items-center gap-2.5">
        <div className="w-7 h-7 rounded-lg bg-primary/10 flex items-center justify-center">
          <Sparkles className="w-3.5 h-3.5 text-primary" />
        </div>
        <h2 className="text-base font-semibold text-foreground">At a glance</h2>
        <span className="text-xs text-muted-foreground">
          {asset.groupName ? `In ${asset.groupName}` : ""}{asset.ageDays != null ? ` · added ${asset.ageDays}d ago` : ""}
        </span>
      </div>

      {/* Stat tiles */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {stats.map(({ icon: Icon, label, value, sub, color }) => (
          <div key={label} className="rounded-lg border border-border bg-background/50 p-3">
            <div className="flex items-center gap-2 text-[11px] text-muted-foreground uppercase tracking-wide">
              <Icon className="w-3 h-3" style={{ color }} />
              {label}
            </div>
            <div className="mt-1.5 text-xl font-bold text-foreground" style={{ color }}>
              {value}
            </div>
            <div className="text-[11px] text-muted-foreground mt-0.5 lowercase">{sub}</div>
          </div>
        ))}
      </div>

      {/* Two-column grid for findings + recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top open findings */}
        {findings.topOpen.length > 0 ? (
          <div className="space-y-2">
            <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wide">
              Top open findings
            </div>
            {findings.topOpen.map((f) => (
              <Link
                key={f.id}
                href={`/findings?focus=${f.id}`}
                className="flex items-center gap-3 rounded-lg border border-border bg-background/40 px-3 py-2 hover:bg-accent/50 transition-colors group"
              >
                <span className={`text-[10px] font-semibold uppercase tracking-wide rounded px-1.5 py-0.5 border ${SEV_BG[f.severity] || SEV_BG.info}`}>
                  {f.severity}
                </span>
                <span className="flex-1 text-sm text-foreground truncate">{f.title}</span>
                <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/40 group-hover:text-foreground/70 transition-colors shrink-0" />
              </Link>
            ))}
          </div>
        ) : (
          <div className="rounded-lg border border-border bg-background/40 p-4 flex items-center gap-3 text-sm">
            <Shield className="w-4 h-4 text-[#10b981] shrink-0" />
            <span className="text-muted-foreground">
              {scan.totalScans === 0
                ? "No scans yet — run one to surface any issues."
                : "No open findings on this asset."}
            </span>
          </div>
        )}

        {/* Recommendations */}
        {recommendations.length > 0 ? (
          <div className="space-y-2">
            <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wide">
              Recommended next steps
            </div>
            <ul className="space-y-1.5">
              {recommendations.map((r, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-foreground/85 rounded-lg bg-background/40 border border-border px-3 py-2">
                  <span className="text-primary text-xs mt-0.5">→</span>
                  <span className="leading-snug">{r}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <div className="rounded-lg border border-border bg-background/40 p-4 flex items-center gap-3 text-sm">
            <Shield className="w-4 h-4 text-[#10b981] shrink-0" />
            <span className="text-muted-foreground">
              Nothing to recommend — this asset is in good shape.
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
