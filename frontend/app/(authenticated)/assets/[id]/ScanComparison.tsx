// FILE: app/(authenticated)/assets/[id]/ScanComparison.tsx
// F6: Scan Diff & Comparison — inline expandable section on asset detail page
// Compares two completed scan jobs using dedupe_key matching
"use client";

import { useEffect, useState, useMemo } from "react";
import {
  ArrowRight, Plus, Minus, Equal, AlertTriangle, ChevronDown,
  ChevronRight, Loader2, X, ArrowLeftRight, TrendingUp,
  TrendingDown, Shield,
} from "lucide-react";
import { apiFetch } from "../../../lib/api";
import { SeverityBadge } from "../../../SeverityBadge";
import { Button } from "../../../ui/button";

function cn(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(" ");
}

function formatDate(d?: any) {
  if (!d) return "—";
  let dt: Date;
  if (typeof d === "string" && !d.endsWith("Z") && !d.includes("+")) dt = new Date(d + "Z");
  else dt = d instanceof Date ? d : new Date(d);
  if (isNaN(dt.getTime())) return "—";
  return dt.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

// ─── Types ────────────────────────────────────
type DiffFinding = {
  id: string;
  title: string;
  severity: string;
  category: string;
  findingType: string;
  description: string;
  source: string;
  detectedAt?: string;
};

type JobMeta = {
  id: string;
  status: string;
  profileName?: string;
  startedAt?: string;
  finishedAt?: string;
  findingCount: number;
};

type CompareData = {
  assetValue: string;
  jobA: JobMeta;
  jobB: JobMeta;
  new: DiffFinding[];
  removed: DiffFinding[];
  unchanged: DiffFinding[];
  summary: {
    newCount: number;
    removedCount: number;
    unchangedCount: number;
    newSeverity: Record<string, number>;
    removedSeverity: Record<string, number>;
  };
};

type DiffTab = "new" | "removed" | "unchanged";

// ─── Severity helpers ─────────────────────────
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function countActionable(counts: Record<string, number>): number {
  return (counts.critical || 0) + (counts.high || 0) + (counts.medium || 0);
}

// ─── Finding Row ──────────────────────────────
function DiffFindingRow({ finding, variant }: { finding: DiffFinding; variant: DiffTab }) {
  const [expanded, setExpanded] = useState(false);

  const rowBg = {
    new: "hover:bg-emerald-500/5",
    removed: "hover:bg-zinc-500/5",
    unchanged: "hover:bg-accent/30",
  }[variant];

  const indicator = {
    new: <Plus className="w-3.5 h-3.5 text-emerald-400 shrink-0" />,
    removed: <Minus className="w-3.5 h-3.5 text-zinc-400 shrink-0" />,
    unchanged: <Equal className="w-3.5 h-3.5 text-muted-foreground/50 shrink-0" />,
  }[variant];

  return (
    <div className={cn("border-b border-border last:border-0 transition-colors", rowBg)}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center gap-3 text-left"
      >
        {indicator}
        <SeverityBadge severity={finding.severity} />
        <span className="text-sm text-foreground font-medium flex-1 min-w-0 truncate">{finding.title}</span>
        {finding.category && (
          <span className="text-[10px] text-muted-foreground bg-accent rounded px-1.5 py-0.5 shrink-0">{finding.category}</span>
        )}
        <ChevronDown className={cn("w-3.5 h-3.5 text-muted-foreground transition-transform shrink-0", expanded && "rotate-180")} />
      </button>
      {expanded && finding.description && (
        <div className="px-4 pb-3 pl-12">
          <p className="text-xs text-muted-foreground leading-relaxed">{finding.description}</p>
          {finding.detectedAt && (
            <p className="text-[10px] text-muted-foreground/60 mt-1">Detected: {formatDate(finding.detectedAt)}</p>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════
// Main Export: ScanComparison
// ═══════════════════════════════════════════════
export default function ScanComparison({
  assetId,
  scanJobs,
  onClose,
}: {
  assetId: string;
  scanJobs: any[];
  onClose: () => void;
}) {
  // Only completed jobs can be compared
  const completedJobs = useMemo(
    () => scanJobs.filter((j) => j.status === "completed").sort((a, b) => {
      const da = new Date(a.finishedAt || a.startedAt || 0).getTime();
      const db = new Date(b.finishedAt || b.startedAt || 0).getTime();
      return db - da; // newest first
    }),
    [scanJobs]
  );

  const [jobAId, setJobAId] = useState<string>("");
  const [jobBId, setJobBId] = useState<string>("");
  const [data, setData] = useState<CompareData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<DiffTab>("new");

  // Auto-select: newest two scans
  useEffect(() => {
    if (completedJobs.length >= 2) {
      setJobBId(String(completedJobs[0].id)); // newer
      setJobAId(String(completedJobs[1].id)); // older
    }
  }, [completedJobs]);

  // Auto-load when both selected
  useEffect(() => {
    if (!jobAId || !jobBId || jobAId === jobBId) {
      setData(null);
      return;
    }
    setLoading(true);
    setError(null);
    apiFetch<CompareData>(`/scan-jobs/${jobAId}/compare/${jobBId}`)
      .then((d) => {
        setData(d);
        // Default to the most interesting tab
        if (d.summary.newCount > 0) setActiveTab("new");
        else if (d.summary.removedCount > 0) setActiveTab("removed");
        else setActiveTab("unchanged");
      })
      .catch((e: any) => setError(e?.message || "Failed to compare scans"))
      .finally(() => setLoading(false));
  }, [jobAId, jobBId]);

  if (completedJobs.length < 2) {
    return (
      <div className="bg-card border border-border rounded-xl p-6">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <ArrowLeftRight className="w-4 h-4 text-primary" />Scan Comparison
          </h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
        </div>
        <div className="text-center py-8 text-muted-foreground">
          <ArrowLeftRight className="w-8 h-8 mx-auto mb-3 opacity-30" />
          <p className="text-sm">Need at least 2 completed scans to compare.</p>
          <p className="text-xs mt-1">Run another scan to see what changed.</p>
        </div>
      </div>
    );
  }

  const findings = data ? data[activeTab] : [];

  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-border flex items-center justify-between">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <ArrowLeftRight className="w-4 h-4 text-primary" />Scan Comparison
        </h3>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Scan selectors */}
      <div className="px-5 py-4 border-b border-border bg-muted/10">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground font-medium">Baseline</span>
            <select
              value={jobAId}
              onChange={(e) => setJobAId(e.target.value)}
              className="h-8 rounded-md border border-border bg-background px-2 text-xs text-foreground outline-none"
            >
              <option value="">Select scan…</option>
              {completedJobs.map((j) => (
                <option key={j.id} value={String(j.id)} disabled={String(j.id) === jobBId}>
                  {formatDate(j.finishedAt || j.startedAt)} — {j.profileName || "Scan"}
                </option>
              ))}
            </select>
          </div>

          <ArrowRight className="w-4 h-4 text-muted-foreground shrink-0" />

          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground font-medium">Current</span>
            <select
              value={jobBId}
              onChange={(e) => setJobBId(e.target.value)}
              className="h-8 rounded-md border border-border bg-background px-2 text-xs text-foreground outline-none"
            >
              <option value="">Select scan…</option>
              {completedJobs.map((j) => (
                <option key={j.id} value={String(j.id)} disabled={String(j.id) === jobAId}>
                  {formatDate(j.finishedAt || j.startedAt)} — {j.profileName || "Scan"}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Loading / Error */}
      {loading && (
        <div className="px-5 py-12 flex items-center justify-center gap-2 text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin" />Comparing scans…
        </div>
      )}

      {error && (
        <div className="px-5 py-4">
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>
        </div>
      )}

      {/* Results */}
      {data && !loading && (
        <>
          {/* Summary cards */}
          <div className="px-5 py-4 border-b border-border">
            <div className="grid grid-cols-3 gap-3">
              {/* New */}
              <div className={cn(
                "rounded-xl border p-3 text-center cursor-pointer transition-all",
                activeTab === "new"
                  ? "border-emerald-500/40 bg-emerald-500/10"
                  : "border-border bg-background hover:border-emerald-500/20"
              )} onClick={() => setActiveTab("new")}>
                <div className="flex items-center justify-center gap-1.5 mb-1">
                  <TrendingUp className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-xs font-medium text-muted-foreground">New</span>
                </div>
                <div className="text-2xl font-bold text-emerald-400">{data.summary.newCount}</div>
                {countActionable(data.summary.newSeverity) > 0 && (
                  <div className="text-[10px] text-amber-400 mt-0.5">
                    {countActionable(data.summary.newSeverity)} actionable
                  </div>
                )}
              </div>

              {/* Removed */}
              <div className={cn(
                "rounded-xl border p-3 text-center cursor-pointer transition-all",
                activeTab === "removed"
                  ? "border-zinc-400/40 bg-zinc-500/10"
                  : "border-border bg-background hover:border-zinc-400/20"
              )} onClick={() => setActiveTab("removed")}>
                <div className="flex items-center justify-center gap-1.5 mb-1">
                  <TrendingDown className="w-3.5 h-3.5 text-zinc-400" />
                  <span className="text-xs font-medium text-muted-foreground">Removed</span>
                </div>
                <div className="text-2xl font-bold text-zinc-400">{data.summary.removedCount}</div>
                {countActionable(data.summary.removedSeverity) > 0 && (
                  <div className="text-[10px] text-emerald-400 mt-0.5">
                    {countActionable(data.summary.removedSeverity)} resolved
                  </div>
                )}
              </div>

              {/* Unchanged */}
              <div className={cn(
                "rounded-xl border p-3 text-center cursor-pointer transition-all",
                activeTab === "unchanged"
                  ? "border-primary/40 bg-primary/10"
                  : "border-border bg-background hover:border-primary/20"
              )} onClick={() => setActiveTab("unchanged")}>
                <div className="flex items-center justify-center gap-1.5 mb-1">
                  <Shield className="w-3.5 h-3.5 text-muted-foreground" />
                  <span className="text-xs font-medium text-muted-foreground">Unchanged</span>
                </div>
                <div className="text-2xl font-bold text-foreground">{data.summary.unchangedCount}</div>
              </div>
            </div>
          </div>

          {/* Change summary sentence */}
          <div className="px-5 py-3 border-b border-border bg-muted/10">
            <p className="text-xs text-muted-foreground">
              {data.summary.newCount === 0 && data.summary.removedCount === 0 ? (
                <span className="text-emerald-400 font-medium">No changes detected between these scans.</span>
              ) : (
                <>
                  Between{" "}
                  <span className="text-foreground font-medium">{data.jobA.profileName || "Scan"}</span>
                  {" "}({formatDate(data.jobA.finishedAt)}) and{" "}
                  <span className="text-foreground font-medium">{data.jobB.profileName || "Scan"}</span>
                  {" "}({formatDate(data.jobB.finishedAt)}):
                  {data.summary.newCount > 0 && (
                    <span className="text-emerald-400 font-medium"> +{data.summary.newCount} new</span>
                  )}
                  {data.summary.newCount > 0 && data.summary.removedCount > 0 && ","}
                  {data.summary.removedCount > 0 && (
                    <span className="text-zinc-400 font-medium"> -{data.summary.removedCount} removed</span>
                  )}
                  .
                </>
              )}
            </p>
          </div>

          {/* Severity breakdown for active tab (new/removed) */}
          {activeTab !== "unchanged" && data.summary[activeTab === "new" ? "newSeverity" : "removedSeverity"] && (
            <div className="px-5 py-3 border-b border-border flex flex-wrap gap-2">
              {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
                const counts = data.summary[activeTab === "new" ? "newSeverity" : "removedSeverity"];
                const count = counts[sev] || 0;
                if (!count) return null;
                return (
                  <span key={sev} className="text-[10px] font-semibold">
                    <SeverityBadge severity={sev} />
                    <span className="ml-1 text-muted-foreground">×{count}</span>
                  </span>
                );
              })}
            </div>
          )}

          {/* Findings list */}
          <div className="max-h-[500px] overflow-y-auto">
            {findings.length === 0 ? (
              <div className="px-5 py-12 text-center text-muted-foreground">
                <p className="text-sm">
                  {activeTab === "new" && "No new findings in the current scan."}
                  {activeTab === "removed" && "No findings were removed between scans."}
                  {activeTab === "unchanged" && "No unchanged findings."}
                </p>
              </div>
            ) : (
              <div>
                {findings.map((f: DiffFinding) => (
                  <DiffFindingRow key={f.id} finding={f} variant={activeTab} />
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="px-5 py-3 border-t border-border bg-muted/10 flex items-center justify-between text-xs text-muted-foreground">
            <span>
              {data.jobA.findingCount} findings in baseline → {data.jobB.findingCount} in current
            </span>
            <span>
              Net change: {data.jobB.findingCount - data.jobA.findingCount >= 0 ? "+" : ""}
              {data.jobB.findingCount - data.jobA.findingCount}
            </span>
          </div>
        </>
      )}
    </div>
  );
}