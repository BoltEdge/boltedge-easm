// FILE: app/(authenticated)/discovery/DiscoverySummaryCard.tsx
//
// TL;DR card for a discovery job's results page.
// Pulls the templated summary payload from /discovery/jobs/<id>/summary
// and renders it as a compact "what just happened?" overview.
//
// Pure templated rendering — no LLM, no client-side analysis.

"use client";

import { useEffect, useState } from "react";
import { Sparkles, AlertTriangle, ChevronRight, Loader2 } from "lucide-react";
import { getDiscoverySummary, type DiscoverySummary } from "../../lib/discovery-api";

const NOTABLE_ICON: Record<string, string> = {
  dev_or_staging: "🛠",
  cloud_assets:   "☁",
  new_assets:     "✨",
  ip_ranges:      "🌐",
  urls:           "🔗",
};

const NOTABLE_COLOR: Record<string, string> = {
  dev_or_staging: "border-orange-500/30 bg-orange-500/5",
  cloud_assets:   "border-sky-500/30 bg-sky-500/5",
  new_assets:     "border-[#00b8d4]/30 bg-[#00b8d4]/5",
  ip_ranges:      "border-purple-500/30 bg-purple-500/5",
  urls:           "border-cyan-500/30 bg-cyan-500/5",
};

export default function DiscoverySummaryCard({ jobId }: { jobId: number }) {
  const [data, setData] = useState<DiscoverySummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    getDiscoverySummary(jobId)
      .then((d) => { if (!cancelled) setData(d); })
      .catch((e) => { if (!cancelled) setError(e?.message || "Failed to load summary"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [jobId]);

  if (loading) {
    return (
      <div className="rounded-xl border border-border bg-card p-5 flex items-center gap-3 text-muted-foreground text-sm">
        <Loader2 className="w-4 h-4 animate-spin" />
        Loading discovery overview…
      </div>
    );
  }

  if (error || !data) return null;  // Silent fail — page works without us.

  const { totals, notable, recommendations } = data;

  if (totals.discovered === 0) {
    return (
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="flex items-center gap-2.5 mb-2">
          <div className="w-7 h-7 rounded-lg bg-[#00b8d4]/10 flex items-center justify-center">
            <Sparkles className="w-3.5 h-3.5 text-[#00b8d4]" />
          </div>
          <h2 className="text-base font-semibold text-foreground">Discovery overview</h2>
        </div>
        <p className="text-sm text-muted-foreground">
          No assets were discovered. Try a deeper discovery profile or a different target.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-[#00b8d4]/30 bg-card p-5 space-y-4">
      {/* Header + quick totals */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-[#00b8d4]/10 flex items-center justify-center">
            <Sparkles className="w-3.5 h-3.5 text-[#00b8d4]" />
          </div>
          <h2 className="text-base font-semibold text-foreground">Discovery overview</h2>
        </div>
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <span><strong className="text-foreground text-sm">{totals.discovered}</strong> total</span>
          {totals.new > 0 && (
            <span><strong className="text-[#00b8d4] text-sm">{totals.new}</strong> new</span>
          )}
          <span><strong className="text-foreground text-sm">{totals.alreadyInInventory}</strong> in inventory</span>
        </div>
      </div>

      {/* Type breakdown */}
      {Object.keys(totals.byType).length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(totals.byType).map(([type, count]) => (
            <span
              key={type}
              className="px-2 py-0.5 rounded-md text-[11px] font-medium bg-muted/30 text-muted-foreground"
            >
              {count} {type.replace(/_/g, " ")}{count !== 1 ? "s" : ""}
            </span>
          ))}
        </div>
      )}

      {/* Two-column: notable + recommendations */}
      {(notable.length > 0 || recommendations.length > 0) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Notable patterns */}
          {notable.length > 0 && (
            <div className="space-y-2">
              <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wide flex items-center gap-1.5">
                <AlertTriangle className="w-3 h-3" />Notable
              </div>
              {notable.map((item, i) => (
                <div
                  key={i}
                  className={`rounded-lg border p-3 ${NOTABLE_COLOR[item.kind] || "border-border bg-background/40"}`}
                >
                  <div className="flex items-start gap-2 text-sm text-foreground/90">
                    <span className="text-base leading-none">{NOTABLE_ICON[item.kind] || "•"}</span>
                    <span className="leading-snug">{item.label}</span>
                  </div>
                  {item.sample.length > 0 && (
                    <div className="mt-1.5 ml-7 flex flex-wrap gap-1">
                      {item.sample.map((s) => (
                        <code
                          key={s}
                          className="text-[11px] font-mono bg-background/60 border border-border/60 rounded px-1.5 py-0.5 text-foreground/70"
                        >
                          {s}
                        </code>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Recommendations */}
          {recommendations.length > 0 && (
            <div className="space-y-2">
              <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wide">
                Suggested next steps
              </div>
              <ul className="space-y-1.5">
                {recommendations.map((r, i) => (
                  <li
                    key={i}
                    className="flex items-start gap-2 text-sm text-foreground/85 rounded-lg bg-background/40 border border-border px-3 py-2"
                  >
                    <ChevronRight className="w-3.5 h-3.5 text-[#00b8d4] mt-0.5 shrink-0" />
                    <span className="leading-snug">{r}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
