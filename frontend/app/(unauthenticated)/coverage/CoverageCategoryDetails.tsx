"use client";

// Client component for the per-category template list. Server component
// would be cleaner, but we need a tiny bit of interactivity:
//  - Show first 12 templates by default; "show all N" reveals the rest
//    so the page doesn't render 5 × 80-row tables on first paint.
//  - Per-category severity filter pills.
// Both are pure UI state — no API calls, no useEffect cascade.

import { useMemo, useState } from "react";

type Template = {
  id: string;
  title: string;
  severity: string;
  summary: string;
  alertName: string;
  cwe: string;
};

type Props = {
  templates: Template[];
  severityPill: Record<string, string>;
};

const INITIAL_VISIBLE = 12;
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export default function CoverageCategoryDetails({ templates, severityPill }: Props) {
  const [activeSeverity, setActiveSeverity] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);

  const filtered = useMemo(() => {
    if (!activeSeverity) return templates;
    return templates.filter((t) => t.severity === activeSeverity);
  }, [templates, activeSeverity]);

  const visible = showAll ? filtered : filtered.slice(0, INITIAL_VISIBLE);
  const remaining = filtered.length - visible.length;

  return (
    <div>
      {/* Severity filter pills */}
      <div className="flex flex-wrap items-center gap-2 mb-4">
        <button
          type="button"
          onClick={() => { setActiveSeverity(null); setShowAll(false); }}
          className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold border transition-colors ${
            activeSeverity === null
              ? "bg-white/10 text-white border-white/20"
              : "bg-white/[0.02] text-white/40 border-white/[0.08] hover:text-white/70"
          }`}
        >
          All ({templates.length})
        </button>
        {SEVERITIES.map((sev) => {
          const count = templates.filter((t) => t.severity === sev).length;
          if (count === 0) return null;
          const active = activeSeverity === sev;
          return (
            <button
              key={sev}
              type="button"
              onClick={() => { setActiveSeverity(active ? null : sev); setShowAll(false); }}
              className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold border transition-colors ${
                active
                  ? severityPill[sev]
                  : "bg-white/[0.02] text-white/40 border-white/[0.08] hover:text-white/70"
              }`}
            >
              {count} {sev}
            </button>
          );
        })}
      </div>

      {/* Template list */}
      <div className="rounded-xl border border-white/[0.06] divide-y divide-white/[0.06] overflow-hidden">
        {visible.map((t) => (
          <div key={t.id} className="p-4 hover:bg-white/[0.02] transition-colors">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span
                    className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${severityPill[t.severity]}`}
                  >
                    {t.severity}
                  </span>
                  {t.cwe && (
                    <span className="text-[10px] text-white/30 font-mono">{t.cwe}</span>
                  )}
                </div>
                <div className="text-sm font-medium text-white/85">
                  {t.alertName || t.title}
                </div>
                {t.summary && (
                  <p className="mt-1 text-xs text-white/50 leading-relaxed line-clamp-2">
                    {t.summary}
                  </p>
                )}
              </div>
              <code className="hidden sm:block text-[10px] text-white/25 font-mono whitespace-nowrap pt-0.5">
                {t.id}
              </code>
            </div>
          </div>
        ))}
        {visible.length === 0 && (
          <div className="p-8 text-center text-sm text-white/40">
            No templates match this severity filter.
          </div>
        )}
      </div>

      {/* Show more */}
      {!showAll && remaining > 0 && (
        <div className="mt-4 text-center">
          <button
            type="button"
            onClick={() => setShowAll(true)}
            className="text-xs text-teal-300 hover:text-teal-200 transition-colors font-medium"
          >
            Show {remaining} more {remaining === 1 ? "template" : "templates"} →
          </button>
        </div>
      )}
      {showAll && filtered.length > INITIAL_VISIBLE && (
        <div className="mt-4 text-center">
          <button
            type="button"
            onClick={() => setShowAll(false)}
            className="text-xs text-white/40 hover:text-white/70 transition-colors"
          >
            Collapse
          </button>
        </div>
      )}
    </div>
  );
}
