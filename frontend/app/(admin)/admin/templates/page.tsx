"use client";

// FILE: app/(admin)/admin/templates/page.tsx
// Root-admin-only template browser. The full finding-template registry
// is the platform's detection IP — this page lets root admins audit
// titles, severities, descriptions, and remediation copy in one place
// without going to the markdown catalogue.
//
// Backend gates the data with require_root_admin (404s for everyone
// else). This page also gates the UI route with getIsRootAdmin() so
// non-root-admins navigating directly to /admin/templates see a 404.

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Search, FileSearch, ShieldAlert, ChevronRight, ChevronDown, X,
} from "lucide-react";
import { getAdminTemplates } from "../../../lib/api";
import { getIsRootAdmin } from "../../../lib/auth";

type Template = {
  id: string;
  title: string;
  severity: string;
  internalCategory: string;
  cwe: string;
  description: string;
  remediation: string;
  references: string[];
  tags: string[];
  alertName: string;
  monitorType: string;
  tunable: boolean;
  summary: string;
  confidence: string;
};

type Category = {
  id: string;
  label: string;
  blurb: string;
  totalCount: number;
  templates: Template[];
};

type Data = {
  totalTemplates: number;
  categories: Category[];
};

const SEVERITY_PILL: Record<string, string> = {
  critical: "bg-red-500/10 text-red-300 border-red-500/20",
  high:     "bg-orange-500/10 text-orange-300 border-orange-500/20",
  medium:   "bg-amber-500/10 text-amber-300 border-amber-500/20",
  low:      "bg-sky-500/10 text-sky-300 border-sky-500/20",
  info:     "bg-white/[0.06] text-white/40 border-white/10",
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export default function AdminTemplates() {
  const [data, setData] = useState<Data | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [search, setSearch] = useState("");
  const [activeCategory, setActiveCategory] = useState<string | null>(null);
  const [activeSeverity, setActiveSeverity] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  // Render-time root-admin gate. Prevents the page from briefly
  // flashing template content for users who navigated here directly
  // before the backend 404 fires.
  const allowed = typeof window === "undefined" ? false : getIsRootAdmin();

  useEffect(() => {
    if (!allowed) {
      setLoading(false);
      return;
    }
    (async () => {
      try {
        setData(await getAdminTemplates());
      } catch (e: any) {
        setError(e?.message || "Failed to load templates");
      } finally {
        setLoading(false);
      }
    })();
  }, [allowed]);

  const filteredCategories = useMemo(() => {
    if (!data) return [];
    const term = search.trim().toLowerCase();
    return data.categories
      .filter((c) => activeCategory === null || c.id === activeCategory)
      .map((c) => ({
        ...c,
        templates: c.templates.filter((t) => {
          if (activeSeverity && t.severity !== activeSeverity) return false;
          if (!term) return true;
          return (
            t.id.toLowerCase().includes(term) ||
            t.title.toLowerCase().includes(term) ||
            t.alertName.toLowerCase().includes(term) ||
            t.cwe.toLowerCase().includes(term) ||
            t.description.toLowerCase().includes(term) ||
            t.tags.some((tag) => tag.toLowerCase().includes(term))
          );
        }),
      }))
      .filter((c) => c.templates.length > 0);
  }, [data, search, activeCategory, activeSeverity]);

  const totalShowing = filteredCategories.reduce((acc, c) => acc + c.templates.length, 0);

  if (!allowed) {
    return (
      <div className="text-center py-20">
        <div className="text-6xl font-bold text-white/10 mb-4">404</div>
        <p className="text-white/40 text-sm">Page not found.</p>
        <Link href="/admin/dashboard" className="mt-4 inline-block text-sm text-teal-400 hover:underline">
          Back to admin
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-white flex items-center gap-2">
            <FileSearch className="w-5 h-5 text-teal-400" />
            Finding Templates
          </h1>
          <p className="text-xs text-white/30 mt-1 max-w-2xl">
            The complete detection registry. Root-admin-only — every
            severity, CWE, description, and remediation that ever
            surfaces to a customer. Source of truth lives in
            <code className="mx-1 text-white/50">backend/app/scanner/templates.py</code>.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-white/40">
          <ShieldAlert className="w-3.5 h-3.5" />
          Restricted access
        </div>
      </div>

      {/* Search + filters */}
      <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 space-y-3">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-white/30" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by id, title, CWE, or description…"
            className="w-full pl-9 pr-9 py-2 rounded-lg bg-white/[0.04] border border-white/[0.08] text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-teal-500/40"
          />
          {search && (
            <button
              type="button"
              onClick={() => setSearch("")}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded hover:bg-white/[0.08] text-white/40 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-white/30 mr-1">Category:</span>
          <button
            type="button"
            onClick={() => setActiveCategory(null)}
            className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
              activeCategory === null
                ? "bg-teal-500/15 text-teal-300 border-teal-500/30"
                : "bg-white/[0.02] text-white/40 border-white/[0.08] hover:text-white/70"
            }`}
          >
            All ({data?.totalTemplates ?? 0})
          </button>
          {data?.categories.map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => setActiveCategory(activeCategory === c.id ? null : c.id)}
              className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                activeCategory === c.id
                  ? "bg-teal-500/15 text-teal-300 border-teal-500/30"
                  : "bg-white/[0.02] text-white/40 border-white/[0.08] hover:text-white/70"
              }`}
            >
              {c.label} ({c.totalCount})
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-white/30 mr-1">Severity:</span>
          <button
            type="button"
            onClick={() => setActiveSeverity(null)}
            className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
              activeSeverity === null
                ? "bg-teal-500/15 text-teal-300 border-teal-500/30"
                : "bg-white/[0.02] text-white/40 border-white/[0.08] hover:text-white/70"
            }`}
          >
            All
          </button>
          {SEVERITIES.map((sev) => (
            <button
              key={sev}
              type="button"
              onClick={() => setActiveSeverity(activeSeverity === sev ? null : sev)}
              className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                activeSeverity === sev ? SEVERITY_PILL[sev]
                  : "bg-white/[0.02] text-white/40 border-white/[0.08] hover:text-white/70"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Status */}
      {error && (
        <div className="rounded-lg px-4 py-2.5 text-sm bg-red-500/10 text-red-300 border border-red-500/20">{error}</div>
      )}
      {loading && !data && (
        <div className="text-center text-white/30 text-sm py-16">Loading templates…</div>
      )}
      {data && (
        <div className="text-xs text-white/40">
          Showing {totalShowing} of {data.totalTemplates} templates.
        </div>
      )}

      {/* Categories */}
      <div className="space-y-6">
        {filteredCategories.map((cat) => (
          <section key={cat.id}>
            <div className="flex items-baseline gap-3 mb-2">
              <h2 className="text-base font-semibold text-white">{cat.label}</h2>
              <span className="text-xs text-white/30">{cat.templates.length} matched · {cat.totalCount} total</span>
            </div>
            <div className="rounded-xl border border-white/[0.06] divide-y divide-white/[0.06] overflow-hidden">
              {cat.templates.map((t) => {
                const open = expanded === t.id;
                return (
                  <div key={t.id} className="hover:bg-white/[0.02] transition-colors">
                    <button
                      type="button"
                      onClick={() => setExpanded(open ? null : t.id)}
                      className="w-full flex items-start gap-3 p-3 text-left"
                    >
                      <span className="mt-1">
                        {open ? <ChevronDown className="w-3.5 h-3.5 text-white/40" />
                              : <ChevronRight className="w-3.5 h-3.5 text-white/40" />}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${SEVERITY_PILL[t.severity]}`}>
                            {t.severity}
                          </span>
                          {t.cwe && <span className="text-[10px] text-white/30 font-mono">{t.cwe}</span>}
                          <span className="text-[10px] text-white/25 font-mono">{t.internalCategory}</span>
                          {!t.tunable && (
                            <span className="text-[10px] text-amber-300 font-mono">non-tunable</span>
                          )}
                        </div>
                        <div className="text-sm text-white/85">{t.title}</div>
                        {t.alertName && (
                          <div className="text-xs text-teal-300/80 mt-0.5">Alert: {t.alertName}</div>
                        )}
                        <code className="block text-[10px] text-white/25 font-mono mt-0.5">{t.id}</code>
                      </div>
                    </button>
                    {open && (
                      <div className="px-10 pb-4 space-y-4 text-sm">
                        {t.summary && (
                          <div>
                            <div className="text-[10px] uppercase tracking-wider text-white/30 mb-1">Summary</div>
                            <div className="text-white/70 leading-relaxed">{t.summary}</div>
                          </div>
                        )}
                        <div>
                          <div className="text-[10px] uppercase tracking-wider text-white/30 mb-1">Description</div>
                          <div className="text-white/70 leading-relaxed whitespace-pre-line">{t.description}</div>
                        </div>
                        {t.remediation && (
                          <div>
                            <div className="text-[10px] uppercase tracking-wider text-white/30 mb-1">Remediation</div>
                            <div className="text-white/70 leading-relaxed whitespace-pre-line">{t.remediation}</div>
                          </div>
                        )}
                        {(t.tags?.length || t.monitorType || t.confidence !== "high") && (
                          <div className="flex flex-wrap items-center gap-2 text-xs">
                            {t.tags?.map((tag) => (
                              <span key={tag} className="px-1.5 py-0.5 rounded bg-white/[0.04] text-white/50 font-mono text-[10px]">{tag}</span>
                            ))}
                            {t.monitorType && (
                              <span className="px-1.5 py-0.5 rounded bg-white/[0.04] text-white/50 text-[10px]">monitor: <code>{t.monitorType}</code></span>
                            )}
                            {t.confidence !== "high" && (
                              <span className="px-1.5 py-0.5 rounded bg-white/[0.04] text-white/50 text-[10px]">confidence: {t.confidence}</span>
                            )}
                          </div>
                        )}
                        {t.references?.length > 0 && (
                          <div>
                            <div className="text-[10px] uppercase tracking-wider text-white/30 mb-1">References</div>
                            <ul className="space-y-1">
                              {t.references.map((r) => (
                                <li key={r}>
                                  <a href={r} target="_blank" rel="noreferrer noopener"
                                     className="text-xs text-teal-400 hover:text-teal-300 break-all">
                                    {r}
                                  </a>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </section>
        ))}
        {!loading && data && filteredCategories.length === 0 && (
          <div className="text-center text-white/30 text-sm py-12">No templates match the current filters.</div>
        )}
      </div>
    </div>
  );
}
