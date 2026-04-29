"use client";
import { useEffect, useState, useCallback, useMemo } from "react";
import { useSearchParams } from "next/navigation";
import { getAdminAuditLog } from "../../../lib/api";
import {
  Search, ChevronLeft, ChevronRight, RefreshCcw,
  AlertTriangle, Play, Trash2, Globe, Server, FileText,
  LogIn, Settings, UserPlus, ShieldAlert,
} from "lucide-react";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(d?: string) {
  if (!d) return "—";
  const dt = new Date(d);
  if (isNaN(dt.getTime())) return "—";
  return dt.toLocaleString(undefined, {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function timeAgo(d?: string): string {
  if (!d) return "";
  const ms = Date.now() - new Date(d).getTime();
  if (ms < 0) return "just now";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const days = Math.floor(h / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

function formatAction(action: string): string {
  return action.replace(/\./g, " ").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// ─── Category config ──────────────────────────────────────────────────────────

const CATEGORIES: Record<string, { label: string; color: string; icon: React.ComponentType<{ className?: string }> }> = {
  finding:  { label: "Findings",  color: "text-amber-400 bg-amber-500/10 border-amber-500/20",   icon: AlertTriangle },
  asset:    { label: "Assets",    color: "text-blue-400 bg-blue-500/10 border-blue-500/20",       icon: Globe },
  scan:     { label: "Scans",     color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",       icon: Play },
  group:    { label: "Groups",    color: "text-purple-400 bg-purple-500/10 border-purple-500/20", icon: Server },
  user:     { label: "Users",     color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20", icon: UserPlus },
  settings: { label: "Settings",  color: "text-zinc-400 bg-zinc-500/10 border-zinc-500/20",       icon: Settings },
  auth:     { label: "Auth",      color: "text-indigo-400 bg-indigo-500/10 border-indigo-500/20", icon: LogIn },
  export:   { label: "Exports",   color: "text-teal-400 bg-teal-500/10 border-teal-500/20",       icon: FileText },
  admin:    { label: "Admin",     color: "text-rose-400 bg-rose-500/10 border-rose-500/20",       icon: ShieldAlert },
};

function actionColor(action: string): string {
  if (action.includes("deleted") || action.includes("removed") || action.includes("suspended") || action.includes("archived")) return "text-red-400";
  if (action.includes("created") || action.includes("added") || action.includes("register") || action.includes("restored") || action.includes("unsuspended")) return "text-emerald-400";
  if (action.includes("started") || action.includes("login")) return "text-cyan-400";
  if (action.includes("failed")) return "text-red-400";
  if (action.includes("completed") || action.includes("resolved")) return "text-emerald-400";
  if (action.includes("plan_changed")) return "text-amber-400";
  return "text-white/70";
}

// ─── Entry Row ────────────────────────────────────────────────────────────────

type Entry = {
  id: string;
  organizationId?: string;
  organizationName?: string;
  userId?: string;
  userEmail?: string;
  action: string;
  category: string;
  targetType?: string;
  targetId?: string;
  targetLabel?: string;
  description?: string;
  metadata?: Record<string, any>;
  ipAddress?: string;
  createdAt?: string;
};

function EntryRow({ entry }: { entry: Entry }) {
  const [expanded, setExpanded] = useState(false);
  const cat = CATEGORIES[entry.category] || CATEGORIES.settings;
  const CatIcon = cat.icon;

  return (
    <div className="border-b border-white/[0.04] last:border-0">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center gap-3 text-left hover:bg-white/[0.02] transition-colors"
      >
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 border ${cat.color}`}>
          <CatIcon className="w-3.5 h-3.5" />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-sm font-medium ${actionColor(entry.action)}`}>
              {formatAction(entry.action)}
            </span>
            {entry.targetLabel && (
              <span className="text-xs text-white/30 font-mono truncate max-w-[180px]">{entry.targetLabel}</span>
            )}
          </div>
          {entry.description && (
            <p className="text-xs text-white/40 mt-0.5 truncate">{entry.description}</p>
          )}
        </div>

        {/* Org */}
        <div className="text-xs text-white/30 shrink-0 text-right w-[120px] truncate hidden lg:block">
          {entry.organizationName || "—"}
        </div>

        {/* User */}
        <div className="text-xs text-white/40 shrink-0 text-right w-[150px] truncate hidden md:block">
          {entry.userEmail || (entry.userId ? `#${entry.userId}` : "system")}
        </div>

        {/* Time */}
        <div className="text-xs text-white/30 shrink-0 text-right w-[80px]" title={formatDate(entry.createdAt)}>
          {timeAgo(entry.createdAt)}
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 pl-[52px] space-y-3 bg-white/[0.01]">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs pt-1">
            <div>
              <div className="text-white/30 mb-0.5">Organization</div>
              <div className="text-white/70">{entry.organizationName || entry.organizationId || "—"}</div>
            </div>
            <div>
              <div className="text-white/30 mb-0.5">User</div>
              <div className="text-white/70 font-mono">{entry.userEmail || entry.userId || "system"}</div>
            </div>
            <div>
              <div className="text-white/30 mb-0.5">Action</div>
              <div className="text-white/70 font-mono">{entry.action}</div>
            </div>
            {entry.targetType && (
              <div>
                <div className="text-white/30 mb-0.5">Target</div>
                <div className="text-white/70">{entry.targetType} #{entry.targetId}</div>
              </div>
            )}
          </div>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <div className="text-white/30 mb-0.5">Timestamp</div>
              <div className="text-white/60">{formatDate(entry.createdAt)}</div>
            </div>
            {entry.ipAddress && (
              <div>
                <div className="text-white/30 mb-0.5">IP Address</div>
                <div className="text-white/60 font-mono">{entry.ipAddress}</div>
              </div>
            )}
          </div>
          {entry.metadata && Object.keys(entry.metadata).length > 0 && (
            <div>
              <div className="text-white/30 text-xs mb-1">Details</div>
              <pre className="text-[11px] text-white/40 font-mono bg-white/[0.03] rounded-lg px-3 py-2 overflow-x-auto max-h-32 border border-white/[0.05]">
                {JSON.stringify(entry.metadata, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function AdminAuditLog() {
  const searchParams = useSearchParams();
  const [entries, setEntries] = useState<Entry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [categoryCounts, setCategoryCounts] = useState<Record<string, number>>({});

  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [orgFilter, setOrgFilter] = useState<number | undefined>(
    searchParams?.get("org_id") ? Number(searchParams.get("org_id")) : undefined
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getAdminAuditLog({
        page,
        perPage: 50,
        q: search || undefined,
        category: category || undefined,
        orgId: orgFilter,
        dateFrom: dateFrom || undefined,
        dateTo: dateTo || undefined,
      });
      setEntries(data.entries);
      setTotal(data.total);
      setPages(data.pages);
      setCategoryCounts(data.categoryCounts || {});
    } catch (e: any) {
      setError(e?.message || "Failed to load audit log");
    } finally {
      setLoading(false);
    }
  }, [page, search, category, dateFrom, dateTo]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [search, category, dateFrom, dateTo, orgFilter]);

  const totalAll = useMemo(() => Object.values(categoryCounts).reduce((a, b) => a + b, 0), [categoryCounts]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Audit Log</h1>
          <p className="text-xs text-white/30 mt-0.5">
            {loading ? "…" : `${total.toLocaleString()} event${total !== 1 ? "s" : ""} across all organizations`}
          </p>
        </div>
        <button onClick={load} className="flex items-center gap-1.5 text-xs text-white/40 hover:text-white transition-colors">
          <RefreshCcw className="w-3.5 h-3.5" />Refresh
        </button>
      </div>

      {/* Category tabs */}
      <div className="flex items-center gap-1.5 flex-wrap">
        <button
          onClick={() => setCategory("")}
          className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
            category === "" ? "bg-white/10 text-white" : "text-white/40 hover:text-white hover:bg-white/[0.04]"
          }`}
        >
          All <span className="ml-1 opacity-50">{totalAll.toLocaleString()}</span>
        </button>
        {Object.entries(CATEGORIES).map(([key, cfg]) => {
          const count = categoryCounts[key] || 0;
          if (!count && category !== key) return null;
          return (
            <button
              key={key}
              onClick={() => setCategory(key === category ? "" : key)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition-colors border ${
                category === key ? cfg.color : "text-white/40 border-transparent hover:text-white hover:bg-white/[0.04]"
              }`}
            >
              {cfg.label} <span className="ml-1 opacity-60">{count.toLocaleString()}</span>
            </button>
          );
        })}
      </div>

      {/* Org filter pill */}
      {orgFilter && (
        <div className="flex items-center gap-2">
          <span className="text-xs text-white/40">Filtered by org ID {orgFilter}</span>
          <button onClick={() => setOrgFilter(undefined)} className="text-xs text-white/30 hover:text-white transition-colors">&times; Remove</button>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-48 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/30" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search action, user, description…"
            className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg pl-8 pr-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40"
          />
        </div>
        <div className="flex items-center gap-2">
          <input
            type="date"
            value={dateFrom}
            onChange={(e) => setDateFrom(e.target.value)}
            className="bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white/60 focus:outline-none focus:border-teal-500/40 [color-scheme:dark]"
          />
          <span className="text-white/20 text-xs">to</span>
          <input
            type="date"
            value={dateTo}
            onChange={(e) => setDateTo(e.target.value)}
            className="bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white/60 focus:outline-none focus:border-teal-500/40 [color-scheme:dark]"
          />
        </div>
        {(search || category || dateFrom || dateTo || orgFilter) && (
          <button
            onClick={() => { setSearch(""); setCategory(""); setDateFrom(""); setDateTo(""); setOrgFilter(undefined); }}
            className="text-xs text-white/30 hover:text-white transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table header */}
      <div className="rounded-xl border border-white/[0.06] overflow-hidden">
        <div className="grid grid-cols-[28px_1fr_120px_150px_80px] gap-3 px-4 py-2.5 bg-white/[0.02] border-b border-white/[0.06] hidden md:grid">
          <div />
          <div className="text-xs font-medium text-white/40">Action / Description</div>
          <div className="text-xs font-medium text-white/40 hidden lg:block">Organization</div>
          <div className="text-xs font-medium text-white/40">User</div>
          <div className="text-xs font-medium text-white/40 text-right">When</div>
        </div>

        {error ? (
          <div className="px-4 py-8 text-center text-red-400 text-sm">{error}</div>
        ) : loading ? (
          <div className="px-4 py-8 text-center text-white/30 text-xs">Loading…</div>
        ) : entries.length === 0 ? (
          <div className="px-4 py-8 text-center text-white/30 text-xs">No audit events found.</div>
        ) : (
          entries.map((entry) => <EntryRow key={entry.id} entry={entry} />)
        )}
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <div className="flex items-center justify-between text-xs text-white/40">
          <span>Page {page} of {pages} — {total.toLocaleString()} total events</span>
          <div className="flex items-center gap-2">
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
              className="p-1.5 rounded hover:bg-white/[0.04] disabled:opacity-30 transition-colors">
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button onClick={() => setPage((p) => Math.min(pages, p + 1))} disabled={page === pages}
              className="p-1.5 rounded hover:bg-white/[0.04] disabled:opacity-30 transition-colors">
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
