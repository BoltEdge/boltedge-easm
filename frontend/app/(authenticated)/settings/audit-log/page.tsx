// FILE: app/(authenticated)/settings/audit-log/page.tsx
// F7: Audit Log — view all actions taken across the organization
"use client";

import { useEffect, useMemo, useState, useCallback } from "react";
import {
  Shield, Search, Download, Loader2, ChevronLeft, ChevronRight,
  AlertTriangle, Play, Trash2, Edit, UserPlus, Key, Settings,
  Globe, Server, FileText, LogIn, ArrowLeftRight, RefreshCcw,
} from "lucide-react";
import { Button } from "../../../ui/button";
import { Input } from "../../../ui/input";
import { apiFetch } from "../../../lib/api";

function cn(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(" ");
}

function formatDate(d?: any) {
  if (!d) return "—";
  let dt: Date;
  if (typeof d === "string" && !d.endsWith("Z") && !d.includes("+")) dt = new Date(d + "Z");
  else dt = d instanceof Date ? d : new Date(d);
  if (isNaN(dt.getTime())) return "—";
  return dt.toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function timeAgo(d: any): string {
  if (!d) return "";
  if (typeof d === "string" && !d.endsWith("Z") && !d.includes("+")) d = d + "Z";
  const date = d instanceof Date ? d : new Date(d);
  if (isNaN(date.getTime())) return "";
  const diffMs = Date.now() - date.getTime();
  if (diffMs < 0) return "just now";
  const sec = Math.floor(diffMs / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const days = Math.floor(hr / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

// ─── Types ────────────────────────────────────
type AuditEntry = {
  id: string;
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

type CategoryKey = "all" | "finding" | "asset" | "scan" | "group" | "user" | "settings" | "auth" | "export";

// ─── Category config ──────────────────────────
const CATEGORY_CONFIG: Record<string, { label: string; color: string; icon: React.ComponentType<{ className?: string }> }> = {
  finding: { label: "Findings", color: "text-amber-400 bg-amber-500/10 border-amber-500/20", icon: AlertTriangle },
  asset: { label: "Assets", color: "text-blue-400 bg-blue-500/10 border-blue-500/20", icon: Globe },
  scan: { label: "Scans", color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20", icon: Play },
  group: { label: "Groups", color: "text-purple-400 bg-purple-500/10 border-purple-500/20", icon: Server },
  user: { label: "Users", color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20", icon: UserPlus },
  settings: { label: "Settings", color: "text-zinc-400 bg-zinc-500/10 border-zinc-500/20", icon: Settings },
  auth: { label: "Auth", color: "text-indigo-400 bg-indigo-500/10 border-indigo-500/20", icon: LogIn },
  export: { label: "Exports", color: "text-teal-400 bg-teal-500/10 border-teal-500/20", icon: FileText },
};

// ─── Action icon/color helpers ────────────────
function getActionStyle(action: string): { color: string } {
  if (action.includes("deleted") || action.includes("removed")) return { color: "text-red-400" };
  if (action.includes("created") || action.includes("added") || action.includes("register")) return { color: "text-emerald-400" };
  if (action.includes("started") || action.includes("login")) return { color: "text-cyan-400" };
  if (action.includes("failed")) return { color: "text-red-400" };
  if (action.includes("completed")) return { color: "text-emerald-400" };
  if (action.includes("resolved")) return { color: "text-emerald-400" };
  if (action.includes("suppressed") || action.includes("accepted_risk")) return { color: "text-amber-400" };
  return { color: "text-foreground" };
}

function formatAction(action: string): string {
  // "finding.resolved" → "Finding Resolved"
  return action
    .replace(/\./g, " ")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

// ─── Entry Row ────────────────────────────────
function AuditRow({ entry }: { entry: AuditEntry }) {
  const [expanded, setExpanded] = useState(false);
  const catConfig = CATEGORY_CONFIG[entry.category] || CATEGORY_CONFIG.settings;
  const CatIcon = catConfig.icon;
  const actionStyle = getActionStyle(entry.action);

  return (
    <div className="border-b border-border last:border-0">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center gap-3 text-left hover:bg-accent/30 transition-colors"
      >
        {/* Category icon */}
        <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border", catConfig.color)}>
          <CatIcon className="w-4 h-4" />
        </div>

        {/* Description */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className={cn("text-sm font-medium", actionStyle.color)}>
              {formatAction(entry.action)}
            </span>
            {entry.targetLabel && (
              <span className="text-xs text-muted-foreground font-mono truncate max-w-[200px]">
                {entry.targetLabel}
              </span>
            )}
          </div>
          {entry.description && (
            <p className="text-xs text-muted-foreground mt-0.5 truncate">{entry.description}</p>
          )}
        </div>

        {/* User */}
        <div className="text-xs text-muted-foreground shrink-0 text-right w-[140px] truncate">
          {entry.userEmail || (entry.userId ? `User #${entry.userId}` : "System")}
        </div>

        {/* Time */}
        <div className="text-xs text-muted-foreground shrink-0 text-right w-[90px]" title={formatDate(entry.createdAt)}>
          {timeAgo(entry.createdAt)}
        </div>
      </button>

      {/* Expanded details */}
      {expanded && (
        <div className="px-4 pb-3 pl-[60px] space-y-2">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div>
              <span className="text-muted-foreground">Action</span>
              <div className="text-foreground font-mono mt-0.5">{entry.action}</div>
            </div>
            <div>
              <span className="text-muted-foreground">Category</span>
              <div className="text-foreground mt-0.5 capitalize">{entry.category}</div>
            </div>
            {entry.targetType && (
              <div>
                <span className="text-muted-foreground">Target</span>
                <div className="text-foreground mt-0.5">{entry.targetType} #{entry.targetId}</div>
              </div>
            )}
            {entry.ipAddress && (
              <div>
                <span className="text-muted-foreground">IP Address</span>
                <div className="text-foreground font-mono mt-0.5">{entry.ipAddress}</div>
              </div>
            )}
          </div>

          <div>
            <span className="text-muted-foreground text-xs">Timestamp</span>
            <div className="text-foreground text-xs mt-0.5">{formatDate(entry.createdAt)}</div>
          </div>

          {entry.metadata && Object.keys(entry.metadata).length > 0 && (
            <div>
              <span className="text-muted-foreground text-xs">Details</span>
              <pre className="text-[11px] text-muted-foreground font-mono mt-1 bg-accent/50 rounded-lg px-3 py-2 overflow-x-auto max-h-32">
                {JSON.stringify(entry.metadata, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════
export default function AuditLogPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [perPage] = useState(50);
  const [categoryCounts, setCategoryCounts] = useState<Record<string, number>>({});

  // Filters
  const [category, setCategory] = useState<CategoryKey>("all");
  const [search, setSearch] = useState("");
  const [searchDebounced, setSearchDebounced] = useState("");

  // Debounce search
  useEffect(() => {
    const t = setTimeout(() => setSearchDebounced(search), 300);
    return () => clearTimeout(t);
  }, [search]);

  // Reset page on filter change
  useEffect(() => { setPage(1); }, [category, searchDebounced]);

  const loadEntries = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set("page", String(page));
      params.set("per_page", String(perPage));
      if (category !== "all") params.set("category", category);
      if (searchDebounced) params.set("q", searchDebounced);

      const data = await apiFetch<any>(`/audit-log?${params.toString()}`);
      setEntries(data.entries || []);
      setTotal(data.total || 0);
      setCategoryCounts(data.categoryCounts || {});
    } catch (e: any) {
      setError(e?.message || "Failed to load audit log");
    } finally {
      setLoading(false);
    }
  }, [page, perPage, category, searchDebounced]);

  useEffect(() => { loadEntries(); }, [loadEntries]);

  const totalPages = Math.ceil(total / perPage);
  const totalAll = useMemo(() => Object.values(categoryCounts).reduce((a, b) => a + b, 0), [categoryCounts]);

  async function handleExport() {
    try {
      const params = new URLSearchParams();
      if (category !== "all") params.set("category", category);
      if (searchDebounced) params.set("q", searchDebounced);

      const response = await fetch(`/api/audit-log/export?${params.toString()}`, {
        credentials: "include",
      });
      if (!response.ok) throw new Error("Export failed");

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `audit-log-${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      console.error("Export failed:", e);
    }
  }

  return (
    <div className="flex-1 bg-background overflow-auto">
      <div className="p-8 space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-foreground flex items-center gap-2">
              <Shield className="w-6 h-6 text-primary" />Audit Log
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Track all actions taken across your organization.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={loadEntries} className="gap-1.5">
              <RefreshCcw className="w-3.5 h-3.5" />Refresh
            </Button>
            <Button variant="outline" size="sm" onClick={handleExport} className="gap-1.5">
              <Download className="w-3.5 h-3.5" />Export CSV
            </Button>
          </div>
        </div>

        {/* Category filter tabs */}
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setCategory("all")}
            className={cn(
              "px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all",
              category === "all"
                ? "bg-primary/15 text-primary border-primary/30"
                : "bg-card text-muted-foreground border-border hover:border-primary/30"
            )}
          >
            All ({totalAll})
          </button>
          {Object.entries(CATEGORY_CONFIG).map(([key, cfg]) => {
            const count = categoryCounts[key] || 0;
            if (count === 0 && category !== key) return null;
            return (
              <button
                key={key}
                onClick={() => setCategory(key as CategoryKey)}
                className={cn(
                  "px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all",
                  category === key ? cfg.color : "bg-card text-muted-foreground border-border hover:border-primary/30"
                )}
              >
                {cfg.label} ({count})
              </button>
            );
          })}
        </div>

        {/* Search */}
        <div className="relative w-full max-w-md">
          <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search actions, targets, descriptions…"
            className="pl-9"
          />
        </div>

        {/* Error */}
        {error && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
            {error}
          </div>
        )}

        {/* Table */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          {/* Header row */}
          <div className="px-4 py-3 border-b border-border bg-muted/30 flex items-center gap-3">
            <div className="w-8 shrink-0" />
            <div className="flex-1 text-xs font-semibold text-muted-foreground uppercase">Action</div>
            <div className="text-xs font-semibold text-muted-foreground uppercase w-[140px] text-right">User</div>
            <div className="text-xs font-semibold text-muted-foreground uppercase w-[90px] text-right">When</div>
          </div>

          {/* Loading */}
          {loading && (
            <div className="px-4 py-12 flex items-center justify-center gap-2 text-muted-foreground">
              <Loader2 className="w-5 h-5 animate-spin" />Loading…
            </div>
          )}

          {/* Empty */}
          {!loading && entries.length === 0 && (
            <div className="px-4 py-12 text-center text-muted-foreground">
              <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="text-sm">
                {search || category !== "all"
                  ? "No audit entries match your filters."
                  : "No audit log entries yet. Actions will appear here as your team uses the platform."}
              </p>
            </div>
          )}

          {/* Entries */}
          {!loading && entries.map((entry) => (
            <AuditRow key={entry.id} entry={entry} />
          ))}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>
              Showing {(page - 1) * perPage + 1}–{Math.min(page * perPage, total)} of {total}
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
              >
                <ChevronLeft className="w-4 h-4" />
              </Button>
              <span className="text-xs">
                Page {page} of {totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
              >
                <ChevronRight className="w-4 h-4" />
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}