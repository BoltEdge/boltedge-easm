// FILE: app/(authenticated)/findings/page.tsx
// Exposure Findings — list, filter, status workflow, bulk actions, export
// F2: Full status workflow (open, in_progress, accepted_risk, suppressed, resolved)
// M9 RBAC: edit_findings gates status/bulk actions, export_scan_results gates export
// CLOUD: Added cloud category + sub-type icons for cloud asset findings
// Phase 1: Skeleton loading state on initial page load
"use client";

import { useEffect, useMemo, useState, useCallback } from "react";
import Link from "next/link";
import {
  AlertTriangle, Search, Loader2, Download, EyeOff, Eye,
  CheckSquare, Square, X, ChevronDown, ChevronLeft, ChevronRight,
  Tag, Wrench, CheckCircle2, RotateCcw, Clock, ShieldCheck,
  AlertCircle, Cloud, Database, Box, Cpu, Shield,
} from "lucide-react";

import type { AssetGroup, Finding } from "../../types";
import { getGroups, apiFetch } from "../../lib/api";
import { useOrg } from "../contexts/OrgContext";

import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "../../ui/dialog";
import { SeverityBadge } from "../../SeverityBadge";
import { FindingDetailsDialog } from "../../FindingDetailsDialog";
import { FindingsPageSkeleton } from "../../ui/skeleton";

type SeverityKey = "critical" | "high" | "medium" | "low" | "info";
type SeverityFilter = "all" | SeverityKey;
type CategoryFilter = "all" | string;
type StatusKey = "open" | "in_progress" | "accepted_risk" | "suppressed" | "resolved" | "all";

function cn(...classes: Array<string | undefined | null | false>) {
  return classes.filter(Boolean).join(" ");
}

function formatDate(d?: any) {
  if (!d) return "\u2014";
  let dt: Date;
  if (typeof d === "string" && !d.endsWith("Z") && !d.includes("+")) dt = new Date(d + "Z");
  else dt = d instanceof Date ? d : new Date(d);
  if (isNaN(dt.getTime())) return "\u2014";
  return dt.toLocaleString();
}

function getSeverity(f: any): SeverityKey {
  const s = String(f?.severity || "info").toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") return s;
  return "info";
}

function getCategory(f: any): string {
  const direct = f.category ?? f.details?.category;
  if (direct) return String(direct).toLowerCase();

  // Cloud finding detection by template_id
  const templateId = String(f.templateId ?? f.template_id ?? "").toLowerCase();
  if (templateId.startsWith("cloud-")) return "cloud";

  const title = String(f.title || "").toLowerCase();

  // Cloud keyword detection
  if (
    title.includes("cloud storage") || title.includes("cloud registry") ||
    title.includes("cloud serverless") || title.includes("cloud cdn") ||
    title.includes("public bucket") || title.includes("s3 bucket") ||
    title.includes("azure blob") || title.includes("gcs bucket") ||
    title.includes("container registry") || title.includes("ecr ") ||
    title.includes("acr ") || title.includes("gcr ") ||
    title.includes("docker hub") || title.includes("cdn origin") ||
    title.includes("serverless") || title.includes("cloud function") ||
    title.includes("azure function") || title.includes("cloud run")
  ) return "cloud";

  if (title.includes("tls") || title.includes("ssl") || title.includes("certificate")) return "ssl";
  if (title.includes("header") || title.includes("csp") || title.includes("hsts")) return "headers";
  if (title.includes("spf") || title.includes("dkim") || title.includes("dmarc") || title.includes("dns") || title.includes("aaaa")) return "dns";
  if (title.includes("cve") || title.includes("vulnerab")) return "cve";
  if (title.includes("port") || title.includes("exposed") || title.includes("service")) return "ports";
  if (title.includes("technology") || title.includes("detected")) return "tech";
  if (title.includes("exposure score")) return "exposure";
  if (title.includes("api") || title.includes("swagger") || title.includes("graphql") || title.includes("actuator") || title.includes(".env") || title.includes(".git")) return "api";
  return "other";
}

/**
 * Determine cloud sub-type from template_id for icon display.
 * Returns: "storage" | "registry" | "serverless" | "cdn" | null
 */
function getCloudSubType(f: any): string | null {
  const templateId = String(f.templateId ?? f.template_id ?? "").toLowerCase();
  if (templateId.includes("storage")) return "storage";
  if (templateId.includes("registry")) return "registry";
  if (templateId.includes("serverless")) return "serverless";
  if (templateId.includes("cdn")) return "cdn";

  const title = String(f.title || "").toLowerCase();
  if (title.includes("bucket") || title.includes("blob") || title.includes("storage")) return "storage";
  if (title.includes("registry") || title.includes("container") || title.includes("docker")) return "registry";
  if (title.includes("serverless") || title.includes("function") || title.includes("lambda") || title.includes("cloud run")) return "serverless";
  if (title.includes("cdn") || title.includes("origin")) return "cdn";

  return null;
}

/** Returns the appropriate icon component for a cloud sub-type */
function CloudSubIcon({ subType, className }: { subType: string | null; className?: string }) {
  switch (subType) {
    case "storage":    return <Database className={cn("w-3.5 h-3.5 text-sky-400 shrink-0", className)} />;
    case "registry":   return <Box className={cn("w-3.5 h-3.5 text-violet-400 shrink-0", className)} />;
    case "serverless": return <Cpu className={cn("w-3.5 h-3.5 text-amber-400 shrink-0", className)} />;
    case "cdn":        return <Shield className={cn("w-3.5 h-3.5 text-teal-400 shrink-0", className)} />;
    default:           return <Cloud className={cn("w-3.5 h-3.5 text-sky-400 shrink-0", className)} />;
  }
}

const CATEGORY_CONFIG: Record<string, { label: string; color: string }> = {
  ssl:              { label: "SSL/TLS",    color: "bg-purple-500/15 text-purple-300 border-purple-500/30" },
  ports:            { label: "Ports",      color: "bg-blue-500/15 text-blue-300 border-blue-500/30" },
  headers:          { label: "Headers",    color: "bg-amber-500/15 text-amber-300 border-amber-500/30" },
  cve:              { label: "CVE",        color: "bg-red-500/15 text-red-300 border-red-500/30" },
  dns:              { label: "DNS",        color: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30" },
  tech:             { label: "Tech",       color: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" },
  technology:       { label: "Tech",       color: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" },
  api:              { label: "API",        color: "bg-rose-500/15 text-rose-300 border-rose-500/30" },
  exposure:         { label: "Exposure",   color: "bg-orange-500/15 text-orange-300 border-orange-500/30" },
  misconfiguration: { label: "Misconfig",  color: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30" },
  vulnerability:    { label: "Vuln",       color: "bg-red-500/15 text-red-300 border-red-500/30" },
  score:            { label: "Score",      color: "bg-indigo-500/15 text-indigo-300 border-indigo-500/30" },
  cloud:            { label: "Cloud",      color: "bg-sky-500/15 text-sky-300 border-sky-500/30" },
  other:            { label: "Other",      color: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30" },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-300 border-red-500/30",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-300 border-blue-500/30",
  info: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
};

const STATUS_TABS: { key: StatusKey; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { key: "open",          label: "Open",          icon: AlertTriangle },
  { key: "in_progress",   label: "In Progress",   icon: Clock },
  { key: "accepted_risk", label: "Accepted Risk",  icon: ShieldCheck },
  { key: "suppressed",    label: "Suppressed",     icon: EyeOff },
  { key: "resolved",      label: "Resolved",       icon: CheckCircle2 },
  { key: "all",           label: "All",            icon: Eye },
];

const STATUS_BADGE_CONFIG: Record<string, { label: string; class: string }> = {
  open:          { label: "OPEN",          class: "text-red-300 bg-red-500/10 border-red-500/20" },
  in_progress:   { label: "IN PROGRESS",   class: "text-blue-300 bg-blue-500/10 border-blue-500/20" },
  accepted_risk: { label: "ACCEPTED RISK", class: "text-amber-300 bg-amber-500/10 border-amber-500/20" },
  suppressed:    { label: "SUPPRESSED",    class: "text-zinc-300 bg-zinc-500/10 border-zinc-500/20" },
  resolved:      { label: "RESOLVED",      class: "text-emerald-300 bg-emerald-500/10 border-emerald-500/20" },
};

// Bulk action options — what you can do with selected findings
const BULK_STATUS_OPTIONS: { status: string; label: string; icon: React.ComponentType<{ className?: string }>; color: string }[] = [
  { status: "in_progress",   label: "In Progress",   icon: Clock,        color: "text-blue-400 border-blue-500/30 hover:bg-blue-500/10" },
  { status: "resolved",      label: "Resolve",       icon: CheckCircle2, color: "text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/10" },
  { status: "accepted_risk", label: "Accept Risk",   icon: ShieldCheck,  color: "text-amber-400 border-amber-500/30 hover:bg-amber-500/10" },
  { status: "suppressed",    label: "Suppress",      icon: EyeOff,       color: "text-zinc-400 border-zinc-500/30 hover:bg-zinc-500/10" },
  { status: "open",          label: "Reopen",        icon: RotateCcw,    color: "text-red-400 border-red-500/30 hover:bg-red-500/10" },
];

export default function FindingsPage() {
  const { canDo } = useOrg();
  const canEdit = canDo("edit_findings");
  const canExport = canDo("export_scan_results");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const [groups, setGroups] = useState<AssetGroup[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>({});
  const [categoryCounts, setCategoryCounts] = useState<Record<string, number>>({});
  const [statusCounts, setStatusCounts] = useState<Record<string, number>>({});

  // Filters
  const [groupFilter, setGroupFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusKey>("open");
  const [page, setPage] = useState(1);
  const perPage = 50;

  // Selection for bulk actions
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Detail dialog
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [selected, setSelected] = useState<Finding | null>(null);

  // Bulk action dialog
  const [bulkActionOpen, setBulkActionOpen] = useState(false);
  const [bulkActionStatus, setBulkActionStatus] = useState<string>("");
  const [bulkActionNotes, setBulkActionNotes] = useState("");
  const [actionLoading, setActionLoading] = useState(false);

  // Debounced search
  const [debouncedSearch, setDebouncedSearch] = useState("");
  useEffect(() => {
    const t = setTimeout(() => { setDebouncedSearch(searchQuery); setPage(1); }, 300);
    return () => clearTimeout(t);
  }, [searchQuery]);

  // Reset page on filter change
  useEffect(() => { setPage(1); }, [groupFilter, severityFilter, categoryFilter, statusFilter]);

  // Auto-clear banner
  useEffect(() => {
    if (banner) { const t = setTimeout(() => setBanner(null), 4000); return () => clearTimeout(t); }
  }, [banner]);

  // ────────────────────────────────────────────
  // Data Loading
  // ────────────────────────────────────────────

  const loadFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (severityFilter !== "all") params.set("severity", severityFilter);
      if (categoryFilter !== "all") params.set("category", categoryFilter);
      if (groupFilter !== "all") params.set("group_id", groupFilter);
      if (debouncedSearch) params.set("q", debouncedSearch);
      params.set("status", statusFilter);
      params.set("page", String(page));
      params.set("per_page", String(perPage));

      const [g, data] = await Promise.all([
        groups.length ? Promise.resolve(groups) : getGroups(),
        apiFetch<any>(`/findings?${params.toString()}`),
      ]);

      setGroups(g);
      setFindings(data.findings || data);
      setTotal(data.total ?? (data.findings || data).length);
      setSeverityCounts(data.severityCounts || {});
      setCategoryCounts(data.categoryCounts || {});
      setStatusCounts(data.statusCounts || {});
      setSelectedIds(new Set());
    } catch (e: any) {
      setError(e?.message || "Failed to load findings");
    } finally {
      setLoading(false);
    }
  }, [severityFilter, categoryFilter, groupFilter, debouncedSearch, statusFilter, page]);

  useEffect(() => { loadFindings(); }, [loadFindings]);

  // Total category count for the "All" button
  const totalCategoryCount = useMemo(() => {
    return Object.values(categoryCounts).reduce((a, b) => a + b, 0);
  }, [categoryCounts]);

  // ────────────────────────────────────────────
  // Selection
  // ────────────────────────────────────────────

  const allSelected = findings.length > 0 && findings.every((f: any) => selectedIds.has(String(f.id)));
  const someSelected = selectedIds.size > 0;

  function toggleSelect(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    if (allSelected) setSelectedIds(new Set());
    else setSelectedIds(new Set(findings.map((f: any) => String(f.id))));
  }

  // ────────────────────────────────────────────
  // Status Change (single finding via dialog)
  // ────────────────────────────────────────────

  async function handleStatusChange(id: string, newStatus: string, notes?: string) {
    try {
      const updated = await apiFetch<any>(`/findings/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ status: newStatus, notes }),
      });
      setFindings((prev) => prev.map((x: any) => (String(x.id) === String(id) ? updated : x)));
      setSelected((prev: any) => (prev && String(prev.id) === String(id) ? updated : prev));
      const label = STATUS_BADGE_CONFIG[newStatus]?.label || newStatus;
      setBanner({ kind: "ok", text: `Finding set to ${label.toLowerCase()}` });
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to update status" });
    }
  }

  // ────────────────────────────────────────────
  // Bulk Status Change
  // ────────────────────────────────────────────

  function openBulkAction(status: string) {
    setBulkActionStatus(status);
    setBulkActionNotes("");
    setBulkActionOpen(true);
  }

  async function handleBulkStatus() {
    if (selectedIds.size === 0 || !bulkActionStatus) return;

    // Validate accepted_risk requires notes
    if (bulkActionStatus === "accepted_risk" && !bulkActionNotes.trim()) {
      setBanner({ kind: "err", text: "Justification is required when accepting risk" });
      return;
    }

    try {
      setActionLoading(true);
      await apiFetch<any>("/findings/bulk-status", {
        method: "POST",
        body: JSON.stringify({
          ids: Array.from(selectedIds),
          status: bulkActionStatus,
          notes: bulkActionNotes.trim() || undefined,
        }),
      });
      const label = STATUS_BADGE_CONFIG[bulkActionStatus]?.label || bulkActionStatus;
      setBanner({ kind: "ok", text: `${selectedIds.size} finding(s) set to ${label.toLowerCase()}` });
      setBulkActionOpen(false);
      setBulkActionNotes("");
      setBulkActionStatus("");
      await loadFindings();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Bulk action failed" });
    } finally {
      setActionLoading(false);
    }
  }

  // ────────────────────────────────────────────
  // Export
  // ────────────────────────────────────────────

  async function handleExport() {
    const params = new URLSearchParams();
    if (severityFilter !== "all") params.set("severity", severityFilter);
    if (categoryFilter !== "all") params.set("category", categoryFilter);
    if (groupFilter !== "all") params.set("group_id", groupFilter);
    if (debouncedSearch) params.set("q", debouncedSearch);
    params.set("status", statusFilter);

    try {
      const token = typeof window !== "undefined" ? localStorage.getItem("asm_access_token") : null;
      const baseUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";
      const resp = await fetch(`${baseUrl}/findings/export?${params.toString()}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!resp.ok) throw new Error("Export failed");
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `findings-export-${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      setBanner({ kind: "ok", text: "Export downloaded" });
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Export failed" });
    }
  }

  const totalPages = Math.ceil(total / perPage);

  // ────────────────────────────────────────────
  // Render
  // ────────────────────────────────────────────

  // Full-page skeleton on initial load (no data yet)
  if (loading && findings.length === 0) return <FindingsPageSkeleton />;

  return (
    <div className="flex-1 bg-background overflow-auto">
      <div className="p-8 space-y-5">

        {/* ── Header ── */}
        <div className="flex items-start justify-between gap-6">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className="w-6 h-6 text-primary" />
              <h1 className="text-2xl font-semibold text-foreground">Exposure Findings</h1>
            </div>
            <p className="text-muted-foreground">
              {total} finding{total === 1 ? "" : "s"} detected
            </p>
          </div>
          <div className="flex items-center gap-2">
            {canExport && (
              <Button variant="outline" onClick={handleExport} className="gap-2">
                <Download className="w-4 h-4" />Export CSV
              </Button>
            )}
          </div>
        </div>

        {/* ── Banner ── */}
        {banner && (
          <div className={cn(
            "rounded-xl border px-4 py-2.5 text-sm flex items-center justify-between",
            banner.kind === "ok"
              ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]"
              : "border-red-500/30 bg-red-500/10 text-red-200",
          )}>
            <span>{banner.text}</span>
            <button onClick={() => setBanner(null)} className="hover:opacity-70">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}
        {error && !banner && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-sm text-red-200">
            {error}
          </div>
        )}

        {/* ── Status Tabs ── */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center bg-card border border-border rounded-lg overflow-hidden">
            {STATUS_TABS.map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => setStatusFilter(key)}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors",
                  statusFilter === key
                    ? "bg-primary/15 text-primary"
                    : "text-muted-foreground hover:text-foreground hover:bg-accent/30",
                )}
              >
                <Icon className="w-3.5 h-3.5" />
                {label}
                {statusCounts[key] !== undefined && (
                  <span className="text-[10px] opacity-60">({statusCounts[key]})</span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* ── Severity Quick Filters ── */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setSeverityFilter("all")}
            className={cn(
              "px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all",
              severityFilter === "all"
                ? "bg-primary/15 text-primary border-primary/30"
                : "bg-card text-muted-foreground border-border hover:border-primary/30",
            )}
          >
            All ({Object.values(severityCounts).reduce((a, b) => a + b, 0) || total})
          </button>
          {(["critical", "high", "medium", "low", "info"] as SeverityKey[]).map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={cn(
                "px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all capitalize",
                severityFilter === sev
                  ? SEVERITY_COLORS[sev]
                  : "bg-card text-muted-foreground border-border hover:border-primary/30",
              )}
            >
              {sev} ({severityCounts[sev] || 0})
            </button>
          ))}
        </div>

        {/* ── Category Quick Filters ── */}
        {(Object.keys(categoryCounts).length > 0 || categoryFilter !== "all") && (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-muted-foreground mr-1">
              <Tag className="w-3.5 h-3.5 inline-block mr-1" />Category:
            </span>
            <button
              onClick={() => setCategoryFilter("all")}
              className={cn(
                "px-2.5 py-1 rounded-md border text-xs font-medium transition-all",
                categoryFilter === "all"
                  ? "bg-primary/15 text-primary border-primary/30"
                  : "bg-card text-muted-foreground border-border hover:border-primary/30",
              )}
            >
              All ({totalCategoryCount})
            </button>
            {Object.entries(categoryCounts)
              .sort(([, a], [, b]) => b - a)
              .map(([cat, count]) => {
                const cfg = CATEGORY_CONFIG[cat] || CATEGORY_CONFIG.other;
                return (
                  <button
                    key={cat}
                    onClick={() => setCategoryFilter(cat)}
                    className={cn(
                      "px-2.5 py-1 rounded-md border text-xs font-medium transition-all",
                      categoryFilter === cat
                        ? cfg.color
                        : "bg-card text-muted-foreground border-border hover:border-primary/30",
                    )}
                  >
                    {cat === "cloud" && <Cloud className="w-3 h-3 inline-block mr-1 -mt-0.5" />}
                    {cfg.label} ({count})
                  </button>
                );
              })}
          </div>
        )}

        {/* ── Search + Group Filter ── */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative w-full sm:max-w-md">
            <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search findings by title or description\u2026"
              className="pl-9"
            />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <select
              value={groupFilter}
              onChange={(e) => setGroupFilter(e.target.value)}
              className="h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground outline-none focus:ring-2 focus:ring-primary/40"
            >
              <option value="all">All Groups</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>{g.name}</option>
              ))}
            </select>
          </div>
        </div>

        {/* ── Bulk Actions Bar ── */}
        {canEdit && someSelected && (
          <div className="flex items-center gap-3 bg-primary/5 border border-primary/20 rounded-xl px-4 py-2.5">
            <span className="text-sm font-medium text-foreground">
              {selectedIds.size} selected
            </span>
            <div className="flex-1" />
            {BULK_STATUS_OPTIONS.map(({ status, label, icon: Icon, color }) => (
              <Button
                key={status}
                size="sm"
                variant="outline"
                onClick={() => openBulkAction(status)}
                disabled={actionLoading}
                className={`gap-1.5 ${color}`}
              >
                <Icon className="w-3.5 h-3.5" />{label}
              </Button>
            ))}
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setSelectedIds(new Set())}
              className="text-muted-foreground"
            >
              <X className="w-4 h-4" />
            </Button>
          </div>
        )}

        {/* ── Table ── */}
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-muted/30 border-b border-border">
              <tr>
                {canEdit && (
                  <th className="w-[50px] px-4 py-3">
                    <button onClick={toggleSelectAll} className="text-muted-foreground hover:text-foreground">
                      {allSelected
                        ? <CheckSquare className="w-4 h-4 text-primary" />
                        : <Square className="w-4 h-4" />}
                    </button>
                  </th>
                )}
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[100px]">Severity</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Finding</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[110px]">Category</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[180px]">Asset</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[140px]">Group</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[150px]">Detected</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {/* Inline loading indicator for filter/page changes (data already loaded once) */}
              {loading && findings.length > 0 && (
                <tr>
                  <td colSpan={canEdit ? 7 : 6} className="px-4 py-2 text-center">
                    <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />Updating…
                    </div>
                  </td>
                </tr>
              )}
              {findings.map((f: any) => {
                const id = String(f.id);
                const sev = getSeverity(f);
                const cat = getCategory(f);
                const catCfg = CATEGORY_CONFIG[cat] || CATEGORY_CONFIG.other;
                const title = f.title || f.finding || f.name || "Finding";
                const assetValue = f.assetValue ?? f.asset_value ?? "\u2014";
                const gid = String(f.groupId ?? f.group_id ?? "");
                const gname = f.groupName ?? "\u2014";
                const detectedAt = f.detectedAt ?? f.detected_at ?? f.createdAt ?? null;
                const status: string = f.status || "open";
                const isSelected = selectedIds.has(id);
                const hasRemediation = Boolean(f.remediation || f.details?._remediation);
                const statusBadge = STATUS_BADGE_CONFIG[status];
                const isCloud = cat === "cloud";
                const cloudSub = isCloud ? getCloudSubType(f) : null;

                return (
                  <tr
                    key={id}
                    className={cn(
                      "hover:bg-accent/30 transition-colors cursor-pointer",
                      (status !== "open" && status !== "in_progress") && "opacity-60",
                    )}
                    onClick={() => { setSelected(f); setDetailsOpen(true); }}
                  >
                    {canEdit && (
                      <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                        <button onClick={() => toggleSelect(id)} className="text-muted-foreground hover:text-foreground">
                          {isSelected
                            ? <CheckSquare className="w-4 h-4 text-primary" />
                            : <Square className="w-4 h-4" />}
                        </button>
                      </td>
                    )}
                    <td className="px-4 py-3">
                      <SeverityBadge severity={sev} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {/* Cloud sub-type icon */}
                        {isCloud && <CloudSubIcon subType={cloudSub} />}
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-foreground font-medium truncate" title={title}>
                              {title}
                            </span>
                            {statusBadge && status !== "open" && (
                              <span className={`text-[10px] px-1.5 py-0.5 rounded border ${statusBadge.class}`}>
                                {statusBadge.label}
                              </span>
                            )}
                            {hasRemediation && (
                              <span title="Remediation available">
                                <Wrench className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                              </span>
                            )}
                          </div>
                          {f.summary && (
                            <div className="text-xs text-muted-foreground mt-0.5 truncate">
                              {f.summary}
                            </div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium ${catCfg.color}`}>
                        {isCloud && <Cloud className="w-3 h-3" />}
                        {catCfg.label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-primary font-mono text-sm truncate block" title={assetValue}>
                        {assetValue}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {gid ? (
                        <Link
                          href={`/groups/${gid}`}
                          className="text-primary text-sm hover:underline truncate block"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {gname}
                        </Link>
                      ) : (
                        <span className="text-muted-foreground">{"\u2014"}</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {formatDate(detectedAt)}
                    </td>
                  </tr>
                );
              })}
              {findings.length === 0 && !loading && (
                <tr>
                  <td
                    colSpan={canEdit ? 7 : 6}
                    className="px-4 py-12 text-center text-muted-foreground"
                  >
                    {debouncedSearch || severityFilter !== "all" || groupFilter !== "all" || categoryFilter !== "all"
                      ? "No findings match your filters."
                      : statusFilter === "resolved"
                      ? "No resolved findings yet. Resolve findings to track remediation progress."
                      : statusFilter === "suppressed"
                      ? "No suppressed findings."
                      : statusFilter === "in_progress"
                      ? "No findings in progress. Start working on findings to track them here."
                      : statusFilter === "accepted_risk"
                      ? "No accepted risk findings. Accept risk on findings with justification."
                      : "No findings detected yet. Run a scan to discover exposures."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* ── Pagination ── */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>Page {page} of {totalPages} ({total} findings)</span>
            <div className="flex items-center gap-2">
              <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                <ChevronLeft className="w-4 h-4" />Prev
              </Button>
              <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                Next<ChevronRight className="w-4 h-4" />
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* ── Finding Details Dialog ── */}
      <FindingDetailsDialog
        open={detailsOpen}
        onOpenChange={setDetailsOpen}
        finding={selected as any}
        onStatusChange={canEdit ? handleStatusChange : undefined}
      />

      {/* ── Bulk Status Action Dialog ── */}
      <Dialog open={bulkActionOpen} onOpenChange={setBulkActionOpen}>
        <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {(() => {
                const opt = BULK_STATUS_OPTIONS.find((o) => o.status === bulkActionStatus);
                if (!opt) return null;
                const Icon = opt.icon;
                return <Icon className="w-5 h-5 text-primary" />;
              })()}
              {bulkActionStatus === "open"
                ? `Reopen ${selectedIds.size} Finding${selectedIds.size !== 1 ? "s" : ""}`
                : `Set ${selectedIds.size} Finding${selectedIds.size !== 1 ? "s" : ""} to ${STATUS_BADGE_CONFIG[bulkActionStatus]?.label || bulkActionStatus}`}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <p className="text-sm text-muted-foreground">
              {bulkActionStatus === "accepted_risk"
                ? "Accepted risk findings are acknowledged but won\u2019t count toward your exposure score. Justification is required."
                : bulkActionStatus === "suppressed"
                ? "Suppressed findings are hidden from default views and don\u2019t count toward risk. You can unsuppress them anytime."
                : bulkActionStatus === "resolved"
                ? "Resolved findings are marked as remediated and won\u2019t count toward your exposure score."
                : bulkActionStatus === "in_progress"
                ? "Mark these findings as being actively worked on."
                : "Reopen these findings to make them count toward your exposure score again."}
            </p>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-foreground block">
                {bulkActionStatus === "accepted_risk" ? "Justification (required)" : "Notes (optional)"}
              </label>
              <Input
                placeholder={
                  bulkActionStatus === "accepted_risk"
                    ? "e.g., Risk accepted per security review\u2026"
                    : bulkActionStatus === "suppressed"
                    ? "e.g., False positive, compensating control\u2026"
                    : "Add a note\u2026"
                }
                value={bulkActionNotes}
                onChange={(e) => setBulkActionNotes(e.target.value)}
              />
            </div>
            <div className="flex gap-3 justify-end pt-2">
              <Button
                variant="outline"
                onClick={() => setBulkActionOpen(false)}
                className="border-border text-foreground hover:bg-accent"
              >
                Cancel
              </Button>
              <Button
                onClick={handleBulkStatus}
                disabled={actionLoading || (bulkActionStatus === "accepted_risk" && !bulkActionNotes.trim())}
                className="bg-primary hover:bg-primary/90"
              >
                {actionLoading ? "Updating\u2026" : "Confirm"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}