"use client";

import { useEffect, useMemo, useState, useCallback, useRef } from "react";
import Link from "next/link";
import { useSearchParams, useRouter } from "next/navigation";
import {
  AlertTriangle, Search, Loader2, Download, EyeOff, Eye,
  CheckSquare, Square, X, ChevronDown, ChevronLeft, ChevronRight,
  Tag, Wrench, CheckCircle2, RotateCcw, Clock, ShieldCheck,
  AlertCircle, Cloud, Database, Box, Cpu, Shield, Siren, RefreshCw,
} from "lucide-react";

import type { AssetGroup, Finding } from "../../types";
import { getGroups, getAllAssets, apiFetch, escalateFinding, bulkEscalateFindings, API_BASE_URL } from "../../lib/api";
import { getAccessToken } from "../../lib/auth";
import { useOrg } from "../contexts/OrgContext";
import ProvenanceTag, { type Provenance } from "../_components/ProvenanceTag";
import { usePreferences } from "../../lib/usePreferences";

import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "../../ui/dialog";
import { SeverityBadge } from "../../SeverityBadge";
import { FindingDetailsDialog } from "../../FindingDetailsDialog";
import { FindingsPageSkeleton } from "../../ui/skeleton";
import { PageHint, PageHintToggle } from "../../ui/PageHint";

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

/** Relative time for recent moments, absolute (Mon DD) for older. The
 *  full timestamp is available on hover via title attribute, so power
 *  users keep precision while the common-case reader sees "2h ago". */
function formatRelativeOrDate(d?: any): { display: string; full: string } {
  if (!d) return { display: "\u2014", full: "" };
  let dt: Date;
  if (typeof d === "string" && !d.endsWith("Z") && !d.includes("+")) dt = new Date(d + "Z");
  else dt = d instanceof Date ? d : new Date(d);
  if (isNaN(dt.getTime())) return { display: "\u2014", full: "" };
  const sec = Math.floor((Date.now() - dt.getTime()) / 1000);
  const full = dt.toLocaleString();
  if (sec < 60) return { display: "just now", full };
  if (sec < 3600) return { display: `${Math.floor(sec / 60)}m ago`, full };
  if (sec < 86400) return { display: `${Math.floor(sec / 3600)}h ago`, full };
  const days = Math.floor(sec / 86400);
  if (days < 7) return { display: `${days}d ago`, full };
  // 7d+ \u2192 absolute date so the eye can scan dates instead of doing math
  return { display: dt.toLocaleDateString(undefined, { month: "short", day: "numeric" }), full };
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

const STATUS_BADGE_CONFIG: Record<string, { label: string; class: string; dot: string }> = {
  open:          { label: "Open",          class: "text-red-300 bg-red-500/10 border-red-500/20",          dot: "bg-red-400" },
  in_progress:   { label: "In progress",   class: "text-blue-300 bg-blue-500/10 border-blue-500/20",       dot: "bg-blue-400 animate-pulse" },
  accepted_risk: { label: "Accepted risk", class: "text-amber-300 bg-amber-500/10 border-amber-500/20",    dot: "bg-amber-400" },
  suppressed:    { label: "Suppressed",    class: "text-zinc-300 bg-zinc-500/10 border-zinc-500/20",       dot: "bg-zinc-400" },
  resolved:      { label: "Resolved",      class: "text-emerald-300 bg-emerald-500/10 border-emerald-500/20", dot: "bg-emerald-400" },
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
  const { prefs, update: updatePrefs } = usePreferences();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  // Resizable details panel — width is a percentage (lg+ only). Bounded to
  // 30..70 so neither column collapses. Persisted in localStorage.
  const PANEL_MIN = 30;
  const PANEL_MAX = 70;
  const PANEL_DEFAULT = 45;
  const [panelWidth, setPanelWidth] = useState<number>(() => {
    if (typeof window === "undefined") return PANEL_DEFAULT;
    const saved = parseFloat(localStorage.getItem("findings-panel-width") || "");
    if (Number.isFinite(saved)) {
      return Math.max(PANEL_MIN, Math.min(PANEL_MAX, saved));
    }
    return PANEL_DEFAULT;
  });
  const splitContainerRef = useRef<HTMLDivElement>(null);
  const draggingRef = useRef(false);

  function startResize(e: React.MouseEvent) {
    e.preventDefault();
    draggingRef.current = true;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  }

  useEffect(() => {
    function onMove(e: MouseEvent) {
      if (!draggingRef.current || !splitContainerRef.current) return;
      const rect = splitContainerRef.current.getBoundingClientRect();
      const next = ((rect.right - e.clientX) / rect.width) * 100;
      const clamped = Math.max(PANEL_MIN, Math.min(PANEL_MAX, next));
      setPanelWidth(clamped);
    }
    function onUp() {
      if (!draggingRef.current) return;
      draggingRef.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      try {
        localStorage.setItem("findings-panel-width", String(panelWidth));
      } catch {}
    }
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [panelWidth]);

  const [groups, setGroups] = useState<AssetGroup[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>({});
  const [categoryCounts, setCategoryCounts] = useState<Record<string, number>>({});
  const [statusCounts, setStatusCounts] = useState<Record<string, number>>({});

  // Filters
  const [groupFilter, setGroupFilter] = useState("all");
  const [assetFilter, setAssetFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>("all");
  const [frameworkFilter, setFrameworkFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusKey>("open");
  // Default sort: most recently detected first. The previous default was
  // severity-first, but users hitting this page after a fresh scan want
  // to see what just landed, not re-litigate yesterday's criticals.
  const [sortBy, setSortBy] = useState<"recent" | "severity" | "epss">("recent");
  // Group-by — purely a display concern; filters still apply globally.
  // "none" keeps the original flat table; "asset" / "category" insert
  // section header rows between findings.
  const [groupBy, setGroupBy] = useState<"none" | "asset" | "category">("none");
  const [sinceFilter, setSinceFilter] = useState<"all" | "24h" | "7d" | "30d" | "90d">("all");
  // Provenance filter — mirrors the pill priorities (resolved_before > new
  // > seen_before). Independent of the showProvenanceTags display pref so
  // a user can filter to "new only" without rendering pills on every row.
  const [provenanceFilter, setProvenanceFilter] = useState<"all" | "new" | "seen_before" | "resolved_before">("all");
  // Threat-intel filter — show only findings whose CVE is on CISA's KEV
  // catalog (actively exploited in the wild). Binary toggle, not a select.
  const [kevOnlyFilter, setKevOnlyFilter] = useState<boolean>(false);
  const [page, setPage] = useState(1);
  const perPage = 50;

  // Selection for bulk actions
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Detail dialog
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [selected, setSelected] = useState<Finding | null>(null);

  // Deep-link: open the dialog for ?focus=<findingId> on mount and keep
  // the URL in sync so customers can copy/share a link to a specific
  // finding. The findings list is paginated; if the focused finding isn't
  // in the current page yet, we leave the param in the URL and let it
  // resolve once that page loads (the dialog will open then).
  const searchParams = useSearchParams();
  const router = useRouter();
  const focusId = searchParams?.get("focus") || null;
  // Tracks whether we've already auto-opened from the URL — prevents the
  // dialog from re-opening every time the findings list refreshes.
  const autoOpenedRef = useRef<string | null>(null);
  useEffect(() => {
    if (!focusId || autoOpenedRef.current === focusId) return;
    const match = findings.find((f: any) => String(f.id) === focusId);
    if (match) {
      autoOpenedRef.current = focusId;
      setSelected(match);
      setDetailsOpen(true);
    }
  }, [focusId, findings]);

  function setFocusInUrl(id: string | null) {
    if (typeof window === "undefined") return;
    const url = new URL(window.location.href);
    if (id) url.searchParams.set("focus", id);
    else url.searchParams.delete("focus");
    // replaceState avoids a history entry per open/close — feels like a
    // small navigation cost otherwise.
    window.history.replaceState({}, "", url.toString());
  }

  // Bulk status-change dialog
  const [bulkActionOpen, setBulkActionOpen] = useState(false);
  const [bulkActionStatus, setBulkActionStatus] = useState<string>("");
  const [bulkActionNotes, setBulkActionNotes] = useState("");
  const [actionLoading, setActionLoading] = useState(false);

  // Bulk escalate-to-alert dialog
  const [bulkEscalateOpen, setBulkEscalateOpen] = useState(false);
  const [bulkEscalateNote, setBulkEscalateNote] = useState("");
  const [bulkEscalateAck, setBulkEscalateAck] = useState(true);
  const [bulkEscalating, setBulkEscalating] = useState(false);

  // Debounced search
  const [debouncedSearch, setDebouncedSearch] = useState("");
  useEffect(() => {
    const t = setTimeout(() => { setDebouncedSearch(searchQuery); setPage(1); }, 300);
    return () => clearTimeout(t);
  }, [searchQuery]);

  // Reset page on filter change
  useEffect(() => { setPage(1); }, [groupFilter, assetFilter, severityFilter, categoryFilter, frameworkFilter, statusFilter, sortBy, sinceFilter, provenanceFilter, kevOnlyFilter]);

  // Asset list scoped by selected group (when one is chosen) so the
  // dropdown only shows assets the group filter would permit. Resets
  // assetFilter to "all" when the user picks a group that excludes the
  // currently-selected asset, so the UI doesn't end up in a state with
  // a hidden asset still constraining the query.
  const filteredAssets = useMemo(() => {
    if (groupFilter === "all") return assets;
    return assets.filter(
      (a) => String(a.groupId ?? a.group_id ?? "") === groupFilter,
    );
  }, [assets, groupFilter]);
  useEffect(() => {
    if (assetFilter === "all") return;
    const stillVisible = filteredAssets.some((a) => String(a.id) === assetFilter);
    if (!stillVisible) setAssetFilter("all");
  }, [filteredAssets, assetFilter]);

  // Auto-clear banner
  useEffect(() => {
    if (banner) { const t = setTimeout(() => setBanner(null), 4000); return () => clearTimeout(t); }
  }, [banner]);

  const loadFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (severityFilter !== "all") params.set("severity", severityFilter);
      if (categoryFilter !== "all") params.set("customer_category", categoryFilter);
      if (frameworkFilter !== "all") params.set("framework", frameworkFilter);
      if (groupFilter !== "all") params.set("group_id", groupFilter);
      if (assetFilter !== "all") params.set("asset_id", assetFilter);
      if (sortBy !== "recent") params.set("sort", sortBy);
      if (sinceFilter !== "all") params.set("since", sinceFilter);
      if (provenanceFilter !== "all") params.set("provenance", provenanceFilter);
      if (kevOnlyFilter) params.set("kev", "1");
      if (debouncedSearch) params.set("q", debouncedSearch);
      params.set("status", statusFilter);
      params.set("page", String(page));
      params.set("per_page", String(perPage));

      const [g, a, data] = await Promise.all([
        groups.length ? Promise.resolve(groups) : getGroups(),
        assets.length ? Promise.resolve(assets) : getAllAssets(),
        apiFetch<any>(`/findings?${params.toString()}`),
      ]);

      setGroups(g);
      setAssets(a || []);
      setFindings(data.findings || data);
      setTotal(data.total ?? (data.findings || data).length);
      setSeverityCounts(data.severityCounts || {});
      setCategoryCounts(data.customerCategoryCounts || {});
      setStatusCounts(data.statusCounts || {});
      setSelectedIds(new Set());
    } catch (e: any) {
      setError(e?.message || "Failed to load findings");
    } finally {
      setLoading(false);
    }
  }, [severityFilter, categoryFilter, frameworkFilter, groupFilter, assetFilter, sortBy, sinceFilter, provenanceFilter, kevOnlyFilter, debouncedSearch, statusFilter, page]);

  useEffect(() => { loadFindings(); }, [loadFindings]);

  const totalCategoryCount = useMemo(() => {
    return Object.values(categoryCounts).reduce((a, b) => a + b, 0);
  }, [categoryCounts]);

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

  async function handleBulkEscalate() {
    if (selectedIds.size === 0) return;
    setBulkEscalating(true);
    try {
      const res = await bulkEscalateFindings({
        ids: Array.from(selectedIds),
        note: bulkEscalateNote.trim() || undefined,
        acknowledge: bulkEscalateAck,
      });
      setBanner({ kind: res.escalated > 0 ? "ok" : "err", text: res.message });
      setBulkEscalateOpen(false);
      setBulkEscalateNote("");
      setSelectedIds(new Set());
      await loadFindings();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Bulk escalate failed" });
    } finally {
      setBulkEscalating(false);
    }
  }

  async function handleExport() {
    const params = new URLSearchParams();
    if (severityFilter !== "all") params.set("severity", severityFilter);
    if (categoryFilter !== "all") params.set("customer_category", categoryFilter);
    if (frameworkFilter !== "all") params.set("framework", frameworkFilter);
    if (groupFilter !== "all") params.set("group_id", groupFilter);
    if (assetFilter !== "all") params.set("asset_id", assetFilter);
    if (sortBy !== "recent") params.set("sort", sortBy);
    if (sinceFilter !== "all") params.set("since", sinceFilter);
    if (debouncedSearch) params.set("q", debouncedSearch);
    params.set("status", statusFilter);

    try {
      const token = getAccessToken();
      const resp = await fetch(`${API_BASE_URL}/findings/export?${params.toString()}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!resp.ok) {
        const txt = await resp.text().catch(() => "");
        throw new Error(txt || `Export failed (${resp.status})`);
      }
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
              <PageHintToggle pageKey="findings" />
            </div>
            <p className="text-muted-foreground">
              {total} finding{total === 1 ? "" : "s"} detected
            </p>
          </div>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-xs text-white/65 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={prefs.showProvenanceTags}
                onChange={(e) => updatePrefs({ showProvenanceTags: e.target.checked })}
              />
              Show recurrence tags
            </label>
            {canExport && (
              <Button variant="outline" onClick={handleExport} className="gap-2">
                <Download className="w-4 h-4" />Export CSV
              </Button>
            )}
          </div>
        </div>

        <PageHint
          pageKey="findings"
          title="Findings"
          body="Vulnerabilities and misconfigurations across your assets. Triage by severity, filter by compliance framework, mark resolved or accepted."
        />

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

        {/* ── Dashboard Summary — compact chip row replaces the previous
              6-card grid. Same data, ~1/3 the vertical space; clicking a
              chip applies that filter. */}
        <div className="flex items-center gap-2 flex-wrap">
          {[
            { key: "total",    label: "Total",    value: total,                          icon: AlertTriangle, color: "text-foreground",  activeBg: "bg-foreground/10 border-foreground/30",  onClick: () => { setStatusFilter("all"); setSeverityFilter("all"); }, isActive: statusFilter === "all" && severityFilter === "all" },
            { key: "open",     label: "Open",     value: statusCounts.open || 0,         icon: AlertCircle,   color: "text-red-300",     activeBg: "bg-red-500/10 border-red-500/40",        onClick: () => setStatusFilter("open"), isActive: statusFilter === "open" && severityFilter === "all" },
            { key: "critical", label: "Critical", value: severityCounts.critical || 0,   icon: AlertCircle,   color: "text-red-300",     activeBg: "bg-red-500/10 border-red-500/40",        onClick: () => { setSeverityFilter("critical"); setStatusFilter("open"); }, isActive: severityFilter === "critical" },
            { key: "high",     label: "High",     value: severityCounts.high || 0,       icon: AlertTriangle, color: "text-orange-300",  activeBg: "bg-orange-500/10 border-orange-500/40",  onClick: () => { setSeverityFilter("high"); setStatusFilter("open"); }, isActive: severityFilter === "high" },
            { key: "medium",   label: "Medium",   value: severityCounts.medium || 0,     icon: AlertTriangle, color: "text-yellow-300",  activeBg: "bg-yellow-500/10 border-yellow-500/40",  onClick: () => { setSeverityFilter("medium"); setStatusFilter("open"); }, isActive: severityFilter === "medium" },
            { key: "resolved", label: "Resolved", value: statusCounts.resolved || 0,     icon: CheckCircle2,  color: "text-emerald-300", activeBg: "bg-emerald-500/10 border-emerald-500/40", onClick: () => setStatusFilter("resolved"), isActive: statusFilter === "resolved" },
          ].map(({ key, label, value, icon: Icon, color, activeBg, onClick, isActive }) => (
            <button
              key={key}
              type="button"
              onClick={onClick}
              className={cn(
                "inline-flex items-center gap-2 px-3 py-1.5 rounded-full border text-sm transition-colors",
                isActive ? activeBg : "border-border bg-card/40 hover:bg-card/60",
              )}
            >
              <Icon className={cn("w-3.5 h-3.5", color)} />
              <span className={cn("font-bold tabular-nums", color)}>{value}</span>
              <span className="text-muted-foreground">{label}</span>
            </button>
          ))}
        </div>

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

        {/* ── Category Quick Filters (customer-facing taxonomy) ──
            Mirrors the 5 categories surfaced on the public /coverage
            page plus an "Other" catch-all for anything outside the
            template registry. Counts come from the backend's
            customerCategoryCounts roll-up. */}
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
            {([
              { id: "vulnerabilities",   label: "Vulnerabilities",   color: "bg-red-500/15 text-red-300 border-red-500/30" },
              { id: "service_exposure",  label: "Service Exposure",  color: "bg-amber-500/15 text-amber-300 border-amber-500/30" },
              { id: "data_leaks",        label: "Data Leaks",        color: "bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30" },
              { id: "misconfigurations", label: "Misconfigurations", color: "bg-orange-500/15 text-orange-300 border-orange-500/30" },
              { id: "security_hygiene",  label: "Security Hygiene",  color: "bg-teal-500/15 text-teal-300 border-teal-500/30" },
              { id: "other",             label: "Other",             color: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30" },
            ] as const).map(({ id, label, color }) => {
              const count = categoryCounts[id] || 0;
              if (count === 0 && categoryFilter !== id) return null;
              return (
                <button
                  key={id}
                  onClick={() => setCategoryFilter(id)}
                  className={cn(
                    "px-2.5 py-1 rounded-md border text-xs font-medium transition-all",
                    categoryFilter === id
                      ? color
                      : "bg-card text-muted-foreground border-border hover:border-primary/30",
                  )}
                >
                  {label} ({count})
                </button>
              );
            })}
          </div>
        )}

        {/* ── Search + Group Filter (Framework filter consolidated into this row) ── */}
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
              title="Filter by asset group"
            >
              <option value="all">All Groups</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>{g.name}</option>
              ))}
            </select>
            <select
              value={assetFilter}
              onChange={(e) => setAssetFilter(e.target.value)}
              className="h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground outline-none focus:ring-2 focus:ring-primary/40 max-w-[220px]"
              title="Filter by individual asset"
            >
              <option value="all">All Assets</option>
              {filteredAssets.map((a) => (
                <option key={a.id} value={String(a.id)}>{a.value || a.name || a.id}</option>
              ))}
            </select>
            <select
              value={sinceFilter}
              onChange={(e) => setSinceFilter(e.target.value as typeof sinceFilter)}
              className="h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground outline-none focus:ring-2 focus:ring-primary/40"
              title="Restrict to findings first detected in this window"
            >
              <option value="all">All time</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
              <option value="90d">Last 90 days</option>
            </select>
            <select
              value={provenanceFilter}
              onChange={(e) => setProvenanceFilter(e.target.value as typeof provenanceFilter)}
              className="h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground outline-none focus:ring-2 focus:ring-primary/40"
              title="Filter by finding recurrence"
            >
              <option value="all">All recurrence</option>
              <option value="new">New only</option>
              <option value="seen_before">Seen before</option>
              <option value="resolved_before">Resolved before</option>
            </select>
            {/* KEV — binary toggle, not a select. Active state is visually
                louder (red) than the other filters because "actively
                exploited" is a more urgent signal than category/recurrence. */}
            <button
              type="button"
              onClick={() => setKevOnlyFilter((v) => !v)}
              title="Show only findings whose CVE is on CISA's Known Exploited Vulnerabilities catalog"
              className={cn(
                "h-10 inline-flex items-center gap-1.5 rounded-md border px-3 text-sm outline-none focus:ring-2 focus:ring-primary/40 transition-colors",
                kevOnlyFilter
                  ? "border-red-500/40 bg-red-500/10 text-red-300"
                  : "border-border bg-background text-foreground hover:border-red-500/30 hover:text-red-300",
              )}
            >
              <span className="text-[10px] font-bold uppercase tracking-wider">KEV</span>
              {kevOnlyFilter ? "On" : "Filter"}
            </button>
            <select
              value={frameworkFilter}
              onChange={(e) => setFrameworkFilter(e.target.value)}
              className={cn(
                "h-10 rounded-md border px-3 text-sm outline-none focus:ring-2 focus:ring-primary/40",
                frameworkFilter === "all"
                  ? "border-border bg-background text-foreground"
                  : "border-primary/30 bg-primary/10 text-primary",
              )}
              title="Map findings to a compliance framework (SOC 2 / ISO 27001 via NIST cross-walk)"
            >
              <option value="all">All frameworks</option>
              <option value="owasp_asvs">OWASP ASVS 4.0</option>
              <option value="cis_v8">CIS Controls v8</option>
              <option value="nist_csf">NIST CSF v2.0</option>
              <option value="pci_dss_4">PCI-DSS 4.0</option>
              <option value="soc2">SOC 2 (TSC)</option>
              <option value="iso_27001">ISO/IEC 27001:2022</option>
            </select>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
              className="h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground outline-none focus:ring-2 focus:ring-primary/40"
              title="Sort order"
            >
              <option value="recent">Most recent</option>
              <option value="severity">By severity</option>
              <option value="epss">By exploit likelihood (EPSS)</option>
            </select>
            <select
              value={groupBy}
              onChange={(e) => setGroupBy(e.target.value as typeof groupBy)}
              className={cn(
                "h-10 rounded-md border px-3 text-sm outline-none focus:ring-2 focus:ring-primary/40",
                groupBy === "none"
                  ? "border-border bg-background text-foreground"
                  : "border-primary/30 bg-primary/10 text-primary",
              )}
              title="Group findings in the table by asset or category"
            >
              <option value="none">No grouping</option>
              <option value="asset">Group by asset</option>
              <option value="category">Group by category</option>
            </select>
            <button
              type="button"
              onClick={() => loadFindings()}
              disabled={loading}
              title="Reload findings"
              className="h-10 w-10 inline-flex items-center justify-center rounded-md border border-border bg-background text-muted-foreground hover:text-foreground hover:border-primary/30 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>

        {/* SOC 2 / ISO 27001 cross-walk reminder — only when one of those
            frameworks is selected. Keeps the legal-disclaimer copy near the
            data, not buried in a tooltip. */}
        {(frameworkFilter === "soc2" || frameworkFilter === "iso_27001") && (
          <div className="flex items-center gap-2 text-[11px] text-muted-foreground/80 italic">
            <ShieldCheck className="w-3.5 h-3.5" />
            Showing findings mapped to this framework via NIST cross-walk — verify with your auditor.
          </div>
        )}

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
              variant="outline"
              onClick={() => { setBulkEscalateNote(""); setBulkEscalateAck(true); setBulkEscalateOpen(true); }}
              disabled={actionLoading || bulkEscalating}
              className="gap-1.5 text-amber-400 border-amber-500/30 hover:bg-amber-500/10"
            >
              <Siren className="w-3.5 h-3.5" />Escalate to Alerts
            </Button>
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

        {/* ── Table + side panel (resizable split-pane on lg+) ── */}
        <div ref={splitContainerRef} className="flex flex-col lg:flex-row gap-5 lg:gap-0 items-start">

        {/* Left: table column */}
        <div className="w-full min-w-0 flex-1 space-y-5">

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
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[140px]">Status</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[110px]">Category</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[180px]">Asset</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[140px]">Group</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[150px]">Detected</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading && findings.length > 0 && (
                <tr>
                  <td colSpan={canEdit ? 7 : 6} className="px-4 py-2 text-center">
                    <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />Updating…
                    </div>
                  </td>
                </tr>
              )}
              {(() => {
                // When groupBy != "none", insert a section header row whenever
                // the group key changes. We rely on the findings array already
                // being sorted (recent/severity); within each group, the same
                // sort order applies. Simpler than re-sorting in a derived memo.
                let lastGroupKey: string | null = null;
                return findings.flatMap((f: any) => {
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

                  // Decide whether to emit a group header before this row
                  const groupKey = groupBy === "asset" ? assetValue
                    : groupBy === "category" ? (catCfg.label || "Other")
                    : null;
                  const headerRow = (groupKey != null && groupKey !== lastGroupKey)
                    ? (
                      <tr key={`group-${groupKey}-${id}`} className="bg-muted/30 border-y border-border">
                        <td colSpan={canEdit ? 8 : 7} className="px-4 py-2 text-xs font-semibold text-muted-foreground">
                          <div className="flex items-center gap-2">
                            {groupBy === "asset" ? (
                              <>
                                <Tag className="w-3.5 h-3.5" />
                                <span className="text-foreground font-mono">{groupKey}</span>
                              </>
                            ) : (
                              <>
                                <span className={cn("inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px]", catCfg.color)}>
                                  {groupKey}
                                </span>
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    )
                    : null;
                  lastGroupKey = groupKey;
                  return [headerRow, (
                  <tr
                    key={id}
                    className={cn(
                      "group hover:bg-accent/40 hover:border-l-2 hover:border-l-primary transition-all cursor-pointer",
                      (status !== "open" && status !== "in_progress") && "opacity-60",
                    )}
                    onClick={() => { setSelected(f); setDetailsOpen(true); setFocusInUrl(id); }}
                    title="Click to see finding details, evidence, and recommendations"
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
                        {isCloud && <CloudSubIcon subType={cloudSub} />}
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-foreground font-medium truncate" title={title}>
                              {title}
                            </span>
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
                      <div className="flex flex-col gap-1 items-start">
                        {statusBadge && (
                          <span className={`inline-flex items-center gap-1.5 text-[10px] px-1.5 py-0.5 rounded border ${statusBadge.class}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${statusBadge.dot}`} />
                            {statusBadge.label}
                          </span>
                        )}
                        {prefs.showProvenanceTags && (
                          <ProvenanceTag value={(f.provenance as Provenance) ?? null} />
                        )}
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
                      {(() => {
                        const { display, full } = formatRelativeOrDate(detectedAt);
                        return <span title={full || undefined}>{display}</span>;
                      })()}
                    </td>
                  </tr>
                )];
                });
              })()}
              {findings.length === 0 && !loading && (
                <tr>
                  <td
                    colSpan={canEdit ? 8 : 7}
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

        </div>{/* end left column */}

        {/* Drag handle — only when panel is visible, only on lg+ */}
        {selected && (
          <div
            role="separator"
            aria-orientation="vertical"
            aria-label="Resize details panel"
            onMouseDown={startResize}
            className="hidden lg:flex shrink-0 self-stretch w-2 mx-1 cursor-col-resize group sticky top-4 lg:h-[calc(100vh-2rem)] items-center justify-center"
          >
            <div className="w-px h-12 bg-border group-hover:bg-primary/60 group-active:bg-primary transition-colors" />
          </div>
        )}

        {/* Right: details panel (sticky on lg+, stacks below on mobile) */}
        {selected && (
          <aside
            className="w-full shrink-0 lg:sticky lg:top-4 lg:self-start lg:h-[calc(100vh-2rem)] flex lg:w-[var(--panel-w)]"
            style={{ "--panel-w": `${panelWidth}%` } as React.CSSProperties}
          >
            <FindingDetailsDialog
              open={true}
              onOpenChange={(o) => {
                if (!o) {
                  setSelected(null);
                  setDetailsOpen(false);
                  setFocusInUrl(null);
                }
              }}
              finding={selected as any}
              mode="panel"
              onStatusChange={canEdit ? handleStatusChange : undefined}
              onEscalate={
                canEdit
                  ? async (id, payload) => {
                      try {
                        const res = await escalateFinding(id, payload);
                        setBanner({ kind: "ok", text: `Escalated — alert #${res.alertId} created.` });
                        if (payload.acknowledge) {
                          loadFindings();
                        }
                      } catch (e: any) {
                        setBanner({ kind: "err", text: e?.message || "Failed to escalate" });
                        throw e;
                      }
                    }
                  : undefined
              }
            />
          </aside>
        )}

        </div>{/* end split-pane container */}
      </div>

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

      {/* \u2500\u2500 Bulk Escalate-to-Alerts Dialog \u2500\u2500 */}
      <Dialog open={bulkEscalateOpen} onOpenChange={(o) => { if (!o && !bulkEscalating) setBulkEscalateOpen(false); }}>
        <DialogContent className="bg-card border-border text-foreground sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Siren className="w-5 h-5 text-amber-400" />
              Escalate {selectedIds.size} finding{selectedIds.size !== 1 ? "s" : ""} to alerts
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <p className="text-sm text-muted-foreground">
              Creates one alert per selected finding and routes them through your notification rules
              (Slack, Jira, email, etc.). The findings themselves stay open unless you tick the option below.
            </p>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-foreground block">Shared note (optional)</label>
              <textarea
                value={bulkEscalateNote}
                onChange={(e) => setBulkEscalateNote(e.target.value)}
                placeholder="Why are these being escalated together?"
                rows={3}
                maxLength={500}
                className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
              />
              <p className="text-[11px] text-muted-foreground">Appended to every alert's summary.</p>
            </div>
            <label className="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer">
              <input
                type="checkbox"
                checked={bulkEscalateAck}
                onChange={(e) => setBulkEscalateAck(e.target.checked)}
                className="accent-primary"
              />
              Mark these findings as &quot;In Progress&quot;
            </label>
            <div className="flex gap-3 justify-end pt-2">
              <Button
                variant="outline"
                onClick={() => setBulkEscalateOpen(false)}
                disabled={bulkEscalating}
                className="border-border text-foreground hover:bg-accent"
              >
                Cancel
              </Button>
              <Button
                onClick={handleBulkEscalate}
                disabled={bulkEscalating}
                className="bg-amber-500 hover:bg-amber-600 text-white"
              >
                <Siren className="w-4 h-4 mr-2" />
                {bulkEscalating ? "Escalating\u2026" : `Escalate ${selectedIds.size}`}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}