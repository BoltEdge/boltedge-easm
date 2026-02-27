// FILE: app/(authenticated)/reports/page.tsx
// Reports page — list generated reports, generate new reports (org-wide or group-scoped),
// download PDFs, and delete reports. Supports executive and technical templates.
// Permissions: viewer+ can view/download, analyst+ can generate, admin+ can delete.
// Auto-polls while reports are generating.
"use client";

import { useState, useEffect, useCallback } from "react";
import {
  FileText, Download, Trash2, Plus, Loader2, AlertCircle,
  Building2, FolderOpen, ChevronDown, X, RefreshCw,
} from "lucide-react";
import { useOrg } from "../contexts/OrgContext";
import {
  getReports, generateReport, deleteReport, downloadReport, getGroups,
  isPlanError,
} from "../../lib/api";
import type {
  ReportItem, ReportScope, ReportTemplate, ReportListResponse,
} from "../../lib/api";
import type { AssetGroup } from "../../types";

// ════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString("en-US", {
      month: "short", day: "numeric", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

function formatFileSize(bytes: number | null): string {
  if (!bytes) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function statusBadge(status: string) {
  const map: Record<string, { bg: string; text: string; label: string }> = {
    ready: { bg: "bg-emerald-500/10", text: "text-emerald-400", label: "Ready" },
    generating: { bg: "bg-amber-500/10", text: "text-amber-400", label: "Generating" },
    pending: { bg: "bg-blue-500/10", text: "text-blue-400", label: "Pending" },
    failed: { bg: "bg-red-500/10", text: "text-red-400", label: "Failed" },
  };
  const s = map[status] || map.pending;
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${s.bg} ${s.text}`}>
      {status === "generating" && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
      {s.label}
    </span>
  );
}

function templateBadge(template: string) {
  const isExec = template === "executive";
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
      isExec ? "bg-teal-500/10 text-teal-400" : "bg-purple-500/10 text-purple-400"
    }`}>
      {isExec ? "Executive" : "Technical"}
    </span>
  );
}

function scopeBadge(scope: string, groupName: string | null) {
  if (scope === "group") {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-500/10 text-blue-400">
        <FolderOpen className="w-3 h-3" />
        {groupName || "Group"}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-white/5 text-white/60">
      <Building2 className="w-3 h-3" />
      Organization
    </span>
  );
}

function severityDot(sev: string, count: number) {
  const colors: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-amber-500",
    low: "bg-blue-500",
    info: "bg-slate-400",
  };
  if (count === 0) return null;
  return (
    <span key={sev} className="inline-flex items-center gap-1 text-xs text-white/50">
      <span className={`w-2 h-2 rounded-full ${colors[sev] || "bg-slate-400"}`} />
      {count}
    </span>
  );
}

// ════════════════════════════════════════════════════════════════
// GENERATE DIALOG
// ════════════════════════════════════════════════════════════════

function GenerateDialog({
  open, onClose, onGenerated, groups,
}: {
  open: boolean;
  onClose: () => void;
  onGenerated: () => void;
  groups: AssetGroup[];
}) {
  const [template, setTemplate] = useState<ReportTemplate>("executive");
  const [scope, setScope] = useState<ReportScope>("organization");
  const [groupId, setGroupId] = useState<string>("");
  const [title, setTitle] = useState("");
  const [includeSuppressed, setIncludeSuppressed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setTemplate("executive");
      setScope("organization");
      setGroupId("");
      setTitle("");
      setIncludeSuppressed(false);
      setError(null);
    }
  }, [open]);

  const handleGenerate = async () => {
    if (scope === "group" && !groupId) {
      setError("Please select a group");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await generateReport({
        template,
        scope,
        groupId: scope === "group" ? groupId : undefined,
        title: title.trim() || undefined,
        config: { includeIgnored: includeSuppressed },
      });
      onGenerated();
      onClose();
    } catch (e: any) {
      if (isPlanError(e)) {
        setError(e.planError?.error || "Plan limit reached");
      } else {
        setError(e?.message || "Failed to generate report");
      }
    } finally {
      setLoading(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-[#0f1729] border border-white/10 rounded-xl shadow-2xl w-full max-w-lg mx-4 p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-white">Generate Report</h2>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-white/10 text-white/40 hover:text-white/70 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm flex items-start gap-2">
            <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
            {error}
          </div>
        )}

        {/* Template Selection */}
        <div className="mb-5">
          <label className="block text-sm font-medium text-white/70 mb-2">Report Template</label>
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setTemplate("executive")}
              className={`p-4 rounded-lg border text-left transition-all ${
                template === "executive"
                  ? "border-teal-500 bg-teal-500/10 ring-1 ring-teal-500/30"
                  : "border-white/10 bg-white/5 hover:border-white/20"
              }`}
            >
              <div className={`text-sm font-semibold ${template === "executive" ? "text-teal-400" : "text-white/80"}`}>
                Executive Summary
              </div>
              <div className="text-xs text-white/40 mt-1">1-2 pages, key metrics, top risks. For CISOs and client handoffs.</div>
            </button>
            <button
              type="button"
              onClick={() => setTemplate("technical")}
              className={`p-4 rounded-lg border text-left transition-all ${
                template === "technical"
                  ? "border-purple-500 bg-purple-500/10 ring-1 ring-purple-500/30"
                  : "border-white/10 bg-white/5 hover:border-white/20"
              }`}
            >
              <div className={`text-sm font-semibold ${template === "technical" ? "text-purple-400" : "text-white/80"}`}>
                Full Technical
              </div>
              <div className="text-xs text-white/40 mt-1">All findings with remediation details. For security teams.</div>
            </button>
          </div>
        </div>

        {/* Scope Selection */}
        <div className="mb-5">
          <label className="block text-sm font-medium text-white/70 mb-2">Report Scope</label>
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => { setScope("organization"); setGroupId(""); }}
              className={`p-4 rounded-lg border text-left transition-all ${
                scope === "organization"
                  ? "border-teal-500 bg-teal-500/10 ring-1 ring-teal-500/30"
                  : "border-white/10 bg-white/5 hover:border-white/20"
              }`}
            >
              <div className="flex items-center gap-2">
                <Building2 className={`w-4 h-4 ${scope === "organization" ? "text-teal-400" : "text-white/40"}`} />
                <span className={`text-sm font-semibold ${scope === "organization" ? "text-teal-400" : "text-white/80"}`}>
                  Organization
                </span>
              </div>
              <div className="text-xs text-white/40 mt-1">All groups and assets across the entire organization.</div>
            </button>
            <button
              type="button"
              onClick={() => setScope("group")}
              className={`p-4 rounded-lg border text-left transition-all ${
                scope === "group"
                  ? "border-blue-500 bg-blue-500/10 ring-1 ring-blue-500/30"
                  : "border-white/10 bg-white/5 hover:border-white/20"
              }`}
            >
              <div className="flex items-center gap-2">
                <FolderOpen className={`w-4 h-4 ${scope === "group" ? "text-blue-400" : "text-white/40"}`} />
                <span className={`text-sm font-semibold ${scope === "group" ? "text-blue-400" : "text-white/80"}`}>
                  Single Group
                </span>
              </div>
              <div className="text-xs text-white/40 mt-1">Scoped to one group — ideal for MSSP client delivery.</div>
            </button>
          </div>
        </div>

        {/* Group Selector */}
        {scope === "group" && (
          <div className="mb-5">
            <label className="block text-sm font-medium text-white/70 mb-2">Select Group</label>
            <div className="relative">
              <select
                value={groupId}
                onChange={(e) => setGroupId(e.target.value)}
                className="w-full appearance-none bg-white/5 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-1 focus:ring-teal-500 focus:border-teal-500"
              >
                <option value="" className="bg-[#0f1729]">Choose a group...</option>
                {groups.map((g) => (
                  <option key={g.id} value={String(g.id)} className="bg-[#0f1729]">
                    {g.name}
                  </option>
                ))}
              </select>
              <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30 pointer-events-none" />
            </div>
          </div>
        )}

        {/* Custom Title */}
        <div className="mb-5">
          <label className="block text-sm font-medium text-white/70 mb-2">
            Report Title <span className="text-white/30 font-normal">(optional)</span>
          </label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Auto-generated if left blank"
            className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white placeholder-white/30 focus:outline-none focus:ring-1 focus:ring-teal-500 focus:border-teal-500"
          />
        </div>

        {/* Include Suppressed Toggle */}
        <div className="mb-6 p-3 rounded-lg bg-white/[0.03] border border-white/5">
          <label className="flex items-center justify-between cursor-pointer">
            <div>
              <div className="text-sm font-medium text-white/70">Include suppressed findings</div>
              <div className="text-xs text-white/30 mt-0.5">Suppressed findings are excluded by default. Enable to include risk-accepted items.</div>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={includeSuppressed}
              onClick={() => setIncludeSuppressed((v) => !v)}
              className={`relative inline-flex h-6 w-11 shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 ${
                includeSuppressed ? "bg-teal-600" : "bg-white/10"
              }`}
            >
              <span className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ${
                includeSuppressed ? "translate-x-5" : "translate-x-0"
              }`} />
            </button>
          </label>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm font-medium text-white/60 hover:text-white/80 hover:bg-white/5 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleGenerate}
            disabled={loading}
            className="inline-flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-semibold bg-teal-600 hover:bg-teal-500 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
            {loading ? "Generating..." : "Generate Report"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// MAIN PAGE
// ════════════════════════════════════════════════════════════════

export default function ReportsPage() {
  const { canDo, role } = useOrg();

  const [reports, setReports] = useState<ReportItem[]>([]);
  const [groups, setGroups] = useState<AssetGroup[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [filterScope, setFilterScope] = useState<string>("all");
  const [filterTemplate, setFilterTemplate] = useState<string>("all");
  const [filterGroupId, setFilterGroupId] = useState<string>("all");

  // Dialog
  const [showGenerate, setShowGenerate] = useState(false);

  // Banner
  const [banner, setBanner] = useState<{ type: "success" | "error"; message: string } | null>(null);

  const canGenerate = canDo("edit_findings") || role === "analyst" || role === "admin" || role === "owner";
  const canDelete = role === "admin" || role === "owner";

  const perPage = 20;

  const fetchReports = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const params: any = { page, perPage };
      if (filterScope !== "all") params.scope = filterScope;
      if (filterTemplate !== "all") params.template = filterTemplate;
      if (filterGroupId !== "all") params.groupId = filterGroupId;

      const res = await getReports(params);
      setReports(res.reports);
      setTotal(res.total);
    } catch (e: any) {
      setError(e?.message || "Failed to load reports");
    } finally {
      setLoading(false);
    }
  }, [page, filterScope, filterTemplate, filterGroupId]);

  const fetchGroups = useCallback(async () => {
    try {
      const g = await getGroups();
      setGroups(g);
    } catch {
      // Non-critical — generate dialog just won't have groups
    }
  }, []);

  useEffect(() => { fetchReports(); }, [fetchReports]);
  useEffect(() => { fetchGroups(); }, [fetchGroups]);

  // Auto-poll while any report is still generating (every 3s)
  useEffect(() => {
    const hasGenerating = reports.some((r) => r.status === "generating");
    if (!hasGenerating) return;

    const timer = setInterval(() => {
      fetchReports();
    }, 3000);

    return () => clearInterval(timer);
  }, [reports, fetchReports]);

  const handleDownload = async (r: ReportItem) => {
    try {
      const blob = await downloadReport(r.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${r.title.replace(/\s+/g, "_")}_${r.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setBanner({ type: "error", message: e?.message || "Download failed" });
      setTimeout(() => setBanner(null), 5000);
    }
  };

  const handleDelete = async (r: ReportItem) => {
    if (!confirm(`Delete report "${r.title}"? This cannot be undone.`)) return;
    try {
      await deleteReport(r.id);
      setBanner({ type: "success", message: "Report deleted" });
      setTimeout(() => setBanner(null), 4000);
      fetchReports();
    } catch (e: any) {
      setBanner({ type: "error", message: e?.message || "Failed to delete report" });
      setTimeout(() => setBanner(null), 5000);
    }
  };

  const handleGenerated = () => {
    setBanner({ type: "success", message: "Report generated successfully!" });
    setTimeout(() => setBanner(null), 4000);
    fetchReports();
  };

  const totalPages = Math.ceil(total / perPage);

  return (
    <div className="p-6 md:p-10 max-w-7xl mx-auto space-y-6">
      {/* Banner */}
      {banner && (
        <div className={`p-4 rounded-lg border text-sm flex items-center justify-between ${
          banner.type === "success"
            ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
            : "bg-red-500/10 border-red-500/20 text-red-400"
        }`}>
          <span>{banner.message}</span>
          <button onClick={() => setBanner(null)} className="hover:opacity-70"><X className="w-4 h-4" /></button>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Reports</h1>
          <p className="text-sm text-white/50 mt-1">
            Generate and download security reports for your organization or individual groups.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchReports}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border border-white/10 text-white/60 hover:text-white/80 hover:bg-white/5 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          {canGenerate && (
            <button
              onClick={() => setShowGenerate(true)}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-teal-600 hover:bg-teal-500 text-white transition-colors"
            >
              <Plus className="w-4 h-4" />
              Generate Report
            </button>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative">
          <select
            value={filterScope}
            onChange={(e) => { setFilterScope(e.target.value); setPage(1); }}
            className="appearance-none bg-white/5 border border-white/10 rounded-lg px-4 py-2 pr-9 text-sm text-white focus:outline-none focus:ring-1 focus:ring-teal-500"
          >
            <option value="all" className="bg-[#0f1729]">All Scopes</option>
            <option value="organization" className="bg-[#0f1729]">Organization</option>
            <option value="group" className="bg-[#0f1729]">Group</option>
          </select>
          <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30 pointer-events-none" />
        </div>

        <div className="relative">
          <select
            value={filterTemplate}
            onChange={(e) => { setFilterTemplate(e.target.value); setPage(1); }}
            className="appearance-none bg-white/5 border border-white/10 rounded-lg px-4 py-2 pr-9 text-sm text-white focus:outline-none focus:ring-1 focus:ring-teal-500"
          >
            <option value="all" className="bg-[#0f1729]">All Templates</option>
            <option value="executive" className="bg-[#0f1729]">Executive</option>
            <option value="technical" className="bg-[#0f1729]">Technical</option>
          </select>
          <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30 pointer-events-none" />
        </div>

        {groups.length > 0 && (
          <div className="relative">
            <select
              value={filterGroupId}
              onChange={(e) => { setFilterGroupId(e.target.value); setPage(1); }}
              className="appearance-none bg-white/5 border border-white/10 rounded-lg px-4 py-2 pr-9 text-sm text-white focus:outline-none focus:ring-1 focus:ring-teal-500"
            >
              <option value="all" className="bg-[#0f1729]">All Groups</option>
              {groups.map((g) => (
                <option key={g.id} value={String(g.id)} className="bg-[#0f1729]">{g.name}</option>
              ))}
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30 pointer-events-none" />
          </div>
        )}

        {(filterScope !== "all" || filterTemplate !== "all" || filterGroupId !== "all") && (
          <button
            onClick={() => { setFilterScope("all"); setFilterTemplate("all"); setFilterGroupId("all"); setPage(1); }}
            className="text-xs text-white/40 hover:text-white/60 transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Error State */}
      {error && (
        <div className="p-6 rounded-xl bg-red-500/5 border border-red-500/10 text-center">
          <AlertCircle className="w-8 h-8 text-red-400 mx-auto mb-2" />
          <p className="text-red-400 text-sm">{error}</p>
          <button onClick={fetchReports} className="mt-3 text-sm text-teal-400 hover:text-teal-300">Retry</button>
        </div>
      )}

      {/* Loading State */}
      {loading && !error && (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-teal-400 animate-spin" />
          <span className="ml-3 text-white/50 text-sm">Loading reports...</span>
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && reports.length === 0 && (
        <div className="p-12 rounded-xl bg-[#0f1729]/60 border border-white/5 text-center">
          <FileText className="w-12 h-12 text-white/20 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-white/80 mb-2">No reports yet</h3>
          <p className="text-sm text-white/40 mb-6 max-w-md mx-auto">
            Generate your first security report to share with stakeholders or deliver to MSSP clients.
          </p>
          {canGenerate && (
            <button
              onClick={() => setShowGenerate(true)}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold bg-teal-600 hover:bg-teal-500 text-white transition-colors"
            >
              <Plus className="w-4 h-4" />
              Generate Report
            </button>
          )}
        </div>
      )}

      {/* Report List */}
      {!loading && !error && reports.length > 0 && (
        <div className="rounded-xl bg-[#0f1729]/60 border border-white/5 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/5">
                <th className="text-left px-5 py-3 text-xs font-semibold text-white/40 uppercase tracking-wider">Report</th>
                <th className="text-left px-5 py-3 text-xs font-semibold text-white/40 uppercase tracking-wider">Template</th>
                <th className="text-left px-5 py-3 text-xs font-semibold text-white/40 uppercase tracking-wider">Scope</th>
                <th className="text-left px-5 py-3 text-xs font-semibold text-white/40 uppercase tracking-wider">Summary</th>
                <th className="text-left px-5 py-3 text-xs font-semibold text-white/40 uppercase tracking-wider">Status</th>
                <th className="text-left px-5 py-3 text-xs font-semibold text-white/40 uppercase tracking-wider">Generated</th>
                <th className="text-right px-5 py-3 text-xs font-semibold text-white/40 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {reports.map((r) => {
                const sev = r.summaryData?.severityCounts;
                return (
                  <tr key={r.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="px-5 py-4">
                      <div className="text-sm font-medium text-white/90">{r.title}</div>
                      <div className="text-xs text-white/30 mt-0.5">
                        {formatFileSize(r.fileSize)} &middot; ID: {r.id}
                      </div>
                    </td>
                    <td className="px-5 py-4">{templateBadge(r.template)}</td>
                    <td className="px-5 py-4">{scopeBadge(r.scope, r.groupName)}</td>
                    <td className="px-5 py-4">
                      {r.summaryData ? (
                        <div className="space-y-1">
                          <div className="text-xs text-white/50">
                            Score: <span className="font-semibold text-white/80">{r.summaryData.exposureScore}</span>
                            <span className="mx-1.5">·</span>
                            {r.summaryData.totalFindings} findings
                          </div>
                          <div className="flex items-center gap-2">
                            {sev && Object.entries(sev).map(([s, c]) => severityDot(s, c as number))}
                          </div>
                        </div>
                      ) : (
                        <span className="text-xs text-white/20">—</span>
                      )}
                    </td>
                    <td className="px-5 py-4">
                      {statusBadge(r.status)}
                      {r.status === "failed" && r.errorMessage && (
                        <div className="mt-1 text-[11px] text-red-400/70 max-w-[200px] truncate" title={r.errorMessage}>
                          {r.errorMessage}
                        </div>
                      )}
                    </td>
                    <td className="px-5 py-4">
                      <div className="text-sm text-white/60">{formatDate(r.generatedAt || r.createdAt)}</div>
                    </td>
                    <td className="px-5 py-4">
                      <div className="flex items-center justify-end gap-1">
                        {r.status === "ready" && (
                          <button
                            onClick={() => handleDownload(r)}
                            className="p-2 rounded-lg text-teal-400 hover:bg-teal-500/10 transition-colors"
                            title="Download PDF"
                          >
                            <Download className="w-4 h-4" />
                          </button>
                        )}
                        {canDelete && (
                          <button
                            onClick={() => handleDelete(r)}
                            className="p-2 rounded-lg text-red-400/60 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                            title="Delete report"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-5 py-3 border-t border-white/5">
              <span className="text-xs text-white/30">
                Showing {(page - 1) * perPage + 1}–{Math.min(page * perPage, total)} of {total}
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium border border-white/10 text-white/50 hover:text-white/80 hover:bg-white/5 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  Previous
                </button>
                <span className="text-xs text-white/40">
                  {page} / {totalPages}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium border border-white/10 text-white/50 hover:text-white/80 hover:bg-white/5 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Generate Dialog */}
      <GenerateDialog
        open={showGenerate}
        onClose={() => setShowGenerate(false)}
        onGenerated={handleGenerated}
        groups={groups}
      />
    </div>
  );
}