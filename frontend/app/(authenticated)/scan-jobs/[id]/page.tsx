// FILE: app/(authenticated)/scan/[id]/page.tsx
// Scan Job Detail — results, findings, exposure score, Cloud Assets section
// CLOUD: Added cloud category, cloud sub-icons, and Cloud Assets results panel
// Phase 1 fix: Injects job asset context into findings for the detail dialog
"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ChevronLeft, Shield, Clock, CheckCircle2, XCircle, Loader2,
  AlertTriangle, Search, Tag, Wrench, Cloud, Database, Box, Cpu,
  ChevronDown, ChevronRight,
} from "lucide-react";

import { apiFetch } from "../../../lib/api";
import { Button } from "../../../ui/button";
import { Input } from "../../../ui/input";
import { SeverityBadge } from "../../../SeverityBadge";
import { FindingDetailsDialog } from "../../../FindingDetailsDialog";

import type { Finding } from "../../../types";

type SeverityKey = "critical" | "high" | "medium" | "low" | "info";

function cn(...classes: Array<string | undefined | null | false>) {
  return classes.filter(Boolean).join(" ");
}

function formatDate(d?: any) {
  if (!d) return "—";
  let dt: Date;
  if (typeof d === "string" && !d.endsWith("Z") && !d.includes("+")) dt = new Date(d + "Z");
  else dt = d instanceof Date ? d : new Date(d);
  if (isNaN(dt.getTime())) return "—";
  return dt.toLocaleString();
}

function formatDuration(start?: string, end?: string): string {
  if (!start || !end) return "—";
  const s = new Date(start).getTime();
  const e = new Date(end).getTime();
  if (isNaN(s) || isNaN(e)) return "—";
  const sec = Math.round((e - s) / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  const rem = sec % 60;
  return `${min}m ${rem}s`;
}

function getSeverity(f: any): SeverityKey {
  const s = String(f?.severity || "info").toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") return s;
  return "info";
}

const CATEGORY_CONFIG: Record<string, { label: string; color: string }> = {
  ssl:              { label: "SSL/TLS",    color: "bg-purple-500/15 text-purple-300 border-purple-500/30" },
  ports:            { label: "Ports",      color: "bg-blue-500/15 text-blue-300 border-blue-500/30" },
  headers:          { label: "Headers",    color: "bg-amber-500/15 text-amber-300 border-amber-500/30" },
  cve:              { label: "CVE",        color: "bg-red-500/15 text-red-300 border-red-500/30" },
  dns:              { label: "DNS",        color: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30" },
  tech:             { label: "Tech",       color: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" },
  technology:       { label: "Tech",       color: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" },
  exposure:         { label: "Exposure",   color: "bg-orange-500/15 text-orange-300 border-orange-500/30" },
  misconfiguration: { label: "Misconfig",  color: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30" },
  vulnerability:    { label: "Vuln",       color: "bg-red-500/15 text-red-300 border-red-500/30" },
  cloud:            { label: "Cloud",      color: "bg-sky-500/15 text-sky-300 border-sky-500/30" },
  other:            { label: "Other",      color: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30" },
};

function getCategory(f: any): string {
  const direct = f.category ?? f.details?.category;
  if (direct) return String(direct).toLowerCase();

  const templateId = String(f.templateId ?? f.template_id ?? "").toLowerCase();
  if (templateId.startsWith("cloud-")) return "cloud";

  const title = String(f.title || "").toLowerCase();

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

  if (title.includes("ssl") || title.includes("tls") || title.includes("certificate")) return "ssl";
  if (title.includes("header") || title.includes("csp") || title.includes("hsts")) return "headers";
  if (title.includes("spf") || title.includes("dkim") || title.includes("dmarc") || title.includes("dns")) return "dns";
  if (title.includes("cve")) return "cve";
  if (title.includes("port") || title.includes("exposed") || title.includes("service")) return "ports";
  if (title.includes("technology") || title.includes("detected")) return "tech";
  if (title.includes("exposure score")) return "exposure";
  return "other";
}

/** Cloud sub-type from template_id or title */
function getCloudSubType(f: any): string | null {
  const templateId = String(f.templateId ?? f.template_id ?? "").toLowerCase();
  if (templateId.includes("storage")) return "storage";
  if (templateId.includes("registry")) return "registry";
  if (templateId.includes("serverless")) return "serverless";
  if (templateId.includes("cdn")) return "cdn";

  const title = String(f.title || "").toLowerCase();
  if (title.includes("bucket") || title.includes("blob") || title.includes("storage")) return "storage";
  if (title.includes("registry") || title.includes("container") || title.includes("docker")) return "registry";
  if (title.includes("serverless") || title.includes("function") || title.includes("lambda")) return "serverless";
  if (title.includes("cdn") || title.includes("origin")) return "cdn";
  return null;
}

const CLOUD_SUB_CONFIG: Record<string, { label: string; icon: typeof Cloud; color: string; bgColor: string }> = {
  storage:    { label: "Storage Buckets",       icon: Database,  color: "text-sky-400",    bgColor: "bg-sky-500/10" },
  registry:   { label: "Container Registries",  icon: Box,       color: "text-violet-400", bgColor: "bg-violet-500/10" },
  serverless: { label: "Serverless Endpoints",  icon: Cpu,       color: "text-amber-400",  bgColor: "bg-amber-500/10" },
  cdn:        { label: "CDN Origin Exposure",   icon: Shield,    color: "text-teal-400",   bgColor: "bg-teal-500/10" },
};

function CloudSubIcon({ subType, className }: { subType: string | null; className?: string }) {
  switch (subType) {
    case "storage":    return <Database className={cn("w-3.5 h-3.5 text-sky-400 shrink-0", className)} />;
    case "registry":   return <Box className={cn("w-3.5 h-3.5 text-violet-400 shrink-0", className)} />;
    case "serverless": return <Cpu className={cn("w-3.5 h-3.5 text-amber-400 shrink-0", className)} />;
    case "cdn":        return <Shield className={cn("w-3.5 h-3.5 text-teal-400 shrink-0", className)} />;
    default:           return <Cloud className={cn("w-3.5 h-3.5 text-sky-400 shrink-0", className)} />;
  }
}

function statusConfig(status: string) {
  switch (status) {
    case "completed": return { icon: CheckCircle2, color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/30", label: "Completed" };
    case "running":   return { icon: Loader2, color: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/30", label: "Running" };
    case "queued":    return { icon: Clock, color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/30", label: "Queued" };
    case "failed":    return { icon: XCircle, color: "text-red-400", bg: "bg-red-500/10 border-red-500/30", label: "Failed" };
    default:          return { icon: Clock, color: "text-zinc-400", bg: "bg-zinc-500/10 border-zinc-500/30", label: status };
  }
}

export default function ScanJobDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const jobId = params.id;

  const [job, setJob] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"all" | SeverityKey>("all");
  const [categoryFilter, setCategoryFilter] = useState("all");

  // Detail dialog
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [selected, setSelected] = useState<any>(null);

  // Cloud section collapse state
  const [cloudExpanded, setCloudExpanded] = useState(true);
  const [expandedCloudSubs, setExpandedCloudSubs] = useState<Set<string>>(new Set(["storage", "registry", "serverless", "cdn"]));

  function toggleCloudSub(sub: string) {
    setExpandedCloudSubs((prev) => {
      const next = new Set(prev);
      if (next.has(sub)) next.delete(sub); else next.add(sub);
      return next;
    });
  }

  // Helper: open finding detail with job context injected
  function openFinding(f: any) {
    setSelected({
      ...f,
      _jobAssetValue: job?.assetValue || job?.asset_value || null,
      _jobGroupName: job?.groupName || job?.group_name || null,
    });
    setDetailsOpen(true);
  }

  const loadJob = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch job list and find this one
      const jobs = await apiFetch<any[]>("/scan-jobs");
      const thisJob = jobs.find((j: any) => String(j.id) === String(jobId));

      if (!thisJob) {
        setError("Scan job not found");
        return;
      }
      setJob(thisJob);

      // Fetch findings for this job
      if (thisJob.status === "completed") {
        const f = await apiFetch<any[]>(`/scan-jobs/${jobId}/findings`);
        setFindings(f || []);
      }
    } catch (e: any) {
      setError(e?.message || "Failed to load scan job");
    } finally {
      setLoading(false);
    }
  }, [jobId]);

  useEffect(() => { loadJob(); }, [loadJob]);

  // Auto-poll if running
  useEffect(() => {
    if (!job || (job.status !== "running" && job.status !== "queued")) return;
    const iv = setInterval(loadJob, 5000);
    return () => clearInterval(iv);
  }, [job, loadJob]);

  // Severity counts
  const severityCounts: Record<string, number> = {};
  for (const f of findings) {
    const s = getSeverity(f);
    severityCounts[s] = (severityCounts[s] || 0) + 1;
  }

  // Category counts
  const categoryCounts: Record<string, number> = {};
  for (const f of findings) {
    const c = getCategory(f);
    categoryCounts[c] = (categoryCounts[c] || 0) + 1;
  }

  // Find exposure score finding
  const exposureFinding = findings.find((f) =>
    f.title?.includes("Exposure Score") || f.templateId === "exposure-score"
  );
  const exposureDetails = exposureFinding?.details;

  // ── Cloud findings grouped by sub-type ──
  const cloudFindings = findings.filter((f) => getCategory(f) === "cloud");
  const cloudBySubType: Record<string, any[]> = {};
  for (const f of cloudFindings) {
    const sub = getCloudSubType(f) || "other";
    if (!cloudBySubType[sub]) cloudBySubType[sub] = [];
    cloudBySubType[sub].push(f);
  }
  const hasCloudFindings = cloudFindings.length > 0;

  // Filter findings (exclude exposure score from table)
  const filteredFindings = findings.filter((f) => {
    // Exclude exposure score from the list — it's shown as a card
    if (f.title?.includes("Exposure Score")) return false;

    if (severityFilter !== "all" && getSeverity(f) !== severityFilter) return false;
    if (categoryFilter !== "all" && getCategory(f) !== categoryFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      if (!(f.title || "").toLowerCase().includes(q) && !(f.description || "").toLowerCase().includes(q)) return false;
    }
    return true;
  });

  if (loading) {
    return (
      <div className="flex-1 bg-background p-8">
        <div className="flex items-center justify-center gap-2 text-muted-foreground py-20">
          <Loader2 className="w-5 h-5 animate-spin" />Loading scan job…
        </div>
      </div>
    );
  }

  if (error || !job) {
    return (
      <div className="flex-1 bg-background p-8">
        <button onClick={() => router.back()} className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-6">
          <ChevronLeft className="w-4 h-4" />Back to Scanning
        </button>
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {error || "Scan job not found"}
        </div>
      </div>
    );
  }

  const sc = statusConfig(job.status);
  const StatusIcon = sc.icon;

  return (
    <div className="flex-1 bg-background overflow-auto">
      <div className="p-8 space-y-6">
        {/* Breadcrumb */}
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <button onClick={() => router.back()} className="hover:text-foreground flex items-center gap-1">
            <ChevronLeft className="w-4 h-4" />Scanning
          </button>
          <span>›</span>
          <span className="text-foreground/90">Job #{job.id}</span>
        </div>

        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-foreground flex items-center gap-3">
              <Shield className="w-6 h-6 text-primary" />
              Scan Results
              <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-semibold", sc.bg)}>
                <StatusIcon className={cn("w-3.5 h-3.5", sc.color, job.status === "running" && "animate-spin")} />
                <span className={sc.color}>{sc.label}</span>
              </span>
            </h1>
            <p className="text-muted-foreground mt-1">
              <span className="font-mono text-foreground">{job.assetValue || `Asset #${job.assetId}`}</span>
              {job.groupName && <span> · {job.groupName}</span>}
            </p>
          </div>
        </div>

        {/* Job Info Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="text-xs text-muted-foreground mb-1">Started</div>
            <div className="text-sm font-semibold text-foreground">{formatDate(job.startedAt || job.createdAt)}</div>
          </div>
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="text-xs text-muted-foreground mb-1">Completed</div>
            <div className="text-sm font-semibold text-foreground">{job.finishedAt ? formatDate(job.finishedAt) : job.status === "running" ? "In progress…" : "—"}</div>
          </div>
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="text-xs text-muted-foreground mb-1">Duration</div>
            <div className="text-sm font-semibold text-foreground">{formatDuration(job.startedAt || job.createdAt, job.finishedAt)}</div>
          </div>
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="text-xs text-muted-foreground mb-1">Findings</div>
            <div className="text-sm font-semibold text-foreground">{findings.length}</div>
          </div>
        </div>

        {/* Running state */}
        {(job.status === "running" || job.status === "queued") && (
          <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-xl p-6 flex items-center gap-4">
            <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
            <div>
              <div className="text-foreground font-semibold">Scan in progress…</div>
              <div className="text-sm text-muted-foreground mt-0.5">This page will automatically update when the scan completes.</div>
            </div>
          </div>
        )}

        {/* Failed state */}
        {job.status === "failed" && (
          <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-6">
            <div className="flex items-center gap-2 text-red-400 font-semibold mb-1">
              <XCircle className="w-5 h-5" />Scan Failed
            </div>
            <div className="text-sm text-muted-foreground">{job.error || "An unknown error occurred during scanning."}</div>
          </div>
        )}

        {/* Exposure Score Card */}
        {exposureDetails && (
          <div className="bg-card border border-border rounded-xl p-6">
            <div className="flex items-center gap-5 mb-4">
              <div className={cn("text-5xl font-bold",
                exposureDetails.exposure_score >= 70 ? "text-red-400" :
                exposureDetails.exposure_score >= 40 ? "text-amber-400" :
                exposureDetails.exposure_score >= 20 ? "text-yellow-400" : "text-emerald-400"
              )}>
                {exposureDetails.exposure_score}<span className="text-xl text-muted-foreground">/100</span>
              </div>
              <div>
                <div className="text-xl font-semibold text-foreground">Grade {exposureDetails.grade}</div>
                <div className="text-sm text-muted-foreground">{exposureDetails.grade_description}</div>
                <div className="text-xs text-muted-foreground mt-1">
                  {exposureDetails.total_findings} findings · {exposureDetails.actionable_findings} actionable
                </div>
              </div>
            </div>

            {/* Severity summary pills */}
            {exposureDetails.severity_counts && (
              <div className="flex flex-wrap gap-2 mb-4">
                {exposureDetails.severity_counts.critical > 0 && <span className="px-2.5 py-1 rounded-md text-xs font-semibold bg-red-500/15 text-red-300 border border-red-500/30">{exposureDetails.severity_counts.critical} Critical</span>}
                {exposureDetails.severity_counts.high > 0 && <span className="px-2.5 py-1 rounded-md text-xs font-semibold bg-orange-500/15 text-orange-300 border border-orange-500/30">{exposureDetails.severity_counts.high} High</span>}
                {exposureDetails.severity_counts.medium > 0 && <span className="px-2.5 py-1 rounded-md text-xs font-semibold bg-yellow-500/15 text-yellow-300 border border-yellow-500/30">{exposureDetails.severity_counts.medium} Medium</span>}
                {exposureDetails.severity_counts.low > 0 && <span className="px-2.5 py-1 rounded-md text-xs font-semibold bg-blue-500/15 text-blue-300 border border-blue-500/30">{exposureDetails.severity_counts.low} Low</span>}
                {exposureDetails.severity_counts.info > 0 && <span className="px-2.5 py-1 rounded-md text-xs font-semibold bg-zinc-500/15 text-zinc-300 border border-zinc-500/30">{exposureDetails.severity_counts.info} Info</span>}
              </div>
            )}

            {/* Category breakdown */}
            {exposureDetails.category_breakdown && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {Object.entries(exposureDetails.category_breakdown).map(([cat, data]: [string, any]) => {
                  const cfg = CATEGORY_CONFIG[cat] || CATEGORY_CONFIG.other;
                  return (
                    <div key={cat} className="bg-background/50 border border-border rounded-lg p-3">
                      <div className={cn("text-xs font-semibold uppercase mb-1 flex items-center gap-1", cfg.color.split(" ")[1])}>
                        {cat === "cloud" && <Cloud className="w-3 h-3" />}
                        {cfg.label || cat}
                      </div>
                      <div className="text-lg font-bold text-foreground">{data.count}</div>
                      <div className="flex gap-1 mt-1 flex-wrap">
                        {data.critical > 0 && <span className="text-[10px] text-red-300">{data.critical}C</span>}
                        {data.high > 0 && <span className="text-[10px] text-orange-300">{data.high}H</span>}
                        {data.medium > 0 && <span className="text-[10px] text-yellow-300">{data.medium}M</span>}
                        {data.low > 0 && <span className="text-[10px] text-blue-300">{data.low}L</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ═══ Cloud Assets Section ═══ */}
        {job.status === "completed" && hasCloudFindings && (
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            {/* Section header — collapsible */}
            <button
              onClick={() => setCloudExpanded(!cloudExpanded)}
              className="w-full px-6 py-4 flex items-center justify-between hover:bg-accent/20 transition-colors"
            >
              <div className="flex items-center gap-3">
                <div className="h-9 w-9 rounded-lg bg-sky-500/10 flex items-center justify-center">
                  <Cloud className="w-5 h-5 text-sky-400" />
                </div>
                <div className="text-left">
                  <div className="text-sm font-semibold text-foreground">Cloud Assets</div>
                  <div className="text-xs text-muted-foreground">
                    {cloudFindings.length} finding{cloudFindings.length !== 1 ? "s" : ""} across{" "}
                    {Object.keys(cloudBySubType).length} categor{Object.keys(cloudBySubType).length !== 1 ? "ies" : "y"}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                {/* Quick severity summary for cloud findings */}
                <div className="flex gap-1.5">
                  {(() => {
                    const cloudSev: Record<string, number> = {};
                    for (const f of cloudFindings) {
                      const s = getSeverity(f);
                      cloudSev[s] = (cloudSev[s] || 0) + 1;
                    }
                    return (
                      <>
                        {cloudSev.critical > 0 && <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-red-500/15 text-red-300 border border-red-500/30">{cloudSev.critical}C</span>}
                        {cloudSev.high > 0 && <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-orange-500/15 text-orange-300 border border-orange-500/30">{cloudSev.high}H</span>}
                        {cloudSev.medium > 0 && <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-yellow-500/15 text-yellow-300 border border-yellow-500/30">{cloudSev.medium}M</span>}
                        {cloudSev.low > 0 && <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-500/15 text-blue-300 border border-blue-500/30">{cloudSev.low}L</span>}
                        {cloudSev.info > 0 && <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-zinc-500/15 text-zinc-300 border border-zinc-500/30">{cloudSev.info}I</span>}
                      </>
                    );
                  })()}
                </div>
                {cloudExpanded
                  ? <ChevronDown className="w-4 h-4 text-muted-foreground" />
                  : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
              </div>
            </button>

            {/* Expanded content — grouped by sub-type */}
            {cloudExpanded && (
              <div className="border-t border-border">
                {(["storage", "registry", "serverless", "cdn"] as const).map((subKey) => {
                  const subFindings = cloudBySubType[subKey];
                  if (!subFindings || subFindings.length === 0) return null;

                  const subCfg = CLOUD_SUB_CONFIG[subKey];
                  const SubIcon = subCfg.icon;
                  const isExpanded = expandedCloudSubs.has(subKey);

                  return (
                    <div key={subKey} className="border-b border-border last:border-b-0">
                      {/* Sub-type header */}
                      <button
                        onClick={() => toggleCloudSub(subKey)}
                        className="w-full px-6 py-3 flex items-center justify-between hover:bg-accent/10 transition-colors"
                      >
                        <div className="flex items-center gap-2.5">
                          <div className={cn("h-7 w-7 rounded-md flex items-center justify-center", subCfg.bgColor)}>
                            <SubIcon className={cn("w-4 h-4", subCfg.color)} />
                          </div>
                          <span className="text-sm font-medium text-foreground">{subCfg.label}</span>
                          <span className="text-xs text-muted-foreground">({subFindings.length})</span>
                        </div>
                        {isExpanded
                          ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
                          : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />}
                      </button>

                      {/* Sub-type findings list */}
                      {isExpanded && (
                        <div className="px-6 pb-3">
                          <div className="rounded-lg border border-border overflow-hidden">
                            <table className="w-full">
                              <tbody className="divide-y divide-border">
                                {subFindings.map((f: any) => {
                                  const sev = getSeverity(f);
                                  const title = f.title || "Finding";
                                  const hasRemediation = Boolean(f.remediation || f.details?._remediation);

                                  return (
                                    <tr
                                      key={f.id}
                                      className="hover:bg-accent/30 transition-colors cursor-pointer"
                                      onClick={() => openFinding(f)}
                                    >
                                      <td className="px-3 py-2.5 w-[80px]">
                                        <SeverityBadge severity={sev} />
                                      </td>
                                      <td className="px-3 py-2.5">
                                        <div className="flex items-center gap-2">
                                          <span className="text-sm text-foreground font-medium truncate" title={title}>{title}</span>
                                          {hasRemediation && (
                                            <span title="Remediation available">
                                              <Wrench className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                            </span>
                                          )}
                                        </div>
                                        {f.summary && <div className="text-xs text-muted-foreground mt-0.5 truncate">{f.summary}</div>}
                                      </td>
                                      <td className="px-3 py-2.5 text-xs text-muted-foreground w-[140px]">
                                        {formatDate(f.detectedAt || f.created_at)}
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}

                {/* "other" cloud findings that didn't match a sub-type */}
                {cloudBySubType.other && cloudBySubType.other.length > 0 && (
                  <div className="border-b border-border last:border-b-0">
                    <div className="px-6 py-3">
                      <div className="flex items-center gap-2.5 mb-2">
                        <Cloud className="w-4 h-4 text-sky-400" />
                        <span className="text-sm font-medium text-foreground">Other Cloud</span>
                        <span className="text-xs text-muted-foreground">({cloudBySubType.other.length})</span>
                      </div>
                      <div className="rounded-lg border border-border overflow-hidden">
                        <table className="w-full">
                          <tbody className="divide-y divide-border">
                            {cloudBySubType.other.map((f: any) => (
                              <tr
                                key={f.id}
                                className="hover:bg-accent/30 transition-colors cursor-pointer"
                                onClick={() => openFinding(f)}
                              >
                                <td className="px-3 py-2.5 w-[80px]"><SeverityBadge severity={getSeverity(f)} /></td>
                                <td className="px-3 py-2.5">
                                  <span className="text-sm text-foreground font-medium truncate">{f.title || "Finding"}</span>
                                </td>
                                <td className="px-3 py-2.5 text-xs text-muted-foreground w-[140px]">{formatDate(f.detectedAt || f.created_at)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Findings section */}
        {job.status === "completed" && findings.length > 0 && (
          <>
            <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-primary" />
              Findings ({filteredFindings.length})
            </h2>

            {/* Severity filter pills */}
            <div className="flex flex-wrap items-center gap-2">
              <button onClick={() => setSeverityFilter("all")}
                className={cn("px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all",
                  severityFilter === "all" ? "bg-primary/15 text-primary border-primary/30" : "bg-card text-muted-foreground border-border hover:border-primary/30")}>
                All ({findings.filter((f) => !f.title?.includes("Exposure Score")).length})
              </button>
              {(["critical", "high", "medium", "low", "info"] as SeverityKey[]).map((sev) => (
                <button key={sev} onClick={() => setSeverityFilter(sev)}
                  className={cn("px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all capitalize",
                    severityFilter === sev
                      ? sev === "critical" ? "bg-red-500/15 text-red-300 border-red-500/30"
                      : sev === "high" ? "bg-orange-500/15 text-orange-300 border-orange-500/30"
                      : sev === "medium" ? "bg-yellow-500/15 text-yellow-300 border-yellow-500/30"
                      : sev === "low" ? "bg-blue-500/15 text-blue-300 border-blue-500/30"
                      : "bg-zinc-500/15 text-zinc-300 border-zinc-500/30"
                      : "bg-card text-muted-foreground border-border hover:border-primary/30")}>
                  {sev} ({severityCounts[sev] || 0})
                </button>
              ))}
            </div>

            {/* Category filter pills */}
            {Object.keys(categoryCounts).length > 1 && (
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-muted-foreground mr-1"><Tag className="w-3.5 h-3.5 inline-block mr-1" />Category:</span>
                <button onClick={() => setCategoryFilter("all")}
                  className={cn("px-2.5 py-1 rounded-md border text-xs font-medium transition-all",
                    categoryFilter === "all" ? "bg-primary/15 text-primary border-primary/30" : "bg-card text-muted-foreground border-border hover:border-primary/30")}>
                  All
                </button>
                {Object.entries(categoryCounts)
                  .filter(([cat]) => cat !== "exposure")
                  .sort(([, a], [, b]) => b - a)
                  .map(([cat, count]) => {
                    const cfg = CATEGORY_CONFIG[cat] || CATEGORY_CONFIG.other;
                    return (
                      <button key={cat} onClick={() => setCategoryFilter(cat)}
                        className={cn("px-2.5 py-1 rounded-md border text-xs font-medium transition-all inline-flex items-center gap-1",
                          categoryFilter === cat ? cfg.color : "bg-card text-muted-foreground border-border hover:border-primary/30")}>
                        {cat === "cloud" && <Cloud className="w-3 h-3" />}
                        {cfg.label} ({count})
                      </button>
                    );
                  })}
              </div>
            )}

            {/* Search */}
            <div className="relative w-full max-w-md">
              <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} placeholder="Search findings…" className="pl-9" />
            </div>

            {/* Findings table */}
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <table className="w-full">
                <thead className="bg-muted/30 border-b border-border">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[100px]">Severity</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Finding</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[110px]">Category</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[150px]">Detected</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredFindings.map((f: any) => {
                    const sev = getSeverity(f);
                    const cat = getCategory(f);
                    const catCfg = CATEGORY_CONFIG[cat] || CATEGORY_CONFIG.other;
                    const title = f.title || "Finding";
                    const hasRemediation = Boolean(f.remediation || f.details?._remediation);
                    const isCloud = cat === "cloud";
                    const cloudSub = isCloud ? getCloudSubType(f) : null;

                    return (
                      <tr key={f.id}
                        className="hover:bg-accent/30 transition-colors cursor-pointer"
                        onClick={() => openFinding(f)}>
                        <td className="px-4 py-3"><SeverityBadge severity={sev} /></td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            {isCloud && <CloudSubIcon subType={cloudSub} />}
                            <div className="min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="text-foreground font-medium truncate" title={title}>{title}</span>
                                {hasRemediation && <span title="Remediation available"><Wrench className="w-3.5 h-3.5 text-emerald-400 shrink-0" /></span>}
                              </div>
                              {f.summary && <div className="text-xs text-muted-foreground mt-0.5 truncate">{f.summary}</div>}
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={cn("inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium", catCfg.color)}>
                            {isCloud && <Cloud className="w-3 h-3" />}
                            {catCfg.label}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm text-muted-foreground">{formatDate(f.detectedAt || f.created_at)}</td>
                      </tr>
                    );
                  })}
                  {filteredFindings.length === 0 && (
                    <tr><td colSpan={4} className="px-4 py-12 text-center text-muted-foreground">
                      No findings match your filters.
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* No findings */}
        {job.status === "completed" && findings.length === 0 && (
          <div className="bg-card border border-border rounded-xl p-12 text-center">
            <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
            <h3 className="text-foreground font-semibold mb-1">No findings detected</h3>
            <p className="text-sm text-muted-foreground">This scan completed without detecting any security issues.</p>
          </div>
        )}
      </div>

      {/* Finding Details Dialog */}
      <FindingDetailsDialog
        open={detailsOpen}
        onOpenChange={setDetailsOpen}
        finding={selected}
        onToggleIgnore={() => {}}
      />
    </div>
  );
}