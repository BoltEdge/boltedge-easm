// FILE: app/(authenticated)/assets/[id]/page.tsx
// Asset Detail Page — individual asset view with scan history, findings, risk
// F5: IntelligenceTabs (tech, SSL, DNS, ports)
// F6: ScanComparison (inline diff between two scans)
"use client";

import React, { useEffect, useMemo, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ChevronLeft, Shield, Clock, CheckCircle2, XCircle, Loader2,
  AlertTriangle, Play, ExternalLink, RefreshCcw, Trash2,
  Globe, Server, Mail, Tag, Search, Eye, MoreVertical,
  ArrowLeftRight, Cloud, Database, Box, Cpu, Radio,
} from "lucide-react";
import { Button } from "../../../ui/button";
import { Input } from "../../../ui/input";
import { SeverityBadge } from "../../../SeverityBadge";
import { StatusBadge } from "../../../StatusBadge";
import IntelligenceTabs from "./IntelligenceTabs";
import ScanComparison from "./ScanComparison";
import {
  apiFetch, getAssetRisk, getScanProfiles, createScanJob, runScanJob,
  getScanJobs, updateAsset, deleteAsset, isPlanError,
} from "../../../lib/api";
import { useOrg } from "../../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../../ui/plan-limit-dialog";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "../../../ui/dialog";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "../../../ui/dropdown-menu";

function cn(...parts: Array<string | false | null | undefined>) { return parts.filter(Boolean).join(" "); }

function formatDate(d?: any) {
  if (!d) return "—";
  let dt: Date;
  if (typeof d === "string" && !d.endsWith("Z") && !d.includes("+")) dt = new Date(d + "Z");
  else dt = d instanceof Date ? d : new Date(d);
  if (isNaN(dt.getTime())) return "—";
  return dt.toLocaleString();
}

function timeAgo(d: any): string {
  if (!d) return "—";
  if (typeof d === "string" && !d.endsWith("Z") && !d.includes("+")) d = d + "Z";
  const date = d instanceof Date ? d : new Date(d);
  if (isNaN(date.getTime())) return "—";
  const diffMs = Date.now() - date.getTime();
  if (diffMs < 0) return "just now";
  const sec = Math.floor(diffMs / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

// ─── Cloud Provider / Category Metadata ──────────────────────

const PROVIDER_LABELS: Record<string, string> = {
  aws_s3: "AWS S3", azure_blob: "Azure Blob Storage", gcs: "Google Cloud Storage",
  acr: "Azure Container Registry", gcr: "Google Container Registry",
  ecr_public: "AWS ECR Public", ecr: "AWS ECR", dockerhub: "Docker Hub",
  azure_functions: "Azure Functions", cloud_run: "Google Cloud Run",
  cloud_functions: "Google Cloud Functions", aws_lambda: "AWS Lambda",
  aws_apigateway: "AWS API Gateway",
  cloudfront: "Amazon CloudFront", azure_cdn: "Azure CDN",
  fastly: "Fastly", akamai: "Akamai",
  other: "Other",
};

const CATEGORY_META: Record<string, { icon: typeof Cloud; color: string; bgColor: string; label: string }> = {
  storage:    { icon: Database, color: "text-blue-400",    bgColor: "bg-blue-500/10 border-blue-500/20",    label: "Storage Bucket" },
  registry:   { icon: Box,      color: "text-purple-400",  bgColor: "bg-purple-500/10 border-purple-500/20", label: "Container Registry" },
  serverless: { icon: Cpu,      color: "text-emerald-400", bgColor: "bg-emerald-500/10 border-emerald-500/20", label: "Serverless Endpoint" },
  cdn:        { icon: Radio,    color: "text-amber-400",   bgColor: "bg-amber-500/10 border-amber-500/20",   label: "CDN / Edge" },
};

function getTypeIcon(type: string) {
  switch ((type || "").toLowerCase()) {
    case "ip": return Server;
    case "email": return Mail;
    case "cloud": return Cloud;
    default: return Globe;
  }
}

function getTypeIconColor(type: string) {
  switch ((type || "").toLowerCase()) {
    case "cloud": return "text-sky-400";
    default: return "text-[#00b8d4]";
  }
}

function jobStatusBadge(status: string) {
  switch (status) {
    case "completed": return "bg-[#10b981]/10 text-[#10b981]";
    case "running": return "bg-[#00b8d4]/10 text-[#00b8d4]";
    case "queued": return "bg-[#ffcc00]/10 text-[#ffcc00]";
    case "failed": return "bg-red-500/10 text-red-400";
    default: return "bg-muted/30 text-muted-foreground";
  }
}

function jobStatusIcon(status: string) {
  switch (status) {
    case "completed": return CheckCircle2;
    case "running": return Loader2;
    case "queued": return Clock;
    case "failed": return XCircle;
    default: return Clock;
  }
}

type SeverityKey = "critical" | "high" | "medium" | "low" | "info";

export default function AssetDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const assetId = params.id;
  const { canDo } = useOrg();
  const planLimit = usePlanLimit();
  const canScan = canDo("start_scans");

  const [asset, setAsset] = useState<any>(null);
  const [risk, setRisk] = useState<any>(null);
  const [scanJobs, setScanJobs] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [profiles, setProfiles] = useState<any[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState("");
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  // Findings filters
  const [sevFilter, setSevFilter] = useState<"all" | SeverityKey>("all");
  const [findingSearch, setFindingSearch] = useState("");

  // Edit/delete modals
  const [editOpen, setEditOpen] = useState(false);
  const [editValue, setEditValue] = useState("");
  const [editLabel, setEditLabel] = useState("");
  const [saving, setSaving] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);

  // F6: Scan comparison
  const [compareOpen, setCompareOpen] = useState(false);

  const loadAll = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      let assetData: any = null;
      try {
        assetData = await apiFetch(`/assets/${assetId}`);
      } catch {
        try {
          const allAssets = await apiFetch<any[]>("/assets");
          assetData = allAssets?.find((a: any) => String(a.id) === String(assetId));
        } catch {}
      }

      if (!assetData) {
        setError("Asset not found");
        return;
      }
      setAsset(assetData);

      const [riskData, allJobs, profs] = await Promise.all([
        getAssetRisk(assetId).catch(() => null),
        getScanJobs().catch(() => []),
        getScanProfiles().catch(() => []),
      ]);

      setRisk(riskData);
      setProfiles(profs);

      const assetJobs = (allJobs || []).filter((j: any) => String(j.assetId) === String(assetId));
      setScanJobs(assetJobs);

      const latestCompleted = assetJobs.find((j: any) => j.status === "completed");
      if (latestCompleted) {
        try {
          const f = await apiFetch<any[]>(`/scan-jobs/${latestCompleted.id}/findings`);
          setFindings(f || []);
        } catch { setFindings([]); }
      }

      if (!selectedProfileId && profs.length) {
        const def = profs.find((p: any) => p.isDefault);
        setSelectedProfileId(def ? def.id : profs[0].id);
      }
    } catch (e: any) {
      setError(e?.message || "Failed to load asset");
    } finally {
      setLoading(false);
    }
  }, [assetId]);

  useEffect(() => { loadAll(); }, [loadAll]);
  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 5000); return () => clearTimeout(t); } }, [banner]);

  // Auto-refresh if scan running
  useEffect(() => {
    if (!scanJobs.some((j) => j.status === "running" || j.status === "queued")) return;
    const iv = setInterval(loadAll, 5000);
    return () => clearInterval(iv);
  }, [scanJobs, loadAll]);

  async function handleScan() {
    try {
      setScanning(true);
      const job = await createScanJob(assetId, selectedProfileId || undefined);
      await runScanJob(String(job.id));
      setBanner({ kind: "ok", text: "Scan started!" });
      loadAll();
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed to start scan" });
    } finally { setScanning(false); }
  }

  async function handleSave() {
    if (!editValue.trim()) return;
    setSaving(true);
    try {
      const updated = await updateAsset(assetId, { value: editValue.trim(), label: editLabel.trim() || null });
      setAsset(updated);
      setEditOpen(false);
      setBanner({ kind: "ok", text: "Asset updated" });
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed" }); }
    finally { setSaving(false); }
  }

  async function handleDelete() {
    setDeleting(true);
    try {
      await deleteAsset(assetId);
      setBanner({ kind: "ok", text: "Asset deleted" });
      setTimeout(() => router.push("/assets"), 500);
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed" }); }
    finally { setDeleting(false); }
  }

  // Severity counts
  const sevCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of findings) {
      const s = (f.severity || "info").toLowerCase();
      c[s] = (c[s] || 0) + 1;
    }
    return c;
  }, [findings]);

  const filteredFindings = useMemo(() => {
    let items = findings.filter((f) => !f.title?.includes("Exposure Score"));
    if (sevFilter !== "all") items = items.filter((f) => (f.severity || "info").toLowerCase() === sevFilter);
    if (findingSearch.trim()) {
      const q = findingSearch.toLowerCase();
      items = items.filter((f) => (f.title || "").toLowerCase().includes(q) || (f.description || "").toLowerCase().includes(q));
    }
    return items;
  }, [findings, sevFilter, findingSearch]);

  const completedScanCount = useMemo(() => scanJobs.filter((j) => j.status === "completed").length, [scanJobs]);

  if (loading) {
    return (
      <div className="flex-1 bg-background p-8">
        <div className="flex items-center justify-center gap-2 text-muted-foreground py-20">
          <Loader2 className="w-5 h-5 animate-spin" />Loading asset…
        </div>
      </div>
    );
  }

  if (error || !asset) {
    return (
      <div className="flex-1 bg-background p-8">
        <button onClick={() => router.back()} className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-6">
          <ChevronLeft className="w-4 h-4" />Back
        </button>
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {error || "Asset not found"}
        </div>
      </div>
    );
  }

  const assetType = (asset.type || asset.assetType || "domain").toLowerCase();
  const isCloud = assetType === "cloud";
  const TypeIcon = getTypeIcon(assetType);
  const typeIconColor = getTypeIconColor(assetType);
  const groupName = asset.groupName || asset.group_name || (scanJobs[0]?.groupName);
  const groupId = asset.groupId || asset.group_id || (scanJobs[0]?.groupId);
  const lastScan = asset.lastScanAt || asset.last_scan_at || asset.lastScan;
  const latestJob = scanJobs.find((j) => j.status === "completed");
  const lastScanTime = latestJob?.finishedAt || latestJob?.startedAt || lastScan;
  const isRunning = scanJobs.some((j) => j.status === "running" || j.status === "queued");

  // Cloud-specific
  const provider = asset.provider;
  const cloudCategory = asset.cloudCategory || asset.cloud_category;
  const catMeta = isCloud ? (CATEGORY_META[cloudCategory] || CATEGORY_META.storage) : null;

  return (
    <div className="flex-1 bg-background overflow-auto">
      <div className="p-8 space-y-6">

        {/* Breadcrumb */}
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/assets" className="hover:text-foreground flex items-center gap-1">
            <ChevronLeft className="w-4 h-4" />Asset Groups
          </Link>
          {groupName && (
            <>
              <span>›</span>
              <Link href={`/groups/${groupId}`} className="hover:text-foreground">{groupName}</Link>
            </>
          )}
          <span>›</span>
          <span className="text-foreground/90 font-mono">{asset.value}</span>
        </div>

        {banner && (
          <div className={cn("rounded-xl border px-4 py-3 text-sm",
            banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>
            {banner.text}
          </div>
        )}

        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <div className={cn("w-10 h-10 rounded-xl flex items-center justify-center",
                isCloud ? "bg-sky-500/10" : "bg-[#00b8d4]/10")}>
                <TypeIcon className={cn("w-5 h-5", typeIconColor)} />
              </div>
              <div>
                <h1 className="text-2xl font-semibold text-foreground font-mono">{asset.value}</h1>
                <div className="flex items-center gap-3 mt-0.5 text-sm text-muted-foreground flex-wrap">
                  <span className={cn("inline-flex items-center gap-1 rounded-md bg-accent px-2 py-0.5 text-xs font-medium text-foreground/90 uppercase",
                    isCloud && "gap-1")}>
                    {isCloud && <Cloud className="w-3 h-3 text-sky-400" />}
                    {assetType.toUpperCase()}
                  </span>
                  {/* Cloud provider + category badges */}
                  {isCloud && provider && (
                    <span className="inline-flex items-center gap-1 rounded-md bg-accent/60 border border-border px-2 py-0.5 text-xs font-medium text-foreground/80">
                      {PROVIDER_LABELS[provider] || provider}
                    </span>
                  )}
                  {isCloud && catMeta && (
                    <span className={cn("inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium", catMeta.bgColor)}>
                      <catMeta.icon className={cn("w-3 h-3", catMeta.color)} />
                      {catMeta.label}
                    </span>
                  )}
                  {asset.label && <span className="flex items-center gap-1"><Tag className="w-3 h-3" />{asset.label}</span>}
                  {groupName && <span>Group: <Link href={`/groups/${groupId}`} className="text-primary hover:underline">{groupName}</Link></span>}
                </div>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {canScan && (
              <div className="flex items-center gap-2">
                <select value={selectedProfileId} onChange={(e) => setSelectedProfileId(e.target.value)}
                  className="h-9 rounded-md border border-border bg-background px-2 text-xs text-foreground outline-none">
                  {profiles.map((p: any) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
                <Button onClick={handleScan} disabled={scanning || isRunning} className="bg-[#00b8d4] hover:bg-[#00b8d4]/90">
                  {scanning || isRunning ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Scanning...</> : <><Play className="w-4 h-4 mr-2" />Scan</>}
                </Button>
              </div>
            )}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="h-9 w-9 p-0"><MoreVertical className="w-4 h-4" /></Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => { setEditValue(asset.value || ""); setEditLabel(asset.label || ""); setEditOpen(true); }}>Edit asset</DropdownMenuItem>
                <DropdownMenuItem onClick={() => loadAll()}><RefreshCcw className="w-3.5 h-3.5 mr-2" />Refresh</DropdownMenuItem>
                <DropdownMenuItem variant="destructive" onClick={() => setDeleteOpen(true)}>Delete asset</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        {/* Cloud Info Card — only for cloud assets */}
        {isCloud && (
          <div className={cn("border rounded-xl p-5", catMeta?.bgColor || "bg-sky-500/10 border-sky-500/20")}>
            <div className="flex items-center gap-3 mb-3">
              {catMeta && <catMeta.icon className={cn("w-5 h-5", catMeta.color)} />}
              <h3 className="text-sm font-semibold text-foreground">Cloud Resource Details</h3>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <div className="text-xs text-muted-foreground mb-0.5">Provider</div>
                <div className="text-foreground font-medium">{PROVIDER_LABELS[provider] || provider || "Unknown"}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-0.5">Category</div>
                <div className="text-foreground font-medium">{catMeta?.label || cloudCategory || "Storage"}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-0.5">URL</div>
                <div className="text-foreground font-mono text-xs truncate max-w-[200px]" title={asset.value}>{asset.value}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-0.5">Scan Mode</div>
                <div className="text-foreground font-medium">Direct Probe</div>
              </div>
            </div>
          </div>
        )}

        {/* Stats cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="text-xs text-muted-foreground mb-1">Risk Level</div>
            {risk ? (
              <div className="flex items-center gap-2">
                <SeverityBadge severity={risk.maxSeverity || "info"} />
                <span className="text-sm text-muted-foreground">{risk.openFindings || 0} findings</span>
              </div>
            ) : (
              <div className="text-sm text-muted-foreground">{lastScan ? "Clean" : "Not scanned"}</div>
            )}
          </div>
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="text-xs text-muted-foreground mb-1">Total Findings</div>
            <div className="text-2xl font-bold text-foreground">{findings.length}</div>
          </div>
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="text-xs text-muted-foreground mb-1">Scan History</div>
            <div className="text-2xl font-bold text-foreground">{scanJobs.length}</div>
            <div className="text-xs text-muted-foreground">{completedScanCount} completed</div>
          </div>
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="text-xs text-muted-foreground mb-1">Last Scan</div>
            <div className="text-sm font-semibold text-foreground">{timeAgo(lastScanTime)}</div>
          </div>
        </div>

        {/* Severity breakdown */}
        {risk && risk.bySeverity && (
          <div className="bg-card border border-border rounded-xl p-5">
            <h3 className="text-sm font-semibold text-foreground mb-3">Finding Severity Breakdown</h3>
            <div className="flex flex-wrap gap-3">
              {(["critical", "high", "medium", "low", "info"] as SeverityKey[]).map((sev) => {
                const count = risk.bySeverity[sev] || 0;
                if (count === 0) return null;
                const colors: Record<string, string> = {
                  critical: "bg-red-500/15 text-red-300 border-red-500/30",
                  high: "bg-orange-500/15 text-orange-300 border-orange-500/30",
                  medium: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
                  low: "bg-blue-500/15 text-blue-300 border-blue-500/30",
                  info: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
                };
                return (
                  <span key={sev} className={cn("px-3 py-1.5 rounded-lg border text-xs font-semibold capitalize", colors[sev])}>
                    {count} {sev}
                  </span>
                );
              })}
            </div>
          </div>
        )}

        {/* ═══ Asset Intelligence ═══ */}
        <IntelligenceTabs assetId={assetId} />

        {/* Running scan indicator */}
        {isRunning && (
          <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-xl p-5 flex items-center gap-4">
            <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
            <div>
              <div className="text-foreground font-semibold">Scan in progress…</div>
              <div className="text-sm text-muted-foreground">This page will automatically update when the scan completes.</div>
            </div>
          </div>
        )}

        {/* Scan History */}
        {scanJobs.length > 0 && (
          <>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                <Clock className="w-5 h-5 text-primary" />Scan History ({scanJobs.length})
              </h2>
              {completedScanCount >= 2 && (
                <Button size="sm" variant="outline" onClick={() => setCompareOpen(!compareOpen)}
                  className="text-xs gap-1.5">
                  <ArrowLeftRight className="w-3.5 h-3.5" />
                  {compareOpen ? "Hide Comparison" : "Compare Scans"}
                </Button>
              )}
            </div>

            {/* F6: Scan Comparison (inline) */}
            {compareOpen && (
              <ScanComparison
                assetId={assetId}
                scanJobs={scanJobs}
                onClose={() => setCompareOpen(false)}
              />
            )}

            <div className="bg-card border border-border rounded-xl overflow-hidden">
              <table className="w-full">
                <thead className="bg-muted/30">
                  <tr>
                    <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase">Status</th>
                    <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase">Profile</th>
                    <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase">Started</th>
                    <th className="text-left p-4 text-xs font-semibold text-muted-foreground uppercase">Completed</th>
                    <th className="text-right p-4 text-xs font-semibold text-muted-foreground uppercase">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {scanJobs.slice(0, 10).map((job) => {
                    const SIcon = jobStatusIcon(job.status);
                    return (
                      <tr key={job.id} className="hover:bg-accent/30 transition-colors">
                        <td className="p-4">
                          <span className={cn("inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-semibold", jobStatusBadge(job.status))}>
                            <SIcon className={cn("w-3 h-3", job.status === "running" && "animate-spin")} />{job.status}
                          </span>
                        </td>
                        <td className="p-4 text-sm text-muted-foreground">{job.profileName || "—"}</td>
                        <td className="p-4 text-sm text-muted-foreground">{formatDate(job.startedAt || job.createdAt)}</td>
                        <td className="p-4 text-sm text-muted-foreground">{job.finishedAt ? formatDate(job.finishedAt) : job.status === "running" ? "In progress…" : "—"}</td>
                        <td className="p-4 text-right">
                          {job.status === "completed" && (
                            <Button size="sm" variant="outline" onClick={() => router.push(`/scan-jobs/${job.id}`)}
                              className="border-primary/50 text-primary hover:bg-primary/10">
                              <ExternalLink className="w-3 h-3 mr-1" />View Results
                            </Button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* Findings */}
        {findings.length > 0 && (
          <>
            <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-primary" />Findings ({filteredFindings.length})
            </h2>

            {/* Severity filter pills */}
            <div className="flex flex-wrap items-center gap-2">
              <button onClick={() => setSevFilter("all")}
                className={cn("px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all",
                  sevFilter === "all" ? "bg-primary/15 text-primary border-primary/30" : "bg-card text-muted-foreground border-border hover:border-primary/30")}>
                All ({findings.filter((f) => !f.title?.includes("Exposure Score")).length})
              </button>
              {(["critical", "high", "medium", "low", "info"] as SeverityKey[]).map((sev) => {
                const count = sevCounts[sev] || 0;
                if (!count) return null;
                const activeColors: Record<string, string> = {
                  critical: "bg-red-500/15 text-red-300 border-red-500/30",
                  high: "bg-orange-500/15 text-orange-300 border-orange-500/30",
                  medium: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
                  low: "bg-blue-500/15 text-blue-300 border-blue-500/30",
                  info: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
                };
                return (
                  <button key={sev} onClick={() => setSevFilter(sev)}
                    className={cn("px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all capitalize",
                      sevFilter === sev ? activeColors[sev] : "bg-card text-muted-foreground border-border hover:border-primary/30")}>
                    {sev} ({count})
                  </button>
                );
              })}
            </div>

            <div className="relative w-full max-w-md">
              <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input value={findingSearch} onChange={(e) => setFindingSearch(e.target.value)} placeholder="Search findings…" className="pl-9" />
            </div>

            <div className="bg-card border border-border rounded-xl overflow-hidden">
              <table className="w-full">
                <thead className="bg-muted/30">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[100px]">Severity</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Finding</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[150px]">Detected</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredFindings.map((f: any) => (
                    <tr key={f.id} className="hover:bg-accent/30 transition-colors cursor-pointer"
                      onClick={() => latestJob && router.push(`/scan-jobs/${latestJob.id}`)}>
                      <td className="px-4 py-3"><SeverityBadge severity={(f.severity || "info").toLowerCase()} /></td>
                      <td className="px-4 py-3">
                        <div className="text-foreground font-medium text-sm">{f.title || "Finding"}</div>
                        {f.description && <div className="text-xs text-muted-foreground mt-0.5 truncate max-w-lg">{f.description}</div>}
                      </td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">{formatDate(f.detectedAt || f.created_at)}</td>
                    </tr>
                  ))}
                  {filteredFindings.length === 0 && (
                    <tr><td colSpan={3} className="px-4 py-8 text-center text-muted-foreground">No findings match your filters.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* No scans yet */}
        {!lastScanTime && !isRunning && scanJobs.length === 0 && (
          <div className="bg-card border border-border rounded-xl p-12 text-center">
            <Shield className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
            <h3 className="text-foreground font-semibold mb-1">No scans yet</h3>
            <p className="text-sm text-muted-foreground mb-4">
              {isCloud
                ? "Run a scan to probe this cloud resource for public exposure and misconfigurations."
                : "Run a scan to discover vulnerabilities for this asset."}
            </p>
            {canScan && (
              <Button onClick={handleScan} disabled={scanning} className="bg-[#00b8d4] hover:bg-[#00b8d4]/90">
                <Play className="w-4 h-4 mr-2" />{isCloud ? "Probe Cloud Asset" : "Scan Now"}
              </Button>
            )}
          </div>
        )}

        {/* Edit dialog */}
        <Dialog open={editOpen} onOpenChange={setEditOpen}>
          <DialogContent className="bg-card border-border text-foreground sm:max-w-md">
            <DialogHeader><DialogTitle>Edit Asset</DialogTitle></DialogHeader>
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium text-foreground mb-2 block">
                  {isCloud ? "Cloud Resource URL" : "Value"}
                </label>
                <Input value={editValue} onChange={(e) => setEditValue(e.target.value)} />
              </div>
              <div>
                <label className="text-sm font-medium text-foreground mb-2 block">Label (optional)</label>
                <Input value={editLabel} onChange={(e) => setEditLabel(e.target.value)} placeholder="e.g. Main Website" />
              </div>
              <div className="flex gap-3 justify-end">
                <Button variant="outline" onClick={() => setEditOpen(false)}>Cancel</Button>
                <Button onClick={handleSave} disabled={saving || !editValue.trim()} className="bg-primary hover:bg-primary/90">
                  {saving ? "Saving…" : "Save"}
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>

        {/* Delete dialog */}
        <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
          <DialogContent className="bg-card border-border text-foreground sm:max-w-md">
            <DialogHeader><DialogTitle>Delete Asset</DialogTitle></DialogHeader>
            <p className="text-sm text-muted-foreground">
              Delete <span className="text-foreground font-semibold font-mono">{asset.value}</span>? This will also remove all scan history and findings. This cannot be undone.
            </p>
            <div className="flex gap-3 justify-end">
              <Button variant="outline" onClick={() => setDeleteOpen(false)}>Cancel</Button>
              <Button onClick={handleDelete} disabled={deleting} className="bg-red-500 hover:bg-red-600 text-white">
                {deleting ? "Deleting…" : "Delete Asset"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <PlanLimitDialog {...planLimit} />
    </div>
  );
}