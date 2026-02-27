"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import {
  ChevronLeft, MoreVertical, Plus, Play, FileText, X, Search,
  Eye, Shield, Zap, ShieldCheck, ShieldAlert, AlertTriangle,
  Layers, Clock, Target, TrendingUp, CheckSquare, Square,
  Trash2, ArrowRightLeft, Cloud, Database, Box, Cpu, Radio,
} from "lucide-react";

import type { Asset, AssetGroup, AssetType, ScanProfile } from "../../../types";
import {
  getGroups, getGroupAssets, addAssetToGroup, createScanJob, runScanJob,
  updateAsset, deleteAsset, getAssetRisk, getScanProfiles, apiFetch,
  bulkAddAssets,
} from "../../../lib/api";

import { Button } from "../../../ui/button";
import { Input } from "../../../ui/input";
import { Label } from "../../../ui/label";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "../../../ui/dropdown-menu";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../../ui/dialog";
import { SeverityBadge } from "../../../SeverityBadge";
import { StatusBadge } from "../../../StatusBadge";

// ─── Types ──────────────────────────────────────

type AssetRisk = {
  assetId: string; type: string; value: string; openFindings: number;
  bySeverity: { critical: number; high: number; medium: number; low: number; info: number };
  maxSeverity: "critical" | "high" | "medium" | "low" | "info";
  totalFindings?: number;
};

type RiskFilter = "all" | "no_issues" | "critical" | "high" | "medium" | "low" | "info" | "not_scanned";

// ─── Cloud Provider Detection (client-side, mirrors backend) ──────

type CloudDetection = { provider: string; category: string; label: string } | null;

const CLOUD_PATTERNS: Array<{ pattern: RegExp; provider: string; category: string; label: string }> = [
  // Storage
  { pattern: /\.s3[.\-]amazonaws\.com/i,         provider: "aws_s3",         category: "storage",    label: "AWS S3" },
  { pattern: /^s3:\/\//i,                         provider: "aws_s3",         category: "storage",    label: "AWS S3" },
  { pattern: /\.blob\.core\.windows\.net/i,       provider: "azure_blob",     category: "storage",    label: "Azure Blob" },
  { pattern: /storage\.googleapis\.com/i,         provider: "gcs",            category: "storage",    label: "Google Cloud Storage" },
  { pattern: /^gs:\/\//i,                         provider: "gcs",            category: "storage",    label: "Google Cloud Storage" },
  // Registries
  { pattern: /\.azurecr\.io/i,                    provider: "acr",            category: "registry",   label: "Azure Container Registry" },
  { pattern: /gcr\.io\//i,                        provider: "gcr",            category: "registry",   label: "Google Container Registry" },
  { pattern: /\.pkg\.dev/i,                       provider: "gcr",            category: "registry",   label: "Google Artifact Registry" },
  { pattern: /public\.ecr\.aws/i,                 provider: "ecr_public",     category: "registry",   label: "AWS ECR Public" },
  { pattern: /\.dkr\.ecr\./i,                     provider: "ecr",            category: "registry",   label: "AWS ECR" },
  { pattern: /hub\.docker\.com/i,                 provider: "dockerhub",      category: "registry",   label: "Docker Hub" },
  { pattern: /docker\.io\//i,                     provider: "dockerhub",      category: "registry",   label: "Docker Hub" },
  // Serverless
  { pattern: /\.azurewebsites\.net/i,             provider: "azure_functions", category: "serverless", label: "Azure Functions" },
  { pattern: /\.run\.app/i,                       provider: "cloud_run",      category: "serverless", label: "Google Cloud Run" },
  { pattern: /\.cloudfunctions\.net/i,            provider: "cloud_functions", category: "serverless", label: "Google Cloud Functions" },
  { pattern: /\.lambda-url\./i,                   provider: "aws_lambda",     category: "serverless", label: "AWS Lambda" },
  { pattern: /\.execute-api\./i,                  provider: "aws_apigateway", category: "serverless", label: "AWS API Gateway" },
  // CDN
  { pattern: /\.cloudfront\.net/i,                provider: "cloudfront",     category: "cdn",        label: "CloudFront" },
  { pattern: /\.azureedge\.net/i,                 provider: "azure_cdn",      category: "cdn",        label: "Azure CDN" },
  { pattern: /\.fastly\.net/i,                    provider: "fastly",         category: "cdn",        label: "Fastly" },
  { pattern: /\.akamaiedge\.net/i,                provider: "akamai",         category: "cdn",        label: "Akamai" },
];

function detectCloudProvider(url: string): CloudDetection {
  if (!url || url.trim().length < 5) return null;
  for (const { pattern, provider, category, label } of CLOUD_PATTERNS) {
    if (pattern.test(url)) return { provider, category, label };
  }
  return null;
}

const CATEGORY_META: Record<string, { icon: typeof Cloud; color: string; label: string }> = {
  storage:    { icon: Database, color: "text-blue-400",   label: "Storage Bucket" },
  registry:   { icon: Box,      color: "text-purple-400", label: "Container Registry" },
  serverless: { icon: Cpu,      color: "text-emerald-400", label: "Serverless Endpoint" },
  cdn:        { icon: Radio,    color: "text-amber-400",  label: "CDN / Edge" },
};

// ─── Helpers ──────────────────────────────────────

function cn(...classes: Array<string | undefined | null | false>) { return classes.filter(Boolean).join(" "); }

function safeDate(v: any): Date | null {
  if (!v) return null;
  if (typeof v === "string" && !v.endsWith("Z") && !v.includes("+")) v = v + "Z";
  const d = v instanceof Date ? v : new Date(v);
  return isNaN(d.getTime()) ? null : d;
}

function timeAgo(d: Date): string {
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 20) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

function formatLastScan(v: any) { const d = safeDate(v); if (!d) return { short: "Never", full: "" }; return { short: timeAgo(d), full: d.toLocaleString() }; }

function normalize(s: string) { return (s || "").toLowerCase().trim(); }

function matchesRiskFilter(filter: RiskFilter, riskByAssetId: Record<string, AssetRisk | undefined>, asset: Asset) {
  if (filter === "all") return true;
  const lastScan = (asset as any).lastScanAt ?? (asset as any).lastScan;
  const status = String((asset as any).status || "").toLowerCase();
  if (filter === "not_scanned") return !lastScan || status === "not_scanned";
  const r = riskByAssetId[String(asset.id)];
  if (!r) return false;
  if (filter === "no_issues") return (r.totalFindings ?? r.openFindings ?? 0) <= 0;
  return r.maxSeverity === filter;
}

function getAssetStatus(asset: Asset): string { return String((asset as any).status || "").toLowerCase() || "not_scanned"; }
function getScanButtonLabel(status: string) { if (status === "running") return "Scanning…"; if (status === "queued") return "Queued"; if (status === "failed") return "Retry"; if (status === "completed") return "Re-scan"; return "Scan"; }
function getAssetPlaceholder(type: AssetType) {
  switch (type) {
    case "ip": return "e.g., 8.8.8.8";
    case "email": return "e.g., security@example.com";
    case "cloud": return "e.g., https://mybucket.s3.amazonaws.com";
    default: return "e.g., example.com";
  }
}

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-blue-500", info: "bg-zinc-500",
};

const SEV_TEXT: Record<string, string> = {
  critical: "text-red-300", high: "text-orange-300", medium: "text-yellow-300", low: "text-blue-300", info: "text-zinc-300",
};

// ─── Cloud Provider Badge ──────────────────────────────────────

function CloudProviderBadge({ provider, category, className }: { provider?: string; category?: string; className?: string }) {
  if (!provider && !category) return null;
  const catMeta = CATEGORY_META[category || "storage"] || CATEGORY_META.storage;
  const CatIcon = catMeta.icon;

  // Nice label for the provider
  const providerLabels: Record<string, string> = {
    aws_s3: "S3", azure_blob: "Azure Blob", gcs: "GCS",
    acr: "ACR", gcr: "GCR", ecr_public: "ECR", ecr: "ECR", dockerhub: "Docker Hub",
    azure_functions: "Azure Func", cloud_run: "Cloud Run", cloud_functions: "Cloud Func",
    aws_lambda: "Lambda", aws_apigateway: "API GW",
    cloudfront: "CloudFront", azure_cdn: "Azure CDN", fastly: "Fastly", akamai: "Akamai",
  };

  return (
    <span className={cn("inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-accent/60 border border-border", className)}>
      <CatIcon className={cn("w-3 h-3", catMeta.color)} />
      <span className="text-foreground/80">{providerLabels[provider || ""] || provider || catMeta.label}</span>
    </span>
  );
}

// ─── Asset Type Display (with cloud icon) ──────────────────────

function AssetTypeBadge({ asset }: { asset: any }) {
  const type = String(asset.type || asset.asset_type || "domain").toLowerCase();

  if (type === "cloud") {
    return (
      <span className="inline-flex items-center gap-1 rounded-md bg-accent px-2 py-0.5 text-xs font-medium text-foreground/90">
        <Cloud className="w-3 h-3 text-sky-400" />CLOUD
      </span>
    );
  }

  return (
    <span className="inline-flex items-center rounded-md bg-accent px-2 py-0.5 text-xs font-medium text-foreground/90">
      {type.toUpperCase()}
    </span>
  );
}

// ─── Mini Dashboard Component ──────────────────────────────────────

function GroupMiniDashboard({ groupId }: { groupId: string }) {
  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    apiFetch<any>(`/groups/${groupId}/summary`)
      .then(setSummary)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [groupId]);

  if (loading) return <div className="h-40 bg-card border border-border rounded-xl animate-pulse" />;
  if (!summary) return null;

  const { assets: a, findings: f, scans: s, topRiskyAssets } = summary;
  const sevs = f?.bySeverity || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const totalFindings = f?.total || 0;
  const critHigh = (sevs.critical || 0) + (sevs.high || 0);

  return (
    <div className="space-y-4">
      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard icon={<Layers className="w-5 h-5 text-primary" />} label="Total Assets" value={a?.total || 0} sub={`${a?.scanned || 0} scanned`} />
        <StatCard icon={<AlertTriangle className="w-5 h-5 text-amber-400" />} label="Open Findings" value={totalFindings}
          sub={totalFindings === 0 ? "Clean" : undefined}
          subColor={totalFindings === 0 ? "text-emerald-400" : undefined} />
        <StatCard icon={<ShieldAlert className="w-5 h-5 text-red-400" />} label="Critical + High" value={critHigh}
          sub={critHigh > 0 ? "Requires attention" : "None"}
          subColor={critHigh > 0 ? "text-red-400" : "text-emerald-400"} />
        <StatCard icon={<Clock className="w-5 h-5 text-blue-400" />} label="Last Scan"
          value={s?.lastScanAt ? timeAgo(safeDate(s.lastScanAt)!) : "Never"}
          isText sub={`${s?.completed || 0} completed`} />
      </div>

      {/* Severity Bar + Top Risky */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {/* Severity Breakdown */}
        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-xs font-semibold text-muted-foreground uppercase mb-3">Finding Severity Breakdown</h3>
          {totalFindings === 0 ? (
            <div className="text-sm text-muted-foreground flex items-center gap-2"><Shield className="w-4 h-4 text-emerald-400" />No open findings</div>
          ) : (
            <div className="space-y-2">
              {/* Bar */}
              <div className="flex h-3 rounded-full overflow-hidden bg-muted/30 w-full">
                {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
                  const count = sevs[sev] || 0;
                  if (count === 0) return null;
                  return <div key={sev} className={cn(SEV_COLORS[sev], "h-full")} style={{ width: `${(count / totalFindings) * 100}%` }} />;
                })}
              </div>
              {/* Legend */}
              <div className="flex flex-wrap gap-x-4 gap-y-1">
                {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
                  const count = sevs[sev] || 0;
                  if (count === 0) return null;
                  return (
                    <div key={sev} className="flex items-center gap-1.5 text-xs">
                      <div className={cn("w-2.5 h-2.5 rounded-full", SEV_COLORS[sev])} />
                      <span className="text-muted-foreground capitalize">{sev}</span>
                      <span className={cn("font-semibold", SEV_TEXT[sev])}>{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Top Risky Assets */}
        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-xs font-semibold text-muted-foreground uppercase mb-3">Top Risky Assets</h3>
          {!topRiskyAssets?.length ? (
            <div className="text-sm text-muted-foreground flex items-center gap-2"><Shield className="w-4 h-4 text-emerald-400" />All assets are clean</div>
          ) : (
            <div className="space-y-2">
              {topRiskyAssets.slice(0, 3).map((ra: any) => (
                <Link key={ra.assetId} href={`/assets/${ra.assetId}`} className="flex items-center justify-between py-1.5 hover:bg-accent/30 rounded-md px-2 -mx-2 transition-colors">
                  <div className="flex items-center gap-2 min-w-0">
                    <SeverityBadge severity={ra.maxSeverity} />
                    <span className="text-sm font-mono text-foreground truncate">{ra.value}</span>
                  </div>
                  <span className="text-xs text-muted-foreground shrink-0">{ra.findingCount} finding{ra.findingCount !== 1 ? "s" : ""}</span>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, sub, subColor, isText }: { icon: React.ReactNode; label: string; value: any; sub?: string; subColor?: string; isText?: boolean }) {
  return (
    <div className="bg-card border border-border rounded-xl p-4">
      <div className="flex items-center gap-2 mb-2">{icon}<span className="text-xs font-semibold text-muted-foreground uppercase">{label}</span></div>
      <div className={cn("font-bold", isText ? "text-lg" : "text-2xl", "text-foreground")}>{value}</div>
      {sub && <p className={cn("text-xs mt-0.5", subColor || "text-muted-foreground")}>{sub}</p>}
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────

export default function AssetGroupDetailsPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const groupId = params.id;

  const [groups, setGroups] = useState<AssetGroup[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [riskByAssetId, setRiskByAssetId] = useState<Record<string, AssetRisk | undefined>>({});
  const [riskLoading, setRiskLoading] = useState(false);
  const [scanningIds, setScanningIds] = useState<Record<string, boolean>>({});

  // Scan profiles
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<string>("");

  // Bulk selection
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Add/Edit/Delete modals
  const [addOpen, setAddOpen] = useState(false);
  const [assetType, setAssetType] = useState<AssetType>("domain");
  const [assetValue, setAssetValue] = useState("");
  const [assetLabel, setAssetLabel] = useState("");
  const [addError, setAddError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const [editOpen, setEditOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);
  const [editValue, setEditValue] = useState("");
  const [editLabel, setEditLabel] = useState("");
  const [editError, setEditError] = useState<string | null>(null);
  const [savingEdit, setSavingEdit] = useState(false);

  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deletingAsset, setDeletingAsset] = useState<Asset | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Bulk delete
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const [bulkDeleting, setBulkDeleting] = useState(false);

  // Bulk add
  const [bulkAddOpen, setBulkAddOpen] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const [bulkLabel, setBulkLabel] = useState("");
  const [bulkType, setBulkType] = useState<"domain" | "ip" | "email" | "cloud" | "auto">("auto");
  const [bulkResults, setBulkResults] = useState<any>(null);
  const [bulkAdding, setBulkAdding] = useState(false);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const group = useMemo(() => groups.find((g) => String(g.id) === String(groupId)), [groups, groupId]);

  // Cloud provider auto-detection for the Add modal
  const cloudDetection = useMemo(() => {
    if (assetType !== "cloud") return null;
    return detectCloudProvider(assetValue);
  }, [assetType, assetValue]);

  // Auto-clear banner
  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 5000); return () => clearTimeout(t); } }, [banner]);

  // Parse bulk text into items
  function parseBulkText(text: string) {
    return text
      .split(/[\n,;]+/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((value) => ({ value }));
  }

  async function onBulkAdd() {
    const items = parseBulkText(bulkText).map((item) => ({
      ...item,
      type: bulkType !== "auto" ? bulkType : undefined,
      label: bulkLabel.trim() || undefined,
    }));
    if (items.length === 0) return;
    try {
      setBulkAdding(true);
      const result = await bulkAddAssets(groupId, items);
      setBulkResults(result);
      if (result.added > 0) {
        const refreshed = await getGroupAssets(groupId);
        setAssets(refreshed);
        setBanner({ kind: "ok", text: `${result.added} asset${result.added !== 1 ? "s" : ""} added${result.skipped ? `, ${result.skipped} skipped` : ""}${result.errors ? `, ${result.errors} invalid` : ""}` });
      }
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Bulk add failed" });
    } finally {
      setBulkAdding(false);
    }
  }

  const loadPage = async () => {
    setLoading(true);
    try {
      const [g, a, p] = await Promise.all([getGroups(), getGroupAssets(groupId), getScanProfiles()]);
      setGroups(g); setAssets(a);
      const order = (name: string) => { const n = name.toLowerCase(); if (n.includes("quick")) return 0; if (n.includes("standard")) return 1; if (n.includes("deep")) return 2; return 3; };
      const sorted = [...p].sort((x, y) => order(x.name) - order(y.name));
      setProfiles(sorted);
      if (!selectedProfileId && sorted.length) { const def = sorted.find((x) => x.isDefault); setSelectedProfileId(def ? def.id : sorted[0].id); }
      setRiskByAssetId({}); setRiskFilter("all"); setSearch(""); setScanningIds({}); setSelectedIds(new Set());
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => { loadPage(); }, [groupId]);

  // Fetch risks
  useEffect(() => {
    if (!assets.length) return;
    let cancelled = false;
    async function fetchRisks() {
      try {
        setRiskLoading(true);
        const results = await Promise.all(assets.map(async (a) => { try { const r = await getAssetRisk(String(a.id)); return [String(a.id), r] as const; } catch { return [String(a.id), undefined] as const; } }));
        if (cancelled) return;
        const next: Record<string, AssetRisk | undefined> = {};
        for (const [id, r] of results) next[id] = r;
        setRiskByAssetId(next);
      } finally { if (!cancelled) setRiskLoading(false); }
    }
    fetchRisks();
    return () => { cancelled = true; };
  }, [assets]);

  // Selection helpers
  function toggleSelect(id: string) {
    setSelectedIds((prev) => { const next = new Set(prev); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  }

  // Scan
  const onRunScan = async (asset: Asset) => {
    const id = String(asset.id);
    try {
      setScanningIds((prev) => ({ ...prev, [id]: true }));
      const job = await createScanJob(id, selectedProfileId || undefined);
      await runScanJob(String(job.id));
      const refreshed = await getGroupAssets(groupId);
      setAssets(refreshed);
      try { const r = await getAssetRisk(id); setRiskByAssetId((prev) => ({ ...prev, [id]: r })); } catch {}
    } catch (e) { console.error(e); }
    finally { setScanningIds((prev) => { const next = { ...prev }; delete next[id]; return next; }); }
  };

  // Add Asset
  const closeAddModal = () => { setAddOpen(false); setAssetType("domain"); setAssetValue(""); setAssetLabel(""); setAddError(null); setAdding(false); };
  const canSubmit = assetValue.trim().length > 0 && !adding;
  const onAddAsset = async () => {
    if (!canSubmit) return;
    try { setAdding(true); setAddError(null); const created = await addAssetToGroup(groupId, { type: assetType, value: assetValue.trim(), label: assetLabel.trim() || undefined }); setAssets((prev) => [created, ...prev]); closeAddModal(); }
    catch (e: any) { setAddError(e?.message || "Failed to add asset"); setAdding(false); }
  };

  // Edit Asset
  const openEditModal = (asset: Asset) => { setEditingAsset(asset); setEditValue(asset.value || ""); setEditLabel(asset.label || ""); setEditError(null); setSavingEdit(false); setEditOpen(true); };
  const closeEditModal = () => { setEditOpen(false); setEditingAsset(null); };
  const onSaveEdit = async () => {
    if (!editingAsset) return;
    const nextValue = editValue.trim();
    if (!nextValue) { setEditError("Asset value is required."); return; }
    try { setSavingEdit(true); setEditError(null); const updated = await updateAsset(String(editingAsset.id), { value: nextValue, label: editLabel.trim() || null }); setAssets((prev) => prev.map((a) => (String(a.id) === String(updated.id) ? updated : a))); closeEditModal(); }
    catch (e: any) { setEditError(e?.message || "Failed to update"); setSavingEdit(false); }
  };

  // Delete Asset
  const openDeleteModal = (asset: Asset) => { setDeletingAsset(asset); setDeleteError(null); setDeleting(false); setDeleteOpen(true); };
  const closeDeleteModal = () => { setDeleteOpen(false); setDeletingAsset(null); };
  const onConfirmDelete = async () => {
    if (!deletingAsset) return;
    try { setDeleting(true); await deleteAsset(String(deletingAsset.id)); setAssets((prev) => prev.filter((a) => String(a.id) !== String(deletingAsset.id))); closeDeleteModal(); }
    catch (e: any) { setDeleteError(e?.message || "Failed"); setDeleting(false); }
  };

  // Bulk Delete
  const onBulkDelete = async () => {
    if (selectedIds.size === 0) return;
    try {
      setBulkDeleting(true);
      for (const id of selectedIds) { try { await deleteAsset(id); } catch {} }
      setAssets((prev) => prev.filter((a) => !selectedIds.has(String(a.id))));
      setSelectedIds(new Set());
      setBulkDeleteOpen(false);
    } catch {} finally { setBulkDeleting(false); }
  };

  // Paging
  const PAGE_SIZE = 10;
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  useEffect(() => { setVisibleCount(PAGE_SIZE); }, [search, riskFilter]);

  const filteredAssets = useMemo(() => {
    const q = normalize(search);
    const byText = (a: Asset) => {
      if (!q) return true;
      const searchable = [a.value, a.label, a.type, (a as any).provider, (a as any).cloudCategory].filter(Boolean).join(" ");
      return normalize(searchable).includes(q);
    };
    const byRisk = (a: Asset) => matchesRiskFilter(riskFilter, riskByAssetId, a);
    return assets.filter((a) => byText(a) && byRisk(a));
  }, [assets, search, riskFilter, riskByAssetId]);

  const visibleAssets = useMemo(() => filteredAssets.slice(0, visibleCount), [filteredAssets, visibleCount]);
  const canViewMore = visibleCount < filteredAssets.length;

  const allSelected = visibleAssets.length > 0 && visibleAssets.every((a: any) => selectedIds.has(String(a.id)));
  function toggleSelectAll() {
    if (allSelected) setSelectedIds(new Set());
    else setSelectedIds(new Set(visibleAssets.map((a: any) => String(a.id))));
  }

  if (loading) return <div className="flex-1 bg-background p-8"><div className="text-muted-foreground">Loading group...</div></div>;
  if (!group) return <div className="flex-1 bg-background p-8"><h1 className="text-xl font-semibold text-foreground">Group not found</h1><Link href="/assets" className="text-primary mt-4 inline-block hover:underline">&larr; Back to Asset Groups</Link></div>;

  return (
    <div className="flex-1 bg-background overflow-auto">
      <div className="p-8 space-y-6">
        {/* Breadcrumb */}
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Link href="/assets" className="hover:text-foreground flex items-center gap-1"><ChevronLeft className="w-4 h-4" />Asset Groups</Link>
          <span>&rsaquo;</span>
          <span className="text-foreground/90">{group.name}</span>
        </div>

        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="text-3xl font-semibold text-foreground truncate">{group.name}</h1>
              <DropdownMenu>
                <DropdownMenuTrigger asChild><Button variant="ghost" size="sm" className="h-9 w-9 p-0"><MoreVertical className="w-4 h-4" /></Button></DropdownMenuTrigger>
                <DropdownMenuContent align="start">
                  <DropdownMenuItem>Edit group</DropdownMenuItem>
                  <DropdownMenuItem variant="destructive">Delete group</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
            <p className="text-muted-foreground mt-1">{assets.length} asset{assets.length !== 1 ? "s" : ""}</p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => { setBulkAddOpen(true); setBulkText(""); setBulkLabel(""); setBulkType("auto"); setBulkResults(null); }} className="gap-2"><Plus className="w-4 h-4" />Bulk Add</Button>
            <Button className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2" onClick={() => setAddOpen(true)}><Plus className="w-4 h-4" />Add Asset</Button>
          </div>
        </div>

        {/* ═══ Mini Dashboard ═══ */}
        <GroupMiniDashboard groupId={groupId} />

        {/* Banner */}
        {banner && (
          <div className={cn("rounded-xl border px-4 py-2.5 text-sm flex items-center justify-between", banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>
            <span>{banner.text}</span>
            <button onClick={() => setBanner(null)} className="hover:opacity-70"><X className="w-4 h-4" /></button>
          </div>
        )}

        {/* Search + Filters */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative w-full sm:max-w-lg">
            <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search assets (value, label, type, provider)…" className="pl-9" />
          </div>
          <div className="flex items-center gap-3">
            <Label className="text-muted-foreground">Risk</Label>
            <select value={riskFilter} onChange={(e) => setRiskFilter(e.target.value as RiskFilter)} className="h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground">
              <option value="all">All</option><option value="no_issues">Clean</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option><option value="not_scanned">Not scanned</option>
            </select>
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-muted-foreground" />
              <select value={selectedProfileId} onChange={(e) => setSelectedProfileId(e.target.value)} className="h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground">
                {profiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>
          </div>
        </div>

        {/* Bulk Actions */}
        {selectedIds.size > 0 && (
          <div className="flex items-center gap-3 bg-primary/5 border border-primary/20 rounded-xl px-4 py-2.5">
            <span className="text-sm font-medium text-foreground">{selectedIds.size} selected</span>
            <div className="flex-1" />
            <Button size="sm" variant="outline" onClick={() => setBulkDeleteOpen(true)} className="gap-1.5 border-red-500/50 text-red-400 hover:bg-red-500/10">
              <Trash2 className="w-3.5 h-3.5" />Delete Selected
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setSelectedIds(new Set())} className="text-muted-foreground"><X className="w-4 h-4" /></Button>
          </div>
        )}

        {/* Table */}
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-muted/30 border-b border-border">
              <tr>
                <th className="w-[50px] px-4 py-3">
                  <button onClick={toggleSelectAll} className="text-muted-foreground hover:text-foreground">
                    {allSelected ? <CheckSquare className="w-4 h-4 text-primary" /> : <Square className="w-4 h-4" />}
                  </button>
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[120px]">Type</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Asset</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Label</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[140px]">Status</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[140px]">Risk</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[120px]">Last Scan</th>
                <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase w-[280px]">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {visibleAssets.map((asset) => {
                const id = String(asset.id);
                const lastScan = (asset as any).lastScanAt ?? (asset as any).lastScan;
                const scanMeta = formatLastScan(lastScan);
                const status = getAssetStatus(asset);
                const locallyScanning = Boolean(scanningIds[id]);
                const effectiveStatus = locallyScanning ? "running" : status;
                const r = riskByAssetId[id];
                const hasRisk = Boolean(r);
                const isSelected = selectedIds.has(id);
                const isCloud = String((asset as any).type || "").toLowerCase() === "cloud";

                let riskNode: React.ReactNode = <span className="text-xs text-muted-foreground">{riskLoading ? "…" : "—"}</span>;
                if (!lastScan) riskNode = <span className="text-xs text-muted-foreground">—</span>;
                else if (hasRisk && (r!.totalFindings ?? r!.openFindings ?? 0) <= 0) riskNode = <span className="inline-flex items-center rounded-md bg-emerald-500/15 border border-emerald-500/25 text-emerald-200 px-2 py-0.5 text-xs font-semibold">Clean</span>;
                else if (hasRisk) riskNode = <div className="flex items-center gap-1.5"><SeverityBadge severity={r!.maxSeverity} /><span className="text-xs text-muted-foreground">{r!.totalFindings ?? r!.openFindings}</span></div>;

                return (
                  <tr key={id} className="hover:bg-accent/30 transition-colors">
                    <td className="px-4 py-3">
                      <button onClick={() => toggleSelect(id)} className="text-muted-foreground hover:text-foreground">
                        {isSelected ? <CheckSquare className="w-4 h-4 text-primary" /> : <Square className="w-4 h-4" />}
                      </button>
                    </td>
                    <td className="px-4 py-3"><AssetTypeBadge asset={asset} /></td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-1">
                        <Link href={`/assets/${id}`} className="text-primary font-mono text-sm hover:underline truncate max-w-xs block">{asset.value}</Link>
                        {isCloud && (asset as any).provider && (
                          <CloudProviderBadge provider={(asset as any).provider} category={(asset as any).cloudCategory} />
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-foreground">{asset.label ?? "—"}</td>
                    <td className="px-4 py-3"><StatusBadge status={effectiveStatus} /></td>
                    <td className="px-4 py-3">{riskNode}</td>
                    <td className="px-4 py-3 text-sm text-muted-foreground" title={scanMeta.full || undefined}>{scanMeta.short}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <Button size="sm" variant="outline" onClick={() => router.push(`/assets/${id}`)} className="gap-1.5"><Eye className="w-3.5 h-3.5" />Details</Button>
                        <Button size="sm" variant="outline" onClick={() => onRunScan(asset)} disabled={effectiveStatus === "running" || effectiveStatus === "queued"} className="gap-1.5">
                          <Play className="w-3.5 h-3.5" />{getScanButtonLabel(effectiveStatus)}
                        </Button>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild><Button variant="ghost" size="sm" className="h-8 w-8 p-0"><MoreVertical className="w-4 h-4" /></Button></DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => openEditModal(asset)}>Edit</DropdownMenuItem>
                            <DropdownMenuItem variant="destructive" onClick={() => openDeleteModal(asset)}>Delete</DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {visibleAssets.length === 0 && (
                <tr><td colSpan={8} className="px-4 py-12 text-center text-muted-foreground">
                  {assets.length === 0
                    ? <div className="space-y-3"><Layers className="w-12 h-12 text-muted-foreground/30 mx-auto" /><p>No assets in this group yet.</p><Button onClick={() => setAddOpen(true)} className="bg-primary hover:bg-primary/90"><Plus className="w-4 h-4 mr-2" />Add your first asset</Button></div>
                    : "No assets match your filters."}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <span>Showing {Math.min(visibleCount, filteredAssets.length)} of {filteredAssets.length}</span>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setVisibleCount((c) => Math.min(c + PAGE_SIZE, filteredAssets.length))} disabled={!canViewMore}>View more</Button>
            <Button variant="outline" size="sm" onClick={() => setVisibleCount(filteredAssets.length)} disabled={filteredAssets.length <= PAGE_SIZE}>View all</Button>
          </div>
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════════ */}
      {/* Add Asset Modal — now with Cloud type                  */}
      {/* ═══════════════════════════════════════════════════════ */}
      <Dialog open={addOpen} onOpenChange={(o) => { if (!o) closeAddModal(); else setAddOpen(true); }}>
        <DialogContent className="sm:max-w-[560px]">
          <DialogHeader><DialogTitle>Add Asset to {group?.name}</DialogTitle></DialogHeader>
          <div className="space-y-4 pt-2">
            {/* Asset Type Selector — visual buttons */}
            <div className="space-y-2">
              <Label>Asset Type</Label>
              <div className="grid grid-cols-4 gap-2">
                {([
                  { value: "domain" as AssetType, label: "Domain", icon: "🌐" },
                  { value: "ip" as AssetType,     label: "IP",     icon: "🖥" },
                  { value: "email" as AssetType,  label: "Email",  icon: "✉" },
                  { value: "cloud" as AssetType,  label: "Cloud",  icon: "☁" },
                ]).map(({ value, label, icon }) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => { setAssetType(value); setAssetValue(""); setAddError(null); }}
                    className={cn(
                      "flex flex-col items-center gap-1 px-3 py-2.5 rounded-lg border text-sm font-medium transition-all",
                      assetType === value
                        ? "bg-primary/15 text-primary border-primary/30"
                        : "bg-card text-muted-foreground border-border hover:border-primary/30"
                    )}
                  >
                    <span className="text-base">{icon}</span>
                    <span>{label}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Value input */}
            <div className="space-y-2">
              <Label>{assetType === "cloud" ? "Cloud Resource URL" : "Asset Value"}</Label>
              <Input
                placeholder={getAssetPlaceholder(assetType)}
                value={assetValue}
                onChange={(e) => setAssetValue(e.target.value)}
              />
              {assetType === "cloud" && (
                <p className="text-xs text-muted-foreground">
                  Enter the full URL of the cloud resource (S3 bucket, Azure Blob, container registry, serverless endpoint, CDN, etc.)
                </p>
              )}
            </div>

            {/* Cloud auto-detection badges */}
            {assetType === "cloud" && assetValue.trim().length > 5 && (
              <div className="flex items-center gap-2 flex-wrap">
                {cloudDetection ? (
                  <>
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs font-medium text-emerald-300">
                      <CheckSquare className="w-3 h-3" />
                      {cloudDetection.label}
                    </span>
                    {(() => {
                      const catMeta = CATEGORY_META[cloudDetection.category];
                      const CatIcon = catMeta?.icon || Cloud;
                      return (
                        <span className={cn("inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-accent/60 border border-border text-xs font-medium")}>
                          <CatIcon className={cn("w-3 h-3", catMeta?.color || "text-muted-foreground")} />
                          {catMeta?.label || cloudDetection.category}
                        </span>
                      );
                    })()}
                  </>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs font-medium text-amber-300">
                    <AlertTriangle className="w-3 h-3" />
                    Unknown provider — will be probed generically
                  </span>
                )}
              </div>
            )}

            {/* Label */}
            <div className="space-y-2">
              <Label>Label (Optional)</Label>
              <Input placeholder="e.g., Main Website" value={assetLabel} onChange={(e) => setAssetLabel(e.target.value)} />
            </div>

            {addError && <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">{addError}</div>}
            <Button className="w-full bg-primary hover:bg-primary/90" disabled={!canSubmit} onClick={onAddAsset}>
              {adding ? "Adding..." : assetType === "cloud" ? "Add Cloud Asset" : "Add Asset"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Edit Modal */}
      <Dialog open={editOpen} onOpenChange={(o) => { if (!o) closeEditModal(); }}>
        <DialogContent className="sm:max-w-[560px]">
          <DialogHeader><DialogTitle>Edit Asset</DialogTitle></DialogHeader>
          <div className="space-y-4 pt-2">
            <div className="space-y-2"><Label>Asset Type</Label><Input value={String(editingAsset?.type || "").toUpperCase()} disabled /></div>
            <div className="space-y-2"><Label>Asset Value</Label><Input value={editValue} onChange={(e) => setEditValue(e.target.value)} /></div>
            <div className="space-y-2"><Label>Label</Label><Input value={editLabel} onChange={(e) => setEditLabel(e.target.value)} /></div>
            {editError && <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">{editError}</div>}
            <div className="flex gap-3"><Button variant="outline" className="flex-1" onClick={closeEditModal}>Cancel</Button><Button className="flex-1 bg-primary hover:bg-primary/90" onClick={onSaveEdit} disabled={savingEdit}>{savingEdit ? "Saving..." : "Save"}</Button></div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Delete Modal */}
      <Dialog open={deleteOpen} onOpenChange={(o) => { if (!o) closeDeleteModal(); }}>
        <DialogContent className="sm:max-w-[440px]">
          <DialogHeader><DialogTitle>Delete Asset</DialogTitle></DialogHeader>
          <p className="text-sm text-muted-foreground">Delete <span className="text-foreground font-semibold">{deletingAsset?.value}</span>? This cannot be undone.</p>
          {deleteError && <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">{deleteError}</div>}
          <div className="flex gap-3"><Button variant="outline" className="flex-1" onClick={closeDeleteModal}>Cancel</Button><Button className="flex-1 bg-[#ef4444] hover:bg-[#dc2626] text-white" onClick={onConfirmDelete} disabled={deleting}>{deleting ? "Deleting..." : "Delete"}</Button></div>
        </DialogContent>
      </Dialog>

      {/* Bulk Delete Modal */}
      <Dialog open={bulkDeleteOpen} onOpenChange={setBulkDeleteOpen}>
        <DialogContent className="sm:max-w-[440px]">
          <DialogHeader><DialogTitle>Delete {selectedIds.size} Assets</DialogTitle></DialogHeader>
          <p className="text-sm text-muted-foreground">This will permanently delete {selectedIds.size} asset{selectedIds.size !== 1 ? "s" : ""} and all associated findings.</p>
          <div className="flex gap-3"><Button variant="outline" className="flex-1" onClick={() => setBulkDeleteOpen(false)}>Cancel</Button><Button className="flex-1 bg-[#ef4444] hover:bg-[#dc2626] text-white" onClick={onBulkDelete} disabled={bulkDeleting}>{bulkDeleting ? "Deleting..." : "Delete All"}</Button></div>
        </DialogContent>
      </Dialog>

      {/* ═══════════════════════════════════════════════════════ */}
      {/* Bulk Add Modal — now with Cloud type                   */}
      {/* ═══════════════════════════════════════════════════════ */}
      <Dialog open={bulkAddOpen} onOpenChange={(o) => { if (!o) { setBulkAddOpen(false); setBulkResults(null); } else setBulkAddOpen(true); }}>
        <DialogContent className="sm:max-w-[600px]">
          <DialogHeader><DialogTitle className="flex items-center gap-2"><Plus className="w-5 h-5 text-primary" />Bulk Add Assets</DialogTitle></DialogHeader>

          {bulkResults ? (
            <div className="space-y-4 pt-2">
              {/* Summary */}
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-[#10b981]/10 border border-[#10b981]/30 rounded-lg p-3 text-center">
                  <div className="text-xl font-bold text-[#10b981]">{bulkResults.added}</div>
                  <div className="text-xs text-muted-foreground">Added</div>
                </div>
                <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-center">
                  <div className="text-xl font-bold text-amber-300">{bulkResults.skipped}</div>
                  <div className="text-xs text-muted-foreground">Skipped</div>
                </div>
                <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-center">
                  <div className="text-xl font-bold text-red-300">{bulkResults.errors}</div>
                  <div className="text-xs text-muted-foreground">Invalid</div>
                </div>
              </div>

              {/* Detail list */}
              <div className="max-h-64 overflow-y-auto space-y-1">
                {bulkResults.results?.map((r: any, i: number) => (
                  <div key={i} className={cn("flex items-center justify-between px-3 py-1.5 rounded-md text-sm", r.status === "added" ? "bg-[#10b981]/5" : r.status === "error" ? "bg-red-500/5" : "bg-muted/20")}>
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="font-mono text-foreground truncate">{r.value}</span>
                      {r.type && <span className="text-[10px] text-muted-foreground uppercase">{r.type}</span>}
                    </div>
                    <span className={cn("text-xs font-medium shrink-0",
                      r.status === "added" ? "text-[#10b981]" : r.status === "duplicate" ? "text-amber-300" : r.status === "moved" ? "text-blue-300" : "text-red-300")}>
                      {r.status === "added" ? "✓ Added" : r.status === "duplicate" ? "Duplicate" : r.status === "moved" ? "Moved here" : r.reason || "Invalid"}
                    </span>
                  </div>
                ))}
              </div>

              <Button onClick={() => { setBulkAddOpen(false); setBulkResults(null); }} className="w-full bg-primary hover:bg-primary/90">Done</Button>
            </div>
          ) : (
            <div className="space-y-4 pt-2">
              <p className="text-sm text-muted-foreground">Select the asset type, then paste your list — one per line.</p>

              {/* Type Selector — now includes Cloud */}
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-foreground block">Asset Type</label>
                <div className="flex gap-2">
                  {(["domain", "ip", "email", "cloud", "auto"] as const).map((t) => (
                    <button key={t} type="button" onClick={() => setBulkType(t)}
                      className={cn("flex-1 px-3 py-2 rounded-lg border text-sm font-medium transition-all capitalize",
                        bulkType === t ? "bg-primary/15 text-primary border-primary/30" : "bg-card text-muted-foreground border-border hover:border-primary/30")}>
                      {t === "auto" ? "Auto-detect" : t === "ip" ? "IP Address" : t === "domain" ? "Domain" : t === "cloud" ? "Cloud URL" : "Email"}
                    </button>
                  ))}
                </div>
                {bulkType === "auto" && <p className="text-xs text-muted-foreground">Types will be detected automatically from each value</p>}
                {bulkType === "cloud" && <p className="text-xs text-muted-foreground">Paste cloud resource URLs (S3 buckets, Azure Blob, container registries, etc.)</p>}
              </div>

              {/* Textarea */}
              <textarea
                className="w-full h-40 rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground font-mono outline-none focus:ring-2 focus:ring-primary/40 resize-none"
                placeholder={
                  bulkType === "ip" ? "192.168.1.1\n10.0.0.1\n172.16.0.5" :
                  bulkType === "email" ? "admin@example.com\nsecurity@company.org\ndev@startup.io" :
                  bulkType === "domain" ? "example.com\napi.company.org\napp.startup.io" :
                  bulkType === "cloud" ? "mybucket.s3.amazonaws.com\nmyaccount.blob.core.windows.net\nmyregistry.azurecr.io" :
                  "example.com\n192.168.1.1\nuser@company.com\nmybucket.s3.amazonaws.com"
                }
                value={bulkText}
                onChange={(e) => setBulkText(e.target.value)}
              />

              {/* Label */}
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-foreground block">Label (optional)</label>
                <Input placeholder="e.g., Production Servers, Marketing Sites…" value={bulkLabel} onChange={(e) => setBulkLabel(e.target.value)} />
                <p className="text-xs text-muted-foreground">Applied to all assets in this batch</p>
              </div>
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>{parseBulkText(bulkText).length} item{parseBulkText(bulkText).length !== 1 ? "s" : ""} detected</span>
                <span>Max 200 per batch</span>
              </div>
              <div className="flex gap-3">
                <Button variant="outline" className="flex-1" onClick={() => setBulkAddOpen(false)}>Cancel</Button>
                <Button className="flex-1 bg-primary hover:bg-primary/90" onClick={onBulkAdd} disabled={bulkAdding || parseBulkText(bulkText).length === 0}>
                  {bulkAdding ? "Adding..." : `Add ${parseBulkText(bulkText).length} Asset${parseBulkText(bulkText).length !== 1 ? "s" : ""}`}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}