// app/lib/api.ts
import type { AssetGroup, Asset, ScanJob, Finding, ScanProfile, ScanSchedule } from "../types";

// Auth imports are dynamic inside apiFetch to avoid circular deps
// and to enable inactivity checking. Static import only for non-apiFetch usage.
import { getAccessToken } from "./auth";

// Current (localhost fallback)
const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/+$/, "") ||
  (typeof window !== "undefined" && window.location.hostname !== "localhost"
    ? `http://${window.location.hostname}:5000`
    : "http://127.0.0.1:5000");

export const API = {
  health: "/health",
  auth: {
    login: "/auth/login",
    register: "/auth/register",
    me: "/auth/me",
  },

  groups: "/groups",
  assets: "/assets",
  scanJobs: "/scan-jobs",
  findings: "/findings",
  quickScan: "/quick-scan",

  discovery: {
    run: "/discovery/domain",
    runs: "/discovery/runs",
    runById: (id: string | number) => `/discovery/runs/${id}`,
  },

  monitoring: {
    summary: "/monitoring/summary",
    alerts: "/monitoring/alerts",
    alertById: (id: string) => `/monitoring/alerts/${id}`,
    acknowledge: (id: string) => `/monitoring/alerts/${id}/acknowledge`,
    verdict: (id: string) => `/monitoring/alerts/${id}/verdict`,
    status: (id: string) => `/monitoring/alerts/${id}/status`,
    tuning: "/monitoring/tuning",
    tuningById: (id: string) => `/monitoring/tuning/${id}`,
  },

  // ✅ M11: Reports
  reports: {
    list: "/reports",
    generate: "/reports/generate",
    byId: (id: string) => `/reports/${id}`,
    download: (id: string) => `/reports/${id}/download`,
    schedules: "/reports/schedules",
    scheduleById: (id: string) => `/reports/schedules/${id}`,
  },

  tools: {
    certLookup: "/tools/cert-lookup",
    certHash: "/tools/cert-hash",
    dnsLookup: "/tools/dns-lookup",
    reverseDns: "/tools/reverse-dns",
    headerCheck: "/tools/header-check",
    whois: "/tools/whois",
    connectivityCheck: "/connectivity-check"
  },

  trending: {
    data: "/trending/data",
    summary: "/trending/summary",
    snapshot: "/trending/snapshot",
    groups: "/trending/groups",
    findingEvents: (findingId: string) => `/trending/finding-events/${findingId}`,
  },

  // ✅ M3: Scan Profiles & Schedules
  scanProfiles: "/scan-profiles",
  scanProfileById: (id: string) => `/scan-profiles/${id}`,
  scanProfileDefault: "/scan-profiles/default",

  scanSchedules: "/scan-schedules",
  scanScheduleById: (id: string) => `/scan-schedules/${id}`,
  scanScheduleRunNow: (id: string) => `/scan-schedules/${id}/run-now`,
} as const;

// ────────────────────────────────────────────────────────────
// Error types
// ────────────────────────────────────────────────────────────

export type PlanErrorCode =
  | "PLAN_LIMIT_REACHED"
  | "FEATURE_NOT_AVAILABLE"
  | "PROFILE_NOT_AVAILABLE";

export type PlanErrorData = {
  error: string;
  code?: PlanErrorCode;
  resource?: string;
  limit?: number;
  current?: number;
  feature?: string;
  profile?: string;
  allowed_profiles?: string[];
  plan?: string;
  upgrade_url?: string;
  required_role?: string;
  required_permission?: string;
  your_role?: string;
};

// ── Trending Types ──

export interface TrendSnapshot {
  id: string;
  date: string;
  assetCount: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  suppressedCount: number;
  exposureScore: number;
  newFindings: number;
  resolvedFindings: number;
  suppressedFindings: number;
  mttrHours: number | null;
}

export interface TrendDataResponse {
  snapshots: TrendSnapshot[];
  days: number;
  startDate: string;
  endDate: string;
  groupId: string | null;
  scope: "organization" | "group";
}

export interface TrendDelta {
  value: number;
  percent: number;
  direction: "up" | "down" | "flat";
}

export interface TrendSummaryResponse {
  current: TrendSnapshot | null;
  previous: TrendSnapshot | null;
  deltas: {
    exposureScore: TrendDelta;
    totalFindings: TrendDelta;
    critical: TrendDelta;
    high: TrendDelta;
    assetCount: TrendDelta;
  } | null;
  comparedToDaysAgo: number;
}

export interface GroupTrendItem {
  groupId: string;
  groupName: string;
  snapshot: TrendSnapshot | null;
}

export interface FindingEventItem {
  id: string;
  findingId: string;
  eventType: "opened" | "resolved" | "suppressed" | "unsuppressed" | "reopened" | "severity_changed";
  oldValue: string | null;
  newValue: string | null;
  userId: string | null;
  userName: string | null;
  notes: string | null;
  createdAt: string;
}

type ApiError = Error & {
  status?: number;
  payload?: any;
  planError?: PlanErrorData;
};

function makeError(message: string, status?: number, payload?: any): ApiError {
  const err = new Error(message) as ApiError;
  err.status = status;
  err.payload = payload;
  return err;
}

/**
 * Check if an error payload is a plan/permission enforcement error.
 * Use this in catch blocks: if (isPlanError(e)) { planLimit.handle(e.planError); }
 */
export function isPlanError(err: any): err is ApiError & { planError: PlanErrorData } {
  return err && err.planError != null;
}

function isBrowser() {
  return typeof window !== "undefined";
}

// ────────────────────────────────────────────────────────────
// Core fetch wrapper
// ────────────────────────────────────────────────────────────

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  // Dynamic import to avoid circular deps and enable inactivity check
  const {
    getAccessToken: getToken,
    clearSession,
    isInactive,
    touchActivity,
  } = await import("./auth");

  const token = getToken();

  // ── Inactivity check: 30 min idle → force logout ──
  if (token && isInactive()) {
    clearSession();
    if (isBrowser()) {
      const next = `${window.location.pathname}${window.location.search}`;
      window.location.href = `/login?next=${encodeURIComponent(next)}&expired=true`;
    }
    throw makeError("Session expired due to inactivity", 401);
  }

  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      ...(init?.headers || {}),
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    cache: "no-store",
  });

  // ── 401: token expired on backend → clear & redirect ──
  if (res.status === 401) {
    clearSession();
    if (isBrowser()) {
      const next = `${window.location.pathname}${window.location.search}`;
      window.location.href = `/login?next=${encodeURIComponent(next)}&expired=true`;
    }
    throw makeError("Session expired", 401);
  }

  // Touch activity on every successful authenticated request
  if (token) touchActivity();

  let payload: any = null;
  let rawText = "";
  try {
    rawText = await res.text();
    payload = rawText ? JSON.parse(rawText) : null;
  } catch {
    payload = rawText || null;
  }

  // ── 403: plan limit / feature gate / role insufficient ──
  if (res.status === 403 && payload && typeof payload === "object") {
    const isPlanOrPermError =
      payload.code === "PLAN_LIMIT_REACHED" ||
      payload.code === "FEATURE_NOT_AVAILABLE" ||
      payload.code === "PROFILE_NOT_AVAILABLE" ||
      payload.required_role ||
      payload.required_permission;

    if (isPlanOrPermError) {
      const err = makeError(
        payload.error || "Permission denied",
        403,
        payload
      );
      err.planError = payload as PlanErrorData;
      throw err;
    }
  }

  if (!res.ok) {
    const msg =
      (payload && (payload.error || payload.message || payload.detail)) ||
      `Request failed: ${res.status}`;
    throw makeError(msg, res.status, payload);
  }

  if (res.status === 204) return undefined as unknown as T;
  if (!rawText) return undefined as unknown as T;

  return payload as T;
}

function toDate(v: any): Date | undefined {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d;
}

// ────────────────────────────────────────────────────────────
// Parsers
// ────────────────────────────────────────────────────────────

function parseGroup(g: any): AssetGroup {
  return {
    ...g,
    createdAt: g.createdAt ? new Date(g.createdAt) : new Date(),
  };
}

function parseAsset(a: any): Asset {
  return {
    ...a,
    lastScan: toDate(a.lastScanAt ?? a.lastScan),
    lastScanAt: a.lastScanAt ?? null,
  };
}

function parseJob(j: any): ScanJob {
  const created = toDate(j.createdAt);
  const started = toDate(j.startedAt ?? j.timeStarted);
  const finished = toDate(j.finishedAt ?? j.timeCompleted);

  return {
    ...j,
    timeStarted: started ?? created ?? new Date(),
    timeCompleted: finished,
    // ✅ M3: pass through profile/schedule info
    profileId: j.profileId ?? null,
    profileName: j.profileName ?? null,
    scheduleId: j.scheduleId ?? null,
  };
}

function parseFinding(f: any): Finding {
  return {
    ...f,
    detectedAt: f.detectedAt ? new Date(f.detectedAt) : new Date(),
    ignoredAt: toDate(f.ignoredAt),
    resolvedAt: toDate(f.resolvedAt),
    status: f.status || (f.resolved ? "resolved" : f.ignored ? "suppressed" : "open"),
  };
}

// ────────────────────────────────────────────────────────────
// Auth
// ────────────────────────────────────────────────────────────

export type AuthResponse = {
  accessToken: string;
  user: {
    id: string | number;
    email: string;
    name?: string;
    job_title?: string;
    company?: string;
    country?: string;
  };
  organization?: {
    id: string | number;
    name: string;
    slug: string;
    plan: string;
    country?: string;
    asset_limit?: number;
    assets_count?: number;
    scans_this_month?: number;
  };
};

export async function login(payload: {
  email: string;
  password: string;
}): Promise<AuthResponse> {
  return apiFetch<AuthResponse>(API.auth.login, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function register(payload: {
  name: string;
  email: string;
  password: string;
  job_title?: string;
  company?: string;
  country?: string;
  invite_token?: string;
}): Promise<AuthResponse> {
  return apiFetch<AuthResponse>(API.auth.register, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export type MeResponse = {
  user: {
    id: string | number;
    email: string;
    name?: string;
    job_title?: string;
    company?: string;
    country?: string;
  };
  organization: {
    id: string | number;
    name: string;
    slug: string;
    plan: string;
    country?: string;
    asset_limit?: number;
    assets_count?: number;
    scans_this_month?: number;
  };
  role: "owner" | "admin" | "analyst" | "viewer";
};

export async function me(): Promise<MeResponse> {
  return apiFetch<MeResponse>(API.auth.me);
}

// ────────────────────────────────────────────────────────────
// Groups
// ────────────────────────────────────────────────────────────

export async function getGroups(): Promise<AssetGroup[]> {
  const rows = await apiFetch<any[]>(API.groups);
  return rows.map(parseGroup);
}

export async function createGroup(name: string): Promise<AssetGroup> {
  const g = await apiFetch<any>(API.groups, {
    method: "POST",
    body: JSON.stringify({ name }),
  });
  return parseGroup(g);
}

export async function renameGroup(groupId: string, name: string): Promise<AssetGroup> {
  const g = await apiFetch<any>(`${API.groups}/${groupId}`, {
    method: "PATCH",
    body: JSON.stringify({ name }),
  });
  return parseGroup(g);
}

export async function deleteGroup(groupId: string): Promise<void> {
  await apiFetch(`${API.groups}/${groupId}`, { method: "DELETE" });
}

// ────────────────────────────────────────────────────────────
// Assets
// ────────────────────────────────────────────────────────────

export async function getGroupAssets(groupId: string): Promise<Asset[]> {
  const rows = await apiFetch<any[]>(`${API.groups}/${groupId}/assets`);
  return rows.map(parseAsset);
}

export async function addAssetToGroup(
  groupId: string,
  payload: { type: "domain" | "ip" | "email"; value: string; label?: string }
): Promise<Asset> {
  const a = await apiFetch<any>(`${API.groups}/${groupId}/assets`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  return parseAsset(a);
}

export async function getAllAssets(): Promise<Asset[]> {
  const rows = await apiFetch<any[]>(API.assets);
  return rows.map(parseAsset);
}

export async function updateAsset(
  assetId: string,
  payload: { value?: string; label?: string | null }
): Promise<Asset> {
  const a = await apiFetch<any>(`${API.assets}/${assetId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
  return parseAsset(a);
}

export async function deleteAsset(assetId: string): Promise<void> {
  await apiFetch(`${API.assets}/${assetId}`, { method: "DELETE" });
}

export async function bulkAddAssets(
  groupId: string,
  items: Array<{ value: string; type?: string; label?: string }>
): Promise<any> {
  return apiFetch<any>(`/groups/${groupId}/assets/bulk`, {
    method: "POST",
    body: JSON.stringify({ items }),
  });
}

// ────────────────────────────────────────────────────────────
// Scan Jobs
// ────────────────────────────────────────────────────────────

export async function getScanJobs(): Promise<ScanJob[]> {
  const rows = await apiFetch<any[]>(API.scanJobs);
  return rows.map(parseJob);
}

export async function createScanJob(assetId: string, profileId?: string): Promise<ScanJob> {
  const body: any = { assetId };
  if (profileId) body.profileId = profileId;

  return apiFetch("/scan-jobs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function runScanJob(jobId: string): Promise<void> {
  await apiFetch(`${API.scanJobs}/${jobId}/run`, { method: "POST" });
}

export async function deleteScanJob(jobId: string): Promise<void> {
  await apiFetch(`${API.scanJobs}/${jobId}`, { method: "DELETE" });
}

export async function getScanJobFindings(jobId: string): Promise<Finding[]> {
  const rows = await apiFetch<any[]>(`${API.scanJobs}/${jobId}/findings`);
  return rows.map(parseFinding);
}

export async function getScanJobDetail(jobId: string) {
  const raw = await apiFetch<any>(`${API.scanJobs}/${jobId}`);

  return {
    ...raw,
    asset_value: raw.assetValue,
    asset_type: raw.assetType,
    group_id: raw.groupId,
    group_name: raw.groupName,
    created_at: raw.createdAt,
    started_at: raw.startedAt,
    completed_at: raw.finishedAt,
  };
}

export async function createAndRunScanForAssetId(assetId: string, profileId?: string): Promise<ScanJob> {
  const job = await createScanJob(assetId, profileId);
  await runScanJob(String(job.id));
  return job;
}

export async function addAssetToGroupAndScan(params: {
  groupId: string;
  type: "domain" | "ip" | "email";
  value: string;
  label?: string;
  profileId?: string;
}): Promise<{ asset: Asset; job: ScanJob }> {
  const { groupId, type, value, label, profileId } = params;

  let asset: Asset | null = null;

  try {
    asset = await addAssetToGroup(groupId, { type, value, label });
  } catch (e: any) {
    // Re-throw plan errors so the caller can show the upgrade dialog
    if (isPlanError(e)) throw e;

    const msg = String(e?.message || "").toLowerCase();
    if (msg.includes("exists") || msg.includes("already")) {
      const assets = await getGroupAssets(groupId);
      const found = assets.find((a) => String(a.value).toLowerCase() === String(value).toLowerCase());
      if (!found) throw e;
      asset = found;
    } else {
      throw e;
    }
  }

  const job = await createAndRunScanForAssetId(String(asset.id), profileId);
  return { asset, job };
}

// ────────────────────────────────────────────────────────────
// Findings
// ────────────────────────────────────────────────────────────

export async function getFindings(): Promise<Finding[]> {
  const rows = await apiFetch<any[]>(API.findings);
  return rows.map(parseFinding);
}

export async function setFindingIgnored(
  findingId: string,
  ignored: boolean,
  ignoredReason?: string
): Promise<Finding> {
  const f = await apiFetch<any>(`${API.findings}/${findingId}`, {
    method: "PATCH",
    body: JSON.stringify({ ignored, ignoredReason }),
  });
  return parseFinding(f);
}

export async function setFindingResolved(
  findingId: string,
  resolved: boolean,
  resolvedReason?: string
): Promise<Finding> {
  const f = await apiFetch<any>(`${API.findings}/${findingId}`, {
    method: "PATCH",
    body: JSON.stringify({ resolved, resolvedReason }),
  });
  return parseFinding(f);
}

export async function bulkIgnoreFindings(payload: {
  ids: string[];
  ignored: boolean;
  reason?: string;
}): Promise<{ message: string; updated: number }> {
  return apiFetch("/findings/bulk-ignore", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function bulkResolveFindings(payload: {
  ids: string[];
  resolved: boolean;
  reason?: string;
}): Promise<{ message: string; updated: number }> {
  return apiFetch("/findings/bulk-resolve", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

// ────────────────────────────────────────────────────────────
// Asset Risk
// ────────────────────────────────────────────────────────────

export type AssetRisk = {
  assetId: string;
  type: string;
  value: string;
  openFindings: number;
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  maxSeverity: "critical" | "high" | "medium" | "low" | "info";
  totalFindings?: number;
  counts?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
};

export async function getAssetRisk(assetId: string): Promise<AssetRisk> {
  const raw: any = await apiFetch<any>(`${API.assets}/${assetId}/risk`);

  const srcCounts = raw?.bySeverity ?? raw?.counts ?? {};
  const counts = {
    critical: Number(srcCounts.critical || 0),
    high: Number(srcCounts.high || 0),
    medium: Number(srcCounts.medium || 0),
    low: Number(srcCounts.low || 0),
    info: Number(srcCounts.info || 0),
  };

  const totalFindings = raw?.openFindings ?? 0;

  return {
    assetId: String(raw?.assetId ?? assetId),
    type: raw?.type ?? "unknown",
    value: raw?.value ?? "",
    openFindings: totalFindings,
    bySeverity: counts,
    maxSeverity: (String(raw?.maxSeverity || "info").toLowerCase() as any) || "info",
    totalFindings,
    counts,
  };
}

// ────────────────────────────────────────────────────────────
// Quick Scan
// ────────────────────────────────────────────────────────────

export type QuickScanFinding = {
  title?: string;
  severity?: "critical" | "high" | "medium" | "low" | "info" | string;
  description?: string;
  details_json?: any;
  [k: string]: any;
};

export type QuickScanResponse = {
  assetType: "domain" | "ip";
  assetValue: string;
  maxSeverity: "critical" | "high" | "medium" | "low" | "info";
  totalFindings: number;
  ipsScanned: string[];
  counts: Record<"critical" | "high" | "medium" | "low" | "info", number>;
  errors?: { ip?: string; error: string }[];
  findings?: QuickScanFinding[];
};

type BackendQuickScanResponse = {
  status: "completed" | "failed";
  assetType: "domain" | "ip";
  assetValue: string;
  summary?: { ips_scanned?: string[]; errors?: any[]; [k: string]: any };
  risk?: { maxSeverity?: string; totalFindings?: number; counts?: any; [k: string]: any };
  findings?: any[];
  error?: string;
};

export async function quickScanAsset(payload: {
  type: "domain" | "ip";
  value: string;
}): Promise<QuickScanResponse> {
  const res = await apiFetch<BackendQuickScanResponse>(API.quickScan, {
    method: "POST",
    body: JSON.stringify(payload),
  });

  const counts =
    res?.risk?.counts ||
    ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 } as const);

  return {
    assetType: res.assetType,
    assetValue: res.assetValue,
    maxSeverity: (res?.risk?.maxSeverity as any) || "info",
    totalFindings: Number(res?.risk?.totalFindings || 0),
    ipsScanned: (res?.summary?.ips_scanned || []) as string[],
    counts: {
      critical: Number(counts.critical || 0),
      high: Number(counts.high || 0),
      medium: Number(counts.medium || 0),
      low: Number(counts.low || 0),
      info: Number(counts.info || 0),
    },
    errors: (res?.summary?.errors || []) as any[],
    findings: (res?.findings || []) as any[],
  };
}

// ────────────────────────────────────────────────────────────
// Discovery
// ────────────────────────────────────────────────────────────

export type DiscoveryDomainResponse = {
  status?: "queued" | "running" | "completed" | "failed" | string;
  stored?: boolean;
  domain?: string;
  counts?: {
    ct?: number;
    brute?: number;
    subdomains?: number;
    resolvedNames?: number;
    [k: string]: any;
  };
  subdomains?: string[];
  apexIps?: string[];
  resolved?: Record<string, string[]>;
  errors?: Array<{ source?: string; error?: string }>;
  createdAt?: string;
  completedAt?: string;
  error?: string;
  details?: string;
  [k: string]: any;
};

export type DiscoveryRunListItem = {
  id: string | number;
  status?: string;
  createdAt?: string;
  completedAt?: string;
  domain?: string;
  counts?: Record<string, any>;
  input?: { type?: string; value?: string; [k: string]: any };
  summary?: Record<string, any>;
  [k: string]: any;
};

export type DiscoveryRunDetail = DiscoveryRunListItem & {
  result?: {
    subdomains?: string[];
    domains?: string[];
    ips?: string[];
    resolved?: Record<string, string[]>;
    errors?: any[];
    [k: string]: any;
  };
};

export async function discoveryDomain(payload: any): Promise<DiscoveryDomainResponse> {
  return apiFetch<DiscoveryDomainResponse>(API.discovery.run, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getDiscoveryRuns(): Promise<DiscoveryRunListItem[]> {
  const rows = await apiFetch<any>(API.discovery.runs);
  if (Array.isArray(rows)) return rows as DiscoveryRunListItem[];
  if (rows && Array.isArray(rows.items)) return rows.items as DiscoveryRunListItem[];
  return [];
}

export async function getDiscoveryRun(runId: string | number): Promise<DiscoveryRunDetail> {
  return apiFetch<DiscoveryRunDetail>(API.discovery.runById(runId));
}

export async function deleteDiscoveryRun(runId: string | number): Promise<void> {
  await apiFetch(API.discovery.runById(runId), { method: "DELETE" });
}

// ────────────────────────────────────────────────────────────
// Health
// ────────────────────────────────────────────────────────────

export async function health(): Promise<{ status: string }> {
  return apiFetch<{ status: string }>(API.health, { method: "GET" });
}

// ────────────────────────────────────────────────────────────
// Quick Discovery compatibility wrappers
// ────────────────────────────────────────────────────────────

export type QuickDiscoveryResponse = DiscoveryDomainResponse;

export async function discoverDomainQuick(payload: {
  domain: string;
  useCt?: boolean;
  useDnsBrute?: boolean;
  includeApex?: boolean;
  resolveIps?: boolean;
  ctLimit?: number;
  bruteMax?: number;
  resolveMaxNames?: number;
}): Promise<QuickDiscoveryResponse> {
  return discoveryDomain({
    domain: payload.domain,
    options: {
      useCt: payload.useCt ?? true,
      useDnsBrute: payload.useDnsBrute ?? true,
      includeApex: payload.includeApex ?? true,
      resolveIps: payload.resolveIps ?? true,
      ctLimit: payload.ctLimit ?? 2000,
      bruteMax: payload.bruteMax ?? 600,
      resolveMaxNames: payload.resolveMaxNames ?? 300,
    },
  });
}

// ────────────────────────────────────────────────────────────
// Dashboard
// ────────────────────────────────────────────────────────────

export type TopRiskyAsset = {
  assetId: string;
  type: "domain" | "ip" | "email";
  value: string;
  openFindings: number;
  maxSeverity: "critical" | "high" | "medium" | "low" | "info";
};

export type DashboardSummary = {
  assets: {
    total: number;
    groups: number;
  };
  findings: {
    total: number;
    open: number;
    bySeverity: Record<"critical" | "high" | "medium" | "low" | "info", number>;
  };
  topRiskyAssets: TopRiskyAsset[];
  recentScanJobs: any[];
};

export async function getDashboardSummary(): Promise<DashboardSummary> {
  return apiFetch<DashboardSummary>("/dashboard/summary");
}

// ────────────────────────────────────────────────────────────
// Scan Profiles
// ────────────────────────────────────────────────────────────

export async function getScanProfiles(): Promise<ScanProfile[]> {
  return apiFetch<ScanProfile[]>(API.scanProfiles);
}

export async function getScanProfile(profileId: string): Promise<ScanProfile> {
  return apiFetch<ScanProfile>(API.scanProfileById(profileId));
}

export async function getDefaultScanProfile(): Promise<ScanProfile> {
  return apiFetch<ScanProfile>(API.scanProfileDefault);
}

// ────────────────────────────────────────────────────────────
// Scan Schedules
// ────────────────────────────────────────────────────────────

export async function getScanSchedules(): Promise<ScanSchedule[]> {
  const rows = await apiFetch<any[]>(API.scanSchedules);
  return rows;
}

export async function createScanSchedule(payload: {
  scheduleType?: "asset" | "group";
  assetId?: string;
  groupId?: string;
  profileId?: string;
  name?: string;
  frequency: "daily" | "weekly" | "monthly";
  timeOfDay: string;
  dayOfWeek?: number;
  dayOfMonth?: number;
}): Promise<ScanSchedule> {
  return apiFetch<ScanSchedule>(API.scanSchedules, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateScanSchedule(
  scheduleId: string,
  payload: {
    enabled?: boolean;
    frequency?: string;
    timeOfDay?: string;
    dayOfWeek?: number | null;
    dayOfMonth?: number | null;
    profileId?: string;
    name?: string;
  }
): Promise<ScanSchedule> {
  return apiFetch<ScanSchedule>(API.scanScheduleById(scheduleId), {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function deleteScanSchedule(scheduleId: string): Promise<void> {
  await apiFetch(API.scanScheduleById(scheduleId), { method: "DELETE" });
}

export async function runScheduleNow(scheduleId: string): Promise<{ jobId: string }> {
  return apiFetch<{ jobId: string }>(API.scanScheduleRunNow(scheduleId), {
    method: "POST",
  });
}

// ────────────────────────────────────────────────────────────
// Monitoring
// ────────────────────────────────────────────────────────────

export type MonitoringSummary = {
  openAlerts: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  acknowledged: number;
  unacknowledged: number;
};

export type MonitoringSeverity = "critical" | "high" | "medium" | "low" | "info";
export type MonitoringStatus = "open" | "closed";
export type MonitoringVerdict = "TP" | "FP" | "Expected" | null;

export type MonitoringAlertRow = {
  id: string;
  eventType: string;
  name: string;
  severity: MonitoringSeverity;
  asset: { id: string; type: "domain" | "ip" | "email"; value: string };
  group: { id: string; name: string };
  status: MonitoringStatus;
  verdict: MonitoringVerdict;
  acknowledged: boolean;
  firstSeenAt: string;
  lastSeenAt: string;
};

export type MonitoringAlertsResponse = {
  total: number;
  limit: number;
  offset: number;
  alerts: MonitoringAlertRow[];
};

export type MonitoringAlertDetail = MonitoringAlertRow & {
  details?: Record<string, any>;
};

export type MonitoringTuningRule = {
  id: string;
  eventType: string;
  scope: { type: "global" | "group" | "asset"; id?: string };
  enabled: boolean;
  reason?: string;
  createdAt: string;
  match?: Record<string, any>;
};

export async function getMonitoringSummary(): Promise<MonitoringSummary> {
  return apiFetch<MonitoringSummary>(API.monitoring.summary);
}

export async function getMonitoringAlerts(params: {
  status?: "open" | "closed" | "all";
  severity?: MonitoringSeverity[];
  limit?: number;
  offset?: number;
  groupId?: string;
  assetId?: string;
  acknowledged?: "all" | "yes" | "no";
  verdict?: "all" | "TP" | "FP" | "Expected" | "None";
}): Promise<MonitoringAlertsResponse> {
  const q = new URLSearchParams();

  if (params.status && params.status !== "all") q.set("status", params.status);
  if (params.severity?.length) q.set("severity", params.severity.join(","));
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.offset != null) q.set("offset", String(params.offset));

  if (params.groupId) q.set("groupId", params.groupId);
  if (params.assetId) q.set("assetId", params.assetId);

  if (params.acknowledged === "yes") q.set("acknowledged", "true");
  if (params.acknowledged === "no") q.set("acknowledged", "false");

  if (params.verdict && params.verdict !== "all") {
    q.set("verdict", params.verdict === "None" ? "null" : params.verdict);
  }

  const path = `${API.monitoring.alerts}?${q.toString()}`;
  return apiFetch<MonitoringAlertsResponse>(path);
}

export async function getMonitoringAlert(id: string): Promise<MonitoringAlertDetail> {
  return apiFetch<MonitoringAlertDetail>(API.monitoring.alertById(id));
}

export async function patchMonitoringAcknowledge(id: string, acknowledged: boolean) {
  return apiFetch<{ status: "ok"; alertId: string; acknowledged: boolean }>(
    API.monitoring.acknowledge(id),
    { method: "PATCH", body: JSON.stringify({ acknowledged }) }
  );
}

export async function patchMonitoringVerdict(id: string, verdict: MonitoringVerdict) {
  return apiFetch<{ status: "ok"; alertId: string; verdict: MonitoringVerdict }>(
    API.monitoring.verdict(id),
    { method: "PATCH", body: JSON.stringify({ verdict }) }
  );
}

export async function patchMonitoringStatus(id: string, status: MonitoringStatus) {
  return apiFetch<{ status: "ok"; alertId: string; newStatus: MonitoringStatus }>(
    API.monitoring.status(id),
    { method: "PATCH", body: JSON.stringify({ status }) }
  );
}

export async function createMonitoringTuningRule(payload: {
  eventType: string;
  scope: { type: "global" | "group" | "asset"; id?: string };
  match: Record<string, any>;
  reason?: string;
}) {
  return apiFetch<{ status: "ok"; ruleId: string }>(API.monitoring.tuning, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getMonitoringTuningRules(): Promise<{ items: MonitoringTuningRule[] }> {
  return apiFetch<{ items: MonitoringTuningRule[] }>(API.monitoring.tuning);
}

export async function patchMonitoringTuningRule(ruleId: string, enabled: boolean) {
  return apiFetch<{ status: "ok"; ruleId: string; enabled: boolean }>(
    API.monitoring.tuningById(ruleId),
    { method: "PATCH", body: JSON.stringify({ enabled }) }
  );
}

// ────────────────────────────────────────────────────────────
// Settings
// ────────────────────────────────────────────────────────────

// Organization
export async function getOrganizationSettings(): Promise<any> {
  return apiFetch<any>("/settings/organization");
}

export async function updateOrganizationSettings(payload: {
  name?: string;
  country?: string;
}): Promise<any> {
  return apiFetch<any>("/settings/organization", {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

// Members
export async function getMembers(): Promise<any[]> {
  return apiFetch<any[]>("/settings/members");
}

export async function inviteMember(payload: {
  email: string;
  role: string;
}): Promise<any> {
  return apiFetch<any>("/settings/members/invite", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getInvitations(): Promise<any[]> {
  return apiFetch<any[]>("/settings/members/invitations");
}

export async function revokeInvitation(inviteId: string): Promise<any> {
  return apiFetch<any>(`/settings/members/invitations/${inviteId}`, {
    method: "DELETE",
  });
}

export async function updateMemberRole(
  memberId: string,
  role: string
): Promise<any> {
  return apiFetch<any>(`/settings/members/${memberId}/role`, {
    method: "PATCH",
    body: JSON.stringify({ role }),
  });
}

export async function removeMember(memberId: string): Promise<any> {
  return apiFetch<any>(`/settings/members/${memberId}`, {
    method: "DELETE",
  });
}

// API Keys
export async function getApiKeys(): Promise<any[]> {
  return apiFetch<any[]>("/settings/api-keys");
}

export async function createApiKey(payload: {
  name: string;
  expiresInDays?: number;
}): Promise<any> {
  return apiFetch<any>("/settings/api-keys", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function revokeApiKey(keyId: string): Promise<any> {
  return apiFetch<any>(`/settings/api-keys/${keyId}`, {
    method: "DELETE",
  });
}

// Billing
export async function getBilling(): Promise<any> {
  return apiFetch<any>("/settings/billing");
}

// Audit Log
export async function getAuditLog(page: number = 1): Promise<any> {
  return apiFetch<any>(`/settings/audit-log?page=${page}`);
}

// Current user settings/role
export async function getMySettings(): Promise<any> {
  return apiFetch<any>("/settings/me");
}

// ────────────────────────────────────────────────────────────
// Reports (M11)
// ────────────────────────────────────────────────────────────

export type ReportScope = "organization" | "group";
export type ReportTemplate = "executive" | "technical";
export type ReportStatus = "pending" | "generating" | "ready" | "failed";

export type ReportSummaryData = {
  exposureScore: number;
  totalFindings: number;
  assetCount: number;
  groupCount: number;
  severityCounts: Record<"critical" | "high" | "medium" | "low" | "info", number>;
  categoryCounts?: Record<string, number>;
};

export type ReportItem = {
  id: string;
  title: string;
  template: ReportTemplate;
  format: string;
  scope: ReportScope;
  groupId: string | null;
  groupName: string | null;
  status: ReportStatus;
  errorMessage: string | null;
  config: Record<string, any> | null;
  fileSize: number | null;
  summaryData: ReportSummaryData | null;
  generatedBy: string | null;
  generatedAt: string | null;
  createdAt: string | null;
};

export type ReportListResponse = {
  reports: ReportItem[];
  total: number;
  page: number;
  perPage: number;
};

export type ReportScheduleItem = {
  id: string;
  name: string;
  template: ReportTemplate;
  scope: ReportScope;
  groupId: string | null;
  frequency: "weekly" | "monthly";
  dayOfWeek: number | null;
  dayOfMonth: number | null;
  hour: number;
  recipients: string[];
  includePdfAttachment: boolean;
  enabled: boolean;
  lastRunAt: string | null;
  lastReportId: string | null;
  nextRunAt: string | null;
  runCount: number;
  createdAt: string | null;
};

export async function getReports(params?: {
  scope?: ReportScope;
  groupId?: string;
  template?: ReportTemplate;
  page?: number;
  perPage?: number;
}): Promise<ReportListResponse> {
  const q = new URLSearchParams();
  if (params?.scope) q.set("scope", params.scope);
  if (params?.groupId) q.set("group_id", params.groupId);
  if (params?.template) q.set("template", params.template);
  if (params?.page) q.set("page", String(params.page));
  if (params?.perPage) q.set("per_page", String(params.perPage));

  const qs = q.toString();
  return apiFetch<ReportListResponse>(`${API.reports.list}${qs ? `?${qs}` : ""}`);
}

export async function getReport(reportId: string): Promise<ReportItem> {
  return apiFetch<ReportItem>(API.reports.byId(reportId));
}

export async function generateReport(payload: {
  template: ReportTemplate;
  scope: ReportScope;
  groupId?: string;
  title?: string;
  config?: Record<string, any>;
}): Promise<ReportItem> {
  return apiFetch<ReportItem>(API.reports.generate, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function deleteReport(reportId: string): Promise<void> {
  await apiFetch(API.reports.byId(reportId), { method: "DELETE" });
}

export async function downloadReport(reportId: string): Promise<Blob> {
  const token = (await import("./auth")).getAccessToken();
  const dlBase =
    process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/+$/, "") ||
    (typeof window !== "undefined" && window.location.hostname !== "localhost"
      ? `http://${window.location.hostname}:5000`
      : "http://127.0.0.1:5000");

  const res = await fetch(`${dlBase}${API.reports.download(reportId)}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  if (!res.ok) {
    const text = await res.text();
    let msg = "Download failed";
    try { msg = JSON.parse(text).error || msg; } catch {}
    throw new Error(msg);
  }

  return res.blob();
}

// ── Report Schedules ──

export async function getReportSchedules(): Promise<{ schedules: ReportScheduleItem[] }> {
  return apiFetch<{ schedules: ReportScheduleItem[] }>(API.reports.schedules);
}

export async function createReportSchedule(payload: {
  name: string;
  template: ReportTemplate;
  scope: ReportScope;
  groupId?: string;
  config?: Record<string, any>;
  frequency: "weekly" | "monthly";
  dayOfWeek?: number;
  dayOfMonth?: number;
  hour?: number;
  recipients?: string[];
  includePdfAttachment?: boolean;
  enabled?: boolean;
}): Promise<ReportScheduleItem> {
  return apiFetch<ReportScheduleItem>(API.reports.schedules, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateReportSchedule(
  scheduleId: string,
  payload: {
    name?: string;
    template?: ReportTemplate;
    frequency?: "weekly" | "monthly";
    dayOfWeek?: number | null;
    dayOfMonth?: number | null;
    hour?: number;
    recipients?: string[];
    includePdfAttachment?: boolean;
    enabled?: boolean;
    config?: Record<string, any>;
  }
): Promise<ReportScheduleItem> {
  return apiFetch<ReportScheduleItem>(API.reports.scheduleById(scheduleId), {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function deleteReportSchedule(scheduleId: string): Promise<void> {
  await apiFetch(API.reports.scheduleById(scheduleId), { method: "DELETE" });
}

// ── Trending API Functions ──

export async function getTrendData(params?: {
  groupId?: string;
  days?: number;
}): Promise<TrendDataResponse> {
  const searchParams = new URLSearchParams();
  if (params?.groupId) searchParams.set("group_id", params.groupId);
  if (params?.days) searchParams.set("days", String(params.days));
  const qs = searchParams.toString();
  return apiFetch(`${API.trending.data}${qs ? `?${qs}` : ""}`);
}

export async function getTrendSummary(params?: {
  groupId?: string;
}): Promise<TrendSummaryResponse> {
  const searchParams = new URLSearchParams();
  if (params?.groupId) searchParams.set("group_id", params.groupId);
  const qs = searchParams.toString();
  return apiFetch(`${API.trending.summary}${qs ? `?${qs}` : ""}`);
}

export async function generateSnapshot(params?: {
  backfill?: number;
}): Promise<{ message: string; days?: number; date?: string }> {
  return apiFetch(API.trending.snapshot, {
    method: "POST",
    body: JSON.stringify(params || {}),
  });
}

export async function getGroupTrends(): Promise<{ groups: GroupTrendItem[] }> {
  return apiFetch(API.trending.groups);
}

export async function getFindingEvents(findingId: string): Promise<{ events: FindingEventItem[] }> {
  return apiFetch(API.trending.findingEvents(findingId));
}

// ═══════════════════════════════════════════════════════════════════
// Integrations
// ═══════════════════════════════════════════════════════════════════

export interface Integration {
  id: string;
  type: "slack" | "jira" | "pagerduty" | "webhook" | "email";
  name: string;
  config: Record<string, any>;
  enabled: boolean;
  lastTestAt: string | null;
  lastTestOk: boolean | null;
  lastError: string | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface NotificationRule {
  id: string;
  integrationId: string;
  integrationName: string | null;
  integrationType: string | null;
  name: string;
  eventType: string;
  filters: Record<string, any>;
  actionMode: "notify" | "create_ticket";
  actionConfig: Record<string, any>;
  enabled: boolean;
  lastTriggeredAt: string | null;
  triggerCount: number;
  createdAt: string;
}

/// ── Integration CRUD ──

export async function listIntegrations(): Promise<Integration[]> {
  const res = await apiFetch<{ integrations: Integration[] }>("/integrations");
  return res.integrations;
}

export async function createIntegration(data: {
  type: string;
  name: string;
  config: Record<string, any>;
  enabled?: boolean;
}): Promise<Integration> {
  return apiFetch<Integration>("/integrations", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function updateIntegration(
  id: string,
  data: Partial<{ name: string; config: Record<string, any>; enabled: boolean }>
): Promise<Integration> {
  return apiFetch<Integration>(`/integrations/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function deleteIntegration(id: string): Promise<void> {
  await apiFetch(`/integrations/${id}`, { method: "DELETE" });
}

export async function testIntegration(id: string): Promise<{ success: boolean; error?: string; message?: string }> {
  return apiFetch<{ success: boolean; error?: string; message?: string }>(`/integrations/${id}/test`, {
    method: "POST",
  });
}

// ── Notification Rules CRUD ──

export async function listNotificationRules(): Promise<NotificationRule[]> {
  const res = await apiFetch<{ rules: NotificationRule[] }>("/integrations/rules");
  return res.rules;
}

export async function createNotificationRule(data: {
  integrationId: string;
  name: string;
  eventType: string;
  actionMode?: string;
  filters?: Record<string, any>;
  actionConfig?: Record<string, any>;
  enabled?: boolean;
}): Promise<NotificationRule> {
  return apiFetch<NotificationRule>("/integrations/rules", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function updateNotificationRule(
  id: string,
  data: Partial<{
    name: string;
    integrationId: string;
    eventType: string;
    actionMode: string;
    filters: Record<string, any>;
    actionConfig: Record<string, any>;
    enabled: boolean;
  }>
): Promise<NotificationRule> {
  return apiFetch<NotificationRule>(`/integrations/rules/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function deleteNotificationRule(id: string): Promise<void> {
  await apiFetch(`/integrations/rules/${id}`, { method: "DELETE" });
}