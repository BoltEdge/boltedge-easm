// FILE: lib/discovery-api.ts
// Discovery Engine v2 API client
// Complements lib/api.ts — import alongside existing API functions

import { apiFetch } from "./api";

// ── Types ──

export type DiscoveryTargetType = "domain" | "ip" | "asn" | "org_name" | "cidr";
export type ScanDepth = "standard" | "deep";

export type DiscoveryJobStatus =
  | "pending" | "running" | "completed" | "partial" | "failed" | "cancelled";

export interface DiscoveryModuleStatus {
  name: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  assetsFound: number;
  durationMs: number | null;
  error: string | null;
}

export interface DiscoveredAssetItem {
  id: number;
  assetType: string;
  value: string;
  confidence: number;
  resolvedIps: string[];
  tags: string[];
  isNew: boolean;
  isIgnored: boolean;
  addedToInventory: boolean;
  addedAssetId: number | null;
  discoveredAt: string;
}

export interface EngineProgress {
  total: number;
  completed: number;
  running: number;
  failed: number;
}

export interface DiscoveryJob {
  id: number;
  target: string;
  targetType: DiscoveryTargetType;
  status: DiscoveryJobStatus;
  scanDepth: ScanDepth;
  totalFound: number;
  newAssets: number;
  countsByType: Record<string, number>;
  errorMessage: string | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
  engineProgress?: EngineProgress;
  discoveredAssets?: DiscoveredAssetItem[];
}

export interface DiscoveryJobListResponse {
  items: DiscoveryJob[];
  total: number;
  limit: number;
  offset: number;
}

export interface AddAssetsResponse {
  added: Array<{ id: number; value: string; assetId: number }>;
  skipped: Array<{ id: number; value: string; reason: string }>;
  errors: Array<{ id: number; value: string; error: string }>;
  totalAdded: number;
  totalSkipped: number;
  totalErrors: number;
}

// ── API Functions ──

export async function launchDiscovery(payload: {
  target: string;
  targetType: DiscoveryTargetType;
  scanDepth?: ScanDepth;
}): Promise<DiscoveryJob> {
  return apiFetch<DiscoveryJob>("/discovery/run", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getDiscoveryJobs(params?: {
  status?: DiscoveryJobStatus;
  limit?: number;
  offset?: number;
}): Promise<DiscoveryJobListResponse> {
  const q = new URLSearchParams();
  if (params?.status) q.set("status", params.status);
  if (params?.limit != null) q.set("limit", String(params.limit));
  if (params?.offset != null) q.set("offset", String(params.offset));
  const qs = q.toString();
  return apiFetch<DiscoveryJobListResponse>(`/discovery/jobs${qs ? `?${qs}` : ""}`);
}

export async function getDiscoveryJobDetail(jobId: number): Promise<DiscoveryJob> {
  return apiFetch<DiscoveryJob>(`/discovery/jobs/${jobId}`);
}

export async function cancelDiscoveryJob(jobId: number): Promise<void> {
  await apiFetch(`/discovery/jobs/${jobId}/cancel`, { method: "POST" });
}

export async function addDiscoveredAssetsToInventory(
  jobId: number,
  payload: { assetIds: number[]; groupId: number | string }
): Promise<AddAssetsResponse> {
  return apiFetch<AddAssetsResponse>(`/discovery/jobs/${jobId}/add-assets`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function deleteDiscoveryJob(jobId: number): Promise<void> {
  await apiFetch(`/discovery/jobs/${jobId}`, { method: "DELETE" });
}

// Group creation helper (if not available in lib/api.ts, use this one)
export async function createDiscoveryGroup(payload: { name: string; description?: string }): Promise<any> {
  return apiFetch("/groups", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateAssetTags(
  assetId: number,
  payload: { add?: string[]; remove?: string[] } | { tags: string[] },
): Promise<{ id: number; tags: string[] }> {
  return apiFetch(`/discovery/assets/${assetId}/tags`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function bulkUpdateAssetTags(
  payload: { assetIds: number[]; add?: string[]; remove?: string[] },
): Promise<{ updated: number }> {
  return apiFetch(`/discovery/assets/bulk-tags`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

// ── Ignore List ──

export interface IgnoredAsset {
  id: number;
  assetType: string;
  value: string;
  reason: string | null;
  ignoredAt: string;
}

export async function ignoreDiscoveredAssets(
  payload: { assetIds?: number[]; assets?: { assetType: string; value: string }[]; reason?: string },
): Promise<{ added: number; skipped: number }> {
  return apiFetch("/discovery/ignore", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function unignoreAssets(
  payload: { ids?: number[]; assets?: { assetType: string; value: string }[] },
): Promise<{ removed: number }> {
  return apiFetch("/discovery/ignore", {
    method: "DELETE",
    body: JSON.stringify(payload),
  });
}

export async function getIgnoredAssets(): Promise<IgnoredAsset[]> {
  return apiFetch<IgnoredAsset[]>("/discovery/ignore");
}

// ── Schedules ──

export interface DiscoverySchedule {
  id: number;
  name: string;
  target: string;
  targetType: string;
  scanDepth: string;
  frequency: string;
  dayOfWeek: number | null;
  dayOfMonth: number | null;
  hour: number;
  enabled: boolean;
  lastRunAt: string | null;
  lastJobId: number | null;
  nextRunAt: string | null;
  runCount: number;
  createdAt: string;
}

export async function getDiscoverySchedules(): Promise<DiscoverySchedule[]> {
  return apiFetch<DiscoverySchedule[]>("/discovery/schedules");
}

export async function createDiscoverySchedule(payload: {
  name: string;
  target: string;
  targetType: string;
  scanDepth?: string;
  frequency: string;
  dayOfWeek?: number;
  dayOfMonth?: number;
  hour?: number;
}): Promise<DiscoverySchedule> {
  return apiFetch<DiscoverySchedule>("/discovery/schedules", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateDiscoverySchedule(
  id: number,
  payload: Partial<{
    name: string; target: string; targetType: string; scanDepth: string;
    frequency: string; dayOfWeek: number; dayOfMonth: number; hour: number; enabled: boolean;
  }>,
): Promise<DiscoverySchedule> {
  return apiFetch<DiscoverySchedule>(`/discovery/schedules/${id}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function deleteDiscoverySchedule(id: number): Promise<void> {
  await apiFetch(`/discovery/schedules/${id}`, { method: "DELETE" });
}

export async function runScheduleNow(id: number): Promise<{ jobId: number }> {
  return apiFetch<{ jobId: number }>(`/discovery/schedules/${id}/run`, { method: "POST" });
}