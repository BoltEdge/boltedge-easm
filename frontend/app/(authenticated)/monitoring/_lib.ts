// app/(authenticated)/monitoring/_lib.ts
// Shared types, API functions, and helpers for all monitoring pages

import { apiFetch } from "../../lib/api";

/* ================================================================
   TYPES
   ================================================================ */

export interface Monitor {
  id: string;
  assetId?: string;
  asset_id?: string;
  assetValue?: string;
  asset_value?: string;
  assetType?: string;
  asset_type?: string;
  groupId?: string;
  group_id?: string;
  groupName?: string;
  group_name?: string;
  monitorTypes: string[];
  frequency: string;
  enabled: boolean;
  baselineScanJobId?: string;
  lastScanJobId?: string;
  lastCheckedAt?: string;
  nextCheckAt?: string;
  alertCount?: number;
  openAlertCount?: number;
  createdAt?: string;
}

export interface MonitorAlert {
  id: string;
  monitorId: string;
  findingId?: string;
  alertType: string;
  templateId?: string;
  alertName?: string;
  severity: string;
  status: string;
  title: string;
  summary?: string;
  assetValue?: string;
  groupName?: string;
  notifiedVia?: string[];
  createdAt?: string;
  acknowledgedAt?: string;
}

export interface MonitorSettings {
  emailEnabled: boolean;
  inAppEnabled: boolean;
  webhookEnabled: boolean;
  webhookUrl: string;
  emailRecipients: string[];
  notifyOnSeverity: string[];
  digestFrequency: string;
}

export interface TuningRule {
  id: string;
  templateId?: string;
  category?: string;
  severityMatch?: string;
  assetId?: string;
  assetValue?: string;
  groupId?: string;
  groupName?: string;
  assetPattern?: string;
  port?: number;
  serviceName?: string;
  cwe?: string;
  titleContains?: string;
  action: string;
  targetSeverity?: string;
  snoozeUntil?: string;
  reason?: string;
  enabled: boolean;
  createdAt?: string;
  createdBy?: string;
}

/* ================================================================
   CONSTANTS
   ================================================================ */

export const MONITOR_TYPE_CONFIG: Record<string, { label: string; icon: string; color: string; bg: string }> = {
  all:     { label: "Everything",  icon: "Shield",      color: "text-primary",     bg: "bg-primary/10" },
  dns:     { label: "DNS",         icon: "Globe",       color: "text-[#00b8d4]",   bg: "bg-[#00b8d4]/10" },
  ssl:     { label: "SSL/TLS",     icon: "Lock",        color: "text-[#10b981]",   bg: "bg-[#10b981]/10" },
  ports:   { label: "Ports",       icon: "Server",      color: "text-[#ff8800]",   bg: "bg-[#ff8800]/10" },
  headers: { label: "Headers",     icon: "FileCode",    color: "text-[#a78bfa]",   bg: "bg-[#a78bfa]/10" },
  tech:    { label: "Technology",  icon: "Cpu",         color: "text-[#f472b6]",   bg: "bg-[#f472b6]/10" },
  cve:     { label: "CVEs",        icon: "ShieldAlert", color: "text-red-400",     bg: "bg-red-400/10" },
};

export const FREQUENCY_LABELS: Record<string, string> = {
  daily: "Daily",
  every_2_days: "Every 2 days",
  every_5_days: "Every 5 days",
  every_12_hours: "Every 12 hours",
  weekly: "Weekly",
};

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

/* ================================================================
   HELPERS
   ================================================================ */

export function cn(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(" ");
}

export function timeAgo(iso?: string | null) {
  if (!iso) return "Never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 0) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

export function formatWhen(iso?: string | null) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

export function monitoringFrequencyLabel(freq?: string | null): string {
  if (!freq) return "Not available";
  return FREQUENCY_LABELS[freq] || freq.replace(/_/g, " ");
}

export function alertStatusBadge(status: string) {
  switch (status) {
    case "open": return "bg-red-500/10 text-red-400 border-red-500/30";
    case "acknowledged": return "bg-[#ffcc00]/10 text-[#ffcc00] border-[#ffcc00]/30";
    case "resolved": return "bg-[#10b981]/10 text-[#10b981] border-[#10b981]/30";
    default: return "bg-muted/30 text-muted-foreground border-border";
  }
}

/* ================================================================
   API FUNCTIONS
   ================================================================ */

export async function getMonitors(): Promise<Monitor[]> {
  try {
    const res = await apiFetch<any>("/monitors");
    if (Array.isArray(res)) return res;
    if (res && Array.isArray(res.items)) return res.items;
    if (res && Array.isArray(res.monitors)) return res.monitors;
    return [];
  } catch { return []; }
}
export async function createMonitor(data: any): Promise<Monitor> {
  return await apiFetch<Monitor>("/monitors", { method: "POST", body: JSON.stringify(data) });
}
export async function updateMonitor(id: string, data: any): Promise<Monitor> {
  return await apiFetch<Monitor>(`/monitors/${id}`, { method: "PATCH", body: JSON.stringify(data) });
}
export async function deleteMonitor(id: string): Promise<void> {
  await apiFetch<void>(`/monitors/${id}`, { method: "DELETE" });
}
export async function getMonitorAlerts(params?: string): Promise<MonitorAlert[]> {
  try {
    const res = await apiFetch<any>(`/monitors/alerts${params ? `?${params}` : ""}`);
    if (Array.isArray(res)) return res;
    if (res && Array.isArray(res.alerts)) return res.alerts;
    return [];
  } catch { return []; }
}
export async function acknowledgeAlert(id: string): Promise<void> {
  await apiFetch<void>(`/monitors/alerts/${id}/acknowledge`, { method: "POST" });
}
export async function resolveAlert(id: string): Promise<void> {
  await apiFetch<void>(`/monitors/alerts/${id}/resolve`, { method: "POST" });
}
export async function getMonitorSettings(): Promise<MonitorSettings> {
  try {
    return await apiFetch<MonitorSettings>("/monitors/settings");
  } catch {
    return { emailEnabled: true, inAppEnabled: true, webhookEnabled: false, webhookUrl: "", emailRecipients: [], notifyOnSeverity: ["critical", "high"], digestFrequency: "immediate" };
  }
}
export async function updateMonitorSettings(data: any): Promise<MonitorSettings> {
  return await apiFetch<MonitorSettings>("/monitors/settings", { method: "PUT", body: JSON.stringify(data) });
}
export async function getTuningRules(): Promise<TuningRule[]> {
  try {
    const res = await apiFetch<any>("/monitors/tuning");
    if (Array.isArray(res)) return res;
    if (res && Array.isArray(res.items)) return res.items;
    if (res && Array.isArray(res.rules)) return res.rules;
    return [];
  } catch { return []; }
}
export async function createTuningRule(data: any): Promise<TuningRule> {
  return await apiFetch<TuningRule>("/monitors/tuning", { method: "POST", body: JSON.stringify(data) });
}
export async function updateTuningRule(id: string, data: any): Promise<TuningRule> {
  return await apiFetch<TuningRule>(`/monitors/tuning/${id}`, { method: "PATCH", body: JSON.stringify(data) });
}
export async function deleteTuningRule(id: string): Promise<void> {
  await apiFetch<void>(`/monitors/tuning/${id}`, { method: "DELETE" });
}
export async function getGroups(): Promise<Array<{ id: any; name: string }>> {
  try { const r = await apiFetch<any[]>("/groups"); return r.map((x: any) => ({ id: x.id, name: x.name })); } catch { return []; }
}
export async function getGroupAssets(groupId: string): Promise<any[]> {
  try { return await apiFetch<any[]>(`/groups/${groupId}/assets`); } catch { return []; }
}