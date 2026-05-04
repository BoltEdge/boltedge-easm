// =============================================================================
// Shared primitives for tool result renderers.
//
// Each tool's result renderer (cert.tsx, dns.tsx, etc.) imports from
// here so we have one place to evolve the visual language — issue
// lists, collapsibles, key/value rows, grade badges. These were
// previously inline in tools/page.tsx and duplicated subtly across
// renderers; pulling them out makes drift impossible.
// =============================================================================

"use client";

import React, { useState, useContext, createContext } from "react";
import {
  AlertTriangle, Info, ChevronDown, ChevronUp, CheckCircle2, ArrowRight,
} from "lucide-react";
import { cn } from "../../../lib/utils";

// ─── Issue / severity types ──────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Issue {
  severity: Severity | string;
  title: string;
  description?: string;
  recommendation?: string;
}

export const SEV_BORDER: Record<string, string> = {
  critical: "border-l-red-500",
  high: "border-l-orange-500",
  medium: "border-l-yellow-500",
  low: "border-l-blue-500",
  info: "border-l-emerald-500",
};

export function SevIcon({ severity }: { severity: string }) {
  switch (severity) {
    case "critical":
    case "high":
      return <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />;
    case "medium":
      return <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />;
    case "low":
      return <Info className="w-4 h-4 text-blue-400 shrink-0" />;
    default:
      return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />;
  }
}

// ─── Grade badge ──────────────────────────────────────────────────

const GRADE_COLORS: Record<string, string> = {
  A: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  B: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  C: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  D: "bg-red-500/15 text-red-400 border-red-500/30",
  F: "bg-red-500/20 text-red-300 border-red-500/40",
};

export function GradeBadge({ grade }: { grade: string | null | undefined }) {
  if (!grade) return null;
  const g = grade.replace(/[+-]/g, "");
  return (
    <span className={cn("inline-flex items-center px-3 py-1.5 rounded-lg text-lg font-bold border", GRADE_COLORS[g] || GRADE_COLORS.F)}>
      {grade}
    </span>
  );
}

// ─── Collapsible ──────────────────────────────────────────────────

export function Collapsible({
  title, defaultOpen, children,
}: {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen ?? false);
  return (
    <div className="rounded-xl border border-border bg-card/30 overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-foreground hover:bg-card/50 transition-colors"
      >
        {title}
        {open
          ? <ChevronUp className="w-4 h-4 text-muted-foreground" />
          : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
      </button>
      {open && <div className="px-4 pb-4 border-t border-border">{children}</div>}
    </div>
  );
}

// ─── Issues list ──────────────────────────────────────────────────

export function IssuesList({ issues }: { issues?: Issue[] | null }) {
  if (!issues?.length) return null;
  return (
    <div className="space-y-2">
      {issues.map((issue, i) => (
        <div
          key={i}
          className={cn(
            "flex items-start gap-3 p-3 rounded-lg border-l-2 bg-card/30 border border-border",
            SEV_BORDER[issue.severity] || SEV_BORDER.info,
          )}
        >
          <SevIcon severity={issue.severity} />
          <div className="min-w-0">
            <div className="text-sm font-medium text-foreground">{issue.title}</div>
            {issue.description && (
              <div className="text-xs text-muted-foreground mt-0.5">{issue.description}</div>
            )}
            {issue.recommendation && (
              <div className="text-xs text-primary mt-1">{issue.recommendation}</div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Key/value row ────────────────────────────────────────────────

export function KV({ label, value, mono }: { label: string; value: unknown; mono?: boolean }) {
  if (value === null || value === undefined || value === "") return null;
  const display = typeof value === "boolean" ? (value ? "Yes" : "No") : String(value);
  return (
    <div className="flex items-start gap-2 py-1.5">
      <span className="text-xs text-muted-foreground w-36 shrink-0">{label}</span>
      <span className={cn("text-xs text-foreground break-all", mono && "font-mono")}>{display}</span>
    </div>
  );
}

// ─── Protocol badge (used by email-security; reusable) ────────────

export function ProtocolBadge({
  label, found, detail,
}: {
  label: string;
  found: boolean;
  detail?: string;
}) {
  return (
    <div className={cn(
      "flex items-center gap-2.5 px-4 py-3 rounded-xl border",
      found ? "border-emerald-500/20 bg-emerald-500/5" : "border-red-500/20 bg-red-500/5",
    )}>
      {found
        ? <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
        : <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />}
      <div>
        <div className={cn("text-sm font-semibold", found ? "text-emerald-400" : "text-red-400")}>
          {label}
        </div>
        {detail && <div className="text-[11px] text-muted-foreground mt-0.5">{detail}</div>}
      </div>
    </div>
  );
}

// ─── Result-level error banner ────────────────────────────────────

export function ResultErrorBanner({ error }: { error: string }) {
  return (
    <div className="flex items-center gap-3 p-4 rounded-xl border border-red-500/20 bg-red-500/5">
      <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
      <div className="text-sm text-red-400">{error}</div>
    </div>
  );
}

// ─── Empty / "no results" success state ───────────────────────────

export function ResultEmptyOk({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-2 p-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5">
      <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
      <div className="text-sm text-emerald-400">{message}</div>
    </div>
  );
}

// ─── Cross-tool chaining (#25) ────────────────────────────────────
// Result renderers can mark extracted values (IPs, hostnames,
// domains) so the user can send them to another tool with one
// click. Wired up via context so renderers don't need props
// threaded through them.

export type ValueKind = "domain" | "ip" | "hostname" | "hash";

export type SendToToolFn = (toolId: string, target: string) => void;

export const SendToToolContext = createContext<{
  send: SendToToolFn;
  /** map of which tool ids accept which kinds of input */
  acceptsByTool: Record<string, string[]>;
  /** display name for each tool id */
  nameByTool: Record<string, string>;
} | null>(null);

// Map a generic ValueKind to the `accepts` strings used in the
// tool definitions (which use mixed-case for display). Loose
// matching by lowercasing both sides.
const KIND_TO_ACCEPT: Record<ValueKind, string[]> = {
  domain: ["domain"],
  ip: ["ipv4", "ipv6"],
  hostname: ["domain"],
  hash: ["sha-256"],
};

export function SendTo({ value, kind }: { value: string; kind: ValueKind }) {
  const ctx = useContext(SendToToolContext);
  const [open, setOpen] = useState(false);
  if (!ctx || !value) return null;

  const wanted = KIND_TO_ACCEPT[kind].map((s) => s.toLowerCase());
  const compatible = Object.entries(ctx.acceptsByTool)
    .filter(([, accepts]) => accepts.some((a) => wanted.includes(a.toLowerCase())))
    .map(([toolId]) => toolId);

  if (compatible.length === 0) return null;

  return (
    <span className="relative inline-flex">
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); setOpen((o) => !o); }}
        title={`Send "${value}" to another tool`}
        className="inline-flex items-center justify-center w-4 h-4 rounded text-muted-foreground/40 hover:text-primary hover:bg-primary/10 transition-colors"
      >
        <ArrowRight className="w-3 h-3" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute top-full left-0 mt-1 z-50 min-w-[160px] rounded-lg border border-white/[0.08] bg-[#0c1222]/98 backdrop-blur-xl shadow-2xl py-1">
            <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">
              Send to
            </div>
            {compatible.map((toolId) => (
              <button
                key={toolId}
                onClick={(e) => {
                  e.stopPropagation();
                  ctx.send(toolId, value);
                  setOpen(false);
                }}
                className="w-full flex items-center gap-2 px-3 py-1.5 text-left text-[12px] text-foreground hover:bg-white/[0.06] transition-colors"
              >
                <ArrowRight className="w-3 h-3 text-primary shrink-0" />
                {ctx.nameByTool[toolId] || toolId}
              </button>
            ))}
          </div>
        </>
      )}
    </span>
  );
}

// ─── Header row used by most result renderers ────────────────────
// Most tools open their result with: optional grade badge + a primary
// label + a subtitle. Pulling this out kills five copies of the same
// JSX scattered across the renderers.

export function ResultHeaderRow({
  grade, label, subtitle, badge,
}: {
  grade?: string | null;
  label: React.ReactNode;
  subtitle?: React.ReactNode;
  badge?: { text: string; color: string };
}) {
  return (
    <div className="flex items-center gap-4">
      {grade !== undefined && <GradeBadge grade={grade} />}
      <div>
        <div className="flex items-center gap-2">
          {badge && (
            <span
              className="px-2 py-0.5 rounded text-[10px] font-semibold border"
              style={{
                backgroundColor: `${badge.color}1a`,
                color: badge.color,
                borderColor: `${badge.color}33`,
              }}
            >
              {badge.text}
            </span>
          )}
          <span className="text-sm font-medium text-foreground">{label}</span>
        </div>
        {subtitle && <div className="text-xs text-muted-foreground mt-0.5">{subtitle}</div>}
      </div>
    </div>
  );
}
