// app/FindingDetailsDialog.tsx
// Finding detail dialog with full F2 status workflow
// Statuses: open → in_progress → resolved, or open → accepted_risk, or open → suppressed
// M9 RBAC: action buttons hidden when onStatusChange not provided (viewer has no edit_findings)
"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  EyeOff, Eye, Info, ShieldAlert, Wrench, ExternalLink,
  Tag, BookOpen, CheckCircle2, AlertCircle, RotateCcw,
  Clock, ShieldCheck, ChevronDown, Loader2, Siren, Sparkles, X,
} from "lucide-react";

import { Button } from "./ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "./ui/dialog";
import { SeverityBadge } from "./SeverityBadge";
import { cn } from "./lib/utils";
import { explainFinding, type FindingExplanation } from "./lib/api";

type FindingStatus = "open" | "in_progress" | "accepted_risk" | "suppressed" | "resolved";

const STATUS_CONFIG: Record<FindingStatus, {
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  badgeClass: string;
}> = {
  open: {
    label: "Open",
    icon: AlertCircle,
    color: "text-red-400",
    badgeClass: "bg-red-500/15 text-red-300 border-red-500/30",
  },
  in_progress: {
    label: "In Progress",
    icon: Clock,
    color: "text-blue-400",
    badgeClass: "bg-blue-500/15 text-blue-300 border-blue-500/30",
  },
  accepted_risk: {
    label: "Accepted Risk",
    icon: ShieldCheck,
    color: "text-amber-400",
    badgeClass: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  },
  suppressed: {
    label: "Suppressed",
    icon: EyeOff,
    color: "text-zinc-400",
    badgeClass: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
  },
  resolved: {
    label: "Resolved",
    icon: CheckCircle2,
    color: "text-emerald-400",
    badgeClass: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  },
};

function formatDate(d?: any) {
  if (!d) return "\u2014";
  let dt: Date;
  if (typeof d === "string" && !d.endsWith("Z") && !d.includes("+")) dt = new Date(d + "Z");
  else dt = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(dt.getTime())) return "\u2014";
  return dt.toLocaleString();
}

function safeText(v: any) {
  return v == null || v === "" ? "\u2014" : String(v);
}

const CATEGORY_CONFIG: Record<string, { label: string; color: string }> = {
  ssl:              { label: "SSL / TLS",        color: "bg-purple-500/15 text-purple-300 border-purple-500/30" },
  ports:            { label: "Ports",            color: "bg-blue-500/15 text-blue-300 border-blue-500/30" },
  headers:          { label: "HTTP Headers",     color: "bg-amber-500/15 text-amber-300 border-amber-500/30" },
  cve:              { label: "CVE",              color: "bg-red-500/15 text-red-300 border-red-500/30" },
  dns:              { label: "DNS / Email",      color: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30" },
  tech:             { label: "Technology",       color: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" },
  technology:       { label: "Technology",       color: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" },
  api:              { label: "API",              color: "bg-rose-500/15 text-rose-300 border-rose-500/30" },
  exposure:         { label: "Exposure",         color: "bg-orange-500/15 text-orange-300 border-orange-500/30" },
  misconfiguration: { label: "Misconfiguration", color: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30" },
  vulnerability:    { label: "Vulnerability",    color: "bg-red-500/15 text-red-300 border-red-500/30" },
};

function CategoryBadge({ category }: { category?: string }) {
  if (!category) return null;
  const cfg = CATEGORY_CONFIG[category.toLowerCase()] || {
    label: category,
    color: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
  };
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium ${cfg.color}`}>
      <Tag className="w-3 h-3" />
      {cfg.label}
    </span>
  );
}

function ConfidenceBadge({ confidence }: { confidence?: string }) {
  if (!confidence) return null;
  const c = confidence.toLowerCase();
  const cfg = c === "high"
    ? { icon: CheckCircle2, color: "text-emerald-400", label: "High confidence" }
    : c === "medium"
    ? { icon: AlertCircle, color: "text-amber-400", label: "Medium confidence" }
    : { icon: AlertCircle, color: "text-zinc-400", label: "Low confidence" };
  const Icon = cfg.icon;
  return (
    <span className={`inline-flex items-center gap-1 text-xs ${cfg.color}`}>
      <Icon className="w-3 h-3" />
      {cfg.label}
    </span>
  );
}

function StatusBadge({ status }: { status: FindingStatus }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.open;
  const Icon = cfg.icon;
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs font-medium ${cfg.badgeClass}`}>
      <Icon className="w-3 h-3" />
      {cfg.label}
    </span>
  );
}

function Section({
  icon,
  title,
  children,
  className,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`bg-card border border-border rounded-lg p-4 ${className || ""}`}>
      <div className="flex items-center gap-2 mb-3">
        <span className="text-muted-foreground">{icon}</span>
        <div className="text-xs font-semibold text-muted-foreground uppercase">
          {title}
        </div>
      </div>
      {children}
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-sm font-semibold text-foreground mt-1">{value}</div>
    </div>
  );
}

// ── Status Action Menu ──
function StatusActions({
  currentStatus,
  onStatusChange,
  loading,
}: {
  currentStatus: FindingStatus;
  onStatusChange: (status: FindingStatus, notes?: string) => void;
  loading: boolean;
}) {
  const [showMenu, setShowMenu] = useState(false);
  const [pendingStatus, setPendingStatus] = useState<FindingStatus | null>(null);
  const [notes, setNotes] = useState("");

  // Define available transitions from each status
  const transitions: Record<FindingStatus, { status: FindingStatus; label: string; icon: React.ComponentType<{ className?: string }>; color: string }[]> = {
    open: [
      { status: "in_progress", label: "Start Working", icon: Clock, color: "text-blue-400" },
      { status: "resolved", label: "Resolve", icon: CheckCircle2, color: "text-emerald-400" },
      { status: "accepted_risk", label: "Accept Risk", icon: ShieldCheck, color: "text-amber-400" },
      { status: "suppressed", label: "Suppress", icon: EyeOff, color: "text-zinc-400" },
    ],
    in_progress: [
      { status: "resolved", label: "Resolve", icon: CheckCircle2, color: "text-emerald-400" },
      { status: "accepted_risk", label: "Accept Risk", icon: ShieldCheck, color: "text-amber-400" },
      { status: "open", label: "Reopen", icon: RotateCcw, color: "text-red-400" },
    ],
    accepted_risk: [
      { status: "open", label: "Reopen", icon: RotateCcw, color: "text-red-400" },
      { status: "in_progress", label: "Start Working", icon: Clock, color: "text-blue-400" },
      { status: "resolved", label: "Resolve", icon: CheckCircle2, color: "text-emerald-400" },
    ],
    suppressed: [
      { status: "open", label: "Unsuppress", icon: Eye, color: "text-red-400" },
      { status: "in_progress", label: "Start Working", icon: Clock, color: "text-blue-400" },
      { status: "resolved", label: "Resolve", icon: CheckCircle2, color: "text-emerald-400" },
    ],
    resolved: [
      { status: "open", label: "Reopen", icon: RotateCcw, color: "text-red-400" },
      { status: "in_progress", label: "Start Working", icon: Clock, color: "text-blue-400" },
    ],
  };

  const available = transitions[currentStatus] || [];

  function handleSelect(status: FindingStatus) {
    // accepted_risk requires justification — always show notes prompt
    if (status === "accepted_risk") {
      setPendingStatus(status);
      setNotes("");
      setShowMenu(false);
      return;
    }
    // For other statuses, allow optional notes
    setPendingStatus(status);
    setNotes("");
    setShowMenu(false);
  }

  function handleConfirm() {
    if (!pendingStatus) return;
    onStatusChange(pendingStatus, notes.trim() || undefined);
    setPendingStatus(null);
    setNotes("");
  }

  function handleCancel() {
    setPendingStatus(null);
    setNotes("");
  }

  // Notes prompt dialog
  if (pendingStatus) {
    const cfg = STATUS_CONFIG[pendingStatus];
    const Icon = cfg.icon;
    const isAcceptedRisk = pendingStatus === "accepted_risk";

    return (
      <div className="bg-card border border-border rounded-lg p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Icon className={`w-4 h-4 ${cfg.color}`} />
          <span className="text-sm font-medium text-foreground">
            {pendingStatus === "open" ? "Reopen finding" : `Set to ${cfg.label}`}
          </span>
        </div>
        <div className="space-y-1.5">
          <label className="text-xs text-muted-foreground block">
            {isAcceptedRisk ? "Justification (required)" : "Notes (optional)"}
          </label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder={
              isAcceptedRisk
                ? "e.g., Risk accepted per security review — compensating controls in place\u2026"
                : pendingStatus === "suppressed"
                ? "e.g., False positive, compensating control\u2026"
                : pendingStatus === "resolved"
                ? "e.g., Patched in v2.4.1, DMARC record added\u2026"
                : pendingStatus === "in_progress"
                ? "e.g., Assigned to infra team, tracking in JIRA-1234\u2026"
                : "Add a note\u2026"
            }
            rows={2}
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground outline-none focus:ring-2 focus:ring-primary/40 resize-none"
          />
        </div>
        <div className="flex items-center gap-2 justify-end">
          <Button variant="outline" size="sm" onClick={handleCancel} disabled={loading}>
            Cancel
          </Button>
          <Button
            size="sm"
            onClick={handleConfirm}
            disabled={loading || (isAcceptedRisk && !notes.trim())}
            className="gap-1.5"
          >
            {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            Confirm
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="relative">
      <Button
        variant="outline"
        size="sm"
        onClick={() => setShowMenu(!showMenu)}
        className="gap-1.5"
        disabled={loading}
      >
        Change Status
        <ChevronDown className="w-3.5 h-3.5" />
      </Button>

      {showMenu && (
        <>
          {/* Backdrop */}
          <div className="fixed inset-0 z-40" onClick={() => setShowMenu(false)} />
          {/* Menu */}
          <div className="absolute right-0 top-full mt-1 z-50 bg-card border border-border rounded-lg shadow-lg py-1 min-w-[180px]">
            {available.map(({ status, label, icon: Icon, color }) => (
              <button
                key={status}
                onClick={() => handleSelect(status)}
                className="w-full flex items-center gap-2 px-3 py-2 text-sm hover:bg-accent/30 transition-colors text-left"
              >
                <Icon className={`w-4 h-4 ${color}`} />
                <span className="text-foreground">{label}</span>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// ── Nano EASM Assistant ──────────────────────────────────────────────────────
// Backed by the FindingTemplate registry on the server, not an external LLM.
// State is owned by the dialog so the button (in the toolbar) and the result
// panel (in the body) can render in separate parts of the layout.
type AiState = {
  loading: boolean;
  explanation: FindingExplanation | null;
  error: string | null;
  visible: boolean;  // collapsed/expanded
};

function NanoAiBar({
  state,
  onLoad,
}: {
  state: AiState;
  onLoad: () => void;
}) {
  // Collapsed-state banner — full-width row at the top of the dialog body so
  // it doesn't crowd the header toolbar.
  if (state.visible) return null;

  return (
    <div className="flex items-center justify-between gap-3 rounded-xl border border-teal-500/20 bg-teal-500/[0.04] px-4 py-3">
      <div className="flex items-center gap-2.5 min-w-0">
        <Sparkles className="w-4 h-4 text-teal-300 shrink-0" />
        <div className="min-w-0">
          <div className="text-sm font-medium text-teal-100">Nano EASM Assistant</div>
          <div className="text-xs text-muted-foreground">
            Get a plain-English explanation, evidence, and remediation steps for this finding.
          </div>
        </div>
      </div>
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={onLoad}
        disabled={state.loading}
        className="gap-1.5 border-teal-500/40 text-teal-300 hover:bg-teal-500/10 shrink-0"
      >
        {state.loading
          ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
          : <Sparkles className="w-3.5 h-3.5" />}
        {state.loading ? "Thinking…" : state.explanation ? "Show again" : "Explain"}
      </Button>
    </div>
  );
}

function NanoAiPanel({
  state,
  onRegenerate,
  onHide,
}: {
  state: AiState;
  onRegenerate: () => void;
  onHide: () => void;
}) {
  if (!state.visible) return null;

  return (
    <div className="rounded-xl border border-teal-500/20 bg-teal-500/[0.04] overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-teal-500/15">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-teal-300" />
          <span className="text-xs font-semibold text-teal-200 uppercase tracking-wide">
            Nano EASM Assistant
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRegenerate}
            disabled={state.loading}
            className="text-[11px] text-teal-300/70 hover:text-teal-200 transition-colors disabled:opacity-50"
          >
            {state.loading ? "Refreshing…" : "Regenerate"}
          </button>
          <button
            type="button"
            onClick={onHide}
            className="text-[11px] text-muted-foreground hover:text-foreground transition-colors"
          >
            Hide
          </button>
        </div>
      </div>

      <div className="px-4 py-4 space-y-4">
        {state.error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3.5 py-2.5 text-sm text-red-200 flex items-start gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{state.error}</span>
          </div>
        )}

        {state.explanation && (
          <>
            <ExplanationSection label="Summary" body={state.explanation.summary} />
            <ExplanationSection label="Technical explanation" body={state.explanation.technicalExplanation} />
            <ExplanationSection label="Evidence" body={state.explanation.evidence} mono />
            <ExplanationSection label="Recommended remediation" body={state.explanation.remediation} />
            <ExplanationSection label="Summary" body={state.explanation.clientSummary} />

            <p className="text-[10px] text-muted-foreground/60 pt-1 border-t border-border/30">
              Generated from the Nano EASM finding knowledge base — deterministic, no external AI services involved.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

function ExplanationSection({
  label,
  body,
  mono = false,
}: {
  label: string;
  body: string;
  mono?: boolean;
}) {
  if (!body) return null;
  return (
    <div>
      <div className="text-[10px] font-semibold text-teal-300/70 uppercase tracking-wider mb-1.5">
        {label}
      </div>
      <pre
        className={
          mono
            ? "whitespace-pre-wrap break-words font-mono text-[11px] text-foreground/80 bg-background/40 border border-border/50 rounded-md px-3 py-2 leading-relaxed"
            : "whitespace-pre-wrap break-words font-sans text-sm text-foreground/85 leading-relaxed"
        }
      >
        {body}
      </pre>
    </div>
  );
}


export function FindingDetailsDialog({
  open,
  onOpenChange,
  finding,
  onStatusChange,
  onEscalate,
  // Legacy callbacks — still supported for backward compat
  onToggleIgnore,
  onToggleResolve,
  // "dialog" (default) — opens as a modal drawer.
  // "panel"  — renders inline as a non-modal panel for split-pane layouts.
  mode = "dialog",
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  finding: any | null;
  onStatusChange?: (id: string, status: FindingStatus, notes?: string) => Promise<void> | void;
  onEscalate?: (id: string, payload: { note?: string; acknowledge?: boolean }) => Promise<void> | void;
  onToggleIgnore?: (id: string, next: boolean) => void;
  onToggleResolve?: (id: string, next: boolean) => void;
  mode?: "dialog" | "panel";
}) {
  const [actionLoading, setActionLoading] = useState(false);
  const [escalateOpen, setEscalateOpen] = useState(false);
  const [escalateNote, setEscalateNote] = useState("");
  const [escalateAck, setEscalateAck] = useState(true);
  const [escalating, setEscalating] = useState(false);

  // Nano EASM Assistant state — see NanoAiBar / NanoAiPanel above.
  const [aiState, setAiState] = useState<AiState>({
    loading: false, explanation: null, error: null, visible: false,
  });

  // Reset AI state when the dialog switches to a different finding so a
  // stale explanation from another row never shows.
  const findingIdRaw = finding ? String(finding.id) : null;
  useEffect(() => {
    setAiState({ loading: false, explanation: null, error: null, visible: false });
  }, [findingIdRaw]);

  async function loadAiExplanation(findingId: string) {
    // Toggle visibility if we already have a successful explanation cached.
    if (aiState.explanation && !aiState.error) {
      setAiState((s) => ({ ...s, visible: !s.visible }));
      return;
    }
    setAiState({ loading: true, explanation: null, error: null, visible: true });
    try {
      const res = await explainFinding(findingId);
      setAiState({ loading: false, explanation: res.explanation, error: null, visible: true });
    } catch (e: any) {
      setAiState({
        loading: false,
        explanation: null,
        error: e?.message || "Could not generate an explanation right now.",
        visible: true,
      });
    }
  }

  if (!finding) return null;

  const id = String(finding.id);
  const ignored = Boolean(finding.ignored);
  const resolved = Boolean(finding.resolved);
  const inProgress = Boolean(finding.inProgress || finding.in_progress);
  const acceptedRisk = Boolean(finding.acceptedRisk || finding.accepted_risk);

  // Derive status
  let status: FindingStatus;
  if (finding.status && ["open", "in_progress", "accepted_risk", "suppressed", "resolved"].includes(finding.status)) {
    status = finding.status as FindingStatus;
  } else if (resolved) {
    status = "resolved";
  } else if (acceptedRisk) {
    status = "accepted_risk";
  } else if (ignored) {
    status = "suppressed";
  } else if (inProgress) {
    status = "in_progress";
  } else {
    status = "open";
  }

  const canEdit = Boolean(onStatusChange || onToggleIgnore || onToggleResolve);

  const title =
    finding.title || finding.name || finding.finding || finding.rule_name || "Finding";

  // Tags
  const severity = finding.severity ?? "info";
  const cvss = finding.cvss ?? finding.cvss_score ?? finding.score ?? null;
  const cve = finding.cve ?? finding.cve_id ?? null;
  const cwe = finding.cwe ?? null;
  const category = finding.category ?? null;
  const confidence = finding.confidence ?? null;

  // Remediation
  const remediation =
    finding.remediation ??
    finding.remediationSteps?.join("\n") ??
    finding.recommendations?.join("\n") ??
    null;

  // References
  const references: string[] = finding.references ?? [];

  // Tags
  const tags: string[] = finding.tags ?? [];

  // Core details
  const detectedAt =
    finding.detectedAt || finding.detected_at || finding.createdAt || finding.created_at || finding.timestamp || null;

  const assetValue = finding.asset?.value ?? finding.assetValue ?? finding.asset_value ?? "\u2014";
  const assetType = finding.asset?.type ?? finding.assetType ?? finding.asset_type ?? "\u2014";

  const groupId = finding.group?.id ?? finding.groupId ?? finding.group_id ?? null;
  const groupName = finding.group?.name ?? finding.groupName ?? "\u2014";

  const affectedComponent =
    finding.affectedComponent || finding.affected_component || finding.component || null;

  const description =
    finding.description || finding.summary || finding.message || "";

  const technical =
    finding.technicalDetails || finding.technical_details || finding.technical || finding.evidence || "";

  // Check if this is an exposure score finding
  const templateId = finding.templateId ?? finding.template_id ?? null;
  const isExposureScore = templateId === "exposure-score" || title.includes("Exposure Score");
  const exposureDetails = isExposureScore ? finding.details : null;

  // Status metadata
  const statusNotes =
    finding.resolvedReason || finding.resolved_reason ||
    finding.acceptedRiskJustification || finding.accepted_risk_justification ||
    finding.ignoredReason || finding.ignored_reason ||
    finding.inProgressNotes || finding.in_progress_notes ||
    null;

  const statusAt =
    finding.resolvedAt || finding.resolved_at ||
    finding.acceptedRiskAt || finding.accepted_risk_at ||
    finding.ignoredAt || finding.ignored_at ||
    finding.inProgressAt || finding.in_progress_at ||
    null;

  async function handleStatusChange(newStatus: FindingStatus, notes?: string) {
    setActionLoading(true);
    try {
      if (onStatusChange) {
        await onStatusChange(id, newStatus, notes);
      } else {
        // Legacy fallback
        if (newStatus === "suppressed" && onToggleIgnore) {
          onToggleIgnore(id, true);
        } else if (newStatus === "open" && status === "suppressed" && onToggleIgnore) {
          onToggleIgnore(id, false);
        } else if (newStatus === "resolved" && onToggleResolve) {
          onToggleResolve(id, true);
        } else if (newStatus === "open" && status === "resolved" && onToggleResolve) {
          onToggleResolve(id, false);
        }
      }
    } finally {
      setActionLoading(false);
    }
  }

  // ── Header content — same in both modes, but DialogTitle is only valid
  //    inside a Radix Dialog. Rendered as a plain h2 in panel mode.
  const headerInner = (
    <>
      <div className="min-w-0">
        {mode === "dialog" ? (
          <DialogTitle className="text-xl">{title}</DialogTitle>
        ) : (
          <h2 className="text-xl font-semibold leading-none tracking-tight text-foreground">
            {title}
          </h2>
        )}

            {/* Human-readable summary */}
            {finding.summary && (
              <p className="mt-1.5 text-sm text-muted-foreground">{finding.summary}</p>
            )}

            {/* Badges row */}
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={severity} />
              <StatusBadge status={status} />
              <CategoryBadge category={category} />

              {cvss != null && (
                <span className="inline-flex items-center rounded-md bg-accent px-2.5 py-1 text-xs font-medium text-foreground/90">
                  CVSS {safeText(cvss)}
                </span>
              )}

              {cve && (
                <span className="inline-flex items-center rounded-md bg-primary/20 border border-primary/30 px-2.5 py-1 text-xs font-medium text-primary">
                  {safeText(cve)}
                </span>
              )}

              {cwe && (
                <span className="inline-flex items-center rounded-md bg-amber-500/15 border border-amber-500/30 px-2.5 py-1 text-xs font-medium text-amber-300">
                  {cwe}
                </span>
              )}

              <ConfidenceBadge confidence={confidence} />
            </div>

            <div className="text-sm text-muted-foreground mt-2">
              Detailed information for this security finding
            </div>
          </div>

          {/* Action toolbar: Escalate + Status (AI assistant lives in body) */}
          <div className="shrink-0 flex items-center gap-2 flex-wrap">
            {onEscalate && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => { setEscalateNote(""); setEscalateAck(true); setEscalateOpen(true); }}
                className="gap-1.5 border-amber-500/30 text-amber-300 hover:bg-amber-500/10"
                title="Send to alerts inbox via your notification rules"
              >
                <Siren className="w-3.5 h-3.5" />
                Escalate to Alert
              </Button>
            )}
            {canEdit && (
              <StatusActions
                currentStatus={status}
                onStatusChange={handleStatusChange}
                loading={actionLoading}
              />
            )}
            {mode === "panel" && (
              <button
                type="button"
                onClick={() => onOpenChange(false)}
                aria-label="Close panel"
                className="p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent/30 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        </>
      );

  // ── Body content — same in both modes ──
  const bodyInner = (
    <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">
          {/* Exposure Score Card (special rendering) */}
          {isExposureScore && exposureDetails && (
            <div className="bg-card border border-border rounded-lg p-5">
              <div className="flex items-center gap-4 mb-4">
                <div className={`text-4xl font-bold ${
                  exposureDetails.exposure_score >= 70 ? "text-red-400" :
                  exposureDetails.exposure_score >= 40 ? "text-amber-400" :
                  exposureDetails.exposure_score >= 20 ? "text-yellow-400" : "text-emerald-400"
                }`}>
                  {exposureDetails.exposure_score}/100
                </div>
                <div>
                  <div className="text-lg font-semibold text-foreground">Grade {exposureDetails.grade}</div>
                  <div className="text-sm text-muted-foreground">{exposureDetails.grade_description}</div>
                </div>
              </div>

              {exposureDetails.category_breakdown && (
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mt-3">
                  {Object.entries(exposureDetails.category_breakdown).map(([cat, data]: [string, any]) => (
                    <div key={cat} className="bg-background/50 border border-border rounded-md p-3">
                      <div className="text-xs text-muted-foreground uppercase mb-1">{cat}</div>
                      <div className="text-lg font-semibold text-foreground">{data.count} findings</div>
                      <div className="flex gap-1.5 mt-1 flex-wrap">
                        {data.critical > 0 && <span className="text-[10px] bg-red-500/15 text-red-300 px-1.5 py-0.5 rounded">{data.critical} crit</span>}
                        {data.high > 0 && <span className="text-[10px] bg-orange-500/15 text-orange-300 px-1.5 py-0.5 rounded">{data.high} high</span>}
                        {data.medium > 0 && <span className="text-[10px] bg-yellow-500/15 text-yellow-300 px-1.5 py-0.5 rounded">{data.medium} med</span>}
                        {data.low > 0 && <span className="text-[10px] bg-blue-500/15 text-blue-300 px-1.5 py-0.5 rounded">{data.low} low</span>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Status context card — show when finding has status metadata */}
          {status !== "open" && (statusNotes || statusAt) && (
            <Section
              icon={(() => { const Icon = STATUS_CONFIG[status].icon; return <Icon className="w-4 h-4" />; })()}
              title="Status Details"
              className={
                status === "accepted_risk" ? "border-amber-500/20 bg-amber-500/[0.03]" :
                status === "resolved" ? "border-emerald-500/20 bg-emerald-500/[0.03]" :
                status === "in_progress" ? "border-blue-500/20 bg-blue-500/[0.03]" :
                ""
              }
            >
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <InfoRow
                  label="Status"
                  value={<StatusBadge status={status} />}
                />
                {statusAt && (
                  <InfoRow label="Changed" value={formatDate(statusAt)} />
                )}
                {statusNotes && (
                  <div className="md:col-span-2">
                    <InfoRow
                      label={status === "accepted_risk" ? "Justification" : "Notes"}
                      value={
                        <div className="text-sm text-foreground/90 whitespace-pre-wrap">{statusNotes}</div>
                      }
                    />
                  </div>
                )}
              </div>
            </Section>
          )}

          {/* Asset info card */}
          <Section icon={<Info className="w-4 h-4" />} title="Asset Information">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <InfoRow
                label="Asset"
                value={
                  groupId ? (
                    <Link href={`/groups/${groupId}`} className="text-primary hover:underline font-mono">{assetValue}</Link>
                  ) : (
                    <span className="font-mono">{assetValue}</span>
                  )
                }
              />
              <InfoRow label="Type" value={safeText(assetType).toUpperCase()} />
              <InfoRow
                label="Asset Group"
                value={
                  groupId ? (
                    <Link href={`/groups/${groupId}`} className="text-primary hover:underline">{groupName}</Link>
                  ) : (
                    safeText(groupName)
                  )
                }
              />
              <InfoRow label="Detected" value={formatDate(detectedAt)} />
              {affectedComponent && <InfoRow label="Affected Component" value={safeText(affectedComponent)} />}
            </div>
          </Section>

          {/* Description */}
          <Section icon={<ShieldAlert className="w-4 h-4" />} title="Description">
            {description ? (
              <div className="text-sm text-foreground/90 whitespace-pre-wrap">{description}</div>
            ) : (
              <div className="text-sm text-muted-foreground">{"\u2014"}</div>
            )}
          </Section>

          {/* Nano EASM Assistant \u2014 slim banner when collapsed, full panel when expanded */}
          <NanoAiBar state={aiState} onLoad={() => loadAiExplanation(id)} />
          <NanoAiPanel
            state={aiState}
            onRegenerate={() => {
              setAiState({ loading: false, explanation: null, error: null, visible: true });
              loadAiExplanation(id);
            }}
            onHide={() => setAiState((s) => ({ ...s, visible: false }))}
          />

          {/* Remediation */}
          {remediation && (
            <Section icon={<Wrench className="w-4 h-4" />} title="Remediation" className="border-emerald-500/20 bg-emerald-500/[0.03]">
              <div className="text-sm text-foreground/90 whitespace-pre-wrap">{remediation}</div>
            </Section>
          )}

          {/* References */}
          {references.length > 0 && (
            <Section icon={<BookOpen className="w-4 h-4" />} title="References">
              <div className="space-y-1.5">
                {references.map((ref, i) => (
                  <a
                    key={i}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1.5 text-sm text-primary hover:underline truncate"
                  >
                    <ExternalLink className="w-3.5 h-3.5 shrink-0" />
                    {ref}
                  </a>
                ))}
              </div>
            </Section>
          )}

          {/* Technical details */}
          {technical && (
            <Section icon={<Wrench className="w-4 h-4" />} title="Technical Details">
              <div className="text-sm text-foreground/90 whitespace-pre-wrap">
                {typeof technical === "string" ? technical : JSON.stringify(technical, null, 2)}
              </div>
            </Section>
          )}

          {/* Tags */}
          {tags.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground uppercase">
                <Tag className="w-3.5 h-3.5" />Tags
              </div>
              <div className="flex flex-wrap gap-1.5">
                {tags.map((tag, i) => (
                  <span key={i} className="inline-flex items-center rounded-md bg-accent/50 border border-border px-2 py-0.5 text-xs text-muted-foreground">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}
    </div>
  );

  // ── Escalate sub-modal — same in both modes ──
  const escalateModal = (
    <Dialog open={escalateOpen} onOpenChange={(o) => { if (!o && !escalating) setEscalateOpen(false); }}>
        <DialogContent className="bg-card border-border text-foreground sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Siren className="w-5 h-5 text-amber-400" />
              Escalate to Alert
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <p className="text-sm text-muted-foreground">
              Creates an alert from this finding and routes it through your notification
              rules (Slack, Jira, etc.). The finding itself is preserved.
            </p>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-foreground block">Note (optional)</label>
              <textarea
                value={escalateNote}
                onChange={(e) => setEscalateNote(e.target.value)}
                placeholder="Why is this being escalated?"
                rows={3}
                className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
              />
            </div>
            <label className="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer">
              <input
                type="checkbox"
                checked={escalateAck}
                onChange={(e) => setEscalateAck(e.target.checked)}
                className="accent-primary"
              />
              Mark this finding as &quot;In Progress&quot;
            </label>
            <div className="flex gap-3 justify-end pt-2">
              <Button
                variant="outline"
                onClick={() => setEscalateOpen(false)}
                disabled={escalating}
              >
                Cancel
              </Button>
              <Button
                onClick={async () => {
                  if (!onEscalate) return;
                  setEscalating(true);
                  try {
                    await onEscalate(id, {
                      note: escalateNote.trim() || undefined,
                      acknowledge: escalateAck,
                    });
                    setEscalateOpen(false);
                  } finally {
                    setEscalating(false);
                  }
                }}
                disabled={escalating}
                className="bg-amber-500 hover:bg-amber-600 text-white"
              >
                <Siren className="w-4 h-4 mr-2" />
                {escalating ? "Escalating..." : "Escalate"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
  );

  // ── Render — panel (inline) vs dialog (modal drawer) ──
  if (mode === "panel") {
    return (
      <>
        <div className="bg-card border border-border rounded-xl flex flex-col h-full overflow-hidden">
          <div className="sticky top-0 z-10 bg-card border-b border-border pl-6 pr-6 pt-6 pb-4 flex flex-row items-start justify-between gap-4">
            {headerInner}
          </div>
          {bodyInner}
        </div>
        {escalateModal}
      </>
    );
  }

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent
          className={cn(
            "left-auto right-0 top-0 translate-x-0 translate-y-0",
            "h-screen max-h-screen w-[min(820px,95vw)] max-w-none",
            "rounded-l-2xl rounded-r-none",
            "border-0 border-l border-border",
            "p-0",
            "flex flex-col gap-0",
          )}
        >
          <DialogHeader className="sticky top-0 z-10 bg-card border-b border-border pl-6 pr-14 pt-6 pb-4 flex flex-row items-start justify-between gap-4">
            {headerInner}
          </DialogHeader>
          {bodyInner}
        </DialogContent>
      </Dialog>
      {escalateModal}
    </>
  );
}