"use client";

import React, { useEffect, useState, useCallback, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Lock, Globe, Shield, FileText, Search, RefreshCcw,
  Loader2, ChevronDown, ChevronUp, Plug, Mail,
  FolderSearch, GitBranch, X, Plus,
  Play, Target, Trash2, Copy, Download,
  Maximize2, Minimize2, AlertCircle, LayoutGrid, Server, GripVertical,
  Siren, List, History, Bookmark, Link as LinkIcon, StickyNote,
} from "lucide-react";

import { apiFetch, createManualAlert, type Severity } from "../../lib/api";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../ui/dialog";
import { useOrg } from "../contexts/OrgContext";
import { cn } from "../../lib/utils";
import { formatToolResultSummary, suggestAlertTitle, suggestSeverity } from "./formatToolSummary";
import { RichResultView } from "./results";
import { SendToToolContext } from "./results/_shared";

/* ═══════════════════════════════════════════════════════════════
   TOOL DEFINITIONS
   ═══════════════════════════════════════════════════════════════ */

type ToolId = "cert-lookup" | "dns-lookup" | "reverse-dns" | "header-check" | "whois" | "connectivity-check" | "email-security" | "sensitive-paths" | "github-leaks";

interface ToolDef {
  id: ToolId;
  name: string;
  description: string;
  icon: React.ReactNode;
  inputPlaceholder: string;
  inputField: string;
  accepts: string[];
  color: string;
  iconBg: string;
  category: string;
}

const TOOLS: ToolDef[] = [
  { id: "cert-lookup", name: "Certificate Lookup", description: "SSL/TLS certs by domain or SHA-256", icon: <Lock className="w-4 h-4" />, inputPlaceholder: "example.com or AB:CD:EF:12:34...", inputField: "query", accepts: ["Domain", "SHA-256"], color: "text-emerald-400", iconBg: "bg-emerald-500/10", category: "Discovery" },
  { id: "dns-lookup", name: "DNS Lookup", description: "All DNS record types + security analysis", icon: <Globe className="w-4 h-4" />, inputPlaceholder: "example.com", inputField: "domain", accepts: ["Domain"], color: "text-cyan-400", iconBg: "bg-cyan-500/10", category: "Discovery" },
  { id: "reverse-dns", name: "Reverse DNS", description: "IP → hostname with forward verification", icon: <RefreshCcw className="w-4 h-4" />, inputPlaceholder: "8.8.8.8", inputField: "ip", accepts: ["IPv4", "IPv6"], color: "text-purple-400", iconBg: "bg-purple-500/10", category: "Discovery" },
  { id: "header-check", name: "Header Check", description: "HTTP security headers & config", icon: <Shield className="w-4 h-4" />, inputPlaceholder: "example.com", inputField: "domain", accepts: ["Domain"], color: "text-amber-400", iconBg: "bg-amber-500/10", category: "Analysis" },
  { id: "whois", name: "WHOIS Lookup", description: "Registration & ownership details", icon: <FileText className="w-4 h-4" />, inputPlaceholder: "example.com / 8.8.8.8 / AS13335", inputField: "query", accepts: ["Domain", "IPv4", "ASN"], color: "text-rose-400", iconBg: "bg-rose-500/10", category: "Discovery" },
  { id: "connectivity-check", name: "Connectivity Check", description: "TCP ports, banner grab, TLS detect", icon: <Plug className="w-4 h-4" />, inputPlaceholder: "example.com:443", inputField: "host", accepts: ["Domain", "Host:Port"], color: "text-sky-400", iconBg: "bg-sky-500/10", category: "Analysis" },
  { id: "email-security", name: "Email Security", description: "SPF, DKIM & DMARC validation", icon: <Mail className="w-4 h-4" />, inputPlaceholder: "example.com", inputField: "domain", accepts: ["Domain"], color: "text-indigo-400", iconBg: "bg-indigo-500/10", category: "Analysis" },
  { id: "sensitive-paths", name: "Exposed Paths", description: "Scan for .env, .git, SQL dumps", icon: <FolderSearch className="w-4 h-4" />, inputPlaceholder: "example.com", inputField: "domain", accepts: ["Domain"], color: "text-orange-400", iconBg: "bg-orange-500/10", category: "Recon" },
  { id: "github-leaks", name: "GitHub Leaks", description: "Leaked creds & API keys on GitHub", icon: <GitBranch className="w-4 h-4" />, inputPlaceholder: "example.com", inputField: "domain", accepts: ["Domain"], color: "text-pink-400", iconBg: "bg-pink-500/10", category: "Recon" },
];

const TOOL_MAP: Record<string, ToolDef> = Object.fromEntries(TOOLS.map((t) => [t.id, t]));
const CATEGORIES = ["Discovery", "Analysis", "Recon"] as const;
const CAT_COLORS: Record<string, string> = { Discovery: "#22d3ee", Analysis: "#f59e0b", Recon: "#f43f5e" };

function isSha256Hash(input: string): boolean {
  return /^[a-f0-9]{64}$/i.test(input.replace(/[:\s-]/g, ""));
}

/* ═══════════════════════════════════════════════════════════════
   RESULT RENDERERS — moved to ./results/* (one file per tool plus
   _shared.tsx for the small primitives). Imported as RichResultView
   above; the dispatch lives in results/index.tsx.
   ═══════════════════════════════════════════════════════════════ */


/* ═══════════════════════════════════════════════════════════════
   PANEL STATE & CONSTANTS
   ═══════════════════════════════════════════════════════════════ */

interface PanelState {
  uid: number;
  toolId: ToolId;
  localTarget: string;
  status: "idle" | "running" | "done" | "error";
  result: any;
  error: string | null;
  execMs: number | null;
  expanded: boolean;
  widthPct: number;
  heightPx: number;
  /** True if the most recent result differs from the previously
   *  cached one for the same (toolId, target). Cleared when the
   *  panel is removed or replaced. (#27, minimal) */
  changedFromPrev?: boolean;
}

// Centralised layout constants. Hoist any new magic number here so the
// whole workspace's behaviour is editable from one place.
const LAYOUT = {
  GAP: 10,                   // px between panels in the grid
  MIN_WIDTH_PCT: 20,         // panel can't shrink narrower than this fraction of the canvas
  MAX_WIDTH_PCT: 100,
  MIN_HEIGHT_PX: 240,
  DEFAULT_HEIGHT_PX: 380,
  VIEWPORT_HEIGHT_BUFFER: 200, // panel max-height = window.innerHeight - this
  SIDEBAR_DEFAULT: 220,
  SIDEBAR_MIN: 180,
  SIDEBAR_MAX: 400,
  SNAP_THRESHOLD: 2,         // % within which width pops to a snap point
  SNAP_WIDTHS: [25, 100 / 3, 50, 200 / 3, 75, 100],
  RUN_ALL_CONCURRENCY: 3,    // upper bound on simultaneous tool runs (#1)
  STORAGE_KEY: "asm_lookup_layout_v1",
} as const;

// Plan-tier ceilings on how many panels can sit on the canvas at once.
// Each tool call hits a backend that may itself cost (Shodan, GitHub,
// WHOIS providers), so this needs a hard cap per tier — not just a
// per-route rate limit.
const MAX_PANELS_BY_PLAN: Record<string, number> = {
  free: 3,
  starter: 6,
  professional: 12,
  enterprise_silver: 12,
  enterprise_gold: 18,
  custom: 24,
};
const MAX_PANELS_DEFAULT = 6;

function maxPanelsForPlan(plan: string | null | undefined): number {
  if (!plan) return MAX_PANELS_DEFAULT;
  return MAX_PANELS_BY_PLAN[plan] ?? MAX_PANELS_DEFAULT;
}

const DEFAULT_TOOLS: ToolId[] = [];

// Workspace presets (#24). A preset is a curated set of tool panels
// matched to a common investigation workflow. The built-ins are
// immutable; users can save additional presets that are stored in
// localStorage. We intentionally keep the built-in list short — five
// or six well-chosen workflows are more useful than twenty.
type WorkspacePreset = {
  id: string;          // stable id; doubles as display key
  name: string;        // human-readable
  description: string;
  builtIn: boolean;
  toolIds: ToolId[];
};

const BUILTIN_PRESETS: WorkspacePreset[] = [
  {
    id: "preset.recon",
    name: "Pre-engagement Recon",
    description: "WHOIS, DNS, certs, security headers",
    builtIn: true,
    toolIds: ["whois", "dns-lookup", "cert-lookup", "header-check"],
  },
  {
    id: "preset.email",
    name: "Email Posture",
    description: "DNS + SPF / DKIM / DMARC",
    builtIn: true,
    toolIds: ["dns-lookup", "email-security"],
  },
  {
    id: "preset.dns-hygiene",
    name: "DNS Hygiene",
    description: "DNS records, reverse DNS, certificate transparency",
    builtIn: true,
    toolIds: ["dns-lookup", "reverse-dns", "cert-lookup"],
  },
  {
    id: "preset.exposure",
    name: "Exposure Audit",
    description: "Headers, exposed paths, GitHub leaks",
    builtIn: true,
    toolIds: ["header-check", "sensitive-paths", "github-leaks"],
  },
];

const PRESETS_STORAGE_KEY = "asm_lookup_presets_v1";
const AUTH_DISCLAIMER_DISMISSED_KEY = "asm_lookup_auth_disclaimer_dismissed_v1";

/** Single-line authorisation reminder. Dismissable after first ack —
 *  stored in localStorage so it doesn't nag returning users. */
function AuthorisationDisclaimer() {
  const [dismissed, setDismissed] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    return window.localStorage.getItem(AUTH_DISCLAIMER_DISMISSED_KEY) === "1";
  });
  if (dismissed) return null;
  return (
    <div className="px-4 py-1.5 border-b border-white/[0.04] bg-amber-500/[0.03] flex items-center gap-2 text-[11px] text-amber-300/80 shrink-0">
      <AlertCircle size={11} className="shrink-0" />
      <span className="flex-1">
        Some tools (port checks, exposed-path scanning, header probes) reach out to the target from Nano EASM infrastructure. Only run them against assets you&apos;re authorised to test.
      </span>
      <button
        type="button"
        onClick={() => {
          try { window.localStorage.setItem(AUTH_DISCLAIMER_DISMISSED_KEY, "1"); } catch {}
          setDismissed(true);
        }}
        className="text-amber-300/70 hover:text-amber-300 transition-colors px-1.5"
        title="Got it — don't show this banner again on this device"
      >
        Got it
      </button>
    </div>
  );
}

/** Discovery hint strip below the workspace header — explains the
 *  primary interactions so a new user isn't lost on a blank canvas. */
function KeyboardHintStrip() {
  return (
    <div className="hidden md:flex px-4 py-1 border-b border-white/[0.04] items-center gap-3 text-[10px] text-white/30 shrink-0">
      <span><strong className="text-white/55 font-medium">Drag</strong> a tool from the sidebar</span>
      <span className="text-white/15">·</span>
      <span><strong className="text-white/55 font-medium">Type or paste a target</strong> at the top (one shared input)</span>
      <span className="text-white/15">·</span>
      <span><strong className="text-white/55 font-medium">Run All</strong> to fire every panel against it</span>
      <span className="text-white/15">·</span>
      <span><strong className="text-white/55 font-medium">Presets</strong> save common bundles</span>
    </div>
  );
}

function loadUserPresets(): WorkspacePreset[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(PRESETS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((p): p is WorkspacePreset =>
      p && typeof p.id === "string" && typeof p.name === "string"
      && Array.isArray(p.toolIds)
      && p.toolIds.every((t: any) => typeof t === "string" && !!TOOL_MAP[t]),
    ).map((p) => ({ ...p, builtIn: false })); // never trust stored builtIn flag
  } catch {
    return [];
  }
}

function saveUserPresets(presets: WorkspacePreset[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(
      PRESETS_STORAGE_KEY,
      JSON.stringify(presets.filter((p) => !p.builtIn)),
    );
  } catch { /* noop */ }
}

// Run history (#29). Sliding window of the last N tool runs across
// the session — even after panels are removed/replaced. Click a row
// in the drawer to re-open that target/tool combo.
type HistoryEntry = {
  id: string;
  toolId: ToolId;
  target: string;
  status: "done" | "error";
  timestamp: number;
  durationMs?: number;
  errorMessage?: string;
};

const HISTORY_STORAGE_KEY = "asm_lookup_history_v1";
const HISTORY_MAX = 50;

function loadHistory(): HistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((e): e is HistoryEntry =>
        e && typeof e.id === "string"
        && typeof e.toolId === "string" && !!TOOL_MAP[e.toolId]
        && typeof e.target === "string"
        && typeof e.timestamp === "number"
        && (e.status === "done" || e.status === "error"))
      .slice(0, HISTORY_MAX);
  } catch {
    return [];
  }
}

function saveHistory(entries: HistoryEntry[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(
      HISTORY_STORAGE_KEY,
      JSON.stringify(entries.slice(0, HISTORY_MAX)),
    );
  } catch { /* noop */ }
}

// Per-result notes (#30, partial). Keyed by `toolId|target` so the
// note follows the result, not the panel — re-running the same
// query in another panel shows the same note.
const NOTES_STORAGE_KEY = "asm_lookup_notes_v1";

function notesKeyFor(toolId: ToolId, target: string): string {
  return `${toolId}|${target.toLowerCase()}`;
}

function loadNotes(): Record<string, string> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(NOTES_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: Record<string, string> = {};
    for (const k of Object.keys(parsed)) {
      if (typeof parsed[k] === "string") out[k] = parsed[k];
    }
    return out;
  } catch {
    return {};
  }
}

function saveNotes(notes: Record<string, string>): void {
  if (typeof window === "undefined") return;
  try {
    // Drop empty notes so the store doesn't bloat with deleted ones.
    const trimmed: Record<string, string> = {};
    for (const k of Object.keys(notes)) {
      if (notes[k] && notes[k].trim()) trimmed[k] = notes[k];
    }
    window.localStorage.setItem(NOTES_STORAGE_KEY, JSON.stringify(trimmed));
  } catch { /* noop */ }
}

// Result diff (#27, minimal). We don't render the diff — that's a
// future job — but we do remember a hash of the previous result for
// each (toolId, target) pair so a re-run can mark itself "changed
// since last time". For most tools that's the most useful signal.
const RESULT_HASHES_KEY = "asm_lookup_result_hashes_v1";

function quickHash(s: string): string {
  // djb2-ish; we just need stability + cheap comparability, not
  // cryptographic strength.
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  }
  return h.toString(36);
}

function loadResultHashes(): Record<string, string> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(RESULT_HASHES_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: Record<string, string> = {};
    for (const k of Object.keys(parsed)) {
      if (typeof parsed[k] === "string") out[k] = parsed[k];
    }
    return out;
  } catch {
    return {};
  }
}

function saveResultHashes(hashes: Record<string, string>): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(RESULT_HASHES_KEY, JSON.stringify(hashes));
  } catch { /* noop */ }
}

// Shareable workspace URLs (#28). Panels + targets are encoded into
// a `#share=…` hash fragment so an analyst can paste a link to a
// teammate and have them land on the same workspace shape (without
// results — those re-fetch when they hit Run). We use compact keys
// to keep typical URLs under a few hundred characters.
type SharedPayload = {
  v: 1;
  panels: Array<{ t: ToolId; w: number; h: number; lt?: string }>;
  gt?: string;
  bm?: 1;
};

function encodeSharedLayout(
  panels: PanelState[],
  globalTarget: string,
  bulkMode: boolean,
): string {
  const payload: SharedPayload = {
    v: 1,
    panels: panels.map((p) => ({
      t: p.toolId,
      w: Math.round(p.widthPct * 10) / 10,
      h: Math.round(p.heightPx),
      ...(p.localTarget ? { lt: p.localTarget } : {}),
    })),
    ...(globalTarget ? { gt: globalTarget } : {}),
    ...(bulkMode ? { bm: 1 } : {}),
  };
  // Use base64url so the hash is URL-safe without %-encoding.
  const json = JSON.stringify(payload);
  if (typeof window === "undefined") return "";
  // btoa needs Latin-1; non-ASCII targets (rare for hostnames) get
  // round-tripped via TextEncoder.
  const utf8 = new TextEncoder().encode(json);
  let bin = "";
  utf8.forEach((b) => { bin += String.fromCharCode(b); });
  return window.btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeSharedLayout(str: string): SharedPayload | null {
  if (typeof window === "undefined") return null;
  try {
    const padded = str.replace(/-/g, "+").replace(/_/g, "/")
      + "===".slice((str.length + 3) % 4);
    const bin = window.atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const json = new TextDecoder().decode(bytes);
    const parsed = JSON.parse(json);
    if (!parsed || parsed.v !== 1 || !Array.isArray(parsed.panels)) return null;
    // Validate every entry references a real tool — protects against
    // tampered or stale URLs.
    for (const p of parsed.panels) {
      if (!p || typeof p.t !== "string" || !TOOL_MAP[p.t as ToolId]) return null;
      if (typeof p.w !== "number" || typeof p.h !== "number") return null;
    }
    return parsed as SharedPayload;
  } catch {
    return null;
  }
}

/* ═══════════════════════════════════════════════════════════════
   RESIZABLE TOOL PANEL
   ═══════════════════════════════════════════════════════════════ */

function ToolPanel({
  panel, tool, globalTarget, canvasWidth, canvasRef,
  onRemove, onRun, onToggleExpand, onSetLocalTarget, onResize, onAutofit,
  hasMonitoring, onSavedAsAlert,
  note, onSetNote,
}: {
  panel: PanelState; tool: ToolDef; globalTarget: string; canvasWidth: number;
  canvasRef: React.RefObject<HTMLDivElement | null>;
  onRemove: () => void; onRun: () => void;
  onToggleExpand: () => void; onSetLocalTarget: (v: string) => void;
  onResize: (w: number, h: number) => void;
  onAutofit: () => void;
  hasMonitoring: boolean;
  onSavedAsAlert: (kind: "ok" | "err", text: string) => void;
  note: string;
  onSetNote: (note: string) => void;
}) {
  const [noteOpen, setNoteOpen] = useState(false);
  const [alertOpen, setAlertOpen] = useState(false);
  const [alertSeverity, setAlertSeverity] = useState<Severity>("medium");
  const [alertTitle, setAlertTitle] = useState("");
  const [alertNote, setAlertNote] = useState("");
  const [savingAlert, setSavingAlert] = useState(false);
  const resizeRef = useRef<{ sx: number; sy: number; ow: number; oh: number } | null>(null);
  // Snap-during-drag feedback (#11). Holds the live width % while the
  // user is mid-drag so we can render a small chip; null when idle.
  const [dragWidthHint, setDragWidthHint] = useState<number | null>(null);
  const effectiveTarget = panel.localTarget.trim() || globalTarget.trim();
  const isLocal = panel.localTarget.trim().length > 0;
  const isRunning = panel.status === "running";
  // Cheap, but #23 — memo prevents re-running the regex on every render
  // of the title bar.
  const certMode = React.useMemo(
    () => tool.id === "cert-lookup" && effectiveTarget
      ? (isSha256Hash(effectiveTarget) ? "SHA-256" : "Domain")
      : null,
    [tool.id, effectiveTarget],
  );

  // Run-button disabled-reason text (#13). Surfaced via title.
  const runDisabledReason = isRunning
    ? "Running…"
    : !effectiveTarget
      ? "Set a target above (or in this panel) first"
      : "";

  // 8-direction resize. The two axis signs decide whether outward drag
  // grows or shrinks each dimension — e.g. dragging the W (left) edge
  // LEFT grows the panel, so xSign = -1 maps "left drag" to "+ width".
  // In flow layout the panel's top-left stays where the flow placed
  // it, so visually growth always happens on the right/bottom edge no
  // matter which handle was grabbed. The handles are still useful as
  // grab affordances on every side.
  type ResizeDir = "n" | "s" | "e" | "w" | "ne" | "nw" | "se" | "sw";
  const CURSOR_BY_DIR: Record<ResizeDir, string> = {
    n: "ns-resize", s: "ns-resize",
    e: "ew-resize", w: "ew-resize",
    ne: "nesw-resize", sw: "nesw-resize",
    nw: "nwse-resize", se: "nwse-resize",
  };

  // We hold the in-flight drag's listeners in a ref so a single
  // unmount-effect (#3) can detach them if the component disappears
  // while a drag is active.
  const dragListenersRef = useRef<{
    onMove: (e: MouseEvent) => void;
    onUp: () => void;
  } | null>(null);

  const stopActiveDrag = React.useCallback(() => {
    const h = dragListenersRef.current;
    if (!h) return;
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    window.removeEventListener("mousemove", h.onMove);
    window.removeEventListener("mouseup", h.onUp);
    dragListenersRef.current = null;
    resizeRef.current = null;
    setDragWidthHint(null);
  }, []);

  React.useEffect(() => {
    // Cleanup on unmount: if a drag is mid-flight when the panel gets
    // removed (or the page navigates away), the global window
    // listeners would otherwise leak.
    return () => stopActiveDrag();
  }, [stopActiveDrag]);

  const startResize = (direction: ResizeDir) => (e: React.MouseEvent) => {
    e.preventDefault(); e.stopPropagation();
    // Ignore drags initiated as the second click of a dblclick — the
    // dblclick handler runs the autofit instead.
    if (e.detail >= 2) return;
    // Detach any prior drag's listeners before starting a new one.
    stopActiveDrag();
    resizeRef.current = { sx: e.clientX, sy: e.clientY, ow: panel.widthPct, oh: panel.heightPx };

    const xSign = direction.includes("e") ? 1 : direction.includes("w") ? -1 : 0;
    const ySign = direction.includes("s") ? 1 : direction.includes("n") ? -1 : 0;

    const onMove = (ev: MouseEvent) => {
      if (!resizeRef.current) return;
      const currentWidth = canvasRef.current?.clientWidth || canvasWidth || 800;
      let newW = resizeRef.current.ow;
      let newH = resizeRef.current.oh;

      if (xSign !== 0) {
        const dxPct = ((ev.clientX - resizeRef.current.sx) / currentWidth) * 100 * xSign;
        newW = resizeRef.current.ow + dxPct;
        if (!ev.shiftKey) {
          const snap = LAYOUT.SNAP_WIDTHS.find((p) => Math.abs(p - newW) < LAYOUT.SNAP_THRESHOLD);
          if (snap !== undefined) newW = snap;
        }
        newW = Math.min(LAYOUT.MAX_WIDTH_PCT, Math.max(LAYOUT.MIN_WIDTH_PCT, newW));
      }

      if (ySign !== 0) {
        const dy = (ev.clientY - resizeRef.current.sy) * ySign;
        // Cap height to a bit less than the viewport so users can't
        // drag a panel into a region they can't scroll back to.
        const maxH = Math.max(
          LAYOUT.MIN_HEIGHT_PX,
          (typeof window !== "undefined" ? window.innerHeight : 1080) - LAYOUT.VIEWPORT_HEIGHT_BUFFER,
        );
        newH = Math.min(maxH, Math.max(LAYOUT.MIN_HEIGHT_PX, resizeRef.current.oh + dy));
      }

      // Surface the live width % during drag (#11). Cheap to set — the
      // chip is positioned absolutely so it doesn't shift layout.
      if (xSign !== 0) setDragWidthHint(newW);
      onResize(newW, newH);
    };

    const onUp = () => stopActiveDrag();

    dragListenersRef.current = { onMove, onUp };
    document.body.style.cursor = CURSOR_BY_DIR[direction];
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const handleCopyJson = () => { if (panel.result) navigator.clipboard.writeText(JSON.stringify(panel.result, null, 2)); };
  const handleExportCsv = () => {
    if (!panel.result) return;
    const rows = Object.entries(panel.result).map(([k, v]) => {
      const cell = v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
      return `"${k}","${cell.replace(/"/g, '""')}"`;
    });
    const blob = new Blob(["key,value\n" + rows.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `${tool.id}-results.csv`; a.click(); URL.revokeObjectURL(url);
  };

  function renderTitleBar() {
    return (
      <div className="flex items-center gap-2 px-3 py-2 border-b border-white/[0.06] bg-white/[0.02] shrink-0">
        <div className={cn("h-6 w-6 rounded-md flex items-center justify-center shrink-0", tool.iconBg, tool.color)}>{tool.icon}</div>
        <span className="text-[12px] font-semibold text-white truncate flex-1">{tool.name}</span>
        <span className="text-[10px] text-[#475569] font-mono mr-1">{tool.category}</span>
        {panel.changedFromPrev && (
          <span
            className="text-[9px] font-mono uppercase tracking-wider text-amber-400 bg-amber-500/10 border border-amber-500/30 px-1 py-0.5 rounded"
            title="The result differs from the last time this tool was run against the same target"
          >
            changed
          </span>
        )}
        {panel.execMs !== null && <span className="text-[10px] text-[#475569] font-mono">{panel.execMs}ms</span>}
        <div className="flex items-center gap-0.5">
          <button onClick={onToggleExpand} className="p-1 rounded hover:bg-white/[0.06] text-[#64748b] hover:text-white transition-colors" title={panel.expanded ? "Restore" : "Maximize"}>
            {panel.expanded ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
          </button>
          <button onClick={onRemove} className="p-1 rounded hover:bg-red-500/20 text-[#64748b] hover:text-red-400 transition-colors" title="Remove">
            <X size={12} />
          </button>
        </div>
      </div>
    );
  }

  function renderInputBar() {
    return (
      <>
      <div className="px-3 py-2 border-b border-white/[0.04] flex items-center gap-2 shrink-0">
        <input type="text" value={panel.localTarget}
          onChange={(e) => onSetLocalTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !isRunning && onRun()}
          placeholder={globalTarget ? `▸ ${globalTarget}` : tool.inputPlaceholder}
          className="flex-1 bg-[#080d1a] border border-white/[0.06] rounded-lg px-3 py-1.5 text-[12px] text-white placeholder-[#3b4559] outline-none focus:border-primary/30 transition-colors font-mono"
          disabled={isRunning} />
        {isLocal && <span className="text-[9px] font-mono uppercase tracking-wider text-primary shrink-0 px-1">local</span>}
        {certMode && <span className="text-[9px] font-mono uppercase tracking-wider text-teal-400 shrink-0 px-1">{certMode}</span>}
        <button onClick={onRun} disabled={isRunning || !effectiveTarget}
          title={runDisabledReason || `Run ${tool.name}`}
          className="flex items-center gap-1 rounded-lg bg-white/[0.04] border border-white/[0.06] px-2.5 py-1.5 text-[11px] font-medium text-white hover:bg-white/[0.08] hover:border-primary/20 transition-all disabled:opacity-30 disabled:cursor-not-allowed shrink-0">
          {isRunning ? <Loader2 size={12} className="animate-spin" /> : <Play size={11} className="text-primary" />}
          Run
        </button>
      </div>
      <div className="px-3 pb-1 flex items-center gap-2 shrink-0">
        <span className="text-[10px] text-muted-foreground/40 truncate">{tool.description}</span>
        <div className="flex gap-1 ml-auto shrink-0">
          {tool.accepts.map((a) => (
            <span key={a} className="px-1.5 py-0.5 rounded text-[9px] font-medium bg-muted/20 text-muted-foreground/50 border border-border/30">{a}</span>
          ))}
        </div>
      </div>
      </>
    );
  }

  function renderBody() {
    return (
      <div className="flex-1 overflow-auto min-h-0 p-3">
        {panel.status === "error" && (
          <div className="rounded-lg border border-red-500/20 bg-red-500/[0.05] px-3 py-2 flex items-start gap-2 mb-3">
            <AlertCircle size={13} className="text-red-400 mt-0.5 shrink-0" />
            <p className="text-[11px] text-red-300 leading-relaxed break-all">{panel.error}</p>
          </div>
        )}
        {panel.status === "done" && panel.result && (
          <div>
            <div className="flex items-center justify-end gap-2 mb-3">
              {hasMonitoring && !panel.result?.error && (
                <button
                  onClick={() => {
                    // Seed the dialog with sensible defaults derived from
                    // the result so the user starts with a descriptive
                    // title and a severity that matches what the tool found.
                    setAlertTitle(suggestAlertTitle(tool.id, tool.name, panel.result, effectiveTarget));
                    setAlertNote("");
                    setAlertSeverity(suggestSeverity(tool.id, panel.result) || "medium");
                    setAlertOpen(true);
                  }}
                  className="flex items-center gap-1 text-[10px] text-amber-400 hover:text-amber-300 transition-colors"
                  title="Create an alert from this result and route it through your notification rules"
                >
                  <Siren size={10} /> Save as Alert
                </button>
              )}
              <button
                onClick={() => setNoteOpen((o) => !o)}
                className={cn(
                  "flex items-center gap-1 text-[10px] transition-colors",
                  note
                    ? "text-primary hover:text-primary/80"
                    : "text-[#64748b] hover:text-white",
                )}
                title={note ? "Edit note" : "Add a note for this result"}
              >
                <StickyNote size={10} /> {note ? "Note*" : "Note"}
              </button>
              <button onClick={handleCopyJson} className="flex items-center gap-1 text-[10px] text-[#64748b] hover:text-white transition-colors"><Copy size={10} /> JSON</button>
              <button onClick={handleExportCsv} className="flex items-center gap-1 text-[10px] text-[#64748b] hover:text-white transition-colors"><Download size={10} /> CSV</button>
            </div>
            {noteOpen && (
              <div className="mb-3 rounded-lg border border-primary/20 bg-primary/[0.03] p-2">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">
                    Note for {effectiveTarget}
                  </span>
                  <span className="text-[9px] text-muted-foreground/40">Saved automatically</span>
                </div>
                <textarea
                  value={note}
                  onChange={(e) => onSetNote(e.target.value)}
                  placeholder="False positive? Already triaged? Reminder for next time?"
                  rows={3}
                  className="w-full bg-background border border-white/[0.06] rounded px-2 py-1.5 text-[11px] text-foreground placeholder-muted-foreground/40 outline-none focus:border-primary/30 transition-colors resize-y"
                />
              </div>
            )}
            <RichResultView toolId={panel.toolId} data={panel.result} />
          </div>
        )}
        {panel.status === "running" && (
          <div className="flex flex-col items-center justify-center h-full">
            <Loader2 size={20} className="animate-spin mb-2 text-primary" />
            <span className="text-[11px] text-[#64748b]">Running {tool.name}…</span>
          </div>
        )}
        {panel.status === "idle" && (
          <div className="flex flex-col items-center justify-center h-full opacity-40">
            <div className={cn("h-10 w-10 rounded-xl flex items-center justify-center mb-2", tool.iconBg, tool.color)}>{tool.icon}</div>
            <span className="text-[11px] text-[#64748b]">{effectiveTarget ? "Click Run to query" : tool.inputPlaceholder}</span>
          </div>
        )}
      </div>
    );
  }

  async function handleSaveAlert() {
    setSavingAlert(true);
    try {
      // Human-readable per-tool summary instead of a raw JSON dump.
      // Falls back to a short JSON preview for unknown tools.
      const formatted = formatToolResultSummary(tool.id, panel.result, effectiveTarget);
      const note = alertNote.trim();
      const summary = note ? `${note}\n\n${formatted}` : formatted;

      const fallbackTitle = suggestAlertTitle(tool.id, tool.name, panel.result, effectiveTarget);

      await createManualAlert({
        title: alertTitle.trim() || fallbackTitle,
        severity: alertSeverity,
        summary,
        sourceTool: tool.id,
        sourceTarget: effectiveTarget,
      });
      onSavedAsAlert("ok", `Saved as alert (${alertSeverity}).`);
      setAlertOpen(false);
    } catch (e: any) {
      onSavedAsAlert("err", e?.message || "Failed to save alert");
    } finally {
      setSavingAlert(false);
    }
  }

  function renderAlertDialog() {
    return (
      <Dialog open={alertOpen} onOpenChange={(o) => { if (!o && !savingAlert) setAlertOpen(false); }}>
        <DialogContent className="bg-card border-border text-foreground sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Siren className="w-5 h-5 text-amber-400" />
              Save as Alert
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <p className="text-sm text-muted-foreground">
              Creates an alert from this {tool.name} result and routes it through your
              notification rules.
            </p>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-foreground block">Title</label>
              <input
                type="text"
                value={alertTitle}
                onChange={(e) => setAlertTitle(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-foreground block">Severity</label>
              <select
                value={alertSeverity}
                onChange={(e) => setAlertSeverity(e.target.value as Severity)}
                className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
              >
                <option value="info">Info</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-foreground block">Note (optional)</label>
              <textarea
                value={alertNote}
                onChange={(e) => setAlertNote(e.target.value)}
                placeholder="Additional context for the alert"
                rows={3}
                className="w-full px-3 py-2 rounded-lg bg-background border border-border/50 text-foreground text-sm placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
              />
            </div>
            <div className="flex gap-3 justify-end pt-2">
              <button
                type="button"
                onClick={() => setAlertOpen(false)}
                disabled={savingAlert}
                className="px-4 py-2 rounded-lg border border-border/50 text-sm text-foreground hover:bg-accent transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSaveAlert}
                disabled={savingAlert}
                className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-600 text-white text-sm font-medium disabled:opacity-50 transition-colors flex items-center gap-2"
              >
                <Siren className="w-4 h-4" />
                {savingAlert ? "Saving..." : "Save as Alert"}
              </button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    );
  }

  if (panel.expanded) {
    return (<>
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm" onClick={onToggleExpand} />
      <div className="fixed inset-4 z-50 rounded-xl border border-white/[0.08] bg-[#0c1222]/98 backdrop-blur-xl shadow-2xl flex flex-col overflow-hidden">
        {renderTitleBar()}{renderInputBar()}{renderBody()}
      </div>
      {renderAlertDialog()}
    </>);
  }

  return (
    <div className="rounded-xl border border-white/[0.08] bg-[#0c1222]/95 backdrop-blur-xl shadow-lg flex flex-col overflow-hidden relative group/panel"
      style={{ width: `calc(${panel.widthPct}% - ${LAYOUT.GAP * (1 - panel.widthPct / 100)}px)`, height: panel.heightPx, flexShrink: 0, flexGrow: 0 }}>
      {renderTitleBar()}{renderInputBar()}{renderBody()}

      {/*
        Eight resize handles — one per edge, one per corner.
        - Edges show a subtle indicator bar that's always visible (so
          users discover them) and brightens on hover.
        - All four corners get a tiny dot so the affordance reads on
          every side (#10).
        - Double-click any handle to autofit (distribute panel widths
          evenly across the workspace).
        - Hold Shift while dragging to disable snap-to-grid (#12 —
          mentioned consistently on all width-affecting handles).
        - ARIA: each handle is a `separator` with orientation; arrow-
          key resize is a separate project (#15 partial).
        Note: in the flow layout, dragging any handle visually grows
        the panel on its right/bottom edges since the top-left is
        anchored by the row.
      */}

      {/* Top edge — height only */}
      <div
        onMouseDown={startResize("n")}
        onDoubleClick={onAutofit}
        role="separator"
        aria-orientation="horizontal"
        aria-label="Resize panel height (top edge)"
        className="absolute -top-0.5 left-3 right-3 h-1.5 cursor-ns-resize z-10 group/handle-n"
        title="Drag to resize height · double-click to autofit row"
      >
        <div className="absolute top-0.5 left-1/2 -translate-x-1/2 h-0.5 w-8 rounded-full bg-muted-foreground/15 group-hover/handle-n:bg-primary/60 group-hover/handle-n:w-12 transition-all" />
      </div>

      {/* Bottom edge — height only */}
      <div
        onMouseDown={startResize("s")}
        onDoubleClick={onAutofit}
        role="separator"
        aria-orientation="horizontal"
        aria-label="Resize panel height (bottom edge)"
        className="absolute -bottom-0.5 left-3 right-3 h-1.5 cursor-ns-resize z-10 group/handle-s"
        title="Drag to resize height · double-click to autofit row"
      >
        <div className="absolute bottom-0.5 left-1/2 -translate-x-1/2 h-0.5 w-8 rounded-full bg-muted-foreground/15 group-hover/handle-s:bg-primary/60 group-hover/handle-s:w-12 transition-all" />
      </div>

      {/* Left edge — width only */}
      <div
        onMouseDown={startResize("w")}
        onDoubleClick={onAutofit}
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize panel width (left edge)"
        aria-valuenow={Math.round(panel.widthPct)}
        aria-valuemin={LAYOUT.MIN_WIDTH_PCT}
        aria-valuemax={LAYOUT.MAX_WIDTH_PCT}
        className="absolute -left-0.5 top-3 bottom-3 w-1.5 cursor-ew-resize z-10 group/handle-w"
        title="Drag to resize width · double-click to autofit · Shift to disable snap"
      >
        <div className="absolute left-0.5 top-1/2 -translate-y-1/2 w-0.5 h-8 rounded-full bg-muted-foreground/15 group-hover/handle-w:bg-primary/60 group-hover/handle-w:h-12 transition-all" />
      </div>

      {/* Right edge — width only */}
      <div
        onMouseDown={startResize("e")}
        onDoubleClick={onAutofit}
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize panel width (right edge)"
        aria-valuenow={Math.round(panel.widthPct)}
        aria-valuemin={LAYOUT.MIN_WIDTH_PCT}
        aria-valuemax={LAYOUT.MAX_WIDTH_PCT}
        className="absolute -right-0.5 top-3 bottom-3 w-1.5 cursor-ew-resize z-10 group/handle-e"
        title="Drag to resize width · double-click to autofit · Shift to disable snap"
      >
        <div className="absolute right-0.5 top-1/2 -translate-y-1/2 w-0.5 h-8 rounded-full bg-muted-foreground/15 group-hover/handle-e:bg-primary/60 group-hover/handle-e:h-12 transition-all" />
      </div>

      {/* NW corner */}
      <div
        onMouseDown={startResize("nw")}
        onDoubleClick={onAutofit}
        role="separator"
        aria-label="Resize panel (top-left corner)"
        className="absolute top-0 left-0 w-3 h-3 cursor-nwse-resize z-20 group/handle-nw"
        title="Drag to resize · double-click to autofit · Shift to disable snap"
      >
        <div className="absolute top-1 left-1 w-1 h-1 rounded-full bg-muted-foreground/20 group-hover/handle-nw:bg-primary transition-colors" />
      </div>

      {/* NE corner */}
      <div
        onMouseDown={startResize("ne")}
        onDoubleClick={onAutofit}
        role="separator"
        aria-label="Resize panel (top-right corner)"
        className="absolute top-0 right-0 w-3 h-3 cursor-nesw-resize z-20 group/handle-ne"
        title="Drag to resize · double-click to autofit · Shift to disable snap"
      >
        <div className="absolute top-1 right-1 w-1 h-1 rounded-full bg-muted-foreground/20 group-hover/handle-ne:bg-primary transition-colors" />
      </div>

      {/* SW corner */}
      <div
        onMouseDown={startResize("sw")}
        onDoubleClick={onAutofit}
        role="separator"
        aria-label="Resize panel (bottom-left corner)"
        className="absolute bottom-0 left-0 w-3 h-3 cursor-nesw-resize z-20 group/handle-sw"
        title="Drag to resize · double-click to autofit · Shift to disable snap"
      >
        <div className="absolute bottom-1 left-1 w-1 h-1 rounded-full bg-muted-foreground/20 group-hover/handle-sw:bg-primary transition-colors" />
      </div>

      {/* SE corner — the primary "this resizes" affordance, with chevron */}
      <div
        onMouseDown={startResize("se")}
        onDoubleClick={onAutofit}
        role="separator"
        aria-label="Resize panel (bottom-right corner)"
        className="absolute bottom-0 right-0 w-3.5 h-3.5 cursor-nwse-resize z-20 group/handle-se"
        title="Drag to resize · double-click to autofit · Shift to disable snap"
      >
        <svg viewBox="0 0 14 14" className="w-full h-full text-muted-foreground/30 group-hover/handle-se:text-primary transition-colors">
          <path d="M13 13L8 13M13 13L13 8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
          <path d="M13 13L4 13M13 13L13 4" stroke="currentColor" strokeWidth="1" strokeLinecap="round" opacity="0.5" />
        </svg>
      </div>

      {/* Snap visual feedback (#11). While the user drags any width-
          changing handle we show a small chip with the live percentage;
          when the value matches a snap point the chip flashes teal. */}
      {dragWidthHint !== null && (() => {
        const snapped = LAYOUT.SNAP_WIDTHS.some((p) => Math.abs(p - dragWidthHint) < 0.1);
        return (
          <div
            aria-hidden
            className={cn(
              "absolute top-2 right-2 z-30 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold pointer-events-none border transition-colors",
              snapped
                ? "bg-primary/20 text-primary border-primary/40"
                : "bg-card/80 text-foreground border-border/60",
            )}
          >
            {Math.round(dragWidthHint)}%
          </div>
        );
      })()}

      {renderAlertDialog()}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   PRESETS DROPDOWN (#24)
   ═══════════════════════════════════════════════════════════════ */

function PresetsDropdown({
  userPresets, onApply, onSave, onDelete, panelsCount,
}: {
  userPresets: WorkspacePreset[];
  onApply: (p: WorkspacePreset) => void;
  onSave: (name: string) => void;
  onDelete: (id: string) => void;
  panelsCount: number;
}) {
  const [open, setOpen] = useState(false);
  const [showSavePrompt, setShowSavePrompt] = useState(false);
  const [saveName, setSaveName] = useState("");

  function handleSave() {
    if (!saveName.trim()) return;
    onSave(saveName);
    setSaveName("");
    setShowSavePrompt(false);
    setOpen(false);
  }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 rounded-lg border border-white/[0.06] bg-white/[0.03] px-3 py-2 text-[12px] font-medium text-[#94a3b8] hover:bg-white/[0.06] hover:text-white transition-all"
        title="Apply a workspace preset"
      >
        <Bookmark size={13} /> Presets
        <ChevronDown size={11} className={cn("transition-transform duration-200", open && "rotate-180")} />
      </button>
      {open && (
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => { setOpen(false); setShowSavePrompt(false); setSaveName(""); }}
          />
          <div className="absolute top-full right-0 mt-1 z-50 w-[320px] max-h-[480px] overflow-y-auto rounded-xl border border-white/[0.08] bg-[#0c1222]/98 backdrop-blur-xl shadow-2xl py-1.5">
            <div className="px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground/60">
              Built-in
            </div>
            {BUILTIN_PRESETS.map((p) => (
              <button
                key={p.id}
                onClick={() => { onApply(p); setOpen(false); }}
                className="w-full flex items-start gap-2 px-3 py-2 hover:bg-white/[0.04] transition-colors text-left"
              >
                <Bookmark size={12} className="text-primary mt-0.5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="text-[12px] font-medium text-foreground truncate">{p.name}</div>
                  <div className="text-[11px] text-muted-foreground truncate">{p.description}</div>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground/50 shrink-0 mt-0.5">
                  {p.toolIds.length}
                </span>
              </button>
            ))}

            {userPresets.length > 0 && (
              <>
                <div className="px-3 py-2 mt-1 border-t border-white/[0.05] text-[10px] font-bold uppercase tracking-wider text-muted-foreground/60">
                  Saved
                </div>
                {userPresets.map((p) => (
                  <div key={p.id} className="group/p flex items-stretch hover:bg-white/[0.04] transition-colors">
                    <button
                      onClick={() => { onApply(p); setOpen(false); }}
                      className="flex-1 flex items-start gap-2 px-3 py-2 text-left min-w-0"
                    >
                      <Bookmark size={12} className="text-muted-foreground mt-0.5 shrink-0" />
                      <div className="min-w-0 flex-1">
                        <div className="text-[12px] font-medium text-foreground truncate">{p.name}</div>
                        <div className="text-[11px] text-muted-foreground truncate">{p.description}</div>
                      </div>
                    </button>
                    <button
                      onClick={() => onDelete(p.id)}
                      title="Delete preset"
                      className="px-2 text-muted-foreground hover:text-red-400 opacity-0 group-hover/p:opacity-100 transition-opacity"
                    >
                      <X size={12} />
                    </button>
                  </div>
                ))}
              </>
            )}

            <div className="px-3 py-2 mt-1 border-t border-white/[0.05]">
              {showSavePrompt ? (
                <div className="flex items-center gap-1.5">
                  <input
                    autoFocus
                    type="text"
                    value={saveName}
                    onChange={(e) => setSaveName(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") handleSave();
                      if (e.key === "Escape") { setShowSavePrompt(false); setSaveName(""); }
                    }}
                    placeholder="Preset name…"
                    className="flex-1 bg-background border border-white/[0.06] rounded px-2 py-1 text-[11px] text-foreground placeholder-muted-foreground/40 outline-none focus:border-primary/30"
                  />
                  <button
                    onClick={handleSave}
                    disabled={!saveName.trim()}
                    className="px-2 py-1 rounded bg-primary/20 text-[11px] font-medium text-primary hover:bg-primary/30 transition-colors disabled:opacity-30"
                  >
                    Save
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => setShowSavePrompt(true)}
                  disabled={panelsCount === 0}
                  title={panelsCount === 0 ? "Add tools to the workspace first" : "Save the current panel set as a reusable preset"}
                  className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-md border border-white/[0.06] text-[11px] text-muted-foreground hover:text-foreground hover:bg-white/[0.04] transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  <Plus size={11} /> Save current as preset
                </button>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   ADD TOOL DROPDOWN
   ═══════════════════════════════════════════════════════════════ */

function AddToolDropdown({ onAdd, disabled }: { onAdd: (toolId: ToolId) => void; disabled: boolean }) {
  const [open, setOpen] = useState(false);
  const [expandedCat, setExpandedCat] = useState<string | null>(null);
  return (
    <div className="relative">
      <button onClick={() => setOpen(!open)} disabled={disabled}
        className="flex items-center gap-1.5 rounded-lg border border-white/[0.06] bg-white/[0.03] px-3 py-2 text-[12px] font-medium text-[#94a3b8] hover:bg-white/[0.06] hover:text-white transition-all disabled:opacity-30 disabled:cursor-not-allowed">
        <Plus size={13} /> Add Tool <ChevronDown size={11} className={cn("transition-transform duration-200", open && "rotate-180")} />
      </button>
      {open && (<>
        <div className="fixed inset-0 z-40" onClick={() => { setOpen(false); setExpandedCat(null); }} />
        <div className="absolute top-full left-0 mt-1 z-50 w-[260px] max-h-[420px] overflow-y-auto rounded-xl border border-white/[0.08] bg-[#0c1222]/98 backdrop-blur-xl shadow-2xl py-1.5">
          {CATEGORIES.map((cat) => {
            const catTools = TOOLS.filter((t) => t.category === cat);
            return (
              <div key={cat}>
                <button onClick={() => setExpandedCat(expandedCat === cat ? null : cat)}
                  className="w-full flex items-center gap-2 px-3 py-2 hover:bg-white/[0.04] transition-colors">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ background: CAT_COLORS[cat] }} />
                  <span className="text-[12px] font-medium text-[#94a3b8] flex-1 text-left">{cat}</span>
                  <span className="text-[10px] text-[#475569] font-mono">{catTools.length}</span>
                  <ChevronDown size={11} className={cn("text-[#475569] transition-transform duration-200", expandedCat === cat && "rotate-180")} />
                </button>
                {expandedCat === cat && (
                  <div className="pb-1">
                    {catTools.map((tool) => (
                      <button
                        key={tool.id}
                        onClick={() => { onAdd(tool.id); setOpen(false); setExpandedCat(null); }}
                        title={tool.description}
                        className="w-full flex items-start gap-2 px-5 py-2 text-left hover:bg-white/[0.06] transition-colors group"
                      >
                        <div className={cn("h-5 w-5 rounded flex items-center justify-center shrink-0 mt-0.5", tool.iconBg, tool.color)}>{tool.icon}</div>
                        <div className="flex-1 min-w-0">
                          <div className="text-[11px] text-[#94a3b8] group-hover:text-white truncate transition-colors">{tool.name}</div>
                          <div className="text-[10px] text-[#475569] group-hover:text-[#64748b] truncate transition-colors">{tool.description}</div>
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </>)}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   MAIN PAGE — INVESTIGATION WORKSPACE
   ═══════════════════════════════════════════════════════════════ */

// LAYOUT.STORAGE_KEY versions the persisted shape — bump it whenever
// the saved object's structure changes in a way that wouldn't load
// cleanly with the old reader.

type StoredPanel = { toolId: ToolId; widthPct: number; heightPx: number };

function loadStoredLayout(maxPanels: number): StoredPanel[] | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(LAYOUT.STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return null;
    // Clamp height at load so a layout saved on a tall screen doesn't
    // overflow on a small one (#16). Drop anything malformed or
    // referencing a tool that no longer exists.
    const maxHeight =
      typeof window !== "undefined"
        ? Math.max(LAYOUT.MIN_HEIGHT_PX, window.innerHeight - LAYOUT.VIEWPORT_HEIGHT_BUFFER)
        : 720;
    return parsed
      .filter((p): p is StoredPanel =>
        p && typeof p.toolId === "string"
        && typeof p.widthPct === "number"
        && typeof p.heightPx === "number"
        && !!TOOL_MAP[p.toolId as ToolId])
      .map((p) => ({
        toolId: p.toolId,
        widthPct: Math.min(LAYOUT.MAX_WIDTH_PCT, Math.max(LAYOUT.MIN_WIDTH_PCT, p.widthPct)),
        heightPx: Math.min(maxHeight, Math.max(LAYOUT.MIN_HEIGHT_PX, p.heightPx)),
      }))
      .slice(0, maxPanels);
  } catch {
    return null;
  }
}

export default function ToolsPage() {
  const canvasRef = useRef<HTMLDivElement>(null);
  const { hasFeature, plan } = useOrg();
  const hasMonitoring = hasFeature("monitoring");

  // Plan-gated panel limit (#2). Pulled from useOrg so it tracks plan
  // changes without a reload.
  const maxPanels = maxPanelsForPlan(plan);

  const [panels, setPanels] = useState<PanelState[]>(() => {
    const stored = loadStoredLayout(maxPanels);
    if (stored && stored.length > 0) {
      return stored.map((s, i) => ({
        uid: i + 1, toolId: s.toolId, localTarget: "", status: "idle" as const,
        result: null, error: null, execMs: null, expanded: false,
        widthPct: s.widthPct, heightPx: s.heightPx,
      }));
    }
    const cols = Math.min(DEFAULT_TOOLS.length, 3);
    return DEFAULT_TOOLS.map((toolId, i) => ({
      uid: i + 1, toolId, localTarget: "", status: "idle" as const,
      result: null, error: null, execMs: null, expanded: false,
      widthPct: 100 / cols, heightPx: LAYOUT.DEFAULT_HEIGHT_PX,
    }));
  });

  // Reset uid counter so the first added panel gets a fresh id past
  // anything we restored from localStorage.
  const nextUid = useRef(0);
  if (nextUid.current === 0) {
    nextUid.current = (panels.reduce((m, p) => Math.max(m, p.uid), 0) || 0) + 1;
  }

  // Per-panel AbortController (#4) — created on run, aborted on rerun
  // or panel removal. Map keyed by uid; survives across renders via a
  // ref so we don't re-create on every state change.
  const abortControllersRef = useRef<Map<number, AbortController>>(new Map());

  // Live canvas width (#5). ResizeObserver keeps this in sync with the
  // actual rendered width — the previous prop-based approach went stale.
  const [canvasWidth, setCanvasWidth] = useState<number>(0);
  React.useEffect(() => {
    const el = canvasRef.current;
    if (!el) return;
    const setFromEl = () => setCanvasWidth(el.clientWidth);
    setFromEl();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => setFromEl());
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Persist layout — but throttle (#6) so a 2-second drag doesn't fire
  // 100+ writes. We just save shape (toolId/width/height); session
  // state (results, in-flight target, status) shouldn't survive refresh.
  React.useEffect(() => {
    if (typeof window === "undefined") return;
    const id = window.setTimeout(() => {
      try {
        const slim: StoredPanel[] = panels.map((p) => ({
          toolId: p.toolId, widthPct: p.widthPct, heightPx: p.heightPx,
        }));
        window.localStorage.setItem(LAYOUT.STORAGE_KEY, JSON.stringify(slim));
      } catch {
        // localStorage can fail (quota, private browsing) — non-fatal.
      }
    }, 250);
    return () => window.clearTimeout(id);
  }, [panels]);

  // Cancel all in-flight requests when the page unmounts (#3 / #4).
  React.useEffect(() => {
    return () => {
      abortControllersRef.current.forEach((c) => {
        try { c.abort(); } catch { /* noop */ }
      });
      abortControllersRef.current.clear();
    };
  }, []);

  // Apply a shared workspace from the URL hash on mount (#28). We
  // strip the hash after applying so the page URL doesn't keep
  // referring to a layout that's already been adopted; subsequent
  // edits won't mutate the original share link.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  React.useEffect(() => {
    if (typeof window === "undefined") return;
    const hash = window.location.hash;
    const m = hash.match(/^#share=([A-Za-z0-9_-]+)$/);
    if (!m) return;
    const decoded = decodeSharedLayout(m[1]);
    if (!decoded) return;
    abortControllersRef.current.forEach((c) => { try { c.abort(); } catch { /* noop */ } });
    abortControllersRef.current.clear();
    const startUid = nextUid.current;
    setPanels(decoded.panels.slice(0, maxPanels).map((p, i) => ({
      uid: startUid + i, toolId: p.t,
      localTarget: p.lt || "", status: "idle" as const,
      result: null, error: null, execMs: null, expanded: false,
      widthPct: Math.min(LAYOUT.MAX_WIDTH_PCT, Math.max(LAYOUT.MIN_WIDTH_PCT, p.w)),
      heightPx: Math.min(
        Math.max(LAYOUT.MIN_HEIGHT_PX, window.innerHeight - LAYOUT.VIEWPORT_HEIGHT_BUFFER),
        Math.max(LAYOUT.MIN_HEIGHT_PX, p.h),
      ),
    })));
    nextUid.current = startUid + decoded.panels.length;
    if (decoded.gt) setGlobalTarget(decoded.gt);
    if (decoded.bm) setBulkMode(true);
    // Strip the share fragment so subsequent edits don't masquerade
    // as the shared layout.
    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    } else {
      window.location.hash = "";
    }
  }, []);

  const [globalTarget, setGlobalTarget] = useState("");
  // Bulk-target mode (#26). When on, the toolbar input becomes a
  // textarea and Run All iterates over each non-empty line in
  // sequence — useful for "header-check across these 30 subdomains"
  // or "DNS lookup for this list" without manually setting each one.
  const [bulkMode, setBulkMode] = useState(false);
  const [bulkProgress, setBulkProgress] = useState<{ current: number; total: number; target: string } | null>(null);
  const bulkAbortRef = useRef<{ aborted: boolean }>({ aborted: false });
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [sidebarWidth, setSidebarWidth] = useState<number>(LAYOUT.SIDEBAR_DEFAULT);
  const [collapsedCats, setCollapsedCats] = useState<Record<string, boolean>>({});
  const [alertBanner, setAlertBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [draggingTool, setDraggingTool] = useState(false); // #18 — drop-zone visual feedback
  // Workspace presets (#24). User-saved presets live in localStorage.
  const [userPresets, setUserPresets] = useState<WorkspacePreset[]>(() => loadUserPresets());
  // Run history (#29). Toggleable drawer.
  const [history, setHistory] = useState<HistoryEntry[]>(() => loadHistory());
  const [historyOpen, setHistoryOpen] = useState(false);
  // Persist history on every change. Cheap — sliding window of 50.
  React.useEffect(() => {
    saveHistory(history);
  }, [history]);

  // Per-result notes (#30). Persisted to localStorage on every edit
  // (debounced). Keys are toolId|target so the same note shows
  // wherever that combo is rendered.
  const [notes, setNotes] = useState<Record<string, string>>(() => loadNotes());
  React.useEffect(() => {
    const id = window.setTimeout(() => saveNotes(notes), 250);
    return () => window.clearTimeout(id);
  }, [notes]);
  const setNoteFor = useCallback((toolId: ToolId, target: string, note: string) => {
    setNotes((prev) => ({ ...prev, [notesKeyFor(toolId, target)]: note }));
  }, []);

  // Result hashes (#27). Stored in a ref so updates from many panels
  // don't cause re-renders; we persist after each successful run.
  const resultHashesRef = useRef<Record<string, string>>({});
  const resultHashesSaveTimer = useRef<number | null>(null);
  React.useEffect(() => {
    resultHashesRef.current = loadResultHashes();
    return () => {
      if (resultHashesSaveTimer.current) {
        window.clearTimeout(resultHashesSaveTimer.current);
        // Flush any pending writes.
        saveResultHashes(resultHashesRef.current);
        resultHashesSaveTimer.current = null;
      }
    };
  }, []);
  const sidebarResizeRef = useRef<{ startX: number; startW: number } | null>(null);

  React.useEffect(() => {
    if (!alertBanner) return;
    const t = setTimeout(() => setAlertBanner(null), 4000);
    return () => clearTimeout(t);
  }, [alertBanner]);

  const handleSidebarResizeDown = (e: React.MouseEvent) => {
    e.preventDefault();
    sidebarResizeRef.current = { startX: e.clientX, startW: sidebarWidth };
    const onMove = (ev: MouseEvent) => {
      if (!sidebarResizeRef.current) return;
      const newW = sidebarResizeRef.current.startW + (ev.clientX - sidebarResizeRef.current.startX);
      setSidebarWidth(Math.min(LAYOUT.SIDEBAR_MAX, Math.max(LAYOUT.SIDEBAR_MIN, newW)));
    };
    const onUp = () => {
      sidebarResizeRef.current = null;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    document.body.style.cursor = "ew-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const addPanel = useCallback((toolId: ToolId) => {
    if (panels.length >= maxPanels) return;
    const cols = Math.min(panels.length + 1, 3);
    setPanels((p) => [...p, {
      uid: nextUid.current++, toolId, localTarget: "", status: "idle",
      result: null, error: null, execMs: null, expanded: false,
      widthPct: 100 / cols, heightPx: LAYOUT.DEFAULT_HEIGHT_PX,
    }]);
  }, [panels.length, maxPanels]);

  const removePanel = useCallback((uid: number) => {
    // Abort any in-flight request the panel owns (#4) — otherwise the
    // request still runs to completion on the backend and resolves
    // into a state update for a panel that no longer exists.
    const ac = abortControllersRef.current.get(uid);
    if (ac) {
      try { ac.abort(); } catch { /* noop */ }
      abortControllersRef.current.delete(uid);
    }
    setPanels((p) => p.filter((x) => x.uid !== uid));
  }, []);
  const toggleExpand = useCallback((uid: number) => setPanels((p) => p.map((x) => x.uid === uid ? { ...x, expanded: !x.expanded } : x)), []);
  const setLocalTarget = useCallback((uid: number, val: string) => setPanels((p) => p.map((x) => x.uid === uid ? { ...x, localTarget: val } : x)), []);
  const resizePanel = useCallback((uid: number, w: number, h: number) => setPanels((p) => p.map((x) => x.uid === uid ? { ...x, widthPct: w, heightPx: h } : x)), []);
  const updatePanel = useCallback((uid: number, patch: Partial<PanelState>) => setPanels((p) => p.map((x) => x.uid === uid ? { ...x, ...patch } : x)), []);

  // Double-click a resize handle → distribute panel widths evenly so
  // the workspace settles into a clean grid. Heights are intentionally
  // left alone; the user usually wants to keep whatever heights they
  // set per-tool.
  const autofitRow = useCallback(() => {
    setPanels((p) => {
      if (p.length === 0) return p;
      const w = 100 / p.length;
      return p.map((x) => ({ ...x, widthPct: w }));
    });
  }, []);

  const runTool = useCallback(async (uid: number, targetOverride?: string) => {
    const panel = panels.find((p) => p.uid === uid);
    if (!panel) return;
    const tool = TOOL_MAP[panel.toolId];
    if (!tool) return;
    // Local target still wins (user explicitly set it for this panel).
    // Otherwise fall through to targetOverride (bulk-mode iterator) or
    // the toolbar's globalTarget. The override path lets a caller
    // sequence many targets through without round-tripping through
    // globalTarget state on each step.
    const localT = panel.localTarget.trim();
    const val = localT || (targetOverride ?? globalTarget).trim();
    if (!val) return;

    // Cancel a previous in-flight request for this panel before
    // starting a new one (#4). The aborted request will reject with an
    // AbortError which we swallow below so the panel doesn't end up in
    // an "error" state because the user clicked Run again.
    const prev = abortControllersRef.current.get(uid);
    if (prev) { try { prev.abort(); } catch { /* noop */ } }
    const ac = new AbortController();
    abortControllersRef.current.set(uid, ac);

    updatePanel(uid, { status: "running", result: null, error: null, execMs: null });
    const startMs = performance.now();

    try {
      let endpoint = `/tools/${panel.toolId}`;
      let body: Record<string, string> = {};
      if (panel.toolId === "cert-lookup") {
        if (isSha256Hash(val)) { endpoint = "/tools/cert-hash"; body = { hash: val }; }
        else { endpoint = "/tools/cert-lookup"; body = { domain: val }; }
      } else {
        body = { [tool.inputField]: val };
      }
      const res = await apiFetch(endpoint, { method: "POST", body: JSON.stringify(body), signal: ac.signal });
      if (ac.signal.aborted) return; // raced with abort — drop result
      const elapsed = Math.round(performance.now() - startMs);

      // Result diff (#27, minimal). Compare a quick content hash
      // against the cached one for this (toolId, target). Show a
      // "changed" badge when it differs from a prior run; first
      // run for a target is silent (no badge).
      const hashKey = notesKeyFor(panel.toolId, val);
      let nextHash: string;
      try {
        nextHash = quickHash(JSON.stringify(res));
      } catch {
        nextHash = "";
      }
      const prevHash = resultHashesRef.current[hashKey];
      const changed = !!prevHash && nextHash && prevHash !== nextHash;
      if (nextHash) {
        resultHashesRef.current[hashKey] = nextHash;
        // Defer persistence — many concurrent runs would otherwise
        // hammer localStorage; one save per ~250ms is plenty.
        if (!resultHashesSaveTimer.current) {
          resultHashesSaveTimer.current = window.setTimeout(() => {
            saveResultHashes(resultHashesRef.current);
            resultHashesSaveTimer.current = null;
          }, 250);
        }
      }

      updatePanel(uid, {
        status: "done", result: res, execMs: elapsed,
        changedFromPrev: changed || undefined,
      });
      // Record in history (#29). Newest first, sliding window.
      setHistory((prev) => [{
        id: `h.${Date.now().toString(36)}.${Math.random().toString(36).slice(2, 6)}`,
        toolId: panel.toolId, target: val, status: "done" as const,
        timestamp: Date.now(), durationMs: elapsed,
      }, ...prev].slice(0, HISTORY_MAX));
    } catch (e: any) {
      if (e?.name === "AbortError" || ac.signal.aborted) {
        // User cancelled (rerun, removed panel, or page unmount) — do
        // not flip the panel to "error" state.
        return;
      }
      const elapsed = Math.round(performance.now() - startMs);
      const errorMessage = e?.message || "Request failed";
      updatePanel(uid, { status: "error", error: errorMessage, execMs: elapsed });
      setHistory((prev) => [{
        id: `h.${Date.now().toString(36)}.${Math.random().toString(36).slice(2, 6)}`,
        toolId: panel.toolId, target: val, status: "error" as const,
        timestamp: Date.now(), durationMs: elapsed, errorMessage,
      }, ...prev].slice(0, HISTORY_MAX));
    } finally {
      // Only clear if the controller is still ours; a later run may
      // have already replaced it.
      if (abortControllersRef.current.get(uid) === ac) {
        abortControllersRef.current.delete(uid);
      }
    }
  }, [panels, globalTarget, updatePanel]);

  // Bound concurrency for "Run All" (#1, #9) so we don't burst the
  // shared target with N simultaneous probes — looks like a bot to the
  // far end and bursts the rate-limit on shared API providers (Shodan,
  // GitHub, etc.). Tools are issued in batches of RUN_ALL_CONCURRENCY
  // and the next batch only fires once the previous one settles.
  //
  // In bulk mode (#26), runAll iterates sequentially over each line of
  // globalTarget — applying RUN_ALL_CONCURRENCY *within* each target
  // but waiting for one target's batch to finish before starting the
  // next. This keeps total upstream load roughly the same as a single
  // run, just stretched across N targets.
  const runForTarget = useCallback(async (target: string | undefined) => {
    const queue = panels.filter((p) => {
      // In bulk mode, the per-panel localTarget still wins — caller
      // wants their override applied where no localTarget is set.
      const localT = p.localTarget.trim();
      const effective = localT || (target ?? globalTarget).trim();
      return effective && p.status !== "running";
    });
    let i = 0;
    const worker = async () => {
      while (i < queue.length) {
        const idx = i++;
        const p = queue[idx];
        if (!p) continue;
        await runTool(p.uid, target);
      }
    };
    const workers = Array.from(
      { length: Math.min(LAYOUT.RUN_ALL_CONCURRENCY, queue.length) },
      () => worker(),
    );
    await Promise.all(workers);
  }, [panels, globalTarget, runTool]);

  const runAll = useCallback(async () => {
    if (!bulkMode) {
      await runForTarget(undefined);
      return;
    }
    // Bulk mode — iterate over each line.
    const targets = globalTarget
      .split(/\r?\n/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0);
    if (targets.length === 0) {
      await runForTarget(undefined);
      return;
    }
    bulkAbortRef.current = { aborted: false };
    for (let i = 0; i < targets.length; i++) {
      if (bulkAbortRef.current.aborted) break;
      const t = targets[i];
      setBulkProgress({ current: i + 1, total: targets.length, target: t });
      await runForTarget(t);
    }
    setBulkProgress(null);
  }, [bulkMode, globalTarget, runForTarget]);

  const cancelBulk = useCallback(() => {
    bulkAbortRef.current = { aborted: true };
    // Abort any panels in-flight for the current target so the loop
    // skips ahead.
    abortControllersRef.current.forEach((c) => { try { c.abort(); } catch { /* noop */ } });
  }, []);

  // Reset back to default layout (#17). Aborts in-flight requests so
  // their results don't land in the new panels.
  const resetToDefaults = useCallback(() => {
    abortControllersRef.current.forEach((c) => { try { c.abort(); } catch { /* noop */ } });
    abortControllersRef.current.clear();
    nextUid.current = DEFAULT_TOOLS.length + 1;
    const cols = Math.min(DEFAULT_TOOLS.length, 3) || 1;
    setPanels(DEFAULT_TOOLS.map((toolId, i) => ({
      uid: i + 1, toolId, localTarget: "", status: "idle" as const,
      result: null, error: null, execMs: null, expanded: false,
      widthPct: 100 / cols, heightPx: LAYOUT.DEFAULT_HEIGHT_PX,
    })));
  }, []);

  // "Clear all" (the trash button) is now distinct from "Reset"
  // — clear leaves the canvas empty; reset goes back to defaults.
  const clearAll = useCallback(() => {
    abortControllersRef.current.forEach((c) => { try { c.abort(); } catch { /* noop */ } });
    abortControllersRef.current.clear();
    setPanels([]);
  }, []);

  // Apply a preset — replace the current workspace with the preset's
  // tool list. Aborts any in-flight requests since the panels are
  // about to be replaced. Respects the per-plan panel cap.
  const applyPreset = useCallback((preset: WorkspacePreset) => {
    abortControllersRef.current.forEach((c) => { try { c.abort(); } catch { /* noop */ } });
    abortControllersRef.current.clear();
    const ids = preset.toolIds.slice(0, maxPanels);
    const cols = Math.min(ids.length, 3) || 1;
    const startUid = nextUid.current;
    setPanels(ids.map((toolId, i) => ({
      uid: startUid + i, toolId, localTarget: "", status: "idle" as const,
      result: null, error: null, execMs: null, expanded: false,
      widthPct: 100 / cols, heightPx: LAYOUT.DEFAULT_HEIGHT_PX,
    })));
    nextUid.current = startUid + ids.length;
  }, [maxPanels]);

  // Save the current panel set as a named user preset. Writes to
  // localStorage and updates state immediately.
  const saveCurrentAsPreset = useCallback((name: string) => {
    const trimmed = name.trim();
    if (!trimmed || panels.length === 0) return;
    const id = `user.${Date.now().toString(36)}.${Math.random().toString(36).slice(2, 6)}`;
    const newPreset: WorkspacePreset = {
      id, name: trimmed,
      description: `${panels.length} tool${panels.length === 1 ? "" : "s"}`,
      builtIn: false,
      toolIds: panels.map((p) => p.toolId),
    };
    setUserPresets((prev) => {
      // De-dup by name — replace if user re-saves with the same name.
      const without = prev.filter((p) => p.name !== trimmed);
      const next = [...without, newPreset];
      saveUserPresets(next);
      return next;
    });
  }, [panels]);

  const deleteUserPreset = useCallback((id: string) => {
    setUserPresets((prev) => {
      const next = prev.filter((p) => p.id !== id);
      saveUserPresets(next);
      return next;
    });
  }, []);

  // Open a value in another tool (#25). Used by SendTo chips inside
  // result renderers — e.g. click an IP in DNS result, send it to
  // Reverse DNS. If a panel for the target tool already exists, set
  // its localTarget and run; otherwise add a fresh panel pre-set.
  const openInTool = useCallback((toolId: string, target: string) => {
    if (!TOOL_MAP[toolId]) return;
    const trimmed = target.trim();
    if (!trimmed) return;
    const existing = panels.find((p) => p.toolId === toolId);
    if (existing) {
      setPanels((p) => p.map((x) => x.uid === existing.uid ? { ...x, localTarget: trimmed } : x));
      setTimeout(() => runTool(existing.uid, trimmed), 0);
      return;
    }
    if (panels.length >= maxPanels) {
      setAlertBanner({ kind: "err", text: `Panel limit reached (${maxPanels}). Remove one to add another.` });
      return;
    }
    const newUid = nextUid.current++;
    const cols = Math.min(panels.length + 1, 3);
    setPanels((p) => [...p, {
      uid: newUid, toolId: toolId as ToolId, localTarget: trimmed, status: "idle",
      result: null, error: null, execMs: null, expanded: false,
      widthPct: 100 / cols, heightPx: LAYOUT.DEFAULT_HEIGHT_PX,
    }]);
    setTimeout(() => runTool(newUid, trimmed), 0);
  }, [panels, maxPanels, runTool]);

  // Memoised lookup tables for the SendTo context — avoids
  // rebuilding on every render.
  const sendToCtxValue = React.useMemo(() => ({
    send: openInTool,
    acceptsByTool: Object.fromEntries(TOOLS.map((t) => [t.id, t.accepts])),
    nameByTool: Object.fromEntries(TOOLS.map((t) => [t.id, t.name])),
  }), [openInTool]);

  // Re-run an entry from history (#29). If a panel for that tool
  // already exists, set its localTarget and run; otherwise add a new
  // panel pre-targeted to that value. Closes the drawer either way.
  const rerunFromHistory = useCallback((entry: HistoryEntry) => {
    const existing = panels.find((p) => p.toolId === entry.toolId);
    if (existing) {
      setPanels((p) => p.map((x) => x.uid === existing.uid ? { ...x, localTarget: entry.target } : x));
      setHistoryOpen(false);
      // Run after the state update lands
      setTimeout(() => runTool(existing.uid, entry.target), 0);
      return;
    }
    if (panels.length >= maxPanels) {
      setAlertBanner({ kind: "err", text: `Panel limit reached (${maxPanels}). Remove one to add another.` });
      return;
    }
    const newUid = nextUid.current++;
    const cols = Math.min(panels.length + 1, 3);
    setPanels((p) => [...p, {
      uid: newUid, toolId: entry.toolId, localTarget: entry.target, status: "idle",
      result: null, error: null, execMs: null, expanded: false,
      widthPct: 100 / cols, heightPx: LAYOUT.DEFAULT_HEIGHT_PX,
    }]);
    setHistoryOpen(false);
    setTimeout(() => runTool(newUid, entry.target), 0);
  }, [panels, maxPanels, runTool]);

  const clearHistory = useCallback(() => setHistory([]), []);

  // ── Deep-link from finding/alert detail panels ──────────────────────
  // URL contract: /tools?tool=<id>&target=<value>&autorun=1
  // - Spawns or focuses a panel for `tool` with the target pre-filled.
  // - When autorun=1, runs it as soon as the panel is mounted.
  // Single-shot: a guard ref ensures it only fires once per page load,
  // and the URL params are stripped after processing so a refresh
  // doesn't re-trigger the same run.
  const router = useRouter();
  const searchParams = useSearchParams();
  const deepLinkHandled = useRef(false);
  // The setTimeout(() => runTool(newUid)) pattern that openInTool uses
  // works for click-triggered flows (state has flushed by the time the
  // closure runs) but races React's mount-time render path. Instead we
  // park the request in a ref and let a separate effect — keyed on
  // panels — pick it up the moment the new panel appears in state.
  const pendingDeepLinkRunRef = useRef<{ uid: number; target: string } | null>(null);

  useEffect(() => {
    if (deepLinkHandled.current) return;
    const tool = searchParams?.get("tool");
    const target = searchParams?.get("target");
    const autorun = searchParams?.get("autorun") === "1";
    if (!tool || !target || !TOOL_MAP[tool]) return;
    deepLinkHandled.current = true;

    const trimmed = target.trim();
    const existing = panels.find((p) => p.toolId === tool);
    if (existing) {
      setPanels((p) =>
        p.map((x) => (x.uid === existing.uid ? { ...x, localTarget: trimmed } : x))
      );
      if (autorun) pendingDeepLinkRunRef.current = { uid: existing.uid, target: trimmed };
    } else if (panels.length < maxPanels) {
      const newUid = nextUid.current++;
      const cols = Math.min(panels.length + 1, 3);
      setPanels((p) => [
        ...p,
        {
          uid: newUid,
          toolId: tool as ToolId,
          localTarget: trimmed,
          status: "idle",
          result: null,
          error: null,
          execMs: null,
          expanded: false,
          widthPct: 100 / cols,
          heightPx: LAYOUT.DEFAULT_HEIGHT_PX,
        },
      ]);
      if (autorun) pendingDeepLinkRunRef.current = { uid: newUid, target: trimmed };
    } else {
      setAlertBanner({
        kind: "err",
        text: `Panel limit reached (${maxPanels}). Remove one to add another.`,
      });
    }

    // Strip the params so a refresh doesn't re-fire the run.
    router.replace("/tools", { scroll: false });
    // We intentionally read panels/maxPanels/router from the closure at
    // mount; the deepLinkHandled guard prevents re-execution if any of
    // these change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Fire the pending autorun once the deep-link panel is actually in
  // the panels array (so runTool's panels.find succeeds).
  useEffect(() => {
    const pending = pendingDeepLinkRunRef.current;
    if (!pending) return;
    const panel = panels.find((p) => p.uid === pending.uid);
    if (!panel) return;
    pendingDeepLinkRunRef.current = null;
    runTool(pending.uid, pending.target);
  }, [panels, runTool]);

  // Build and copy a shareable URL containing the current workspace
  // shape (#28). Clipboard write is wrapped because some browsers
  // reject it without a user gesture; the click counts as one but
  // private-browsing modes can still throw.
  const copyShareLink = useCallback(async () => {
    if (panels.length === 0) {
      setAlertBanner({ kind: "err", text: "Nothing to share — workspace is empty." });
      return;
    }
    try {
      const enc = encodeSharedLayout(panels, globalTarget, bulkMode);
      const url = `${window.location.origin}${window.location.pathname}#share=${enc}`;
      await navigator.clipboard.writeText(url);
      setAlertBanner({ kind: "ok", text: "Share link copied to clipboard." });
    } catch (e: any) {
      setAlertBanner({ kind: "err", text: `Couldn't copy share link: ${e?.message || "clipboard blocked"}` });
    }
  }, [panels, globalTarget, bulkMode]);

  // Sidebar drag → workspace drop. We light up the canvas (#18) so
  // first-time users discover that drag-and-drop is supported.
  const handleSidebarDragStart = (e: React.DragEvent, toolId: string) => {
    e.dataTransfer.setData("newToolId", toolId);
    e.dataTransfer.effectAllowed = "copy";
    setDraggingTool(true);
  };
  const handleSidebarDragEnd = () => {
    setDraggingTool(false);
  };

  const handleWorkspaceDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDraggingTool(false);
    const newToolId = e.dataTransfer.getData("newToolId");
    if (newToolId && TOOL_MAP[newToolId]) addPanel(newToolId as ToolId);
  };

  const toggleCat = (cat: string) => setCollapsedCats((prev) => ({ ...prev, [cat]: !prev[cat] }));

  const runningCount = panels.filter((p) => p.status === "running").length;

  return (
    <SendToToolContext.Provider value={sendToCtxValue}>
    <div className="flex-1 flex overflow-hidden bg-background text-foreground">
      {/* ═══ SIDEBAR ═══ */}
      <div className={cn(
        "shrink-0 border-r border-border bg-card/40 transition-all duration-200 flex flex-col relative",
        sidebarOpen ? "" : "w-0 overflow-hidden"
      )} style={sidebarOpen ? { width: sidebarWidth } : undefined}>
        <div className="px-4 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-primary" />
            <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Tools</span>
          </div>
          <div className="text-[10px] text-muted-foreground/50 mt-1">Drag tools into workspace or click to add</div>
        </div>

        <div className="flex-1 overflow-auto py-2">
          {CATEGORIES.map((cat) => {
            const catTools = TOOLS.filter((t) => t.category === cat);
            const collapsed = collapsedCats[cat];
            return (
              <div key={cat}>
                <button onClick={() => toggleCat(cat)}
                  className="w-full flex items-center justify-between px-4 py-2 text-left hover:bg-accent/20 transition-colors">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ background: CAT_COLORS[cat] }} />
                    <span className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">{cat}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] text-muted-foreground/40">{catTools.length}</span>
                    {collapsed ? <ChevronDown className="w-3 h-3 text-muted-foreground/30" /> : <ChevronUp className="w-3 h-3 text-muted-foreground/30" />}
                  </div>
                </button>
                {!collapsed && (
                  <div className="px-2 pb-1 space-y-0.5">
                    {catTools.map((t) => (
                      <div key={t.id}
                        className="flex items-center gap-2.5 px-2 py-2 rounded-lg cursor-grab active:cursor-grabbing hover:bg-accent/30 transition-colors group"
                        draggable
                        onDragStart={(e) => handleSidebarDragStart(e, t.id)}
                        onDragEnd={handleSidebarDragEnd}
                        onClick={() => addPanel(t.id)}
                        title={`Drag or click to add ${t.name}`}>
                        <div className={cn("h-6 w-6 rounded-md flex items-center justify-center shrink-0", t.iconBg, t.color)}>
                          {t.icon}
                        </div>
                        <div className="min-w-0 flex-1">
                          <span className="text-xs text-muted-foreground group-hover:text-foreground transition-colors truncate block">{t.name}</span>
                          <span className="text-[10px] text-muted-foreground/40 truncate block">{t.description}</span>
                        </div>
                        <Plus className="w-3 h-3 text-muted-foreground/0 group-hover:text-primary/60 transition-all ml-auto shrink-0" />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div className="px-4 py-3 border-t border-border text-[10px] text-muted-foreground/40">
          {panels.length} panel{panels.length !== 1 ? "s" : ""}
          {runningCount > 0 && <span className="text-amber-400 ml-1">· {runningCount} running</span>}
        </div>

        {/* Resize handle */}
        <div onMouseDown={handleSidebarResizeDown}
          className="absolute top-0 right-0 w-1.5 h-full cursor-ew-resize z-20 hover:bg-primary/20 transition-colors group">
          <div className="absolute top-1/2 -translate-y-1/2 right-0 w-1 h-8 rounded-full bg-muted-foreground/10 group-hover:bg-primary/40 transition-colors" />
        </div>
      </div>

      {/* ═══ MAIN AREA ═══ */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Toolbar */}
        <div className="flex items-center gap-3 px-4 py-2.5 border-b border-white/[0.06] bg-card/60 backdrop-blur-sm shrink-0">
          <button onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent/30 transition-colors"
            title={sidebarOpen ? "Hide sidebar" : "Show sidebar"}>
            <LayoutGrid className="w-4 h-4" />
          </button>
          <div className="flex items-center gap-2 shrink-0">
            <Target size={15} className="text-primary" />
            <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              {bulkMode ? "Targets" : "Target"}
            </span>
          </div>
          {/* Bulk-mode toggle (#26). When on, the input becomes a
              textarea and Run All iterates over each non-empty line. */}
          <button
            type="button"
            onClick={() => setBulkMode((m) => !m)}
            disabled={!!bulkProgress}
            title={bulkMode ? "Switch to single target" : "Switch to bulk mode (one target per line)"}
            className={cn(
              "p-1.5 rounded-md border transition-colors shrink-0",
              bulkMode
                ? "border-primary/30 bg-primary/10 text-primary"
                : "border-white/[0.06] text-muted-foreground hover:text-foreground hover:bg-accent/30",
            )}
          >
            <List className="w-4 h-4" />
          </button>
          {bulkMode ? (
            <textarea
              value={globalTarget}
              onChange={(e) => setGlobalTarget(e.target.value)}
              placeholder={`One target per line — e.g.\nexample.com\nshop.example.com\nblog.example.com`}
              rows={3}
              disabled={!!bulkProgress}
              className="flex-1 bg-background border border-white/[0.06] rounded-lg px-4 py-2 text-[12px] text-foreground placeholder-muted-foreground/40 outline-none focus:border-primary/30 transition-colors font-mono resize-y min-h-[42px] max-h-[140px]"
            />
          ) : (
            <input
              type="text"
              value={globalTarget}
              onChange={(e) => setGlobalTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && runAll()}
              placeholder="Shared target — e.g. example.com, 8.8.8.8, CVE-2024-1234 ..."
              className="flex-1 bg-background border border-white/[0.06] rounded-lg px-4 py-2 text-[13px] text-foreground placeholder-muted-foreground/40 outline-none focus:border-primary/30 transition-colors font-mono"
            />
          )}
          {bulkProgress ? (
            <button
              onClick={cancelBulk}
              title="Cancel batch"
              className="flex items-center gap-2 rounded-lg bg-red-500/10 border border-red-500/30 px-4 py-2 text-[12px] font-semibold text-red-400 hover:bg-red-500/20 transition-all"
            >
              <X size={13} /> Stop
            </button>
          ) : (() => {
            // Disabled reasons surfaced via title (#13). Run All needs
            // both at least one panel and at least one panel with a
            // resolvable target.
            const targets = bulkMode
              ? globalTarget.split(/\r?\n/).map((t) => t.trim()).filter(Boolean)
              : [globalTarget.trim()].filter(Boolean);
            const hasRunnable = panels.some((p) =>
              p.localTarget.trim() !== "" || targets.length > 0,
            );
            const disabled = panels.length === 0 || !hasRunnable;
            const reason = panels.length === 0
              ? "Add a tool to the workspace first"
              : !hasRunnable
                ? bulkMode ? "Add at least one target line first" : "Set a target above (or in a panel) first"
                : bulkMode
                  ? `Runs ${targets.length} target${targets.length === 1 ? "" : "s"} sequentially, up to ${LAYOUT.RUN_ALL_CONCURRENCY} tools per target`
                  : `Runs up to ${LAYOUT.RUN_ALL_CONCURRENCY} tools concurrently`;
            return (
              <button onClick={runAll} disabled={disabled} title={reason}
                className="flex items-center gap-2 rounded-lg bg-primary/10 border border-primary/20 px-4 py-2 text-[12px] font-semibold text-primary hover:bg-primary/20 transition-all disabled:opacity-30 disabled:cursor-not-allowed">
                <Search size={13} />
                {bulkMode ? `Run Batch${targets.length > 0 ? ` (${targets.length})` : ""}` : "Run All"}
              </button>
            );
          })()}
          <div className="w-px h-6 bg-white/[0.06]" />
          <PresetsDropdown
            userPresets={userPresets}
            onApply={applyPreset}
            onSave={saveCurrentAsPreset}
            onDelete={deleteUserPreset}
            panelsCount={panels.length}
          />
          <AddToolDropdown onAdd={addPanel} disabled={panels.length >= maxPanels} />
          <span
            className="text-[10px] text-muted-foreground font-mono"
            title={`Panel limit on the ${plan || "Free"} plan: ${maxPanels}`}
          >
            {panels.length}/{maxPanels}
            {runningCount > 0 && <span className="text-amber-400 ml-1">· {runningCount} running</span>}
          </span>
          <button
            onClick={copyShareLink}
            disabled={panels.length === 0}
            className="p-2 rounded-lg border border-white/[0.06] hover:bg-primary/10 hover:border-primary/20 text-muted-foreground hover:text-primary transition-colors disabled:opacity-30"
            title="Copy a shareable link to this workspace"
          >
            <LinkIcon size={13} />
          </button>
          <button
            onClick={() => setHistoryOpen(true)}
            className="p-2 rounded-lg border border-white/[0.06] hover:bg-primary/10 hover:border-primary/20 text-muted-foreground hover:text-primary transition-colors relative"
            title={`Run history (${history.length})`}
          >
            <History size={13} />
            {history.length > 0 && (
              <span className="absolute -top-1 -right-1 min-w-[14px] h-[14px] px-0.5 rounded-full bg-primary text-primary-foreground text-[9px] font-bold flex items-center justify-center">
                {history.length > 99 ? "99+" : history.length}
              </span>
            )}
          </button>
          <button
            onClick={resetToDefaults}
            disabled={panels.length === 0 && DEFAULT_TOOLS.length === 0}
            className="p-2 rounded-lg border border-white/[0.06] hover:bg-primary/10 hover:border-primary/20 text-muted-foreground hover:text-primary transition-colors disabled:opacity-30"
            title="Reset to default layout"
          >
            <RefreshCcw size={13} />
          </button>
          <button
            onClick={clearAll}
            disabled={panels.length === 0}
            className="p-2 rounded-lg border border-white/[0.06] hover:bg-red-500/10 hover:border-red-500/20 text-muted-foreground hover:text-red-400 transition-colors disabled:opacity-30"
            title="Clear all panels"
          >
            <Trash2 size={13} />
          </button>
        </div>

        {/* Active-scan disclaimer (#8). Dismissable after first ack —
            stored in localStorage so it doesn't nag returning users.
            Tools that probe targets actively (port scan, exposed paths,
            header probe) do reach out from our infra to the target;
            users should only point them at assets they're authorised
            to test. */}
        <AuthorisationDisclaimer />
        {/* Keyboard-shortcut hints — light single-line strip. Shown
            once dismissed; otherwise the disclaimer line above carries
            the visual weight. */}
        <KeyboardHintStrip />

        {alertBanner && (
          <div className={cn(
            "mx-3 mt-3 rounded-lg border px-3 py-2 text-xs flex items-center justify-between gap-2",
            alertBanner.kind === "ok"
              ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]"
              : "border-red-500/30 bg-red-500/10 text-red-200"
          )}>
            <span>{alertBanner.text}</span>
            <button type="button" onClick={() => setAlertBanner(null)} className="opacity-60 hover:opacity-100">
              <X size={12} />
            </button>
          </div>
        )}

        {/* Bulk-progress indicator (#26). Shown only while a batch is
            in flight — gives the user a "this is what's happening"
            anchor and a click-to-cancel path. */}
        {bulkProgress && (
          <div className="mx-3 mt-3 rounded-lg border border-primary/30 bg-primary/5 px-3 py-2 text-xs flex items-center gap-3">
            <Loader2 className="w-3.5 h-3.5 text-primary shrink-0 animate-spin" />
            <span className="text-foreground shrink-0">
              Running batch {bulkProgress.current}/{bulkProgress.total}:
            </span>
            <span className="font-mono text-primary truncate flex-1">{bulkProgress.target}</span>
            <button
              type="button"
              onClick={cancelBulk}
              className="text-muted-foreground hover:text-red-400 transition-colors shrink-0"
              title="Cancel batch"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Canvas. While the user is dragging a tool from the sidebar
            we light up the drop zone (#18) so the affordance is
            obvious — a soft teal outline + slight tint. The plus
            icon in the empty state also brightens. */}
        <div ref={canvasRef}
          onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; }}
          onDrop={handleWorkspaceDrop}
          className={cn(
            "flex-1 min-h-0 overflow-auto p-3 transition-colors",
            draggingTool && "bg-primary/[0.04] outline outline-2 outline-dashed outline-primary/40 -outline-offset-2",
          )}
          style={{ backgroundImage: "radial-gradient(circle, hsl(var(--border)) 1px, transparent 1px)", backgroundSize: "32px 32px" }}>
          {panels.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center">
              <div className={cn(
                "w-24 h-24 rounded-2xl border-2 border-dashed flex items-center justify-center mb-5 relative transition-colors",
                draggingTool ? "border-primary/60 bg-primary/10" : "border-white/[0.08]",
              )}>
                <GripVertical size={28} className={cn("absolute -left-2 top-1/2 -translate-y-1/2 transition-colors", draggingTool ? "text-primary/60" : "text-white/10")} />
                <Plus size={32} className={cn("transition-colors", draggingTool ? "text-primary" : "text-white/10")} />
              </div>
              <p className={cn("text-[16px] font-semibold mb-2 transition-colors", draggingTool ? "text-primary" : "text-white/20")}>
                {draggingTool ? "Drop here" : "Drag & Drop Tools Here"}
              </p>
              <p className="text-[13px] text-white/10 max-w-sm text-center leading-relaxed">
                Grab any tool from the sidebar and drop it into this workspace to get started.
              </p>
              <p className="text-[11px] text-white/[0.06] mt-3">or use the <span className="text-white/10 font-medium">Add Tool</span> button in the toolbar above</p>
            </div>
          ) : (
            <div className="flex flex-wrap content-start" style={{ gap: `${LAYOUT.GAP}px` }}>
              {panels.map((panel) => {
                const tool = TOOL_MAP[panel.toolId];
                if (!tool) return null;
                return (
                  <ToolPanel key={panel.uid} panel={panel} tool={tool} globalTarget={globalTarget} canvasWidth={canvasWidth} canvasRef={canvasRef}
                    onRemove={() => removePanel(panel.uid)} onRun={() => runTool(panel.uid)}
                    onToggleExpand={() => toggleExpand(panel.uid)} onSetLocalTarget={(v) => setLocalTarget(panel.uid, v)}
                    onResize={(w, h) => resizePanel(panel.uid, w, h)}
                    onAutofit={autofitRow}
                    hasMonitoring={hasMonitoring}
                    onSavedAsAlert={(kind, text) => setAlertBanner({ kind, text })}
                    note={notes[notesKeyFor(panel.toolId, (panel.localTarget || globalTarget).trim())] || ""}
                    onSetNote={(v) => setNoteFor(panel.toolId, (panel.localTarget || globalTarget).trim(), v)}
                  />
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* History drawer (#29). Slides in from the right; click any
          row to re-open that tool with that target. */}
      {historyOpen && (
        <>
          <div className="fixed inset-0 z-40 bg-black/40" onClick={() => setHistoryOpen(false)} />
          <div className="fixed top-0 right-0 bottom-0 z-50 w-[400px] max-w-[90vw] bg-[#0c1222]/98 backdrop-blur-xl border-l border-white/[0.08] shadow-2xl flex flex-col">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.06] shrink-0">
              <History className="w-4 h-4 text-primary" />
              <span className="text-[12px] font-bold uppercase tracking-wider text-foreground">Run History</span>
              <span className="text-[10px] text-muted-foreground/60 ml-1">{history.length} of {HISTORY_MAX}</span>
              <div className="ml-auto flex items-center gap-1">
                <button
                  onClick={clearHistory}
                  disabled={history.length === 0}
                  title="Clear history"
                  className="p-1.5 rounded text-muted-foreground hover:text-red-400 transition-colors disabled:opacity-30"
                >
                  <Trash2 size={13} />
                </button>
                <button
                  onClick={() => setHistoryOpen(false)}
                  className="p-1.5 rounded text-muted-foreground hover:text-foreground transition-colors"
                >
                  <X size={13} />
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto">
              {history.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-center px-6">
                  <History className="w-10 h-10 text-muted-foreground/20 mb-3" />
                  <p className="text-[13px] text-muted-foreground">No runs yet.</p>
                  <p className="text-[11px] text-muted-foreground/50 mt-1">Run any tool — it'll show up here.</p>
                </div>
              ) : (
                <div className="divide-y divide-white/[0.04]">
                  {history.map((entry) => {
                    const tool = TOOL_MAP[entry.toolId];
                    if (!tool) return null;
                    const ago = (() => {
                      const sec = Math.floor((Date.now() - entry.timestamp) / 1000);
                      if (sec < 60) return `${sec}s ago`;
                      const min = Math.floor(sec / 60);
                      if (min < 60) return `${min}m ago`;
                      const hr = Math.floor(min / 60);
                      if (hr < 24) return `${hr}h ago`;
                      return `${Math.floor(hr / 24)}d ago`;
                    })();
                    return (
                      <button
                        key={entry.id}
                        onClick={() => rerunFromHistory(entry)}
                        className="w-full flex items-start gap-3 px-4 py-2.5 hover:bg-white/[0.04] transition-colors text-left"
                      >
                        <div className={cn("h-7 w-7 rounded-md flex items-center justify-center shrink-0", tool.iconBg, tool.color)}>
                          {tool.icon}
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-[12px] font-medium text-foreground truncate">{tool.name}</span>
                            {entry.status === "error" && (
                              <span className="text-[9px] font-mono uppercase tracking-wider text-red-400 px-1">err</span>
                            )}
                          </div>
                          <div className="text-[11px] font-mono text-muted-foreground truncate">{entry.target}</div>
                          {entry.errorMessage && entry.status === "error" && (
                            <div className="text-[10px] text-red-400/70 truncate mt-0.5">{entry.errorMessage}</div>
                          )}
                        </div>
                        <div className="text-[10px] text-muted-foreground/50 shrink-0 mt-0.5 text-right">
                          <div>{ago}</div>
                          {entry.durationMs !== undefined && (
                            <div className="font-mono">{entry.durationMs}ms</div>
                          )}
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
            <div className="px-4 py-2 border-t border-white/[0.06] text-[10px] text-muted-foreground/40 text-center shrink-0">
              Click a row to re-run the same target in that tool.
            </div>
          </div>
        </>
      )}
    </div>
    </SendToToolContext.Provider>
  );
}