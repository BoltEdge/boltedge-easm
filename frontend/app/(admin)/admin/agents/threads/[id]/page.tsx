"use client";
import { use, useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  AgentThreadDetail,
  AgentMessageRow,
  AgentRunSummary,
  getAgentThread,
} from "../../../../../lib/api";
import {
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  Terminal,
  AlertCircle,
} from "lucide-react";

// ────────────────────────────────────────────────────────────
// Status helpers
// ────────────────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  success: "text-emerald-400",
  completed: "text-emerald-400",
  failed: "text-red-400",
  timeout: "text-amber-400",
  "over-budget": "text-amber-400",
  running: "text-teal-400",
  pending: "text-white/40",
};

function fmtCost(v: number | null): string {
  if (v == null) return "—";
  return `$${v.toFixed(4)}`;
}

function fmtDuration(ms: number | null): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

// ────────────────────────────────────────────────────────────
// Collapsible JSON block
// ────────────────────────────────────────────────────────────

function JsonBlock({
  value,
  defaultCollapsed,
  label,
}: {
  value: unknown;
  defaultCollapsed?: boolean;
  label?: string;
}) {
  const text =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
  const lines = text.split("\n");
  const isLong = lines.length > 10;
  const [collapsed, setCollapsed] = useState(
    defaultCollapsed ?? (isLong ? true : false)
  );

  const preview = collapsed ? lines.slice(0, 10).join("\n") + "\n…" : text;

  return (
    <div className="mt-1.5">
      {label && (
        <div className="text-xs text-white/30 mb-1 font-mono">{label}</div>
      )}
      <div className="relative rounded bg-zinc-900 border border-white/[0.06]">
        <pre className="text-xs text-white/70 font-mono p-2.5 overflow-x-auto whitespace-pre-wrap">
          {preview}
        </pre>
        {isLong && (
          <button
            onClick={() => setCollapsed((c) => !c)}
            className="flex items-center gap-1 text-xs text-teal-400/70 hover:text-teal-400 px-2.5 py-1 border-t border-white/[0.06] w-full transition-colors"
          >
            {collapsed ? (
              <>
                <ChevronRight className="w-3 h-3" />
                Show all ({lines.length} lines)
              </>
            ) : (
              <>
                <ChevronDown className="w-3 h-3" />
                Collapse
              </>
            )}
          </button>
        )}
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────
// Per-message renderers
// ────────────────────────────────────────────────────────────

function UserMessage({ msg }: { msg: AgentMessageRow }) {
  const text = msg.content?.text ?? JSON.stringify(msg.content);
  return (
    <div className="flex justify-end">
      <div className="max-w-[75%]">
        <div className="text-xs text-white/30 text-right mb-1">
          {new Date(msg.created_at).toLocaleTimeString()}
        </div>
        <div className="rounded-2xl rounded-tr-sm bg-teal-500/15 border border-teal-500/20 px-4 py-2.5 text-sm text-white/90 whitespace-pre-wrap">
          {text}
        </div>
      </div>
    </div>
  );
}

function AssistantMessage({ msg }: { msg: AgentMessageRow }) {
  const text = msg.content?.text ?? JSON.stringify(msg.content);
  return (
    <div className="flex justify-start">
      <div className="max-w-[75%]">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs text-white/30">
            {new Date(msg.created_at).toLocaleTimeString()}
          </span>
          {msg.tokens_used != null && (
            <span className="text-xs text-white/20">
              {msg.tokens_used.toLocaleString()} tokens
            </span>
          )}
        </div>
        <div className="rounded-2xl rounded-tl-sm bg-white/[0.05] border border-white/[0.08] px-4 py-2.5 text-sm text-white/80 whitespace-pre-wrap">
          {text}
        </div>
      </div>
    </div>
  );
}

function ToolMessage({ msg }: { msg: AgentMessageRow }) {
  const c = msg.content ?? {};
  const toolName: string = c.tool_name ?? "unknown tool";
  const isError: boolean = c.is_error ?? false;
  const input = c.input;
  const output = c.output;

  const [open, setOpen] = useState(false);

  const accentBorder = isError
    ? "border-red-500/30"
    : "border-white/[0.06]";
  const accentBadge = isError
    ? "bg-red-500/10 text-red-400 border-red-500/20"
    : "bg-teal-500/10 text-teal-400 border-teal-500/20";

  return (
    <div className="flex justify-start w-full">
      <div className="w-full max-w-[85%]">
        <div className="text-xs text-white/30 mb-1">
          {new Date(msg.created_at).toLocaleTimeString()}
        </div>
        <div
          className={`rounded-lg border ${accentBorder} bg-white/[0.02] overflow-hidden`}
        >
          {/* Header row */}
          <button
            onClick={() => setOpen((o) => !o)}
            className="flex items-center gap-2 w-full px-3 py-2 hover:bg-white/[0.03] transition-colors text-left"
          >
            <Terminal className="w-3.5 h-3.5 text-white/30 shrink-0" />
            <span
              className={`text-xs px-2 py-0.5 rounded border font-mono ${accentBadge}`}
            >
              {toolName}
            </span>
            {isError && (
              <AlertCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
            )}
            <span className="ml-auto text-white/20">
              {open ? (
                <ChevronDown className="w-3.5 h-3.5" />
              ) : (
                <ChevronRight className="w-3.5 h-3.5" />
              )}
            </span>
          </button>

          {/* Expanded body */}
          {open && (
            <div className="px-3 pb-3 border-t border-white/[0.06]">
              {input !== undefined && (
                <JsonBlock value={input} label="input" defaultCollapsed={false} />
              )}
              {output !== undefined && (
                <JsonBlock
                  value={output}
                  label={isError ? "error output" : "output"}
                  defaultCollapsed={true}
                />
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Message({ msg }: { msg: AgentMessageRow }) {
  if (msg.role === "user") return <UserMessage msg={msg} />;
  if (msg.role === "assistant") return <AssistantMessage msg={msg} />;
  return <ToolMessage msg={msg} />;
}

// ────────────────────────────────────────────────────────────
// Runs strip
// ────────────────────────────────────────────────────────────

function RunsStrip({ runs }: { runs: AgentRunSummary[] }) {
  if (runs.length === 0) return null;
  return (
    <section className="mb-6">
      <h2 className="text-xs font-semibold uppercase tracking-wider text-white/30 mb-2">
        Runs in this thread
      </h2>
      <div className="flex flex-col gap-1.5">
        {runs.map((r) => (
          <div
            key={r.id}
            className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2 text-xs"
          >
            <span
              className={`font-medium w-20 shrink-0 ${STATUS_COLORS[r.status] ?? "text-white/60"}`}
            >
              {r.status}
            </span>
            {r.skill && (
              <code className="text-white/50 shrink-0">{r.skill}</code>
            )}
            <span className="text-white/40">{fmtCost(r.cost_usd)}</span>
            <span className="text-white/40">{fmtDuration(r.duration_ms)}</span>
            <span className="text-white/30 ml-auto">
              {new Date(r.started_at).toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

// ────────────────────────────────────────────────────────────
// Page
// ────────────────────────────────────────────────────────────

export default function ThreadDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const [detail, setDetail] = useState<AgentThreadDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    getAgentThread(Number(id))
      .then(setDetail)
      .catch((e: any) => setError(e?.message ?? String(e)));
  }, [id]);

  // Auto-scroll to bottom once messages load
  useEffect(() => {
    if (detail) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [detail]);

  if (error)
    return <div className="text-red-400 text-sm">{error}</div>;
  if (!detail)
    return <div className="text-white/40 text-sm">Loading…</div>;

  const { thread, messages, runs } = detail;

  return (
    <div className="max-w-3xl">
      {/* Back link */}
      <Link
        href={`/admin/agents/${encodeURIComponent(thread.agent_id)}`}
        className="inline-flex items-center gap-1.5 text-sm text-white/40 hover:text-white mb-6 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        {thread.agent_id}
      </Link>

      {/* Header */}
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-white">
          {thread.title ?? <span className="italic text-white/40">Untitled thread</span>}
        </h1>
        <div className="text-xs text-white/30 mt-1">
          <code className="mr-2">{thread.agent_id}</code>
          &middot;
          <span className="ml-2">{new Date(thread.created_at).toLocaleString()}</span>
        </div>
      </div>

      {/* Runs strip */}
      <RunsStrip runs={runs} />

      {/* Chat messages */}
      {messages.length === 0 ? (
        <p className="text-white/40 text-sm">No messages in this thread.</p>
      ) : (
        <div className="flex flex-col gap-4 pb-8">
          {messages.map((m) => (
            <Message key={m.id} msg={m} />
          ))}
          <div ref={bottomRef} />
        </div>
      )}
    </div>
  );
}
