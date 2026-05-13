"use client";
import { useState } from "react";
import {
  Bot,
  Check,
  ChevronDown,
  ChevronRight,
  Clock,
  FileText,
  GitBranch,
  Loader2,
  X,
} from "lucide-react";
import type { PendingActionRow } from "../../../../lib/api";

type ProposedFile = { path: string; content: string };

type CodePRPayload = {
  branch_name?: string;
  base?: string;
  commit_message?: string;
  files?: ProposedFile[];
  pr_title?: string;
  pr_body?: string;
};

export function ApprovalCard_CodePR({
  row,
  onApprove,
  onReject,
  busy,
}: {
  row: PendingActionRow;
  onApprove: (id: number) => void;
  onReject: (id: number) => void;
  busy: boolean;
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const payload = (row.payload || {}) as CodePRPayload;
  const files = payload.files ?? [];

  function toggle(path: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  }

  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="flex items-center gap-1.5 text-sm font-medium text-white">
            <Bot className="w-4 h-4 text-teal-400" />
            {row.agent_id}
          </span>
          <span className="text-white/30">·</span>
          <code className="text-xs px-2 py-0.5 rounded bg-purple-500/10 text-purple-300">
            code-pr
          </code>
          {row.skill && (
            <>
              <span className="text-white/30">·</span>
              <code className="text-xs px-2 py-0.5 rounded bg-teal-500/10 text-teal-400">
                {row.skill}
              </code>
            </>
          )}
        </div>
        <div className="flex items-center gap-1 text-xs text-white/30 shrink-0">
          <Clock className="w-3 h-3" />
          {new Date(row.proposed_at).toLocaleString()}
        </div>
      </div>

      <h3 className="text-base font-semibold text-white mb-2">
        {payload.pr_title || row.target || "(no title)"}
      </h3>

      <div className="flex items-center gap-2 text-xs text-white/60 mb-3 flex-wrap">
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-white/[0.06] font-mono">
          <GitBranch className="w-3 h-3" />
          {payload.branch_name || "(no branch)"}
        </span>
        <span className="text-white/30">→</span>
        <code className="text-xs px-2 py-0.5 rounded bg-white/[0.06] font-mono">
          {payload.base || "master"}
        </code>
        {payload.commit_message && (
          <>
            <span className="text-white/30">·</span>
            <span className="text-white/50 italic">
              {payload.commit_message}
            </span>
          </>
        )}
      </div>

      {payload.pr_body && (
        <pre className="text-xs whitespace-pre-wrap text-white/70 bg-black/30 border border-white/[0.06] rounded-lg p-3 mb-4">
          {payload.pr_body}
        </pre>
      )}

      <div className="mb-4">
        <div className="text-xs text-white/30 mb-2">
          Files ({files.length})
        </div>
        <ul className="space-y-1">
          {files.map((f) => {
            const lineCount = (f.content.match(/\n/g) || []).length + 1;
            const isExpanded = expanded.has(f.path);
            return (
              <li
                key={f.path}
                className="border border-white/[0.06] rounded-lg overflow-hidden"
              >
                <button
                  onClick={() => toggle(f.path)}
                  className="w-full text-left px-3 py-2 text-sm flex items-center justify-between hover:bg-white/[0.04] transition-colors"
                >
                  <span className="flex items-center gap-2 text-white/80">
                    {isExpanded ? (
                      <ChevronDown className="w-3.5 h-3.5 text-white/40" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5 text-white/40" />
                    )}
                    <FileText className="w-3.5 h-3.5 text-white/40" />
                    <code className="font-mono text-xs">{f.path}</code>
                  </span>
                  <span className="text-xs text-white/30">{lineCount} lines</span>
                </button>
                {isExpanded && (
                  <pre className="text-xs font-mono bg-black/40 border-t border-white/[0.06] p-3 overflow-auto whitespace-pre text-white/70">
                    {f.content}
                  </pre>
                )}
              </li>
            );
          })}
        </ul>
      </div>

      {row.rationale && (
        <div className="text-sm text-white/50 mb-3">
          <span className="text-white/30">Rationale: </span>
          {row.rationale}
        </div>
      )}

      <div className="text-xs text-white/30 mb-3">
        Expires {new Date(row.expires_at).toLocaleString()}
      </div>

      <div className="flex gap-2">
        <button
          onClick={() => onApprove(row.id)}
          disabled={busy}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-teal-500/10 hover:bg-teal-500/20 disabled:bg-white/[0.04] text-teal-400 disabled:text-white/20 text-sm transition-colors"
        >
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
          Approve and open PR
        </button>
        <button
          onClick={() => onReject(row.id)}
          disabled={busy}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.06] hover:bg-white/[0.1] disabled:bg-white/[0.02] text-white/60 disabled:text-white/20 text-sm transition-colors"
        >
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <X className="w-3.5 h-3.5" />}
          Reject
        </button>
      </div>
    </div>
  );
}
