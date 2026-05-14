"use client";
import { Bot, Check, Clock, Loader2, X } from "lucide-react";
import type { PendingActionRow } from "../../../../lib/api";

export function ApprovalCard_MemoryWrite({
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
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="flex items-center gap-1.5 text-sm font-medium text-white">
            <Bot className="w-4 h-4 text-teal-400" />
            {row.agent_id}
          </span>
          <span className="text-white/30">·</span>
          <code className={`text-xs px-2 py-0.5 rounded ${
            row.action_type === "memory-delete"
              ? "bg-red-500/10 text-red-300"
              : "bg-white/[0.06] text-white/60"
          }`}>
            {row.action_type}
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

      {row.target && (
        <div className="text-sm text-white/60 mb-1.5">
          <span className="text-white/30">Target: </span>
          <span className="font-mono">{row.target}</span>
        </div>
      )}
      {row.rationale && (
        <div className="text-sm text-white/50 mb-3">
          <span className="text-white/30">Rationale: </span>
          {row.rationale}
        </div>
      )}

      <div className="text-xs text-white/30 mb-3">
        Expires {new Date(row.expires_at).toLocaleString()}
      </div>

      <pre className="text-xs font-mono bg-black/30 border border-white/[0.06] rounded-lg p-3 overflow-auto mb-4 text-white/60">
        {JSON.stringify(row.payload, null, 2)}
      </pre>

      <div className="flex gap-2">
        <button
          onClick={() => onApprove(row.id)}
          disabled={busy}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-teal-500/10 hover:bg-teal-500/20 disabled:bg-white/[0.04] text-teal-400 disabled:text-white/20 text-sm transition-colors"
        >
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
          {row.action_type === "memory-delete" ? "Approve delete" : "Approve"}
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
