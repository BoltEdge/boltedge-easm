"use client";
import { useEffect, useState } from "react";
import {
  getAgentProposals,
  AgentProposalsResponse,
} from "../../../../lib/api";

function statusColor(decision: string | null): string {
  if (decision === null) return "#f59e0b"; // amber — pending
  if (decision === "rejected") return "#ef4444"; // red
  return "#14b8a6"; // teal — approved / edited-and-approved
}

function statusLabel(decision: string | null): string {
  if (decision === null) return "⏳";
  if (decision === "rejected") return "✗";
  return "✓";
}

function relativeTime(iso: string): string {
  const t = new Date(iso).getTime();
  const diff = Math.max(0, Date.now() - t);
  const min = Math.floor(diff / 60000);
  if (min < 1) return "just now";
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const d = Math.floor(hr / 24);
  return `${d}d ago`;
}

export function AgentTimeline({
  agentId,
  selectedRunId,
  onSelectRun,
}: {
  agentId: string;
  selectedRunId: number | null;
  onSelectRun: (runId: number) => void;
}) {
  const [data, setData] = useState<AgentProposalsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getAgentProposals(agentId)
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [agentId]);

  if (error)
    return (
      <div className="text-red-400 text-xs px-2 py-3">
        Timeline error: {error}
      </div>
    );
  if (!data)
    return (
      <div className="text-white/30 text-xs px-2 py-3">Loading…</div>
    );

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5 px-1">
        <span className="text-[11px] px-2 py-0.5 rounded bg-amber-500/15 text-amber-300">
          {data.summary.pending} pending
        </span>
        <span className="text-[11px] px-2 py-0.5 rounded bg-teal-500/15 text-teal-300">
          {data.summary.approved} approved
        </span>
        <span className="text-[11px] px-2 py-0.5 rounded bg-red-500/15 text-red-300">
          {data.summary.rejected} rejected
        </span>
      </div>

      <div className="text-[10px] uppercase tracking-wide text-white/30 px-1">
        Proposals · all
      </div>

      {data.proposals.length === 0 && (
        <div className="text-xs text-white/40 px-1 py-3">
          No proposals yet.
        </div>
      )}

      <ul className="space-y-1">
        {data.proposals.map((p) => {
          const isSelected =
            selectedRunId !== null && p.run_id === selectedRunId;
          const isClickable = p.run_id !== null;
          return (
            <li
              key={p.id}
              onClick={() => isClickable && onSelectRun(p.run_id!)}
              className={`px-2 py-2 rounded text-xs ${
                isClickable
                  ? "cursor-pointer hover:bg-white/[0.05]"
                  : "cursor-default"
              } ${isSelected ? "bg-white/[0.08]" : "bg-transparent"}`}
              style={{ borderLeft: `3px solid ${statusColor(p.decision)}` }}
            >
              <div className="flex items-center gap-1.5 text-white/50 text-[10px]">
                <span>{statusLabel(p.decision)}</span>
                <span>{relativeTime(p.proposed_at)}</span>
                {p.run_id !== null && <span>· run #{p.run_id}</span>}
              </div>
              <div className="text-white/80 mt-0.5">{p.action_type}</div>
              <div className="text-white/50 font-mono text-[11px] truncate">
                {p.target ?? "—"}
              </div>
              {p.decision === "rejected" && p.decision_note && (
                <div className="text-red-300/80 text-[11px] mt-1 italic">
                  &quot;{p.decision_note}&quot;
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
