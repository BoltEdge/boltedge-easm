"use client";
import { ApprovalHistoryRow as Row } from "../../../../lib/api";

function statusBadge(decision: string) {
  if (decision === "rejected")
    return (
      <span className="text-red-300 text-xs w-[80px] inline-block">
        ✗ rejected
      </span>
    );
  if (decision === "expired")
    return (
      <span className="text-white/40 text-xs w-[80px] inline-block">
        ⏰ expired
      </span>
    );
  return (
    <span className="text-teal-300 text-xs w-[80px] inline-block">
      ✓ approved
    </span>
  );
}

function relativeTime(iso: string | null): string {
  if (!iso) return "—";
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

export function ApprovalHistoryRow({ row }: { row: Row }) {
  return (
    <div className="py-2 px-3 border-b border-white/[0.04] text-xs">
      <div className="flex items-center gap-2">
        {statusBadge(row.decision)}
        <span className="flex-1 font-mono text-white/70 truncate">
          {row.agent_id} · {row.action_type} · {row.target ?? "—"}
        </span>
        <span className="text-white/40">{relativeTime(row.decided_at)}</span>
      </div>
      {row.decision === "rejected" && row.decision_note && (
        <div className="mt-1 ml-[80px] text-[11px] text-red-300/80 italic">
          &quot;{row.decision_note}&quot;
        </div>
      )}
    </div>
  );
}
