"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import {
  PendingActionRow,
  getPendingApprovals,
  approveAction,
  rejectAction,
} from "../../../../lib/api";
import { ArrowLeft, Check, X, Loader2, Clock, Bot } from "lucide-react";

export default function ApprovalsPage() {
  const [items, setItems] = useState<PendingActionRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  async function reload() {
    try {
      setItems(await getPendingApprovals());
    } catch (e: any) {
      setError(e?.message || String(e));
    }
  }

  useEffect(() => {
    reload();
  }, []);

  function showBanner(kind: "ok" | "err", text: string) {
    setBanner({ kind, text });
    setTimeout(() => setBanner(null), 3000);
  }

  async function onApprove(id: number) {
    setBusy(id);
    try {
      await approveAction(id);
      showBanner("ok", `Action #${id} approved.`);
      await reload();
    } catch (e: any) {
      showBanner("err", e?.message || String(e));
    } finally {
      setBusy(null);
    }
  }

  async function onReject(id: number) {
    // Using a simple browser prompt here keeps the implementation
    // self-contained; a modal would add more complexity than the
    // approvals flow warrants for an internal admin tool.
    const note = window.prompt("Reason for rejection (visible to the agent):");
    if (note === null) return; // cancelled
    setBusy(id);
    try {
      await rejectAction(id, note);
      showBanner("ok", `Action #${id} rejected.`);
      await reload();
    } catch (e: any) {
      showBanner("err", e?.message || String(e));
    } finally {
      setBusy(null);
    }
  }

  if (error) return <div className="text-red-400 text-sm">{error}</div>;
  if (!items) return <div className="text-white/40 text-sm">Loading…</div>;

  return (
    <div className="max-w-3xl">
      {/* Back link */}
      <Link
        href="/admin/agents"
        className="inline-flex items-center gap-1.5 text-sm text-white/40 hover:text-white mb-6 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Agents
      </Link>

      {/* Header */}
      <div className="flex items-baseline gap-3 mb-6">
        <h1 className="text-xl font-semibold text-white">Pending Approvals</h1>
        <span className="text-sm text-white/40">{items.length} pending</span>
      </div>

      {/* Banner */}
      {banner && (
        <div
          className={`mb-4 px-4 py-2.5 rounded-lg text-sm ${
            banner.kind === "ok"
              ? "bg-emerald-500/10 text-emerald-400"
              : "bg-red-500/10 text-red-400"
          }`}
        >
          {banner.text}
        </div>
      )}

      {items.length === 0 ? (
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-10 text-center">
          <Check className="w-8 h-8 text-teal-400 mx-auto mb-3" />
          <p className="text-white/40 text-sm">Nothing pending — queue is clear.</p>
        </div>
      ) : (
        <ul className="space-y-3">
          {items.map((p) => (
            <li
              key={p.id}
              className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5"
            >
              {/* Top row */}
              <div className="flex items-start justify-between gap-3 mb-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="flex items-center gap-1.5 text-sm font-medium text-white">
                    <Bot className="w-4 h-4 text-teal-400" />
                    {p.agent_id}
                  </span>
                  <span className="text-white/30">·</span>
                  <code className="text-xs px-2 py-0.5 rounded bg-white/[0.06] text-white/60">
                    {p.action_type}
                  </code>
                  {p.skill && (
                    <>
                      <span className="text-white/30">·</span>
                      <code className="text-xs px-2 py-0.5 rounded bg-teal-500/10 text-teal-400">
                        {p.skill}
                      </code>
                    </>
                  )}
                </div>
                <div className="flex items-center gap-1 text-xs text-white/30 shrink-0">
                  <Clock className="w-3 h-3" />
                  {new Date(p.proposed_at).toLocaleString()}
                </div>
              </div>

              {/* Target + rationale */}
              {p.target && (
                <div className="text-sm text-white/60 mb-1.5">
                  <span className="text-white/30">Target: </span>
                  <span className="font-mono">{p.target}</span>
                </div>
              )}
              {p.rationale && (
                <div className="text-sm text-white/50 mb-3">
                  <span className="text-white/30">Rationale: </span>
                  {p.rationale}
                </div>
              )}

              {/* Expiry */}
              <div className="text-xs text-white/30 mb-3">
                Expires {new Date(p.expires_at).toLocaleString()}
              </div>

              {/* Payload */}
              <pre className="text-xs font-mono bg-black/30 border border-white/[0.06] rounded-lg p-3 overflow-auto mb-4 text-white/60">
                {JSON.stringify(p.payload, null, 2)}
              </pre>

              {/* Actions */}
              <div className="flex gap-2">
                <button
                  onClick={() => onApprove(p.id)}
                  disabled={busy === p.id}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-teal-500/10 hover:bg-teal-500/20 disabled:bg-white/[0.04] text-teal-400 disabled:text-white/20 text-sm transition-colors"
                >
                  {busy === p.id ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Check className="w-3.5 h-3.5" />
                  )}
                  Approve
                </button>
                <button
                  onClick={() => onReject(p.id)}
                  disabled={busy === p.id}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.06] hover:bg-white/[0.1] disabled:bg-white/[0.02] text-white/60 disabled:text-white/20 text-sm transition-colors"
                >
                  {busy === p.id ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <X className="w-3.5 h-3.5" />
                  )}
                  Reject
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
