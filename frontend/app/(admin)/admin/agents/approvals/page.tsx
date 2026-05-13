"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import {
  PendingActionRow,
  getPendingApprovals,
  approveAction,
  rejectAction,
} from "../../../../lib/api";
import { ArrowLeft, Check } from "lucide-react";
import { ApprovalCard_MemoryWrite } from "./ApprovalCard_MemoryWrite";
import { ApprovalCard_CodePR } from "./ApprovalCard_CodePR";

type AppliedResult =
  | { pr_url?: string; pr_number?: number; branch?: string }
  | { error?: string }
  | null;

export default function ApprovalsPage() {
  const [items, setItems] = useState<PendingActionRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [lastResult, setLastResult] = useState<{ id: number; result: AppliedResult } | null>(null);

  async function reload() {
    try {
      setItems(await getPendingApprovals());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
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
    setLastResult(null);
    try {
      const resp = await approveAction(id);
      setLastResult({ id: resp.id, result: (resp.applied_result as AppliedResult) ?? null });
      showBanner("ok", `Action #${id} approved.`);
      await reload();
    } catch (e: unknown) {
      showBanner("err", e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  async function onReject(id: number) {
    const note = window.prompt("Reason for rejection (visible to the agent):");
    if (note === null) return;
    setBusy(id);
    try {
      await rejectAction(id, note);
      showBanner("ok", `Action #${id} rejected.`);
      await reload();
    } catch (e: unknown) {
      showBanner("err", e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  if (error) return <div className="text-red-400 text-sm">{error}</div>;
  if (!items) return <div className="text-white/40 text-sm">Loading…</div>;

  const resultPrUrl =
    lastResult?.result && "pr_url" in lastResult.result ? lastResult.result.pr_url : undefined;
  const resultError =
    lastResult?.result && "error" in lastResult.result ? lastResult.result.error : undefined;

  return (
    <div className="max-w-3xl">
      <Link
        href="/admin/agents"
        className="inline-flex items-center gap-1.5 text-sm text-white/40 hover:text-white mb-6 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Agents
      </Link>

      <div className="flex items-baseline gap-3 mb-6">
        <h1 className="text-xl font-semibold text-white">Pending Approvals</h1>
        <span className="text-sm text-white/40">{items.length} pending</span>
      </div>

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

      {lastResult && (
        <div
          className={`mb-4 px-4 py-3 rounded-lg text-sm border ${
            resultError
              ? "bg-red-500/5 border-red-500/20 text-red-300"
              : "bg-teal-500/5 border-teal-500/20 text-teal-300"
          }`}
        >
          <strong className="text-white">Result for #{lastResult.id}:</strong>{" "}
          {resultPrUrl ? (
            <a
              href={resultPrUrl}
              target="_blank"
              rel="noreferrer"
              className="underline hover:text-teal-200"
            >
              PR opened: {resultPrUrl}
            </a>
          ) : resultError ? (
            <span>Failed: {resultError}</span>
          ) : (
            <span>OK</span>
          )}
        </div>
      )}

      {items.length === 0 ? (
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-10 text-center">
          <Check className="w-8 h-8 text-teal-400 mx-auto mb-3" />
          <p className="text-white/40 text-sm">Nothing pending — queue is clear.</p>
        </div>
      ) : (
        <ul className="space-y-3">
          {items.map((row) => (
            <li key={row.id}>
              {row.action_type === "code-pr" ? (
                <ApprovalCard_CodePR
                  row={row}
                  onApprove={onApprove}
                  onReject={onReject}
                  busy={busy === row.id}
                />
              ) : (
                <ApprovalCard_MemoryWrite
                  row={row}
                  onApprove={onApprove}
                  onReject={onReject}
                  busy={busy === row.id}
                />
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
