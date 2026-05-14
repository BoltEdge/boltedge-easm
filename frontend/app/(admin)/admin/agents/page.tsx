"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import {
  AgentSummary,
  AgentSpendRow,
  getAgents,
  getPendingApprovals,
  getAgentSpend,
} from "../../../lib/api";
import { Bot, DollarSign, Cpu, PenLine } from "lucide-react";

function spendBarColor(pct: number): string {
  if (pct >= 90) return "#ef4444"; // red
  if (pct >= 70) return "#f59e0b"; // amber
  return "#14b8a6"; // teal
}

function SpendBar({ row }: { row: AgentSpendRow }) {
  const color = spendBarColor(row.pct);
  return (
    <div className="mt-3">
      <div className="flex items-center justify-between text-[11px] text-white/60">
        <span>
          ${row.spend_usd.toFixed(2)} / ${row.cap_usd.toFixed(0)}
        </span>
        <span>{row.pct.toFixed(1)}%</span>
      </div>
      <div className="h-1 bg-white/[0.06] rounded mt-1 overflow-hidden">
        <div
          className="h-full transition-all"
          style={{
            width: `${Math.min(100, row.pct)}%`,
            backgroundColor: color,
          }}
        />
      </div>
    </div>
  );
}

export default function AgentListPage() {
  const [agents, setAgents] = useState<AgentSummary[] | null>(null);
  const [pendingCount, setPendingCount] = useState<number | null>(null);
  const [spendByAgent, setSpendByAgent] = useState<Record<string, AgentSpendRow>>({});
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [a, p] = await Promise.all([getAgents(), getPendingApprovals()]);
        setAgents(a);
        setPendingCount(p.length);
      } catch (e: any) {
        setError(e?.message || String(e));
      }
    })();
    // Spend is a separate fetch — silent failure is acceptable
    // (spend bars just won't appear; rest of page still renders).
    getAgentSpend()
      .then((d) => {
        const map: Record<string, AgentSpendRow> = {};
        for (const a of d.agents) map[a.agent_id] = a;
        setSpendByAgent(map);
      })
      .catch(() => {
        /* silent */
      });
  }, []);

  if (error) return <div className="text-red-400 text-sm">{error}</div>;
  if (!agents) return <div className="text-white/40 text-sm">Loading…</div>;

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-white">Agents</h1>
          <p className="text-xs text-white/30 mt-0.5">{agents.length} agent{agents.length !== 1 ? "s" : ""} registered</p>
        </div>
        <Link
          href="/admin/agents/approvals"
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-teal-500/10 hover:bg-teal-500/20 text-teal-400 text-sm transition-colors"
        >
          <PenLine className="w-4 h-4" />
          Approvals {pendingCount !== null ? `(${pendingCount})` : ""}
          {pendingCount !== null && pendingCount > 0 && (
            <span className="ml-1 w-2 h-2 rounded-full bg-teal-400 animate-pulse" />
          )}
        </Link>
      </div>

      {agents.length === 0 ? (
        <div className="text-white/40 text-sm">No agents registered.</div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {agents.map((a) => (
            <Link
              key={a.name}
              href={`/admin/agents/${encodeURIComponent(a.name)}`}
              className="block rounded-xl border border-white/[0.06] bg-white/[0.02] hover:bg-white/[0.04] p-5 transition-colors"
            >
              <div className="flex items-start justify-between gap-2 mb-4">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-teal-500/10 flex items-center justify-center shrink-0">
                    <Bot className="w-4 h-4 text-teal-400" />
                  </div>
                  <div>
                    <h2 className="text-sm font-medium text-white leading-tight">{a.display_name}</h2>
                    <code className="text-[10px] text-white/30">{a.name}</code>
                  </div>
                </div>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded-full shrink-0 ${
                    a.external_writes
                      ? "bg-amber-500/10 text-amber-400"
                      : "bg-white/[0.06] text-white/40"
                  }`}
                >
                  {a.external_writes ? "writes" : "read-only"}
                </span>
              </div>
              <dl className="space-y-1.5 text-sm">
                <div className="flex items-center justify-between">
                  <dt className="flex items-center gap-1.5 text-white/40">
                    <Cpu className="w-3.5 h-3.5" />Model
                  </dt>
                  <dd className="text-white/70 font-mono text-xs">{a.default_model}</dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="flex items-center gap-1.5 text-white/40">
                    <DollarSign className="w-3.5 h-3.5" />Cap / month
                  </dt>
                  <dd className="text-white/70">${a.cost_cap_monthly_usd}</dd>
                </div>
              </dl>
              {spendByAgent[a.name] && <SpendBar row={spendByAgent[a.name]} />}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
