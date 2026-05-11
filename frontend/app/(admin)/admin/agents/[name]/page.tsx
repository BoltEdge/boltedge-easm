"use client";
import { use, useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { AgentDetail, getAgent, runAgent } from "../../../../lib/api";
import { ArrowLeft, Play, Loader2, Shield, Cpu, DollarSign, Wrench } from "lucide-react";

export default function AgentDetailPage({
  params,
}: {
  params: Promise<{ name: string }>;
}) {
  const { name } = use(params);
  const [agent, setAgent] = useState<AgentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [prompt, setPrompt] = useState("");
  const [running, setRunning] = useState(false);
  const [lastResult, setLastResult] = useState<unknown>(null);

  const reload = useCallback(async () => {
    try {
      setAgent(await getAgent(name));
    } catch (e: any) {
      setError(e?.message || String(e));
    }
  }, [name]);

  useEffect(() => {
    reload();
  }, [reload]);

  async function onRun() {
    if (!prompt.trim()) return;
    setRunning(true);
    setLastResult(null);
    try {
      const r = await runAgent(name, prompt);
      setLastResult(r);
      setPrompt("");
      await reload();
    } catch (e: any) {
      setLastResult({ error: e?.message || String(e) });
    } finally {
      setRunning(false);
    }
  }

  if (error) return <div className="text-red-400 text-sm">{error}</div>;
  if (!agent) return <div className="text-white/40 text-sm">Loading…</div>;

  const STATUS_COLORS: Record<string, string> = {
    completed: "text-emerald-400",
    failed: "text-red-400",
    running: "text-teal-400",
    pending: "text-white/40",
  };

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
      <div className="flex items-start justify-between mb-8">
        <div>
          <h1 className="text-xl font-semibold text-white">{agent.display_name}</h1>
          <code className="text-xs text-white/30">{agent.name}</code>
        </div>
        <div className="flex gap-2 flex-wrap justify-end">
          <span
            className={`text-xs px-2.5 py-1 rounded-full ${
              agent.external_writes
                ? "bg-amber-500/10 text-amber-400"
                : "bg-white/[0.06] text-white/40"
            }`}
          >
            {agent.external_writes ? "external writes" : "read-only"}
          </span>
        </div>
      </div>

      {/* Meta strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-8">
        <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
          <div className="flex items-center gap-1.5 text-xs text-white/40 mb-1">
            <Cpu className="w-3.5 h-3.5" />Model
          </div>
          <div className="text-sm text-white font-mono">{agent.default_model}</div>
        </div>
        <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
          <div className="flex items-center gap-1.5 text-xs text-white/40 mb-1">
            <DollarSign className="w-3.5 h-3.5" />Cost cap / month
          </div>
          <div className="text-sm text-white">${agent.cost_cap_monthly_usd}</div>
        </div>
        <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
          <div className="flex items-center gap-1.5 text-xs text-white/40 mb-1">
            <Shield className="w-3.5 h-3.5" />Allowed tools
          </div>
          <div className="text-sm text-white">{agent.allowed_tools.length}</div>
        </div>
      </div>

      {/* Allowed tools list */}
      {agent.allowed_tools.length > 0 && (
        <section className="mb-8">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-white/30 mb-3 flex items-center gap-1.5">
            <Wrench className="w-3.5 h-3.5" />Allowed Tools
          </h2>
          <div className="flex flex-wrap gap-1.5">
            {agent.allowed_tools.map((t) => (
              <code
                key={t}
                className="text-xs px-2 py-0.5 rounded bg-white/[0.06] text-white/60"
              >
                {t}
              </code>
            ))}
          </div>
        </section>
      )}

      {/* System prompt */}
      <section className="mb-8">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-white/30 mb-3">
          System Prompt
        </h2>
        <pre className="whitespace-pre-wrap rounded-lg border border-white/[0.06] bg-white/[0.02] p-4 text-sm text-white/70 font-mono leading-relaxed">
          {agent.system_prompt}
        </pre>
      </section>

      {/* Run now */}
      <section className="mb-8">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-white/30 mb-3">
          Run Now
        </h2>
        <textarea
          className="w-full rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-sm text-white font-mono leading-relaxed focus:outline-none focus:border-teal-500/40 resize-none"
          rows={4}
          placeholder={`Enter a prompt for ${agent.display_name}…`}
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
        />
        <button
          onClick={onRun}
          disabled={running || !prompt.trim()}
          className="mt-2 flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-500/10 hover:bg-teal-500/20 disabled:bg-white/[0.04] text-teal-400 disabled:text-white/20 text-sm transition-colors"
        >
          {running ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Play className="w-4 h-4" />
          )}
          {running ? "Running…" : "Run"}
        </button>
        {lastResult !== null && (
          <pre className="mt-3 whitespace-pre-wrap rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-sm text-white/70 font-mono overflow-auto">
            {JSON.stringify(lastResult, null, 2)}
          </pre>
        )}
      </section>

      {/* Recent runs */}
      <section className="mb-8">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-white/30 mb-3">
          Recent Runs
        </h2>
        {agent.runs.length === 0 ? (
          <p className="text-white/40 text-sm">No runs yet.</p>
        ) : (
          <div className="rounded-lg border border-white/[0.06] overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/[0.06]">
                  <th className="text-left text-xs text-white/30 font-medium px-4 py-2.5">When</th>
                  <th className="text-left text-xs text-white/30 font-medium px-4 py-2.5">Skill</th>
                  <th className="text-left text-xs text-white/30 font-medium px-4 py-2.5">Status</th>
                  <th className="text-left text-xs text-white/30 font-medium px-4 py-2.5">Cost</th>
                  <th className="text-left text-xs text-white/30 font-medium px-4 py-2.5">Duration</th>
                </tr>
              </thead>
              <tbody>
                {agent.runs.map((r) => (
                  <tr key={r.id} className="border-t border-white/[0.04] hover:bg-white/[0.02]">
                    <td className="px-4 py-2.5 text-white/60">
                      {new Date(r.started_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-2.5 text-white/60">
                      {r.skill ? <code className="text-xs">{r.skill}</code> : "—"}
                    </td>
                    <td className={`px-4 py-2.5 font-medium ${STATUS_COLORS[r.status] ?? "text-white/60"}`}>
                      {r.status}
                    </td>
                    <td className="px-4 py-2.5 text-white/60">
                      {r.cost_usd != null ? `$${r.cost_usd.toFixed(4)}` : "—"}
                    </td>
                    <td className="px-4 py-2.5 text-white/60">
                      {r.duration_ms != null ? `${r.duration_ms}ms` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Threads */}
      {agent.threads.length > 0 && (
        <section>
          <h2 className="text-xs font-semibold uppercase tracking-wider text-white/30 mb-3">
            Threads
          </h2>
          <div className="rounded-lg border border-white/[0.06] overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/[0.06]">
                  <th className="text-left text-xs text-white/30 font-medium px-4 py-2.5">Title</th>
                  <th className="text-left text-xs text-white/30 font-medium px-4 py-2.5">Created</th>
                  <th className="text-left text-xs text-white/30 font-medium px-4 py-2.5">Messages</th>
                </tr>
              </thead>
              <tbody>
                {agent.threads.map((t) => (
                  <tr key={t.id} className="border-t border-white/[0.04] hover:bg-white/[0.02]">
                    <td className="px-4 py-2.5 text-white/60">{t.title || <span className="italic text-white/30">Untitled</span>}</td>
                    <td className="px-4 py-2.5 text-white/60">{new Date(t.created_at).toLocaleString()}</td>
                    <td className="px-4 py-2.5 text-white/60">{t.message_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
