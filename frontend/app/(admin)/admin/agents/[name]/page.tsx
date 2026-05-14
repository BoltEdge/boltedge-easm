"use client";
import { use, useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { AgentDetail, AgentSkillSummary, getAgent, runAgent, runAgentSkill } from "../../../../lib/api";
import { ArrowLeft, Play, Loader2, Shield, Cpu, DollarSign, Wrench, ChevronDown, ChevronRight, Zap, Clock } from "lucide-react";
import { AgentTimeline } from "./AgentTimeline";

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

  // System prompt collapse state — collapsed by default
  const [promptExpanded, setPromptExpanded] = useState(false);

  // Per-skill run state: skill name -> { running, result }
  type SkillState = { running: boolean; result: unknown | null };
  const [skillStates, setSkillStates] = useState<Record<string, SkillState>>({});

  // Thread mode: "new" | "continue"
  const [threadMode, setThreadMode] = useState<"new" | "continue">("new");

  // Selected proposal run from the timeline sidebar.
  // For now this only highlights the entry; thread loading is deferred
  // (existing thread links remain in the Threads section).
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);

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
    if (!prompt.trim() || !agent) return;
    setRunning(true);
    setLastResult(null);
    try {
      const opts: { thread_id?: number } = {};
      if (threadMode === "continue" && agent.threads.length > 0) {
        opts.thread_id = agent.threads[0].id;
      }
      const r = await runAgent(name, prompt, opts);
      setLastResult(r);
      setPrompt("");
      await reload();
    } catch (e: any) {
      setLastResult({ error: e?.message || String(e) });
    } finally {
      setRunning(false);
    }
  }

  async function onRunSkill(skill: AgentSkillSummary) {
    setSkillStates((prev) => ({
      ...prev,
      [skill.name]: { running: true, result: null },
    }));
    try {
      const r = await runAgentSkill(name, skill.name, true);
      setSkillStates((prev) => ({
        ...prev,
        [skill.name]: { running: false, result: r },
      }));
      await reload();
    } catch (e: any) {
      setSkillStates((prev) => ({
        ...prev,
        [skill.name]: { running: false, result: { error: e?.message || String(e) } },
      }));
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

  // System prompt preview: first 300 chars
  const PREVIEW_LENGTH = 300;
  const systemPromptFull = agent.system_prompt;
  const isLongPrompt = systemPromptFull.length > PREVIEW_LENGTH;
  const systemPromptPreview = isLongPrompt
    ? systemPromptFull.slice(0, PREVIEW_LENGTH) + "…"
    : systemPromptFull;

  const hasThreads = agent.threads.length > 0;
  const lastThread = hasThreads ? agent.threads[0] : null;

  return (
    <div className="flex gap-6">
      {/* Left sidebar: proposal timeline */}
      <aside className="w-[260px] flex-shrink-0 hidden lg:block border-r border-white/[0.06] pr-4 sticky top-0 self-start max-h-screen overflow-y-auto py-2">
        <AgentTimeline
          agentId={name}
          selectedRunId={selectedRunId}
          onSelectRun={setSelectedRunId}
        />
      </aside>

      {/* Right pane: existing page content */}
      <div className="max-w-3xl flex-1 min-w-0">
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

      {/* System prompt — collapsible */}
      <section className="mb-8">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-white/30">
            System Prompt
          </h2>
          {isLongPrompt && (
            <button
              onClick={() => setPromptExpanded((v) => !v)}
              className="flex items-center gap-1 text-xs text-teal-400/70 hover:text-teal-400 transition-colors"
            >
              {promptExpanded ? (
                <>
                  <ChevronDown className="w-3 h-3" />
                  Hide prompt
                </>
              ) : (
                <>
                  <ChevronRight className="w-3 h-3" />
                  Show full prompt
                </>
              )}
            </button>
          )}
        </div>
        <pre className="whitespace-pre-wrap rounded-lg border border-white/[0.06] bg-white/[0.02] p-4 text-sm text-white/70 font-mono leading-relaxed">
          {promptExpanded || !isLongPrompt ? systemPromptFull : systemPromptPreview}
        </pre>
      </section>

      {/* Skills */}
      <section className="mb-8">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-white/30 mb-3 flex items-center gap-1.5">
          <Zap className="w-3.5 h-3.5" />Skills
        </h2>
        {agent.skills.length === 0 ? (
          <p className="text-white/40 text-sm">No skills registered for this agent.</p>
        ) : (
          <div className="flex flex-col gap-3">
            {agent.skills.map((skill) => {
              const ss = skillStates[skill.name] ?? { running: false, result: null };
              return (
                <div
                  key={skill.name}
                  className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-4"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-medium text-white">
                          {skill.display_name}
                        </span>
                        <code className="text-xs text-white/30">{skill.name}</code>
                      </div>
                      {skill.schedule && (
                        <div className="flex items-center gap-1 text-xs text-white/40 mb-1.5">
                          <Clock className="w-3 h-3" />
                          Scheduled: {skill.schedule}
                        </div>
                      )}
                      <p className="text-xs text-white/50 leading-relaxed">
                        {skill.description}
                      </p>
                    </div>
                    <button
                      onClick={() => onRunSkill(skill)}
                      disabled={ss.running}
                      className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-teal-500/10 hover:bg-teal-500/20 disabled:bg-white/[0.04] text-teal-400 disabled:text-white/20 text-xs transition-colors"
                    >
                      {ss.running ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Play className="w-3.5 h-3.5" />
                      )}
                      {ss.running ? "Running…" : "Run now"}
                    </button>
                  </div>
                  {ss.result !== null && (
                    <div className="mt-3 pt-3 border-t border-white/[0.06]">
                      {(() => {
                        const r = ss.result as any;
                        if (r?.error) {
                          return (
                            <p className="text-xs text-red-400 font-mono">{r.error}</p>
                          );
                        }
                        return (
                          <div className="flex flex-wrap gap-4 text-xs text-white/60">
                            <span>
                              Status:{" "}
                              <span
                                className={
                                  r?.status === "success" || r?.status === "completed"
                                    ? "text-emerald-400"
                                    : r?.status === "failed"
                                    ? "text-red-400"
                                    : "text-teal-400"
                                }
                              >
                                {r?.status ?? "—"}
                              </span>
                            </span>
                            {r?.cost_usd != null && (
                              <span>Cost: ${Number(r.cost_usd).toFixed(4)}</span>
                            )}
                            {r?.run_id != null && (
                              <span>Run #{r.run_id}</span>
                            )}
                          </div>
                        );
                      })()}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Run now */}
      <section className="mb-8">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-white/30 mb-3">
          Run Now
        </h2>

        {/* Thread mode toggle */}
        <div className="flex items-center gap-4 mb-3">
          <label className="flex items-center gap-2 cursor-pointer text-sm">
            <input
              type="radio"
              name="thread-mode"
              value="new"
              checked={threadMode === "new"}
              onChange={() => setThreadMode("new")}
              className="accent-teal-400"
            />
            <span className={threadMode === "new" ? "text-white/80" : "text-white/40"}>
              Start new thread
            </span>
          </label>
          <label
            className={`flex items-center gap-2 text-sm ${hasThreads ? "cursor-pointer" : "cursor-not-allowed opacity-40"}`}
          >
            <input
              type="radio"
              name="thread-mode"
              value="continue"
              checked={threadMode === "continue"}
              onChange={() => setThreadMode("continue")}
              disabled={!hasThreads}
              className="accent-teal-400"
            />
            <span className={threadMode === "continue" ? "text-white/80" : "text-white/40"}>
              Continue last thread
              {lastThread && (
                <span className="ml-1 text-xs text-white/30">
                  ({lastThread.title ?? `#${lastThread.id}`})
                </span>
              )}
            </span>
          </label>
        </div>

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
                    <td className="px-4 py-2.5">
                      <Link
                        href={`/admin/agents/threads/${t.id}`}
                        className="text-teal-400 hover:text-teal-300 transition-colors"
                      >
                        {t.title || <span className="italic text-white/30">Untitled</span>}
                      </Link>
                    </td>
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
    </div>
  );
}
