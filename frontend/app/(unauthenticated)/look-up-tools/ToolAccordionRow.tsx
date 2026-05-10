// app/(unauthenticated)/look-up-tools/ToolAccordionRow.tsx
// One tool tile in the /look-up-tools grid. Visually mirrors the cards on
// /coverage (icon in tinted square, accent name + description, "Run check"
// hint). Click expands the card in place to show input + run + result.
//
// Cloudflare Turnstile is page-level (rendered by the parent ToolsAccordion)
// — this component receives the current token via prop and notifies the
// parent after consumption so the global widget can remount for a fresh
// token.
"use client";

import { useState, useCallback, useEffect } from "react";
import Link from "next/link";
import { Loader2, ArrowRight, Lock, LogIn } from "lucide-react";

import ToolResultView from "./ToolResultView";
import type { ToolConfig } from "./tools-config";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:5000/api";
const TURNSTILE_ENABLED = !!process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;

type Props = {
  tool: ToolConfig;
  isOpen: boolean;
  onToggle: () => void;
  /** Current page-level Turnstile token (or null if not yet issued). */
  turnstileToken: string | null;
  /** Tell the parent the token was consumed so it can remount the widget. */
  onTokenConsumed: () => void;
};

export default function ToolAccordionRow({
  tool,
  isOpen,
  onToggle,
  turnstileToken,
  onTokenConsumed,
}: Props) {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // Collapsing the card clears state so reopening starts clean.
  useEffect(() => {
    if (!isOpen) {
      setResult(null);
      setError(null);
    }
  }, [isOpen]);

  const canRun =
    input.trim().length > 0 &&
    !loading &&
    (!TURNSTILE_ENABLED || !!turnstileToken);

  const onRun = useCallback(async () => {
    if (!canRun) return;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const body: Record<string, string> = { [tool.inputField]: input.trim() };
      if (turnstileToken) body.turnstileToken = turnstileToken;
      const res = await fetch(`${API_BASE}/tools/public/${tool.endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || `Request failed (${res.status})`);
      } else {
        setResult(data);
      }
    } catch {
      setError("Request failed. Please try again.");
    } finally {
      setLoading(false);
      onTokenConsumed();
    }
  }, [canRun, input, tool.endpoint, tool.inputField, turnstileToken, onTokenConsumed]);

  const Icon = tool.icon;

  return (
    <div
      className={`group rounded-xl border ${tool.ring} ${tool.tint} transition-all ${isOpen ? "ring-1 ring-white/[0.06]" : "hover:bg-white/[0.04]"}`}
    >
      {/* Header — clickable area; whole card surface acts as toggle when collapsed */}
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={isOpen}
        className="w-full text-left p-6"
      >
        <div className={`w-11 h-11 rounded-lg flex items-center justify-center ${tool.tint} border ${tool.ring} mb-4`}>
          <Icon className={`w-5 h-5 ${tool.iconColor}`} />
        </div>
        <h3 className={`text-base font-semibold ${tool.iconColor} mb-2 flex items-center gap-1.5`}>
          {tool.name}
          {tool.authOnly && <Lock className="w-3 h-3 opacity-60" />}
        </h3>
        <p className="text-sm text-white/55 leading-relaxed">{tool.description}</p>
        {!isOpen && (
          <div className={`mt-4 text-xs font-medium ${tool.iconColor} opacity-60 group-hover:opacity-100 transition-opacity`}>
            {tool.authOnly ? "Sign in to use →" : "Run check →"}
          </div>
        )}
      </button>

      {/* Body — only mounted when open */}
      {isOpen && tool.authOnly && (
        <div className="px-6 pb-6 -mt-1 space-y-3">
          <div className="rounded-lg border border-white/[0.08] bg-white/[0.02] p-4 text-center space-y-3">
            <p className="text-sm text-white/70">
              {tool.shortName} is available to signed-in users.
            </p>
            <div className="flex items-center justify-center gap-2">
              <Link
                href="/register"
                className={`inline-flex items-center gap-1.5 rounded-lg px-4 py-2 text-xs font-semibold ${tool.tint} ${tool.iconColor} border ${tool.ring} hover:bg-white/[0.08] transition-colors`}
              >
                <LogIn className="w-3.5 h-3.5" />
                Sign up free
              </Link>
              <Link
                href="/login"
                className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-4 py-2 text-xs font-medium text-white/70 hover:text-white hover:bg-white/[0.06] transition-colors"
              >
                Sign in
              </Link>
            </div>
          </div>
          <button
            type="button"
            onClick={onToggle}
            className="text-xs text-white/40 hover:text-white/70 transition-colors"
          >
            Close
          </button>
        </div>
      )}
      {isOpen && !tool.authOnly && (
        <div className="px-6 pb-6 -mt-1 space-y-3">
          <div className="flex gap-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onRun()}
              placeholder={tool.placeholder}
              disabled={loading}
              autoFocus
              className="flex-1 min-w-0 rounded-lg border border-white/[0.08] bg-white/[0.02] px-3 py-2 text-sm text-white placeholder:text-white/30 outline-none focus:border-white/20 focus:ring-2 focus:ring-white/10 transition-all font-mono disabled:opacity-50"
            />
            <button
              type="button"
              onClick={onRun}
              disabled={!canRun}
              className={`shrink-0 rounded-lg px-4 py-2 text-sm font-semibold transition-all ${
                !canRun
                  ? "bg-white/[0.04] text-white/40 cursor-not-allowed"
                  : `${tool.tint} ${tool.iconColor} border ${tool.ring} hover:bg-white/[0.08]`
              }`}
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
            </button>
          </div>

          {TURNSTILE_ENABLED && !turnstileToken && (
            <p className="text-[11px] text-white/40">
              Waiting for verification — see the badge below the grid.
            </p>
          )}

          {error && (
            <div className="rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3 py-2 text-sm text-red-300">
              {error}
            </div>
          )}

          {result && (
            <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
              <ToolResultView data={result} />
            </div>
          )}

          <button
            type="button"
            onClick={onToggle}
            className="text-xs text-white/40 hover:text-white/70 transition-colors"
          >
            Close
          </button>
        </div>
      )}
    </div>
  );
}
