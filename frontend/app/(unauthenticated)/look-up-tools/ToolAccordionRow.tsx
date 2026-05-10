// app/(unauthenticated)/tools/ToolAccordionRow.tsx
"use client";

import { useState, useCallback, useEffect } from "react";
import { ChevronDown, Loader2, ArrowRight } from "lucide-react";

import TurnstileWidget from "../TurnstileWidget";
import ToolResultView from "./ToolResultView";
import type { ToolConfig } from "./tools-config";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:5000/api";
const TURNSTILE_ENABLED = !!process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;

type Props = {
  tool: ToolConfig;
  /** Whether this row is currently the open one. */
  isOpen: boolean;
  /** Called when this row's header is clicked. */
  onToggle: () => void;
};

export default function ToolAccordionRow({ tool, isOpen, onToggle }: Props) {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const [widgetKey, setWidgetKey] = useState(0);

  // When the row is collapsed, clear the result so reopening starts clean.
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
      setTurnstileToken(null);
      setWidgetKey((k) => k + 1);
    }
  }, [canRun, input, tool.endpoint, tool.inputField, turnstileToken]);

  const Icon = tool.icon;

  return (
    <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] overflow-hidden">
      {/* Header — click to toggle */}
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={isOpen}
        className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-white/[0.03] transition-colors"
      >
        <span className={`shrink-0 w-9 h-9 rounded-lg bg-white/[0.04] flex items-center justify-center ${tool.iconColor}`}>
          <Icon className="w-5 h-5" />
        </span>
        <span className="flex-1 min-w-0">
          <span className="block text-sm font-semibold text-white">{tool.name}</span>
          <span className="block text-xs text-white/50 mt-0.5 truncate">{tool.description}</span>
        </span>
        <ChevronDown
          className={`shrink-0 w-4 h-4 text-white/40 transition-transform ${isOpen ? "rotate-180" : ""}`}
        />
      </button>

      {/* Body — only mounted when open */}
      {isOpen && (
        <div className="px-5 pb-5 pt-1 space-y-3 border-t border-white/[0.06]">
          <div className="flex gap-2 pt-3">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onRun()}
              placeholder={tool.placeholder}
              disabled={loading}
              className="flex-1 rounded-lg border border-white/[0.08] bg-white/[0.02] px-3 py-2 text-sm text-white placeholder:text-white/30 outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 transition-all font-mono disabled:opacity-50"
            />
            <button
              type="button"
              onClick={onRun}
              disabled={!canRun}
              className={`shrink-0 rounded-lg px-4 py-2 text-sm font-semibold transition-all ${
                !canRun
                  ? "bg-white/[0.04] text-white/40 cursor-not-allowed"
                  : "bg-teal-600 text-white hover:bg-teal-500"
              }`}
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
            </button>
          </div>

          {TURNSTILE_ENABLED && (
            <TurnstileWidget
              key={widgetKey}
              onVerify={setTurnstileToken}
              onExpire={() => setTurnstileToken(null)}
              onError={() => setTurnstileToken(null)}
            />
          )}

          {error && (
            <div className="rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3 py-2 text-sm text-red-300">
              {error}
            </div>
          )}

          {result && (
            <div className="pt-1">
              <ToolResultView data={result} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
