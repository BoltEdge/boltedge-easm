// app/(unauthenticated)/QuickToolsCard.tsx
"use client";

import React, { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import {
  Lock, Globe, Shield, FileText, RefreshCcw, Plug,
  ArrowRight, Loader2, Server,
  LogIn,
} from "lucide-react";

import TurnstileWidget from "./TurnstileWidget";
import ToolResultView from "./look-up-tools/ToolResultView";

const TURNSTILE_ENABLED = !!process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";

function cn(...c: Array<string | false | null | undefined>) {
  return c.filter(Boolean).join(" ");
}

type ToolId = "cert-lookup" | "dns-lookup" | "header-check" | "whois" | "reverse-dns" | "connectivity-check";

interface ToolDef {
  id: ToolId;
  name: string;
  icon: React.ComponentType<{ className?: string }>;
  placeholder: string;
  inputField: string;
  color: string;
  authOnly?: boolean;
  authTeaser?: string;
}

const TOOLS: ToolDef[] = [
  { id: "cert-lookup", name: "Certificate", icon: Lock, placeholder: "example.com or SHA-256 hash", inputField: "__smart", color: "text-emerald-400" },
  { id: "dns-lookup", name: "DNS", icon: Globe, placeholder: "example.com", inputField: "domain", color: "text-cyan-400" },
  { id: "header-check", name: "Headers", icon: Shield, placeholder: "example.com", inputField: "domain", color: "text-amber-400" },
  { id: "whois", name: "WHOIS", icon: FileText, placeholder: "example.com / 8.8.8.8 / AS13335", inputField: "query", color: "text-rose-400" },
  { id: "reverse-dns", name: "Reverse DNS", icon: RefreshCcw, placeholder: "8.8.8.8", inputField: "ip", color: "text-purple-400" },
  { id: "connectivity-check", name: "Connectivity", icon: Plug, placeholder: "example.com:443", inputField: "host", color: "text-sky-400", authOnly: true, authTeaser: "Test TCP port reachability, latency, banner grabs, and TLS detection" },
];

function AuthOnlyTeaser({ tool }: { tool: ToolDef }) {
  const Icon = tool.icon;
  return (
    <div className="flex flex-col items-center justify-center py-6 space-y-3">
      <div className="h-10 w-10 rounded-xl bg-sky-500/10 flex items-center justify-center">
        <Icon className="w-5 h-5 text-sky-400" />
      </div>
      <div className="text-center">
        <p className="text-sm text-foreground/70 mb-1">{tool.name} requires sign-in</p>
        {tool.authTeaser && <p className="text-xs text-muted-foreground/40">{tool.authTeaser}</p>}
      </div>
      <Link href="/register" className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-gradient-to-r from-teal-500 to-cyan-500 text-white shadow-lg shadow-teal-500/20 hover:shadow-teal-500/30 hover:brightness-110 transition-all">
        <LogIn className="w-3.5 h-3.5" />Sign up free
      </Link>
    </div>
  );
}

type QuickToolsCardProps = {
  /** Notifies the parent when the card has results to show, so the page can
   *  expand the card to full width and tuck away the sibling tool cards. */
  onActiveChange?: (active: boolean) => void;
};

export default function QuickToolsCard({ onActiveChange }: QuickToolsCardProps = {}) {
  const [activeTool, setActiveTool] = useState<ToolId>("cert-lookup");
  const [inputValue, setInputValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const [widgetKey, setWidgetKey] = useState(0);

  const tool = TOOLS.find((t) => t.id === activeTool)!;

  useEffect(() => {
    onActiveChange?.(result !== null);
  }, [result, onActiveChange]);

  const handleToolSwitch = useCallback((id: ToolId) => { setActiveTool(id); setInputValue(""); setResult(null); }, []);

  const handleSubmit = useCallback(async () => {
    const val = inputValue.trim();
    if (!val || tool.authOnly) return;
    if (TURNSTILE_ENABLED && !turnstileToken) return;
    setLoading(true); setResult(null);
    try {
      let endpoint: string; let body: Record<string, string>;
      if (activeTool === "cert-lookup") {
        const cleaned = val.replace(/[:\s]/g, "").toLowerCase();
        const isHash = /^[0-9a-f]{64}$/.test(cleaned);
        if (isHash) { endpoint = `${API_BASE}/tools/public/cert-hash`; body = { hash: cleaned }; }
        else { endpoint = `${API_BASE}/tools/public/cert-lookup`; body = { domain: val }; }
      } else { endpoint = `${API_BASE}/tools/public/${activeTool}`; body = { [tool.inputField]: val }; }
      if (turnstileToken) body.turnstileToken = turnstileToken;
      const res = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const data = await res.json();
      if (!res.ok && data.error) setResult({ error: data.error }); else setResult(data);
    } catch { setResult({ error: "Request failed. Please try again." }); }
    finally {
      setLoading(false);
      setTurnstileToken(null);
      setWidgetKey((k) => k + 1);
    }
  }, [inputValue, activeTool, tool, turnstileToken]);

  const emptyHint = (() => {
    if (tool.authOnly) return "";
    switch (tool.inputField) { case "__smart": return "Enter a domain or SHA-256 hash"; case "query": return "Enter a domain, IP, or ASN"; default: return `Enter a ${tool.inputField}`; }
  })();

  return (
    <div className="rounded-2xl border border-border bg-card/40 backdrop-blur overflow-hidden h-full flex flex-col shadow-[0_0_80px_rgba(20,184,166,0.08)]">
      {/* Header */}
      <div className="px-6 pt-6 pb-4">
        <div className="flex items-center gap-2 mb-1"><Server className="w-5 h-5 text-teal-400" /><h3 className="text-sm font-semibold text-foreground">LookUp Tools</h3></div>
        <p className="text-xs text-muted-foreground">Quick-check any domain or IP — no account needed</p>
      </div>

      {/* Tool selector pills */}
      <div className="px-6 pb-4 flex flex-wrap gap-1.5">
        {TOOLS.map((t) => {
          const Icon = t.icon;
          return (
            <button key={t.id} onClick={() => handleToolSwitch(t.id)}
              className={cn("inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-all border",
                activeTool === t.id ? "border-teal-500/30 bg-teal-500/10 text-teal-300" : "border-border bg-card/30 text-muted-foreground hover:text-foreground hover:border-border")}>
              <Icon className="w-3.5 h-3.5" />{t.name}{t.authOnly && <Lock className="w-2.5 h-2.5 ml-0.5 opacity-50" />}
            </button>
          );
        })}
      </div>

      {/* Input — hidden for auth-only tools */}
      {!tool.authOnly && (
        <div className="px-6 pb-4 space-y-3">
          <div className="flex gap-2">
            <input type="text" value={inputValue} onChange={(e) => setInputValue(e.target.value)} onKeyDown={(e) => e.key === "Enter" && !loading && handleSubmit()}
              placeholder={tool.placeholder} disabled={loading}
              className="flex-1 rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40 font-mono" />
            <button onClick={handleSubmit} disabled={loading || !inputValue.trim() || (TURNSTILE_ENABLED && !turnstileToken)}
              className={cn("rounded-lg px-4 py-2 text-sm font-medium transition-all shrink-0",
                loading || !inputValue.trim() || (TURNSTILE_ENABLED && !turnstileToken)
                  ? "bg-muted text-muted-foreground cursor-not-allowed"
                  : "bg-gradient-to-r from-teal-500 to-cyan-500 text-white shadow-lg shadow-teal-500/20 hover:shadow-teal-500/30 hover:brightness-110")}>
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
        </div>
      )}

      {/* Results */}
      <div className="px-6 pb-6 flex-1">
        {tool.authOnly ? <AuthOnlyTeaser tool={tool} /> : result ? <ToolResultView data={result} /> : (
          <div className="flex items-center justify-center h-20 text-xs text-muted-foreground/40">{emptyHint} and press Enter</div>
        )}
      </div>

      {result && !tool.authOnly && (
        <div className="px-6 pb-4 -mt-1">
          <Link
            href="/look-up-tools"
            className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-teal-400 hover:text-teal-300 transition-colors"
          >
            See all lookup tools <ArrowRight className="w-3 h-3" />
          </Link>
        </div>
      )}
    </div>
  );
}