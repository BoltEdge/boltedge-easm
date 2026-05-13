// FILE: app/(unauthenticated)/resources/blog/SubscribeForm.tsx
//
// Subscribe-by-email form for the blog. Single opt-in (the user lands
// on the active list immediately) but Turnstile-gated + an immediate
// welcome email with a one-click unsubscribe link.
//
// Two variants:
//   variant="card"    — large card with heading + lede (for the bottom of
//                       the blog index)
//   variant="inline"  — compact one-line form (for the article sidebar)
"use client";

import { useState } from "react";
import { Loader2, Check, Mail, AlertTriangle } from "lucide-react";

import { API_BASE_URL } from "../../../lib/api";
import TurnstileWidget from "../../TurnstileWidget";

const TURNSTILE_ENABLED = !!process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;

type Variant = "card" | "inline";

type Status = "idle" | "submitting" | "ok" | "error";

export default function SubscribeForm({
  variant = "card",
  source = "blog-index",
}: {
  variant?: Variant;
  source?: string;
}) {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [message, setMessage] = useState<string | null>(null);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  // Bumping the widget key on submit forces a fresh token next attempt —
  // Cloudflare tokens are single-use.
  const [widgetKey, setWidgetKey] = useState(0);

  // Loose email check to disable the button before submit. Server does
  // the real validation; this is just UX.
  const emailLooksOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  const canSubmit =
    emailLooksOk &&
    status !== "submitting" &&
    (!TURNSTILE_ENABLED || !!turnstileToken);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setStatus("submitting");
    setMessage(null);
    try {
      const res = await fetch(`${API_BASE_URL}/blog/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email.trim(),
          source,
          turnstileToken: turnstileToken || undefined,
        }),
      });
      const data = await res.json().catch(() => ({} as any));
      if (!res.ok) {
        setStatus("error");
        setMessage(data?.error || "Couldn't subscribe right now. Please try again.");
        setTurnstileToken(null);
        setWidgetKey((k) => k + 1);
        return;
      }
      setStatus("ok");
      setMessage(data?.message || "Subscribed. Check your inbox for confirmation.");
      setEmail("");
      setTurnstileToken(null);
    } catch {
      setStatus("error");
      setMessage("Network error. Please try again.");
      setTurnstileToken(null);
      setWidgetKey((k) => k + 1);
    }
  }

  // ── Success state (same UI for both variants — short and clear) ──
  if (status === "ok") {
    return (
      <div
        className={
          variant === "card"
            ? "rounded-2xl border border-teal-500/30 bg-teal-500/[0.06] p-5 sm:p-6"
            : "rounded-xl border border-teal-500/30 bg-teal-500/[0.06] p-4"
        }
      >
        <div className="flex items-start gap-2.5">
          <Check className="w-4 h-4 text-teal-400 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-sm font-medium text-white">{message}</p>
            <p className="text-xs text-white/55 mt-1 leading-relaxed">
              You can unsubscribe any time from the link at the bottom of every email — one click, no questions.
            </p>
          </div>
        </div>
      </div>
    );
  }

  // ── Form ──
  if (variant === "inline") {
    return (
      <form onSubmit={handleSubmit} className="space-y-2">
        <div className="flex items-center gap-2">
          <Mail className="w-3.5 h-3.5 text-teal-400 flex-shrink-0" />
          <div className="text-sm font-medium text-white">Subscribe to our newsletter</div>
        </div>
        <p className="text-xs text-white/55 leading-relaxed">
          Articles on ASM &mdash; discovery, scanning, monitoring. One click to unsubscribe.
        </p>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@company.com"
          autoComplete="email"
          className="w-full h-9 px-3 rounded-md border border-white/[0.08] bg-white/[0.02] text-sm text-white placeholder:text-white/30 outline-none focus:border-teal-500/40 focus:bg-white/[0.04] transition-colors"
          disabled={status === "submitting"}
        />
        {TURNSTILE_ENABLED && (
          <TurnstileWidget
            key={widgetKey}
            onVerify={setTurnstileToken}
            onExpire={() => setTurnstileToken(null)}
            onError={() => setTurnstileToken(null)}
          />
        )}
        {status === "error" && message && (
          <p className="text-[11px] text-red-300 flex items-start gap-1.5">
            <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" />
            {message}
          </p>
        )}
        <button
          type="submit"
          disabled={!canSubmit}
          className="w-full inline-flex items-center justify-center gap-1.5 h-9 px-3 rounded-md bg-teal-600 hover:bg-teal-500 text-xs font-semibold text-white shadow-sm shadow-teal-900/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-teal-600"
        >
          {status === "submitting" ? (
            <>
              <Loader2 className="w-3 h-3 animate-spin" />Subscribing…
            </>
          ) : (
            <>Subscribe</>
          )}
        </button>
      </form>
    );
  }

  // ── Card variant (default — for the blog index + article footer) ──
  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-2xl border border-teal-500/20 bg-gradient-to-br from-teal-500/[0.06] via-[#060b18] to-[#060b18] p-6 sm:p-8"
    >
      <div className="flex items-center gap-2 mb-3">
        <Mail className="w-4 h-4 text-teal-400" />
        <div className="text-[11px] font-semibold text-teal-400/85 uppercase tracking-wider">
          Subscribe to our newsletter
        </div>
      </div>
      <h3 className="text-xl font-bold text-foreground">ASM articles, plainly written</h3>
      <p className="mt-2 text-sm text-white/65 leading-relaxed max-w-xl">
        Articles on External Attack Surface Management &mdash; what to discover, what to scan, what to monitor,
        and what to ignore. Roughly one a week, sometimes less. No product marketing, no sales emails.
      </p>

      <div className="mt-5 flex flex-col sm:flex-row gap-2 max-w-xl">
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@company.com"
          autoComplete="email"
          aria-label="Email address"
          className="flex-1 h-11 px-3.5 rounded-lg border border-white/[0.08] bg-white/[0.02] text-sm text-white placeholder:text-white/30 outline-none focus:border-teal-500/40 focus:bg-white/[0.04] transition-colors"
          disabled={status === "submitting"}
        />
        <button
          type="submit"
          disabled={!canSubmit}
          className="inline-flex items-center justify-center gap-2 h-11 px-5 rounded-lg bg-teal-600 hover:bg-teal-500 text-sm font-semibold text-white shadow-md shadow-teal-900/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-teal-600"
        >
          {status === "submitting" ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />Subscribing…
            </>
          ) : (
            <>Subscribe</>
          )}
        </button>
      </div>

      {TURNSTILE_ENABLED && (
        <div className="mt-3">
          <TurnstileWidget
            key={widgetKey}
            onVerify={setTurnstileToken}
            onExpire={() => setTurnstileToken(null)}
            onError={() => setTurnstileToken(null)}
          />
        </div>
      )}

      {status === "error" && message && (
        <div className="mt-3 rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3.5 py-2.5 text-xs text-red-300 flex items-start gap-2 max-w-xl">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
          <span>{message}</span>
        </div>
      )}

      <p className="mt-4 text-[11px] text-white/40">
        Newsletter only &mdash; no third-party sharing. Unsubscribe in one click from any email.
      </p>
    </form>
  );
}
