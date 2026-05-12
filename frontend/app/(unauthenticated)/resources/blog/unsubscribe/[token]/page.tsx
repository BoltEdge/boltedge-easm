// FILE: app/(unauthenticated)/resources/blog/unsubscribe/[token]/page.tsx
//
// One-click unsubscribe landing page. Resolves the token on mount so
// the user lands on a clear "you're out" confirmation rather than a
// form they have to submit. Backend marks the row inactive and rotates
// nothing — the token stays so refreshing the page doesn't error.

"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import { Check, AlertTriangle, ArrowLeft, ArrowRight, Loader2 } from "lucide-react";

import LandingNav from "../../../../LandingNav";
import LandingFooter from "../../../../LandingFooter";
import { API_BASE_URL } from "../../../../../lib/api";

type State =
  | { kind: "loading" }
  | { kind: "ok"; message: string }
  | { kind: "error"; message: string };

export default function UnsubscribePage({ params }: { params: Promise<{ token: string }> }) {
  // Next.js 16: params is a Promise; `use` unwraps it synchronously
  // for client components.
  const { token } = use(params);
  const [state, setState] = useState<State>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(
          `${API_BASE_URL}/blog/unsubscribe/${encodeURIComponent(token)}`,
          { method: "GET" },
        );
        const data = await res.json().catch(() => ({} as any));
        if (cancelled) return;
        if (!res.ok) {
          setState({
            kind: "error",
            message: data?.error || "We couldn't process that unsubscribe link.",
          });
          return;
        }
        setState({
          kind: "ok",
          message: data?.message || "You've been unsubscribed.",
        });
      } catch {
        if (!cancelled) {
          setState({ kind: "error", message: "Network error. Please try again." });
        }
      }
    })();
    return () => { cancelled = true; };
  }, [token]);

  return (
    <div className="min-h-screen bg-[#060b18] text-white overflow-x-hidden">
      <LandingNav />
      <div className="h-16" />

      <main className="mx-auto max-w-2xl px-4 sm:px-6 pt-16 pb-20">
        <Link
          href="/resources/blog"
          className="inline-flex items-center gap-1.5 text-sm text-white/50 hover:text-white transition-colors mb-8"
        >
          <ArrowLeft className="w-4 h-4" />Back to blog
        </Link>

        <div className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-8 sm:p-10 text-center">
          {state.kind === "loading" && (
            <>
              <Loader2 className="w-8 h-8 text-white/30 mx-auto mb-4 animate-spin" />
              <p className="text-sm text-white/55">Processing your unsubscribe…</p>
            </>
          )}

          {state.kind === "ok" && (
            <>
              <div className="w-12 h-12 rounded-full bg-teal-500/10 border border-teal-500/30 flex items-center justify-center mx-auto mb-5">
                <Check className="w-6 h-6 text-teal-400" />
              </div>
              <h1 className="text-2xl font-bold tracking-tight">You're unsubscribed</h1>
              <p className="mt-3 text-sm text-white/65 leading-relaxed max-w-md mx-auto">
                {state.message} If you change your mind later, you can re-subscribe from any article on the blog.
              </p>
              <div className="mt-7 flex flex-col sm:flex-row gap-3 justify-center">
                <Link
                  href="/resources/blog"
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-teal-600 hover:bg-teal-500 px-5 py-2.5 text-sm font-semibold text-white transition-all"
                >
                  Browse the blog <ArrowRight className="w-4 h-4" />
                </Link>
                <Link
                  href="/"
                  className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-5 py-2.5 text-sm font-medium text-white/70 hover:text-white hover:bg-white/[0.06] transition-all"
                >
                  Back to home
                </Link>
              </div>
            </>
          )}

          {state.kind === "error" && (
            <>
              <div className="w-12 h-12 rounded-full bg-amber-500/10 border border-amber-500/30 flex items-center justify-center mx-auto mb-5">
                <AlertTriangle className="w-6 h-6 text-amber-400" />
              </div>
              <h1 className="text-2xl font-bold tracking-tight">Couldn't process that link</h1>
              <p className="mt-3 text-sm text-white/65 leading-relaxed max-w-md mx-auto">
                {state.message} The link may have expired, or you may already be unsubscribed.
                If you keep receiving emails after this, reply to one of them and we'll remove you by hand.
              </p>
              <div className="mt-7 flex flex-col sm:flex-row gap-3 justify-center">
                <Link
                  href="/"
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-teal-600 hover:bg-teal-500 px-5 py-2.5 text-sm font-semibold text-white transition-all"
                >
                  Back to home <ArrowRight className="w-4 h-4" />
                </Link>
              </div>
            </>
          )}
        </div>
      </main>

      <LandingFooter />
    </div>
  );
}
