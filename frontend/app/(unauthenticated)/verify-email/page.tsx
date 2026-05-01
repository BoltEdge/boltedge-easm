"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { CheckCircle2, AlertTriangle, Loader2, ArrowRight } from "lucide-react";

import { verifyEmail } from "../../lib/api";

function BoltIcon({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className="shrink-0">
      <rect width="32" height="32" rx="7" fill="#0a0f1e" />
      <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#14b8a6" />
    </svg>
  );
}

function VerifyEmailInner() {
  const searchParams = useSearchParams();
  const token = searchParams?.get("token") || "";

  const [state, setState] = useState<"loading" | "ok" | "already" | "error">("loading");
  const [email, setEmail] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>("");

  useEffect(() => {
    if (!token) {
      setState("error");
      setErrorMessage("This verification link is missing its token.");
      return;
    }

    let cancelled = false;
    verifyEmail(token)
      .then((res) => {
        if (cancelled) return;
        setEmail(res.email || null);
        setState(res.alreadyVerified ? "already" : "ok");
      })
      .catch((err: any) => {
        if (cancelled) return;
        setErrorMessage(err?.message || "This verification link is invalid or has expired.");
        setState("error");
      });
    return () => { cancelled = true; };
  }, [token]);

  return (
    <div className="min-h-screen bg-[#060b18] text-white flex items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <Link href="/" className="flex items-center gap-2.5 mb-10">
          <BoltIcon />
          <span className="text-base font-semibold">
            Nano<span className="text-teal-400">EASM</span>
          </span>
        </Link>

        {state === "loading" && (
          <div className="space-y-4">
            <Loader2 className="w-6 h-6 text-teal-400 animate-spin" />
            <h1 className="text-2xl font-bold tracking-tight">Verifying your email…</h1>
            <p className="text-sm text-white/40">One moment while we check your link.</p>
          </div>
        )}

        {(state === "ok" || state === "already") && (
          <div className="space-y-5">
            <div className="w-12 h-12 rounded-xl bg-emerald-500/15 flex items-center justify-center">
              <CheckCircle2 className="w-7 h-7 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">
                {state === "already" ? "Already verified" : "Email verified"}
              </h1>
              <p className="mt-2 text-sm text-white/50 leading-relaxed">
                {state === "already"
                  ? "Your email was already confirmed."
                  : "Thanks for confirming your email."}
                {email && (
                  <>
                    {" "}
                    <span className="text-white font-medium">{email}</span> is good to go.
                  </>
                )}
              </p>
            </div>
            <Link
              href="/login"
              className="inline-flex items-center justify-center gap-2 w-full h-11 rounded-lg bg-gradient-to-r from-teal-500 to-cyan-500 text-sm font-semibold text-white shadow-lg shadow-teal-500/20 hover:brightness-110 transition-all"
            >
              Continue to sign in
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        )}

        {state === "error" && (
          <div className="space-y-5">
            <div className="w-12 h-12 rounded-xl bg-red-500/15 flex items-center justify-center">
              <AlertTriangle className="w-7 h-7 text-red-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Link invalid or expired</h1>
              <p className="mt-2 text-sm text-white/50 leading-relaxed">{errorMessage}</p>
              <p className="mt-3 text-sm text-white/40">
                Sign in to request a new verification email.
              </p>
            </div>
            <Link
              href="/login"
              className="inline-flex items-center justify-center gap-2 w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] text-sm font-medium text-white transition-all"
            >
              Go to sign in
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#060b18] flex items-center justify-center text-white/40 text-sm">Loading…</div>}>
      <VerifyEmailInner />
    </Suspense>
  );
}
