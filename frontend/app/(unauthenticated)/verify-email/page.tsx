"use client";

import { Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { CheckCircle2, AlertTriangle, Loader2, ArrowRight, MailCheck } from "lucide-react";

import { verifyEmail } from "../../lib/api";

function BoltIcon({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className="shrink-0">
      <rect width="32" height="32" rx="7" fill="#0a0f1e" />
      <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#14b8a6" />
    </svg>
  );
}

// IMPORTANT: do NOT call verifyEmail() automatically on page load.
// Corporate email security gateways (Microsoft Safe Links,
// Mimecast, Proofpoint, Gmail safe-browsing) pre-fetch every link
// in inbound mail to scan it. If we auto-verified on mount, those
// crawler GETs would consume the token and mark the user verified
// before they actually click anything.
//
// Requiring an explicit click on the page closes that hole — bots
// can fetch the HTML all they want, but they can't trigger the
// POST that does the actual verification.

function VerifyEmailInner() {
  const searchParams = useSearchParams();
  const token = searchParams?.get("token") || "";

  const [state, setState] = useState<"idle" | "verifying" | "ok" | "already" | "error">(
    token ? "idle" : "error",
  );
  const [email, setEmail] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>(
    token ? "" : "This verification link is missing its token.",
  );

  async function handleConfirm() {
    if (!token || state === "verifying") return;
    setState("verifying");
    try {
      const res = await verifyEmail(token);
      setEmail(res.email || null);
      setState(res.alreadyVerified ? "already" : "ok");
    } catch (err: any) {
      setErrorMessage(err?.message || "This verification link is invalid or has expired.");
      setState("error");
    }
  }

  return (
    <div className="min-h-screen bg-[#060b18] text-white flex items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <Link href="/" className="flex items-center gap-2.5 mb-10">
          <BoltIcon />
          <span className="text-base font-semibold">
            Nano <span className="text-teal-400">EASM</span>
          </span>
        </Link>

        {state === "idle" && (
          <div className="space-y-5">
            <div className="w-12 h-12 rounded-xl bg-teal-500/15 flex items-center justify-center">
              <MailCheck className="w-7 h-7 text-teal-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Confirm your email</h1>
              <p className="mt-2 text-sm text-white/50 leading-relaxed">
                Click the button below to verify this is your email address.
                {/* The explicit-click step guards against automated link
                    scanners (Microsoft Safe Links, Mimecast, etc.) that
                    pre-fetch every URL in inbound mail. */}
              </p>
            </div>
            <button
              onClick={handleConfirm}
              className="inline-flex items-center justify-center gap-2 w-full h-11 rounded-lg bg-gradient-to-r from-teal-500 to-cyan-500 text-sm font-semibold text-white shadow-lg shadow-teal-500/20 hover:brightness-110 transition-all"
            >
              Verify my email
              <ArrowRight className="w-4 h-4" />
            </button>
            <p className="text-xs text-white/30">
              Didn&apos;t request this? You can safely close this tab — nothing changes until you click above.
            </p>
          </div>
        )}

        {state === "verifying" && (
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
