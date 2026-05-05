// app/(unauthenticated)/login/mfa/page.tsx
// Second factor at login. Reached when /auth/login returns mfaRequired=true.
"use client";

import React, { Suspense, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowRight, Key, Loader2, Lock } from "lucide-react";

import { verifyMfa } from "../../../lib/api";
import { establishSession, type AuthRole } from "../../../lib/auth";

function BoltIcon({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className="shrink-0">
      <rect width="32" height="32" rx="7" fill="#0a0f1e" />
      <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#14b8a6" />
    </svg>
  );
}

function MfaVerifyInner() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const mfaToken = searchParams?.get("mfaToken") ?? "";
  const email = searchParams?.get("email") ?? "";
  const nextPath = useMemo(() => {
    const n = searchParams?.get("next");
    return n && n.startsWith("/") ? n : "/dashboard";
  }, [searchParams]);

  const [code, setCode] = useState("");
  const [useRecoveryKey, setUseRecoveryKey] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = code.trim().length > 0 && mfaToken.length > 0 && !loading;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    try {
      setLoading(true);
      setError(null);

      const res = await verifyMfa({
        mfaToken,
        code: code.trim(),
      });

      establishSession({
        accessToken: res.accessToken,
        user: res.user,
        organization: res.organization,
        role: (res.role ?? "owner") as AuthRole,
      });

      router.replace(nextPath);
    } catch (err: any) {
      if (err?.payload?.code === "MFA_TOKEN_EXPIRED") {
        // Token expired — bounce back to /login.
        router.replace("/login?expired=true");
        return;
      }
      setError(err?.message || "Verification failed");
    } finally {
      setLoading(false);
    }
  }

  if (!mfaToken) {
    // Direct access without a token — send them back to login.
    return (
      <div className="min-h-screen bg-[#060b18] text-white flex items-center justify-center">
        <div className="text-sm text-white/40">
          Missing sign-in state.{" "}
          <Link href="/login" className="text-teal-400 hover:text-teal-300">
            Return to sign-in
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#060b18] text-white flex items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2.5 mb-10 justify-center">
          <BoltIcon size={28} />
          <span className="text-base font-semibold">
            Nano<span className="text-teal-400">EASM</span>
          </span>
        </div>

        <div className="text-center">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-teal-500/15 mb-4">
            <Lock className="w-5 h-5 text-teal-400" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Two-factor authentication</h1>
          <p className="mt-2 text-sm text-white/40">
            Signed in as <span className="text-white/60">{email}</span>
          </p>
        </div>

        <form className="mt-8 space-y-4" onSubmit={onSubmit}>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-white/50 block">
              {useRecoveryKey ? "Recovery key" : "6-digit authenticator code"}
            </label>
            <input
              type="text"
              inputMode={useRecoveryKey ? "text" : "numeric"}
              autoFocus
              autoComplete={useRecoveryKey ? "off" : "one-time-code"}
              className="w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 text-sm text-white placeholder:text-white/20 outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 transition-all tracking-widest text-center font-mono"
              placeholder={
                useRecoveryKey ? "abcd-efgh-ijkl-mnop-qrst-uvwx-yz12-3456" : "123456"
              }
              value={code}
              onChange={(e) => setCode(e.target.value)}
              maxLength={useRecoveryKey ? 40 : 6}
            />
          </div>

          {error && (
            <div className="rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3.5 py-2.5 text-sm text-red-300">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={!canSubmit}
            className="w-full h-11 rounded-lg bg-gradient-to-r from-teal-500 to-cyan-500 text-sm font-semibold text-white shadow-lg shadow-teal-500/20 hover:shadow-teal-500/35 transition-all hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Verifying...
              </>
            ) : (
              <>
                Verify
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>

          <button
            type="button"
            onClick={() => {
              setUseRecoveryKey((v) => !v);
              setCode("");
              setError(null);
            }}
            className="w-full text-xs text-white/40 hover:text-white/60 transition-colors flex items-center justify-center gap-1.5"
          >
            <Key className="w-3 h-3" />
            {useRecoveryKey
              ? "Use authenticator app instead"
              : "Use your recovery key instead"}
          </button>
        </form>

        <p className="mt-6 text-xs text-white/30 text-center">
          Lost your phone and your recovery key?{" "}
          <Link
            href="/contact"
            className="text-teal-400 hover:text-teal-300 transition-colors"
          >
            Contact your admin
          </Link>
        </p>
      </div>
    </div>
  );
}

export default function MfaVerifyPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[#060b18] flex items-center justify-center">
          <div className="text-sm text-white/40">Loading…</div>
        </div>
      }
    >
      <MfaVerifyInner />
    </Suspense>
  );
}
