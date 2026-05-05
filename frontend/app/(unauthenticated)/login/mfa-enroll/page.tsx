// app/(unauthenticated)/login/mfa-enroll/page.tsx
// Forced MFA enrolment at login. Reached when /auth/login returns
// mfaEnrolmentRequired=true (Owner/Admin/Superadmin without MFA).
// The user has NOT been issued a JWT yet — the mfaToken IS the credential
// for /auth/mfa/forced-enroll and /auth/mfa/forced-enroll/confirm.
"use client";

import React, { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  ArrowRight,
  Check,
  Copy,
  Download,
  Loader2,
  Shield,
} from "lucide-react";

import {
  startForcedMfaEnroll,
  confirmForcedMfaEnroll,
  type MfaEnrollResponse,
} from "../../../lib/api";
import { establishSession, type AuthRole } from "../../../lib/auth";

function BoltIcon({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className="shrink-0">
      <rect width="32" height="32" rx="7" fill="#0a0f1e" />
      <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#14b8a6" />
    </svg>
  );
}

function ForcedEnrollInner() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const mfaToken = searchParams?.get("mfaToken") ?? "";
  const email = searchParams?.get("email") ?? "";
  const reason = searchParams?.get("reason") ?? "";
  const nextPath = useMemo(() => {
    const n = searchParams?.get("next");
    return n && n.startsWith("/") ? n : "/dashboard";
  }, [searchParams]);

  const [stage, setStage] = useState<"loading" | "show" | "confirm" | "done">(
    "loading"
  );
  const [enrolment, setEnrolment] = useState<MfaEnrollResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [copied, setCopied] = useState(false);
  const [acknowledgedCodes, setAcknowledgedCodes] = useState(false);

  useEffect(() => {
    if (!mfaToken) {
      setError("Missing sign-in state. Return to sign-in.");
      setStage("show");
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await startForcedMfaEnroll({ mfaToken });
        if (cancelled) return;
        setEnrolment(res);
        setStage("show");
      } catch (err: any) {
        if (cancelled) return;
        if (err?.payload?.code === "MFA_TOKEN_EXPIRED") {
          router.replace("/login?expired=true");
          return;
        }
        setError(err?.message || "Could not start MFA enrolment");
        setStage("show");
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mfaToken]);

  async function onConfirm(e: React.FormEvent) {
    e.preventDefault();
    if (!code.trim() || confirming) return;
    try {
      setConfirming(true);
      setError(null);
      const res = await confirmForcedMfaEnroll({
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
        router.replace("/login?expired=true");
        return;
      }
      setError(err?.message || "Verification failed");
    } finally {
      setConfirming(false);
    }
  }

  async function copyCodes() {
    if (!enrolment) return;
    try {
      await navigator.clipboard.writeText(enrolment.recoveryCodes.join("\n"));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* noop */
    }
  }

  function downloadCodes() {
    if (!enrolment) return;
    const blob = new Blob(
      [
        `Nano EASM — recovery codes for ${email}\n` +
          `Generated ${new Date().toISOString()}\n\n` +
          enrolment.recoveryCodes.join("\n") +
          `\n\nKeep these somewhere safe. Each one works once.\n`,
      ],
      { type: "text/plain" }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nano-easm-recovery-codes.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (!mfaToken && !error) {
    return null;
  }

  return (
    <div className="min-h-screen bg-[#060b18] text-white flex items-center justify-center p-6">
      <div className="w-full max-w-md">
        <div className="flex items-center gap-2.5 mb-8 justify-center">
          <BoltIcon size={28} />
          <span className="text-base font-semibold">
            Nano<span className="text-teal-400">EASM</span>
          </span>
        </div>

        <div className="text-center">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-amber-500/15 mb-4">
            <Shield className="w-5 h-5 text-amber-400" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">
            Set up two-factor authentication
          </h1>
          <p className="mt-2 text-sm text-white/40">
            {reason ||
              "Two-factor authentication is required for this account."}
          </p>
        </div>

        {stage === "loading" && (
          <div className="mt-8 flex items-center justify-center gap-2 text-sm text-white/40">
            <Loader2 className="w-4 h-4 animate-spin" />
            Preparing enrolment…
          </div>
        )}

        {stage === "show" && enrolment && (
          <>
            <div className="mt-8 rounded-xl border border-white/[0.08] bg-white/[0.02] p-5 space-y-5">
              <div>
                <h2 className="text-sm font-semibold mb-2">
                  1 · Scan with your authenticator app
                </h2>
                <p className="text-xs text-white/40 mb-3">
                  Use Google Authenticator, 1Password, Authy, Bitwarden, or any
                  TOTP app.
                </p>
                <div className="flex justify-center">
                  <img
                    src={enrolment.qrCodeDataUrl}
                    alt="MFA QR code"
                    className="w-44 h-44 rounded-lg bg-white p-2"
                  />
                </div>
                <details className="mt-3">
                  <summary className="text-xs text-white/40 hover:text-white/60 cursor-pointer">
                    Can&apos;t scan? Show secret to enter manually
                  </summary>
                  <div className="mt-2 px-3 py-2 rounded bg-white/[0.04] border border-white/[0.08] font-mono text-xs text-white/60 break-all select-all">
                    {enrolment.secret}
                  </div>
                </details>
              </div>

              <div className="border-t border-white/[0.06] pt-5">
                <h2 className="text-sm font-semibold mb-2">
                  2 · Save your recovery codes
                </h2>
                <p className="text-xs text-amber-300 mb-3">
                  These are shown <strong>once</strong>. If you lose your
                  authenticator, they&apos;re the only way to sign in.
                </p>
                <div className="grid grid-cols-2 gap-2 font-mono text-xs">
                  {enrolment.recoveryCodes.map((c) => (
                    <div
                      key={c}
                      className="px-2.5 py-1.5 rounded bg-white/[0.04] border border-white/[0.08] text-white/70 select-all text-center"
                    >
                      {c}
                    </div>
                  ))}
                </div>
                <div className="mt-3 flex gap-2">
                  <button
                    type="button"
                    onClick={copyCodes}
                    className="flex-1 h-9 rounded-lg border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] text-xs text-white/70 transition-all flex items-center justify-center gap-1.5"
                  >
                    {copied ? (
                      <>
                        <Check className="w-3 h-3" /> Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" /> Copy codes
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={downloadCodes}
                    className="flex-1 h-9 rounded-lg border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] text-xs text-white/70 transition-all flex items-center justify-center gap-1.5"
                  >
                    <Download className="w-3 h-3" /> Download
                  </button>
                </div>
                <label className="mt-3 flex items-start gap-2 text-xs text-white/50 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={acknowledgedCodes}
                    onChange={(e) => setAcknowledgedCodes(e.target.checked)}
                  />
                  <span>
                    I&apos;ve saved my recovery codes somewhere safe.
                  </span>
                </label>
              </div>
            </div>

            <button
              type="button"
              disabled={!acknowledgedCodes}
              onClick={() => setStage("confirm")}
              className="mt-5 w-full h-11 rounded-lg bg-gradient-to-r from-teal-500 to-cyan-500 text-sm font-semibold text-white shadow-lg shadow-teal-500/20 hover:shadow-teal-500/35 transition-all hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              Continue
              <ArrowRight className="w-4 h-4" />
            </button>

            {error && (
              <div className="mt-4 rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3.5 py-2.5 text-sm text-red-300">
                {error}
              </div>
            )}
          </>
        )}

        {stage === "confirm" && (
          <form onSubmit={onConfirm} className="mt-8 space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-white/50 block">
                Enter the 6-digit code from your authenticator
              </label>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                maxLength={6}
                className="w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 text-sm text-white placeholder:text-white/20 outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 transition-all tracking-widest text-center font-mono"
                placeholder="123456"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </div>

            {error && (
              <div className="rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3.5 py-2.5 text-sm text-red-300">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={confirming || code.trim().length === 0}
              className="w-full h-11 rounded-lg bg-gradient-to-r from-teal-500 to-cyan-500 text-sm font-semibold text-white shadow-lg shadow-teal-500/20 hover:shadow-teal-500/35 transition-all hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {confirming ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Verifying…
                </>
              ) : (
                <>
                  Enable two-factor authentication
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => setStage("show")}
              className="w-full text-xs text-white/40 hover:text-white/60 transition-colors"
            >
              ← Back to QR code
            </button>
          </form>
        )}

        <p className="mt-6 text-xs text-white/30 text-center">
          <Link
            href="/login"
            className="text-white/40 hover:text-white/60 transition-colors"
          >
            ← Cancel and return to sign-in
          </Link>
        </p>
      </div>
    </div>
  );
}

export default function ForcedEnrollPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[#060b18] flex items-center justify-center">
          <div className="text-sm text-white/40">Loading…</div>
        </div>
      }
    >
      <ForcedEnrollInner />
    </Suspense>
  );
}
