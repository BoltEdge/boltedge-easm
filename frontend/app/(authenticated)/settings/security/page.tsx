// app/(authenticated)/settings/security/page.tsx
// MFA management for the signed-in user.
"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Check,
  Copy,
  Download,
  Loader2,
  Lock,
  RefreshCcw,
  Shield,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";

import {
  confirmMfaEnroll,
  disableMfa,
  getMfaStatus,
  regenerateMfaRecoveryKey,
  startMfaEnroll,
  type MfaEnrollResponse,
  type MfaStatusResponse,
} from "../../../lib/api";

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  let d: Date;
  if (typeof iso === "string" && !iso.endsWith("Z") && !iso.includes("+"))
    d = new Date(iso + "Z");
  else d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export default function SecurityPage() {
  const [status, setStatus] = useState<MfaStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Enrolment state
  const [enrolling, setEnrolling] = useState(false);
  const [enrolment, setEnrolment] = useState<MfaEnrollResponse | null>(null);
  const [confirmCode, setConfirmCode] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);

  // Disable / regenerate state
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [disabling, setDisabling] = useState(false);
  const [showDisable, setShowDisable] = useState(false);

  const [regenPassword, setRegenPassword] = useState("");
  const [regenCode, setRegenCode] = useState("");
  const [regenerating, setRegenerating] = useState(false);
  const [regenKey, setRegenKey] = useState<string | null>(null);
  const [showRegen, setShowRegen] = useState(false);

  const [copied, setCopied] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const s = await getMfaStatus();
      setStatus(s);
    } catch (e: any) {
      setError(e?.message || "Could not load MFA status");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onStartEnroll() {
    try {
      setEnrolling(true);
      setError(null);
      const res = await startMfaEnroll();
      setEnrolment(res);
      setAcknowledged(false);
      setConfirmCode("");
    } catch (e: any) {
      setError(e?.message || "Could not start enrolment");
    } finally {
      setEnrolling(false);
    }
  }

  async function onConfirmEnroll(e: React.FormEvent) {
    e.preventDefault();
    if (!confirmCode.trim()) return;
    try {
      setConfirming(true);
      setError(null);
      await confirmMfaEnroll(confirmCode.trim());
      setEnrolment(null);
      setConfirmCode("");
      setAcknowledged(false);
      await refresh();
    } catch (e: any) {
      setError(e?.message || "Verification failed");
    } finally {
      setConfirming(false);
    }
  }

  async function onDisable(e: React.FormEvent) {
    e.preventDefault();
    if (status?.hasPassword && !disablePassword) return;
    if (!status?.hasPassword && !disableCode) return;
    try {
      setDisabling(true);
      setError(null);
      await disableMfa({
        password: disablePassword || undefined,
        code: disableCode || undefined,
      });
      setDisablePassword("");
      setDisableCode("");
      setShowDisable(false);
      await refresh();
    } catch (e: any) {
      setError(e?.message || "Could not disable MFA");
    } finally {
      setDisabling(false);
    }
  }

  async function onRegenerate(e: React.FormEvent) {
    e.preventDefault();
    if (status?.hasPassword && !regenPassword) return;
    if (!status?.hasPassword && !regenCode) return;
    try {
      setRegenerating(true);
      setError(null);
      const res = await regenerateMfaRecoveryKey({
        password: regenPassword || undefined,
        code: regenCode || undefined,
      });
      setRegenKey(res.recoveryKey);
      setRegenPassword("");
      setRegenCode("");
      setShowRegen(false);
      await refresh();
    } catch (e: any) {
      setError(e?.message || "Could not regenerate recovery key");
    } finally {
      setRegenerating(false);
    }
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* noop */
    }
  }

  function downloadRegen() {
    if (!regenKey) return;
    const blob = new Blob(
      [
        `Nano EASM — recovery key\n` +
          `Generated ${new Date().toISOString()}\n\n` +
          regenKey +
          `\n\nKeep this somewhere safe. It is single-use.\n` +
          `If you lose it, contact your admin to reset MFA.\n`,
      ],
      { type: "text/plain" }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nano-easm-recovery-key.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (loading) {
    return (
      <div className="p-8 text-sm text-white/40 flex items-center gap-2">
        <Loader2 className="w-4 h-4 animate-spin" />
        Loading…
      </div>
    );
  }

  return (
    <div className="p-6 sm:p-8 max-w-5xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Shield className="w-5 h-5 text-teal-400" />
          Security
        </h1>
        <p className="mt-1 text-sm text-white/40">
          Manage two-factor authentication for your account.
        </p>
      </div>

      {/* Top-level security overview strip — at-a-glance state for all the
          checks that contribute to account security. Currently 2FA is the
          only one we manage in-app; the others are surfaced for awareness
          and link out to where they're configured. */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          {
            label: "Two-factor auth",
            state: status?.mfaEnabled ? "On" : "Off",
            tone: status?.mfaEnabled ? "ok" : "warn",
            sub: status?.mfaEnabled ? "TOTP enrolled" : "Not enrolled",
          },
          {
            label: "Recovery key",
            state: status?.recoveryKeyAvailable ? "Set" : "Not set",
            tone: status?.recoveryKeyAvailable ? "ok" : (status?.mfaEnabled ? "warn" : "muted"),
            sub: status?.recoveryKeyAvailable ? "1 single-use code stored locally" : "Generate when prompted",
          },
          {
            label: "Password",
            state: status?.hasPassword ? "Set" : "OAuth only",
            tone: "muted",
            sub: status?.hasPassword ? "Email + password sign-in" : "Google / Microsoft sign-in",
          },
          {
            label: "Active sessions",
            state: "1",
            tone: "muted",
            sub: "This device · session management coming soon",
          },
        ].map(({ label, state, tone, sub }) => {
          const toneClass = tone === "ok"
            ? "text-emerald-300 bg-emerald-500/10 border-emerald-500/20"
            : tone === "warn"
              ? "text-amber-300 bg-amber-500/10 border-amber-500/20"
              : "text-white/70 bg-white/[0.04] border-white/[0.08]";
          return (
            <div key={label} className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-4">
              <div className="text-[10px] uppercase tracking-wider text-white/40 font-semibold mb-2">{label}</div>
              <span className={`inline-block px-2 py-0.5 rounded border text-xs font-semibold ${toneClass}`}>{state}</span>
              <p className="text-[11px] text-white/40 mt-2 leading-relaxed">{sub}</p>
            </div>
          );
        })}
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3.5 py-2.5 text-sm text-red-300 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* ── Status card ──────────────────────────────────── */}
      <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5">
        <div className="flex items-start gap-4">
          <div
            className={`w-10 h-10 rounded-full flex items-center justify-center shrink-0 ${
              status?.mfaEnabled
                ? "bg-emerald-500/15"
                : "bg-zinc-500/15"
            }`}
          >
            {status?.mfaEnabled ? (
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            ) : (
              <ShieldOff className="w-5 h-5 text-zinc-400" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-base font-semibold">
              Two-factor authentication
            </h2>
            <p className="mt-1 text-sm text-white/50">
              {status?.mfaEnabled
                ? `Enabled since ${formatDate(status.enrolledAt)} · ${
                    status.recoveryKeyAvailable
                      ? "recovery key set"
                      : "no recovery key — regenerate one"
                  }`
                : "Add a second step to your sign-in using an authenticator app."}
            </p>
          </div>
        </div>
      </div>

      {/* ── Enrolment flow ───────────────────────────────── */}
      {!status?.mfaEnabled && !enrolment && (
        <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5">
          <h3 className="text-sm font-semibold mb-2">
            Set up an authenticator app
          </h3>
          <p className="text-xs text-white/50 mb-4">
            Use any TOTP authenticator app.
          </p>
          <button
            type="button"
            onClick={onStartEnroll}
            disabled={enrolling}
            className="h-10 px-4 rounded-lg bg-gradient-to-r from-teal-500 to-cyan-500 text-sm font-semibold text-white shadow-lg shadow-teal-500/20 hover:brightness-110 transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {enrolling ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Preparing…
              </>
            ) : (
              <>
                <Lock className="w-4 h-4" />
                Enable two-factor authentication
              </>
            )}
          </button>
        </div>
      )}

      {!status?.mfaEnabled && enrolment && (
        <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5 space-y-5">
          <div>
            <h3 className="text-sm font-semibold mb-2">
              1 · Scan with your authenticator app
            </h3>
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
            <h3 className="text-sm font-semibold mb-2">
              2 · Save your recovery key
            </h3>
            <p className="text-xs text-amber-300 mb-3">
              Shown <strong>once</strong>. It is single-use — if you lose it
              and your authenticator, contact your admin to reset MFA.
            </p>
            <div className="px-3 py-2.5 rounded bg-white/[0.04] border border-white/[0.08] font-mono text-sm text-white/80 select-all text-center break-all">
              {enrolment.recoveryKey}
            </div>
            <div className="mt-3 flex gap-2">
              <button
                type="button"
                onClick={() => copy(enrolment.recoveryKey)}
                className="flex-1 h-9 rounded-lg border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] text-xs text-white/70 transition-all flex items-center justify-center gap-1.5"
              >
                {copied ? (
                  <>
                    <Check className="w-3 h-3" /> Copied
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" /> Copy key
                  </>
                )}
              </button>
            </div>
            <label className="mt-3 flex items-start gap-2 text-xs text-white/50 cursor-pointer select-none">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
              />
              <span>I&apos;ve saved my recovery key somewhere safe.</span>
            </label>
          </div>

          {acknowledged && (
            <form
              onSubmit={onConfirmEnroll}
              className="border-t border-white/[0.06] pt-5 space-y-3"
            >
              <h3 className="text-sm font-semibold">
                3 · Enter the 6-digit code from your authenticator
              </h3>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                maxLength={6}
                className="w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 text-sm text-white placeholder:text-white/20 outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 transition-all tracking-widest text-center font-mono"
                placeholder="123456"
                value={confirmCode}
                onChange={(e) => setConfirmCode(e.target.value)}
              />
              <button
                type="submit"
                disabled={confirming || confirmCode.trim().length === 0}
                className="w-full h-10 rounded-lg bg-gradient-to-r from-teal-500 to-cyan-500 text-sm font-semibold text-white shadow-lg shadow-teal-500/20 hover:brightness-110 transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {confirming ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Verifying…
                  </>
                ) : (
                  "Enable two-factor authentication"
                )}
              </button>
            </form>
          )}
        </div>
      )}

      {/* ── Manage when enabled ─────────────────────────── */}
      {status?.mfaEnabled && (
        <>
          {/* Regenerate */}
          <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold flex items-center gap-2">
                  <RefreshCcw className="w-4 h-4 text-white/60" />
                  Regenerate recovery key
                </h3>
                <p className="mt-1 text-xs text-white/50">
                  Invalidates your current key and creates a new one.
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  setShowRegen((v) => !v);
                  setRegenKey(null);
                }}
                className="h-9 px-3 rounded-lg border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] text-xs font-medium text-white/70 transition-all shrink-0"
              >
                {showRegen ? "Cancel" : "Regenerate"}
              </button>
            </div>

            {showRegen && (
              <form onSubmit={onRegenerate} className="mt-4 space-y-3">
                {status.hasPassword ? (
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-white/50 block">
                      Confirm with your password
                    </label>
                    <input
                      type="password"
                      autoComplete="current-password"
                      className="w-full h-10 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 text-sm text-white outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20"
                      value={regenPassword}
                      onChange={(e) => setRegenPassword(e.target.value)}
                    />
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-white/50 block">
                      Confirm with a current 6-digit code
                    </label>
                    <input
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={6}
                      className="w-full h-10 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 text-sm text-white outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 font-mono tracking-widest text-center"
                      value={regenCode}
                      onChange={(e) => setRegenCode(e.target.value)}
                    />
                  </div>
                )}
                <button
                  type="submit"
                  disabled={regenerating}
                  className="h-10 px-4 rounded-lg bg-gradient-to-r from-teal-500 to-cyan-500 text-sm font-semibold text-white hover:brightness-110 transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {regenerating ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Generating…
                    </>
                  ) : (
                    "Generate new key"
                  )}
                </button>
              </form>
            )}

            {regenKey && (
              <div className="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/[0.04] p-4">
                <p className="text-xs text-amber-300 mb-3 font-semibold">
                  New recovery key — shown once. Save it now.
                </p>
                <div className="px-3 py-2.5 rounded bg-white/[0.04] border border-white/[0.08] font-mono text-sm text-white/80 select-all text-center break-all">
                  {regenKey}
                </div>
                <div className="mt-3 flex gap-2">
                  <button
                    type="button"
                    onClick={() => copy(regenKey)}
                    className="flex-1 h-9 rounded-lg border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] text-xs text-white/70 transition-all flex items-center justify-center gap-1.5"
                  >
                    {copied ? (
                      <>
                        <Check className="w-3 h-3" /> Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" /> Copy
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={downloadRegen}
                    className="flex-1 h-9 rounded-lg border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] text-xs text-white/70 transition-all flex items-center justify-center gap-1.5"
                  >
                    <Download className="w-3 h-3" /> Download
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Disable */}
          <div className="rounded-xl border border-red-500/20 bg-red-500/[0.04] p-5">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold flex items-center gap-2 text-red-300">
                  <ShieldOff className="w-4 h-4" />
                  Disable two-factor authentication
                </h3>
                <p className="mt-1 text-xs text-red-300/70">
                  Removes the requirement to enter a code at sign-in.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowDisable((v) => !v)}
                className="h-9 px-3 rounded-lg border border-red-500/30 bg-red-500/[0.08] hover:bg-red-500/[0.12] text-xs font-medium text-red-300 transition-all shrink-0"
              >
                {showDisable ? "Cancel" : "Disable"}
              </button>
            </div>

            {showDisable && (
              <form onSubmit={onDisable} className="mt-4 space-y-3">
                {status.hasPassword ? (
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-white/50 block">
                      Confirm with your password
                    </label>
                    <input
                      type="password"
                      autoComplete="current-password"
                      className="w-full h-10 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 text-sm text-white outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20"
                      value={disablePassword}
                      onChange={(e) => setDisablePassword(e.target.value)}
                    />
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-white/50 block">
                      Confirm with a current 6-digit code
                    </label>
                    <input
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={6}
                      className="w-full h-10 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 text-sm text-white outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 font-mono tracking-widest text-center"
                      value={disableCode}
                      onChange={(e) => setDisableCode(e.target.value)}
                    />
                  </div>
                )}
                <button
                  type="submit"
                  disabled={disabling}
                  className="h-10 px-4 rounded-lg bg-red-500 hover:bg-red-600 text-sm font-semibold text-white transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {disabling ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Disabling…
                    </>
                  ) : (
                    "Disable two-factor authentication"
                  )}
                </button>
              </form>
            )}
          </div>
        </>
      )}
    </div>
  );
}
