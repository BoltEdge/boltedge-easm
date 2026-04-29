"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { verifyPasswordResetToken, consumePasswordReset } from "../../../lib/api";
import { Eye, EyeOff } from "lucide-react";
import Link from "next/link";

export default function ResetPasswordPage() {
  const { token } = useParams<{ token: string }>();
  const router = useRouter();

  const [status, setStatus] = useState<"verifying" | "ready" | "invalid" | "done">("verifying");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function verify() {
      try {
        const res = await verifyPasswordResetToken(token);
        if (res.valid) {
          setEmail(res.email);
          setStatus("ready");
        } else {
          setStatus("invalid");
        }
      } catch {
        setStatus("invalid");
      }
    }
    if (token) verify();
  }, [token]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await consumePasswordReset(token, password);
      setStatus("done");
    } catch (e: any) {
      setError(e?.message || "Failed to reset password. The link may have expired.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#060b18] flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <span className="text-xl font-bold text-white">
            Nano<span className="text-teal-400">EASM</span>
          </span>
        </div>

        <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-8">
          {status === "verifying" && (
            <p className="text-white/40 text-sm text-center">Verifying link…</p>
          )}

          {status === "invalid" && (
            <div className="text-center space-y-3">
              <h1 className="text-lg font-semibold text-white">Link expired or invalid</h1>
              <p className="text-sm text-white/40">
                This password reset link has expired or already been used.
              </p>
              <Link href="/forgot-password" className="inline-block mt-2 text-sm text-teal-400 hover:text-teal-300 transition-colors">
                Request a new link
              </Link>
            </div>
          )}

          {status === "done" && (
            <div className="text-center space-y-3">
              <div className="w-12 h-12 rounded-full bg-emerald-500/10 flex items-center justify-center mx-auto">
                <svg className="w-6 h-6 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h1 className="text-lg font-semibold text-white">Password updated</h1>
              <p className="text-sm text-white/40">You can now log in with your new password.</p>
              <Link href="/login" className="inline-block mt-2 text-sm text-teal-400 hover:text-teal-300 transition-colors">
                Go to login
              </Link>
            </div>
          )}

          {status === "ready" && (
            <>
              <h1 className="text-lg font-semibold text-white mb-1">Set a new password</h1>
              <p className="text-xs text-white/40 mb-6">For <span className="text-white/60">{email}</span></p>

              <form onSubmit={onSubmit} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-white/50 block">New password</label>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Min. 8 characters"
                      autoFocus
                      className="w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 pr-10 text-sm text-white placeholder:text-white/20 outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 transition-all"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60 transition-colors"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {error && (
                  <p className="text-xs text-red-400">{error}</p>
                )}

                <button
                  type="submit"
                  disabled={submitting || password.length < 8}
                  className="w-full h-11 rounded-lg bg-teal-500 hover:bg-teal-400 text-white text-sm font-semibold transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {submitting ? "Updating…" : "Set new password"}
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
