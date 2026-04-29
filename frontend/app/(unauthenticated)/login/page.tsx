// app/(unauthenticated)/login/page.tsx
// F4: Redesigned login with split layout, Nano ASM branding
"use client";

import React, { useMemo, useState, Suspense } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowRight, Eye, EyeOff, Loader2 } from "lucide-react";

import { login, startOAuth } from "../../lib/api";
import { establishSession } from "../../lib/auth";

const GOOGLE_ENABLED = process.env.NEXT_PUBLIC_GOOGLE_OAUTH_ENABLED === "true";
const MICROSOFT_ENABLED = process.env.NEXT_PUBLIC_MICROSOFT_OAUTH_ENABLED === "true";

function MicrosoftIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
      <path d="M0 0h8.571v8.571H0z" fill="#F25022"/>
      <path d="M9.429 0H18v8.571H9.429z" fill="#7FBA00"/>
      <path d="M0 9.429h8.571V18H0z" fill="#00A4EF"/>
      <path d="M9.429 9.429H18V18H9.429z" fill="#FFB900"/>
    </svg>
  );
}

function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
      <path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.874 2.684-6.615z" fill="#4285F4"/>
      <path d="M9 18c2.43 0 4.467-.806 5.956-2.184l-2.908-2.258c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332C2.438 15.983 5.482 18 9 18z" fill="#34A853"/>
      <path d="M3.964 10.707A5.41 5.41 0 013.682 9c0-.593.102-1.17.282-1.707V4.961H.957C.347 6.175 0 7.55 0 9s.347 2.825.957 4.039l3.007-2.332z" fill="#FBBC05"/>
      <path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0 5.482 0 2.438 2.017.957 4.961L3.964 6.293C4.672 4.166 6.656 3.58 9 3.58z" fill="#EA4335"/>
    </svg>
  );
}

function BoltIcon({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className="shrink-0">
      <rect width="32" height="32" rx="7" fill="#0a0f1e"/>
      <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#14b8a6"/>
    </svg>
  );
}

function LoginPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const nextPath = useMemo(() => {
    const n = searchParams?.get("next");
    return n && n.startsWith("/") ? n : "/dashboard";
  }, [searchParams]);

  const isExpired = useMemo(() => {
    return searchParams?.get("expired") === "true";
  }, [searchParams]);

  const suspendedReason = useMemo(() => {
    if (searchParams?.get("suspended") !== "true") return null;
    return searchParams?.get("reason") || "Your access has been suspended. Please contact your admin or reach out to Nano EASM support.";
  }, [searchParams]);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showExpiredBanner, setShowExpiredBanner] = useState(isExpired);

  const canSubmit = email.trim().length > 0 && password.length > 0 && !loading;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    try {
      setLoading(true);
      setError(null);

      const res = await login({
        email: email.trim().toLowerCase(),
        password,
      });

      establishSession({
        accessToken: res.accessToken,
        user: res.user,
        organization: res.organization,
        role: res.role ?? "owner",
      });

      router.replace(nextPath);
    } catch (err: any) {
      setError(err?.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#060b18] text-white flex">
      {/* ── Left Panel: Branding ── */}
      <div className="hidden lg:flex lg:w-[45%] relative overflow-hidden">
        {/* Background effects */}
        <div className="absolute inset-0 bg-gradient-to-br from-teal-500/[0.08] via-[#060b18] to-cyan-500/[0.05]" />
        <div className="absolute top-1/4 left-1/4 w-[400px] h-[400px] bg-teal-500/[0.06] rounded-full blur-[100px]" />
        <div
          className="absolute inset-0 opacity-[0.02]"
          style={{
            backgroundImage: `linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)`,
            backgroundSize: "40px 40px",
          }}
        />

        <div className="relative flex flex-col justify-between p-12 w-full">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2.5">
            <BoltIcon size={32} />
            <span className="text-lg font-semibold tracking-tight">
              Nano<span className="text-teal-400">EASM</span>
            </span>
          </Link>

          {/* Value prop */}
          <div className="max-w-sm">
            <h2 className="text-2xl font-bold leading-tight tracking-tight">
              Manage your attack surface
              <span className="block text-white/40 font-normal text-lg mt-1">from a single dashboard</span>
            </h2>

            <div className="mt-8 space-y-4">
              {[
                "Discover assets automatically",
                "Scan for vulnerabilities continuously",
                "Track remediation with full audit trail",
              ].map((item) => (
                <div key={item} className="flex items-center gap-3">
                  <div className="w-5 h-5 rounded-full bg-teal-500/15 flex items-center justify-center shrink-0">
                    <div className="w-1.5 h-1.5 rounded-full bg-teal-400" />
                  </div>
                  <span className="text-sm text-white/50">{item}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Footer */}
          <p className="text-xs text-white/20">
            &copy; {new Date().getFullYear()} Nano EASM
          </p>
        </div>
      </div>

      {/* ── Right Panel: Form ── */}
      <div className="flex-1 flex items-center justify-center p-6 sm:p-10">
        <div className="w-full max-w-sm">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-2.5 mb-10">
            <Link href="/" className="flex items-center gap-2.5">
              <BoltIcon size={28} />
              <span className="text-base font-semibold">
                Nano<span className="text-teal-400">EASM</span>
              </span>
            </Link>
          </div>

          <h1 className="text-2xl font-bold tracking-tight">Welcome back</h1>
          <p className="mt-2 text-sm text-white/40">
            Sign in to your account to continue
          </p>

          {/* OAuth */}
          {(GOOGLE_ENABLED || MICROSOFT_ENABLED) && (
            <>
              <div className="mt-6 space-y-2.5">
                {GOOGLE_ENABLED && (
                  <button
                    type="button"
                    onClick={() => startOAuth("google", nextPath)}
                    className="w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] text-sm font-medium text-white transition-all flex items-center justify-center gap-2.5"
                  >
                    <GoogleIcon />
                    Continue with Google
                  </button>
                )}
                {MICROSOFT_ENABLED && (
                  <button
                    type="button"
                    onClick={() => startOAuth("microsoft", nextPath)}
                    className="w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] text-sm font-medium text-white transition-all flex items-center justify-center gap-2.5"
                  >
                    <MicrosoftIcon />
                    Continue with Microsoft
                  </button>
                )}
              </div>
              <div className="mt-6 flex items-center gap-3">
                <div className="flex-1 h-px bg-white/[0.06]" />
                <span className="text-xs text-white/20">or sign in with email</span>
                <div className="flex-1 h-px bg-white/[0.06]" />
              </div>
            </>
          )}

          {/* Session expired banner */}
          {showExpiredBanner && (
            <div className="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/[0.06] px-3.5 py-2.5 text-sm text-amber-300 flex items-center justify-between">
              <span>Your session has expired. Please sign in again.</span>
              <button onClick={() => setShowExpiredBanner(false)} className="text-amber-400/60 hover:text-amber-300 ml-2 shrink-0">
                &times;
              </button>
            </div>
          )}

          {/* Suspended banner */}
          {suspendedReason && (
            <div className="mt-4 rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3.5 py-2.5 text-sm text-red-300">
              {suspendedReason}
            </div>
          )}

          <form className="mt-8 space-y-4" onSubmit={onSubmit}>
            {/* Email */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-white/50 block">Email</label>
              <input
                type="email"
                className="w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 text-sm text-white placeholder:text-white/20 outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 transition-all"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                inputMode="email"
                autoFocus
              />
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-white/50 block">Password</label>
                <Link href="/forgot-password" className="text-xs text-teal-400/70 hover:text-teal-300 transition-colors">
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  className="w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 pr-10 text-sm text-white placeholder:text-white/20 outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 transition-all"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-white/20 hover:text-white/40 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3.5 py-2.5 text-sm text-red-300">
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={!canSubmit}
              className="w-full h-11 rounded-lg bg-gradient-to-r from-teal-500 to-cyan-500 text-sm font-semibold text-white shadow-lg shadow-teal-500/20 hover:shadow-teal-500/35 transition-all hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:brightness-100 disabled:hover:shadow-teal-500/20 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Signing in...
                </>
              ) : (
                <>
                  Sign in
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Footer link */}
          <p className="mt-6 text-sm text-white/30 text-center">
            Don&apos;t have an account?{" "}
            <Link href="/register" className="text-teal-400 hover:text-teal-300 font-medium transition-colors">
              Create one free
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[#060b18] flex items-center justify-center">
          <div className="text-sm text-white/40">Loading…</div>
        </div>
      }
    >
      <LoginPageInner />
    </Suspense>
  );
}