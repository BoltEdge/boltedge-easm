// app/(unauthenticated)/register/page.tsx
// F4: Redesigned registration with split layout, BoltEdge branding, and invite support
"use client";

import React, { useEffect, useMemo, useState, Suspense } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowRight, Eye, EyeOff, Loader2, Users } from "lucide-react";

import { register, apiFetch } from "../../lib/api";
import { establishSession, type AuthRole } from "../../lib/auth";

function BoltIcon({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className="shrink-0">
      <rect width="32" height="32" rx="7" fill="#0a0f1e"/>
      <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#14b8a6"/>
    </svg>
  );
}

function RegisterPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const inviteToken = useMemo(() => searchParams?.get("invite") || null, [searchParams]);

  const nextPath = useMemo(() => {
    const n = searchParams?.get("next");
    return n && n.startsWith("/") ? n : "/assets";
  }, [searchParams]);

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [jobTitle, setJobTitle] = useState("");
  const [company, setCompany] = useState("");
  const [country, setCountry] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Invite info
  const [inviteInfo, setInviteInfo] = useState<{
    email: string;
    role: string;
    organizationName: string;
  } | null>(null);
  const [inviteLoading, setInviteLoading] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);

  useEffect(() => {
    if (!inviteToken) return;
    setInviteLoading(true);
    apiFetch<any>(`/settings/invitations/${inviteToken}`)
      .then((data) => {
        setInviteInfo(data);
        if (data.email) setEmail(data.email);
      })
      .catch((e: any) => setInviteError(e?.message || "Invalid invitation"))
      .finally(() => setInviteLoading(false));
  }, [inviteToken]);

  const canSubmit =
    name.trim().length > 0 &&
    email.trim().length > 0 &&
    password.length >= 8 &&
    !loading;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;

    try {
      setLoading(true);
      setError(null);

      const res = await register({
        name: name.trim(),
        email: email.trim().toLowerCase(),
        password,
        job_title: jobTitle.trim() || undefined,
        company: company.trim() || undefined,
        country: country.trim() || undefined,
        invite_token: inviteToken || undefined,
      });

      establishSession(
        res.accessToken,
        res.user,
        res.organization,
        ((res as any).role || (inviteToken ? inviteInfo?.role : "owner") || "owner") as AuthRole,
      );

      router.replace(nextPath);
    } catch (err: any) {
      setError(err?.message || "Registration failed");
    } finally {
      setLoading(false);
    }
  }

  const inputClass =
    "w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 text-sm text-white placeholder:text-white/20 outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed";

  return (
    <div className="min-h-screen bg-[#060b18] text-white flex">
      {/* ── Left Panel: Branding ── */}
      <div className="hidden lg:flex lg:w-[45%] relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-teal-500/[0.08] via-[#060b18] to-cyan-500/[0.05]" />
        <div className="absolute bottom-1/4 right-1/4 w-[400px] h-[400px] bg-cyan-500/[0.06] rounded-full blur-[100px]" />
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
              Bolt<span className="text-teal-400">Edge</span>
              <span className="text-[10px] text-white/40 font-medium ml-1.5 uppercase tracking-wider">EASM</span>
            </span>
          </Link>

          {/* Social proof */}
          <div className="max-w-sm">
            <h2 className="text-2xl font-bold leading-tight tracking-tight">
              Trusted by security teams
              <span className="block text-white/40 font-normal text-lg mt-1">to manage their attack surface</span>
            </h2>

            <div className="mt-8 space-y-5">
              {[
                { stat: "10K+", label: "Assets monitored" },
                { stat: "50K+", label: "Findings detected" },
                { stat: "99.9%", label: "Platform uptime" },
              ].map(({ stat, label }) => (
                <div key={label} className="flex items-center gap-4">
                  <span className="text-2xl font-bold text-teal-400">{stat}</span>
                  <span className="text-sm text-white/40">{label}</span>
                </div>
              ))}
            </div>
          </div>

          <p className="text-xs text-white/20">
            &copy; {new Date().getFullYear()} BoltEdge
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
                Bolt<span className="text-teal-400">Edge</span>
                <span className="text-[10px] text-white/40 font-medium ml-1.5 uppercase tracking-wider">EASM</span>
              </span>
            </Link>
          </div>

          {/* Invite Banner */}
          {inviteToken && inviteInfo && (
            <div className="mb-6 rounded-xl border border-teal-500/20 bg-teal-500/[0.05] p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-teal-500/10 flex items-center justify-center shrink-0">
                  <Users className="w-5 h-5 text-teal-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-white">
                    Join <span className="font-semibold text-teal-300">{inviteInfo.organizationName}</span>
                  </p>
                  <p className="text-xs text-white/40 mt-0.5">
                    Role: <span className="capitalize font-medium text-white/60">{inviteInfo.role}</span>
                  </p>
                </div>
              </div>
            </div>
          )}

          {inviteToken && inviteLoading && (
            <div className="mb-6 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 text-sm text-white/40 flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading invitation...
            </div>
          )}

          {inviteToken && inviteError && (
            <div className="mb-6 rounded-xl border border-red-500/20 bg-red-500/[0.06] p-4 text-sm text-red-300">
              {inviteError}
            </div>
          )}

          <h1 className="text-2xl font-bold tracking-tight">
            {inviteInfo ? "Create your account" : "Get started free"}
          </h1>
          <p className="mt-2 text-sm text-white/40">
            {inviteInfo
              ? `Sign up to join ${inviteInfo.organizationName}`
              : "No credit card required. Start scanning in minutes."}
          </p>

          <form className="mt-8 space-y-4" onSubmit={onSubmit}>
            {/* Name */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-white/50 block">Full name</label>
              <input
                className={inputClass}
                placeholder="Jane Smith"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="name"
                required
              />
            </div>

            {/* Email */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-white/50 block">Work email</label>
              <input
                type="email"
                className={inputClass}
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                inputMode="email"
                required
                disabled={!!inviteInfo?.email}
              />
              {inviteInfo?.email && (
                <p className="text-[11px] text-white/25">Pre-filled from invitation</p>
              )}
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-white/50 block">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  className={`${inputClass} pr-10`}
                  placeholder="Minimum 8 characters"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-white/20 hover:text-white/40 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {password.length > 0 && password.length < 8 && (
                <p className="text-[11px] text-amber-400/70">Must be at least 8 characters</p>
              )}
            </div>

            {/* Optional fields — hide for invite flow */}
            {!inviteToken && (
              <div className="pt-3 border-t border-white/[0.04] space-y-4">
                <p className="text-[11px] text-white/20 uppercase tracking-wider">Optional</p>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-white/50 block">Job title</label>
                    <input
                      className={inputClass}
                      placeholder="Security Engineer"
                      value={jobTitle}
                      onChange={(e) => setJobTitle(e.target.value)}
                      autoComplete="organization-title"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-white/50 block">Company</label>
                    <input
                      className={inputClass}
                      placeholder="Acme Corp"
                      value={company}
                      onChange={(e) => setCompany(e.target.value)}
                      autoComplete="organization"
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-white/50 block">Country</label>
                  <input
                    className={inputClass}
                    placeholder="Australia"
                    value={country}
                    onChange={(e) => setCountry(e.target.value)}
                    autoComplete="country-name"
                  />
                </div>
              </div>
            )}

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
                  Creating account...
                </>
              ) : inviteInfo ? (
                <>
                  Join {inviteInfo.organizationName}
                  <ArrowRight className="w-4 h-4" />
                </>
              ) : (
                <>
                  Create free account
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Footer */}
          <p className="mt-6 text-sm text-white/30 text-center">
            Already have an account?{" "}
            <Link
              href={inviteToken ? `/login?invite=${inviteToken}` : "/login"}
              className="text-teal-400 hover:text-teal-300 font-medium transition-colors"
            >
              Sign in
            </Link>
          </p>

          <p className="mt-4 text-[11px] text-white/15 text-center">
            By creating an account you agree to our{" "}
            <Link href="/terms" className="underline hover:text-white/30 transition-colors">Terms</Link>
            {" "}and{" "}
            <Link href="/privacy" className="underline hover:text-white/30 transition-colors">Privacy Policy</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default function RegisterPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[#060b18] flex items-center justify-center">
          <div className="text-sm text-white/40">Loading…</div>
        </div>
      }
    >
      <RegisterPageInner />
    </Suspense>
  );
}