// app/(unauthenticated)/register/page.tsx
"use client";

import React, { useEffect, useMemo, useState, Suspense } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowRight, Eye, EyeOff, Loader2, Users } from "lucide-react";

import { register, apiFetch, startOAuth } from "../../lib/api";

const GOOGLE_ENABLED = process.env.NEXT_PUBLIC_GOOGLE_OAUTH_ENABLED === "true";
const MICROSOFT_ENABLED = process.env.NEXT_PUBLIC_MICROSOFT_OAUTH_ENABLED === "true";
import { establishSession, type AuthRole } from "../../lib/auth";
import { BILLING_ENABLED } from "../../lib/billing-config";

import { getNames } from "country-list";

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

const COUNTRIES: string[] = getNames().sort();

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
  const [acceptedTerms, setAcceptedTerms] = useState(false);

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
    acceptedTerms &&
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
        (res.role || (inviteToken ? inviteInfo?.role : "owner") || "owner") as AuthRole,
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
              Nano<span className="text-teal-400">EASM</span>
            </span>
          </Link>

          {/* Value prop */}
          <div className="max-w-sm">
            <h2 className="text-2xl font-bold leading-tight tracking-tight">
              Start securing your attack surface
              <span className="block text-white/40 font-normal text-lg mt-1">in minutes, not months</span>
            </h2>

            <div className="mt-8 space-y-4">
              {[
                "Discover subdomains and exposed assets",
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
              : BILLING_ENABLED ? "No credit card required. Start scanning in minutes." : "Free to use. Start scanning in minutes."}
          </p>

          {/* OAuth — hide for invite flow */}
          {!inviteToken && (GOOGLE_ENABLED || MICROSOFT_ENABLED) && (
            <>
              <div className="mt-6 space-y-2.5">
                {GOOGLE_ENABLED && (
                  <button
                    type="button"
                    onClick={() => {
                      if (!acceptedTerms) { setError("Please accept the Terms of Use to continue."); return; }
                      startOAuth("google", nextPath);
                    }}
                    disabled={!acceptedTerms}
                    className="w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] text-sm font-medium text-white transition-all flex items-center justify-center gap-2.5 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-white/[0.03]"
                  >
                    <GoogleIcon />
                    Continue with Google
                  </button>
                )}
                {MICROSOFT_ENABLED && (
                  <button
                    type="button"
                    onClick={() => {
                      if (!acceptedTerms) { setError("Please accept the Terms of Use to continue."); return; }
                      startOAuth("microsoft", nextPath);
                    }}
                    disabled={!acceptedTerms}
                    className="w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.06] text-sm font-medium text-white transition-all flex items-center justify-center gap-2.5 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-white/[0.03]"
                  >
                    <MicrosoftIcon />
                    Continue with Microsoft
                  </button>
                )}
              </div>
              <div className="mt-6 flex items-center gap-3">
                <div className="flex-1 h-px bg-white/[0.06]" />
                <span className="text-xs text-white/20">or sign up with email</span>
                <div className="flex-1 h-px bg-white/[0.06]" />
              </div>
            </>
          )}

          <form className={inviteToken ? "mt-8 space-y-4" : "mt-6 space-y-4"} onSubmit={onSubmit}>
            {/* Name */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-white/50 block">Full name</label>
              <input
                className={inputClass}
                placeholder="Jane Smith"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="name"
                autoFocus
                required
              />
            </div>

            {/* Email */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-white/50 block">Email</label>
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
                  <select
                    className={`${inputClass} appearance-none`}
                    style={{ backgroundColor: '#0d1427' }}
                    value={country}
                    onChange={(e) => setCountry(e.target.value)}
                    autoComplete="country"
                  >
                    <option value="">Select your country</option>
                    {COUNTRIES.map((c) => (
                      <option key={c} value={c}>{c}</option>
                    ))}
                  </select>
                </div>
              </div>
            )}

            {/* Terms acceptance */}
            <label className={`flex items-start gap-3 rounded-lg border px-3.5 py-3 cursor-pointer transition-all ${
              acceptedTerms
                ? "border-teal-500/30 bg-teal-500/[0.05]"
                : "border-amber-500/30 bg-amber-500/[0.05]"
            }`}>
              <input
                type="checkbox"
                checked={acceptedTerms}
                onChange={(e) => { setAcceptedTerms(e.target.checked); if (e.target.checked) setError(null); }}
                className="mt-0.5 h-4 w-4 shrink-0 accent-teal-500 cursor-pointer"
                required
              />
              <span className="text-xs leading-relaxed text-white/70">
                I agree to the{" "}
                <Link href="/terms" target="_blank" className="text-teal-400 hover:text-teal-300 underline underline-offset-2">
                  Terms of Use
                </Link>
                .
              </span>
            </label>

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