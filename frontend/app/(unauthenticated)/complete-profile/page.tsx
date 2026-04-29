"use client";

import React, { useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowRight, Loader2 } from "lucide-react";
import { getNames } from "country-list";

import { updateProfile } from "../../lib/api";

const COUNTRIES: string[] = getNames().sort();

function BoltIcon({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className="shrink-0">
      <rect width="32" height="32" rx="7" fill="#0a0f1e"/>
      <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#14b8a6"/>
    </svg>
  );
}

const inputClass =
  "w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 text-sm text-white placeholder:text-white/20 outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 transition-all";

function CompleteProfileInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const next = searchParams?.get("next") || "/dashboard";

  const [jobTitle, setJobTitle] = useState("");
  const [company, setCompany] = useState("");
  const [country, setCountry] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const hasAnyField = jobTitle.trim() || company.trim() || country;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!hasAnyField || loading) return;
    try {
      setLoading(true);
      setError(null);
      await updateProfile({
        jobTitle: jobTitle.trim() || undefined,
        company: company.trim() || undefined,
        country: country || undefined,
      });
      router.replace(next);
    } catch (err: any) {
      setError(err?.message || "Failed to save profile. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  function onSkip() {
    router.replace(next);
  }

  return (
    <div className="min-h-screen bg-[#060b18] flex items-center justify-center p-6">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex items-center gap-2.5 mb-10 justify-center">
          <BoltIcon size={28} />
          <span className="text-base font-semibold text-white">
            Nano<span className="text-teal-400">EASM</span>
          </span>
        </div>

        <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-8">
          <h1 className="text-lg font-semibold text-white mb-1">Complete your profile</h1>
          <p className="text-sm text-white/40 mb-6">
            Help us personalise your experience. All fields are optional.
          </p>

          <form onSubmit={onSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-white/50 block">Job title</label>
                <input
                  className={inputClass}
                  placeholder="Security Engineer"
                  value={jobTitle}
                  onChange={(e) => setJobTitle(e.target.value)}
                  autoComplete="organization-title"
                  autoFocus
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

            {error && (
              <div className="rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3.5 py-2.5 text-sm text-red-300">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={!hasAnyField || loading}
              className="w-full h-11 rounded-lg bg-gradient-to-r from-teal-500 to-cyan-500 text-sm font-semibold text-white shadow-lg shadow-teal-500/20 hover:shadow-teal-500/35 transition-all hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Saving…
                </>
              ) : (
                <>
                  Save and continue
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        </div>

        <p className="mt-4 text-center">
          <button
            onClick={onSkip}
            className="text-sm text-white/25 hover:text-white/40 transition-colors"
          >
            Skip for now
          </button>
        </p>
      </div>
    </div>
  );
}

export default function CompleteProfilePage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-[#060b18] flex items-center justify-center">
        <div className="text-sm text-white/40">Loading…</div>
      </div>
    }>
      <CompleteProfileInner />
    </Suspense>
  );
}
