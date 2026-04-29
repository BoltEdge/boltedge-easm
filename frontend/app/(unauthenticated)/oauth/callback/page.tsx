"use client";

import { useEffect, useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";

import { apiFetch } from "../../../lib/api";
import { establishSession } from "../../../lib/auth";

function OAuthCallbackInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = searchParams?.get("token");
    const next = searchParams?.get("next") || "/dashboard";
    const oauthError = searchParams?.get("oauth_error");

    if (oauthError) {
      const messages: Record<string, string> = {
        access_denied: "You cancelled the sign-in. Please try again.",
        invalid_state: "Sign-in session expired. Please try again.",
        token_exchange_failed: "Could not complete sign-in. Please try again.",
        userinfo_failed: "Could not retrieve your profile. Please try again.",
        missing_profile: "Your Google account is missing an email address.",
      };
      setError(messages[oauthError] || "Sign-in failed. Please try again.");
      return;
    }

    if (!token) {
      setError("Sign-in failed. Please try again.");
      return;
    }

    const isNewUser = searchParams?.get("new_user") === "1";

    apiFetch<any>("/auth/me", {
      headers: { Authorization: `Bearer ${token}` },
    } as any)
      .then((data) => {
        establishSession({
          accessToken: token,
          user: data.user,
          organization: data.organization,
          role: data.role ?? "owner",
        });
        if (isNewUser) {
          router.replace(`/complete-profile?next=${encodeURIComponent(next.startsWith("/") ? next : "/dashboard")}`);
        } else {
          router.replace(next.startsWith("/") ? next : "/dashboard");
        }
      })
      .catch(() => setError("Could not load your account. Please try again."));
  }, [searchParams, router]);

  if (error) {
    return (
      <div className="min-h-screen bg-[#060b18] flex items-center justify-center px-4">
        <div className="w-full max-w-sm text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-red-500/10 flex items-center justify-center mx-auto">
            <svg className="w-6 h-6 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </div>
          <h1 className="text-lg font-semibold text-white">Sign-in failed</h1>
          <p className="text-sm text-white/40">{error}</p>
          <a href="/login" className="inline-block text-sm text-teal-400 hover:text-teal-300 transition-colors">
            Back to sign in
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#060b18] flex items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <Loader2 className="w-6 h-6 text-teal-400 animate-spin" />
        <p className="text-sm text-white/40">Signing you in…</p>
      </div>
    </div>
  );
}

export default function OAuthCallbackPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-[#060b18] flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-teal-400 animate-spin" />
      </div>
    }>
      <OAuthCallbackInner />
    </Suspense>
  );
}
