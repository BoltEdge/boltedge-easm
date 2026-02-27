"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { Shield, Check, X, AlertCircle, Loader2, Users, LogIn } from "lucide-react";
import { Button } from "../../../ui/button";
import { apiFetch } from "../../../lib/api";

export default function InvitePage() {
  const params = useParams<{ token: string }>();
  const router = useRouter();
  const token = params?.token;

  const [invite, setInvite] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [accepting, setAccepting] = useState(false);
  const [accepted, setAccepted] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    // Check if user is logged in
    const hasToken = typeof window !== "undefined" && (
      localStorage.getItem("accessToken") ||
      sessionStorage.getItem("accessToken") ||
      document.cookie.includes("accessToken")
    );
    setIsLoggedIn(!!hasToken);
  }, []);

  useEffect(() => {
    if (!token) return;
    setLoading(true);
    apiFetch<any>(`/settings/invitations/${token}`)
      .then(setInvite)
      .catch((e: any) => setError(e?.message || "Invalid or expired invitation"))
      .finally(() => setLoading(false));
  }, [token]);

  async function handleAccept() {
    if (!token) return;
    try {
      setAccepting(true);
      await apiFetch<any>(`/settings/invitations/${token}/accept`, { method: "POST" });
      setAccepted(true);
      setTimeout(() => router.push("/dashboard"), 2000);
    } catch (e: any) {
      setError(e?.message || "Failed to accept invitation");
    } finally {
      setAccepting(false);
    }
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-card border border-border rounded-2xl p-8 text-center space-y-6">
          {/* Logo */}
          <div className="flex justify-center">
            <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center">
              <Shield className="w-8 h-8 text-primary" />
            </div>
          </div>

          {loading ? (
            <div className="space-y-3">
              <Loader2 className="w-8 h-8 text-primary animate-spin mx-auto" />
              <p className="text-muted-foreground text-sm">Loading invitation...</p>
            </div>
          ) : error ? (
            <div className="space-y-4">
              <div className="w-14 h-14 rounded-full bg-red-500/10 flex items-center justify-center mx-auto">
                <X className="w-7 h-7 text-red-400" />
              </div>
              <h1 className="text-xl font-semibold text-foreground">Invitation Invalid</h1>
              <p className="text-muted-foreground text-sm">{error}</p>
              <Button onClick={() => router.push("/login")} variant="outline" className="border-border text-foreground hover:bg-accent">
                Go to Login
              </Button>
            </div>
          ) : accepted ? (
            <div className="space-y-4">
              <div className="w-14 h-14 rounded-full bg-[#10b981]/10 flex items-center justify-center mx-auto">
                <Check className="w-7 h-7 text-[#10b981]" />
              </div>
              <h1 className="text-xl font-semibold text-foreground">Welcome!</h1>
              <p className="text-muted-foreground text-sm">
                You've joined <span className="text-foreground font-semibold">{invite?.organizationName}</span> as <span className="font-semibold capitalize">{invite?.role}</span>.
              </p>
              <p className="text-xs text-muted-foreground">Redirecting to dashboard...</p>
            </div>
          ) : (
            <div className="space-y-5">
              <h1 className="text-xl font-semibold text-foreground">You're Invited!</h1>
              <p className="text-muted-foreground text-sm">
                You've been invited to join <span className="text-foreground font-semibold">{invite?.organizationName}</span> as a <span className="font-semibold capitalize">{invite?.role}</span>.
              </p>

              {/* Invite Details */}
              <div className="bg-muted/30 rounded-xl p-4 border border-border text-left space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Organization</span>
                  <span className="text-foreground font-medium">{invite?.organizationName}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Role</span>
                  <span className="text-foreground font-medium capitalize">{invite?.role}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Email</span>
                  <span className="text-foreground font-medium">{invite?.email}</span>
                </div>
              </div>

              {isLoggedIn ? (
                /* User is logged in — accept directly */
                <div className="flex flex-col gap-3 pt-2">
                  <Button onClick={handleAccept} disabled={accepting} className="w-full bg-primary hover:bg-primary/90">
                    {accepting ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Accepting...</> : <><Check className="w-4 h-4 mr-2" />Accept Invitation</>}
                  </Button>
                  <Button variant="outline" onClick={() => router.push("/dashboard")} className="w-full border-border text-foreground hover:bg-accent">
                    Decline
                  </Button>
                </div>
              ) : (
                /* User is NOT logged in — offer register or login */
                <div className="flex flex-col gap-3 pt-2">
                  <Button onClick={() => router.push(`/register?invite=${token}`)} className="w-full bg-primary hover:bg-primary/90">
                    <Users className="w-4 h-4 mr-2" />Create Account & Join
                  </Button>
                  <Button variant="outline" onClick={() => router.push(`/login?invite=${token}`)} className="w-full border-border text-foreground hover:bg-accent">
                    <LogIn className="w-4 h-4 mr-2" />I Already Have an Account
                  </Button>
                </div>
              )}
            </div>
          )}

          {/* BoltEdge EASM branding */}
          <div className="pt-4 border-t border-border">
            <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
              <Shield className="w-3.5 h-3.5" />BoltEdge EASM
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}