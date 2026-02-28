// app/lib/useSessionGuard.ts
"use client";
import { useEffect } from "react";
import { getAccessToken, isInactive, clearSession } from "./auth";

/**
 * Checks session validity when the user returns to the tab
 * (visibilitychange) plus a long fallback interval (60s).
 *
 * If the token is gone or inactivity timeout exceeded,
 * redirects to /login immediately.
 *
 * Usage: call useSessionGuard() once in your authenticated layout.
 */
export function useSessionGuard() {
  useEffect(() => {
    function check() {
      // Don't run on login/register pages
      const path = window.location.pathname;
      if (path.startsWith("/login") || path.startsWith("/register")) return;

      const token = getAccessToken();
      if (!token || isInactive()) {
        clearSession();
        window.location.href = `/login?next=${encodeURIComponent(path)}&expired=true`;
      }
    }

    function onVisibilityChange() {
      if (document.visibilityState === "visible") check();
    }

    document.addEventListener("visibilitychange", onVisibilityChange);
    const id = setInterval(check, 60_000);

    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
      clearInterval(id);
    };
  }, []);
}