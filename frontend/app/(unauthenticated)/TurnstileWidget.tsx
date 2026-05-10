"use client";

// Cloudflare Turnstile widget. Loads Cloudflare's script once globally
// (browser dedupes the script tag by src) and renders a verification
// widget into a container. Calls `onVerify(token)` when the challenge
// passes — the parent stores that token and submits it with the form.
//
// To trigger a fresh challenge after a successful submit, the parent
// can change the component's `key` prop. That remounts the component
// and forces a new widget render with a fresh token.
//
// When NEXT_PUBLIC_TURNSTILE_SITE_KEY is unset, this component renders
// nothing — letting local dev work without a Turnstile account. The
// backend mirrors the same behaviour: when TURNSTILE_SECRET_KEY is unset,
// verify_turnstile() is a no-op. Both must be set in production.

import Script from "next/script";
import { useEffect, useRef, useState } from "react";

type TurnstileOptions = {
  sitekey: string;
  theme?: "light" | "dark" | "auto";
  size?: "normal" | "flexible" | "compact";
  callback?: (token: string) => void;
  "expired-callback"?: () => void;
  "error-callback"?: () => void;
};

declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement | string, options: TurnstileOptions) => string;
      reset: (widgetId?: string) => void;
      remove: (widgetId?: string) => void;
      getResponse: (widgetId?: string) => string | undefined;
    };
  }
}

const SITE_KEY = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || "";

type Props = {
  /** Called when the user passes the challenge (or it resolves invisibly). */
  onVerify: (token: string) => void;
  /** Called when the token expires (~5 minutes after issue). */
  onExpire?: () => void;
  /** Called if the challenge fails on Cloudflare's side (network/internal). */
  onError?: () => void;
  className?: string;
  size?: "normal" | "compact" | "flexible";
};

export default function TurnstileWidget({
  onVerify,
  onExpire,
  onError,
  className,
  size = "flexible",
}: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const widgetIdRef = useRef<string | null>(null);
  const [scriptReady, setScriptReady] = useState<boolean>(
    typeof window !== "undefined" && !!window.turnstile
  );

  // Latest callbacks via refs so the render effect doesn't re-run every
  // time the parent re-renders with new function identities — that would
  // tear down and re-create the widget on every keystroke.
  const onVerifyRef = useRef(onVerify);
  const onExpireRef = useRef(onExpire);
  const onErrorRef = useRef(onError);
  useEffect(() => { onVerifyRef.current = onVerify; }, [onVerify]);
  useEffect(() => { onExpireRef.current = onExpire; }, [onExpire]);
  useEffect(() => { onErrorRef.current = onError; }, [onError]);

  useEffect(() => {
    if (!SITE_KEY) return;
    if (!scriptReady) return;
    if (!containerRef.current) return;
    if (widgetIdRef.current) return; // already rendered

    const ts = window.turnstile;
    if (!ts) return;

    try {
      widgetIdRef.current = ts.render(containerRef.current, {
        sitekey: SITE_KEY,
        theme: "dark",
        size,
        callback: (token) => onVerifyRef.current(token),
        "expired-callback": () => onExpireRef.current?.(),
        "error-callback": () => onErrorRef.current?.(),
      });
    } catch {
      // Render can throw if the script loaded but the iframe sandbox
      // rejected (rare). Silent — the form will fall back to a missing
      // token, and the backend's fail-open posture keeps the request
      // flowing if Cloudflare-side checks are also down.
    }

    return () => {
      const id = widgetIdRef.current;
      const tsCleanup = window.turnstile;
      if (id && tsCleanup) {
        try { tsCleanup.remove(id); } catch { /* ignore */ }
      }
      widgetIdRef.current = null;
    };
  }, [scriptReady, size]);

  if (!SITE_KEY) return null;

  return (
    <>
      <Script
        src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"
        strategy="afterInteractive"
        onReady={() => setScriptReady(true)}
        onLoad={() => setScriptReady(true)}
      />
      <div ref={containerRef} className={className} />
    </>
  );
}
