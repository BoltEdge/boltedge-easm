// app/(unauthenticated)/look-up-tools/ToolsAccordion.tsx
// Grid of tool cards plus a single, page-level Cloudflare Turnstile widget.
// Lifting the token into this parent has two benefits over a widget per
// card: simpler code, and the token survives card switches (verify once,
// run any tool while the token is alive — Cloudflare tokens last ~5 min).
"use client";

import { useState, useCallback } from "react";

import TurnstileWidget from "../TurnstileWidget";
import ToolAccordionRow from "./ToolAccordionRow";
import { VISIBLE_TOOLS } from "./tools-config";

const TURNSTILE_ENABLED = !!process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;

export default function ToolsAccordion() {
  const [openId, setOpenId] = useState<string | null>(null);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const [widgetKey, setWidgetKey] = useState(0);

  // After any tool consumes the token, invalidate it and remount the
  // widget so the next run gets a fresh challenge. Cloudflare tokens are
  // single-use; reusing one would 403 on the backend.
  const consumeToken = useCallback(() => {
    setTurnstileToken(null);
    setWidgetKey((k) => k + 1);
  }, []);

  return (
    <>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5 items-start">
        {VISIBLE_TOOLS.map((tool) => (
          <ToolAccordionRow
            key={tool.id}
            tool={tool}
            isOpen={openId === tool.id}
            onToggle={() => setOpenId((cur) => (cur === tool.id ? null : tool.id))}
            turnstileToken={turnstileToken}
            onTokenConsumed={consumeToken}
          />
        ))}
      </div>

      {TURNSTILE_ENABLED && (
        <div className="mt-6 flex flex-col items-center gap-2">
          <TurnstileWidget
            key={widgetKey}
            onVerify={setTurnstileToken}
            onExpire={() => setTurnstileToken(null)}
            onError={() => setTurnstileToken(null)}
          />
          <p className="text-[11px] text-white/40">
            Verify once — token is good for the next tool you run.
          </p>
        </div>
      )}
    </>
  );
}
