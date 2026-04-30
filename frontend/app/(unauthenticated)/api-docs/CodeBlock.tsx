"use client";

import { useState } from "react";
import { Copy, Check } from "lucide-react";

export function CodeBlock({ children }: { children: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(children);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard API unavailable — silently no-op
    }
  }

  return (
    <div className="relative group">
      <pre className="rounded-lg bg-black/40 border border-white/[0.06] px-4 py-3 pr-12 text-xs text-white/80 overflow-x-auto leading-relaxed">
        <code>{children}</code>
      </pre>
      <button
        type="button"
        onClick={handleCopy}
        aria-label={copied ? "Copied" : "Copy to clipboard"}
        className="absolute top-2 right-2 inline-flex items-center gap-1 rounded-md border border-white/[0.08] bg-white/[0.04] px-2 py-1 text-[11px] text-white/55 hover:text-white hover:bg-white/[0.08] transition-colors opacity-0 group-hover:opacity-100 focus:opacity-100"
      >
        {copied ? (
          <>
            <Check className="w-3 h-3 text-emerald-300" />
            <span className="text-emerald-300">Copied</span>
          </>
        ) : (
          <>
            <Copy className="w-3 h-3" />
            <span>Copy</span>
          </>
        )}
      </button>
    </div>
  );
}
