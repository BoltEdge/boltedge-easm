"use client";

import * as React from "react";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  variant?: "default" | "inset";
}

export function Input({
  className = "",
  variant = "default",
  ...props
}: InputProps) {
  const base =
    "w-full rounded-md px-3 text-foreground placeholder:text-muted-foreground " +
    "focus:outline-none focus:ring-2 focus:ring-ring";

  const variants =
    variant === "inset"
      ? // ✅ Figma-like inset field
        "h-12 bg-black/20 border border-border shadow-[inset_0_1px_0_rgba(255,255,255,0.06),inset_0_0_0_1px_rgba(255,255,255,0.03)]"
      : // your existing default field
        "h-10 bg-input-background border border-border";

  return (
    <input className={`${base} ${variants} ${className}`} {...props} />
  );
}
