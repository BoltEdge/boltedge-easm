"use client";

import * as React from "react";

type Variant = "default" | "outline" | "pill";

export function Badge({
  className = "",
  variant = "default",
  children,
}: {
  className?: string;
  variant?: Variant;
  children: React.ReactNode;
}) {
  const base =
    "inline-flex items-center rounded-md px-2 py-1 text-xs font-medium";

  const styles =
    variant === "outline"
      ? "border border-border bg-transparent text-foreground"
      : variant === "pill"
      ? "rounded-full border border-border bg-card/40 text-muted-foreground px-2.5 py-1"
      : "bg-accent text-accent-foreground";

  return <span className={`${base} ${styles} ${className}`}>{children}</span>;
}
