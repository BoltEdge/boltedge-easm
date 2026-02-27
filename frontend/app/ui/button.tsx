"use client";

import * as React from "react";

type Variant = "default" | "outline" | "ghost" | "subtle";
type Size = "default" | "sm" | "lg" | "icon" | "pill";

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

export function Button({
  className = "",
  variant = "default",
  size = "default",
  type = "button",
  ...props
}: ButtonProps) {
  const base =
    "inline-flex items-center justify-center rounded-md font-medium transition-colors " +
    "disabled:opacity-50 disabled:pointer-events-none " +
    "focus:outline-none focus:ring-2 focus:ring-primary/40";

  const variants: Record<Variant, string> = {
    default: "bg-primary text-primary-foreground hover:bg-primary/90",
    outline:
      "border border-border bg-transparent text-foreground hover:bg-accent",
    // 👇 make ghost always visible on dark backgrounds (like Figma)
    ghost:
      "bg-transparent text-foreground hover:bg-accent border border-transparent hover:border-border",

    // ✅ NEW: Figma-like “soft surface” button
    subtle:
      "border border-border bg-card/40 text-foreground hover:bg-accent/60",
  };

  const sizes: Record<Size, string> = {
    default: "h-10 px-4 py-2 text-sm",
    sm: "h-9 px-3 text-sm",
    lg: "h-11 px-6 text-base",
    // 👇 perfect for 3-dots buttons
    icon: "h-9 w-9 p-0",

    // ✅ NEW: tab-like pill buttons (Asset Discovery / Scanning)
    pill: "h-9 px-4 text-sm rounded-full",
  };

  return (
    <button
      type={type}
      className={`${base} ${variants[variant]} ${sizes[size]} ${className}`}
      {...props}
    />
  );
}
