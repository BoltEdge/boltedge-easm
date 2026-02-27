// app/(marketing)/layout.tsx
import type { ReactNode } from "react";

export default function MarketingLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <div className="min-h-screen bg-[#060b18] text-white antialiased">
      {children}
    </div>
  );
}