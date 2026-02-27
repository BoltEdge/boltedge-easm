// app/(authenticated)/assets/layout.tsx
import React from "react";

export default function AssetsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // IMPORTANT:
  // - No <html> or <body> here (only allowed in app/layout.tsx)
  // - No TopBar/Sidebar here (handled by app/(authenticated)/layout.tsx)
  // This layout only adds consistent padding for the Assets section.
  return <div className="flex-1 overflow-auto px-8 py-8">{children}</div>;
}
