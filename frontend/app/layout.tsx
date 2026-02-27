// app/layout.tsx
import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "BoltEdge EASM",
  description:
    "External Attack Surface Management by BoltEdge. Discover assets, scan for vulnerabilities, and monitor your exposure.",
  icons: {
    icon: [
      { url: "/favicon.png", sizes: "32x32", type: "image/png" },
      { url: "/favicon-64.png", sizes: "64x64", type: "image/png" },
    ],
    apple: "/favicon-64.png",
  },
  openGraph: {
    title: "BoltEdge EASM",
    description:
      "External Attack Surface Management — discover, scan, and continuously monitor your attack surface.",
    siteName: "BoltEdge EASM",
    type: "website",
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-background text-foreground antialiased">
        {children}
      </body>
    </html>
  );
}