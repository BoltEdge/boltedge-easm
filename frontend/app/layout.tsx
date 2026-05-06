// app/layout.tsx
import "./globals.css";
import type { ReactNode } from "react";
import type { Metadata } from "next";

const SITE_URL = "https://nanoeasm.com";

// Root metadata — sets defaults that per-page metadata extends/overrides.
// metadataBase ensures all relative URLs in metadata (og.url, og.image,
// canonical, etc.) resolve against the production domain even when
// rendered via SSR or Edge.
export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: "Nano EASM — External Attack Surface Management",
    template: "%s | Nano EASM",
  },
  description:
    "Nano EASM is an external attack surface management platform — discover external assets, monitor exposure changes, prioritise risk, and take a practical first step toward continuous threat exposure management.",
  applicationName: "Nano EASM",
  generator: "Next.js",
  keywords: [
    "external attack surface management",
    "EASM",
    "attack surface management",
    "asset discovery",
    "vulnerability scanning",
    "exposure management",
    "subdomain enumeration",
    "shadow IT",
    "MSSP",
    "Nano EASM",
  ],
  authors: [{ name: "Nano EASM" }],
  creator: "Nano EASM",
  publisher: "Nano EASM",
  alternates: {
    canonical: "/",
  },
  icons: {
    icon: [
      { url: "/favicon.png", sizes: "32x32", type: "image/png" },
      { url: "/favicon-64.png", sizes: "64x64", type: "image/png" },
    ],
    apple: "/favicon-64.png",
  },
  // OG / Twitter images are auto-injected from app/opengraph-image.png
  // (Next.js file convention). Regen the PNG via scripts/og-image.html.
  openGraph: {
    type: "website",
    siteName: "Nano EASM",
    title: "Nano EASM — External Attack Surface Management",
    description:
      "Discover external assets, monitor exposure changes, prioritise risk, and take a practical first step toward continuous threat exposure management.",
    url: SITE_URL,
    locale: "en_AU",
  },
  twitter: {
    card: "summary_large_image",
    title: "Nano EASM — External Attack Surface Management",
    description:
      "Discover external assets, monitor exposure changes, prioritise risk, and take a practical first step toward continuous threat exposure management.",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
      "max-video-preview": -1,
    },
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en-AU">
      <body className="bg-background text-foreground antialiased">
        {children}
      </body>
    </html>
  );
}
