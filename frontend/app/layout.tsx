// app/layout.tsx
import "./globals.css";
import type { ReactNode } from "react";
import type { Metadata } from "next";

const SITE_URL = "https://nanoeasm.com";

// Single source of truth for the homepage / global description. Used
// across description, openGraph.description, and twitter.description
// so SEO previews never disagree on copy. Update here only.
const SITE_DESCRIPTION =
  "Nano EASM helps teams discover external assets, monitor exposure changes, prioritise risk, and take a practical first step toward continuous threat exposure management.";

// OG image is also defined explicitly. The Next.js file-convention
// (app/opengraph-image.png) is meant to auto-inject these tags but
// the rendered <head> on prod doesn't always show them — so we set
// them via the metadata API as well. The image file still lives at
// app/opengraph-image.png and is served as /opengraph-image.png.
const OG_IMAGE_URL = `${SITE_URL}/opengraph-image.png`;
const OG_IMAGE_ALT = "Nano EASM external attack surface management platform preview";

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
  description: SITE_DESCRIPTION,
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
  openGraph: {
    type: "website",
    siteName: "Nano EASM",
    title: "Nano EASM — External Attack Surface Management",
    description: SITE_DESCRIPTION,
    url: SITE_URL,
    locale: "en_AU",
    images: [
      {
        url: OG_IMAGE_URL,
        width: 1200,
        height: 630,
        type: "image/png",
        alt: OG_IMAGE_ALT,
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Nano EASM — External Attack Surface Management",
    description: SITE_DESCRIPTION,
    images: [OG_IMAGE_URL],
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
