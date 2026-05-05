// app/opengraph-image.tsx
// Default Open Graph / social-share preview image.
// Next.js ImageResponse renders this at build time — no binary
// asset to commit, no external service, no secret leakage. Returns
// a 1200×630 PNG at /opengraph-image.<hash>.png automatically.

import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "Nano EASM — External Attack Surface Management";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpenGraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          height: "100%",
          width: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          padding: "80px",
          background:
            "linear-gradient(135deg, #060b18 0%, #0a1424 50%, #082030 100%)",
          color: "#fff",
          fontFamily: "system-ui, -apple-system, sans-serif",
        }}
      >
        {/* Bolt logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
          <div
            style={{
              width: 64,
              height: 64,
              borderRadius: 14,
              background: "#0a0f1e",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <svg width="40" height="40" viewBox="0 0 32 32" fill="none">
              <path
                d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z"
                fill="#14b8a6"
              />
            </svg>
          </div>
          <div style={{ display: "flex", fontSize: 40, fontWeight: 700 }}>
            <span>Nano</span>
            <span style={{ color: "#14b8a6", marginLeft: 6 }}>EASM</span>
          </div>
        </div>

        {/* Headline */}
        <div
          style={{
            display: "flex",
            fontSize: 76,
            fontWeight: 700,
            lineHeight: 1.05,
            marginTop: 80,
            letterSpacing: "-0.02em",
          }}
        >
          External Attack
        </div>
        <div
          style={{
            display: "flex",
            fontSize: 76,
            fontWeight: 700,
            lineHeight: 1.05,
            letterSpacing: "-0.02em",
          }}
        >
          Surface Management
        </div>

        {/* Subhead */}
        <div
          style={{
            display: "flex",
            fontSize: 28,
            color: "rgba(255,255,255,0.55)",
            marginTop: 36,
            maxWidth: 900,
            lineHeight: 1.4,
          }}
        >
          Discover assets · scan for risk · monitor exposure changes
        </div>

        {/* URL pill */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            marginTop: 80,
            fontSize: 24,
            color: "#14b8a6",
            border: "1px solid rgba(20,184,166,0.3)",
            background: "rgba(20,184,166,0.08)",
            padding: "10px 22px",
            borderRadius: 999,
            width: "fit-content",
          }}
        >
          nanoasm.com
        </div>
      </div>
    ),
    { ...size },
  );
}
