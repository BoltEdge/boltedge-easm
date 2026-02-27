"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";

type Asset = {
  id: number;
  asset_type: "domain" | "ip" | "email";
  value: string;
  label?: string | null;
  created_at?: string;
  is_active?: boolean;
  deleted_at?: string | null;
};

export default function AssetDetailPage() {
  const params = useParams(); // ✅ reliable
  const id = params?.id as string | undefined;

  const [asset, setAsset] = useState<Asset | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;

    (async () => {
      try {
        setError(null);
        setAsset(null);

        const res = await fetch(`/api/assets/${id}`, { cache: "no-store" });
        if (!res.ok) {
          const body = await res.text().catch(() => "");
          throw new Error(
            `Failed to fetch asset. status=${res.status} ${res.statusText} body=${body.slice(
              0,
              200
            )}`
          );
        }

        const data = (await res.json()) as Asset;
        setAsset(data);
      } catch (e: any) {
        setError(e?.message ?? "Unknown error");
      }
    })();
  }, [id]);

  if (!id) {
    return <div style={{ opacity: 0.8 }}>Missing asset id in URL.</div>;
  }

  if (error) {
    return (
      <div>
        <a href="/assets" style={{ opacity: 0.7 }}>
          ← Back to Assets
        </a>
        <h1 style={{ marginTop: 16, fontSize: 24, fontWeight: 800 }}>Error</h1>
        <pre style={{ marginTop: 12, whiteSpace: "pre-wrap", opacity: 0.85 }}>
          {error}
        </pre>
      </div>
    );
  }

  if (!asset) {
    return (
      <div style={{ opacity: 0.8 }}>
        Loading asset <b>{id}</b>...
      </div>
    );
  }

  return (
    <div>
      <a href="/assets" style={{ opacity: 0.7 }}>
        ← Back to Assets
      </a>

      <h1 style={{ fontSize: 32, fontWeight: 800, marginTop: 16 }}>
        {asset.value}
        <span
          style={{
            marginLeft: 10,
            fontSize: 12,
            fontWeight: 700,
            padding: "4px 10px",
            borderRadius: 999,
            border: "1px solid #1e293b",
            textTransform: "uppercase",
            opacity: 0.9,
          }}
        >
          {asset.asset_type}
        </span>
      </h1>

      <p style={{ marginTop: 6, opacity: 0.7 }}>
        Asset ID: {asset.id}
        {asset.label ? ` · ${asset.label}` : ""}
      </p>

      <div
        style={{
          marginTop: 24,
          border: "1px solid #1e293b",
          borderRadius: 12,
          padding: 20,
          background: "rgba(2,6,23,0.6)",
        }}
      >
        <h2 style={{ fontSize: 18, fontWeight: 700 }}>Asset Information</h2>

        <div
          style={{
            marginTop: 16,
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 16,
          }}
        >
          <Info label="Type" value={asset.asset_type} />
          <Info label="Value" value={asset.value} />
          <Info label="Label" value={asset.label ?? "—"} />
          <Info label="Created" value={asset.created_at ?? "—"} />
          <Info label="Status" value={asset.is_active ? "Active" : "Inactive"} />
        </div>
      </div>
    </div>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div style={{ fontSize: 12, opacity: 0.6 }}>{label}</div>
      <div style={{ marginTop: 6, fontWeight: 600 }}>{value}</div>
    </div>
  );
}
