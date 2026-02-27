// app/(authenticated)/assets/all/page.tsx
"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Search } from "lucide-react";

import type { Asset } from "../../../types";
import { getAllAssets } from "../../../lib/api";

import { Input } from "../../../ui/input";
import { Button } from "../../../ui/button";

export default function AllAssetsPage() {
  const [loading, setLoading] = useState(true);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  useEffect(() => {
    let mounted = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const rows = await getAllAssets();
        if (!mounted) return;
        setAssets(rows);
      } catch (e: any) {
        if (!mounted) return;
        setError(e?.message || "Failed to load assets");
      } finally {
        if (mounted) setLoading(false);
      }
    }

    load();
    return () => {
      mounted = false;
    };
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return assets;

    return assets.filter((a: any) => {
      const value = String(a.value || "").toLowerCase();
      const type = String(a.type || a.asset_type || "").toLowerCase();
      const label = String(a.label || "").toLowerCase();
      const groupId = String(a.groupId || a.group_id || "").toLowerCase();
      return (
        value.includes(q) ||
        type.includes(q) ||
        label.includes(q) ||
        groupId.includes(q)
      );
    });
  }, [assets, query]);

  if (loading) {
    return (
      <div className="flex-1 bg-background overflow-auto">
        <div className="p-8 text-muted-foreground">Loading assets…</div>
      </div>
    );
  }

  return (
    <div className="flex-1 bg-background overflow-auto">
      <div className="p-8">
        <div className="flex items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-2xl font-semibold text-foreground">All Assets</h1>
            <p className="text-muted-foreground">
              View all assets across your groups
            </p>
            {error ? <p className="mt-2 text-sm text-red-300">{error}</p> : null}
          </div>

          <Link href="/assets" className="text-sm text-muted-foreground hover:text-foreground">
            ← Back to Groups
          </Link>
        </div>

        <div className="flex items-center gap-3 mb-5">
          <div className="relative w-full max-w-lg">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              className="pl-9"
              placeholder="Search assets (value, type, label, group id)…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          {query.trim() ? (
            <Button variant="outline" onClick={() => setQuery("")}>
              Clear
            </Button>
          ) : null}
        </div>

        <div className="text-sm text-muted-foreground mb-3">
          Showing {filtered.length} of {assets.length}
        </div>

        <div className="rounded-lg border border-border overflow-hidden bg-card">
          <div className="grid grid-cols-12 gap-3 px-4 py-3 text-xs font-semibold text-muted-foreground border-b border-border">
            <div className="col-span-2">Type</div>
            <div className="col-span-6">Value</div>
            <div className="col-span-2">Label</div>
            <div className="col-span-2">Group</div>
          </div>

          {filtered.length === 0 ? (
            <div className="px-4 py-6 text-muted-foreground">No assets found.</div>
          ) : (
            filtered.map((a: any) => {
              const type = String(a.type || a.asset_type || "—");
              const value = String(a.value || "—");
              const label = String(a.label || "—");
              const groupId = a.groupId ?? a.group_id;

              return (
                <div
                  key={String(a.id)}
                  className="grid grid-cols-12 gap-3 px-4 py-3 text-sm border-b border-border last:border-b-0"
                >
                  <div className="col-span-2 text-muted-foreground uppercase font-semibold">
                    {type}
                  </div>

                  <div className="col-span-6 font-mono text-foreground">
                    {value}
                  </div>

                  <div className="col-span-2 text-muted-foreground">
                    {label}
                  </div>

                  <div className="col-span-2">
                    {groupId ? (
                      <Link
                        href={`/groups/${groupId}`}
                        className="text-primary hover:underline"
                      >
                        {String(groupId)}
                      </Link>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
