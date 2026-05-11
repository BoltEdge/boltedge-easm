// frontend/app/(authenticated)/_components/ProvenanceTag.tsx
// One small pill rendered next to the severity badge on a finding row.
// Display is gated by the user preference showProvenanceTags — the
// caller decides whether to render this component at all.

import { History, Sparkles, RotateCcw } from "lucide-react";

export type Provenance = "new" | "seen_before" | "resolved_before";

const CONFIG: Record<
  Provenance,
  {
    label: string;
    title: string;
    cls: string;
    icon: React.ComponentType<{ className?: string }>;
  }
> = {
  resolved_before: {
    label: "Resolved before",
    title: "Was previously resolved. Detected again — likely a regression.",
    cls: "border-amber-500/30 bg-amber-500/[0.08] text-amber-300",
    icon: RotateCcw,
  },
  new: {
    label: "New",
    title: "First detection. Never seen before this scan.",
    cls: "border-teal-500/30 bg-teal-500/[0.08] text-teal-300",
    icon: Sparkles,
  },
  seen_before: {
    label: "Seen before",
    title: "Seen in a previous scan. No new state.",
    cls: "border-white/10 bg-white/[0.04] text-white/65",
    icon: History,
  },
};

type Props = {
  value: Provenance | null | undefined;
  className?: string;
};

export default function ProvenanceTag({ value, className }: Props) {
  if (!value || !(value in CONFIG)) return null;
  const { label, title, cls, icon: Icon } = CONFIG[value];
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold ${cls} ${className ?? ""}`}
    >
      <Icon className="w-2.5 h-2.5" />
      {label}
    </span>
  );
}
