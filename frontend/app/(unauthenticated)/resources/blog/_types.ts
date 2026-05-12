// FILE: app/(unauthenticated)/resources/blog/_types.ts
//
// Client-safe types and pure helpers — split out of _lib.ts so client
// components can import these without pulling in `fs`/`path` (which
// would break the browser bundle). The fs-touching loader stays in
// _lib.ts and is only imported by server components.

export type ArticleCategory =
  | "fundamentals"
  | "threats"
  | "compliance"
  | "how-to"
  | "product";

export type ArticleFrontmatter = {
  title: string;
  description: string;
  slug: string;
  publishDate: string;
  author: string;
  authorTitle?: string;
  category: ArticleCategory;
  tags?: string[];
  heroImage?: string;
  ogImage?: string;
  readTime?: number;
  featured?: boolean;
};

export type Article = ArticleFrontmatter & {
  body: string;
  computedReadTime: number;
};

export const CATEGORIES: Array<{ id: ArticleCategory; label: string; description: string }> = [
  { id: "fundamentals", label: "Fundamentals", description: "The discipline, vocabulary, and mental models." },
  { id: "threats",      label: "Threats",      description: "What's being exploited, and how." },
  { id: "compliance",   label: "Compliance",   description: "Mapping findings to SOC 2, ISO 27001, PCI-DSS." },
  { id: "how-to",       label: "How-to",       description: "Hands-on guidance for security teams." },
  { id: "product",      label: "Product",      description: "Nano EASM features, releases, deep dives." },
];

export const CATEGORY_BADGE: Record<ArticleCategory, string> = {
  fundamentals:  "bg-teal-500/15 text-teal-300 border-teal-500/30",
  threats:       "bg-red-500/15 text-red-300 border-red-500/30",
  compliance:    "bg-amber-500/15 text-amber-300 border-amber-500/30",
  "how-to":      "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
  product:       "bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30",
};

export function categoryLabel(id: ArticleCategory): string {
  return CATEGORIES.find((c) => c.id === id)?.label ?? id;
}

export function formatPublishDate(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("en-AU", { year: "numeric", month: "long", day: "numeric" });
}
