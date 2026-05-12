// FILE: app/(unauthenticated)/resources/blog/_lib.ts
//
// Server-only article loader. Reads every .md file in /content/articles/,
// parses simple YAML frontmatter (we don't pull in gray-matter because
// the schema is small and stable), and exposes a typed list + per-slug
// lookup.
//
// IMPORTANT: this file imports `fs` and `path` — never import it from
// a "use client" component. Pure types + helpers live in _types.ts so
// client components can use them without pulling Node's stdlib into
// the browser bundle.

import fs from "node:fs";
import path from "node:path";

import type { Article, ArticleCategory, ArticleFrontmatter } from "./_types";

export type { Article, ArticleCategory, ArticleFrontmatter } from "./_types";
export {
  CATEGORIES,
  CATEGORY_BADGE,
  categoryLabel,
  formatPublishDate,
} from "./_types";

const ARTICLES_DIR = path.join(process.cwd(), "content", "articles");

/** Parse a minimal subset of YAML frontmatter — enough for our schema.
 *  Supports strings, numbers, booleans, ISO dates, and string arrays in
 *  the `- item` or `["a","b"]` forms. Anything weirder is ignored. */
function parseFrontmatter(raw: string): { meta: Record<string, unknown>; body: string } {
  const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/);
  if (!match) return { meta: {}, body: raw };
  const [, fmBlock, body] = match;
  const meta: Record<string, unknown> = {};
  const lines = fmBlock.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim() || line.trim().startsWith("#")) { i++; continue; }
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$/);
    if (!m) { i++; continue; }
    const key = m[1];
    const valRaw = m[2].trim();

    if (valRaw === "") {
      // Multi-line list (next lines are "  - item")
      const list: string[] = [];
      i++;
      while (i < lines.length && /^\s*-\s+/.test(lines[i])) {
        list.push(lines[i].replace(/^\s*-\s+/, "").trim().replace(/^["']|["']$/g, ""));
        i++;
      }
      meta[key] = list;
      continue;
    }

    if (valRaw.startsWith("[") && valRaw.endsWith("]")) {
      // Inline array
      meta[key] = valRaw
        .slice(1, -1)
        .split(",")
        .map((s) => s.trim().replace(/^["']|["']$/g, ""))
        .filter(Boolean);
    } else if (/^(true|false)$/.test(valRaw)) {
      meta[key] = valRaw === "true";
    } else if (/^-?\d+(\.\d+)?$/.test(valRaw)) {
      meta[key] = Number(valRaw);
    } else {
      meta[key] = valRaw.replace(/^["']|["']$/g, "");
    }
    i++;
  }
  return { meta, body };
}

/** Rough reading-time estimate. 220 words/min is the common "non-fiction
 *  technical" pace. Rounds up so a 5.3-min read shows as 6, not 5. */
function estimateReadTime(body: string): number {
  const words = body
    .replace(/```[\s\S]*?```/g, " ")     // strip code blocks
    .replace(/`[^`]+`/g, " ")            // inline code
    .replace(/[#*_>\-]/g, " ")           // markdown punctuation
    .split(/\s+/)
    .filter(Boolean).length;
  return Math.max(1, Math.ceil(words / 220));
}

let _cache: Article[] | null = null;

/** Load every article in /content/articles/. Cached for the process
 *  lifetime since articles are static at build time. */
export function getAllArticles(): Article[] {
  if (_cache) return _cache;
  let files: string[] = [];
  try {
    files = fs.readdirSync(ARTICLES_DIR).filter((f) => f.endsWith(".md"));
  } catch {
    _cache = [];
    return _cache;
  }

  const articles: Article[] = files
    .map((file) => {
      const raw = fs.readFileSync(path.join(ARTICLES_DIR, file), "utf-8");
      const { meta, body } = parseFrontmatter(raw);
      const fm: ArticleFrontmatter = {
        title: String(meta.title ?? file),
        description: String(meta.description ?? ""),
        slug: String(meta.slug ?? file.replace(/\.md$/, "")),
        publishDate: String(meta.publishDate ?? "1970-01-01"),
        author: String(meta.author ?? "Nano EASM"),
        authorTitle: meta.authorTitle ? String(meta.authorTitle) : undefined,
        category: (meta.category as ArticleCategory) ?? "fundamentals",
        tags: Array.isArray(meta.tags) ? (meta.tags as string[]) : [],
        heroImage: meta.heroImage ? String(meta.heroImage) : undefined,
        ogImage: meta.ogImage ? String(meta.ogImage) : undefined,
        readTime: typeof meta.readTime === "number" ? meta.readTime : undefined,
        featured: Boolean(meta.featured),
      };
      const computedReadTime = fm.readTime ?? estimateReadTime(body);
      return { ...fm, body: body.trim(), computedReadTime };
    })
    .sort((a, b) => (a.publishDate < b.publishDate ? 1 : -1));

  _cache = articles;
  return _cache;
}

export function getArticleBySlug(slug: string): Article | null {
  return getAllArticles().find((a) => a.slug === slug) ?? null;
}

export function getRelatedArticles(article: Article, limit = 3): Article[] {
  // Match by category first, then fall back to other recent articles so
  // the related-strip is never empty on a freshly-launched category.
  const all = getAllArticles().filter((a) => a.slug !== article.slug);
  const sameCategory = all.filter((a) => a.category === article.category);
  const others = all.filter((a) => a.category !== article.category);
  return [...sameCategory, ...others].slice(0, limit);
}
