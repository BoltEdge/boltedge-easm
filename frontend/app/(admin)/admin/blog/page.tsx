// FILE: app/(admin)/admin/blog/page.tsx
//
// Superadmin view for the blog mailing list: subscriber table + a Send
// button per published article. The article list is read server-side
// from the same markdown loader the public blog uses, so this page
// always reflects what's actually shipped.

import type { Metadata } from "next";

import { getAllArticles } from "../../../(unauthenticated)/resources/blog/_lib";
import AdminBlogClient from "./AdminBlogClient";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Blog Subscribers — Admin",
};

export default function AdminBlogPage() {
  const articles = getAllArticles().map((a) => ({
    slug: a.slug,
    title: a.title,
    description: a.description,
    publishDate: a.publishDate,
    category: a.category,
    readTime: a.computedReadTime,
  }));

  return <AdminBlogClient articles={articles} />;
}
