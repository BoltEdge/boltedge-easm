// FILE: app/(unauthenticated)/legal/[slug]/page.tsx
// Legacy /legal/<slug> URL — preserved as a redirect to the new
// /terms-and-policies/<slug> path. Strips any trailing `.md` for the
// same defensive reason as the canonical route.
import { redirect } from "next/navigation";

export default async function LegacyLegalSlugRedirect({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const cleanSlug = slug.replace(/\.md$/i, "");
  redirect(`/terms-and-policies/${cleanSlug}`);
}
