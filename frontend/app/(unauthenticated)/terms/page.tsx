// FILE: app/(unauthenticated)/terms/page.tsx
// Legacy /terms URL — kept alive as a redirect so existing links
// (registration checkbox, footer, emails) don't 404. The canonical
// home for the Terms of Use is /terms-and-policies/terms-of-use.
import { redirect } from "next/navigation";

export default function LegacyTermsRedirect() {
  redirect("/terms-and-policies/terms-of-use");
}
