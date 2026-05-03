// FILE: app/(unauthenticated)/legal/page.tsx
// Legacy /legal URL — preserved as a redirect to /terms-and-policies
// so any existing bookmarks or external links keep working.
import { redirect } from "next/navigation";

export default function LegacyLegalRedirect() {
  redirect("/terms-and-policies");
}
