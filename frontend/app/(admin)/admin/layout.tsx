"use client";
import { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import { getAccessToken, getIsSuperadmin, logout } from "../../lib/auth";
import Link from "next/link";
import {
  LayoutDashboard, Building2, Users, LogOut, ShieldAlert, ScrollText,
  ScanLine, Megaphone, HeartPulse, ShieldBan, MessageSquare, CreditCard,
  ChevronDown, ArrowLeft,
} from "lucide-react";

// The admin nav is grouped by what the operator is *trying to do*, not
// by which model the page reads from. Five buckets cover everything we
// have today and leave room for the bulk-actions / send-email /
// create-request work coming next without making the sidebar feel
// crowded. Keep `href` paths stable — the grouping is purely visual,
// so existing bookmarks still resolve.
type NavItem = { href: string; label: string; icon: typeof LayoutDashboard };
type NavGroup = { id: string; label: string | null; items: NavItem[] };

const NAV_GROUPS: NavGroup[] = [
  {
    id: "overview",
    label: null, // top-level — no header
    items: [
      { href: "/admin/dashboard", label: "Dashboard", icon: LayoutDashboard },
    ],
  },
  {
    id: "tenants",
    label: "People & Tenants",
    items: [
      { href: "/admin/organizations", label: "Organizations", icon: Building2 },
      { href: "/admin/users", label: "Users", icon: Users },
      { href: "/admin/billing", label: "Billing", icon: CreditCard },
    ],
  },
  {
    id: "comms",
    label: "Requests & Communication",
    items: [
      { href: "/admin/contact-requests", label: "Contact Requests", icon: MessageSquare },
      { href: "/admin/broadcast", label: "Broadcast", icon: Megaphone },
    ],
  },
  {
    id: "activity",
    label: "Activity & Operations",
    items: [
      { href: "/admin/scans", label: "Active Scans", icon: ScanLine },
      { href: "/admin/quick-scans", label: "Quick Scans", icon: ShieldBan },
      { href: "/admin/audit-log", label: "Audit Log", icon: ScrollText },
    ],
  },
  {
    id: "health",
    label: "Platform Health",
    items: [
      { href: "/admin/health", label: "Health", icon: HeartPulse },
    ],
  },
];

function isItemActive(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(href + "/");
}

function isGroupActive(pathname: string, group: NavGroup): boolean {
  return group.items.some((it) => isItemActive(pathname, it.href));
}

function AdminShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();

  // Each group is collapsible. The active group auto-opens on every
  // navigation; user-toggled state is layered on top via local state
  // so they can collapse the active group if they want a tighter
  // sidebar. Persist collapse state across navigation but not across
  // sessions (cheap; no localStorage round-trip).
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const toggleGroup = (id: string) =>
    setCollapsed((prev) => ({ ...prev, [id]: !prev[id] }));

  return (
    <div className="min-h-screen bg-[#060b18] text-white flex">
      <aside className="w-64 shrink-0 border-r border-white/[0.06] flex flex-col">
        <div className="h-14 flex items-center gap-2.5 px-4 border-b border-white/[0.06]">
          <ShieldAlert className="w-5 h-5 text-teal-400" />
          <span className="text-sm font-semibold">
            Nano <span className="text-teal-400">EASM</span>
            <span className="text-[10px] text-white/30 ml-1.5 font-normal">Admin</span>
          </span>
        </div>
        <nav className="flex-1 p-3 overflow-y-auto">
          {NAV_GROUPS.map((group) => {
            const groupActive = isGroupActive(pathname, group);
            // Open by default if (a) the group has no header and is
            // therefore always rendered, (b) the route is inside it,
            // or (c) it's the most-used group ("tenants"). User
            // toggles override the default.
            const userToggled = collapsed[group.id];
            const open =
              group.label === null
                ? true
                : userToggled === undefined
                  ? groupActive || group.id === "tenants"
                  : !userToggled;

            return (
              <div key={group.id} className="mb-3 last:mb-0">
                {group.label && (
                  <button
                    type="button"
                    onClick={() => toggleGroup(group.id)}
                    className="w-full flex items-center justify-between gap-2 px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-white/30 hover:text-white/50 transition-colors"
                  >
                    {/* nowrap+truncate stops long labels (e.g. "Requests
                        & Communication") from wrapping mid-header and
                        making the chevron look detached from the text. */}
                    <span className="truncate whitespace-nowrap">{group.label}</span>
                    <ChevronDown
                      className={`w-3 h-3 shrink-0 transition-transform ${open ? "" : "-rotate-90"}`}
                    />
                  </button>
                )}
                {open && (
                  // Indent children under their group header so the
                  // hierarchy reads at a glance. Headerless groups
                  // (Dashboard) skip the indent because there's no
                  // parent to nest beneath.
                  <div
                    className={`space-y-0.5 mt-0.5 ${
                      group.label ? "ml-2 pl-1.5 border-l border-white/[0.06]" : ""
                    }`}
                  >
                    {group.items.map(({ href, label, icon: Icon }) => {
                      const active = isItemActive(pathname, href);
                      return (
                        <Link
                          key={href}
                          href={href}
                          className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors ${
                            active
                              ? "bg-teal-500/10 text-teal-400"
                              : "text-white/40 hover:text-white hover:bg-white/[0.04]"
                          }`}
                        >
                          <Icon className="w-4 h-4 shrink-0" />
                          {label}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </nav>
        <div className="p-3 border-t border-white/[0.06] space-y-1">
          {/* "Back to app" navigates without ending the session — admins
              regularly bounce between the admin console and their normal
              dashboard while triaging issues. The previous wiring called
              `logout()` here, which cleared the session and forced a
              re-login on every flip back. */}
          <button
            onClick={() => router.push("/dashboard")}
            className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-white/40 hover:text-white hover:bg-white/[0.04] transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to app
          </button>
          <button
            onClick={() => logout("/login")}
            className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-white/40 hover:text-white hover:bg-white/[0.04] transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Sign out
          </button>
        </div>
      </aside>
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 border-b border-white/[0.06] flex items-center px-6">
          <span className="text-xs text-white/30 font-mono">Platform Admin Console</span>
        </header>
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [allowed, setAllowed] = useState(false);

  useEffect(() => {
    const token = getAccessToken();
    const isSuperadmin = getIsSuperadmin();
    setAllowed(!!(token && isSuperadmin));
    setReady(true);
  }, []);

  if (!ready) return null;

  if (!allowed) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="text-6xl font-bold text-muted-foreground/20 mb-4">404</div>
          <p className="text-muted-foreground text-sm">Page not found.</p>
          <Link href="/" className="mt-4 inline-block text-sm text-primary hover:underline">Go home</Link>
        </div>
      </div>
    );
  }

  return <AdminShell>{children}</AdminShell>;
}
