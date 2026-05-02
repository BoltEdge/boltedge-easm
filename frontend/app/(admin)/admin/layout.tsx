"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getAccessToken, getIsSuperadmin, logout } from "../../lib/auth";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutDashboard, Building2, Users, LogOut, ShieldAlert, ScrollText, ScanLine, Megaphone, HeartPulse, ShieldBan, MessageSquare } from "lucide-react";

const NAV = [
  { href: "/admin/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/admin/organizations", label: "Organizations", icon: Building2 },
  { href: "/admin/users", label: "Users", icon: Users },
  { href: "/admin/contact-requests", label: "Contact Requests", icon: MessageSquare },
  { href: "/admin/audit-log", label: "Audit Log", icon: ScrollText },
  { href: "/admin/scans", label: "Active Scans", icon: ScanLine },
  { href: "/admin/broadcast", label: "Broadcast", icon: Megaphone },
  { href: "/admin/health", label: "Health", icon: HeartPulse },
  { href: "/admin/quick-scans", label: "Quick Scans", icon: ShieldBan },
];

function AdminShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="min-h-screen bg-[#060b18] text-white flex">
      <aside className="w-56 shrink-0 border-r border-white/[0.06] flex flex-col">
        <div className="h-14 flex items-center gap-2.5 px-4 border-b border-white/[0.06]">
          <ShieldAlert className="w-5 h-5 text-teal-400" />
          <span className="text-sm font-semibold">
            Nano<span className="text-teal-400">EASM</span>
            <span className="text-[10px] text-white/30 ml-1.5 font-normal">Admin</span>
          </span>
        </div>
        <nav className="flex-1 p-3 space-y-0.5">
          {NAV.map(({ href, label, icon: Icon }) => {
            const active = pathname === href || pathname.startsWith(href + "/");
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
        </nav>
        <div className="p-3 border-t border-white/[0.06]">
          <button
            onClick={() => logout("/dashboard")}
            className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-white/40 hover:text-white hover:bg-white/[0.04] transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Back to app
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
