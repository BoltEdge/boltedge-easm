// FILE: app/Sidebar.tsx
// Sidebar with collapsible dropdown sub-menus, user info footer, and resizable width
"use client";
import { useState, useRef, useCallback, useEffect } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  LayoutDashboard, Layers, Globe, Activity, AlertCircle, Server,
  Bell, Settings, SlidersHorizontal,
  ChevronLeft, ChevronRight, ChevronDown,
  UserCircle, Key, CreditCard, Zap, Calendar,
  FileText, TrendingUp, Plug, LogOut,
} from "lucide-react";
import { useOrg } from "./(authenticated)/contexts/OrgContext";
import { logout } from "./lib/auth";

const SIDEBAR_WIDTH_KEY = "asm_sidebar_width";
const MIN_WIDTH = 220;
const MAX_WIDTH = 360;
const DEFAULT_WIDTH = 256; // w-64
const COLLAPSED_WIDTH = 64; // w-16

const roleColors: Record<string, string> = {
  owner: "bg-purple-500/20 text-purple-300 border-purple-500/30",
  admin: "bg-blue-500/20 text-blue-300 border-blue-500/30",
  analyst: "bg-green-500/20 text-green-300 border-green-500/30",
  viewer: "bg-gray-500/20 text-gray-300 border-gray-500/30",
};

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { user, organization, role, planLabel, isTrialing, trialDaysRemaining } = useOrg();

  const [isCollapsed, setIsCollapsed] = useState(false);
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    if (typeof window === "undefined") return DEFAULT_WIDTH;
    const saved = localStorage.getItem(SIDEBAR_WIDTH_KEY);
    return saved ? Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, Number(saved))) : DEFAULT_WIDTH;
  });

  const [scanningOpen, setScanningOpen] = useState(pathname.startsWith("/scan"));
  const [findingsOpen, setFindingsOpen] = useState(pathname.startsWith("/findings") || pathname.startsWith("/reports") || pathname.startsWith("/trending"));
  const [monitoringOpen, setMonitoringOpen] = useState(pathname.startsWith("/monitoring"));
  const [settingsOpen, setSettingsOpen] = useState(pathname.startsWith("/settings"));

  // ── Resize drag handling ──
  const isResizing = useRef(false);
  const startX = useRef(0);
  const startWidth = useRef(DEFAULT_WIDTH);

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    if (isCollapsed) return;
    e.preventDefault();
    isResizing.current = true;
    startX.current = e.clientX;
    startWidth.current = sidebarWidth;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  }, [isCollapsed, sidebarWidth]);

  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!isResizing.current) return;
      const delta = e.clientX - startX.current;
      const newWidth = Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, startWidth.current + delta));
      setSidebarWidth(newWidth);
    };

    const onMouseUp = () => {
      if (!isResizing.current) return;
      isResizing.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      localStorage.setItem(SIDEBAR_WIDTH_KEY, String(sidebarWidth));
    };

    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    return () => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
    };
  }, [sidebarWidth]);

  const handleLogout = () => {
    logout();
    router.replace("/");
  };

  // ── Sub-menu items ──
  const scanningSubs = [
    { href: "/scan", label: "Scan Jobs", icon: Activity },
    { href: "/scan/initiate", label: "Initiate Scan", icon: Zap },
    { href: "/scan/schedules", label: "Schedules", icon: Calendar },
  ];

  const findingsSubs = [
    { href: "/findings", label: "All Findings", icon: AlertCircle },
    { href: "/reports", label: "Reports", icon: FileText },
    { href: "/trending", label: "Trending", icon: TrendingUp },
  ];

  const monitoringSubs = [
    { href: "/monitoring", label: "Alerts", icon: Bell },
    { href: "/monitoring/tuning", label: "Tuning", icon: SlidersHorizontal },
    { href: "/monitoring/settings", label: "Settings", icon: Settings },
  ];

  const settingsSubs = [
    { href: "/settings/account", label: "Account & Team", icon: UserCircle },
    { href: "/settings/integrations", label: "Integrations", icon: Plug },
    { href: "/settings/api-keys", label: "API Keys", icon: Key },
    { href: "/settings/billing", label: "Payment & Plans", icon: CreditCard },
    { href: "/settings/audit-log", label: "Audit Log", icon: FileText },
  ];

  const isActive = (href: string) => {
    if (href === "/assets") return pathname === "/assets" || pathname.startsWith("/assets/") || pathname.startsWith("/groups");
    if (href === "/findings") return pathname === "/findings" || pathname.startsWith("/findings/");
    if (href === "/reports") return pathname === "/reports" || pathname.startsWith("/reports/");
    if (href === "/trending") return pathname === "/trending" || pathname.startsWith("/trending/");
    if (href === "/settings/account") return pathname === "/settings/account" || pathname === "/settings/profile" || pathname === "/settings/users";
    if (href === "/settings/integrations") return pathname === "/settings/integrations" || pathname.startsWith("/settings/integrations/");
    return pathname === href;
  };

  const isScanningSection = pathname.startsWith("/scan");
  const isFindingsSection = pathname.startsWith("/findings") || pathname.startsWith("/reports") || pathname.startsWith("/trending");
  const isMonitoringSection = pathname.startsWith("/monitoring");
  const isSettingsSection = pathname.startsWith("/settings");

  // ── Shared styles for ALL nav items (top-level links + section headers) ──
  function navCls(active: boolean) {
    return [
      "w-full flex items-center",
      isCollapsed ? "justify-center" : "gap-3",
      "px-3 py-2.5 rounded-lg transition-colors text-[15px]",
      active
        ? "bg-primary text-primary-foreground ring-1 ring-primary/30 font-semibold"
        : "text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground font-medium",
    ].join(" ");
  }

  function subCls(active: boolean) {
    return [
      "w-full flex items-center gap-2.5",
      "pl-9 pr-3 py-2 rounded-lg transition-colors text-[13px]",
      active
        ? "bg-primary/10 text-primary font-semibold"
        : "text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground font-medium",
    ].join(" ");
  }

  function Section({ label, icon: Icon, open, toggle, active, subs, defaultHref }: {
    label: string; icon: React.ElementType; open: boolean; toggle: () => void;
    active: boolean; defaultHref: string;
    subs: { href: string; label: string; icon: React.ElementType }[];
  }) {
    if (isCollapsed) {
      return (
        <Link href={defaultHref} className={navCls(active)} title={label}>
          <Icon className="w-5 h-5 shrink-0" />
        </Link>
      );
    }
    return (
      <>
        <button type="button" onClick={toggle} className={navCls(active)}>
          <Icon className="w-5 h-5 shrink-0" />
          <span className="flex-1 text-left truncate">{label}</span>
          <ChevronDown className={["w-4 h-4 transition-transform duration-200 shrink-0", open ? "rotate-180" : ""].join(" ")} />
        </button>

        {open && (
          <ul className="mt-1 space-y-0.5">
            {subs.map((s) => {
              const SI = s.icon;
              return (
                <li key={s.href}>
                  <Link href={s.href} className={subCls(isActive(s.href))}>
                    <SI className="w-4 h-4 shrink-0" /><span className="truncate">{s.label}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </>
    );
  }

  // ── User initials for collapsed avatar ──
  const initials = (() => {
    const name = user?.name || user?.email || "";
    const parts = name.split(/[\s@]+/);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return name.slice(0, 2).toUpperCase();
  })();

  const currentWidth = isCollapsed ? COLLAPSED_WIDTH : sidebarWidth;

  return (
    <aside
      className="relative bg-sidebar border-r border-sidebar-border sticky top-0 h-screen shrink-0 flex flex-col overflow-hidden"
      style={{ width: currentWidth, transition: isResizing.current ? "none" : "width 0.3s ease" }}
    >
      {/* ── Collapse toggle ── */}
      <div className="p-4 flex justify-end">
        <button
          type="button"
          onClick={() => setIsCollapsed((v) => !v)}
          className="p-2 rounded-lg hover:bg-sidebar-accent text-muted-foreground hover:text-sidebar-accent-foreground transition-colors"
          aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {isCollapsed ? <ChevronRight className="w-5 h-5" /> : <ChevronLeft className="w-5 h-5" />}
        </button>
      </div>

      {/* ── Navigation ── */}
      <nav className="flex-1 px-3 pb-4 overflow-y-auto">
        <ul>
          {/* ── Order: Dashboard, Assets, Discovery, Scanning, Findings, Monitoring, Settings ── */}

          {/* Dashboard */}
          <li className="mb-1">
            <Link href="/dashboard" className={navCls(isActive("/dashboard"))} title={isCollapsed ? "Dashboard" : undefined}>
              <LayoutDashboard className="w-5 h-5 shrink-0" />
              {!isCollapsed && <span className="truncate">Dashboard</span>}
            </Link>
          </li>

          {/* Assets */}
          <li className="mb-1">
            <Link href="/assets" className={navCls(isActive("/assets"))} title={isCollapsed ? "Assets" : undefined}>
              <Layers className="w-5 h-5 shrink-0" />
              {!isCollapsed && <span className="truncate">Assets</span>}
            </Link>
          </li>

          {/* Discovery */}
          <li className="mb-1">
            <Link href="/discovery" className={navCls(isActive("/discovery"))} title={isCollapsed ? "Discovery" : undefined}>
              <Globe className="w-5 h-5 shrink-0" />
              {!isCollapsed && <span className="truncate">Discovery</span>}
            </Link>
          </li>

          {/* Scanning (dropdown) */}
          <li className="mb-1">
            <Section
              label="Scanning" icon={Activity}
              open={scanningOpen} toggle={() => setScanningOpen((v) => !v)}
              active={isScanningSection} defaultHref="/scan"
              subs={scanningSubs}
            />
          </li>

          {/* Findings (dropdown) */}
          <li className="mb-1">
            <Section
              label="Findings" icon={AlertCircle}
              open={findingsOpen} toggle={() => setFindingsOpen((v) => !v)}
              active={isFindingsSection} defaultHref="/findings"
              subs={findingsSubs}
            />
          </li>

          {/* Monitoring (dropdown) */}
          <li className="mb-1">
            <Section
              label="Monitoring" icon={Bell}
              open={monitoringOpen} toggle={() => setMonitoringOpen((v) => !v)}
              active={isMonitoringSection} defaultHref="/monitoring"
              subs={monitoringSubs}
            />
          </li>

          {/* LookUp Tools */}
          <li className="mb-1">
            <Link href="/tools" className={navCls(isActive("/tools"))} title={isCollapsed ? "LookUp Tools" : undefined}>
              <Server className="w-5 h-5 shrink-0" />
              {!isCollapsed && <span className="truncate">LookUp Tools</span>}
            </Link>
          </li>
        </ul>
      </nav>

      {/* ── Settings (pinned above user footer) ── */}
      <div className="px-3 pb-2">
        <Section
          label="Settings" icon={Settings}
          open={settingsOpen} toggle={() => setSettingsOpen((v) => !v)}
          active={isSettingsSection} defaultHref="/settings/account"
          subs={settingsSubs}
        />
      </div>

      {/* ── User info footer ── */}
      <div className="border-t border-sidebar-border px-3 py-3">
        {isCollapsed ? (
          <div className="flex flex-col items-center gap-2">
            <div className="w-8 h-8 rounded-full bg-primary/15 text-primary flex items-center justify-center text-xs font-bold" title={user?.name || user?.email || "User"}>
              {initials}
            </div>
            <button
              onClick={handleLogout}
              className="p-1.5 rounded-lg text-muted-foreground hover:bg-sidebar-accent hover:text-red-400 transition-colors"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <div className="space-y-2.5">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-full bg-primary/15 text-primary flex items-center justify-center text-xs font-bold shrink-0">
                {initials}
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-foreground truncate">
                  {user?.name || user?.email || "User"}
                </div>
                {user?.name && user?.email && (
                  <div className="text-[11px] text-muted-foreground truncate">{user.email}</div>
                )}
              </div>
            </div>

            {role && (
              <div className="flex items-center">
                <span className={`rounded-full border px-1.5 py-0.5 text-[10px] font-medium leading-none ${roleColors[role] || roleColors.viewer}`}>
                  {role.charAt(0).toUpperCase() + role.slice(1)}
                </span>
              </div>
            )}

            {isTrialing && trialDaysRemaining !== null && (
              <div className="rounded-md bg-[#ff8800]/10 border border-[#ff8800]/30 px-2 py-1 text-[10px] font-semibold text-[#ff8800]">
                Trial · {trialDaysRemaining}d remaining
              </div>
            )}

            <button
              onClick={handleLogout}
              className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-sm text-muted-foreground hover:bg-sidebar-accent hover:text-red-400 transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span>Logout</span>
            </button>
          </div>
        )}
      </div>

      {/* ── Resize handle (right edge) ── */}
      {!isCollapsed && (
        <div
          onMouseDown={onMouseDown}
          className="absolute top-0 right-0 w-1 h-full cursor-col-resize hover:bg-primary/30 active:bg-primary/50 transition-colors z-10"
        />
      )}
    </aside>
  );
}