// app/(unauthenticated)/AnimatedDashboard.tsx
"use client";

import { useState, useEffect } from "react";
import { Lock } from "lucide-react";

const VIEWS = ["Dashboard", "Scanning", "Findings"] as const;
type View = (typeof VIEWS)[number];
const INTERVAL = 5000;

export default function AnimatedDashboard() {
  const [activeView, setActiveView] = useState<View>("Dashboard");
  const [animKey, setAnimKey] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setActiveView((prev) => {
        const idx = VIEWS.indexOf(prev);
        return VIEWS[(idx + 1) % VIEWS.length];
      });
      setAnimKey((k) => k + 1);
    }, INTERVAL);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="relative rounded-2xl border border-white/[0.08] bg-[#0a1121]/80 backdrop-blur shadow-2xl shadow-black/40 overflow-hidden">

      <style jsx>{`
        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(12px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes slideInLeft {
          from { opacity: 0; transform: translateX(-10px); }
          to   { opacity: 1; transform: translateX(0); }
        }
        @keyframes growUp {
          from { transform: scaleY(0); }
          to   { transform: scaleY(1); }
        }
        @keyframes drawLine {
          from { stroke-dashoffset: 500; }
          to   { stroke-dashoffset: 0; }
        }
        @keyframes fadeInArea {
          from { opacity: 0; }
          to   { opacity: 1; }
        }
        @keyframes countPulse {
          0%   { opacity: 0; transform: scale(0.8); }
          60%  { opacity: 1; transform: scale(1.04); }
          100% { opacity: 1; transform: scale(1); }
        }
        @keyframes crossfadeIn {
          from { opacity: 0; }
          to   { opacity: 1; }
        }
        @keyframes progressBar {
          from { width: 0%; }
          to   { width: 100%; }
        }
        @keyframes pulseGlow {
          0%, 100% { opacity: 0.4; }
          50%      { opacity: 1; }
        }
        @keyframes slideInRight {
          from { opacity: 0; transform: translateX(16px); }
          to   { opacity: 1; transform: translateX(0); }
        }

        .anim-stat     { opacity: 0; animation: fadeInUp 0.5s ease forwards; }
        .anim-side     { opacity: 0; animation: slideInLeft 0.4s ease forwards; }
        .anim-chart    { opacity: 0; animation: fadeInUp 0.5s ease forwards; }
        .anim-count    { opacity: 0; animation: countPulse 0.5s ease forwards; }
        .anim-crossfade { animation: crossfadeIn 0.4s ease forwards; }
        .anim-slide-r  { opacity: 0; animation: slideInRight 0.4s ease forwards; }

        .anim-bar {
          transform-origin: bottom;
          transform: scaleY(0);
          animation: growUp 0.6s cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
        }
        .anim-line {
          stroke-dasharray: 500;
          stroke-dashoffset: 500;
          animation: drawLine 1.5s ease forwards;
        }
        .anim-area {
          opacity: 0;
          animation: fadeInArea 0.8s ease forwards;
        }
        .anim-progress {
          animation: progressBar 2.5s ease-in-out forwards;
        }
        .anim-pulse {
          animation: pulseGlow 1.5s ease-in-out infinite;
        }
        .view-indicator {
          transition: all 0.3s ease;
        }
      `}</style>

      {/* ── Window chrome ── */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.06] bg-white/[0.02]">
        <div className="flex gap-1.5">
          <div className="w-3 h-3 rounded-full bg-white/10" />
          <div className="w-3 h-3 rounded-full bg-white/10" />
          <div className="w-3 h-3 rounded-full bg-white/10" />
        </div>
        <div className="flex-1 mx-4">
          <div className="h-6 rounded-md bg-white/[0.04] border border-white/[0.06] max-w-sm mx-auto flex items-center px-3">
            <Lock className="w-3 h-3 text-white/20 mr-2" />
            <span className="text-[11px] text-white/25 font-mono">
              easm.boltedge.co/{activeView === "Dashboard" ? "dashboard" : activeView === "Scanning" ? "scan-jobs" : "findings"}
            </span>
          </div>
        </div>
      </div>

      {/* ── Content ── */}
      <div className="p-6 grid grid-cols-12 gap-4" style={{ minHeight: 320 }}>

        {/* Sidebar */}
        <div className="col-span-2 hidden lg:block space-y-3">
          {[
            { name: "Dashboard" },
            { name: "Assets" },
            { name: "Discovery" },
            { name: "Findings" },
            { name: "Scanning" },
            { name: "Monitoring" },
            { name: "Reports" },
          ].map(({ name }, i) => {
            const isActive = name === activeView;
            return (
              <div
                key={name}
                className={`anim-side view-indicator flex items-center gap-2 px-3 py-2 rounded-lg text-xs ${isActive ? "bg-teal-500/10 text-teal-300" : "text-white/25"}`}
                style={{ animationDelay: `${0.8 + i * 0.07}s` }}
              >
                <div className={`w-4 h-4 rounded view-indicator ${isActive ? "bg-teal-500/20" : "bg-white/[0.06]"}`} />
                {name}
              </div>
            );
          })}
        </div>

        {/* Main area */}
        <div className="col-span-12 lg:col-span-10">
          <div key={animKey} className="anim-crossfade">
            {activeView === "Dashboard" && <DashboardView />}
            {activeView === "Scanning" && <ScanningView />}
            {activeView === "Findings" && <FindingsView />}
          </div>
        </div>
      </div>

      {/* ── View dots ── */}
      <div className="flex items-center justify-center gap-2 pb-4">
        {VIEWS.map((v) => (
          <button
            key={v}
            onClick={() => { setActiveView(v); setAnimKey((k) => k + 1); }}
            className={`view-indicator h-1.5 rounded-full ${activeView === v ? "w-6 bg-teal-400/80" : "w-1.5 bg-white/15 hover:bg-white/25"}`}
          />
        ))}
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════
   VIEW 1 — Dashboard
   ═══════════════════════════════════════════ */
function DashboardView() {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Exposure Score", value: "69", color: "text-amber-400", sub: "/100" },
          { label: "Total Assets", value: "162", color: "text-teal-400", sub: "" },
          { label: "Open Findings", value: "48", color: "text-red-400", sub: "" },
          { label: "Resolved", value: "124", color: "text-emerald-400", sub: "" },
        ].map(({ label, value, color, sub }, i) => (
          <div key={label} className="anim-stat rounded-xl border border-white/[0.06] bg-white/[0.02] p-4" style={{ animationDelay: `${i * 0.1}s` }}>
            <div className="text-[10px] text-white/30 uppercase tracking-wider">{label}</div>
            <div className={`anim-count mt-1 text-2xl font-bold ${color}`} style={{ animationDelay: `${0.15 + i * 0.1}s` }}>
              {value}<span className="text-sm font-normal text-white/20">{sub}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="anim-chart rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 h-40" style={{ animationDelay: "0.3s" }}>
          <div className="text-[10px] text-white/30 uppercase tracking-wider mb-4">Exposure Trend</div>
          <svg viewBox="0 0 300 80" className="w-full h-20 overflow-visible">
            <defs>
              <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="rgb(20, 184, 166)" stopOpacity="0.3" />
                <stop offset="100%" stopColor="rgb(20, 184, 166)" stopOpacity="0" />
              </linearGradient>
            </defs>
            <path className="anim-area" style={{ animationDelay: "1s" }} d="M0,60 C50,55 80,45 120,50 C160,55 180,30 220,25 C260,20 280,35 300,30 L300,80 L0,80Z" fill="url(#trendGrad)" />
            <path className="anim-line" style={{ animationDelay: "0.4s" }} d="M0,60 C50,55 80,45 120,50 C160,55 180,30 220,25 C260,20 280,35 300,30" fill="none" stroke="rgb(20,184,166)" strokeWidth="2" />
          </svg>
        </div>
        <div className="anim-chart rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 h-40" style={{ animationDelay: "0.4s" }}>
          <div className="text-[10px] text-white/30 uppercase tracking-wider mb-3">Severity Breakdown</div>
          <div className="flex items-end gap-3 h-24 px-2">
            {[
              { h: "70%", color: "bg-red-500/60", label: "5" },
              { h: "100%", color: "bg-orange-500/60", label: "12" },
              { h: "60%", color: "bg-yellow-500/60", label: "18" },
              { h: "30%", color: "bg-blue-500/60", label: "8" },
              { h: "20%", color: "bg-zinc-500/40", label: "5" },
            ].map(({ h, color, label }, i) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-1">
                <span className="anim-count text-[9px] text-white/30" style={{ animationDelay: `${0.6 + i * 0.08}s` }}>{label}</span>
                <div className={`anim-bar w-full rounded-t ${color}`} style={{ height: h, animationDelay: `${0.5 + i * 0.08}s` }} />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════
   VIEW 2 — Scanning
   ═══════════════════════════════════════════ */
function ScanningView() {
  return (
    <div className="space-y-4">
      <div className="anim-stat flex items-center justify-between" style={{ animationDelay: "0s" }}>
        <div>
          <div className="text-sm font-semibold text-white">Scan Jobs</div>
          <div className="text-[10px] text-white/30 mt-0.5">3 active &middot; 12 completed today</div>
        </div>
        <div className="px-3 py-1.5 rounded-lg bg-teal-500/10 text-teal-400 text-[10px] font-medium uppercase tracking-wide">
          + New Scan
        </div>
      </div>

      <div className="space-y-3">
        {[
          { target: "api.example.com", profile: "Deep", progress: 78, engine: "Nuclei", sev: { c: 2, h: 5, m: 3 } },
          { target: "mail.example.com", profile: "Standard", progress: 45, engine: "Nmap", sev: { c: 0, h: 1, m: 4 } },
          { target: "cdn.example.com", profile: "Quick", progress: 92, engine: "Shodan", sev: { c: 0, h: 0, m: 1 } },
        ].map((scan, i) => (
          <div key={scan.target} className="anim-slide-r rounded-xl border border-white/[0.06] bg-white/[0.02] p-4" style={{ animationDelay: `${0.1 + i * 0.12}s` }}>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-3">
                <div className="anim-pulse w-2 h-2 rounded-full bg-teal-400" />
                <span className="text-xs font-medium text-white">{scan.target}</span>
                <span className="text-[10px] text-white/20 px-2 py-0.5 rounded bg-white/[0.04]">{scan.profile}</span>
                <span className="text-[10px] text-white/20 px-2 py-0.5 rounded bg-white/[0.04]">{scan.engine}</span>
              </div>
              <div className="flex items-center gap-2">
                {scan.sev.c > 0 && <span className="text-[10px] font-bold text-red-400">{scan.sev.c}C</span>}
                {scan.sev.h > 0 && <span className="text-[10px] font-bold text-orange-400">{scan.sev.h}H</span>}
                {scan.sev.m > 0 && <span className="text-[10px] font-bold text-yellow-400">{scan.sev.m}M</span>}
              </div>
            </div>
            <div className="h-1.5 rounded-full bg-white/[0.06] overflow-hidden">
              <div className="anim-progress h-full rounded-full bg-gradient-to-r from-teal-500 to-cyan-400" style={{ animationDelay: `${0.3 + i * 0.12}s`, maxWidth: `${scan.progress}%` }} />
            </div>
            <div className="flex justify-between mt-1.5">
              <span className="text-[10px] text-white/20">{scan.progress}% complete</span>
              <span className="text-[10px] text-white/20">{Math.round((100 - scan.progress) * 0.3)}s remaining</span>
            </div>
          </div>
        ))}
      </div>

      <div className="anim-stat rounded-xl border border-white/[0.06] bg-white/[0.02] p-4" style={{ animationDelay: "0.5s" }}>
        <div className="text-[10px] text-white/30 uppercase tracking-wider mb-3">Recently Completed</div>
        <div className="space-y-2">
          {[
            { target: "login.example.com", findings: 8, time: "2m ago" },
            { target: "app.example.com", findings: 14, time: "18m ago" },
          ].map((scan) => (
            <div key={scan.target} className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-emerald-400/60" />
                <span className="text-white/50">{scan.target}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-white/30">{scan.findings} findings</span>
                <span className="text-white/20">{scan.time}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════
   VIEW 3 — Findings
   ═══════════════════════════════════════════ */
function FindingsView() {
  const findings = [
    { sev: "critical", title: "Remote Code Execution via Log4Shell", asset: "api.example.com", cat: "Injection", status: "open" },
    { sev: "critical", title: "SQL Injection in /api/users endpoint", asset: "app.example.com", cat: "Injection", status: "open" },
    { sev: "high", title: "Expired SSL Certificate", asset: "mail.example.com", cat: "TLS/SSL", status: "in_progress" },
    { sev: "high", title: "Directory Listing Enabled", asset: "cdn.example.com", cat: "Misconfiguration", status: "open" },
    { sev: "high", title: "Missing HSTS Header", asset: "login.example.com", cat: "Headers", status: "open" },
    { sev: "medium", title: "Outdated jQuery 2.1.4", asset: "app.example.com", cat: "Outdated Software", status: "open" },
    { sev: "medium", title: "CORS Wildcard Policy", asset: "api.example.com", cat: "Misconfiguration", status: "in_progress" },
  ];

  const sevColor: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400",
    high: "bg-orange-500/20 text-orange-400",
    medium: "bg-yellow-500/15 text-yellow-400",
    low: "bg-blue-500/20 text-blue-400",
  };
  const statusLabel: Record<string, { text: string; cls: string }> = {
    open: { text: "Open", cls: "text-red-400/70" },
    in_progress: { text: "In Progress", cls: "text-amber-400/70" },
    resolved: { text: "Resolved", cls: "text-emerald-400/70" },
  };

  return (
    <div className="space-y-4">
      <div className="anim-stat flex items-center justify-between" style={{ animationDelay: "0s" }}>
        <div>
          <div className="text-sm font-semibold text-white">All Findings</div>
          <div className="text-[10px] text-white/30 mt-0.5">
            <span className="text-red-400">2 critical</span> &middot; <span className="text-orange-400">3 high</span> &middot; <span className="text-yellow-400">2 medium</span> &middot; 48 total
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="px-2.5 py-1 rounded-md bg-white/[0.04] border border-white/[0.06] text-[10px] text-white/30">Filter</div>
          <div className="px-2.5 py-1 rounded-md bg-white/[0.04] border border-white/[0.06] text-[10px] text-white/30">Export</div>
        </div>
      </div>

      <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
        <div className="grid grid-cols-12 gap-2 px-4 py-2.5 border-b border-white/[0.06] bg-white/[0.02]">
          <div className="col-span-2 text-[10px] text-white/30 uppercase tracking-wider">Severity</div>
          <div className="col-span-4 text-[10px] text-white/30 uppercase tracking-wider">Finding</div>
          <div className="col-span-3 text-[10px] text-white/30 uppercase tracking-wider">Asset</div>
          <div className="col-span-2 text-[10px] text-white/30 uppercase tracking-wider">Category</div>
          <div className="col-span-1 text-[10px] text-white/30 uppercase tracking-wider">Status</div>
        </div>

        {findings.map((f, i) => (
          <div
            key={i}
            className="anim-slide-r grid grid-cols-12 gap-2 px-4 py-2.5 border-b border-white/[0.04] last:border-b-0"
            style={{ animationDelay: `${0.1 + i * 0.06}s` }}
          >
            <div className="col-span-2">
              <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase ${sevColor[f.sev]}`}>{f.sev}</span>
            </div>
            <div className="col-span-4 text-xs text-white/70 truncate">{f.title}</div>
            <div className="col-span-3 text-xs text-white/40 font-mono truncate">{f.asset}</div>
            <div className="col-span-2 text-[10px] text-white/30">{f.cat}</div>
            <div className={`col-span-1 text-[10px] font-medium ${statusLabel[f.status].cls}`}>{statusLabel[f.status].text}</div>
          </div>
        ))}
      </div>
    </div>
  );
}