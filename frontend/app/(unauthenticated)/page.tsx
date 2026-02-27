// app/(unauthenticated)/page.tsx
// F4: Landing page — animated, accurate pricing & features
import Link from "next/link";
import {
  BarChart3, Zap, Globe2, Bell,
  TrendingUp, FileText, ArrowRight,
  Search, Webhook, ClipboardCheck, Radar,
  Code2, ShieldCheck, Check, X,
} from "lucide-react";

import LandingNav from "./LandingNav";
import QuickScanCard from "./QuickScanCard";
import QuickDiscoveryCard from "./QuickDiscoveryCard";
import QuickToolsCard from "./QuickToolsCard";
import FadeInOnScroll from "./Fadeinonscroll";
import AnimatedDashboard from "./AnimatedDashboard";
import {
  HeroStagger, HeroItem, HeroDashboard, HeroFadeIn,
} from "./Animatedhero";

export default function UnauthenticatedHomePage() {
  return (
    <div className="min-h-screen bg-[#060b18] text-white overflow-x-hidden">

      {/* ================= TOP NAV ================= */}
      <LandingNav />
      <div className="h-16" /> {/* spacer for fixed navbar */}

      {/* ================= HERO (Framer Motion) ================= */}
      <main>
        <section className="relative">
          {/* Background effects */}
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[600px] bg-gradient-to-b from-teal-500/[0.07] via-cyan-500/[0.04] to-transparent rounded-full blur-3xl" />
            <div className="absolute top-40 right-0 w-[400px] h-[400px] bg-purple-500/[0.03] rounded-full blur-3xl" />
            <div
              className="absolute inset-0 opacity-[0.03]"
              style={{
                backgroundImage: `linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)`,
                backgroundSize: "60px 60px",
              }}
            />
          </div>

          <div className="relative mx-auto max-w-6xl px-4 sm:px-6 pt-20 sm:pt-28 lg:pt-36 pb-16">
            <HeroStagger>
              <HeroItem>
                <div className="inline-flex items-center gap-2 rounded-full border border-teal-500/20 bg-teal-500/[0.06] px-4 py-1.5 mb-8">
                  <span className="relative flex h-2 w-2">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-teal-400 opacity-75" />
                    <span className="relative inline-flex h-2 w-2 rounded-full bg-teal-400" />
                  </span>
                  <span className="text-xs font-medium text-teal-400/70 tracking-wide">External Attack Surface Management</span>
                </div>
              </HeroItem>

              <HeroItem>
                <h1 className="max-w-4xl text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl lg:text-[3.5rem]">
                  Know your exposure<br />
                  <span className="bg-gradient-to-r from-teal-400/80 via-cyan-400/70 to-teal-500/80 bg-clip-text text-transparent">before attackers do</span>
                </h1>
              </HeroItem>

              <HeroItem>
                <p className="mt-6 max-w-2xl text-base text-white/45 leading-relaxed sm:text-lg">
                  Discover assets, scan for vulnerabilities, and quantify risk across your
                  entire external attack surface. From subdomain enumeration to remediation
                  tracking — one platform, full visibility.
                </p>
              </HeroItem>

              <HeroItem>
                <div className="mt-10 flex flex-col sm:flex-row items-center gap-4">
                  <Link href="/register" className="group inline-flex items-center gap-2 rounded-xl bg-teal-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-teal-900/30 hover:bg-teal-500 transition-all">
                    Start free — no credit card
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                  </Link>
                  <a href="#try-it" className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-6 py-3 text-sm font-medium text-white/50 hover:text-white hover:bg-white/[0.06] transition-all">
                    <Search className="w-4 h-4" />See it in action
                  </a>
                </div>
              </HeroItem>
            </HeroStagger>

            <HeroDashboard className="mt-20 relative">
              <div className="absolute -inset-4 bg-gradient-to-b from-teal-500/10 to-transparent rounded-3xl blur-2xl pointer-events-none" />
              <AnimatedDashboard />
            </HeroDashboard>

            <HeroFadeIn delay={0.9} className="mt-16 text-center">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-6 max-w-2xl mx-auto">
                {[
                  { value: "5", label: "Scan engines" },
                  { value: "3", label: "Scan profiles" },
                  { value: "6+", label: "Integration types" },
                  { value: "100%", label: "API coverage" },
                ].map(({ value, label }) => (
                  <div key={label}>
                    <div className="text-2xl font-bold bg-gradient-to-r from-teal-400/80 to-cyan-400/70 bg-clip-text text-transparent">{value}</div>
                    <div className="text-xs text-white/30 mt-1">{label}</div>
                  </div>
                ))}
              </div>
            </HeroFadeIn>
          </div>
        </section>

        {/* ================= TRY IT ================= */}
        <section id="try-it" className="py-24 sm:py-32">
          <div className="mx-auto max-w-6xl px-4 sm:px-6">
            <FadeInOnScroll>
              <div className="text-center mb-12">
                <span className="text-xs font-semibold text-teal-400 uppercase tracking-widest">Try it now</span>
                <h2 className="mt-4 text-3xl font-bold tracking-tight sm:text-4xl">See it in action — no signup needed</h2>
                <p className="mt-4 text-base text-white/40 max-w-xl mx-auto">
                  Run a quick scan or discovery against any domain to see what BoltEdge EASM can find.
                  Create a free account to save results and unlock full features.
                </p>
              </div>
            </FadeInOnScroll>

            {/* ── FIXED: items-stretch + h-full wrappers ── */}
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-3 items-stretch max-w-5xl mx-auto">
              <FadeInOnScroll delay={100} className="h-full"><QuickScanCard /></FadeInOnScroll>
              <FadeInOnScroll delay={200} className="h-full"><QuickDiscoveryCard /></FadeInOnScroll>
              <FadeInOnScroll delay={300} className="h-full"><QuickToolsCard /></FadeInOnScroll>
            </div>
          </div>
        </section>

        {/* ================= FEATURES ================= */}
        <section id="features" className="relative py-24 sm:py-32">
          <div className="absolute inset-0 bg-gradient-to-b from-transparent via-teal-500/[0.02] to-transparent pointer-events-none" />
          <div className="relative mx-auto max-w-6xl px-4 sm:px-6">
            <FadeInOnScroll>
              <div className="text-center mb-16">
                <span className="text-xs font-semibold text-teal-400 uppercase tracking-widest">Capabilities</span>
                <h2 className="mt-4 text-3xl font-bold tracking-tight sm:text-4xl">
                  Everything you need to manage<br /><span className="text-white/50">your attack surface</span>
                </h2>
              </div>
            </FadeInOnScroll>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
              {[
                { icon: Radar, title: "Asset Discovery", desc: "Enumerate subdomains, IPs, and services from a root domain. CT logs, DNS brute-forcing, and passive intelligence — all automated.", color: "from-cyan-500/20 to-cyan-500/5", iconColor: "text-cyan-400" },
                { icon: Search, title: "Multi-Engine Scanning", desc: "Scan with Shodan, Nmap, Nuclei, and SSLyze. Choose Quick, Standard, or Deep profiles — or schedule recurring scans daily, weekly, or monthly.", color: "from-purple-500/20 to-purple-500/5", iconColor: "text-purple-400" },
                { icon: BarChart3, title: "Exposure Scoring", desc: "Quantified risk scores per asset and group with logarithmic severity weighting. Track score changes over time with trend analysis.", color: "from-amber-500/20 to-amber-500/5", iconColor: "text-amber-400" },
                { icon: Bell, title: "Continuous Monitoring", desc: "Monitor assets and groups for changes. Configurable check intervals from every 12 hours to every 5 days. Fine-tune alerts with custom rules.", color: "from-rose-500/20 to-rose-500/5", iconColor: "text-rose-400" },
                { icon: ClipboardCheck, title: "Remediation Workflow", desc: "Track findings through open → in progress → resolved. Accept risk with justification, suppress false positives, and measure time-to-remediate.", color: "from-emerald-500/20 to-emerald-500/5", iconColor: "text-emerald-400" },
                { icon: FileText, title: "Reports & Trending", desc: "Generate executive summaries and full technical PDF reports with embedded charts. Schedule weekly or monthly report delivery.", color: "from-blue-500/20 to-blue-500/5", iconColor: "text-blue-400" },
                { icon: Webhook, title: "Integrations", desc: "Connect to Slack, Jira, PagerDuty, email, and custom webhooks. Create notification rules that auto-fire on critical findings or exposure thresholds.", color: "from-indigo-500/20 to-indigo-500/5", iconColor: "text-indigo-400" },
                { icon: Code2, title: "API & Automation", desc: "Full REST API with scoped API keys. Automate asset onboarding, trigger scans, pull findings, and integrate with your existing security toolchain.", color: "from-sky-500/20 to-sky-500/5", iconColor: "text-sky-400" },
                { icon: ShieldCheck, title: "Enterprise Controls", desc: "Role-based access (Viewer, Analyst, Admin, Owner), full audit log of every action, team management, and tiered plan controls.", color: "from-teal-500/20 to-teal-500/5", iconColor: "text-teal-400" },
              ].map(({ icon: Icon, title, desc, color, iconColor }, idx) => (
                <FadeInOnScroll key={title} delay={idx * 80}>
                  <div className="group relative rounded-2xl border border-white/[0.06] bg-white/[0.02] p-6 hover:border-white/[0.12] hover:bg-white/[0.04] transition-all duration-300 h-full">
                    <div className={`absolute inset-0 rounded-2xl bg-gradient-to-b ${color} opacity-0 group-hover:opacity-100 transition-opacity duration-300`} />
                    <div className="relative">
                      <div className={`inline-flex h-11 w-11 items-center justify-center rounded-xl bg-white/[0.06] ${iconColor} mb-4 group-hover:scale-110 transition-transform duration-300`}>
                        <Icon className="h-5 w-5" />
                      </div>
                      <h3 className="text-sm font-semibold text-white mb-2">{title}</h3>
                      <p className="text-sm text-white/40 leading-relaxed">{desc}</p>
                    </div>
                  </div>
                </FadeInOnScroll>
              ))}
            </div>
          </div>
        </section>

        {/* ================= HOW IT WORKS ================= */}
        <section id="how-it-works" className="py-24 sm:py-32">
          <div className="mx-auto max-w-6xl px-4 sm:px-6">
            <FadeInOnScroll>
              <div className="text-center mb-16">
                <span className="text-xs font-semibold text-teal-400 uppercase tracking-widest">How it works</span>
                <h2 className="mt-4 text-3xl font-bold tracking-tight sm:text-4xl">Four steps to full visibility</h2>
              </div>
            </FadeInOnScroll>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
              {[
                { step: "01", title: "Discover", desc: "Add a root domain. We enumerate subdomains, IPs, services, and certificates across your entire external surface.", icon: Globe2 },
                { step: "02", title: "Scan & Score", desc: "Run automated scans with multiple engines. Every finding is categorized, scored, and enriched with remediation guidance.", icon: Zap },
                { step: "03", title: "Monitor & Alert", desc: "Set up continuous monitors with configurable frequency. Get alerts in Slack, PagerDuty, Jira, or email when things change.", icon: Bell },
                { step: "04", title: "Remediate & Report", desc: "Track findings through your workflow. Generate PDF reports for stakeholders. Watch your exposure score drop over time.", icon: TrendingUp },
              ].map(({ step, title, desc, icon: Icon }, idx) => (
                <FadeInOnScroll key={step} delay={idx * 120}>
                  <div className="relative">
                    <div className="text-5xl font-bold text-white/[0.04] mb-4">{step}</div>
                    <div className="inline-flex h-10 w-10 items-center justify-center rounded-lg bg-teal-500/10 text-teal-400 mb-4"><Icon className="h-5 w-5" /></div>
                    <h3 className="text-lg font-semibold text-white mb-2">{title}</h3>
                    <p className="text-sm text-white/40 leading-relaxed">{desc}</p>
                  </div>
                </FadeInOnScroll>
              ))}
            </div>
          </div>
        </section>

        {/* ================= PRICING ================= */}
        <section id="pricing" className="py-24 sm:py-32">
          <div className="mx-auto max-w-6xl px-4 sm:px-6">
            <FadeInOnScroll>
              <div className="text-center mb-16">
                <span className="text-xs font-semibold text-teal-400 uppercase tracking-widest">Pricing</span>
                <h2 className="mt-4 text-3xl font-bold tracking-tight sm:text-4xl">Start free, scale when ready</h2>
                <p className="mt-4 text-base text-white/40 max-w-lg mx-auto">Every paid plan includes a free trial. No credit card required to get started.</p>
              </div>
            </FadeInOnScroll>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 max-w-5xl mx-auto">
              {[
                { name: "Free", price: "$0", period: "", desc: "Explore the platform", limits: ["2 assets","4 scans / month","Quick & Standard profiles","1 team member","Basic findings view"], excluded: ["Monitoring","Integrations","Scheduled scans"], cta: "Get started", href: "/register", highlight: false, trial: null },
                { name: "Starter", price: "$19", period: "/mo", desc: "For individuals & small teams", limits: ["15 assets","500 scans / month","All scan profiles","5 team members","10 scheduled scans","Monitoring (every 5 days)","3 API keys"], excluded: ["Webhooks","Deep discovery"], cta: "Start 14-day trial", href: "/register", highlight: false, trial: 14 },
                { name: "Professional", price: "$79", period: "/mo", desc: "For growing security teams", limits: ["100 assets","5,000 scans / month","All scan profiles","20 team members","50 scheduled scans","Monitoring (every 2 days)","10 API keys","Webhooks & integrations","Deep discovery"], excluded: [], cta: "Start 21-day trial", href: "/register", highlight: true, trial: 21 },
                { name: "Enterprise", price: "$249", period: "/mo", desc: "For organizations at scale", limits: ["15,000 assets","Unlimited scans","All scan profiles","100 team members","100 scheduled scans","Daily monitoring","Unlimited API keys","All integrations","Audit log","Priority support"], excluded: [], cta: "Start 30-day trial", href: "/register", highlight: false, trial: 30 },
              ].map(({ name, price, period, desc, limits, excluded, cta, href, highlight, trial }, idx) => (
                <FadeInOnScroll key={name} delay={idx * 100}>
                  <div className={`relative rounded-2xl border p-6 flex flex-col h-full ${highlight ? "border-teal-500/30 bg-gradient-to-b from-teal-500/[0.08] to-transparent" : "border-white/[0.06] bg-white/[0.02]"}`}>
                    {highlight && (
                      <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                        <span className="inline-flex items-center rounded-full bg-teal-600 px-3 py-1 text-[10px] font-semibold text-white uppercase tracking-wider">Most popular</span>
                      </div>
                    )}
                    <div className="text-sm font-semibold text-white mb-1">{name}</div>
                    <div className="flex items-baseline gap-1 mb-1">
                      <span className="text-3xl font-bold text-white">{price}</span>
                      {period && <span className="text-sm text-white/30">{period}</span>}
                    </div>
                    <p className="text-xs text-white/40 mb-5">{desc}</p>
                    {trial && <div className="text-[10px] text-teal-400/80 font-medium mb-4 uppercase tracking-wide">{trial}-day free trial</div>}
                    <ul className="space-y-2 mb-6 flex-1">
                      {limits.map((f) => (<li key={f} className="flex items-start gap-2 text-[13px] text-white/50"><Check className="w-3.5 h-3.5 text-teal-500/70 shrink-0 mt-0.5" />{f}</li>))}
                      {excluded.map((f) => (<li key={f} className="flex items-start gap-2 text-[13px] text-white/20"><X className="w-3.5 h-3.5 text-white/10 shrink-0 mt-0.5" />{f}</li>))}
                    </ul>
                    <Link href={href} className={`block w-full text-center rounded-lg py-2.5 text-sm font-medium transition-all ${highlight ? "bg-teal-600 text-white shadow-md shadow-teal-900/20 hover:bg-teal-500" : "border border-white/10 bg-white/[0.03] text-white/60 hover:text-white hover:bg-white/[0.06]"}`}>{cta}</Link>
                  </div>
                </FadeInOnScroll>
              ))}
            </div>

            <FadeInOnScroll delay={450}>
              <div className="mt-8 max-w-5xl mx-auto">
                <div className="rounded-2xl border border-white/[0.06] bg-white/[0.02] px-8 py-6 flex flex-col sm:flex-row items-center justify-between gap-4">
                  <div>
                    <div className="text-sm font-semibold text-white">Need more? Enterprise Gold</div>
                    <p className="text-xs text-white/40 mt-1">50,000+ assets, custom scan profiles, SSO, dedicated support, and SLA guarantees.</p>
                  </div>
                  <Link href="/register" className="shrink-0 inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-5 py-2.5 text-sm font-medium text-white/60 hover:text-white hover:bg-white/[0.06] transition-all">
                    Contact sales<ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>
            </FadeInOnScroll>
          </div>
        </section>

        {/* ================= FINAL CTA ================= */}
        <section className="py-24 sm:py-32">
          <div className="mx-auto max-w-6xl px-4 sm:px-6">
            <FadeInOnScroll>
              <div className="relative overflow-hidden rounded-3xl border border-white/[0.08] bg-gradient-to-br from-[#0d1a2e] to-[#0a1121] px-8 py-16 text-center sm:px-16">
                <div className="absolute inset-0 pointer-events-none">
                  <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[500px] h-[300px] bg-teal-500/[0.06] rounded-full blur-3xl" />
                </div>
                <div className="relative">
                  <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
                    Start securing your<span className="bg-gradient-to-r from-teal-400/80 to-cyan-400/70 bg-clip-text text-transparent"> attack surface</span>
                  </h2>
                  <p className="mt-4 text-base text-white/40 max-w-lg mx-auto">Join security teams using BoltEdge EASM to discover, scan, and continuously monitor their external exposure.</p>
                  <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
                    <Link href="/register" className="group inline-flex items-center gap-2 rounded-xl bg-teal-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-teal-900/30 hover:bg-teal-500 transition-all">
                      Create free account<ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                    </Link>
                    <Link href="/login" className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-6 py-3 text-sm font-medium text-white/60 hover:text-white hover:bg-white/[0.06] transition-all">Sign in</Link>
                  </div>
                </div>
              </div>
            </FadeInOnScroll>
          </div>
        </section>
      </main>

      {/* ================= FOOTER ================= */}
      <footer className="border-t border-white/[0.06]">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 py-10">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div>
              <Link href="/" className="flex items-center gap-2.5">
                <svg width="22" height="22" viewBox="0 0 32 32" fill="none" className="shrink-0">
                  <rect width="32" height="32" rx="7" fill="#0a0f1e"/>
                  <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#14b8a6"/>
                </svg>
                <span className="text-sm font-semibold">
                  Bolt<span className="text-teal-400">Edge</span>
                  <span className="text-[10px] text-white/40 font-medium ml-1 uppercase tracking-wider">EASM</span>
                </span>
              </Link>
              <p className="mt-2 text-sm text-white/30">
                External Attack Surface Management by{" "}
                <a href="https://boltedge.co" className="text-teal-400/70 hover:text-teal-400 transition-colors">BoltEdge</a>.
              </p>
            </div>
            <div className="flex items-center gap-8 text-sm text-white/30">
              <a href="https://boltedge.co" target="_blank" rel="noopener" className="hover:text-white/60 transition-colors">boltedge.co</a>
              <a href="mailto:support@boltedge.co" className="hover:text-white/60 transition-colors">Support</a>
            </div>
          </div>
          <div className="mt-8 pt-6 border-t border-white/[0.04] text-xs text-white/20 text-center">
            &copy; {new Date().getFullYear()} BoltEdge. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}