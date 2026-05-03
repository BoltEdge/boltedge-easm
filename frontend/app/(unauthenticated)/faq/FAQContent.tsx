// FILE: app/(unauthenticated)/faq/FAQContent.tsx
// Categorised, accordion-style FAQ with live keyword search.
//
// Uses native <details>/<summary> so:
//   - Browser find-in-page (Cmd/Ctrl-F) finds answer text AND
//     auto-expands the matching item (Chrome 102+, Edge, Firefox 124+,
//     Safari 17+) — works alongside our own search box.
//   - Free accessibility: keyboard toggle, screen-reader semantics.
//
// Live search filters by question text + extracted answer text and
// auto-opens matching items so the user sees the answer immediately.

"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import { ChevronDown, Rocket, ShieldAlert, CreditCard, Lock, Plug, Search, X } from "lucide-react";
import type { ReactNode } from "react";

type FAQItem = { q: string; a: ReactNode };
type Category = { title: string; icon: typeof Rocket; items: FAQItem[] };

const FAQS: Category[] = [
  {
    title: "Getting started",
    icon: Rocket,
    items: [
      {
        q: "What does Nano EASM do?",
        a: (
          <p>
            Nano EASM helps you see your external attack surface the way an attacker would.
            You give it a domain, IP, or cloud asset, and it discovers what&rsquo;s connected
            to it — subdomains, exposed services, cloud buckets, certificates — scans for
            vulnerabilities, watches for changes over time, and turns each finding into clear
            next steps your team can act on.
          </p>
        ),
      },
      {
        q: "Do I need to install anything?",
        a: (
          <p>
            No. Nano EASM is fully cloud-hosted. You sign in through your browser, add your
            assets, and start scanning. Nothing to deploy on your network. If you want to
            connect Slack, Jira, or webhooks, that&rsquo;s a config setting in the dashboard.
          </p>
        ),
      },
      {
        q: "How do I add my first asset?",
        a: (
          <p>
            After signing up, go to <strong>Assets</strong> and click <strong>Add asset</strong>.
            Drop in a domain, IP, or cloud asset URL you own or are authorised to test.
            Nano EASM will start mapping what&rsquo;s exposed within minutes.
          </p>
        ),
      },
      {
        q: "What is the difference between Quick, Standard, and Deep scans?",
        a: (
          <>
            <p>
              <strong>Quick</strong> scans run in seconds and check the most-common ports and
              headline issues — good for a first look or fast revalidation.
            </p>
            <p className="mt-2">
              <strong>Standard</strong> scans are the default and balance depth with speed
              (most users live here).
            </p>
            <p className="mt-2">
              <strong>Deep</strong> scans check a wider range of ports, services, and known
              vulnerabilities, and can take several minutes. All three honour the same
              authorisation rules.
            </p>
          </>
        ),
      },
      {
        q: "How long does a scan take?",
        a: (
          <p>
            Quick scans finish in under a minute. Standard scans typically take a few minutes.
            Deep scans can take 10–20 minutes depending on what&rsquo;s exposed and how much
            there is to check. You don&rsquo;t have to wait around — kick it off and we&rsquo;ll
            email you when it&rsquo;s done if you&rsquo;ve enabled notifications.
          </p>
        ),
      },
    ],
  },
  {
    title: "Scanning & authorisation",
    icon: ShieldAlert,
    items: [
      {
        q: "What am I allowed to scan?",
        a: (
          <p>
            Anything you own, or anything you have explicit written permission to test.
            That&rsquo;s the rule. If your name is on the domain registration or your company
            controls the IP range, you&rsquo;re fine. If you&rsquo;re testing a client&rsquo;s
            environment under a contract or statement of work, you&rsquo;re fine. If
            you&rsquo;re &ldquo;pretty sure it&rsquo;ll be okay&rdquo; — you&rsquo;re not.
            The full breakdown is in our{" "}
            <Link href="/terms-and-policies/acceptable-use-policy" className="text-teal-400 hover:text-teal-300">Acceptable Use Policy</Link>{" "}
            and{" "}
            <Link href="/terms-and-policies/security-scanning-authorisation" className="text-teal-400 hover:text-teal-300">Security &amp; Scanning Authorisation</Link>.
          </p>
        ),
      },
      {
        q: "Can I scan a customer's domain?",
        a: (
          <p>
            Yes — if you have written authorisation. A signed pentesting engagement, an MSSP
            services agreement that names the asset, a statement of work, or explicit written
            permission from the asset owner. &ldquo;They&rsquo;re a client&rdquo; or
            &ldquo;I used to work there&rdquo; isn&rsquo;t enough. We log every scan with its
            origin, so attribution is clear if anyone ever asks.
          </p>
        ),
      },
      {
        q: "What should I not scan?",
        a: (
          <p>
            Anything you don&rsquo;t have authority to test. That includes critical national
            infrastructure (power, water, signals), government or military systems without a
            contract, healthcare systems without compliance clearance, and shared cloud
            infrastructure where your authority extends only to your own tenant. You also
            shouldn&rsquo;t scan our own sub-processors (Stripe, Resend, AWS, etc.). Detailed
            list in the{" "}
            <Link href="/terms-and-policies/security-scanning-authorisation" className="text-teal-400 hover:text-teal-300">Security &amp; Scanning Authorisation</Link>{" "}
            document.
          </p>
        ),
      },
      {
        q: "Will scans appear in logs?",
        a: (
          <p>
            Yes. Active scanning generates real network traffic, and any well-monitored target
            will see your requests in their logs. SIEMs and IDS systems may even alert on it.
            This is normal and expected — but it&rsquo;s another reason to only scan what
            you&rsquo;re authorised to scan.
          </p>
        ),
      },
      {
        q: "What happens if someone abuses the platform?",
        a: (
          <p>
            We log every scan with the originating account, IP, and target. We rate-limit
            unauthenticated quick scans, IP-block repeat abusers, and reserve the right to
            suspend or terminate accounts engaged in unauthorised scanning. We may also
            disclose logs to law enforcement when required by law or by a serious abuse
            report. The full enforcement ladder is in our{" "}
            <Link href="/terms-and-policies/acceptable-use-policy" className="text-teal-400 hover:text-teal-300">Acceptable Use Policy</Link>.
          </p>
        ),
      },
      {
        q: "Can Nano EASM guarantee it finds every exposed asset?",
        a: (
          <p>
            <strong>No</strong> — and any tool that claims to is overpromising. Discovery is
            best-effort. We use multiple sources (CT logs, DNS enumeration, certificate
            inspection, third-party intelligence feeds) and continuously expand coverage,
            but no automated tool finds 100% of an organisation&rsquo;s exposed assets,
            especially shadow IT, internal-only DNS, or assets behind authentication.
            Findings, severity scores, and remediation guidance also benefit from independent
            verification before you act on them.
          </p>
        ),
      },
    ],
  },
  {
    title: "Pricing & plans",
    icon: CreditCard,
    items: [
      {
        q: "Is Nano EASM free to start?",
        a: (
          <p>
            Yes. The Free plan lets you add up to 2 assets and run up to 5 scans per month
            with no payment method required. Use it to evaluate the platform on your own
            infrastructure before committing to a paid plan.
          </p>
        ),
      },
      {
        q: "How do trials work?",
        a: (
          <p>
            Trials are <strong>request-only</strong> — click <em>Request free trial</em> on
            any paid plan card and we&rsquo;ll review the request manually. If approved, the
            requested plan is enabled on your organisation for a defined period at no charge.
            No payment method is required during the trial. If you don&rsquo;t convert, your
            organisation reverts to the Free plan when the trial ends.
          </p>
        ),
      },
      {
        q: "What happens if I exceed my plan limits?",
        a: (
          <p>
            You&rsquo;ll see a clear message in the app explaining which limit you hit. Most
            actions are blocked rather than charged as overages — we don&rsquo;t want surprise
            bills. To run more scans, monitor more assets, or invite more teammates, upgrade
            to a higher plan. Plan changes mid-cycle are pro-rated automatically.
          </p>
        ),
      },
      {
        q: "Can I upgrade or downgrade later?",
        a: (
          <p>
            Yes, anytime. Open <strong>Settings &rarr; Billing &rarr; Manage billing</strong>.
            Upgrades take effect immediately with pro-rated charges. Downgrades take effect
            at the end of your current billing period — you keep your current limits until
            then. There&rsquo;s no contract lock-in.
          </p>
        ),
      },
      {
        q: "How do refunds and cancellations work?",
        a: (
          <p>
            Cancellations take effect at the end of your current billing period — you keep
            paid features until then, and your data isn&rsquo;t deleted. Subscription fees
            are non-refundable for elapsed time, with exceptions for billing errors, material
            service failures on our side, and where consumer law requires (e.g. Australian
            Consumer Law guarantees). Full details in our{" "}
            <Link href="/terms-and-policies/refund-cancellation-policy" className="text-teal-400 hover:text-teal-300">Refund &amp; Cancellation Policy</Link>.
          </p>
        ),
      },
    ],
  },
  {
    title: "Data, privacy & security",
    icon: Lock,
    items: [
      {
        q: "What data does Nano EASM collect?",
        a: (
          <p>
            Account info you provide (email, name, optional profile fields), the assets and
            scan configurations you create, scan results and findings we generate on your
            behalf, and operational logs (IP addresses, request data, audit events) for
            security and abuse prevention. Card data is collected by Stripe — we never see
            or store it. Full breakdown in our{" "}
            <Link href="/terms-and-policies/privacy-policy" className="text-teal-400 hover:text-teal-300">Privacy Policy</Link>.
          </p>
        ),
      },
      {
        q: "Where is my data stored?",
        a: (
          <p>
            On AWS in the United States (us-east-1 region). Although Nano EASM is based in
            Australia, we host in the US for sub-processor availability and global
            low-latency. International transfers are governed by the safeguards described in
            our Privacy Policy. If you have a data-residency requirement, contact us — we can
            discuss options under a custom contract.
          </p>
        ),
      },
      {
        q: "Do you train AI on my data?",
        a: (
          <p>
            <strong>No.</strong> We don&rsquo;t use customer data — assets, scan results,
            findings, configurations, or anything else — to train any AI or
            machine-learning model. Our finding explanations are written by security
            engineers up front, not generated from your data. This is a deliberate choice;
            many security tools quietly do the opposite.
          </p>
        ),
      },
      {
        q: "Can I delete my data?",
        a: (
          <p>
            Yes. As an organisation owner you can delete your entire workspace from{" "}
            <strong>Settings &rarr; Billing &rarr; Danger Zone</strong>, which cascades to
            all linked records (assets, scans, findings, members, audit logs for the org).
            Production deletion is immediate. Backups roll over within 30 days. Individual
            data-subject deletion requests under privacy law are honoured within 30 days —
            email <a href="mailto:contact@nanoasm.com" className="text-teal-400 hover:text-teal-300">contact@nanoasm.com</a>.
          </p>
        ),
      },
      {
        q: "Who can access my scan results?",
        a: (
          <p>
            Inside your organisation, role-based access control governs who sees what
            (Owner, Admin, Analyst, Viewer). Outside your organisation, only specific
            Nano EASM operations personnel with named production access can see your data,
            and only when needed for support, security, or legal compliance. Privileged
            actions like superadmin impersonation are audit-logged. We never share or sell
            scan data.
          </p>
        ),
      },
    ],
  },
  {
    title: "Teams, integrations & API",
    icon: Plug,
    items: [
      {
        q: "Can I invite teammates?",
        a: (
          <p>
            Yes. From <strong>Settings &rarr; Team</strong>, send an email invite to any
            teammate. They&rsquo;ll receive a link to set up their account, join your
            organisation, and inherit the role you assigned (Admin, Analyst, or Viewer).
            Owner is the seat that controls billing — there&rsquo;s only one owner per org,
            transferable on request.
          </p>
        ),
      },
      {
        q: "Do you have an API?",
        a: (
          <p>
            Yes. The full Nano EASM API lets you create assets, run scans, fetch findings,
            manage monitors, and pull report data programmatically. Authentication uses API
            keys you generate from <strong>Settings &rarr; API Keys</strong>. Use it to
            integrate with your SOAR, your ticketing system, or your own dashboards.
          </p>
        ),
      },
      {
        q: "Do you support webhooks?",
        a: (
          <p>
            Yes — on Professional plans and above. Configure webhooks to fire on events like
            <em> new finding</em>, <em>scan completed</em>, or <em>monitor alert raised</em>.
            Each webhook gets its own signing secret so you can verify the payload. Configure
            them from <strong>Settings &rarr; Integrations</strong>.
          </p>
        ),
      },
      {
        q: "Can I export findings or reports?",
        a: (
          <p>
            Yes. Findings can be exported to CSV at any time. Generated PDF and Excel reports
            are also available — go to <strong>Reports</strong>, choose what to include, and
            download. The data is yours.
          </p>
        ),
      },
      {
        q: "Is Nano EASM suitable for MSSPs?",
        a: (
          <p>
            Absolutely — MSSPs are one of our core audiences. You can manage multiple client
            organisations from one account, with separate workspaces, separate billing, and
            separate access controls per client. Reports can be exported and rebranded for
            client delivery. If you&rsquo;re an MSSP looking to onboard several clients,{" "}
            <Link href="/#contact" className="text-teal-400 hover:text-teal-300">contact us</Link>{" "}
            for partner pricing.
          </p>
        ),
      },
    ],
  },
];

/**
 * Recursively flatten a React node into searchable plain text.
 * Used so the search box can match against the rendered answer
 * content (which lives as JSX in the FAQS array, not strings).
 */
function nodeToText(node: ReactNode): string {
  if (node == null || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(nodeToText).join(" ");
  if (typeof node === "object" && "props" in (node as any)) {
    return nodeToText((node as any).props?.children);
  }
  return "";
}

function matchesQuery(item: FAQItem, query: string): boolean {
  if (!query) return true;
  const q = query.toLowerCase();
  return (
    item.q.toLowerCase().includes(q) ||
    nodeToText(item.a).toLowerCase().includes(q)
  );
}

function AccordionItem({ q, a, forceOpen }: FAQItem & { forceOpen: boolean }) {
  // When `forceOpen` is true we want the item rendered open, but we
  // also want to leave the user free to toggle it. Spreading the
  // `open` attribute conditionally means: while searching, every
  // matched item starts open; clear the search and items return to
  // normal click-to-toggle behaviour.
  const openProps = forceOpen ? { open: true } : {};
  return (
    <details
      {...openProps}
      className="group border-b border-white/[0.06] last:border-0 [&_summary::-webkit-details-marker]:hidden"
    >
      <summary className="cursor-pointer list-none flex items-center justify-between py-4 px-5 hover:bg-white/[0.02] transition-colors gap-4 select-none">
        <span className="text-sm font-medium text-white">{q}</span>
        <ChevronDown className="w-4 h-4 text-white/40 shrink-0 transition-transform duration-200 group-open:rotate-180" />
      </summary>
      <div className="px-5 pb-5 pt-1 text-sm text-white/60 leading-relaxed">
        {a}
      </div>
    </details>
  );
}

export default function FAQContent() {
  const [query, setQuery] = useState("");
  const trimmed = query.trim();
  const isSearching = trimmed.length > 0;

  const filtered = useMemo(() => {
    if (!isSearching) return FAQS;
    return FAQS
      .map((cat) => ({ ...cat, items: cat.items.filter((i) => matchesQuery(i, trimmed)) }))
      .filter((cat) => cat.items.length > 0);
  }, [trimmed, isSearching]);

  const totalAll = FAQS.reduce((sum, cat) => sum + cat.items.length, 0);
  const totalMatches = filtered.reduce((sum, cat) => sum + cat.items.length, 0);

  return (
    <div className="mt-10">
      {/* ── Search box ── */}
      <div className="relative">
        <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30 pointer-events-none" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search the FAQ — e.g. trial, API, refund, MSSP…"
          className="w-full pl-10 pr-10 py-3 rounded-xl bg-white/[0.03] border border-white/[0.08] text-white text-sm placeholder:text-white/30 focus:outline-none focus:border-teal-500/40 focus:bg-white/[0.05] transition-colors"
          aria-label="Search the FAQ"
        />
        {query && (
          <button
            type="button"
            onClick={() => setQuery("")}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 w-7 h-7 rounded-md flex items-center justify-center text-white/40 hover:text-white hover:bg-white/[0.06] transition-colors"
            aria-label="Clear search"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {isSearching && (
        <p className="mt-3 text-xs text-white/40">
          {totalMatches === 0
            ? "No questions match your search."
            : `${totalMatches} of ${totalAll} ${totalMatches === 1 ? "question matches" : "questions match"}.`}
        </p>
      )}

      {/* ── Results ── */}
      {totalMatches === 0 ? (
        <div className="mt-12 text-center py-12 rounded-xl border border-white/[0.06] bg-white/[0.02]">
          <p className="text-sm text-white/60">Nothing matches &ldquo;{trimmed}&rdquo;.</p>
          <p className="mt-2 text-sm text-white/40">
            Try a different keyword, or{" "}
            <Link href="/#contact" className="text-teal-400 hover:text-teal-300">ask us directly</Link>.
          </p>
        </div>
      ) : (
        <div className="mt-8 space-y-10">
          {filtered.map((category) => {
            const Icon = category.icon;
            return (
              <section key={category.title}>
                <h2 className="flex items-center gap-2.5 text-lg font-semibold text-white mb-3">
                  <span className="w-7 h-7 rounded-lg bg-teal-500/10 flex items-center justify-center">
                    <Icon className="w-3.5 h-3.5 text-teal-400" />
                  </span>
                  {category.title}
                </h2>
                <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
                  {category.items.map((item) => (
                    <AccordionItem key={item.q} {...item} forceOpen={isSearching} />
                  ))}
                </div>
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}
