// FILE: app/(unauthenticated)/faq/faq-data.tsx
//
// Single source of truth for FAQ items.
// Imported by:
//   - FAQContent.tsx — renders the visible accordion UI (client)
//   - page.tsx — emits FAQPage JSON-LD on the server
//
// Keeping data and rendering separate means the structured data and
// the visible UI can never drift, which is what Google's FAQPage
// rich-result policy requires.
//
// No "use client" directive on this module — it's pure data + a
// helper that both server and client components can import.

import type { ReactNode } from "react";
import Link from "next/link";
import { Rocket, ShieldAlert, CreditCard, Lock, Plug } from "lucide-react";

export type FAQItem = { q: string; a: ReactNode };
export type Category = { title: string; icon: typeof Rocket; items: FAQItem[] };

export const FAQS: Category[] = [
  {
    title: "Getting started",
    icon: Rocket,
    items: [
      {
        q: "What is Nano EASM?",
        a: (
          <p>
            Nano EASM is an{" "}
            <strong>External Attack Surface Management</strong> platform — a
            cybersecurity SaaS product that helps IT teams, security generalists, and
            MSSPs discover internet-facing assets, scan for risk, monitor exposure
            changes, and prioritise remediation.
          </p>
        ),
      },
      {
        q: "Is Nano EASM a CTEM platform?",
        a: (
          <p>
            Nano EASM focuses on the <strong>external attack surface</strong> layer of
            Continuous Threat Exposure Management. It helps teams discover
            internet-facing assets, monitor exposure changes, prioritise findings, and
            turn them into remediation actions. CTEM is broader than EASM and may
            include internal vulnerabilities, identity exposure, cloud posture, attack
            path validation, and control validation. Nano EASM is designed as a
            practical starting point for teams building toward a CTEM program — not a
            complete CTEM platform.
          </p>
        ),
      },
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
        q: "What does Nano EASM detect?",
        a: (
          <div className="space-y-3">
            <p>
              Every alert Nano EASM raises falls into one of five categories. The full
              catalogue is on the <Link href="/coverage" className="text-teal-400 hover:underline">Coverage page</Link> —
              short version:
            </p>
            <ul className="space-y-2 list-disc pl-5">
              <li>
                <strong className="text-white/80">Vulnerabilities</strong> — known
                CVEs and software flaws in services running on your assets.
              </li>
              <li>
                <strong className="text-white/80">Service Exposure</strong> — admin
                panels, dev tools, databases, and cloud assets reachable from the
                internet.
              </li>
              <li>
                <strong className="text-white/80">Data Leaks</strong> — secrets,
                credentials, configuration files, and source code exposed in public
                repos or directly on the asset.
              </li>
              <li>
                <strong className="text-white/80">Misconfigurations</strong> — CORS,
                open redirects, default credentials, and accessible admin endpoints.
              </li>
              <li>
                <strong className="text-white/80">Security Hygiene</strong> —
                expiring certificates, missing security headers, weak DMARC/SPF, and
                end-of-life software stacks.
              </li>
            </ul>
            <p>
              You can toggle each category on or off for your organisation, and
              override per asset group — e.g. a group of expected admin panels can
              have Service Exposure disabled while still receiving everything else.
            </p>
          </div>
        ),
      },
      {
        q: "Can I turn off categories of alerts?",
        a: (
          <p>
            Yes. Each of the{" "}
            <Link href="/coverage" className="text-teal-400 hover:underline">
              five detection categories
            </Link>{" "}
            can be enabled or disabled at the organisation level, and overridden
            per asset group. Findings are still recorded in the dashboard for
            auditing — you&rsquo;re only suppressing the alert/notification, not the
            data. For finer control, the platform also supports tuning rules that
            suppress findings matching a pattern (host, port, finding type).
          </p>
        ),
      },
      {
        q: "Can different asset groups have different alert rules?",
        a: (
          <p>
            Yes. An organisation has a default set of alert categories enabled, and
            any asset group can override those defaults. Common patterns we see:
            a group of internal-by-design admin tools with{" "}
            <em>Service Exposure</em> disabled (admin panels are expected); a
            dev/staging group with <em>Misconfigurations</em> and{" "}
            <em>Hygiene</em> turned down because configs are deliberately loose;
            a PCI-scope group with <em>everything</em> required at every severity.
            The group&rsquo;s rules apply only to its assets — the rest of the
            organisation continues with the org default.
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
            requested plan is enabled at no charge for a defined period. No payment method
            is needed. When the trial ends, your organisation reverts to Free unless you
            switch to another tier.
          </p>
        ),
      },
      {
        q: "What happens if I exceed my plan limits?",
        a: (
          <p>
            You&rsquo;ll see a clear message in the app explaining which limit you hit.
            Actions are blocked rather than billed — we don&rsquo;t do overages. Upgrading
            unlocks more scans, more monitored assets, and more team seats. Every paid tier
            is currently free to switch into.
          </p>
        ),
      },
      {
        q: "Can I upgrade or downgrade later?",
        a: (
          <p>
            Yes, anytime — open <strong>Settings &rarr; Plans</strong> and pick the tier you
            want. Every paid tier is free to upgrade into until further notice, and the
            change takes effect immediately. When billing returns later, downgrades will
            apply at the end of the billing period; there&rsquo;s no contract lock-in.
          </p>
        ),
      },
      {
        q: "How do refunds and cancellations work?",
        a: (
          <p>
            Plans are currently free to upgrade — there&rsquo;s nothing to refund or cancel.
            Closing your account anytime keeps your data accessible until you delete it
            manually. When billing returns, cancellations will take effect at the end of the
            billing period and refund exceptions follow our{" "}
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
            On AWS in the United States (us-east-1 region) — chosen for sub-processor
            availability and global low-latency. International transfers follow the
            safeguards described in our Privacy Policy. If you have a data-residency
            requirement, contact us — we can discuss options under a custom contract.
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
            email <a href="mailto:support@nanoeasm.com" className="text-teal-400 hover:text-teal-300">support@nanoeasm.com</a>.
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
 * Used for both the search box (in FAQContent) and FAQPage JSON-LD
 * extraction (in page.tsx). Strips JSX so what crawlers see in the
 * structured data substantively matches what users see rendered.
 */
export function nodeToText(node: ReactNode): string {
  if (node == null || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(nodeToText).join(" ");
  if (typeof node === "object" && "props" in (node as any)) {
    return nodeToText((node as any).props?.children);
  }
  return "";
}

/**
 * Convert the FAQS structure to a Schema.org FAQPage object suitable
 * for embedding via <script type="application/ld+json">. Includes
 * every visible question — Google requires the structured data to
 * mirror the visible content.
 */
export function faqsToJsonLd(): {
  "@context": "https://schema.org";
  "@type": "FAQPage";
  mainEntity: Array<{
    "@type": "Question";
    name: string;
    acceptedAnswer: { "@type": "Answer"; text: string };
  }>;
} {
  const allItems = FAQS.flatMap((category) => category.items);
  return {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: allItems.map((item) => ({
      "@type": "Question",
      name: item.q,
      acceptedAnswer: {
        "@type": "Answer",
        // Collapse internal whitespace so the rendered text reads as a
        // single paragraph; preserves the substance without leaking
        // JSX layout artefacts.
        text: nodeToText(item.a).replace(/\s+/g, " ").trim(),
      },
    })),
  };
}
