// FILE: app/(unauthenticated)/api-docs/page.tsx
// Public API reference for Nano EASM. Linked from sidebar (authenticated)
// and reachable directly at /api-docs.
import Link from "next/link";
import { Key, ArrowUpRight } from "lucide-react";
import LandingNav from "../LandingNav";
import { CodeBlock } from "./CodeBlock";

export const metadata = {
  title: "API Reference — Nano EASM",
  description:
    "REST API reference for Nano EASM. Authenticate with an API key and integrate assets, scans, findings, discovery, monitoring, and reports.",
};

// ────────────────────────────────────────────────────────────
// Section / endpoint registry — single source of truth
// ────────────────────────────────────────────────────────────

type Endpoint = {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  path: string;
  description: string;
  curl?: string;
  responseSnippet?: string;
};

type Section = {
  id: string;
  title: string;
  blurb: string;
  endpoints: Endpoint[];
};

// Production base URL shown in curl examples. Display-only — actual frontend
// requests use NEXT_PUBLIC_API_BASE_URL.
const BASE = "https://nanoasm.com/api";
const HDR = `-H "X-API-Key: ag_sk_..."`;

const SECTIONS: Section[] = [
  {
    id: "assets",
    title: "Assets",
    blurb:
      "Manage the domains, IPs, and cloud resources you monitor. Assets are scoped to your organization and grouped by AssetGroup.",
    endpoints: [
      {
        method: "GET",
        path: "/assets",
        description: "List all assets in your organization.",
        curl: `curl ${HDR} ${BASE}/assets`,
        responseSnippet: `[
  {
    "id": "42",
    "value": "example.com",
    "type": "domain",
    "groupId": "1",
    "createdAt": "2026-04-12T08:21:33"
  }
]`,
      },
      {
        method: "POST",
        path: "/groups/<group_id>/assets",
        description: "Add an asset to a group. Subject to plan asset limit.",
        curl: `curl -X POST ${HDR} -H "Content-Type: application/json" \\
  -d '{"value":"api.example.com","type":"domain"}' \\
  ${BASE}/groups/1/assets`,
      },
      {
        method: "POST",
        path: "/groups/<group_id>/assets/bulk",
        description: "Bulk-import assets to a group (CSV-style array payload).",
        curl: `curl -X POST ${HDR} -H "Content-Type: application/json" \\
  -d '{"assets":[{"value":"a.com","type":"domain"},{"value":"b.com","type":"domain"}]}' \\
  ${BASE}/groups/1/assets/bulk`,
      },
      {
        method: "GET",
        path: "/assets/<asset_id>",
        description: "Fetch a single asset by ID.",
        curl: `curl ${HDR} ${BASE}/assets/42`,
      },
      {
        method: "PATCH",
        path: "/assets/<asset_id>",
        description: "Update asset attributes (group, tags, criticality).",
      },
      {
        method: "DELETE",
        path: "/assets/<asset_id>",
        description: "Remove an asset. Findings tied to it are kept for history.",
      },
      {
        method: "GET",
        path: "/assets/<asset_id>/risk",
        description: "Composite risk score and severity breakdown for an asset.",
      },
      {
        method: "GET",
        path: "/assets/<asset_id>/coverage",
        description: "Which scan profiles have run against the asset and when.",
      },
      {
        method: "GET",
        path: "/assets/<asset_id>/health",
        description: "Reachability + service status snapshot.",
      },
      {
        method: "GET",
        path: "/assets/<asset_id>/timeline",
        description: "Event timeline (scans, findings, status changes).",
      },
      {
        method: "GET",
        path: "/groups/<group_id>/assets",
        description: "List assets within a specific group.",
      },
    ],
  },
  {
    id: "scans",
    title: "Scans",
    blurb:
      "Trigger and inspect vulnerability scans. Scans run asynchronously — POST returns immediately with a job ID you can poll.",
    endpoints: [
      {
        method: "POST",
        path: "/scan-jobs",
        description: "Start a scan job for an asset. Profile: quick | standard | deep.",
        curl: `curl -X POST ${HDR} -H "Content-Type: application/json" \\
  -d '{"asset_id":42,"profile":"standard"}' \\
  ${BASE}/scan-jobs`,
        responseSnippet: `{
  "id": "917",
  "status": "queued",
  "asset_id": "42",
  "profile": "standard",
  "createdAt": "2026-04-30T11:02:14"
}`,
      },
      {
        method: "GET",
        path: "/scan-jobs",
        description: "List recent scan jobs (paginated).",
        curl: `curl ${HDR} "${BASE}/scan-jobs?status=running&limit=20"`,
      },
      {
        method: "POST",
        path: "/scan-jobs/<job_id>/run",
        description: "Re-run a finished scan job (creates a new job, same config).",
      },
      {
        method: "DELETE",
        path: "/scan-jobs/<job_id>",
        description: "Delete a scan job and its findings (irreversible).",
      },
      {
        method: "GET",
        path: "/scan-jobs/<job_id>/findings",
        description: "Findings produced by a specific scan job.",
        curl: `curl ${HDR} ${BASE}/scan-jobs/917/findings`,
      },
    ],
  },
  {
    id: "findings",
    title: "Findings",
    blurb:
      "Read and triage vulnerability findings. Each finding has a status (open, acknowledged, resolved, ignored) and a severity (info, low, medium, high, critical).",
    endpoints: [
      {
        method: "GET",
        path: "/findings",
        description:
          "List findings. Filter with severity, status, asset_id, since, q.",
        curl: `curl ${HDR} "${BASE}/findings?severity=critical&status=open&since=2026-04-01"`,
        responseSnippet: `{
  "items": [
    {
      "id": "5510",
      "templateId": "tls.expired-cert",
      "severity": "high",
      "status": "open",
      "assetId": "42",
      "createdAt": "2026-04-29T17:08:21"
    }
  ],
  "total": 47,
  "page": 1,
  "perPage": 50
}`,
      },
      {
        method: "GET",
        path: "/findings/<finding_id>",
        description: "Full detail for a single finding incl. evidence + remediation.",
      },
      {
        method: "PATCH",
        path: "/findings/<finding_id>",
        description: "Update a finding's status, notes, or assignee.",
        curl: `curl -X PATCH ${HDR} -H "Content-Type: application/json" \\
  -d '{"status":"resolved","notes":"Patched in PR #1234"}' \\
  ${BASE}/findings/5510`,
      },
      {
        method: "POST",
        path: "/findings/bulk-status",
        description: "Set status on multiple findings in one request.",
        curl: `curl -X POST ${HDR} -H "Content-Type: application/json" \\
  -d '{"ids":[5510,5511,5512],"status":"acknowledged"}' \\
  ${BASE}/findings/bulk-status`,
      },
      {
        method: "GET",
        path: "/findings/export",
        description: "CSV export of findings matching the filter query.",
        curl: `curl ${HDR} "${BASE}/findings/export?severity=high" -o findings.csv`,
      },
    ],
  },
  {
    id: "discovery",
    title: "Discovery",
    blurb:
      "Run subdomain and asset discovery against root domains. Discovery jobs surface unknown subdomains, IPs, and services that you can promote into your asset inventory.",
    endpoints: [
      {
        method: "POST",
        path: "/discovery/run",
        description: "Launch a discovery job against one or more domains.",
        curl: `curl -X POST ${HDR} -H "Content-Type: application/json" \\
  -d '{"domains":["example.com"],"deep":false}' \\
  ${BASE}/discovery/run`,
      },
      {
        method: "GET",
        path: "/discovery/jobs",
        description: "List discovery jobs (paginated).",
      },
      {
        method: "GET",
        path: "/discovery/jobs/<job_id>",
        description: "Job detail incl. discovered subdomains, IPs, and modules used.",
      },
      {
        method: "POST",
        path: "/discovery/jobs/<job_id>/cancel",
        description: "Cancel a running discovery job.",
      },
      {
        method: "POST",
        path: "/discovery/jobs/<job_id>/add-assets",
        description:
          "Promote discovered items into your asset inventory (subject to asset limit).",
        curl: `curl -X POST ${HDR} -H "Content-Type: application/json" \\
  -d '{"values":["api.example.com","www.example.com"]}' \\
  ${BASE}/discovery/jobs/123/add-assets`,
      },
    ],
  },
  {
    id: "monitoring",
    title: "Monitoring",
    blurb:
      "Continuous monitors watch assets for change events (new ports, cert changes, DNS drift) and emit alerts. Use the alerts endpoints to ack/resolve from your SIEM or SOAR.",
    endpoints: [
      {
        method: "GET",
        path: "/monitors",
        description: "List monitors configured for your organization.",
        curl: `curl ${HDR} ${BASE}/monitors`,
      },
      {
        method: "POST",
        path: "/monitors",
        description: "Create a monitor for an asset or asset group.",
      },
      {
        method: "PATCH",
        path: "/monitors/<monitor_id>",
        description: "Update monitor frequency, scope, or enabled state.",
      },
      {
        method: "DELETE",
        path: "/monitors/<monitor_id>",
        description: "Remove a monitor.",
      },
      {
        method: "GET",
        path: "/monitors/alerts",
        description: "List alerts. Filter by status, severity, monitor_id.",
        curl: `curl ${HDR} "${BASE}/monitors/alerts?status=open"`,
      },
      {
        method: "POST",
        path: "/monitors/alerts/<alert_id>/acknowledge",
        description: "Acknowledge an alert (tracks who/when).",
      },
      {
        method: "POST",
        path: "/monitors/alerts/<alert_id>/resolve",
        description: "Mark an alert as resolved.",
      },
    ],
  },
  {
    id: "reports",
    title: "Reports",
    blurb:
      "Generate and download PDF/Excel reports. Generation is async — the response returns a report ID you can poll until status='ready', then download.",
    endpoints: [
      {
        method: "POST",
        path: "/reports/generate",
        description: "Start report generation. Type: executive | technical.",
        curl: `curl -X POST ${HDR} -H "Content-Type: application/json" \\
  -d '{"type":"executive","scope":"org"}' \\
  ${BASE}/reports/generate`,
        responseSnippet: `{
  "id": "204",
  "status": "queued",
  "type": "executive",
  "createdAt": "2026-04-30T12:11:01"
}`,
      },
      {
        method: "GET",
        path: "/reports",
        description: "List reports (paginated).",
      },
      {
        method: "GET",
        path: "/reports/<report_id>",
        description: "Report metadata (status, type, scope).",
      },
      {
        method: "GET",
        path: "/reports/<report_id>/download",
        description: "Download the rendered report (PDF or Excel binary).",
        curl: `curl ${HDR} ${BASE}/reports/204/download -o report.pdf`,
      },
    ],
  },
];

// ────────────────────────────────────────────────────────────
// Reusable bits
// ────────────────────────────────────────────────────────────

const METHOD_COLOR: Record<string, string> = {
  GET: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  POST: "bg-blue-500/15 text-blue-300 border-blue-500/30",
  PATCH: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  DELETE: "bg-red-500/15 text-red-300 border-red-500/30",
};

function MethodPill({ method }: { method: string }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-md border text-[10px] font-bold tracking-wide ${METHOD_COLOR[method]}`}
    >
      {method}
    </span>
  );
}

function EndpointCard({ ep }: { ep: Endpoint }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5 space-y-3">
      <div className="flex items-baseline gap-3 flex-wrap">
        <MethodPill method={ep.method} />
        <code className="font-mono text-sm text-white">{ep.path}</code>
      </div>
      <p className="text-sm text-white/60">{ep.description}</p>
      {ep.curl && <CodeBlock>{ep.curl}</CodeBlock>}
      {ep.responseSnippet && (
        <details className="group">
          <summary className="cursor-pointer text-xs text-white/40 hover:text-white/70 transition-colors">
            Sample response →
          </summary>
          <div className="mt-2">
            <CodeBlock>{ep.responseSnippet}</CodeBlock>
          </div>
        </details>
      )}
    </div>
  );
}

// ────────────────────────────────────────────────────────────
// Page
// ────────────────────────────────────────────────────────────

export default function ApiDocsPage() {
  return (
    <div className="min-h-screen bg-[#060b18] text-white">
      <LandingNav />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 pt-24 pb-16">
        <div className="grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-10">
          {/* ── Sticky TOC ── */}
          <aside className="hidden lg:block">
            <nav className="sticky top-24 space-y-1 text-sm">
              <div className="text-[11px] uppercase tracking-wider text-white/30 font-semibold mb-2">
                Reference
              </div>
              {[
                { id: "intro", label: "Introduction" },
                { id: "auth", label: "Authentication" },
                { id: "errors", label: "Errors" },
                { id: "pagination", label: "Pagination" },
              ].map((s) => (
                <a
                  key={s.id}
                  href={`#${s.id}`}
                  className="block py-1.5 px-2 rounded text-white/55 hover:text-white hover:bg-white/[0.04] transition-colors"
                >
                  {s.label}
                </a>
              ))}
              <div className="text-[11px] uppercase tracking-wider text-white/30 font-semibold mt-5 mb-2">
                Endpoints
              </div>
              {SECTIONS.map((s) => (
                <a
                  key={s.id}
                  href={`#${s.id}`}
                  className="block py-1.5 px-2 rounded text-white/55 hover:text-white hover:bg-white/[0.04] transition-colors"
                >
                  {s.title}
                </a>
              ))}
            </nav>
          </aside>

          {/* ── Content ── */}
          <main className="min-w-0 space-y-12">
            {/* Header */}
            <section id="intro" className="space-y-4 scroll-mt-24">
              <h1 className="text-3xl sm:text-4xl font-semibold tracking-tight">
                API Reference
              </h1>
              <p className="text-white/60 max-w-2xl">
                The Nano EASM REST API lets you manage assets, trigger scans, pull
                findings, run discovery, manage monitoring alerts, and generate
                reports — all the things you&apos;d wire into CI/CD, a SOAR, or a SIEM.
              </p>
              <div className="flex items-center gap-3 pt-2">
                <Link
                  href="/settings/api-keys"
                  className="inline-flex items-center gap-2 rounded-lg bg-teal-600 hover:bg-teal-500 px-4 py-2 text-sm font-medium text-white transition-all"
                >
                  <Key className="w-4 h-4" />
                  Generate an API key
                  <ArrowUpRight className="w-4 h-4" />
                </Link>
                <Link
                  href="/login"
                  className="text-sm text-white/50 hover:text-white transition-colors"
                >
                  or sign in →
                </Link>
              </div>
            </section>

            {/* Auth */}
            <section id="auth" className="space-y-4 scroll-mt-24">
              <h2 className="text-2xl font-semibold tracking-tight">Authentication</h2>
              <p className="text-white/60">
                All API endpoints require an API key. Send it on every request as
                the <code className="text-teal-300">X-API-Key</code> header.
              </p>
              <CodeBlock>{`curl -H "X-API-Key: ag_sk_..." ${BASE}/findings`}</CodeBlock>
              <p className="text-white/60 text-sm">
                You can also pass the key as a Bearer token if you prefer:
              </p>
              <CodeBlock>{`curl -H "Authorization: Bearer ag_sk_..." ${BASE}/findings`}</CodeBlock>
              <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-sm">
                <p className="font-semibold text-amber-200 mb-1">Permissions</p>
                <p className="text-white/65">
                  An API key inherits the role of the user who created it. A viewer&apos;s
                  key is read-only; an analyst&apos;s key can create assets and trigger
                  scans. Plan limits (asset count, scans per month, etc.) apply
                  exactly as they do in the UI.
                </p>
              </div>
              <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 text-sm">
                <p className="font-semibold text-white mb-1">What API keys can&apos;t do</p>
                <p className="text-white/55">
                  For safety, account-credential and billing-state actions are not
                  callable with API keys: changing your password, inviting members,
                  changing roles, switching plans, or deleting your organization.
                  These return <code className="text-rose-300">403 API_KEY_NOT_ALLOWED</code>.
                </p>
              </div>
            </section>

            {/* Errors */}
            <section id="errors" className="space-y-4 scroll-mt-24">
              <h2 className="text-2xl font-semibold tracking-tight">Errors</h2>
              <p className="text-white/60">
                Errors are returned as JSON with an <code className="text-teal-300">error</code>{" "}
                field and the appropriate HTTP status code.
              </p>
              <CodeBlock>{`{
  "error": "invalid or expired API key"
}`}</CodeBlock>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                {[
                  ["400", "Bad request — missing or invalid fields"],
                  ["401", "Missing or invalid API key"],
                  ["403", "Permission denied (role or API_KEY_NOT_ALLOWED)"],
                  ["402", "Plan limit reached"],
                  ["404", "Resource not found"],
                  ["429", "Rate-limited"],
                  ["500", "Internal server error"],
                ].map(([code, msg]) => (
                  <div
                    key={code}
                    className="flex items-start gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2"
                  >
                    <code className="text-teal-300 font-mono text-xs shrink-0">{code}</code>
                    <span className="text-white/60 text-sm">{msg}</span>
                  </div>
                ))}
              </div>
            </section>

            {/* Pagination */}
            <section id="pagination" className="space-y-4 scroll-mt-24">
              <h2 className="text-2xl font-semibold tracking-tight">Pagination</h2>
              <p className="text-white/60">
                List endpoints accept <code className="text-teal-300">page</code>{" "}
                (1-indexed) and <code className="text-teal-300">perPage</code>{" "}
                (max 100). Responses include the total count.
              </p>
              <CodeBlock>{`curl ${HDR} "${BASE}/findings?page=2&perPage=50"`}</CodeBlock>
              <CodeBlock>{`{
  "items": [ ... ],
  "total": 247,
  "page": 2,
  "perPage": 50
}`}</CodeBlock>
            </section>

            {/* Per-domain sections */}
            {SECTIONS.map((section) => (
              <section
                key={section.id}
                id={section.id}
                className="space-y-5 scroll-mt-24"
              >
                <div>
                  <h2 className="text-2xl font-semibold tracking-tight">
                    {section.title}
                  </h2>
                  <p className="text-white/60 mt-2 max-w-3xl">{section.blurb}</p>
                </div>
                <div className="space-y-4">
                  {section.endpoints.map((ep, idx) => (
                    <EndpointCard key={`${ep.method}-${ep.path}-${idx}`} ep={ep} />
                  ))}
                </div>
              </section>
            ))}

            {/* Footer */}
            <section className="pt-8 border-t border-white/[0.06] text-sm text-white/40">
              Need something not in this list? The full UI runs on a JWT-only API
              that mirrors most of the surface — get in touch at{" "}
              <a
                href="mailto:contact@nanoasm.com"
                className="text-teal-300 hover:text-teal-200"
              >
                contact@nanoasm.com
              </a>
              .
            </section>
          </main>
        </div>
      </div>
    </div>
  );
}
