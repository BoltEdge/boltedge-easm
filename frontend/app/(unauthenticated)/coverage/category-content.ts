// FILE: app/(unauthenticated)/coverage/category-content.ts
//
// Per-category long-form content for the /coverage/{slug} sub-pages.
// Lives separate from the registry-derived coverage.json because:
//   - This is human-written marketing copy. Auto-generation would
//     produce thin/duplicate content and trip Google's helpful-
//     content rules.
//   - Each category needs ~400 words of unique value-prop framing
//     (what we detect, why it matters, common scenarios) — distinct
//     from the catalogue's per-template descriptions.
//   - Decoupling lets us update marketing tone without forcing a
//     backend regen.
//
// The slugs match the customer-facing category ids in templates.py
// (with underscores → hyphens for URL friendliness). When you add a
// 6th category to the registry, you must also add it here, otherwise
// the [slug] route won't generate a static page for it.

export type CategorySlug =
  | "vulnerabilities"
  | "service-exposure"
  | "data-leaks"
  | "misconfigurations"
  | "security-hygiene";

export type CategoryContent = {
  slug: CategorySlug;
  // Internal id from coverage.json (matches templates.py customer_category)
  registryId: string;
  // The visible label / breadcrumb
  label: string;
  // Tab-title and SEO h1
  pageTitle: string;
  // <meta description> — keep <160 chars
  metaDescription: string;
  // Short headline directly under the H1
  headline: string;
  // 1-2 sentence framing under the headline
  intro: string;
  // What customers see in the alert. Bullet list, plain text.
  whatWeDetect: string[];
  // Why a customer should care (the value-prop framing)
  whyItMatters: string;
  // How Nano EASM detects it (signal layers, scan engines)
  howItWorks: string;
  // 2-3 concrete customer scenarios where this matters
  scenarios: { title: string; body: string }[];
  // Keywords for the per-category JSON-LD
  keywords: string[];
};


export const CATEGORY_CONTENT: Record<CategorySlug, CategoryContent> = {
  "vulnerabilities": {
    slug: "vulnerabilities",
    registryId: "vulnerabilities",
    label: "Vulnerabilities",
    pageTitle: "Vulnerability Detection — Nano EASM",
    metaDescription:
      "External CVE scanning across discovered services. Nuclei-backed detection of known software flaws on every internet-facing asset Nano EASM finds.",
    headline: "Find known CVEs across every internet-facing service.",
    intro:
      "Vulnerabilities are the alerts most security teams reach for first — and they're the easiest to act on, because every CVE comes with a public advisory and a patch. Nano EASM identifies CVEs in services running on your discovered assets so you don't have to maintain a separate vulnerability scanner.",
    whatWeDetect: [
      "Critical and high-severity CVEs in web servers, application servers, message brokers, and databases.",
      "Marquee CVEs that come up in real-world breach reports — Log4Shell, Spring4Shell, ProxyShell, CitrixBleed, MOVEit, and equivalents going back several years.",
      "Software versions that have reached end-of-life and no longer receive security patches.",
      "CVE chains where multiple weaknesses combine into a higher-impact exploit.",
    ],
    whyItMatters:
      "External CVEs are the public attacker's favourite starting point because they're widely exploitable, well-documented, and almost always have a working exploit on the open internet within days of disclosure. The window between a CVE going public and exploitation in the wild is now measured in hours for high-impact issues. Catching them on the assets you control — including the ones IT didn't tell you about — closes that window.",
    howItWorks:
      "Asset discovery identifies internet-facing services on your domains and IPs. The HTTP, SSL, and Nmap engines fingerprint each service to capture vendor, product, and version. The Nuclei engine then runs template-based detection against those services, looking for the specific request/response signatures that indicate an exploitable CVE — not just version-string matching, which is noisy and unreliable. Findings come with a CVE ID, CVSS score, and an evidence snippet showing what was matched.",
    scenarios: [
      {
        title: "Forgotten staging server still running last year's stack",
        body: "A subdomain not in the IT inventory turns up during discovery. It's running an old version of an application server with a critical RCE. Nano EASM finds the asset, fingerprints the version, and matches it to the CVE in one cycle.",
      },
      {
        title: "Newly disclosed CVE drops at 2am",
        body: "Continuous monitoring re-scans your monitored assets on a configurable cadence. When a new template lands in the Nuclei catalogue and one of your services matches, the alert fires without you having to track the disclosure feed yourself.",
      },
      {
        title: "Audit needs evidence of CVE coverage",
        body: "The compliance report aggregates every CVE finding by severity, with timestamps and asset attribution. Export to PDF for the auditor — no separate scanner report to reconcile against your asset inventory.",
      },
    ],
    keywords: [
      "external CVE scanner",
      "vulnerability detection",
      "Nuclei CVE scanning",
      "Log4Shell detection",
      "EOL software detection",
      "external vulnerability management",
      "internet-facing vulnerability scanner",
    ],
  },

  "service-exposure": {
    slug: "service-exposure",
    registryId: "service_exposure",
    label: "Service Exposure",
    pageTitle: "Service Exposure Detection — Nano EASM",
    metaDescription:
      "Detect admin panels, dev tools, databases, and cloud assets that are reachable from the public internet but shouldn't be. The classic shadow-IT failure mode.",
    headline: "Find the admin tools, databases, and cloud buckets that aren't supposed to be on the internet.",
    intro:
      "Service exposure is the unsexy category that causes the most breaches. Someone stands up a dev environment, an admin panel, or a cloud storage bucket — and forgets to put auth in front of it, or misconfigures the firewall, or leaves a port open. Nano EASM catches those before an opportunistic attacker does.",
    whatWeDetect: [
      "Exposed admin panels — Jenkins, GitLab, Grafana, Kubernetes dashboard, Portainer, phpMyAdmin, dozens more.",
      "Database ports open to the internet — MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Memcached, plus their default-credential variants.",
      "Cloud storage buckets, container registries, and serverless endpoints accessible without authentication.",
      "Internal-facing dev/test endpoints (Webpack dev server, Storybook, Swagger UI, Spring Boot Actuator) on production hostnames.",
      "Shadow IT — services on subdomains the IT inventory doesn't know about.",
    ],
    whyItMatters:
      "Exposed services are unauthenticated entry points. They don't need a CVE to be a problem — exposure is the problem. Most ransomware groups, opportunistic scanners, and credential-stuffing botnets find their targets by scanning for these services first, then trying default creds or known weaknesses. The public-internet attack surface assumption is that anything reachable will be probed within minutes.",
    howItWorks:
      "Discovery enumerates subdomains, IPs, and CIDR ranges via certificate transparency logs, DNS, passive sources, and (for paid plans) Shodan. The Shodan engine surfaces every open port and service banner. The HTTP engine fingerprints exposed admin panels by their distinctive paths and response signatures. The cloud-asset engine probes cloud-bucket and registry candidates derived from your domain and brand. Every finding includes the asset, port, service, and a confidence indicator.",
    scenarios: [
      {
        title: "Forgotten Jenkins on a dev subdomain",
        body: "A dev set up Jenkins for a side project two years ago, behind no auth, on dev.acme.com:8080. Discovery finds the subdomain. The HTTP engine fingerprints the Jenkins login page. Alert in your Slack within the hour.",
      },
      {
        title: "S3 bucket spelled like the company name",
        body: "Cloud-asset enumeration generates likely bucket names from your domain (acme-prod, acme-backups, acme-uploads). The cloud-asset engine probes each for public list/read access. Findings include the URL and exact AWS bucket name.",
      },
      {
        title: "Mongo on an EC2 with the firewall off",
        body: "Discovery finds the EC2's elastic IP. Shodan reports port 27017 open with a Mongo banner. Nuclei confirms the database is reachable without auth. Three engines, one finding, one Slack message.",
      },
    ],
    keywords: [
      "service exposure detection",
      "exposed admin panel detection",
      "shadow IT discovery",
      "exposed database scanner",
      "Jenkins exposure scan",
      "S3 bucket exposure",
      "cloud bucket public access scanner",
      "exposed Kubernetes dashboard",
    ],
  },

  "data-leaks": {
    slug: "data-leaks",
    registryId: "data_leaks",
    label: "Data Leaks",
    pageTitle: "Data Leak Detection — Nano EASM",
    metaDescription:
      "Find leaked credentials, exposed source code, and sensitive files that reference your domain. Public GitHub and GitLab code search plus path-based probing.",
    headline: "Find your secrets before someone else does.",
    intro:
      "Credentials, API keys, and configuration files leak in three predictable places: a developer commits a .env file to a public repo; a misconfigured webserver exposes /.git/ or /backup.sql; or a third-party tool dumps your config somewhere indexable. Nano EASM checks all three.",
    whatWeDetect: [
      "Secrets in public code — API keys, tokens, and credentials matching 23 high-confidence patterns (AWS, GitHub PAT, Stripe, OpenAI, Anthropic, JWT, private keys, more).",
      "Exposed sensitive paths on your assets — /.git/, /.env, /backup.sql, /phpinfo.php, /admin/, .DS_Store directory listings, and ~30 more.",
      "Source-code references to your domain in public repositories on GitHub and GitLab, even when they don't contain secrets — useful for tracking shadow integrations.",
      "Configuration files exposed via misconfigured webservers — .htaccess, web.config, application.yml, etc.",
      "SSH keys, SSL private keys, and database dumps exposed at predictable URLs.",
    ],
    whyItMatters:
      "A leaked AWS key is a same-day incident. A leaked .env can include database creds, third-party API keys, mail credentials, and JWT signing secrets — every secret a developer was holding when the leak happened. Public repos are continuously scraped by automated tooling looking for exactly this. If the credential is valid for 30 minutes, that's enough time for an attacker to enumerate everything it can reach.",
    howItWorks:
      "Two parallel paths. First, the leak engine probes your discovered assets directly for ~30 sensitive paths (.git/, .env, backups, etc.) — fast, no third-party dependency. Second, when a paid plan is enabled, it queries public GitHub Code Search and GitLab blob search for code referencing your domain, then runs every matched snippet through a 23-pattern secret detector. Pattern matches are upgraded to high-confidence findings. The detector recognises real secret formats (AWS access key shape, GitHub PAT prefix, Stripe key format) — not just keyword matches.",
    scenarios: [
      {
        title: "Developer accidentally pushes .env to a public GitHub repo",
        body: "Their next commit removes it, but the file is now in the git history. Nano EASM's GitHub search finds the repo via the domain reference, the secret detector recognises the AWS key format, and the alert lands the same day with the full snippet, repo URL, and commit hash.",
      },
      {
        title: ".git folder accessible at production root",
        body: "A deployment didn't strip .git/ from the published artefact. The leak engine probes /.git/HEAD on every discovered subdomain. Finding includes the URL, the response evidence, and a remediation note about cloning the repo via git-dumper.",
      },
      {
        title: "Database backup at a guessable path",
        body: "Common backup paths (/backup.sql, /db_backup.zip, /dump.sql.gz) get probed against every discovered HTTP endpoint. Matches surface as critical findings with the file size and content-type from the response.",
      },
    ],
    keywords: [
      "data leak detection",
      "credential leak monitoring",
      "secret scanning",
      "github leak detection",
      "gitlab leak detection",
      "exposed .git folder scanner",
      "exposed .env detection",
      "AWS key leak detection",
      "API key leak monitoring",
    ],
  },

  "misconfigurations": {
    slug: "misconfigurations",
    registryId: "misconfigurations",
    label: "Misconfigurations",
    pageTitle: "Misconfiguration Detection — Nano EASM",
    metaDescription:
      "Detect CORS, open redirects, default credentials, accessible admin endpoints, and other configuration gaps that turn safe software into an attacker's foothold.",
    headline: "Configuration gaps that turn safe software into an attacker's foothold.",
    intro:
      "Software is rarely insecure on its own. It becomes insecure when it's configured wrong. Misconfigurations sit between vulnerabilities (a flaw in the code) and exposure (the wrong service on the internet) — fully patched, fully expected to be online, but configured in a way that grants more access than intended.",
    whatWeDetect: [
      "Permissive CORS — wildcard Access-Control-Allow-Origin combined with credentials, allowing any site to read authenticated responses.",
      "Open redirects — endpoints that send users wherever the URL parameter says, the foundation of many phishing kill chains.",
      "Default credentials — admin/admin still set on the dev tool you stood up six months ago.",
      "Accessible admin endpoints — /admin, /actuator/env, /server-status, /metrics, /debug — that should be on a private network or behind auth.",
      "Misconfigured DNS records — wildcard delegations, dangling CNAMEs pointing at unclaimed services (the takeover kill chain).",
      "Exposed environment introspection — /env, /heapdump, /threaddump, Spring Boot Actuator endpoints leaking environment variables.",
      "Verb tampering and authentication-bypass header tricks that some web frameworks honour by default.",
    ],
    whyItMatters:
      "Misconfigurations are how breaches actually happen. The Capital One breach was a misconfigured WAF combined with an SSRF. The Equifax breach was an unpatched server, sure — but also a misconfigured certificate-inspection appliance that hid the exfiltration. The Codecov supply-chain attack started with a leaked credential and a misconfigured uploader script. The pattern is consistent: the patch was applied, the service was supposed to be online, but the configuration left a path through.",
    howItWorks:
      "The HTTP engine examines response headers and behaviour for misconfigured CORS, weak Set-Cookie attributes, dangerous redirect handling, and HTTP-method anomalies. The DNS engine analyses zone records for dangling CNAMEs and wildcard mistakes. The Nuclei engine carries hundreds of configuration-specific templates — default-credential checks for popular admin panels, well-known framework actuator endpoints, common debug/info endpoints. The subdomain-takeover analyser cross-references CNAMEs against a list of services where unclaimed targets are takeover-vulnerable.",
    scenarios: [
      {
        title: "Spring Boot Actuator exposed in production",
        body: "/actuator/env on a microservice subdomain returns the environment, including database credentials in plaintext. Nuclei matches the actuator template; finding lands as critical with the JSON evidence excerpted.",
      },
      {
        title: "Dangling CNAME on a marketing subdomain",
        body: "marketing.acme.com points at an old Heroku app that's been deleted. Anyone can register the Heroku name and serve content from that hostname. The DNS engine notices the CNAME target is unclaimed; the takeover analyser confirms by attempting fingerprint resolution.",
      },
      {
        title: "CORS wildcard on the API",
        body: "api.acme.com sets Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. The header analyser reports it; finding includes the request/response pair and a remediation note about which combinations are actually safe.",
      },
    ],
    keywords: [
      "misconfiguration detection",
      "CORS misconfiguration scanner",
      "open redirect detection",
      "default credential scanner",
      "Spring Boot Actuator detection",
      "subdomain takeover detection",
      "dangling CNAME detection",
      "exposed admin endpoint detection",
    ],
  },

  "security-hygiene": {
    slug: "security-hygiene",
    registryId: "security_hygiene",
    label: "Security Hygiene",
    pageTitle: "Security Hygiene & DMARC/SPF/SSL Monitoring — Nano EASM",
    metaDescription:
      "Continuous monitoring for expiring certificates, missing security headers, weak DMARC/SPF/DKIM, and end-of-life software stacks. The compounding-interest of external security.",
    headline: "The compounding-interest of external security.",
    intro:
      "Hygiene checks rarely fire as one critical alert. They sit at low or medium severity. But across an attack surface they accumulate — each one shaving margin off the next time something goes wrong. Strong DMARC blocks spoofing; an HSTS header prevents downgrade; an unexpired certificate is one less chance for a man-in-the-middle. Hygiene is what your auditor actually checks.",
    whatWeDetect: [
      "Expiring or expired SSL/TLS certificates — every monitored asset, with configurable lead time alerts.",
      "Weak SSL/TLS configurations — TLS 1.0/1.1 still enabled, weak cipher suites, missing OCSP stapling, certificate-chain issues.",
      "Missing security headers — Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.",
      "Weak email authentication — missing or permissive SPF, weak DMARC policy (p=none in production), missing DKIM selectors.",
      "End-of-life software stacks — server, framework, language runtime, or library versions whose vendor no longer ships security patches.",
      "Outdated content management systems — WordPress, Drupal, Joomla versions running plugins/themes with known issues.",
      "Cookie security misconfigurations — missing Secure, HttpOnly, or SameSite attributes on session cookies.",
    ],
    whyItMatters:
      "An expired certificate is a 30-second incident that takes the whole service offline. A weak DMARC policy lets phishers send authoritative-looking email as your domain. Missing HSTS makes every public-WiFi user at every airport in the world vulnerable to session hijacking. End-of-life software is exploited the moment a CVE drops because there's no patch coming. None of these is a single-event disaster — but compound them across a year and they're the difference between an audit pass and a remediation project.",
    howItWorks:
      "The SSL engine connects to every TLS endpoint, captures the certificate chain, and analyses it for expiry, signature algorithm, key strength, protocol versions, and cipher suites. The DNS engine fetches and parses SPF/DKIM/DMARC records, flagging weak policies. The HTTP engine walks each asset's response headers and reports anything missing or misconfigured. The technology detector identifies CMS/framework/runtime versions and cross-references against an EOL database. Continuous monitoring re-runs all of this on the cadence you choose, so expiring certificates get caught with lead time.",
    scenarios: [
      {
        title: "Cert expires Saturday morning",
        body: "Continuous monitoring runs daily on the monitored assets. The SSL engine reports a 7-day expiry warning on Wednesday morning. Slack alert fires. You renew on Thursday. No outage on the weekend.",
      },
      {
        title: "DMARC at p=none for two years",
        body: "Marketing complains about phishers spoofing your domain to customers. The DNS engine reports your DMARC policy as p=none — meaning every phishing attempt is being delivered, just with a 'not aligned' note in your aggregate reports nobody reads. Finding includes a remediation walkthrough for the p=none → quarantine → reject ramp.",
      },
      {
        title: "Quarterly audit needs evidence of TLS posture",
        body: "Compliance report aggregates every SSL finding across every monitored asset, by severity. Export to PDF. Auditor's evidence requirement closed in 30 seconds.",
      },
    ],
    keywords: [
      "SSL certificate monitoring",
      "DMARC scanner",
      "SPF DKIM monitoring",
      "security headers scanner",
      "HSTS detection",
      "TLS 1.0 detection",
      "EOL software detection",
      "weak cipher detection",
      "expiring certificate alerts",
    ],
  },
};

export const ALL_SLUGS: CategorySlug[] = [
  "vulnerabilities",
  "service-exposure",
  "data-leaks",
  "misconfigurations",
  "security-hygiene",
];
