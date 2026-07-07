import type { Pattern } from "./types";

// Cross-platform patterns that show up regardless of which AI builder produced the app,
// because the scaffolded deploy config rarely strips them. All are cheap single-request.
export const genericPatterns: Pattern[] = [
  {
    slug: "exposed-env-file",
    platform: "generic",
    category: "Exposed secret",
    severityDefault: "critical",
    title: "Environment file reachable over HTTP",
    description:
      "A .env file is served by the production deploy. These files hold database URLs, API keys and signing secrets. AI scaffolds frequently leave them inside the deployed web root.",
    impactOneline: "Your .env file (all your secret keys) is downloadable by anyone.",
    detectorKind: "http_probe",
    detectorConfig: {
      paths: ["/.env", "/.env.local", "/.env.production", "/api/.env"],
      expect: { kind: "body_regex", regex: "[A-Z0-9_]+=" },
      maxBytes: 4096
    },
    tierRequired: "free",
    remediation: {
      summary: "Stop serving .env and rotate every secret it contained.",
      steps: [
        "Move .env outside the deployed web root and add it to your ignore/deny rules.",
        "Rotate every credential the file contained.",
        "Add a deny rule for dotfiles in your host config."
      ]
    },
    fixPrompt:
      "My deployed site serves my .env file over HTTP. Stop it from being publicly served, ensure .env is excluded from the deploy/web root, and list every secret it contained so I can rotate them.",
    version: 1,
    enabled: true
  },
  {
    slug: "exposed-config-backup",
    platform: "generic",
    category: "Exposed secret",
    severityDefault: "critical",
    title: "Config or backup file reachable over HTTP",
    description:
      "A configuration, credential, or database-backup file is served directly from the web root. AI deploy scaffolds routinely leave these in the published artifact, exposing connection strings, API keys, and full data dumps.",
    impactOneline: "A config/backup file with secrets or data is downloadable by anyone.",
    detectorKind: "http_probe",
    detectorConfig: {
      paths: [
        "/.env.development",
        "/.env.backup",
        "/config.json",
        "/appsettings.json",
        "/credentials.json",
        "/.npmrc",
        "/docker-compose.yml",
        "/database.sql",
        "/dump.sql",
        "/backup.sql",
        "/db.sqlite",
        "/.DS_Store"
      ],
      expect: { kind: "body_regex", regex: "(=|:|\\bBEGIN\\b|INSERT INTO|CREATE TABLE|\"[a-z_]+\"\\s*:)" },
      maxBytes: 4096
    },
    tierRequired: "free",
    remediation: {
      summary: "Stop serving config/backup files from the web root and rotate anything they exposed.",
      steps: [
        "Remove config, credential, and *.sql/backup files from the deployed artifact and web root.",
        "Add host deny rules for dotfiles and *.sql / *.sqlite / *.json config paths.",
        "Rotate every credential any exposed file contained."
      ]
    },
    fixPrompt:
      "My deployed site serves config/backup files (e.g. config.json, dump.sql, .env.*) over HTTP. Ensure these are never included in the deployed web root, add deny rules for them, and list which secrets I must rotate.",
    version: 1,
    enabled: true
  },
  {
    slug: "exposed-git-dir",
    platform: "generic",
    category: "Source exposure",
    severityDefault: "high",
    title: "Exposed .git directory",
    description:
      "The .git directory is reachable, which lets anyone reconstruct your full source history including any secrets committed along the way.",
    impactOneline: "Your full source code and its history can be downloaded.",
    detectorKind: "http_probe",
    detectorConfig: {
      paths: ["/.git/HEAD", "/.git/config"],
      expect: { kind: "body_regex", regex: "ref:|\\[core\\]" },
      maxBytes: 2048
    },
    tierRequired: "free",
    remediation: {
      summary: "Stop serving the .git directory from your production host.",
      steps: [
        "Exclude .git from the deployed artifact / web root.",
        "Add a host rule denying access to /.git.",
        "Audit history for any committed secrets and rotate them."
      ]
    },
    fixPrompt:
      "My production deploy exposes the /.git directory. Make sure .git is never deployed or served, add a deny rule for it, and check whether any secrets were committed to history.",
    version: 1,
    enabled: true
  },
  {
    slug: "exposed-source-maps",
    platform: "generic",
    category: "Source exposure",
    severityDefault: "medium",
    title: "Source maps published to production",
    description:
      "JavaScript source maps are served in production, exposing your original (pre-minified) source. The default AI builder template often does not strip them.",
    impactOneline: "Your original source code is readable in the browser.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "sourceMaps" },
    tierRequired: "free",
    remediation: {
      summary: "Disable source map emission for production builds.",
      steps: [
        "Turn off productionBrowserSourceMaps / build.sourcemap in your config.",
        "Re-deploy and confirm .map files 404."
      ]
    },
    fixPrompt:
      "My production build publishes JavaScript source maps. Disable production source maps in the build config and confirm the .map files are no longer served.",
    version: 1,
    enabled: true
  },
  {
    slug: "missing-security-headers",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "Critical security headers missing",
    description:
      "Core security headers (Content-Security-Policy, X-Frame-Options, Strict-Transport-Security) are absent. Default Vite/Next templates produced by AI builders rarely set them.",
    impactOneline:
      "Missing headers leave you open to clickjacking and protocol-downgrade attacks.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "securityHeaders" },
    tierRequired: "free",
    remediation: {
      summary: "Add CSP, X-Frame-Options and HSTS to your responses.",
      steps: [
        "Set Strict-Transport-Security with a long max-age.",
        "Set X-Frame-Options: DENY (or frame-ancestors in CSP).",
        "Add a Content-Security-Policy starting from a restrictive baseline."
      ]
    },
    fixPrompt:
      "My site is missing Content-Security-Policy, X-Frame-Options and Strict-Transport-Security headers. Add them in my framework config with sensible secure defaults and show me the config.",
    version: 1,
    enabled: true
  },
  {
    slug: "insecure-cookies",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "Cookies set without the Secure flag",
    description:
      "One or more cookies are set over HTTPS without the Secure attribute, so the browser will also send them over plain HTTP where they can be intercepted. Session cookies additionally missing HttpOnly are readable by injected JavaScript.",
    impactOneline: "Session/auth cookies can leak over HTTP or be stolen via XSS.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "insecureCookies" },
    tierRequired: "free",
    remediation: {
      summary: "Set Secure, HttpOnly and SameSite on session/auth cookies.",
      steps: [
        "Add the Secure attribute to every cookie so it is only sent over HTTPS.",
        "Add HttpOnly to session/auth cookies so JavaScript cannot read them.",
        "Set SameSite=Lax (or Strict) to reduce CSRF exposure."
      ]
    },
    fixPrompt:
      "My site sets cookies without the Secure flag (and some without HttpOnly/SameSite). Update my cookie configuration so session/auth cookies are Secure, HttpOnly and SameSite=Lax, and show me the config.",
    version: 1,
    enabled: true
  },
  {
    slug: "permissive-cors",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "CORS allows any origin",
    description:
      "The response sets Access-Control-Allow-Origin: *, letting any website read cross-origin responses. Combined with Allow-Credentials this exposes authenticated data to any site.",
    impactOneline: "Any website can read cross-origin responses from this endpoint.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "permissiveCors" },
    tierRequired: "free",
    remediation: {
      summary: "Replace the wildcard with an explicit allow-list of trusted origins.",
      steps: [
        "Set Access-Control-Allow-Origin to specific trusted origins, not '*'.",
        "Never combine a wildcard origin with Allow-Credentials: true.",
        "Reflect only origins from an allow-list you control."
      ]
    },
    fixPrompt:
      "My API returns Access-Control-Allow-Origin: *. Replace the wildcard CORS policy with an explicit allow-list of trusted origins and make sure credentials are never allowed with a wildcard. Show me the config.",
    version: 1,
    enabled: true
  },
  {
    slug: "cors-reflect-origin",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "CORS reflects arbitrary Origin",
    description:
      "The server echoes whatever Origin header the browser sends in Access-Control-Allow-Origin. Any malicious site can therefore read credentialed API responses from a victim's browser session.",
    impactOneline: "Any website can read authenticated cross-origin API responses.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "corsReflectOrigin" },
    tierRequired: "free",
    remediation: {
      summary: "Stop reflecting Origin; use an explicit allow-list.",
      steps: [
        "Replace dynamic Origin reflection with a fixed allow-list of trusted domains.",
        "Never combine reflected origins with Access-Control-Allow-Credentials: true unless the allow-list is strict.",
        "Return no CORS headers for unknown origins."
      ]
    },
    fixPrompt:
      "My API reflects the request Origin header in Access-Control-Allow-Origin. Replace this with an explicit allow-list of trusted origins and show me the middleware/config change.",
    version: 1,
    enabled: true
  },
  {
    slug: "robots-sensitive-paths",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "robots.txt discloses sensitive paths",
    description:
      "The published robots.txt file lists Disallow paths that reveal admin panels, backups, or internal routes — a free map for attackers.",
    impactOneline: "robots.txt advertises admin/backup paths attackers can probe.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "robotsSensitivePaths" },
    tierRequired: "free",
    remediation: {
      summary: "Remove sensitive paths from robots.txt or block them at the edge.",
      steps: [
        "Delete Disallow entries that name admin, backup, or config paths.",
        "Protect sensitive routes with auth regardless of robots.txt.",
        "Use noindex meta tags for pages you don't want indexed instead of advertising paths."
      ]
    },
    fixPrompt:
      "My robots.txt lists sensitive paths like /admin or /backup. Rewrite it to avoid disclosing internal routes, and show me how to protect those paths with auth instead.",
    version: 1,
    enabled: true
  },
  {
    slug: "tech-stack-disclosure",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "low",
    title: "Server/framework version disclosed in headers",
    description:
      "Response headers (Server, X-Powered-By, X-AspNet-Version) reveal the exact software and version running, which lets an attacker look up known CVEs for that version directly.",
    impactOneline: "Headers reveal your exact stack/version, guiding targeted exploits.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "techDisclosure" },
    tierRequired: "free",
    remediation: {
      summary: "Suppress version-revealing response headers.",
      steps: [
        "Remove or blank the X-Powered-By header (e.g. app.disable('x-powered-by')).",
        "Strip version numbers from the Server header at your proxy/CDN.",
        "Remove X-AspNet-Version / framework version headers."
      ]
    },
    fixPrompt:
      "My site leaks its stack via Server / X-Powered-By / X-AspNet-Version headers. Remove or anonymise these version-disclosing response headers in my framework and proxy config, and show me how.",
    version: 1,
    enabled: true
  },
  {
    slug: "unprotected-webhook-endpoint",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "high",
    title: "Payment webhook endpoint without signature verification",
    description:
      "A Stripe/Razorpay-style webhook path is reachable and appears to accept requests without verifying the provider signature. AI scaffolding very commonly omits signature verification, letting an attacker forge 'payment succeeded' events.",
    impactOneline:
      "Attackers may forge payment events (e.g. fake 'paid') if your webhook is unverified.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "webhookSignature" },
    // Deep tier: confirming this needs a forged test event against an authorized target,
    // which the worker does. On a free scan it would be a guess, so it surfaces as a sealed
    // (locked) exhibit instead of a confirmed finding.
    tierRequired: "deep",
    remediation: {
      summary: "Verify the provider signature on every webhook before trusting it.",
      steps: [
        "Read the raw request body and verify the provider signature header.",
        "Reject any request whose signature does not validate.",
        "Never grant entitlements before signature verification passes."
      ]
    },
    fixPrompt:
      "My payment webhook endpoint may not verify the provider signature. Add strict signature verification (Stripe/Razorpay) using the raw request body before any business logic runs, and reject invalid signatures. Show me the handler.",
    version: 1,
    enabled: true
  },
  {
    slug: "inline-state-secrets",
    platform: "generic",
    category: "Exposed secret",
    severityDefault: "critical",
    title: "Server secrets embedded in the page's inline app state",
    description:
      "Live server credentials are shipped inside the page's inline JSON state (Next.js __NEXT_DATA__, or a window.__ENV__/__CONFIG__ bootstrap object). AI builders commonly pass server config straight into page props, so the secret is readable in View Source.",
    impactOneline: "A server key is sitting in your page's HTML — visible in View Source.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "inlineStateSecrets" },
    tierRequired: "free",
    remediation: {
      summary: "Keep server secrets server-side; never pass them into client props or global state.",
      steps: [
        "Remove secret values from getServerSideProps/getStaticProps output and any window.__ENV__ object.",
        "Access server secrets only in server code (route handlers, server actions), never in props.",
        "Rotate every credential that appeared in the page state."
      ]
    },
    fixPrompt:
      "My page ships server secrets inside its inline app state (__NEXT_DATA__ / window.__ENV__). Move those values to server-only code so they never reach the client, and list the secrets I need to rotate.",
    version: 1,
    enabled: true
  },
  {
    slug: "graphql-introspection-enabled",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "GraphQL introspection is enabled in production",
    description:
      "A public GraphQL endpoint answers introspection queries, handing attackers a complete map of your schema — every type, query, and mutation, including internal ones. Auto-generated GraphQL layers (Hasura, Apollo, Postgraphile) ship with it on by default.",
    impactOneline: "Your full GraphQL schema (incl. internal mutations) is readable by anyone.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "graphqlIntrospection" },
    tierRequired: "free",
    remediation: {
      summary: "Disable introspection in production and lock down the GraphQL endpoint.",
      steps: [
        "Turn off introspection in your GraphQL server's production config.",
        "Require authentication/authorization on the GraphQL endpoint.",
        "Disable any built-in GraphQL playground/IDE in production."
      ]
    },
    fixPrompt:
      "My production GraphQL endpoint allows introspection. Disable introspection and any GraphQL playground in production, and require auth on the endpoint. Show me the config for my server.",
    version: 1,
    enabled: true
  },
  {
    slug: "directory-listing-enabled",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "Directory listing (autoindex) is enabled",
    description:
      "A directory returns an auto-generated file index instead of a page, letting anyone browse and download every file it contains — often uploads, backups, or build artifacts.",
    impactOneline: "Anyone can browse and download the files in an exposed directory.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "directoryListing" },
    tierRequired: "free",
    remediation: {
      summary: "Disable directory autoindex on your web server / host.",
      steps: [
        "Turn off autoindex/directory listing at the server or CDN level.",
        "Serve an index file or return 403/404 for directory paths.",
        "Move private files (uploads, backups) out of the public web root."
      ]
    },
    fixPrompt:
      "My site has directory listing enabled on one or more folders. Disable autoindex so directories don't list their contents, and move any private files out of the public web root. Show me the config.",
    version: 1,
    enabled: true
  },
  {
    slug: "verbose-error-disclosure",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "Verbose error / stack trace exposed in production",
    description:
      "A malformed request triggers a full framework stack trace or debug error page in production, leaking file paths, dependency versions, and sometimes secrets. Debug mode is frequently left on in AI-scaffolded deploys.",
    impactOneline: "Error pages leak your file paths, stack, and versions to attackers.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "errorDisclosure" },
    tierRequired: "deep",
    remediation: {
      summary: "Disable debug mode in production and return generic error pages.",
      steps: [
        "Set the framework to production mode (debug off) so stack traces aren't rendered.",
        "Return generic 4xx/5xx pages without internal details.",
        "Log full errors server-side only, never in the HTTP response."
      ]
    },
    fixPrompt:
      "My production app returns verbose stack traces / debug error pages on bad input. Turn off debug mode in production, return generic error pages, and keep detailed errors in server logs only. Show me the config.",
    version: 1,
    enabled: true
  },
  {
    slug: "idor-sequential-ids",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Object access by predictable sequential IDs (IDOR)",
    description:
      "AI-generated CRUD scaffolding often exposes resources by sequential numeric IDs without an ownership check, so changing the ID in the URL returns another user's data.",
    impactOneline:
      "Changing an ID in the URL may expose other users' private records.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "idorProbe" },
    // This needs authenticated/multi-request probing to confirm safely -> Deep Scan.
    tierRequired: "deep",
    remediation: {
      summary: "Add server-side ownership checks to every record lookup.",
      steps: [
        "On every fetch/update/delete, verify the record belongs to the authenticated user.",
        "Prefer non-guessable IDs (UUIDs) for user-facing resources.",
        "Add automated tests that attempt cross-account access."
      ]
    },
    fixPrompt:
      "My API may have IDOR: records are fetched by sequential ID without checking ownership. Add server-side ownership checks to every record access and switch user-facing IDs to UUIDs. Show the updated handlers.",
    version: 1,
    enabled: true
  }
];
