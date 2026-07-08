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
    slug: "phpinfo-exposed",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "high",
    title: "PHP phpinfo() page reachable in production",
    description:
      "A phpinfo() diagnostic page is publicly reachable. It dumps PHP version, loaded extensions, server paths, and often environment variables — a goldmine for attackers planning further exploits.",
    impactOneline: "Anyone can read your full PHP/server configuration via phpinfo().",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "phpinfoExposed" },
    tierRequired: "free",
    remediation: {
      summary: "Delete phpinfo pages from production and block the paths at the server.",
      steps: [
        "Remove phpinfo.php / info.php from the deployed web root.",
        "Return 404 for /phpinfo* paths in your server or WAF rules.",
        "Rotate any secrets that may have appeared in phpinfo environment output."
      ]
    },
    fixPrompt:
      "My production server still serves phpinfo.php (or similar). Remove those diagnostic files from the web root, block the paths in production, and show me the server config change.",
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
    detectorConfig: { rule: "idorObjectAccess" },
    // Active read-only GET probe with sequential ID — positive proof, not bundle heuristic.
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
  },
  {
    slug: "sql-error-disclosure",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "SQL syntax error disclosed on search/query input",
    description:
      "A search or filter endpoint returns a raw database syntax error when given malformed input, proving the parameter is interpolated into SQL. This is positive proof of SQL injection risk.",
    impactOneline: "Attackers can read or modify your database via the search parameter.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "sqlErrorDisclosure" },
    tierRequired: "deep",
    remediation: {
      summary: "Use parameterized queries; never concatenate user input into SQL.",
      steps: [
        "Replace string-concatenated queries with prepared statements / ORM bindings.",
        "Return generic errors to clients; log SQL details server-side only.",
        "Add input validation and WAF rules on search endpoints."
      ]
    },
    fixPrompt:
      "My search endpoint returns SQL syntax errors (e.g. SQLITE_ERROR) when given malformed input. Switch to parameterized queries/ORM bindings, return generic errors to clients, and show me the fixed handler.",
    version: 1,
    enabled: true
  },
  {
    slug: "unauthenticated-admin-endpoint",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "critical",
    title: "Admin or application configuration reachable without authentication",
    description:
      "An administrative configuration endpoint responds with application settings to unauthenticated GET requests. Attackers gain internal config, feature flags, and sometimes secrets.",
    impactOneline: "Anyone can read your admin/application configuration over HTTP.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "unauthenticatedAdminEndpoint" },
    tierRequired: "free",
    remediation: {
      summary: "Require admin authentication on every configuration endpoint.",
      steps: [
        "Gate /admin and /rest/admin routes behind session + role checks.",
        "Return 401/403 for unauthenticated callers.",
        "Never expose full application config in production APIs."
      ]
    },
    fixPrompt:
      "My /rest/admin/application-configuration (or similar admin config route) returns JSON without authentication. Add admin session + role checks and return 401 for unauthenticated requests. Show the middleware.",
    version: 1,
    enabled: true
  },
  {
    slug: "dangerous-html-sinks",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "Dangerous HTML sinks in client bundle",
    description:
      "The shipped JavaScript uses bypassSecurityTrustHtml, dangerouslySetInnerHTML, or dynamic innerHTML bindings with API/user data — bypassing XSS sanitization. Stored or reflected XSS becomes trivial.",
    impactOneline: "User-controlled data is rendered as HTML — XSS can steal sessions.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "dangerousHtmlSinks" },
    tierRequired: "free",
    remediation: {
      summary: "Never mark user/API content as trusted HTML; encode or sanitize.",
      steps: [
        "Remove bypassSecurityTrustHtml / dangerouslySetInnerHTML on dynamic data.",
        "Render user content as text nodes or through a strict sanitizer.",
        "Add CSP without unsafe-inline in production."
      ]
    },
    fixPrompt:
      "My Angular/React bundle uses bypassSecurityTrustHtml or dangerouslySetInnerHTML with dynamic data (orderId, searchValue, etc.). Remove trusted-HTML rendering on user/API content and show the safe template change.",
    version: 1,
    enabled: true
  },
  {
    slug: "dom-eval-xss",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DOM XSS via eval() on user input",
    description:
      "The shipped JavaScript passes DOM input (getElementById/querySelector .value) directly to eval() or new Function(). Any attacker-controlled string executes as code in the victim's browser.",
    impactOneline: "User input is executed via eval() — full session compromise via crafted input.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "domEvalXss" },
    tierRequired: "free",
    remediation: {
      summary: "Remove eval() and new Function() on any user-influenced string.",
      steps: [
        "Delete eval()/new Function() calls that read from DOM inputs.",
        "Parse structured data with JSON.parse and validate with a schema.",
        "Render user content as text, never as executable code."
      ]
    },
    fixPrompt:
      "My client bundle calls eval() or new Function() on DOM input (.value from getElementById/querySelector). Remove dynamic code execution, parse input safely, and show the fixed handler.",
    version: 1,
    enabled: true
  },
  {
    slug: "open-redirect-query-param",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Open redirect via query parameter",
    description:
      "A URL query parameter (e.g. ?next=, ?redirect=, ?return=) accepts an arbitrary external destination and the server issues an HTTP redirect to it. AI-generated login and OAuth flows commonly ship this pattern for post-auth navigation without validating the target.",
    impactOneline:
      "Attackers can craft links that redirect victims to phishing sites after visiting your domain.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "openRedirect" },
    tierRequired: "free",
    remediation: {
      summary: "Allow-list redirect destinations; never redirect to arbitrary URLs from query params.",
      steps: [
        "Replace open redirects with an allow-list of same-origin paths (or known trusted hosts).",
        "Reject absolute URLs unless the host is explicitly trusted.",
        "Prefer relative paths only (e.g. /dashboard) for post-login navigation."
      ]
    },
    fixPrompt:
      "My app has an open redirect: a query parameter like ?next= or ?redirect= sends users to arbitrary external URLs. Add an allow-list so only same-origin (or explicitly trusted) destinations are permitted, and show me the updated redirect handler.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-idor-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Client bundle documents IDOR-prone API routes",
    description:
      "The shipped JavaScript explicitly documents API endpoints that fetch or mutate resources by user-controlled ID without ownership verification — a client-side IDOR anti-pattern even before probing the server.",
    impactOneline:
      "API routes keyed by user ID lack ownership checks — changing the ID may expose other accounts.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideIdorEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Add server-side ownership checks; never trust client-side authorization.",
      steps: [
        "Verify the authenticated user owns every record on GET/PUT/DELETE.",
        "Remove demo vulnerability markers and mock APIs from production bundles.",
        "Use non-guessable IDs and audit all /api/users/{id} style routes."
      ]
    },
    fixPrompt:
      "My client bundle documents IDOR-prone /api/users/{id} routes without ownership checks. Add server-side authorization on every record access and remove vulnerable demo endpoints from production. Show the fixed handlers.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-sql-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Client bundle builds SQL via string concatenation",
    description:
      "The shipped JavaScript constructs SQL queries by concatenating user input into SELECT/WHERE clauses, or simulates classic SQLi bypass checks (e.g. ' or '1'='1). When wired to a real database this is trivially injectable.",
    impactOneline:
      "SQL is built from user strings in the browser — classic injection if the query reaches a database.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSqlEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Use parameterized queries; never concatenate user input into SQL.",
      steps: [
        "Replace string-concat SQL with prepared statements / ORM parameter binding.",
        "Remove client-side SQL simulation and auth bypass string checks from production.",
        "Validate and escape all user input server-side before it touches a query."
      ]
    },
    fixPrompt:
      "My client bundle concatenates user input into SQL (SELECT ... WHERE id = '\" + input). Replace with parameterized queries server-side and remove unsafe string-concat query builders from the shipped JavaScript.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ssrf-evidence",
    platform: "generic",
    category: "Server-side request forgery",
    severityDefault: "high",
    title: "Client bundle documents SSRF-prone URL fetch in admin panel",
    description:
      "The shipped JavaScript includes SSRF lab markers (e.g. VULNERABILITY: SSRF, localhost blocklist bypass) where user-supplied URLs are fetched server-side without validation.",
    impactOneline:
      "Admin panels that fetch arbitrary URLs enable SSRF — internal services and cloud metadata may be reachable.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSsrfEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Block internal IPs, metadata endpoints, and file:// schemes before server-side fetch.",
      steps: [
        "Allowlist outbound fetch destinations; deny RFC1918, link-local, and metadata IPs.",
        "Never pass raw user URLs to server-side fetch without DNS rebinding protections.",
        "Remove SSRF demo code and vulnerability markers from production bundles."
      ]
    },
    fixPrompt:
      "My admin panel fetches user-supplied URLs server-side (SSRF risk). Add URL allowlisting, block private/metadata IPs, and show the safe fetch handler.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-file-upload-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "critical",
    title: "Client bundle documents unsafe file upload without validation",
    description:
      "The shipped JavaScript advertises file upload with no type or size validation (e.g. VULNERABILITY: No file type validation), enabling arbitrary file upload to admin panels.",
    impactOneline:
      "Unrestricted file upload can lead to webshell deployment and full server compromise.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideFileUploadEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Validate MIME type, extension, and size server-side; store uploads outside webroot.",
      steps: [
        "Allowlist safe extensions and verify magic bytes server-side.",
        "Enforce max file size and scan uploads with AV where possible.",
        "Store uploads on object storage with no execute permission."
      ]
    },
    fixPrompt:
      "My app uploads files without type validation (VULNERABILITY: No file type validation). Add server-side MIME/extension allowlisting, size limits, and store uploads outside the webroot.",
    version: 1,
    enabled: true
  },
  {
    slug: "sensitive-api-token-leakage",
    platform: "generic",
    category: "Sensitive data exposure",
    severityDefault: "high",
    title: "JWT or session token returned in unauthenticated API response",
    description:
      "A JSON API endpoint returns a JWT or session token (e.g. token field with eyJ...) without requiring authentication — leaking secrets to any caller.",
    impactOneline:
      "Session tokens in public API responses let attackers hijack accounts or read privileged data.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "sensitiveApiTokenLeakage" },
    tierRequired: "deep",
    remediation: {
      summary: "Never return session tokens in public API bodies; use HttpOnly cookies.",
      steps: [
        "Remove token fields from unauthenticated GET responses.",
        "Store session tokens in HttpOnly Secure cookies, not JSON bodies.",
        "Remove DEBUG token console.log statements from production bundles."
      ]
    },
    fixPrompt:
      "My /api/posts (or similar) returns a JWT in the JSON body without auth. Remove token fields from public responses, use HttpOnly cookies for sessions, and delete debug token logging.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-session-hijack-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "high",
    title: "Client bundle documents session hijack / token replay",
    description:
      "The shipped HTML/JavaScript walks through session token theft and replay (e.g. doReplay, vault-token UI) — indicating cookies lack HttpOnly/Secure or session fixation is possible.",
    impactOneline:
      "Session tokens can be stolen and replayed — MFA does not protect against cookie theft.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSessionHijackEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Set HttpOnly + Secure + SameSite on session cookies; enable server-side revocation.",
      steps: [
        "Add HttpOnly and Secure flags to all session/auth cookies.",
        "Use SameSite=Lax or Strict to limit cross-site cookie sending.",
        "Rotate session IDs on login and support server-side session revocation."
      ]
    },
    fixPrompt:
      "My app is vulnerable to session hijack (session tokens can be stolen and replayed). Configure session cookies with HttpOnly, Secure, and SameSite=Lax, rotate session IDs on login, and add server-side session revocation. Show the cookie/session config.",
    version: 1,
    enabled: true
  },
  {
    slug: "server-side-eval-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "critical",
    title: "Server handler passes request body to eval()",
    description:
      "Application source (bundled or tutorial-visible) shows eval(req.body.*) or eval(req.query.*) — a classic server-side JavaScript injection pattern in Node/Express apps.",
    impactOneline:
      "User input is passed to eval() on the server — remote code execution is likely.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "serverSideEvalEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Remove eval(); parse input with JSON.parse or typed parsers.",
      steps: [
        "Delete eval() and new Function() calls that read req.body or req.query.",
        "Use JSON.parse with schema validation for structured input.",
        "Return generic errors; never execute user strings as code."
      ]
    },
    fixPrompt:
      "My Node/Express handler uses eval(req.body.field) to parse user input. Remove eval(), parse with JSON.parse + validation, and show the safe handler.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-prototype-pollution-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Client bundle documents prototype pollution via __proto__ merge",
    description:
      "The shipped HTML/JavaScript merges user-controlled objects without blocking __proto__ or constructor.prototype — enabling prototype pollution that can escalate to RCE in some stacks.",
    impactOneline:
      "Unsafe object merge allows __proto__ pollution — privilege escalation or RCE may follow.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePrototypePollutionEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Block __proto__ and constructor keys during object merge.",
      steps: [
        "Use Object.create(null) for lookup maps or a safe merge library.",
        "Reject keys __proto__, constructor, and prototype from user JSON.",
        "Freeze Object.prototype in hardened environments where supported."
      ]
    },
    fixPrompt:
      "My app merges user JSON into config objects without blocking __proto__. Add key blocklisting for __proto__/constructor/prototype and show a safe merge helper.",
    version: 1,
    enabled: true
  },
  {
    slug: "reflected-xss-query-param",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "Reflected XSS via query parameter",
    description:
      "A search or filter query parameter is echoed unescaped in the HTML response body. Attackers can craft links that execute JavaScript in victims' browsers when clicked.",
    impactOneline: "A URL parameter is reflected as raw HTML — session theft via crafted links is likely.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "reflectedXss" },
    tierRequired: "deep",
    remediation: {
      summary: "HTML-encode all user input before rendering; use framework auto-escaping.",
      steps: [
        "Encode dynamic output in HTML contexts (use framework escaping, never raw concatenation).",
        "Add a strict Content-Security-Policy without unsafe-inline.",
        "Validate and reject HTML metacharacters on input where possible."
      ]
    },
    fixPrompt:
      "My app reflects query parameters unescaped in HTML (reflected XSS). HTML-encode all dynamic output, remove raw string concatenation in templates, and add a strict CSP. Show the fixed handler/template.",
    version: 1,
    enabled: true
  },
  {
    slug: "spring-boot-actuator-exposed",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "Spring Boot actuator endpoints exposed",
    description:
      "Spring Boot management endpoints (/actuator) respond with JSON to unauthenticated requests. Attackers can read health, git commit info, and sometimes environment secrets depending on exposure settings.",
    impactOneline: "Management/monitoring endpoints are publicly reachable — config and secrets may leak.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "springActuatorExposed" },
    tierRequired: "free",
    remediation: {
      summary: "Restrict actuator to internal networks and disable sensitive endpoints in production.",
      steps: [
        "Set management.endpoints.web.exposure.include to only what you need (often just health).",
        "Require authentication on /actuator or move it off the public internet.",
        "Disable env, heapdump, and configprops endpoints in production."
      ]
    },
    fixPrompt:
      "My Spring Boot app exposes /actuator publicly (health/info/_links JSON). Lock down management endpoints: restrict exposure, require auth, and show me the application.properties / application.yml changes.",
    version: 1,
    enabled: true
  },
  {
    slug: "hidden-prompt-injection",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "Hidden prompt-injection instructions in page HTML",
    description:
      "The page source embeds instructions for AI agents or scrapers using hidden HTML — comments, zero-opacity text, display:none blocks, data-system-prompt attributes, or zero-width Unicode. Untrusted page content can manipulate agents that summarize or act on the page.",
    impactOneline:
      "Hidden HTML tricks AI agents into leaking data or following attacker instructions — indirect prompt injection.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "hiddenPromptInjection" },
    tierRequired: "free",
    remediation: {
      summary: "Strip untrusted HTML before feeding it to AI agents; never trust page source as benign.",
      steps: [
        "Sanitize or block-list HTML comments, hidden elements, and data-* prompt attributes before agent ingestion.",
        "Detect zero-width Unicode and visually hidden text in content pipelines.",
        "Treat all third-party page content as untrusted input to LLM prompts — use structured extraction, not raw HTML dumps."
      ]
    },
    fixPrompt:
      "My site (or a page we ingest) has hidden prompt-injection vectors in the HTML source — comments, display:none instructions, data-system-prompt, or zero-width Unicode. Show how to strip these before any AI agent reads the page, and add detection in our content pipeline.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-prompt-injection-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "Prompt-injection red-team or scanner functionality in client bundle",
    description:
      "The shipped JavaScript or SSR HTML documents prompt-injection attack tooling — adversarial prompt scanners, AI defender challenges, or exposed system-prompt UI. These apps are intentional red-team surfaces; production chatbots with similar patterns risk LLM abuse.",
    impactOneline:
      "Client exposes prompt-injection attack UX or system prompts — LLM guardrails may be bypassable.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePromptInjectionEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Treat LLM inputs as untrusted; never expose system prompts; rate-limit and monitor adversarial probes.",
      steps: [
        "Remove system-prompt disclosure from client-visible UI and bundles.",
        "Add input/output guardrails and logging for jailbreak / injection attempts.",
        "Rate-limit chat endpoints and block automated adversarial prompt scanners in production."
      ]
    },
    fixPrompt:
      "My app ships prompt-injection red-team UI (adversarial prompts, systemPrompt display, attack pool). Remove system-prompt leakage from the client, add server-side guardrails on chat inputs, and show how to detect automated prompt-injection probes.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-nosql-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Client bundle documents NoSQL injection via MongoDB operators",
    description:
      "The shipped JavaScript constructs MongoDB findOne queries with user-supplied JSON objects or documents NoSQL operator injection ($gt, $ne) that bypass authentication.",
    impactOneline:
      "NoSQL queries built from user JSON objects — auth bypass and data exfiltration if wired to MongoDB.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideNosqlEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Sanitize MongoDB query inputs; reject operator keys starting with $.",
      steps: [
        "Use mongo-sanitize or schema validation to strip $ operator keys from user input.",
        "Never pass raw req.body objects directly to findOne/find without type coercion.",
        "Remove NoSQL injection demo code and educational lab markers from production bundles."
      ]
    },
    fixPrompt:
      "My client bundle documents NoSQL injection via MongoDB $gt/$ne operator objects in findOne queries. Add mongo-sanitize, validate login input as strings only, and show the safe Mongoose/MongoDB query handler.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-xxe-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Client bundle documents XXE via external entity expansion",
    description:
      "The shipped HTML/JavaScript documents XML External Entity attacks — file:// entity payloads, libxmljs parsing without noent/nonet hardening, or DOMParser text/xml usage.",
    impactOneline:
      "XXE entity expansion can read local files or reach internal URLs — critical if XML parsing is server-side.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideXxeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Disable external entity processing in all XML parsers.",
      steps: [
        "Set libxmljs/DOMParser options: noent=false, nonet=true, dtdload=false.",
        "Reject DOCTYPE declarations and external entities in user-supplied XML.",
        "Remove XXE demo payloads and educational lab markers from production."
      ]
    },
    fixPrompt:
      "My app parses user-supplied XML with external entity support (XXE risk). Disable entity expansion, block DOCTYPE/external entities, and show the hardened libxmljs or DOMParser configuration.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-api-security-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Client bundle documents OWASP API Security Top 10 lab",
    description:
      "The shipped HTML/JavaScript advertises deliberately vulnerable REST APIs covering OWASP API Security Top 10 categories — BOLA, BFLA, broken authentication, and related API authorization flaws.",
    impactOneline:
      "API routes documented without object/function-level authorization — BOLA and BFLA likely on production endpoints.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideApiSecurityLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Enforce object-level and function-level authorization on every API route.",
      steps: [
        "Verify the authenticated user owns every object on GET/PUT/DELETE.",
        "Check role/permission before admin or privileged function endpoints.",
        "Remove deliberately vulnerable API lab documentation from production bundles."
      ]
    },
    fixPrompt:
      "My API lacks object-level authorization (BOLA) and function-level checks (BFLA). Add ownership validation on every /api/{resource}/{id} route and role checks on admin endpoints. Show the fixed middleware.",
    version: 1,
    enabled: true
  },
  {
    slug: "ssrf-endpoint-fetch",
    platform: "generic",
    category: "Server-side request forgery",
    severityDefault: "high",
    title: "SSRF — server fetches attacker-controlled URL",
    description:
      "An API endpoint accepts a URL parameter and the server fetches it, returning the remote page content in the response. Attackers can use this to reach internal services, cloud metadata, or localhost-only admin panels.",
    impactOneline:
      "A fetch/proxy endpoint follows arbitrary URLs server-side — internal networks and metadata may be reachable.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "ssrfEndpointProbe" },
    tierRequired: "free",
    remediation: {
      summary: "Block SSRF: allow-list destinations, validate resolved IPs, disable redirects.",
      steps: [
        "Replace open URL fetch with an allow-list of trusted hosts/schemes.",
        "Resolve DNS and reject private, loopback, and link-local IP ranges before connecting.",
        "Disable HTTP redirects on outbound requests and cap response size/timeouts."
      ]
    },
    fixPrompt:
      "My API has an SSRF-prone fetch/proxy endpoint that follows user-supplied URLs. Add allow-listing, block private/metadata IPs after DNS resolution, disable redirects, and show the safe server-side fetch handler.",
    version: 1,
    enabled: true
  }
];
