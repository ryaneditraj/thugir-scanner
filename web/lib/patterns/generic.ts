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
    slug: "client-side-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "Source or bundle documents reflected XSS via unescaped input",
    description:
      "PHP source or client bundle echoes $_GET/$_REQUEST or user input into HTML without encoding (e.g. DVWA xss_r low.php). Reflected XSS is trivial when this code is reachable.",
    impactOneline:
      "User input is rendered as HTML without escaping — reflected XSS can steal sessions.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Encode all user input before HTML output; use Content-Security-Policy.",
      steps: [
        "Replace echo/concat patterns with htmlspecialchars() or framework auto-escaping.",
        "Never assign user input to innerHTML or document.write.",
        "Add CSP without unsafe-inline in production."
      ]
    },
    fixPrompt:
      "My PHP or client code echoes user input into HTML without encoding (e.g. $html .= '<pre>Hello ' . $_GET['name']). Show the fix using proper output encoding and CSP headers.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-security-game-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Educational security game documents multiple vulnerability modules",
    description:
      "The shipped JavaScript documents a level-select security training game with explicit vulnerability modules (SQL Injection, XSS, IDOR, etc.) and vulnerable code walkthroughs — the bundled lab logic is intentionally exploitable.",
    impactOneline:
      "Public game bundle ships working vulnerability modules — attackers can study and exploit the documented patterns.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSecurityGameEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Remove vulnerable lab logic from production bundles; gate training games behind auth.",
      steps: [
        "Do not ship interactive SQLi/XSS/IDOR challenge code in public production JavaScript.",
        "Host security training games on isolated lab domains, not production apps.",
        "Replace string-concat SQL and unescaped echo patterns with safe demo stubs."
      ]
    },
    fixPrompt:
      "My security training game bundle documents SQL Injection, XSS, and IDOR levels with vulnerable code samples. Show how to isolate this to a private lab environment and remove exploitable patterns from the production bundle.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-owasp-ctf-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "OWASP Top 10 CTF hub with linked vulnerable challenge targets",
    description:
      "The shipped JavaScript documents an OWASP Top 10 CTF challenge catalog (A01–A10) with URLs to live vulnerable Railway/deploy targets — broken access control and injection labs are one click away.",
    impactOneline:
      "Public CTF hub exposes linked intentionally vulnerable apps — attackers can enumerate and attack sibling targets.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "owaspCtfLinkedLabProbe" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate CTF hubs behind auth; network-isolate challenge targets.",
      steps: [
        "Remove production URLs to vulnerable challenge apps from public bundles.",
        "Require team login before revealing challenge target URLs.",
        "Deploy challenges on private networks, not public Railway URLs."
      ]
    },
    fixPrompt:
      "Our OWASP CTF hub ships challenge URLs to live vulnerable Railway apps in the client bundle. Show how to gate challenge links behind authenticated APIs and isolate lab targets from the public internet.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctf-platform-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "CTF challenge platform SPA with public challenge APIs",
    description:
      "The shipped JavaScript documents a Hackforge-style CTF platform with publicChallenges(), flag submission UI, and admin challenge routes — challenge metadata and APIs are exposed in the client bundle.",
    impactOneline:
      "Public CTF platform bundle reveals challenge APIs and flag workflows attackers can enumerate.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtfPlatformEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate challenge APIs behind auth; avoid shipping admin routes in public bundles.",
      steps: [
        "Require login before listing or fetching challenge details.",
        "Move admin challenge management off the public SPA bundle.",
        "Rate-limit flag submission endpoints server-side."
      ]
    },
    fixPrompt:
      "Our CTF platform SPA ships publicChallenges APIs and CTF{ flag submission UI in the client bundle. Show how to gate challenge routes behind authenticated APIs and remove admin paths from the production bundle.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-owasp-educational-lab-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "OWASP Top 10 educational lab pages document injectable patterns",
    description:
      "Crawled Docusaurus or static OWASP lab content includes walkthroughs for SQL injection (patient_lookup.php, UNION SELECT), IDOR enumeration, or broken access-control flaws — the tutorial itself documents exploitable patterns.",
    impactOneline:
      "Public OWASP lab tutorials ship vulnerable code samples attackers can study and replay on real targets.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOwaspEducationalLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Host lab tutorials on isolated domains; use sanitized code samples in production docs.",
      steps: [
        "Keep intentionally vulnerable tutorial code on dedicated lab hosts, not production apps.",
        "Replace live exploit strings in public docs with redacted or parameterized examples.",
        "Gate hands-on labs behind authentication when they include runnable vulnerable snippets."
      ]
    },
    fixPrompt:
      "Our OWASP Top 10 lab site publishes SQL injection and IDOR walkthroughs with patient_lookup.php and UNION SELECT examples. Show how to host these on an isolated lab domain and redact exploitable snippets from public documentation.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-jwt-none-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "high",
    title: "Client bundle documents JWT alg:none acceptance",
    description:
      "The shipped JavaScript includes a JWT lab where the none algorithm is accepted and role can be escalated to admin — signature verification is bypassable when the server mirrors this logic.",
    impactOneline:
      "JWT alg:none lets attackers forge admin tokens without a valid signature.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideJwtNoneEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Reject alg:none; enforce HMAC/RSA signature verification server-side.",
      steps: [
        "Maintain an allowlist of permitted JWT algorithms (e.g. RS256, HS256).",
        "Reject tokens with alg:none or missing signatures before parsing claims.",
        "Remove JWT attack lab code from production bundles."
      ]
    },
    fixPrompt:
      "My app accepts JWT alg:none and allows role escalation to admin. Show server-side middleware that rejects unsigned tokens, enforces RS256/HS256 only, and validates role claims after signature verification.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-path-traversal-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Client-side path traversal / LFI lab documented in crawl",
    description:
      "Crawled lab pages document directory traversal via unsanitized file path parameters — attackers can use ../ sequences to read files outside the intended directory (e.g. flag.txt).",
    impactOneline:
      "Unsanitized path parameters let attackers read arbitrary files on the server.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePathTraversalEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Canonicalize paths and deny ../ traversal before reading files.",
      steps: [
        "Resolve paths against a fixed base directory and reject any result outside it.",
        "Use an allow-list of filenames instead of user-supplied paths.",
        "Remove LFI walkthrough pages from production-facing hosts."
      ]
    },
    fixPrompt:
      "Our file viewer accepts a path parameter and is vulnerable to directory traversal (../flag.txt). Show how to canonicalize paths against a base directory, block traversal, and use an allow-list of safe filenames.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-graphql-lab-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "DVGA GraphQL security lab documentation exposed",
    description:
      "SpectaQL or static API reference pages for Damn Vulnerable GraphQL Application (DVGA) are reachable — documents importPaste, audits, and other intentionally vulnerable GraphQL mutations.",
    impactOneline:
      "Public GraphQL lab docs reveal attack surface and vulnerable mutation shapes.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideGraphqlLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate lab documentation behind auth; isolate DVGA from production networks.",
      steps: [
        "Remove public SpectaQL/DVGA API reference from internet-facing hosts.",
        "Run GraphQL security labs on private networks only.",
        "Disable introspection and dangerous mutations in any non-lab deployment."
      ]
    },
    fixPrompt:
      "Our host serves public DVGA SpectaQL API reference with importPaste mutations. Show how to remove or auth-gate lab documentation and harden GraphQL introspection in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-react-rsc-cve-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "critical",
    title: "Next.js RSC CVE lab page disclosed",
    description:
      "HTML or bundle documents an intentional Next.js React Server Components CVE lab (CVE-2025-66478 / CVE-2025-55182) with server actions — remote code execution may be reachable.",
    impactOneline:
      "Public RSC CVE demo advertises a known server-side code execution chain.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideReactRscCveEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Upgrade Next.js/React to patched versions; remove public CVE demos.",
      steps: [
        "Upgrade Next.js and React to vendor-patched releases for RSC CVEs.",
        "Remove public HackerOne/react2shell demo deployments from production domains.",
        "Disable or auth-gate server actions that process attacker-controlled input."
      ]
    },
    fixPrompt:
      "Our Next.js app hosts a CVE-2025-66478 RSC lab with a Run Server Action button. Show the patched Next.js/React versions and how to remove or isolate intentional RCE demos from public URLs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-xss-c2-collector-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "XSS C2 collector dashboard with unauthenticated /api/collect exfil endpoint",
    description:
      "The page documents an attacker C2 dashboard for XSS cookie theft, including /api/collect and cross-origin img onerror exfil techniques. GET /api/collect may respond without auth.",
    impactOneline:
      "Public XSS collector endpoints let any site exfiltrate victim session data to an attacker-controlled dashboard.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideXssC2CollectorEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Remove public C2 collectors; enforce HttpOnly cookies and strict CSP.",
      steps: [
        "Do not deploy XSS exfil collector APIs on production domains.",
        "Set HttpOnly and Secure on session cookies so document.cookie cannot read them.",
        "Use a strict Content-Security-Policy to block inline script injection."
      ]
    },
    fixPrompt:
      "Our app hosts an XSS C2 collector at /api/collect that receives stolen cookies cross-origin. Show how to remove the collector, set HttpOnly session cookies, and add CSP to block cookie theft via XSS.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-devsecops-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "DevSecOps microservices lab documents IDOR and gateway bypass attacks",
    description:
      "The client bundle catalogs DevSecOps Hacking Lab attack scenarios — IDOR profile access, gateway bypass, brute force, MFA bypass, plus SIEM/WAF monitoring modules.",
    impactOneline:
      "Educational attack consoles on public URLs teach adversaries reusable IDOR and auth-bypass patterns against real APIs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideDevSecOpsLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Keep offensive lab consoles off public production URLs.",
      steps: [
        "Host DevSecOps attack simulators on isolated lab networks only.",
        "Require authentication before exposing attack scenario UIs.",
        "Never point lab bundles at production API gateways without network segmentation."
      ]
    },
    fixPrompt:
      "Our DevSecOps Hacking Lab bundle documents IDOR exploitation and gateway bypass against /api/users/profile. Show how to isolate the lab from production and gate attack modules behind auth.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vuln-auth-portal-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "medium",
    title: "Intentionally vulnerable auth portal terminal (VulnPortal-style)",
    description:
      "HTML documents a VulnPortal-style secure access terminal with bcrypt/zxcvbn demos and CVSS/OWASP risk rating — an educational broken-auth lab shell.",
    impactOneline:
      "Public vulnerable auth portals expose login bypass and session flaws for training but also give attackers a live target.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnAuthPortalEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Restrict vuln auth portals to lab environments with clear labeling.",
      steps: [
        "Do not deploy VulnPortal-style terminals on production domains.",
        "Require VPN or invite codes for auth bypass training apps.",
        "Use separate subdomains isolated from customer data."
      ]
    },
    fixPrompt:
      "Our site serves a VulnPortal secure access terminal with intentional auth flaws for training. Show how to move it to an isolated lab subdomain and gate registration.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-csrf-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Client bundle documents CSRF-vulnerable transfer flows",
    description:
      "The shipped JavaScript exposes attack/secure mode CSRF labs, unverified token warnings, or simulated forged transfer requests — cross-site request forgery is likely on state-changing endpoints.",
    impactOneline:
      "CSRF protections are disabled or documented as bypassable — attackers can forge bank transfers and account actions.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCsrfEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Enforce CSRF tokens on every state-changing request; validate Origin/Referer.",
      steps: [
        "Issue per-session CSRF tokens and require them on POST/PUT/DELETE.",
        "Set SameSite=Lax or Strict on session cookies.",
        "Remove CSRF attack simulation and vulnerable-mode toggles from production bundles."
      ]
    },
    fixPrompt:
      "My banking app bundle documents CSRF-vulnerable transfer flows with attack/secure mode toggles. Add server-side CSRF token validation on every state-changing endpoint, set SameSite cookies, and remove CSRF lab demo code from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "ssti-template-injection",
    platform: "generic",
    category: "Injection",
    severityDefault: "critical",
    title: "Server-side template injection (SSTI) confirmed via arithmetic probe",
    description:
      "A GET parameter is injected into a server-side template engine. Probing with 7*7 returns 49 in the rendered output — positive proof the template evaluates attacker-controlled expressions.",
    impactOneline:
      "SSTI often escalates to remote code execution — template engines can invoke OS commands.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "sstiTemplateInjection" },
    tierRequired: "deep",
    remediation: {
      summary: "Never pass user input into template expressions; use logic-less templates or strict sandboxing.",
      steps: [
        "Render templates with a logic-less engine or pass user data only as bound variables.",
        "Disable dangerous template helpers (eval, exec, include) in production.",
        "Add input validation and output encoding before any template render path."
      ]
    },
    fixPrompt:
      "My app evaluates user input inside server-side templates (7*7 renders as 49). Stop passing raw query parameters into template expressions, use bound variables only, and show the safe render handler.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-xor-auth-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "high",
    title: "Client-side XOR/obfuscated credential check in browser JS",
    description:
      "The shipped JavaScript validates login by XORing username:password against a hardcoded ciphertext blob with a static key — authentication is entirely client-side and bypassable in DevTools.",
    impactOneline:
      "Client-side auth checks are trivially bypassed — anyone can forge credentials without server validation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideXorAuthEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Move all authentication to the server; never compare credentials in browser JavaScript.",
      steps: [
        "Remove client-side login validation and XOR/cipher comparison logic from production bundles.",
        "Validate credentials server-side with bcrypt/argon2 and issue HttpOnly session cookies.",
        "Never ship encryption keys or expected credential blobs to the browser."
      ]
    },
    fixPrompt:
      "My login uses client-side xorString() to compare credentials against an encrypted blob with a hardcoded key. Move authentication to the server, remove XOR checks from the bundle, and show the secure login API handler.",
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
    slug: "postmessage-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DOM XSS via postMessage → innerHTML sink",
    description:
      "The shipped JavaScript registers a window message listener and assigns postMessage event data to innerHTML without sanitization. Third-party widgets (e.g. Gartner Peer Insights) have shipped this pattern — any page embedding the widget is vulnerable to DOM XSS from a malicious iframe.",
    impactOneline:
      "postMessage data is written to innerHTML — cross-origin iframe can execute script in the parent page.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "postMessageDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never assign postMessage data to innerHTML; sanitize or use textContent.",
      steps: [
        "Replace innerHTML assignments from message handlers with textContent or a strict HTML sanitizer.",
        "Validate event.origin against an explicit allow-list before processing message data.",
        "Parse message payloads as JSON and reject HTML-bearing fields."
      ]
    },
    fixPrompt:
      "My widget listens for postMessage and assigns event.data to innerHTML. Replace innerHTML with safe rendering (textContent or DOMPurify), validate event.origin, and show the fixed message handler.",
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
  },
  {
    slug: "pentest-forge-linked-lab-probe",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "Public vulnerable lab catalog with linked benchmark targets",
    description:
      "Page catalogs PentestForge *.lab.pentest-forge.com vulnerable apps (Juice Shop, crAPI, VAmPI, Tomcat, WebLogic) or a linked subdomain returned unauthenticated vulnerable-app data.",
    impactOneline:
      "Public benchmark playground exposes live vulnerable targets — scanners and attackers can enumerate OWASP/API/CVE labs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "pentestForgeLinkedLabProbe" },
    tierRequired: "deep",
    remediation: {
      summary: "Restrict lab hubs to authenticated testers; do not expose production-adjacent domains publicly.",
      steps: [
        "Gate benchmark playgrounds behind auth or VPN.",
        "Use robots/noindex and avoid linking live vulnerable apps from public marketing pages.",
        "Isolate lab subnets from production networks."
      ]
    },
    fixPrompt:
      "Our site links to public PentestForge vulnerable lab subdomains. Show how to restrict the catalog to authenticated users and network-isolate benchmark targets.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-chimera-vuln-lab-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "Chimera WAF honeypot documents 456+ intentional API vulnerabilities",
    description:
      "Jekyll documentation catalogs the Chimera vuln-api honeypot with CHM-ID registry entries spanning injection, IDOR, SSRF, and broken auth across 25+ industry domains.",
    impactOneline:
      "Public Chimera docs advertise a deployable honeypot with hundreds of exploitable API flaws — attackers can mirror the catalog against live instances.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideChimeraVulnLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Keep Chimera honeypot docs and deployments on isolated lab networks.",
      steps: [
        "Do not expose Chimera vuln-api instances to the public internet without WAF protection.",
        "Gate vulnerability inventory pages behind authentication for internal red-team use only.",
        "Segment honeypot subnets from production VPCs."
      ]
    },
    fixPrompt:
      "Our site documents the Chimera vuln-api honeypot with CHM-ID vulnerability inventory. Show how to restrict docs to internal red-team networks and isolate honeypot deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hack-health-lab-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Hack Health tutorial documents intentional SQL injection lab",
    description:
      "Nextra tutorial pages walk through CWE-89 SQL injection on the HackHealth login — string-concatenated queries and UNION SELECT pg_user enumeration.",
    impactOneline:
      "Educational SQLi walkthrough on a public deploy teaches reusable PostgreSQL injection patterns against the live login API.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHackHealthLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Use parameterized queries and restrict tutorial labs to local dev.",
      steps: [
        "Replace string-concatenated SQL with parameterized queries or an ORM.",
        "Host HackHealth attack tutorials on localhost only, not public Vercel deploys.",
        "Remove UNION-based enumeration examples from production-facing docs."
      ]
    },
    fixPrompt:
      "Our HackHealth tutorial documents intentional SQL injection with UNION SELECT against pg_user. Show parameterized query fixes and how to gate the attack lab behind local-only access.",
    version: 1,
    enabled: true
  },
  {
    slug: "openapi-debug-password-exposure",
    platform: "generic",
    category: "Sensitive data exposure",
    severityDefault: "critical",
    title: "OpenAPI debug endpoint exposes cleartext passwords",
    description:
      "An OpenAPI-documented GET debug route (e.g. /users/v1/_debug) returns user records with cleartext password fields without authentication.",
    impactOneline:
      "Debug API routes leak password hashes or cleartext credentials to unauthenticated callers.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "openApiDebugPasswordExposure" },
    tierRequired: "deep",
    remediation: {
      summary: "Remove debug endpoints from production; never return password fields in API responses.",
      steps: [
        "Delete or disable /_debug and /debug/* routes outside development.",
        "Strip password fields from all API serializers and OpenAPI schemas.",
        "Require admin authentication for any diagnostic user-listing endpoints."
      ]
    },
    fixPrompt:
      "Our API exposes GET /users/v1/_debug returning cleartext passwords without auth. Remove the debug route, strip password fields from responses, and show the hardened user serializer.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-dom-goat-lab-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DomGoat DOM XSS lab documents client-side sources and sinks",
    description:
      "DomGoat (domgo.at) catalogs Client XSS sources, sinks, and innerHTML exercises across /cxss routes — a deliberate DOM-based XSS training platform.",
    impactOneline:
      "Public DomGoat labs teach DOM XSS gadget chains attackers can replay against any app with similar sink patterns.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideDomGoatLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never assign untrusted data to innerHTML; use textContent or a strict sanitizer.",
      steps: [
        "Replace innerHTML assignments with textContent or DOMPurify-sanitized HTML.",
        "Host DomGoat-style labs on isolated subdomains, not production apps.",
        "Audit all DOM sinks (innerHTML, document.write, eval) in client bundles."
      ]
    },
    fixPrompt:
      "Our site hosts DomGoat-style DOM XSS exercises with innerHTML sinks on /cxss routes. Show safe textContent alternatives and how to isolate the lab from production traffic.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-invicti-practice-site-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "Invicti/Netsparker practice site documents SQLi, XSS, and LFI targets",
    description:
      "Invicti Test Web Site pages advertise sql-injection, XSS, and file-inclusion practice endpoints including hidden phpinfo and nslookup forms.",
    impactOneline:
      "Public scanner benchmark sites expose known-vulnerable PHP endpoints attackers use to tune automated exploitation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideInvictiPracticeSiteEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Remove practice vulnerable apps from public internet; use local Docker labs only.",
      steps: [
        "Take Invicti/Netsparker practice sites offline or restrict to VPN-only access.",
        "Remove hidden phpinfo.php and command-injection forms from any reachable host.",
        "Replace live SQLi/XSS targets with static documentation on secure coding."
      ]
    },
    fixPrompt:
      "Our Invicti practice site exposes artist.php SQLi, hello.php eval, and hidden phpinfo endpoints. Show how to retire the public demo and move exercises to a local-only Docker lab.",
    version: 1,
    enabled: true
  },
  {
    slug: "sensitive-api-password-leakage",
    platform: "generic",
    category: "Sensitive data exposure",
    severityDefault: "critical",
    title: "Cleartext passwords returned by unauthenticated JSON API",
    description:
      "A robots.txt-disclosed or common admin API route (e.g. /api/admin/users) returns user records with cleartext password fields without authentication.",
    impactOneline:
      "User passwords exposed in public API responses enable credential theft and account takeover.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "sensitiveApiPasswordLeakage" },
    tierRequired: "deep",
    remediation: {
      summary: "Never return password fields in API responses; hash credentials server-side.",
      steps: [
        "Remove password columns from all JSON serializers and DTOs.",
        "Hash passwords with bcrypt/argon2; never store or transmit cleartext.",
        "Require authentication and authorization on every /api/admin/* route."
      ]
    },
    fixPrompt:
      "Our /api/admin/users returns Email and Password fields without auth. Remove password from API responses, hash credentials server-side, and lock admin routes behind authentication.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hack-yourself-first-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "Hack Yourself First training app documents deliberate security flaws",
    description:
      "Troy Hunt's Supercar Showdown demo advertises 50+ intentional appsec mistakes for the Pluralsight Hack Yourself First course.",
    impactOneline:
      "Public intentionally-vulnerable training apps expose realistic attack surfaces if left reachable in production.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHackYourselfFirstEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Host training vulnerable apps on isolated lab infrastructure only.",
      steps: [
        "Move Hack Yourself First-style demos to VPN-only or local Docker environments.",
        "Never deploy courseware with live cleartext credential APIs to public URLs.",
        "Reset lab databases frequently and monitor for abuse."
      ]
    },
    fixPrompt:
      "We host a Hack Yourself First-style training app with dozens of deliberate flaws. Show how to isolate it on a lab subdomain with auth gating and remove cleartext password APIs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-websec-challenge-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "WebSec.fr challenge levels disclose injectable PHP source",
    description:
      "WebSec.fr publishes syntax-highlighted PHP for /levelNN/ challenges including doQuery($injection) SQL concatenation behind anti_csrf.php.",
    impactOneline:
      "Public challenge source code documents live SQLi/XSS flaws attackers can practice against without authentication.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWebsecChallengeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Host challenge source on isolated lab infrastructure; never deploy training SQLi to production domains.",
      steps: [
        "Move WebSec-style challenge apps to VPN-only or local Docker environments.",
        "Remove public /source.php disclosure on any internet-facing host.",
        "Replace live SQL concatenation exercises with parameterized query tutorials."
      ]
    },
    fixPrompt:
      "Our WebSec.fr-style challenge site exposes doQuery($injection) source at /level01/source.php. Show how to retire public source disclosure and move labs offline.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-sixhack-ctf-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "SixHack Academy CTF Labs document OWASP web flaws",
    description:
      "SixHack Academy advertises free CTF Labs on platform.sixhackacademy.com covering SQL injection, XSS, IDOR, and SSRF.",
    impactOneline:
      "Public CTF lab platforms expose realistic OWASP Top 10 attack surfaces for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSixHackCtfLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate CTF lab platforms behind registration and rate limits; isolate from production data.",
      steps: [
        "Require authentication before exposing injectable lab endpoints.",
        "Run labs on dedicated subdomains with no production database access.",
        "Reset lab state frequently and monitor for abuse."
      ]
    },
    fixPrompt:
      "We host free CTF Labs on platform.sixhackacademy.com with SQLi and XSS challenges. Show how to gate labs behind auth and isolate them from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-rootme-challenge-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Root Me hacking challenge platform publicly indexed",
    description:
      "Root Me (root-me.org) publishes hundreds of Web-Client, App, and Crypto challenges with RSS feeds and documented solutions.",
    impactOneline:
      "Public challenge platforms list exploitable Web-Client and App targets attackers use to tune scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideRootMeChallengeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Challenge platforms are intentional labs — ensure they never share infrastructure with production apps.",
      steps: [
        "Keep challenge VMs isolated from corporate or customer networks.",
        "Do not reuse challenge code patterns in production applications.",
        "Monitor challenge infrastructure for outbound abuse."
      ]
    },
    fixPrompt:
      "Our site mirrors Root Me-style public challenges. Show how to isolate lab VMs and prevent challenge code from leaking into production deploys.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentesterlab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "PentesterLab web hacking exercise platform disclosed",
    description:
      "PentesterLab advertises 700+ hands-on labs covering real-world CVEs, SQL injection, XSS, and Web for Pentester exercises.",
    impactOneline:
      "Public exercise platforms expose intentionally vulnerable endpoints attackers use to calibrate scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; never reuse lab code in production apps.",
      steps: [
        "Require authentication before serving injectable exercise instances.",
        "Isolate exercise infrastructure from production networks.",
        "Monitor outbound traffic from lab containers."
      ]
    },
    fixPrompt:
      "We host PentesterLab-style web hacking exercises. Show how to gate labs behind auth and isolate them from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentesterlab-web-for-pentester-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "PentesterLab Web for Pentester course disclosed",
    description:
      "PentesterLab Web for Pentester free exercise documents foundational web penetration testing, vulnerability identification, and exploitation techniques.",
    impactOneline:
      "Public Web for Pentester curriculum reveals injection and access-control lab taxonomy for junior pentesters.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterlabWebForPentesterEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; never reuse lab code in production apps.",
      steps: [
        "Require authentication before serving injectable exercise instances.",
        "Isolate exercise infrastructure from production networks.",
        "Monitor outbound traffic from lab containers."
      ]
    },
    fixPrompt:
      "We host PentesterLab Web for Pentester-style exercises. Show how to gate labs behind auth and isolate them from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-kontra-application-security-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Kontra application security training platform disclosed",
    description:
      "Kontra application.security publishes free interactive OWASP Top 10 for Web and API training modules for developer secure-coding education.",
    impactOneline:
      "Public Kontra exercise hubs document API injection and BOLA patterns used to calibrate scanners against training labs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideKontraApplicationSecurityEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Kontra labs are intentional training — gate free exercises behind business email verification.",
      steps: [
        "Require authenticated accounts before launching injectable API lab instances.",
        "Isolate Kontra-style training environments from production API gateways.",
        "Use Kontra findings to patch similar OWASP API Top 10 gaps in production services."
      ]
    },
    fixPrompt:
      "We host Kontra-style OWASP API Top 10 training. Show how to gate lab modules behind auth and isolate them from production APIs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-immersive-labs-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Immersive Labs cyber resilience platform disclosed",
    description:
      "Immersive Labs advertises browser-based cyber resilience drills, hands-on skill labs, and benchmark reporting for security teams.",
    impactOneline:
      "Public Immersive Labs marketing pages document training lab infrastructure attackers use to tune discovery scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideImmersiveLabsEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Immersive Labs instances are intentional training — never expose lab VMs to production networks.",
      steps: [
        "Run Immersive Labs drills only on dedicated training tenants.",
        "Require SSO before granting access to browser-based exploit labs.",
        "Use drill findings to close skill gaps without copying vulnerable lab code to production."
      ]
    },
    fixPrompt:
      "We use Immersive Labs-style cyber drills for team training. Show how to isolate lab tenants from production and gate browser labs behind SSO.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hackthebox-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Hack The Box cyber readiness platform disclosed",
    description:
      "Hack The Box advertises 1,500+ hands-on cybersecurity labs, CTF challenge machines, and cyber readiness exercises for penetration testers.",
    impactOneline:
      "Public HTB marketing pages document lab infrastructure and CTF challenge taxonomy attackers use to calibrate scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHackTheBoxEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "HTB labs are intentional training — isolate challenge VMs from production networks.",
      steps: [
        "Run HTB challenge machines only on dedicated lab VLANs.",
        "Require authenticated accounts before spawning injectable lab instances.",
        "Never copy HTB challenge vulnerability patterns into production code."
      ]
    },
    fixPrompt:
      "We use Hack The Box-style CTF labs for team training. Show how to isolate challenge VMs from production and gate lab spawns behind SSO.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hackthebox-academy-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "HTB Academy cybersecurity training platform disclosed",
    description:
      "HTB Academy publishes guided interactive modules with hands-on exercises against real-world applications and penetration testing certification paths.",
    impactOneline:
      "Public HTB Academy catalogues document web exploitation module taxonomy reusable for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHackTheBoxAcademyEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "HTB Academy modules are intentional training — gate lab instances behind paid accounts.",
      steps: [
        "Require HTB Academy authentication before serving injectable lab VMs.",
        "Isolate Academy lab instances from corporate production networks.",
        "Use module findings to close skill gaps without copying vulnerable lab code to production."
      ]
    },
    fixPrompt:
      "We host HTB Academy-style guided cybersecurity courses. Show how to gate lab modules behind auth and isolate them from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hackthissite-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "HackThisSite mission challenges publicly indexed",
    description:
      "HackThisSite.org advertises Basic, Realistic, and Application mission challenges for ethical hacking practice.",
    impactOneline:
      "Public wargame missions document SQLi, XSS, and auth bypass patterns reusable against real apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHackThisSiteEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Wargame missions are intentional — ensure they never share code with production deployments.",
      steps: [
        "Keep mission challenge VMs isolated from corporate networks.",
        "Do not copy mission vulnerability patterns into production code.",
        "Rate-limit unauthenticated access to mission endpoints."
      ]
    },
    fixPrompt:
      "Our site mirrors HackThisSite-style mission challenges. Show how to isolate wargame VMs from production infrastructure.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-cyberdefenders-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "CyberDefenders blue team cyber range platform disclosed",
    description:
      "CyberDefenders advertises hands-on blue team training, SOC analyst upskilling, and real-world cyber range investigations.",
    impactOneline:
      "Public cyber range platforms expose intentionally vulnerable investigation scenarios attackers use to calibrate scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCyberDefendersEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Cyber range labs are intentional — gate investigations behind paid accounts and isolate lab VMs.",
      steps: [
        "Require authentication before serving investigation lab instances.",
        "Isolate cyber range infrastructure from production networks.",
        "Monitor outbound traffic from lab environments."
      ]
    },
    fixPrompt:
      "We host CyberDefenders-style blue team cyber ranges. Show how to gate investigations behind auth and isolate lab VMs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-web-security-lab-zh-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Chinese Web Security Lab educational platform disclosed",
    description:
      "Web 安全实验室 documents browser-side XSS, CSRF, CSP, and same-origin educational experiments for public learning.",
    impactOneline:
      "Public educational labs expose injectable XSS/CSRF demos reusable as attack templates against real apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWebSecurityLabZhEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Educational labs are intentional — never reuse demo vulnerability patterns in production apps.",
      steps: [
        "Gate interactive lab chapters behind authentication when possible.",
        "Isolate lab environments from production networks.",
        "Add clear educational disclaimers and rate limits on demo endpoints."
      ]
    },
    fixPrompt:
      "We host a Chinese Web Security Lab with XSS/CSRF chapters. Show how to isolate educational demos from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-sectrainer-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "SecTrainer gamified OWASP training platform disclosed",
    description:
      "SecTrainer publishes interactive OWASP Top 10 modules with SQLi, XSS, IDOR, and CTF challenge labs in client bundles.",
    impactOneline:
      "Public training platforms expose intentionally vulnerable lab walkthroughs attackers use to tune scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSectrainerEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Training platforms are intentional — gate labs behind accounts and isolate from production.",
      steps: [
        "Require authentication before serving injectable lab modules.",
        "Never reuse SecTrainer-style vulnerable code snippets in production apps.",
        "Isolate training infrastructure from customer data."
      ]
    },
    fixPrompt:
      "We host SecTrainer-style gamified OWASP labs. Show how to gate modules behind auth and isolate lab VMs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hackadvisor-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "HackAdvisor real-world bug report CTF labs disclosed",
    description:
      "HackAdvisor Labs advertises browser-based challenges modeled on real-world bug reports and vulnerability writeups.",
    impactOneline:
      "Public CTF labs document exploitable patterns from real bug bounty reports reusable against production apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHackAdvisorLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Bug-report CTF labs are intentional — isolate challenge instances from production networks.",
      steps: [
        "Require lab start/auth before exposing challenge instances.",
        "Do not copy challenge vulnerability patterns into production code.",
        "Rate-limit unauthenticated challenge enumeration."
      ]
    },
    fixPrompt:
      "We host HackAdvisor-style real-world bug report CTFs. Show how to isolate challenge VMs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-agentic-ai-ctf-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "Agentic AI security CTF platform disclosed",
    description:
      "OWASP FinBot CTF advertises agentic AI exploit chains — prompt injection, tool abuse, and insecure agent namespaces.",
    impactOneline:
      "Public agentic AI CTFs document exploit patterns transferable to production LLM agents and tool routers.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAgenticAiCtfEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Agentic CTF platforms are intentional — isolate them from production agent infrastructure.",
      steps: [
        "Never reuse FinBot-style agent tool permissions in production.",
        "Gate CTF namespaces behind authentication.",
        "Monitor agent tool calls for prompt-injection exfiltration patterns."
      ]
    },
    fixPrompt:
      "We host an agentic AI CTF like OWASP FinBot. Show how to isolate agent namespaces from production LLM deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-security-writeup-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "Cybersecurity write-up blog with vulnerable code samples disclosed",
    description:
      "Security write-up blogs publish hands-on XSS/SQLi lab walkthroughs with copy-paste vulnerable innerHTML and query-string sink examples.",
    impactOneline:
      "Public write-up labs expose injectable sink patterns attackers reuse against production apps with similar code.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSecurityWriteupEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Write-up labs are intentional — never copy demo sink code into production applications.",
      steps: [
        "Host interactive lab demos on isolated training subdomains.",
        "Sanitize or encode all user input before assigning to innerHTML in production.",
        "Add clear educational disclaimers on write-up pages with live exploit samples."
      ]
    },
    fixPrompt:
      "We publish cybersecurity write-ups with embedded vulnerable code. Show how to keep demo sinks off production domains.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-north-star-agi-ctf-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "North Star AGI agentic CTF platform disclosed",
    description:
      "RoboTech Industries (ctb-pi) is an agentic AI CTF where players restore neural fragments hidden across pages for prompt-injection challenges.",
    impactOneline:
      "Agentic CTF platforms document prompt-injection and tool-abuse chains reusable against production AI agents.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideNorthStarAgiCtfEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Agentic CTF labs are intentional — isolate agent namespaces from production LLM deployments.",
      steps: [
        "Require authentication before exposing agentic challenge namespaces.",
        "Never deploy CTF neural-fragment puzzles on production corporate domains.",
        "Monitor agent tool calls for unauthorized prompt-injection attempts."
      ]
    },
    fixPrompt:
      "We host a North Star AGI-style agentic CTF. Show how to isolate RoboTech challenge agents from production AI systems.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-wrongsecrets-evidence",
    platform: "generic",
    category: "Exposed secret",
    severityDefault: "high",
    title: "OWASP WrongSecrets secrets-management CTF disclosed",
    description:
      "WrongSecrets challenges hide secrets in application code, Docker layers, Git history, and cloud configuration.",
    impactOneline:
      "Secrets-management CTFs mirror real misconfigurations — hardcoded keys, leaked env vars, and container secrets.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWrongSecretsEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "WrongSecrets challenges are intentional — ensure similar secrets never ship in production.",
      steps: [
        "Scan repos and containers for hardcoded secrets before deploy.",
        "Use secret managers instead of application.properties or env files in images.",
        "Rotate any secrets that appeared in Git history."
      ]
    },
    fixPrompt:
      "Our app mirrors OWASP WrongSecrets-style secret hiding. Show how to detect and remove secrets from code, Docker, and Git.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-maestro-agentic-ai-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "MAESTRO agentic AI security analysis demo disclosed",
    description:
      "MAESTRO Framework keynote demos document ElizaOS agent exploit chains — memory poisoning, zero-auth deployments, and RAG prompt injection.",
    impactOneline:
      "Public agentic AI security demos expose attack patterns transferable to production LLM agent deployments.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideMaestroAgenticAiEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Agent security demos are intentional — isolate demo agents from production infrastructure.",
      steps: [
        "Require authentication on all agent API endpoints.",
        "Sanitize and validate agent memory before RAG retrieval.",
        "Never log API keys or database URLs during agent startup."
      ]
    },
    fixPrompt:
      "We host a MAESTRO-style ElizaOS security demo. Show how to gate agent endpoints and prevent memory-poisoning prompt injection.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-zeroday-training-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "0day cybersecurity training platform disclosed",
    description:
      "0day advertises elite hands-on offensive security labs, network pentest courses, and web application security training.",
    impactOneline:
      "Public training platforms expose intentionally vulnerable lab environments for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideZerodayTrainingEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate training labs behind paid accounts; isolate lab VMs from production networks.",
      steps: [
        "Require authentication before serving injectable lab instances.",
        "Run labs on dedicated infrastructure with no production data.",
        "Monitor lab egress for abuse."
      ]
    },
    fixPrompt:
      "We host a 0day-style cybersecurity training platform with hands-on pentest labs. Show how to gate labs behind auth and isolate VMs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctf-research-team-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "CTF research team and vulnerability disclosure program disclosed",
    description:
      "Hidden Investigations-style sites publish CTF team branding, offensive security research, and community vulnerability disclosure programs.",
    impactOneline:
      "Public CTF research teams document exploit training surfaces and responsible disclosure workflows attackers study.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtfResearchTeamEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Research team sites are intentional — ensure CTF infrastructure never shares networks with production.",
      steps: [
        "Isolate CTF challenge VMs from corporate infrastructure.",
        "Do not reuse challenge vulnerability patterns in production code.",
        "Publish disclosure policies without exposing internal lab routes."
      ]
    },
    fixPrompt:
      "Our site is a public CTF research team like Hidden Investigations. Show how to isolate challenge infrastructure from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentester-academy-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Pentester Academy Lab challenge hub disclosed",
    description:
      "Pentester Academy Lab on Appspot links video-guided web hacking challenges covering SQL injection, XSS, and authentication bypass.",
    impactOneline:
      "Public Pentester Academy lab hubs expose intentionally vulnerable exercise endpoints for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterAcademyLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate lab VMs behind paid Pentester Academy accounts; isolate exercise infrastructure.",
      steps: [
        "Require authentication before serving injectable challenge instances.",
        "Run lab containers on dedicated infrastructure with no production data.",
        "Monitor lab egress for abuse."
      ]
    },
    fixPrompt:
      "We host Pentester Academy-style video lab challenges on Appspot. Show how to gate labs behind auth and isolate VMs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-cyber-scavenger-hunt-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "Cyber Scavenger Hunt recon lab disclosed",
    description:
      "Cyber Scavenger Hunt is an 8-step interactive lab teaching robots.txt enumeration, DevTools recon, and query-param privilege escalation.",
    impactOneline:
      "Public scavenger-hunt labs document recon and auth-bypass patterns attackers apply to real applications.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCyberScavengerHuntEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Scavenger hunt labs are intentional — ensure /admin and /robots.txt lessons never mirror production misconfigs.",
      steps: [
        "Do not leave debug console messages in production bundles.",
        "Block unauthenticated access to real admin routes regardless of query params.",
        "Review robots.txt for sensitive path disclosure."
      ]
    },
    fixPrompt:
      "Our site is a Cyber Scavenger Hunt-style recon lab. Show how to remove debug console leaks and harden admin routes against query-param bypass.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-skf-lab-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "medium",
    title: "Security Knowledge Framework (SKF) free labs disclosed",
    description:
      "SKF (secureby.design) publishes free Auth Bypass, SQLi, and XSS labs via lab-player webcomponents with OWASP ASVS write-ups.",
    impactOneline:
      "Public SKF lab catalogs expose injectable auth-bypass and injection exercises reachable without registration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSkfLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate SKF-style labs behind accounts; isolate lab-player instances from production networks.",
      steps: [
        "Require login before launching injectable lab-player environments.",
        "Run labs on dedicated subdomains with no production database access.",
        "Publish ASVS write-ups without exposing live lab infrastructure routes."
      ]
    },
    fixPrompt:
      "We host SKF-style free Auth Bypass labs on secureby.design. Show how to gate lab-player instances behind auth and isolate them from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-google-gruyere-codelab-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "Google Gruyere web security codelab disclosed",
    description:
      "Google Gruyere codelab documents intentionally vulnerable cheese-themed web app exercises covering XSS, SQL injection, XSRF, path traversal, and code execution.",
    impactOneline:
      "Public Gruyere codelabs expose classic web vulnerability patterns attackers use to tune automated scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideGoogleGruyereCodelabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gruyere instances are intentional — never deploy codelab code to production.",
      steps: [
        "Run Gruyere on isolated infrastructure with no production data.",
        "Do not expose codelab instances to the public internet without access controls.",
        "Use codelab findings to patch similar patterns in production code."
      ]
    },
    fixPrompt:
      "We host a Gruyere-style web security codelab. Show how to isolate it from production and fix XSS/SQLi patterns documented in the walkthrough.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-mutillidae-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "OWASP Mutillidae vulnerable lab disclosed",
    description:
      "Mutillidae documents deliberately vulnerable PHP routes for SQLi, HTML injection, command injection, and XSS under index.php?page= handlers.",
    impactOneline:
      "Public Mutillidae instances expose classic OWASP Top 10 injection and XSS challenge routes scannable without authentication.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideMutillidaeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Mutillidae is intentional training software — never deploy it on production networks.",
      steps: [
        "Run Mutillidae only in isolated lab VMs with no production data.",
        "Remove HTML comments that disclose database credentials from any forked code.",
        "Block public internet access to Mutillidae instances."
      ]
    },
    fixPrompt:
      "We host an OWASP Mutillidae lab. Show how to isolate it from production and remove credential hints from HTML comments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-peruggia-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "Peruggia vulnerable photo gallery lab disclosed",
    description:
      "Peruggia is a deliberately vulnerable PHP/MySQL image gallery designed as a safe environment to practice common web application attacks.",
    impactOneline:
      "Public Peruggia project pages document controlled SQLi, XSS, and file-upload vulnerabilities for scanner benchmarking.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePeruggiaEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Peruggia is intentional training software — never deploy it on production networks.",
      steps: [
        "Run Peruggia only in isolated lab VMs with no production data.",
        "Do not mirror Peruggia vulnerability patterns in production photo galleries.",
        "Block public internet access to Peruggia demo instances."
      ]
    },
    fixPrompt:
      "We reference the Peruggia vulnerable photo gallery for security training. Show how to isolate lab instances from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-bwapp-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "bWAPP deliberately insecure training app disclosed",
    description:
      "bWAPP (buggy web application) advertises 100+ web vulnerabilities spanning OWASP Top 10 injection, XSS, CSRF, and file inclusion flaws.",
    impactOneline:
      "Public bWAPP marketing pages document vulnerability taxonomy attackers use to tune scanners against PHP/MySQL labs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBwappEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "bWAPP is an intentional training application — keep installs offline from production.",
      steps: [
        "Install bWAPP only in local VMs (bee-box) or isolated containers.",
        "Do not expose bWAPP instances to the public internet.",
        "Use bWAPP findings to patch similar patterns in production PHP code."
      ]
    },
    fixPrompt:
      "Our site documents bWAPP-style deliberately insecure PHP exercises. Show how to keep lab installs isolated from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-bwapp-injection-catalog-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "bWAPP injection taxonomy catalog disclosed",
    description:
      "bWAPP bugs.htm documents SQL/HTML/LDAP injection, XSS, CSRF, XXE, and SSRF vulnerability categories across 100+ training exercises.",
    impactOneline:
      "Public bWAPP bug catalogs reveal full injection and XSS challenge taxonomy used to benchmark scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBwappInjectionCatalogEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "bWAPP is an intentional training application — keep installs offline from production.",
      steps: [
        "Install bWAPP only in local VMs (bee-box) or isolated containers.",
        "Do not expose bWAPP instances to the public internet.",
        "Use bWAPP taxonomy to patch similar patterns in production PHP code."
      ]
    },
    fixPrompt:
      "Our site documents bWAPP-style injection challenge catalogs. Show how to keep lab installs isolated from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-zero-bank-webinspect-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Fortify Zero Bank WebInspect training demo disclosed",
    description:
      "zero.webappsecurity.com is a Micro Focus Fortify WebInspect demo bank site intentionally published for practicing web vulnerability detection.",
    impactOneline:
      "Public Zero Bank training demos expose Fortify WebInspect benchmark surfaces scannable without authentication.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideZeroBankWebinspectEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Zero Bank is an intentional Fortify training demo — never deploy similar patterns to production.",
      steps: [
        "Run zero.webappsecurity.com only as an isolated scanner calibration target.",
        "Do not mirror Zero Bank login or transfer flows in production banking apps.",
        "Use WebInspect demo findings to tune DAST coverage, not as production code templates."
      ]
    },
    fixPrompt:
      "We host a Fortify WebInspect Zero Bank training demo. Show how to keep scanner calibration targets isolated from production banking systems.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-cs-training-academy-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "CS Training Academy vuln-app playbook disclosed",
    description:
      "Sports Media CS Training Academy publishes a curated cybersecurity playbook linking OWASP Juice Shop, WebGoat, DVWA, and LLM security labs.",
    impactOneline:
      "Public training playbooks index deliberately vulnerable lab deploys attackers use as scanner oracles.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCsTrainingAcademyEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Training playbooks should link to isolated lab instances, not production systems.",
      steps: [
        "Gate lab deploy links behind authenticated student portals.",
        "Do not embed live API keys in training hub bundles.",
        "Isolate linked vulnerable apps on separate infrastructure."
      ]
    },
    fixPrompt:
      "We publish a CS training academy playbook with links to vulnerable lab apps. Show how to gate lab URLs and remove secrets from bundles.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hackable-lab-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "medium",
    title: "hackable.so deliberately vulnerable social platform disclosed",
    description:
      "hackable.so advertises 12 hidden vulnerabilities across auth, admin panel, and social features with JWT stored in localStorage.",
    impactOneline:
      "Public hackable.so instances expose intentional auth bypass and admin routes scannable without registration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHackableSoLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "hackable.so is an intentional CTF platform — never deploy its patterns to production.",
      steps: [
        "Run hackable.so only as an isolated training environment.",
        "Do not store JWTs in localStorage on production apps.",
        "Require authentication before exposing /admin routes."
      ]
    },
    fixPrompt:
      "We host a hackable.so-style vulnerable social platform. Show how to gate admin routes and avoid localStorage JWT storage.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnweb-lab-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "VulnWeb educational vulnerability lab disclosed",
    description:
      "VulnWeb SPA documents intentionally vulnerable SQL injection, XSS, and IDOR modules for OWASP Top 10 training.",
    impactOneline:
      "Public VulnWeb labs expose unsanitized input handlers and IDOR routes documented in client bundles.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnwebLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "VulnWeb is intentional training software — never deploy lab code to production.",
      steps: [
        "Run VulnWeb only in isolated lab environments.",
        "Sanitize all user input before SQL queries and HTML rendering.",
        "Enforce authorization checks on profile/:id routes."
      ]
    },
    fixPrompt:
      "We host a VulnWeb-style educational lab with SQLi, XSS, and IDOR modules. Show how to fix unsanitized handlers.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacking-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Hacking-Lab cyber security training platform disclosed",
    description:
      "Hacking-Lab AG advertises cyber security training, CTF events, offensive/defensive skill assessments, and university lab programs.",
    impactOneline:
      "Public training platforms expose intentionally vulnerable lab environments for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHackingLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate Hacking-Lab instances behind authenticated accounts; isolate lab VMs from production.",
      steps: [
        "Require login before starting challenge instances.",
        "Run lab containers on dedicated infrastructure with no production data.",
        "Monitor lab egress for abuse."
      ]
    },
    fixPrompt:
      "We host Hacking-Lab-style cyber security training and CTF events. Show how to gate labs behind auth and isolate VMs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-solyd-training-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Solyd ethical hacking & pentest training disclosed",
    description:
      "Solyd publishes Introdução ao Hacking e Pentest 2.0 — a free Portuguese course covering ethical hacking and penetration testing fundamentals.",
    impactOneline:
      "Public training courses document hacking and pentest techniques reusable against production applications.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSolydTrainingEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Training courses are intentional — ensure lab exercises never share infrastructure with production.",
      steps: [
        "Gate hands-on lab VMs behind course enrollment.",
        "Do not copy course vulnerability patterns into production code.",
        "Isolate training environments from customer data."
      ]
    },
    fixPrompt:
      "We host Solyd-style ethical hacking and pentest training courses. Show how to isolate lab VMs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-cylab-academy-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "CyLab Security Academy / picoCTF platform disclosed",
    description:
      "picoCTF migrated to CyLab Security Academy — Carnegie Mellon University's free cybersecurity learning and CTF competition platform.",
    impactOneline:
      "Public CTF academies document exploit training surfaces and challenge patterns attackers study.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCylabAcademyEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CTF academies are intentional — isolate challenge infrastructure from production networks.",
      steps: [
        "Require authentication before serving challenge instances.",
        "Do not reuse CTF vulnerability patterns in production code.",
        "Rate-limit unauthenticated challenge enumeration."
      ]
    },
    fixPrompt:
      "Our site mirrors CyLab Security Academy / picoCTF-style CTF training. Show how to isolate challenge VMs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnerableapp-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "OWASP VulnerableApp scanner evaluation platform disclosed",
    description:
      "SasanLabs VulnerableApp is a deliberately vulnerable Spring application for benchmarking vulnerability scanners and security tools.",
    impactOneline:
      "Public VulnerableApp instances expose annotation-driven vulnerability modules and REST APIs for unauthenticated scanner evaluation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnerableappEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "VulnerableApp is intentional training software — never deploy to production or expose publicly.",
      steps: [
        "Run VulnerableApp only in isolated Docker containers on lab networks.",
        "Do not expose VulnerableApp REST APIs to the public internet.",
        "Use VulnerableApp findings to validate scanner rules, not as production patterns."
      ]
    },
    fixPrompt:
      "We host OWASP VulnerableApp for scanner benchmarking. Show how to keep it isolated in Docker lab environments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-rest-vulnweb-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Invicti Vulnerable REST API lab disclosed",
    description:
      "rest.vulnweb.com documents an intentionally vulnerable REST API with JWT, Basic, and OAuth2 authentication flaws for scanner benchmarking.",
    impactOneline:
      "Public Invicti REST API labs expose user data and comment endpoints without proper authorization checks.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideRestVulnwebEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "rest.vulnweb.com is an intentional Invicti benchmark — never deploy similar patterns to production.",
      steps: [
        "Run rest.vulnweb.com only as an isolated scanner evaluation target.",
        "Enforce authorization on all REST API routes in production.",
        "Validate JWT signatures and reject demo tokens in production APIs."
      ]
    },
    fixPrompt:
      "We host an Invicti-style vulnerable REST API lab. Show how to enforce JWT validation and authorization on API routes.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pwnshop-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Pwnshop OWASP Top 10 2025 e-commerce lab disclosed",
    description:
      "Pwnshop is an intentionally vulnerable e-commerce application with 51 documented web and AI/LLM security flaws aligned to OWASP Top 10 2025.",
    impactOneline:
      "Public Pwnshop instances expose a vulnerability catalog with IDOR, XSS, SQLi, and prompt-injection training endpoints.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePwnshopEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Pwnshop is intentional training software — never deploy similar patterns to production.",
      steps: [
        "Run Pwnshop only in isolated lab environments for scanner evaluation.",
        "Do not expose Pwnshop vulnerability endpoints to the public internet without access controls.",
        "Use Pwnshop findings to validate scanner coverage, not as production design patterns."
      ]
    },
    fixPrompt:
      "We host Pwnshop for OWASP Top 10 2025 scanner benchmarking. Show how to keep lab instances isolated from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnforge-academy-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "VulnForge Academy OWASP training platform disclosed",
    description:
      "VulnForge Academy offers 20 deliberately vulnerable levels covering OWASP Top 10, SQLi, XSS, IDOR, SSRF, and RCE with CTF-style flag capture.",
    impactOneline:
      "Public VulnForge instances document exploit training surfaces and gamified vulnerability progression.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnforgeAcademyEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "VulnForge Academy is intentional training software — isolate lab containers from production.",
      steps: [
        "Gate VulnForge lab instances behind invite-code registration.",
        "Run vulnerable levels in isolated containers with no production data.",
        "Do not copy VulnForge vulnerability patterns into production code."
      ]
    },
    fixPrompt:
      "We host VulnForge Academy-style OWASP training with 20 vulnerable levels. Show how to isolate lab containers from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-tegalsec-lab-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "TegalSec browser hacking CTF lab disclosed",
    description:
      "TegalSec publishes Hack the br0w and XSS Labs — browser-based CTF challenges teaching client-side exploitation via user-agent tricks and reflected XSS.",
    impactOneline:
      "Public TegalSec labs document browser hacking challenge patterns and XSS training surfaces for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideTegalsecLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "TegalSec labs are intentional training — isolate challenge instances from production networks.",
      steps: [
        "Run TegalSec CTF labs only on dedicated training infrastructure.",
        "Do not copy browser-hacking challenge patterns into production apps.",
        "Rate-limit unauthenticated challenge enumeration."
      ]
    },
    fixPrompt:
      "We host TegalSec-style browser hacking CTF labs. Show how to isolate challenge pages from production applications.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-bugbountyhunter-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "BugBountyHunter zseano challenge platform disclosed",
    description:
      "BugBountyHunter.com publishes zseano-style bug bounty challenge scenarios and member playground demos for XSS and web app vulnerability hunting.",
    impactOneline:
      "Public BugBountyHunter challenges document real-world bug bounty hunting scenarios attackers study.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBugBountyHunterEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "BugBountyHunter challenges are intentional training — gate active scenarios behind membership.",
      steps: [
        "Require authentication before serving live challenge instances.",
        "Do not expose production-like bug bounty scenarios without access controls.",
        "Monitor challenge endpoints for automated scanner abuse."
      ]
    },
    fixPrompt:
      "We host BugBountyHunter-style bug bounty challenge scenarios. Show how to gate live challenges behind auth.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-zero-health-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Zero Health intentionally vulnerable healthcare platform disclosed",
    description:
      "Zero Health is an educational healthcare security platform documenting JWT bypass, XSS, IDOR, and unsafe file upload flaws in medical technology contexts.",
    impactOneline:
      "Public Zero Health instances expose healthcare-themed vulnerability modules for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideZeroHealthEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Zero Health is intentional training software — never deploy healthcare lab patterns to production.",
      steps: [
        "Run Zero Health only in isolated Docker containers on lab networks.",
        "Enforce JWT validation and HIPAA-compliant access controls in production healthcare apps.",
        "Do not expose medical data APIs without authentication."
      ]
    },
    fixPrompt:
      "We host Zero Health-style intentionally vulnerable healthcare apps. Show how to enforce JWT validation and HIPAA access controls.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-alf-xss-wargame-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "alf.nu alert(1)-to-win XSS wargame disclosed",
    description:
      "Erling Ellingsen's alf.nu publishes alert(1)-to-win XSS challenges — exploit unsafe client-side code with the shortest payload to win.",
    impactOneline:
      "Public XSS wargame instances document reflected/DOM XSS exploitation patterns attackers practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAlfXssWargameEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "alf.nu XSS wargames are intentional training — do not expose production apps with similar unsafe sinks.",
      steps: [
        "Run XSS wargame challenges only on isolated lab infrastructure.",
        "Never deploy alert(1)-style unsafe eval/innerHTML patterns to production.",
        "Sanitize and encode all user-controlled output in HTML contexts."
      ]
    },
    fixPrompt:
      "We host alf.nu-style XSS wargame challenges. Show how to isolate unsafe code labs from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-llm-sec-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "LLM Security Labs OWASP Top 10 training platform disclosed",
    description:
      "TomAbai LLM Security Labs offers hands-on interactive modules covering OWASP Top 10 LLM vulnerabilities including prompt injection and data poisoning.",
    impactOneline:
      "Public LLM security lab instances document adversarial prompt and AI abuse training surfaces.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideLlmSecEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "LLM Security Labs are intentional training — gate AI red-team playgrounds behind authentication.",
      steps: [
        "Require authentication before serving live LLM attack labs.",
        "Do not expose production chatbots to unauthenticated prompt-injection probes.",
        "Monitor LLM endpoints for adversarial prompt patterns."
      ]
    },
    fixPrompt:
      "We host LLM Security Labs-style OWASP Top 10 LLM training. Show how to gate AI red-team labs behind auth.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-defendtheweb-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Defend the Web browser security challenge platform disclosed",
    description:
      "Defend the Web (DtW) was a long-running browser-based web security challenge platform for XSS, SQLi, and access-control drills.",
    impactOneline:
      "Historic Defend the Web deployments documented public security challenge surfaces for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideDefendthewebEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Defend the Web was intentional training software — isolate challenge instances from production networks.",
      steps: [
        "Run security challenge platforms only on dedicated lab infrastructure.",
        "Do not copy challenge vulnerability patterns into production applications.",
        "Gate archived challenge content behind authentication if re-hosted."
      ]
    },
    fixPrompt:
      "We host Defend the Web-style browser security challenges. Show how to isolate challenge apps from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-returntrue-wargame-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "returntrue.win return-true-to-win code-injection wargame disclosed",
    description:
      "Erling Ellingsen's returntrue.win publishes PHP/JS code-injection challenges where attackers craft function arguments that evaluate to true.",
    impactOneline:
      "Public return-true-to-win wargame instances document unsafe eval-style code injection patterns attackers practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideReturnTrueWargameEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "returntrue.win wargames are intentional training — never expose similar unsafe eval patterns in production.",
      steps: [
        "Run code-injection wargame challenges only on isolated lab infrastructure.",
        "Never pass user input into eval, assert, or dynamic code execution in production.",
        "Validate and sandbox any user-supplied expressions server-side."
      ]
    },
    fixPrompt:
      "We host returntrue.win-style code-injection wargames. Show how to isolate unsafe eval labs from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-authlab-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "medium",
    title: "DigiNinja Authentication Lab training platform disclosed",
    description:
      "DigiNinja Authentication Lab catalogs JWT, timing, client-side, and auth-bypass challenges for hands-on authentication security training.",
    impactOneline:
      "Public Authentication Lab instances document authentication vulnerability modules scannable without login.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAuthlabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Authentication Lab is intentional training software — isolate challenge instances from production networks.",
      steps: [
        "Run Authentication Lab only on dedicated lab infrastructure.",
        "Do not copy JWT-none or client-side XOR auth patterns into production.",
        "Gate archived challenge content behind authentication if re-hosted."
      ]
    },
    fixPrompt:
      "We host DigiNinja Authentication Lab-style JWT and auth-bypass challenges. Show how to isolate them from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-xss-quiz-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "yamagata21 XSS Challenges wargame disclosed",
    description:
      "yamagata21's XSS Challenges at xss-quiz.int21h.jp teach reflected and DOM XSS through staged PHP challenge levels.",
    impactOneline:
      "Public XSS quiz instances document staged XSS exploitation patterns for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideXssQuizEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "XSS Challenges wargame is intentional training — sanitize output and encode user input in production.",
      steps: [
        "Run XSS quiz challenges only on isolated lab infrastructure.",
        "Encode and sanitize all user-controlled output in HTML contexts.",
        "Use Content-Security-Policy to mitigate XSS in production apps."
      ]
    },
    fixPrompt:
      "We host yamagata21-style XSS quiz wargames. Show how to isolate reflected XSS labs from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctfchallenge-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "CTFChallenge UK web application hacking platform disclosed",
    description:
      "CTFChallenge UK publishes web application security puzzles with staged vulnerability flags covering XSS, SQLi, and access-control drills.",
    impactOneline:
      "Public CTFChallenge instances document web hacking challenge surfaces for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtfchallengeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CTFChallenge is intentional training — isolate challenge instances from production networks.",
      steps: [
        "Run CTF challenge platforms only on dedicated lab infrastructure.",
        "Require authentication before serving live challenge instances.",
        "Do not copy challenge vulnerability patterns into production applications."
      ]
    },
    fixPrompt:
      "We host CTFChallenge-style web app hacking puzzles. Show how to isolate challenge instances from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-exploit-education-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "Exploit Education buffer overflow VM labs disclosed",
    description:
      "Exploit Education provides Phoenix, Nebula, and Protostar virtual machines teaching buffer overflow, format string, and heap exploitation.",
    impactOneline:
      "Public Exploit Education docs catalog memory corruption lab modules attackers study for binary exploitation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideExploitEducationEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Exploit Education VMs are intentional training — never expose memory corruption labs to the public internet.",
      steps: [
        "Run Phoenix/Nebula/Protostar VMs only on isolated lab networks.",
        "Enable stack canaries, ASLR, and NX in production binaries.",
        "Do not deploy intentionally vulnerable native binaries to production hosts."
      ]
    },
    fixPrompt:
      "We host Exploit Education-style buffer overflow VM labs. Show how to isolate native exploitation training from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-yogsec-xss-labs-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "yogsec XSS Labs interactive training platform disclosed",
    description:
      "yogsec XSS Labs publishes 39 browser-side reflected, stored, and DOM XSS exercises for bug bounty and penetration testing practice.",
    impactOneline:
      "Public yogsec XSS Labs document client-side XSS simulation modules attackers use to practice filter bypasses.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideYogsecXssLabsEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "yogsec XSS Labs are intentional training — isolate lab pages from production applications.",
      steps: [
        "Run XSS training labs only on dedicated lab infrastructure.",
        "Encode and sanitize all user-controlled output in HTML contexts.",
        "Use Content-Security-Policy to mitigate XSS in production apps."
      ]
    },
    fixPrompt:
      "We host yogsec-style XSS training labs. Show how to isolate reflected and DOM XSS exercises from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacker101-ctf-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Hacker101 CTF web security challenge platform disclosed",
    description:
      "Hacker101 CTF is HackerOne's public capture-the-flag game teaching web hacking in a safe environment with staged vulnerability flags.",
    impactOneline:
      "Public Hacker101 CTF instances document web security challenge surfaces for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacker101CtfEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacker101 CTF is intentional training — isolate challenge instances from production networks.",
      steps: [
        "Run CTF challenge platforms only on dedicated lab infrastructure.",
        "Require authentication before serving live challenge instances.",
        "Do not copy challenge vulnerability patterns into production applications."
      ]
    },
    fixPrompt:
      "We host Hacker101-style CTF challenges. Show how to isolate web security challenge instances from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-sockettome-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "DigiNinja SocketToMe WebSocket security lab disclosed",
    description:
      "SocketToMe is DigiNinja's public WebSocket fuzzing and chat game lab for socket security testing and message protocol abuse.",
    impactOneline:
      "Public SocketToMe instances expose WebSocket endpoints suitable for fuzzing and protocol manipulation drills.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSockettomeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "SocketToMe is intentional training — never expose unauthenticated WebSocket labs to production traffic.",
      steps: [
        "Run WebSocket security labs only on isolated lab networks.",
        "Validate and sanitize all WebSocket message payloads server-side.",
        "Require authentication before exposing interactive socket endpoints."
      ]
    },
    fixPrompt:
      "We host SocketToMe-style WebSocket security labs. Show how to isolate socket fuzzing exercises from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-owasp-bricks-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "OWASP Bricks web security learning platform disclosed",
    description:
      "OWASP Bricks documentation catalogs PHP login, content-page, and file-upload injection labs with SQL injection walkthroughs and arbitrary upload backdoor scenarios.",
    impactOneline:
      "Public OWASP Bricks docs expose injectable login and content-page oracles attackers use to practice SQLi and file-upload exploitation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOwaspBricksEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "OWASP Bricks is intentional training — run only on isolated lab VMs, not production hosts.",
      steps: [
        "Deploy Bricks only on dedicated lab infrastructure behind authentication.",
        "Use parameterized queries and input validation in production login forms.",
        "Restrict file uploads to safe types and scan content server-side."
      ]
    },
    fixPrompt:
      "We host OWASP Bricks-style PHP injection labs. Show how to isolate SQLi and file-upload training from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-fvb-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "First Vulnerable Bank API security lab disclosed",
    description:
      "FVB GitBook walkthroughs document BOLA/IDOR and authentication-bypass flaws in a deliberately vulnerable REST banking API.",
    impactOneline:
      "Public FVB docs expose injectable object-ID and auth-bypass oracles attackers use to practice OWASP API Top 10 exploitation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideFvbLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "FVB is intentional training — run only on isolated lab infrastructure, not production APIs.",
      steps: [
        "Enforce object-level authorization on every API route that accepts user or account identifiers.",
        "Apply authentication middleware consistently across all protected endpoints.",
        "Host API security labs only on dedicated training networks."
      ]
    },
    fixPrompt:
      "We host First Vulnerable Bank-style API security labs. Show how to enforce BOLA checks and auth middleware on REST routes.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vaultapp-lab-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "medium",
    title: "VaultApp finance security training lab disclosed",
    description:
      "VaultApp Omega publishes a Secure Personal Finance Portal security training lab with demo credentials displayed on the public login page.",
    impactOneline:
      "Public VaultApp training instances disclose demo login credentials and finance-app attack surface for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVaultappLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "VaultApp training labs must not expose demo credentials on public login pages.",
      steps: [
        "Remove hardcoded test credentials from production-facing login UIs.",
        "Run security training apps only on isolated lab infrastructure.",
        "Require authentication before exposing finance portal functionality."
      ]
    },
    fixPrompt:
      "We host VaultApp-style finance security training labs. Show how to remove demo credentials from public login pages.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-damn-vulnerable-bank-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Damn Vulnerable Bank Android security lab disclosed",
    description:
      "Damn Vulnerable Bank is an intentionally vulnerable Android banking application with public documentation covering REST API flaws, sensitive data disclosure, and exported activity exploits.",
    impactOneline:
      "Public DVB docs catalog mobile banking vulnerability modules attackers study for Android API and data exposure attacks.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideDamnVulnerableBankEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Damn Vulnerable Bank is intentional training — never ship vulnerable Android builds to app stores.",
      steps: [
        "Run mobile security labs only on emulators in isolated environments.",
        "Validate REST API authorization on every endpoint in production apps.",
        "Restrict exported Android activities and protect sensitive data at rest."
      ]
    },
    fixPrompt:
      "We host Damn Vulnerable Bank-style Android security labs. Show how to isolate mobile exploit training from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnlab-academy-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "VulnLab Academy pentest training platform disclosed",
    description:
      "VulnLab Academy (Pentest Toolkit) publishes labeled OWASP Top 10 labs with reflected XSS, SQLi error, IDOR modules, unprotected admin portals, and HTML comment secrets for scanner validation.",
    impactOneline:
      "Public VulnLab Academy instances expose tiered injection and access-control labs plus staging secrets in page source.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnlabAcademyEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "VulnLab Academy is intentional training — isolate lab hubs from production networks.",
      steps: [
        "Deploy pentest training sites only on dedicated lab infrastructure.",
        "Remove HTML comment secrets and staging credentials from crawlable pages.",
        "Protect admin portals with authentication even in training environments."
      ]
    },
    fixPrompt:
      "We host VulnLab Academy-style pentest training labs. Show how to isolate labeled OWASP labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnerable-web-site-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Vulnerable Web Site CSRF/XSS/SSRF lab disclosed",
    description:
      "megmogmog1965/vulnerable-web-site is a Next.js demo reproducing CSRF, clickjacking, stored XSS, and optional SSRF vulnerabilities for security testing practice.",
    impactOneline:
      "Public Vulnerable Web Site deploys advertise a multi-category web vulnerability reproduction lab for unauthenticated discovery.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnerableWebSiteEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Vulnerable Web Site is intentional training — never deploy CSRF/XSS demo patterns to production.",
      steps: [
        "Run vulnerability reproduction labs only on isolated infrastructure.",
        "Implement CSRF tokens on all state-changing forms in production.",
        "Set X-Frame-Options or CSP frame-ancestors to prevent clickjacking."
      ]
    },
    fixPrompt:
      "We host Vulnerable Web Site-style CSRF and XSS reproduction labs. Show how to isolate them from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-nivara-security-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "Nivara security assessment platform disclosed",
    description:
      "Nivara publishes an automated external security assessment platform that maps attack surfaces and tests endpoints for modern companies.",
    impactOneline:
      "Public Nivara demo instances disclose a security assessment SaaS attack surface suitable for reconnaissance drills.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideNivaraSecurityEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Security assessment platform demos should not expose production customer data or unauthenticated scan APIs.",
      steps: [
        "Require authentication before exposing assessment dashboards.",
        "Isolate demo tenants from production scan infrastructure.",
        "Restrict API endpoints that trigger external scanning to authorized users."
      ]
    },
    fixPrompt:
      "We host Nivara-style security assessment platform demos. Show how to protect scan APIs and customer data.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-eks-goat-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "OWASP EKS Goat cloud security masterclass disclosed",
    description:
      "OWASP EKS Goat documents vulnerable AWS EKS cluster deployment, exploitation walkthroughs, and defense with Kyverno, GuardDuty, and eBPF Tetragon.",
    impactOneline:
      "Public EKS Goat guides expose cloud-native attack paths and misconfigurations reusable against production Kubernetes clusters.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideEksGoatEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "EKS Goat labs are intentional — isolate vulnerable clusters from production AWS accounts.",
      steps: [
        "Run EKS Goat only in dedicated sandbox AWS accounts.",
        "Enable GuardDuty and Kyverno policies on production EKS clusters.",
        "Restrict IAM roles and pod service accounts per least privilege."
      ]
    },
    fixPrompt:
      "We host OWASP EKS Goat cloud security training. Show how to isolate vulnerable EKS lab clusters from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctflearn-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "CTFlearn beginner CTF platform disclosed",
    description:
      "CTFlearn advertises hundreds of beginner-friendly web security CTF challenges for learning injection, XSS, and reconnaissance.",
    impactOneline:
      "Public CTFlearn instances document exploit training surfaces attackers study before targeting production apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtflearnEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CTFlearn is intentional training — isolate challenge infrastructure from production networks.",
      steps: [
        "Require authentication before serving challenge instances.",
        "Do not reuse CTF vulnerability patterns in production code.",
        "Rate-limit unauthenticated challenge enumeration."
      ]
    },
    fixPrompt:
      "We host CTFlearn-style beginner CTF challenges. Show how to isolate challenge VMs from production networks.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-cybench-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Cybench LLM cybersecurity CTF benchmark disclosed",
    description:
      "Cybench evaluates language models on professional Capture the Flag tasks spanning web exploitation, crypto, and binary analysis.",
    impactOneline:
      "Public Cybench indexes document CTF challenge categories and exploit patterns used to benchmark AI security capabilities.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCybenchEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Cybench is a research benchmark — isolate CTF task environments from production networks.",
      steps: [
        "Run Cybench CTF tasks only in isolated lab environments.",
        "Do not expose benchmark challenge instances without authentication.",
        "Treat published CTF writeups as training material, not production patterns."
      ]
    },
    fixPrompt:
      "We host Cybench-style LLM cybersecurity CTF benchmarks. Show how to isolate challenge VMs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "html-comment-credential-disclosure",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "high",
    title: "Database or admin credentials in HTML comment",
    description:
      "Page source contains an HTML comment disclosing database passwords, admin credentials, or SECRET staging keys readable by anyone viewing source.",
    impactOneline:
      "Credential hints in HTML comments leak secrets to unauthenticated visitors and search engine caches.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "htmlCommentCredentialDisclosure" },
    tierRequired: "deep",
    remediation: {
      summary: "Remove credential hints from HTML comments and rotate any disclosed secrets.",
      steps: [
        "Delete HTML comments containing passwords or connection strings.",
        "Rotate database credentials if they were ever committed to HTML.",
        "Use server-side config files outside the web root for secrets."
      ]
    },
    fixPrompt:
      "Our HTML includes a comment with database password hints. Show how to remove it and rotate credentials safely.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-w3challs-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "W3Challs offensive security challenge platform disclosed",
    description:
      "W3Challs advertises realistic web hacking, pwnable, reversing, and crypto wargame challenges without simulated scoring.",
    impactOneline:
      "Public W3Challs instances document exploit training surfaces attackers study before targeting production apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideW3challsEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "W3Challs is intentional training — isolate challenge VMs from production networks.",
      steps: [
        "Require authentication before serving challenge instances.",
        "Do not reuse CTF vulnerability patterns in production code.",
        "Rate-limit unauthenticated challenge enumeration."
      ]
    },
    fixPrompt:
      "We host W3Challs-style offensive security challenges. Show how to isolate challenge VMs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-intercode-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "InterCode interactive coding security benchmark disclosed",
    description:
      "InterCode benchmarks agents on interactive coding tasks across IC-CTF, IC-SQL, IC-Bash, and terminal environments.",
    impactOneline:
      "Public InterCode indexes document CTF and shell exploit patterns used to benchmark AI security capabilities.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideIntercodeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "InterCode is a research benchmark — isolate challenge environments from production networks.",
      steps: [
        "Run InterCode tasks only in isolated lab environments.",
        "Do not expose benchmark challenge instances without authentication.",
        "Treat published CTF writeups as training material, not production patterns."
      ]
    },
    fixPrompt:
      "We host InterCode-style interactive coding security benchmarks. Show how to isolate challenge VMs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnerable-qa-lab-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "Intentional scanner QA vulnerable lab disclosed",
    description:
      "RS Vulnerable Lab publishes intentional scanner QA signals — exposed admin paths, fake credentials, skimmer demos, and confidential file listings.",
    impactOneline:
      "Public QA honeypots catalog misconfiguration patterns scanners flag — similar signals in production indicate real exposure.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnerableQaLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "QA labs are intentional — do not deploy scanner honeypot patterns on production domains.",
      steps: [
        "Remove exposed /admin, /backup, and /.git paths from production apps.",
        "Block public access to .env, phpinfo.php, and confidential directories.",
        "Run scanner QA labs only on isolated test domains."
      ]
    },
    fixPrompt:
      "Our site mirrors an intentional scanner QA lab with exposed paths and fake credentials. Show how to harden production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-mlastg-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "MLASTG MLSec security testing guide disclosed",
    description:
      "MLASTG publishes ML/LLM security testing controls mapped to MITRE ATLAS, NIST AI RMF, and OWASP AI guidance with executable harnesses.",
    impactOneline:
      "Public MLASTG instances document adversarial ML and prompt-injection test cases attackers study before targeting production AI systems.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideMlastgEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "MLASTG is intentional training documentation — isolate ML security labs from production networks.",
      steps: [
        "Run MLASTG harnesses only in isolated lab environments.",
        "Do not expose production ML endpoints to unauthenticated adversarial probes.",
        "Treat published prompt-injection patterns as training material, not production patterns."
      ]
    },
    fixPrompt:
      "We host MLASTG-style ML security testing documentation. Show how to isolate adversarial ML labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-cryptohack-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "CryptoHack cryptography CTF platform disclosed",
    description:
      "CryptoHack advertises interactive cryptography challenges for learning cipher weaknesses through puzzles and leaderboard competition.",
    impactOneline:
      "Public CryptoHack instances document cryptographic exploit training surfaces used to practice breaking insecure implementations.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCryptohackEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CryptoHack is intentional training — isolate CTF challenge infrastructure from production networks.",
      steps: [
        "Require authentication before serving challenge instances.",
        "Do not reuse CTF cryptographic vulnerability patterns in production code.",
        "Rate-limit unauthenticated challenge enumeration."
      ]
    },
    fixPrompt:
      "We host CryptoHack-style cryptography CTF challenges. Show how to isolate challenge VMs from production networks.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-webgoat-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "OWASP WebGoat deliberately insecure training app disclosed",
    description:
      "OWASP WebGoat is a deliberately insecure Java application with guided lessons covering injection, auth, and access-control flaws.",
    impactOneline:
      "Public WebGoat instances document intentional vulnerability patterns used for security training and lesson walkthroughs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWebgoatEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "WebGoat is intentional training software — never deploy to production networks.",
      steps: [
        "Run WebGoat only in isolated Docker containers on lab networks.",
        "Do not expose WebGoat lesson endpoints to the public internet.",
        "Use WebGoat findings to validate scanner rules, not as production patterns."
      ]
    },
    fixPrompt:
      "We host OWASP WebGoat for security training. Show how to keep it isolated in Docker lab environments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-overthewire-natas-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "OverTheWire Natas web-security wargame disclosed",
    description:
      "OverTheWire Natas teaches serverside web vulnerabilities across staged challenge sites at natas.labs.overthewire.org.",
    impactOneline:
      "Public Natas wargame instances document web injection and access-control exploit patterns used for security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOverthewireNatasEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Natas is intentional training — isolate wargame VMs from production networks.",
      steps: [
        "Require authentication before serving challenge instances.",
        "Do not reuse Natas vulnerability patterns in production code.",
        "Rate-limit unauthenticated wargame enumeration."
      ]
    },
    fixPrompt:
      "We host OverTheWire Natas-style web security wargames. Show how to isolate challenge VMs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-overthewire-natas-referer-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Natas HTTP Referer guard bypass disclosed",
    description:
      "OverTheWire Natas challenge pages expose weak HTTP Referer checks — Access disallowed unless Referer matches an authorized host.",
    impactOneline:
      "Natas referer-guard pages document header-spoofing bypass patterns reusable against production access controls.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOverthewireNatasRefererEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never rely on Referer alone for access control — use server-side session auth.",
      steps: [
        "Validate authenticated sessions instead of client-supplied Referer headers.",
        "Do not expose referer-guard bypass patterns on public marketing pages.",
        "Rate-limit unauthenticated wargame enumeration."
      ]
    },
    fixPrompt:
      "Our Natas-style lab exposes HTTP Referer guards. Show how to replace Referer checks with proper session authorization.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-overthewire-leviathan-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "OverTheWire Leviathan wargame disclosed",
    description:
      "OverTheWire Leviathan teaches SSH privilege-escalation challenges on leviathan.labs.overthewire.org:2223 with level passwords stored in /etc/leviathan_pass.",
    impactOneline:
      "Public Leviathan wargame pages expose challenge structure and default leviathan0 credentials used to bootstrap the training chain.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOverthewireLeviathanEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "OverTheWire Leviathan is intentional training — isolate wargame VMs from production networks.",
      steps: [
        "Run Leviathan challenges only on dedicated training VMs with no production access.",
        "Rotate default wargame credentials if mirroring challenges internally.",
        "Do not copy password-file privilege patterns into production systems."
      ]
    },
    fixPrompt:
      "We host OverTheWire-style privilege escalation labs. Show how to isolate wargame instances from production infrastructure.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ffufme-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "FFUF.me fuzzing practice lab disclosed",
    description:
      "FFUF.me advertises a live playground to practice ffuf directory, parameter, and vhost fuzzing against intentional targets.",
    impactOneline:
      "Public FFUF.me instances document web fuzzing exploit training surfaces for directory and parameter discovery practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideFfufMeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "FFUF.me is intentional training — isolate fuzzing practice infrastructure from production networks.",
      steps: [
        "Require authentication before serving fuzzing practice targets.",
        "Do not reuse FFUF.me discovery patterns against production without authorization.",
        "Rate-limit unauthenticated fuzzing lab enumeration."
      ]
    },
    fixPrompt:
      "We host FFUF.me-style fuzzing practice labs. Show how to isolate training targets from production networks.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-yrprey-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "YRprey vulnerability testing framework disclosed",
    description:
      "YRprey advertises a deliberate vulnerability testing framework for security professionals and pentesters.",
    impactOneline:
      "Public YRprey instances document intentional security flaw training surfaces for vulnerability identification practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideYrpreyEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "YRprey is intentional training — isolate vulnerability testing frameworks from production networks.",
      steps: [
        "Require authentication before serving the testing framework.",
        "Do not deploy YRprey-style intentional flaws in production environments.",
        "Rate-limit unauthenticated framework enumeration."
      ]
    },
    fixPrompt:
      "We host YRprey-style vulnerability testing frameworks. Show how to isolate training apps from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-berger-cyber-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "BergerZvika Secure Programming Cyber-Lab disclosed",
    description:
      "BergerZvika Cyber-Lab publishes static HTML labs for integer overflow, race conditions, and prompt injection training.",
    impactOneline:
      "Public Cyber-Lab instances document secure-programming vulnerability patterns used in classroom and self-paced training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBergerCyberLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Cyber-Lab is intentional training — isolate lab pages from production networks.",
      steps: [
        "Require authentication before serving interactive lab modules.",
        "Do not reuse integer overflow or prompt injection demo patterns in production code.",
        "Rate-limit unauthenticated lab enumeration."
      ]
    },
    fixPrompt:
      "We host BergerZvika Cyber-Lab-style secure programming exercises. Show how to isolate lab HTML from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pwn-college-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "pwn.college cybersecurity dojo platform disclosed",
    description:
      "pwn.college hosts dojo-based exploit training modules covering Linux fundamentals, computing, and web/binary security challenges.",
    impactOneline:
      "Public pwn.college dojos expose exploit training surfaces attackers study before targeting production systems.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePwnCollegeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "pwn.college is intentional training — isolate dojo workspaces from production networks.",
      steps: [
        "Require authentication before launching challenge workspaces.",
        "Do not reuse dojo exploit patterns in production code.",
        "Rate-limit unauthenticated dojo enumeration."
      ]
    },
    fixPrompt:
      "We host pwn.college-style cybersecurity dojos. Show how to isolate challenge workspaces from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-react-dom-xss-lab-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "React DOM XSS AppSec comparison lab disclosed",
    description:
      "React DOM XSS labs compare vulnerable innerHTML rendering against DOMPurify-sanitized output with onerror/onfocus attack payloads.",
    impactOneline:
      "Public React XSS demos document DOM XSS attack patterns and sanitization bypass training surfaces.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideReactDomXssLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never render attacker-controlled HTML without sanitization; use DOMPurify or textContent.",
      steps: [
        "Replace dangerouslySetInnerHTML with textContent for user input.",
        "Sanitize HTML with DOMPurify before rendering untrusted content.",
        "Do not deploy XSS comparison labs on production domains."
      ]
    },
    fixPrompt:
      "Our React app has a DOM XSS lab comparing vulnerable vs DOMPurify-sanitized rendering. Show how to fix innerHTML sinks.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-owasp-genai-lab-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "OWASP GenAI Security Lab disclosed",
    description:
      "OWASP GenAI Security Lab publishes interactive lessons on LLM Top 10 risks including prompt injection and system prompt leakage.",
    impactOneline:
      "Public GenAI security labs document LLM abuse training surfaces for prompt injection and output-handling vulnerabilities.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOwaspGenaiLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "GenAI labs are intentional training — isolate LLM lesson apps from production agent deployments.",
      steps: [
        "Require authentication before serving interactive LLM vulnerability demos.",
        "Do not reuse prompt-injection lesson patterns in production chatbot system prompts.",
        "Rate-limit unauthenticated GenAI lab enumeration."
      ]
    },
    fixPrompt:
      "We host an OWASP GenAI Security Lab with prompt injection lessons. Show how to isolate LLM training apps from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctf-defi-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "CTF DeFi Security 101 workshop disclosed",
    description:
      "CTF DeFi Security 101 hosts wallet-connected smart-contract vulnerability challenges from the DeFi Security Summit workshop.",
    impactOneline:
      "Public DeFi CTF workshops document smart-contract exploit training surfaces attackers study before targeting production protocols.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtfDefiEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "DeFi CTF workshops are intentional training — isolate challenge contracts from production networks.",
      steps: [
        "Require authentication before launching wallet-connected CTF challenges.",
        "Do not deploy workshop vulnerability patterns on mainnet contracts.",
        "Rate-limit unauthenticated DeFi CTF enumeration."
      ]
    },
    fixPrompt:
      "We host a CTF DeFi Security 101 workshop with wallet play mode. Show how to isolate challenge contracts from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-atlas-crew-inferno-lab-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "Atlas Crew Inferno Lab security testing platform disclosed",
    description:
      "Apparatus and Crucible docs advertise AI red-team automation, Nuclei scanning, chaos engineering, and 80+ pass/fail attack scenarios for security testing labs.",
    impactOneline:
      "Public Inferno Lab documentation exposes deployable offensive security tooling attackers can mirror against reachable instances.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAtlasCrewInfernoLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Keep Apparatus/Crucible lab deployments on isolated networks — docs are intentional but instances must not face production.",
      steps: [
        "Require authentication before launching red-team or chaos scenarios.",
        "Do not expose Apparatus/Crucible admin dashboards to the public internet.",
        "Segment inferno lab subnets from production VPCs."
      ]
    },
    fixPrompt:
      "We document Atlas Crew Apparatus and Crucible security testing platforms. Show how to keep lab deployments isolated from production networks.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-atlas-crew-edge-protection-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "Atlas Crew Horizon + Synapse edge protection platform disclosed",
    description:
      "Horizon and Synapse docs describe fleet-aware WAF, inline DLP, behavioral profiling, and progressive bot interrogation challenges at the edge.",
    impactOneline:
      "Public edge-protection documentation reveals WAF bypass research targets and demo deployments attackers can probe for misconfigurations.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAtlasCrewEdgeProtectionEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate Horizon/Synapse demo instances and architecture docs behind authenticated lab access.",
      steps: [
        "Do not expose horizon-demo.atlascrew.dev without IP allowlisting.",
        "Keep Synapse interrogator challenge configs off public documentation indexes.",
        "Segment edge-protection lab fleets from production API gateways."
      ]
    },
    fixPrompt:
      "We host Atlas Crew Horizon and Synapse edge protection docs with demo deployments. Show how to restrict public access to lab instances.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-owasp-vwad-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "OWASP Vulnerable Web Applications Directory disclosed",
    description:
      "OWASP VWAD indexes 200+ deliberately vulnerable web and mobile applications with per-app detail pages linking to live training instances.",
    impactOneline:
      "Public VWAD registry maps legal security testing targets — attackers harvest linked lab URLs for unauthenticated vulnerability practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOwaspVwadEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "VWAD is an intentional directory — lab operators should monitor listed instances for abuse and keep them isolated.",
      steps: [
        "Rate-limit unauthenticated enumeration of VWAD-linked lab instances.",
        "Require authentication on training apps listed in VWAD when exposed publicly.",
        "Monitor VWAD-listed URLs for scanner and exploit traffic spikes."
      ]
    },
    fixPrompt:
      "Our app is listed in OWASP VWAD. Show how to keep intentionally vulnerable training instances isolated and monitor for abuse.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-atlas-crew-hub-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "Atlas Crew security platform portfolio hub disclosed",
    description:
      "atlascrew.dev catalogs Synapse, Chimera, Crucible, and Apparatus open-source security platforms with links to live lab subdomains.",
    impactOneline:
      "Public security portfolio hub maps reachable offensive-security lab instances attackers can enumerate.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAtlasCrewHubEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate lab subdomains behind auth; portfolio pages are marketing but lab instances must stay isolated.",
      steps: [
        "Require authentication on chimera/synapse/crucible/apparatus lab deployments.",
        "IP-allowlist horizon-demo.atlascrew.dev and similar live demos.",
        "Monitor linked subdomains for unauthenticated scanner traffic."
      ]
    },
    fixPrompt:
      "Our atlascrew.dev hub links to Synapse/Chimera/Crucible lab subdomains. Show how to restrict public access to demo instances.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-mcp-supply-chain-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "high",
    title: "MCP supply-chain security demo with attack pack catalog disclosed",
    description:
      "Reef MCP registry documents signed MCP server supply chains, Anthropic MCP RCE blocking, OWASP Agentic ASI mappings, and DAST-A attack packs.",
    impactOneline:
      "Public MCP security demo reveals attack pack IDs and supply-chain bypass techniques useful for red-team enumeration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideMcpSupplyChainEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Keep MCP registry demos on isolated networks; attack pack catalogs are intentional but instances need auth.",
      steps: [
        "Require authentication before MCP bind demos and /api/summarize attack playground.",
        "Do not expose policy-bus admin tokens in client bundles.",
        "Segment MCP registry control-plane from production agent fleets."
      ]
    },
    fixPrompt:
      "We host a public Reef MCP registry demo with MCP-RCE-26.04 attack packs. Show how to auth-gate the demo API and isolate control-plane endpoints.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-seclab-playground-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "SecLab web vulnerability playground disclosed",
    description:
      "SecLab advertises hands-on XSS, SQL injection, CSRF, and IDOR demos with CWE-tagged vulnerability lab cards.",
    impactOneline:
      "Public SecLab instances expose intentionally vulnerable web security training surfaces for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSecLabPlaygroundEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate SecLab demos behind auth; training labs must stay isolated from production.",
      steps: [
        "Require authentication before serving /xss, /sqli, /csrf, and /idor lab routes.",
        "Run SecLab on dedicated infrastructure with no production data.",
        "Monitor lab egress for abuse."
      ]
    },
    fixPrompt:
      "We host SecLab-style XSS/SQLi/CSRF/IDOR vulnerability playgrounds. Show how to gate labs behind auth and isolate VMs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-mcp-sherpa-workshop-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "high",
    title: "Microsoft Sherpa MCP security workshop disclosed",
    description:
      "Sherpa MCP Security Summit workshop documents intentionally vulnerable MCP servers, prompt-injection defense, and OWASP MCP Azure security camps.",
    impactOneline:
      "Public MCP security workshop catalogs exploit→fix methodology and vulnerable MCP server camps attackers can enumerate.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideMcpSherpaWorkshopEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Keep Sherpa workshop MCP servers on isolated Azure sandboxes; camps are intentional but need auth.",
      steps: [
        "Require Entra ID authentication on workshop MCP endpoints.",
        "Do not expose camp vulnerable servers without network isolation.",
        "Apply Azure AI Content Safety on all MCP I/O paths."
      ]
    },
    fixPrompt:
      "We host a public Sherpa MCP Security Summit workshop with intentionally vulnerable MCP camps. Show how to auth-gate and isolate camp servers.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-brokencrystals-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Broken Crystals intentionally vulnerable API lab disclosed",
    description:
      "Broken Crystals (NeuraLegion) advertises a vulnerable crystal marketplace with OWASP API Top 10 flaws, SSRF /api/goto, and dangerous HTML sinks.",
    impactOneline:
      "Public Broken Crystals instances expose scanner-benchmark API routes, GraphQL, and client-side XSS training surfaces.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBrokencrystalsEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Broken Crystals is an intentional API security benchmark — never deploy similar patterns to production.",
      steps: [
        "Run Broken Crystals only on isolated scanner evaluation infrastructure.",
        "Do not expose /api/goto SSRF or unauthenticated admin routes in production.",
        "Remove dangerous-html sinks and client-side secret storage from production bundles."
      ]
    },
    fixPrompt:
      "We host a Broken Crystals-style API security benchmark. Show how to isolate it from production and fix SSRF/XSS patterns.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-skillaudit-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "SkillAudit MCP skill safety scanner disclosed",
    description:
      "SkillAudit scans MCP skills and agent tool definitions for credential theft, data exfiltration, prompt injection, and reverse shells.",
    impactOneline:
      "Public MCP skill scanners document agentic attack surfaces attackers use to evaluate AI tool supply chains.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSkillauditEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "MCP skill scanners are intentional — vet third-party skills before installing in production agents.",
      steps: [
        "Scan MCP skills in CI before publishing to agent marketplaces.",
        "Never install unaudited skills with filesystem or network tool access.",
        "Isolate agent runtimes from production credentials."
      ]
    },
    fixPrompt:
      "We host SkillAudit-style MCP skill scanning. Show how to gate skill installs and isolate agent credentials.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-secresearchlab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Sec Research Lab interactive cybersecurity training disclosed",
    description:
      "Sec Research Lab publishes browser-based SQL injection, XSS, SSRF, and JWT labs with OWASP Top 10 walkthroughs.",
    impactOneline:
      "Public Sec Research Lab instances document hands-on vulnerability training modules reachable without local setup.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSecResearchLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Sec Research Lab is intentional training — gate interactive labs behind authentication.",
      steps: [
        "Require login before launching in-browser SQLi/XSS/SSRF modules.",
        "Run labs on isolated subdomains with no production data.",
        "Rate-limit unauthenticated lab enumeration."
      ]
    },
    fixPrompt:
      "We host Sec Research Lab-style interactive security training. Show how to auth-gate browser labs and isolate them from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-overthewire-bandit-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "medium",
    title: "OverTheWire Bandit beginner wargame disclosed",
    description:
      "OverTheWire Bandit teaches Unix/Linux basics via SSH challenges at bandit.labs.overthewire.org port 2220.",
    impactOneline:
      "Public Bandit documentation exposes SSH wargame credentials and level progression for security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOverthewireBanditEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Bandit is intentional training — SSH credentials are public by design for beginners.",
      steps: [
        "Do not reuse Bandit-style default credentials in production systems.",
        "Isolate wargame SSH hosts from corporate networks.",
        "Monitor for unauthorized scanning of training infrastructure."
      ]
    },
    fixPrompt:
      "We document OverTheWire Bandit wargame levels. Show how to keep training SSH hosts isolated from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vapi-api-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "vAPI OWASP API Top 10 exercise lab disclosed",
    description:
      "vAPI (Vulnerable Adversely Programmed Interface) is a self-hostable Laravel API lab that mimics OWASP API Top 10 scenarios with Postman exercises.",
    impactOneline:
      "Public vAPI instances document broken API authorization patterns attackers can replay against production REST APIs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVapiEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "vAPI is intentional API security training — never deploy similar broken-auth patterns to production.",
      steps: [
        "Run vAPI only on isolated lab infrastructure with no production data.",
        "Enforce object-level authorization on every API route in production.",
        "Remove vAPI Postman collection references from public marketing pages."
      ]
    },
    fixPrompt:
      "We host a vAPI-style OWASP API Top 10 exercise lab. Show how to isolate it and fix BOLA/BFLA on production APIs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-archon-training-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Archon cybersecurity engineering training path disclosed",
    description:
      "Archon publishes a Cybersecurity Engineering Path with OWASP Top 10 vulnerable/fixed code walkthroughs, pentesting modules, and offensive security curriculum.",
    impactOneline:
      "Public Archon docs expose hands-on security training content including OWASP vulnerability patterns for unauthenticated study.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideArchonTrainingEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Archon training docs are educational — gate interactive labs behind authentication.",
      steps: [
        "Require login before serving runnable vulnerable code samples.",
        "Keep OWASP walkthrough labs on isolated subdomains.",
        "Do not copy vulnerable code patterns from training docs into production apps."
      ]
    },
    fixPrompt:
      "We publish Archon-style OWASP Top 10 vulnerable/fixed code walkthroughs. Show how to auth-gate labs and isolate training from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "http-403-bypass-probe",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "HTTP 403 bypass via path normalization",
    description:
      "A protected admin or internal path returns 403 Forbidden, but path-normalization tricks (trailing slash, /./, ..;/, ;/) reach the resource without authentication.",
    impactOneline:
      "Attackers bypass access controls using URL encoding or path normalization to reach admin-only routes.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "http403BypassProbe" },
    tierRequired: "free",
    remediation: {
      summary: "Normalize and canonicalize request paths before authorization checks.",
      steps: [
        "Reject or redirect ambiguous paths (trailing slash, dot segments, semicolon) before authz.",
        "Apply authorization on the canonical path, not the raw request URI.",
        "Return consistent 404 for unknown admin routes instead of distinguishable 403 responses."
      ]
    },
    fixPrompt:
      "Our /admin route returns 403 but /admin/ bypasses it. Show how to canonicalize paths before authorization and block normalization bypasses.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-devsecops-pipeline-visualizer-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "DevSecOps pipeline visualizer documents intentional vulnerability demos",
    description:
      "A DevSecOps CI/CD training SPA catalogs shift-left security stages with embedded hardcoded-secret, SQL injection, and OWASP Top 10 SAST demo code.",
    impactOneline:
      "Public DevSecOps visualizers expose intentional vulnerability patterns that attackers can study or replay on misconfigured production pipelines.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideDevsecopsPipelineVisualizerEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate interactive DevSecOps vulnerability demos behind authentication on isolated lab hosts.",
      steps: [
        "Do not ship training microservice code with hardcoded secrets to public CDNs.",
        "Run pipeline visualizer labs on dedicated subdomains with no production data.",
        "Replace inline SQLi demo snippets with sanitized pseudocode in public bundles."
      ]
    },
    fixPrompt:
      "Our DevSecOps visualizer bundle includes hardcoded-secret and SQLi demo code. Show how to gate the lab and sanitize public training assets.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-qamax-adversary-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "QAMax adversary hostile demo store disclosed",
    description:
      "Quality-Max qamax-adversary-site embeds 22+ intentional client-side attack vectors including CSRF form submission, cloud metadata SSRF probes, prototype pollution, and WebSocket internal scanning.",
    impactOneline:
      "Public QAMax adversary demos expose hostile client-side attack routines attackers can study for scanner red-team evaluation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideQamaxAdversaryEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "QAMax adversary stores are intentional scanner QA targets — never deploy attack-vector demos to production.",
      steps: [
        "Run QAMax adversary labs only on isolated Railway or lab hosts.",
        "Do not embed CSRF auto-submit forms or metadata SSRF links in production storefronts.",
        "Block client-side fetch/WebSocket probes to internal service hostnames in production apps."
      ]
    },
    fixPrompt:
      "We host a QAMax-style adversary demo store with embedded CSRF and SSRF attack vectors. Show how to isolate lab instances from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "Hacksplaining interactive OWASP secure-coding lessons disclosed",
    description:
      "Hacksplaining publishes 45+ free interactive secure-coding lessons covering OWASP Top 10 classics and AI-era threats with exploit-then-fix XSS, SQLi, CSRF, and prompt-injection walkthroughs.",
    impactOneline:
      "Public Hacksplaining lesson catalogs document vulnerability exploitation patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining is intentional training — gate team dashboards and live lesson progress behind authentication.",
      steps: [
        "Require login before serving runnable exploit lesson instances on private deployments.",
        "Do not copy Hacksplaining vulnerable code samples into production applications.",
        "Rate-limit unauthenticated lesson enumeration on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style OWASP Top 10 exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-portswigger-academy-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "PortSwigger Web Security Academy training hub disclosed",
    description:
      "PortSwigger Web Security Academy publishes free browser-based OWASP labs covering SQL injection, XSS, authentication, and access-control topics with guided learning paths.",
    impactOneline:
      "Public PortSwigger Academy hubs document vulnerability exploitation patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePortswiggerAcademyEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "PortSwigger Academy is intentional training — require accounts before serving live lab instances.",
      steps: [
        "Require login before launching browser-based exploit labs on private deployments.",
        "Do not copy PortSwigger vulnerable lab code into production applications.",
        "Rate-limit unauthenticated academy topic enumeration on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror PortSwigger Web Security Academy-style browser labs. Show how to auth-gate live lab instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-cyberdrill-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Cyber Drill attack simulator suite disclosed",
    description:
      "thecyberdrill.netlify.app hosts browser-based SQL injection, phishing awareness, and camera-hijack simulators with vulnerable query-string login checks.",
    impactOneline:
      "Public Cyber Drill tool pages document SQLi bypass payloads and insecure client-side authentication patterns for security awareness training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCyberDrillEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Cyber Drill simulators are intentional training — never copy insecure login checks into production.",
      steps: [
        "Run Cyber Drill attack simulators only on isolated training subdomains.",
        "Use parameterized queries instead of string-concatenated SQL in production authentication.",
        "Treat phishing and camera-hijack demos as awareness tools, not production features."
      ]
    },
    fixPrompt:
      "We embed Cyber Drill-style SQL injection simulators for training. Show how to keep demo login logic out of production authentication.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-deserialization-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "critical",
    title: "Unsafe deserialization educational lab disclosed",
    description:
      "sjefersuper.netlify.app documents Python pickle.loads and node-serialize gadget chains where __reduce__ and eval execute attacker-controlled payloads during deserialization.",
    impactOneline:
      "Public deserialization write-ups expose pickle and node-serialize RCE patterns attackers replay on apps that accept untrusted serialized objects.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideDeserializationEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never deserialize untrusted data with pickle or node-serialize — use signed JSON schemas instead.",
      steps: [
        "Reject user-controlled serialized blobs at API boundaries.",
        "Replace pickle.loads with versioned JSON schemas and strict validation.",
        "Audit dependencies for node-serialize and remove eval-based deserializers."
      ]
    },
    fixPrompt:
      "Our app accepts serialized session blobs. Show how to block pickle and node-serialize gadget chains that lead to RCE.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hackinghub-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "HackingHub ethical web application hacking platform disclosed",
    description:
      "HackingHub (ctfchallenge.com) offers training and challenges for ethical web application hacking with leaderboard, hackbox, and dashboard modules.",
    impactOneline:
      "Public HackingHub instances document web hacking challenge surfaces for unauthenticated CTF practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHackinghubEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "HackingHub is intentional CTF training — isolate challenge namespaces from production applications.",
      steps: [
        "Require authentication before serving live challenge instances.",
        "Run HackingHub challenge VMs on isolated lab infrastructure.",
        "Do not expose production-like hacking challenge endpoints without access controls."
      ]
    },
    fixPrompt:
      "We host HackingHub-style ethical web application hacking challenges. Show how to isolate CTF namespaces from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-unsecure-pwa-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "TempeHS Unsecure PWA educational lab disclosed",
    description:
      "The Unsecure PWA is an intentionally vulnerable progressive web app for HSC software engineering students to practice XSS, CSRF, authentication, and CSP testing in sandbox environments.",
    impactOneline:
      "Public Unsecure PWA documentation exposes educational vulnerability modules and security-testing guidance for unauthenticated lab discovery.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideUnsecurePwaEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Unsecure PWA is intentional coursework — never deploy the lab app outside isolated sandboxes.",
      steps: [
        "Run the Flask PWA only on localhost or containerized student sandboxes.",
        "Do not expose student_resources vulnerability walkthroughs on production domains.",
        "Gate live vulnerable app instances behind classroom authentication when self-hosting."
      ]
    },
    fixPrompt:
      "We host TempeHS Unsecure PWA coursework. Show how to keep the intentionally vulnerable Flask app isolated in student sandboxes only.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-promptmap-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "PromptMap LLM prompt-injection testing workbench disclosed",
    description:
      "PromptMap provides template and LLM generation modes for red-teaming chat models, with guided training sessions and dashboard workflows for prompt-injection evaluation.",
    impactOneline:
      "Public PromptMap deployments document LLM adversarial testing surfaces for unauthenticated prompt-injection lab discovery.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePromptmapEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "PromptMap is intentional AI red-team tooling — require authentication before exposing live model testing.",
      steps: [
        "Require login before /dashboard and /new-training-session routes on private deployments.",
        "Do not expose production LLM API keys in client bundles.",
        "Rate-limit unauthenticated prompt fuzzing on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We self-host PromptMap-style LLM prompt-injection testing. Show how to auth-gate dashboard and training session routes.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-google-xss-game-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "Google XSS game training program disclosed",
    description:
      "Google's XSS game teaches reflected and DOM XSS exploitation across staged levels modeled on real-world vulnerable web applications.",
    impactOneline:
      "Public XSS game instances document staged cross-site scripting challenge levels for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideGoogleXssGameEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "XSS game levels are intentional training — do not mirror vulnerable level code into production apps.",
      steps: [
        "Keep XSS game deployments on isolated training hosts only.",
        "Do not copy level source patterns that echo unescaped user input into production.",
        "Require authentication if hosting private XSS challenge mirrors."
      ]
    },
    fixPrompt:
      "We mirror Google XSS game-style training levels. Show how to isolate challenge instances from production applications.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-sentinel-ai-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "Sentinel AI LLM guardrails adversarial test suite disclosed",
    description:
      "Sentinel AI publishes safety guardrails for LLM applications with a built-in 55-case adversarial test suite covering prompt injection, jailbreaks, PII redaction, and OWASP Top 10 code scanning.",
    impactOneline:
      "Public Sentinel AI demos document LLM red-team evaluation workflows for unauthenticated adversarial testing lab discovery.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSentinelAiEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Sentinel AI adversarial suites are intentional red-team tooling — auth-gate live guardrail evaluation on private deployments.",
      steps: [
        "Require authentication before exposing live adversarial test runs.",
        "Do not ship demo API keys or private test-case corpora in client bundles.",
        "Rate-limit unauthenticated prompt-injection fuzzing on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We self-host Sentinel AI-style LLM guardrail evaluation. Show how to auth-gate adversarial test suites on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-nodegoat-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "OWASP NodeGoat intentionally insecure Node.js lab disclosed",
    description:
      "OWASP NodeGoat is a deliberately vulnerable Node.js application with tutorial labs covering injection, broken authentication, and NoSQL flaws.",
    impactOneline:
      "Public NodeGoat Heroku demos document OWASP training surfaces for unauthenticated web security lab discovery.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideNodegoatEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "NodeGoat is intentional OWASP training — never deploy tutorial vulnerable code paths to production.",
      steps: [
        "Run NodeGoat only on isolated lab hosts or localhost.",
        "Do not copy NodeGoat eval/NoSQL tutorial handlers into production APIs.",
        "Require authentication if self-hosting NodeGoat outside classroom sandboxes."
      ]
    },
    fixPrompt:
      "We host OWASP NodeGoat-style training apps. Show how to keep intentionally vulnerable Node.js labs isolated from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-gandalf-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "Lakera Gandalf prompt-injection CTF disclosed",
    description:
      "Lakera Gandalf is a public prompt-injection challenge where players attempt to trick an LLM into revealing secrets across staged levels.",
    impactOneline:
      "Public Gandalf CTF instances document prompt-injection attack surfaces for unauthenticated AI security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideGandalfEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gandalf CTF levels are intentional AI red-team challenges — do not expose production LLM secrets to unauthenticated users.",
      steps: [
        "Never embed real secrets in LLM system prompts reachable from public CTF levels.",
        "Rate-limit unauthenticated prompt attempts on self-hosted Gandalf mirrors.",
        "Monitor Gandalf-style challenges for credential harvesting abuse."
      ]
    },
    fixPrompt:
      "We host Lakera Gandalf-style prompt-injection CTF levels. Show how to isolate challenge LLM backends from production secrets.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ironwasp-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "IronWASP Sboxr DOM XSS scanner platform disclosed",
    description:
      "ironwasp.org hosts Sboxr, a DOM XSS and client-side security scanner with training content for finding browser-side vulnerabilities.",
    impactOneline:
      "Public Sboxr landing pages document DOM XSS detection workflows attackers study for client-side security testing.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideIronwaspEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Sboxr is a security scanner product — use it for authorized testing only.",
      steps: [
        "Run DOM XSS scans only on applications you are authorized to test.",
        "Do not point Sboxr demos at third-party production sites without permission.",
        "Keep scanner training instances on isolated lab networks."
      ]
    },
    fixPrompt:
      "We reference IronWASP Sboxr for DOM XSS training. Show how to restrict scanner use to authorized targets.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-try2hack-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Try2Hack security challenge platform disclosed",
    description:
      "try2hack.nl is one of the oldest public security challenge sites with progressive encryption, cipher, and hacking puzzles.",
    impactOneline:
      "Public Try2Hack challenge hubs expose security puzzle catalogs for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideTry2hackEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Try2Hack is intentional challenge software — never mirror its puzzles on production systems.",
      steps: [
        "Complete Try2Hack levels only in isolated browser sessions.",
        "Do not embed Try2Hack challenge answers in production authentication flows.",
        "Use Try2Hack for skill building, not as a production security control."
      ]
    },
    fixPrompt:
      "We link to Try2Hack security challenges for training. Show how to keep challenge progress separate from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-rogueloop-xxs-course-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "RogueLoop XSS interactive course disclosed",
    description:
      "rogueloop.github.io/xxs-course embeds reflected, stored, and DOM XSS demonstrations with innerHTML sinks for browser security training.",
    impactOneline:
      "Public XSS course pages document exploitable innerHTML patterns that attackers replay on misconfigured apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideRogueloopXxsCourseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "XSS training courses are intentional — sanitize outputs in production instead of copying demo sinks.",
      steps: [
        "Host XSS course labs only on GitHub Pages or isolated training subdomains.",
        "Replace innerHTML assignments with textContent in production code.",
        "Use Content-Security-Policy to block inline script execution in production apps."
      ]
    },
    fixPrompt:
      "Our XSS training course uses innerHTML demo sinks. Show how to keep the course isolated from production deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-epicdetect-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "EpicDetect browser-based SOC training academy disclosed",
    description:
      "epicdetect.io hosts hands-on cybersecurity training with Atlas skill tree, story-driven SOC investigations, and SIEM/phishing analysis adventures.",
    impactOneline:
      "Public EpicDetect landing pages document SOC analyst investigation workflows attackers study for defensive security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideEpicdetectEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "EpicDetect is a training platform — isolate lab environments from production SOC tooling.",
      steps: [
        "Complete EpicDetect adventures only in dedicated training browser profiles.",
        "Do not point EpicDetect SIEM labs at production log sources without authorization.",
        "Keep certification prep instances separate from live incident response systems."
      ]
    },
    fixPrompt:
      "We reference EpicDetect for SOC analyst training. Show how to isolate browser-based SIEM labs from production security operations.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-alf-serviceworker-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "alf.nu ServiceWorker sandbox attack lab disclosed",
    description:
      "alf.nu/ServiceWorker demonstrates persistent fetch interception via navigator.serviceWorker.register on sandbox subdomains used for user-generated content.",
    impactOneline:
      "Public ServiceWorker attack lab documents how XSS on sandbox domains installs permanent fetch rootkits that steal secret file URLs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAlfServiceworkerEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Block Service-Worker registration on sandbox file-serving origins.",
      steps: [
        "Reject requests with Service-Worker: script header on user-content subdomains.",
        "Serve untrusted uploads from a separate origin without ServiceWorker scope.",
        "Use per-file signed URLs instead of obscurity for secret file names on shared domains."
      ]
    },
    fixPrompt:
      "We host user files on sandbox subdomains. Show how to block ServiceWorker registration and prevent persistent fetch interception after XSS.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-burp-bounty-lab-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Burp Bounty Lab scanner profile testbed disclosed",
    description:
      "Burp Bounty Lab is an intentionally vulnerable application cataloging XSS, SQLi, SSRF, SSTI, and XXE routes for testing Burp Bounty scanner profiles.",
    impactOneline:
      "Public Burp Bounty Lab instances expose live reflected XSS and error-based SQLi endpoints attackers can probe without authentication.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBurpBountyLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Burp Bounty Lab is intentional scanner training — never deploy similar vuln catalogs to production.",
      steps: [
        "Run Burp Bounty Lab only on isolated lab networks.",
        "Block public access to /xss/, /sqli/, and /ssrf/ training routes in production.",
        "Use Burp Bounty profiles only against authorized staging targets."
      ]
    },
    fixPrompt:
      "We host a Burp Bounty Lab-style scanner testbed. Show how to isolate it and prevent XSS/SQLi routes from reaching production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-artemiskit-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "ArtemisKit LLM red-team toolkit disclosed",
    description:
      "ArtemisKit is an open-source CLI toolkit combining LLM security red-teaming, quality evaluation, and stress testing with prompt-injection and jailbreak mutation scoring.",
    impactOneline:
      "Public ArtemisKit landing pages document prompt-injection and jailbreak attack catalogs useful for adversarial LLM testing.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideArtemisKitEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "ArtemisKit is intentional AI red-team tooling — restrict LLM attack demos to authorized lab environments.",
      steps: [
        "Run ArtemisKit red-team scans only against staging LLM endpoints with synthetic data.",
        "Do not expose ArtemisKit attack mutation catalogs on public marketing pages with live API keys.",
        "Monitor production chatbots for prompt-injection patterns ArtemisKit documents."
      ]
    },
    fixPrompt:
      "We use ArtemisKit for LLM security testing. Show how to run red-team scans safely and harden production chatbots against prompt injection.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-railsgoat-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "OWASP RailsGoat vulnerable Rails training app disclosed",
    description:
      "RailsGoat is OWASP's deliberately vulnerable Ruby on Rails application documenting SQL injection, XSS, CSRF, and broken access control lessons.",
    impactOneline:
      "Public RailsGoat documentation mirrors advertise serious intentional vulnerabilities for security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideRailsgoatEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "RailsGoat is intentional training software — never deploy similar vulnerable Rails apps to production.",
      steps: [
        "Run RailsGoat only on isolated lab VMs without public network binding.",
        "Do not reuse RailsGoat vulnerability patterns in production code.",
        "Use RailsGoat tutorials to patch SQLi, XSS, and CSRF in your own apps."
      ]
    },
    fixPrompt:
      "We host a RailsGoat-style vulnerable Rails training app. Show how to isolate it and fix the SQLi/XSS/CSRF patterns it demonstrates.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pc-parts-store-lab-evidence",
    platform: "generic",
    category: "XSS",
    severityDefault: "high",
    title: "PC Parts Store lab renders unsanitized product HTML",
    description:
      "The PC Parts Store vulnerable e-commerce SPA uses React dangerouslySetInnerHTML to render Commerce.js product descriptions without sanitization.",
    impactOneline:
      "Stored XSS is possible when product catalog descriptions include attacker-controlled HTML rendered on /details pages.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePcPartsStoreLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never render Commerce.js or API product descriptions with dangerouslySetInnerHTML.",
      steps: [
        "Replace dangerouslySetInnerHTML with textContent or a strict HTML sanitizer (DOMPurify).",
        "Validate and strip HTML from product descriptions at import time.",
        "Run PC Parts Store labs only on isolated staging with synthetic catalog data."
      ]
    },
    fixPrompt:
      "Our React e-commerce app uses dangerouslySetInnerHTML for product descriptions. Show the safe alternative and how to sanitize Commerce.js catalog HTML.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-breaktheflask-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "BreakTheFlask vulnerable Flask writeup lab disclosed",
    description:
      "BreakTheFlask GitHub Pages writeups embed intentionally vulnerable Flask routes for SQLi, XSS, command injection, LDAP injection, and broken access control.",
    impactOneline:
      "Public BreakTheFlask walkthrough pages document exploitable Flask patterns attackers can replay against similar apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBreakTheFlaskEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "BreakTheFlask is intentional training material — never deploy similar vulnerable Flask routes to production.",
      steps: [
        "Run BreakTheFlask only on isolated lab VMs.",
        "Replace render_template_string with parameterized queries and Jinja2 templates with autoescape.",
        "Validate session ownership on /profile and /admin_panel routes."
      ]
    },
    fixPrompt:
      "We host BreakTheFlask-style Flask training writeups. Show how to fix SQLi, SSTI via render_template_string, command injection, and IDOR on /profile routes.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-grpc-goat-lab-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "gRPC Goat vulnerability practice lab disclosed",
    description:
      "gRPC Goat documents nine intentionally vulnerable gRPC microservices covering reflection, plaintext transport, mTLS bypass, SQLi, command injection, and SSRF.",
    impactOneline:
      "Public gRPC Goat docs teach reusable attack chains against reflection-enabled and misconfigured gRPC deployments.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideGrpcGoatLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "gRPC Goat is intentional training software — disable reflection and enforce TLS/mTLS in production.",
      steps: [
        "Disable gRPC server reflection outside development.",
        "Require mutual TLS with trusted CA validation on partner APIs.",
        "Parameterize SQL queries and sanitize shell arguments in gRPC handlers."
      ]
    },
    fixPrompt:
      "We document gRPC Goat labs with reflection, plaintext auth, and SQLi. Show how to harden production gRPC services against these attack scenarios.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-webvuln-runner-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "WebVuln-Runner Docker lab launcher disclosed",
    description:
      "WebVuln-Runner is a Docker TUI that launches Juice Shop, DVWA, WebGoat, bWAPP, and other OWASP Top 10 training containers.",
    impactOneline:
      "Public WebVuln-Runner landing pages advertise one-click deployment of multiple intentionally vulnerable applications.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWebvulnRunnerEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "WebVuln-Runner is intentional lab tooling — isolate Docker networks and block public exposure.",
      steps: [
        "Run WebVuln-Runner containers on host-only or lab VLAN networks.",
        "Never expose Juice Shop/DVWA/WebGoat ports to the public internet.",
        "Use WebVuln-Runner only for authorized security training."
      ]
    },
    fixPrompt:
      "We use WebVuln-Runner to spin up Juice Shop and DVWA containers. Show network isolation best practices so lab apps never reach production subnets.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-frontend-xss-demo-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "Frontend XSS educational demo with insecure vs secure routes",
    description:
      "Educational XSS demos document side-by-side insecure and sanitized rendering routes with classic reflected XSS payload examples.",
    impactOneline:
      "Public XSS training SPAs expose /insecure routes that render unsanitized HTML for classroom exploitation practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideFrontendXssDemoEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "XSS training demos are intentional — never copy /insecure rendering patterns into production.",
      steps: [
        "Keep educational /insecure routes off production domains.",
        "Use DOMPurify or textContent for all user-controlled HTML in production.",
        "Gate training demos behind classroom auth when self-hosting."
      ]
    },
    fixPrompt:
      "We host a frontend XSS educational demo with /insecure and /secure routes. Show how to keep training-only XSS sinks off production builds.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ai-chat-html-sink-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "AI chatbot renders model output via dangerouslySetInnerHTML",
    description:
      "Damn Vulnerable AI and similar chat UIs POST to /api/ai then inject LLM responses into the DOM with dangerouslySetInnerHTML.",
    impactOneline:
      "Prompt-injection or XSS in LLM output becomes stored/reflected DOM XSS when chat UIs trust model HTML.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAiChatHtmlSinkEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never render LLM output as HTML — sanitize or use text-only rendering.",
      steps: [
        "Replace dangerouslySetInnerHTML on model responses with textContent or markdown-to-safe-html.",
        "Sanitize LLM output with DOMPurify before any HTML rendering.",
        "Treat /api/ai endpoints as untrusted input sources in threat models."
      ]
    },
    fixPrompt:
      "Our AI chat UI uses dangerouslySetInnerHTML to render /api/ai model responses. Show the safe text-only or sanitized rendering alternative.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-avid-vuln-registry-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "AVID ML vulnerability registry editor disclosed",
    description:
      "AVID vulnerability editors publish submitted ML/LLM flaw reports with structured metadata at /vuln and /editor routes.",
    impactOneline:
      "Public AVID registries document ML vulnerability taxonomies and evaluation flaws attackers study for AI red-team targets.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAvidVulnRegistryEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "AVID registries are research tooling — gate editor routes behind authentication on non-public deployments.",
      steps: [
        "Require auth before /editor submission forms on private AVID instances.",
        "Do not expose draft vulnerability reports on public domains.",
        "Separate public research catalogs from internal flaw tracking."
      ]
    },
    fixPrompt:
      "We deploy an AVID-style vulnerability registry with /vuln listings. Show how to auth-gate editor routes on non-public instances.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-security-shepherd-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "OWASP Security Shepherd training platform disclosed",
    description:
      "OWASP Security Shepherd hosts staged web application security challenges for XSS, injection, access control, and misconfiguration training.",
    impactOneline:
      "Public Security Shepherd instances document intentionally vulnerable challenge labs used for application security education.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSecurityShepherdEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Security Shepherd is intentional training — isolate lab instances from production networks.",
      steps: [
        "Require authentication before serving challenge modules on private deployments.",
        "Do not expose Security Shepherd admin or lesson routes to the public internet without access controls.",
        "Run Shepherd labs only on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "We host OWASP Security Shepherd for security training. Show how to isolate challenge instances from production networks.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-waf-workshop-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "WAF bypass security workshop disclosed",
    description:
      "h3xstream WAF Bypass Workshop teaches ModSecurity SQL injection bypass via alternative syntax, encoding tricks, and libinjection evasion labs.",
    impactOneline:
      "Public WAF workshop pages document SQLi bypass techniques attackers replay against production WAF-protected endpoints.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWafWorkshopEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "WAF workshops are intentional training — tune WAF rules using isolated lab instances only.",
      steps: [
        "Run WAF bypass labs only on dedicated ModSecurity training VMs.",
        "Do not expose workshop SQLi payloads against production databases.",
        "Use workshop findings to harden WAF rule sets in staging environments."
      ]
    },
    fixPrompt:
      "We host a WAF bypass training workshop. Show how to keep ModSecurity lab instances isolated from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-bugforge-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Bugforge web exploitation lab platform disclosed",
    description:
      "Bugforge advertises browser-based web exploitation labs with difficulty tiers, on-demand instances, and CTF flag submission APIs.",
    impactOneline:
      "Public Bugforge lab platforms document intentional vulnerability training surfaces for SQLi, XSS, IDOR, and API security practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBugforgeLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Bugforge is intentional training — isolate lab instances from production networks.",
      steps: [
        "Require authentication before starting lab instances on private deployments.",
        "Do not reuse Bugforge lab vulnerability patterns in production code.",
        "Rate-limit unauthenticated lab API enumeration."
      ]
    },
    fixPrompt:
      "We host Bugforge-style web exploitation labs. Show how to isolate on-demand lab instances from production.",
    version: 1,
    enabled: true
  }
];
