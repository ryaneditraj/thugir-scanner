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
    slug: "sitemap-listed-sensitive-file-exposed",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "high",
    title: "Sitemap-listed sensitive file downloadable",
    description:
      "sitemap.xml advertises a database backup or credential file path and a live HTTP probe confirms the file is served without authentication.",
    impactOneline: "A sensitive file listed in your sitemap is publicly downloadable.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "sitemapListedSensitiveFileProbe" },
    tierRequired: "free",
    remediation: {
      summary: "Remove sensitive files from the web root and exclude them from sitemap generation.",
      steps: [
        "Delete or move database backups and credential files outside the public web root.",
        "Exclude *.mdb, *.sql, and backup paths from sitemap.xml generation.",
        "Rotate credentials if any exposed backup contained secrets."
      ]
    },
    fixPrompt:
      "My sitemap.xml lists paths like *.mdb or *.sql and those files are reachable over HTTP. Remove them from the deploy artifact, block direct access, and exclude them from sitemap generation.",
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
    slug: "graphql-endpoint-disclosed-in-docs",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "GraphQL server URL disclosed in API documentation",
    description:
      "SpectaQL or Swagger-style API docs embed the GraphQL server URL (often localhost:PORT/graphql), exposing the full schema, queries, and mutations to anyone who can read the docs page.",
    impactOneline: "GraphQL schema and mutation catalog are readable from public API docs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "graphqlEndpointDisclosedInDocs" },
    tierRequired: "free",
    remediation: {
      summary: "Remove internal GraphQL URLs from public docs and gate API reference behind auth.",
      steps: [
        "Do not publish SpectaQL/Swagger docs with localhost or internal GraphQL URLs on public hosts.",
        "Require authentication for API reference pages in production.",
        "Disable GraphQL playground and introspection on any reachable GraphQL endpoint."
      ]
    },
    fixPrompt:
      "Our SpectaQL docs expose a GraphQL server URL and full schema on a public page. Show how to redact internal endpoints from docs and lock down the live GraphQL API.",
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
    slug: "phpmyadmin-exposed",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "high",
    title: "phpMyAdmin database admin login reachable",
    description:
      "A phpMyAdmin login page is publicly reachable. Database administration consoles expose schema browsing, SQL execution, and often default credentials on misconfigured hosts.",
    impactOneline: "Anyone can reach your phpMyAdmin login — a common path to full database compromise.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "phpMyAdminExposed" },
    tierRequired: "free",
    remediation: {
      summary: "Remove phpMyAdmin from public internet access and require VPN or IP allowlisting.",
      steps: [
        "Block /phpMyAdmin and /phpmyadmin paths at the reverse proxy for non-admin networks.",
        "Require strong authentication and MFA before any database admin console.",
        "Use managed database consoles instead of exposing phpMyAdmin on app hosts."
      ]
    },
    fixPrompt:
      "Production still serves phpMyAdmin on a public URL. Block admin database consoles from the internet and show me the server or WAF rule.",
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
    slug: "hts-yuppers-search-sqli-probe",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Boolean SQL injection on HTS Yuppers search.cgi",
    description:
      "HackThisSite Realistic mission 14 Yuppers search.cgi returns zero results for a nonsense baseline query but many matches for a lone quote — positive proof the search parameter alters SQL query logic.",
    impactOneline: "Attackers can extract or modify database contents via the search parameter.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "htsYuppersSearchSqliProbe" },
    tierRequired: "deep",
    remediation: {
      summary: "Use parameterized queries; never concatenate user input into SQL.",
      steps: [
        "Replace string-concatenated search queries with prepared statements.",
        "Return generic errors to clients; log SQL details server-side only.",
        "Add input validation on search endpoints."
      ]
    },
    fixPrompt:
      "My search.cgi endpoint shows boolean SQLi behavior (quote-only input returns all rows). Switch to parameterized queries and show the fixed handler.",
    version: 1,
    enabled: true
  },
  {
    slug: "command-injection-form-probe",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "OS command injection via form POST parameter",
    description:
      "A POST form endpoint passes user input to a shell command and echoes command output in the response — positive proof of OS command injection.",
    impactOneline: "Attackers can execute arbitrary OS commands via the vulnerable form parameter.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "invictiNslookupCommandInjectionProbe" },
    tierRequired: "deep",
    remediation: {
      summary: "Never pass user input to shell commands; use safe APIs and strict allow-lists.",
      steps: [
        "Replace shell invocation with purpose-built libraries (DNS resolver APIs, not nslookup).",
        "If subprocess use is unavoidable, use argument arrays and strict input validation.",
        "Remove practice command-injection forms from any internet-reachable host."
      ]
    },
    fixPrompt:
      "My nslookup-style form passes user input to a shell command and echoes output. Replace shell invocation with a safe DNS API, validate input with an allow-list, and show the fixed handler.",
    version: 1,
    enabled: true
  },
  {
    slug: "post-login-sql-bypass",
    platform: "generic",
    category: "Injection",
    severityDefault: "critical",
    title: "SQL injection bypasses POST login authentication",
    description:
      "A POST login form accepts SQL injection payloads in the username field, returning a session cookie and redirect to a protected dashboard — positive proof of authentication bypass via SQLi.",
    impactOneline: "Attackers can log in without valid credentials by injecting SQL into the login form.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "postLoginSqlBypass" },
    tierRequired: "deep",
    remediation: {
      summary: "Use parameterized queries for all authentication SQL; never concatenate user input.",
      steps: [
        "Replace f-string or concatenated login queries with prepared statements.",
        "Return generic login failure messages without SQL details.",
        "Add rate limiting and monitoring on login endpoints."
      ]
    },
    fixPrompt:
      "My Flask login accepts SQLi payloads like ' OR 1=1 -- and issues a session redirect. Switch to parameterized queries and show the fixed login handler.",
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
    slug: "client-side-ctf-challenge-hub-evidence",
    platform: "generic",
    category: "general",
    severityDefault: "medium",
    title: "Static CTF challenge hub with linked web security labs",
    description:
      "A static CTF challenge hub indexes hands-on web security labs (SQL injection, XSS, JWT, path traversal) across /c1/–/cN/ child routes — common on Hack the Basics and webexp05-style training deploys.",
    impactOneline:
      "Public CTF hub pages document deliberately vulnerable challenge routes for security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtfChallengeHubEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CTF training hubs are intentional — isolate lab instances from production and gate with auth when needed.",
      steps: [
        "Run challenge hubs only on isolated training infrastructure.",
        "Do not reuse challenge vulnerability patterns in production apps.",
        "Add auth if challenges should not be publicly enumerable."
      ]
    },
    fixPrompt:
      "Our site hosts a public CTF Challenge Hub linking /c1/–/c5/ SQLi and XSS labs. Explain how to isolate training hubs from production and add optional auth gating.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-bouvet-intro-ctf-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "Bouvet Intro to CTF training hub disclosed",
    description:
      "Bouvet Intro to CTF startpages document per-team vulnerable application instances, CTFD scoreboard registration, and OWASP Top 10 challenge workflows for hands-on CTF training.",
    impactOneline:
      "Public CTF onboarding hubs expose intentionally vulnerable instance URLs and flag-submission workflows for security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBouvetIntroCtfEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CTF training hubs are intentional — isolate challenge instances from production networks.",
      steps: [
        "Run per-team CTF instances on dedicated Heroku dynos or VMs with no production data.",
        "Require CTFD registration before exposing challenge instance URLs.",
        "Do not reuse CTF vulnerability patterns in production applications."
      ]
    },
    fixPrompt:
      "We host a Bouvet Intro to CTF startpage linking bouvet-ctfd.herokuapp.com and per-team ctf-X.herokuapp.com instances. Show how to isolate CTF infrastructure from production.",
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
    slug: "client-side-graphql-security-hub-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "GraphQL security assessment hub disclosed",
    description:
      "Client bundle or HTML documents a GraphQL security testing hub (graphql.security) that assesses introspection, authorization, complexity limits, and injection risks.",
    impactOneline:
      "Public GraphQL security scanner hubs advertise assessment workflows useful for attacker reconnaissance.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideGraphqlSecurityHubEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "GraphQL security hubs are intentional training tools — isolate from production APIs.",
      steps: [
        "Run GraphQL security assessments only against authorized staging targets.",
        "Do not expose production GraphQL endpoints to public scanner hubs.",
        "Disable introspection and enforce auth on production GraphQL APIs."
      ]
    },
    fixPrompt:
      "Our site documents a GraphQL security assessment hub (graphql.security). Explain how to scope security testing to authorized targets and harden production GraphQL introspection and authorization.",
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
    slug: "client-side-auth-security-project-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "high",
    title: "auth-security-project OWASP auth demo disclosed",
    description:
      "darkroot192 auth-security-project on Render documents SQL injection, XSS, IDOR, and plaintext-password flaws on an intentionally insecure Spanish-language auth training app.",
    impactOneline:
      "Public auth-security-project demos expose login SQLi hints and broken access-control patterns attackers replay on production auth flows.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAuthSecurityProjectEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "auth-security-project is intentional training — isolate Render demos from production identity systems.",
      steps: [
        "Run auth-security-project only on ephemeral lab infrastructure.",
        "Never store passwords in plaintext or echo SQLi bypass hints on production login pages.",
        "Enforce object-level authorization on profile and admin routes."
      ]
    },
    fixPrompt:
      "We host an auth-security-project-style OWASP Top 10 auth demo with SQLi and IDOR. Show how to isolate it and fix login and access-control flaws.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-os-command-injection-lab-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Educational OS command injection lab disclosed",
    description:
      "WebVulnsGuide OS-injection dojo and similar training pages document system()/exec() misuse, command-separator gaps, and arbitrary OS command execution patterns.",
    impactOneline:
      "Public command-injection dojos teach shell metacharacter bypasses attackers replay on apps that pass user input to system commands.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOsCommandInjectionLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Command-injection dojos are intentional training — never pipe user input to shell commands in production.",
      steps: [
        "Avoid system(), exec(), and shell=True with any user-controlled input.",
        "Use parameterized APIs instead of shell invocation for network diagnostics.",
        "Host OS-injection labs only on isolated GitHub Pages or lab subdomains."
      ]
    },
    fixPrompt:
      "We mirror WebVulnsGuide-style OS command injection training pages. Show how to fix shell invocation and host labs safely.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-webvulnsguide-ssti-lab-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Educational SSTI lab disclosed",
    description:
      "WebVulnsGuide SSTI Fun House and similar training pages document server-side template injection requirements, engine evaluation oracles, and unsafe template embedding patterns.",
    impactOneline:
      "Public SSTI dojos teach template-engine evaluation tricks attackers replay on apps that embed user input in server templates.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWebVulnsGuideSstiLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "SSTI dojos are intentional training — never embed raw user input in server-side templates in production.",
      steps: [
        "Use logic-less templates or strict auto-escaping for all user-controlled values.",
        "Sandbox template engines and disable dangerous helpers (eval, import, attr).",
        "Host SSTI labs only on isolated GitHub Pages or lab subdomains."
      ]
    },
    fixPrompt:
      "We mirror WebVulnsGuide-style SSTI training pages. Show how to fix template embedding and host labs safely.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-webvulnsguide-cors-lab-evidence",
    platform: "generic",
    category: "Misconfiguration",
    severityDefault: "medium",
    title: "Educational CORS misconfiguration lab disclosed",
    description:
      "WebVulnsGuide CORS Misconfiguration Lab and similar training pages document reflective-origin API policies that let malicious sites bypass Same-Origin Policy.",
    impactOneline:
      "Public CORS dojos teach origin-reflection tricks attackers replay on APIs that echo Access-Control-Allow-Origin from user input.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWebVulnsGuideCorsLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CORS dojos are intentional training — never reflect arbitrary Origin headers in production APIs.",
      steps: [
        "Maintain an explicit allow-list of trusted origins for CORS.",
        "Never echo the request Origin header without validation.",
        "Host CORS labs only on isolated GitHub Pages or lab subdomains."
      ]
    },
    fixPrompt:
      "We mirror WebVulnsGuide-style CORS misconfiguration training pages. Show how to fix origin reflection and host labs safely.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-webvulnsguide-xxe-lab-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Educational XXE lab disclosed",
    description:
      "WebVulnsGuide XXE Vulnerability Demonstration and similar training pages document external entity expansion, file disclosure payloads, and interactive XML parsing demos.",
    impactOneline:
      "Public XXE dojos teach entity-expansion tricks attackers replay on apps that parse untrusted XML with external entities enabled.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWebVulnsGuideXxeLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "XXE dojos are intentional training — disable external entities and DTD processing in production XML parsers.",
      steps: [
        "Set disallow-doctype-decl and disable external-general-entities on XML parsers.",
        "Prefer JSON over XML for untrusted input when possible.",
        "Host XXE labs only on isolated GitHub Pages or lab subdomains."
      ]
    },
    fixPrompt:
      "We mirror WebVulnsGuide-style XXE training pages. Show how to harden XML parsers and host labs safely.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-webvulnsguide-ssrf-lab-evidence",
    platform: "generic",
    category: "SSRF",
    severityDefault: "high",
    title: "Educational SSRF lab disclosed",
    description:
      "WebVulnsGuide SSRF Adventure and similar training pages document server-side URL fetch misuse, internal metadata probes, and unvalidated image_url parameters.",
    impactOneline:
      "Public SSRF dojos teach internal-network fetch tricks attackers replay on apps that retrieve user-supplied URLs server-side.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWebVulnsGuideSsrfLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "SSRF dojos are intentional training — never fetch user-controlled URLs server-side without strict allow-lists.",
      steps: [
        "Block private IP ranges, link-local, and cloud metadata endpoints from server-side fetchers.",
        "Use an allow-list of trusted external hosts instead of open URL retrieval.",
        "Host SSRF labs only on isolated GitHub Pages or lab subdomains."
      ]
    },
    fixPrompt:
      "We mirror WebVulnsGuide-style SSRF training pages. Show how to fix server-side URL fetch validation and host labs safely.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-sql-injection-playground-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Educational SQL injection playground disclosed",
    description:
      "Ashkiani SQL Injection Playground and similar client-side demos build queries via string interpolation and flag injection patterns interactively.",
    impactOneline:
      "Public SQL playgrounds teach string-concat query building that becomes live injection when wired to a real database.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSqlInjectionPlaygroundEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "SQL playgrounds are intentional training — use parameterized queries in production, never string-concat SQL.",
      steps: [
        "Replace string-concat SQL with prepared statements / ORM parameter binding.",
        "Remove client-side SQL simulation and auth bypass string checks from production.",
        "Host SQL injection demos only on isolated GitHub Pages or lab subdomains."
      ]
    },
    fixPrompt:
      "We mirror Ashkiani-style SQL injection playground pages. Show how to fix query building and host labs safely.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-eval-filter-bypass-lab-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "critical",
    title: "Educational eval filter bypass lab disclosed",
    description:
      "WebVulnsGuide Eval Filter Bypass Playground and similar training pages document eval()/Function() misuse with weak input filters that attackers bypass for arbitrary code execution.",
    impactOneline:
      "Public eval-bypass dojos teach filter-evasion tricks attackers replay on apps that dynamically execute user-controlled strings.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideEvalFilterBypassLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Eval-bypass dojos are intentional training — never call eval() or Function() on user input in production.",
      steps: [
        "Remove eval(), Function(), and setTimeout(string) from all user-input paths.",
        "Use safe expression parsers or sandboxed interpreters instead of dynamic code execution.",
        "Host eval-bypass labs only on isolated GitHub Pages or lab subdomains."
      ]
    },
    fixPrompt:
      "We mirror WebVulnsGuide-style eval filter bypass training pages. Show how to eliminate dynamic code execution and host labs safely.",
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
    slug: "client-side-gin-and-juice-scanner-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Gin & Juice Shop scanner evaluation lab documents vulnerability oracle",
    description:
      "PortSwigger Gin & Juice Shop /vulnerabilities page lists deliberate SQLi, DOM XSS, SSTI, and SSRF flaws for web vulnerability scanner benchmarking.",
    impactOneline:
      "Public scanner benchmark oracles expose attack paths attackers use to tune automated exploitation against real targets.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideGinAndJuiceScannerLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Restrict scanner evaluation labs to isolated environments; do not mirror oracle pages on production apps.",
      steps: [
        "Host Gin & Juice Shop and similar scanner labs on VPN-only or local Docker instances.",
        "Remove /vulnerabilities oracle tables from any production-facing hostname.",
        "Use synthetic scanner benchmarks instead of internet-exposed vulnerable apps."
      ]
    },
    fixPrompt:
      "Our Gin & Juice Shop clone exposes a /vulnerabilities oracle listing SQLi and DOM XSS paths. Show how to isolate the scanner lab from production traffic.",
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
    slug: "client-side-pentesterlab-sqli-exercise-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "PentesterLab SQL Injection 01 exercise disclosed",
    description:
      "PentesterLab SQL Injection 01 hosted exercise documents login-bypass SQL injection with injectable payloads exploiting improper input handling.",
    impactOneline:
      "Public SQLi exercise instance reveals authentication-bypass injection patterns for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterlabSqliExerciseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; never reuse lab SQL in production apps.",
      steps: [
        "Require authentication before serving injectable exercise instances.",
        "Use parameterized queries in production login handlers.",
        "Isolate exercise infrastructure from production databases."
      ]
    },
    fixPrompt:
      "We host PentesterLab SQL Injection 01-style login bypass labs. Show how to gate labs behind auth and use parameterized queries in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentesterlab-sqli-02-exercise-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "PentesterLab SQL Injection 02 exercise disclosed",
    description:
      "PentesterLab SQL Injection 02 hosted exercise documents login-form SQL injection with double-quoted string payloads that return at least one user record.",
    impactOneline:
      "Public SQLi exercise instance reveals double-quote login injection patterns for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterlabSqli02ExerciseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; never reuse lab SQL in production apps.",
      steps: [
        "Require authentication before serving injectable exercise instances.",
        "Use parameterized queries in production login handlers.",
        "Isolate exercise infrastructure from production databases."
      ]
    },
    fixPrompt:
      "We host PentesterLab SQL Injection 02-style double-quote login bypass labs. Show how to gate labs behind auth and use parameterized queries in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentesterlab-xss-exercise-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "PentesterLab XSS 01 exercise disclosed",
    description:
      "PentesterLab XSS 01 hosted exercise documents reflected cross-site scripting via alert-box canary payloads and unescaped HTML rendering.",
    impactOneline:
      "Public XSS exercise instance reveals reflected injection patterns for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterlabXssExerciseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; encode output in production apps.",
      steps: [
        "Require authentication before serving injectable exercise instances.",
        "HTML-encode all user-controlled output in production templates.",
        "Isolate exercise infrastructure from production networks."
      ]
    },
    fixPrompt:
      "We host PentesterLab XSS 01-style reflected XSS labs. Show how to gate labs behind auth and encode user output in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentesterlab-sqli-to-shell-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "critical",
    title: "PentesterLab From SQL Injection to Shell exercise disclosed",
    description:
      "PentesterLab From SQL Injection to Shell exercise documents SQL injection exploitation chaining to admin access and remote code execution on the server.",
    impactOneline:
      "Public SQLi-to-RCE exercise reveals multi-step injection and post-exploitation patterns for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterlabSqliToShellEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; never reuse lab SQL or admin shells in production.",
      steps: [
        "Require authentication before serving injectable exercise instances.",
        "Use parameterized queries and least-privilege DB accounts in production.",
        "Isolate exercise infrastructure from production networks and admin panels."
      ]
    },
    fixPrompt:
      "We host PentesterLab From SQL Injection to Shell-style multi-step labs. Show how to gate labs behind auth and prevent SQLi-to-RCE chains in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentesterlab-ssrf-exercise-evidence",
    platform: "generic",
    category: "Server-side request forgery",
    severityDefault: "high",
    title: "PentesterLab SSRF 01 exercise disclosed",
    description:
      "PentesterLab SSRF 01 hosted exercise documents server-side request forgery via url parameter to fetch internal resources on localhost.",
    impactOneline:
      "Public SSRF exercise instance reveals internal fetch patterns for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterlabSsrfExerciseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; block internal URL fetches in production.",
      steps: [
        "Require authentication before serving SSRF exercise instances.",
        "Denylist internal IPs and metadata endpoints in production URL fetchers.",
        "Isolate exercise infrastructure from internal services."
      ]
    },
    fixPrompt:
      "We host PentesterLab SSRF 01-style internal fetch labs. Show how to gate labs behind auth and block SSRF in production URL handlers.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentesterlab-idor-exercise-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "PentesterLab Authorization 01 IDOR exercise disclosed",
    description:
      "PentesterLab Authorization 01 hosted exercise documents Insecure Direct Object Reference via incrementing URL IDs to access other users' data without authorization checks.",
    impactOneline:
      "Public IDOR exercise instance reveals predictable object-reference patterns for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterlabIdorExerciseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; enforce object-level authorization in production.",
      steps: [
        "Require authentication before serving IDOR exercise instances.",
        "Validate session ownership on every object-access API route.",
        "Use non-enumerable identifiers instead of sequential IDs in production."
      ]
    },
    fixPrompt:
      "We host PentesterLab Authorization 01-style IDOR labs. Show how to gate labs behind auth and enforce object-level authorization in production APIs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentesterlab-autho-02-exercise-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "PentesterLab Authorization 02 IDOR exercise disclosed",
    description:
      "PentesterLab Authorization 02 hosted exercise documents Insecure Direct Object Reference via incrementing URL parameters to access other users' data without authorization checks.",
    impactOneline:
      "Public IDOR exercise instance reveals predictable URL-parameter object-reference patterns for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterlabAutho02ExerciseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; enforce object-level authorization in production.",
      steps: [
        "Require authentication before serving IDOR exercise instances.",
        "Validate session ownership on every object-access API route.",
        "Use non-enumerable identifiers instead of sequential URL parameters in production."
      ]
    },
    fixPrompt:
      "We host PentesterLab Authorization 02-style IDOR labs. Show how to gate labs behind auth and enforce object-level authorization in production APIs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentesterlab-xss-02-exercise-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "PentesterLab XSS 02 filter-bypass exercise disclosed",
    description:
      "PentesterLab XSS 02 hosted exercise documents reflected XSS filter bypass using case variation techniques to trigger alert-box payloads.",
    impactOneline:
      "Public XSS exercise instance reveals case-variation filter bypass patterns for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterlabXss02ExerciseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; encode output and use robust XSS filters in production.",
      steps: [
        "Require authentication before serving injectable exercise instances.",
        "HTML-encode all user-controlled output in production templates.",
        "Use context-aware output encoding instead of blacklist-based tag filters."
      ]
    },
    fixPrompt:
      "We host PentesterLab XSS 02-style filter-bypass labs. Show how to gate labs behind auth and encode user output in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentesterlab-autho-03-exercise-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "PentesterLab Authorization 03 content-negotiation exercise disclosed",
    description:
      "PentesterLab Authorization 03 hosted exercise documents IDOR via alternate JSON representations that expose unmasked sensitive data hidden in HTML views.",
    impactOneline:
      "Public content-negotiation IDOR exercise reveals JSON/HTML representation mismatch patterns for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterlabAutho03ExerciseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; enforce consistent field masking across all API representations.",
      steps: [
        "Require authentication before serving IDOR exercise instances.",
        "Apply the same sensitive-field masking on JSON and HTML API responses.",
        "Reject unauthenticated alternate-format requests for user records."
      ]
    },
    fixPrompt:
      "We host PentesterLab Authorization 03-style content-negotiation IDOR labs. Show how to gate labs behind auth and mask sensitive fields across all representations.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentesterlab-xss-03-exercise-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "PentesterLab XSS 03 non-recursive filter exercise disclosed",
    description:
      "PentesterLab XSS 03 hosted exercise documents reflected XSS filter bypass by exploiting non-recursive blacklist sanitization to inject script payloads.",
    impactOneline:
      "Public XSS exercise instance reveals non-recursive filter evasion patterns for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterlabXss03ExerciseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; use recursive/context-aware output encoding in production.",
      steps: [
        "Require authentication before serving injectable exercise instances.",
        "HTML-encode all user-controlled output in production templates.",
        "Replace blacklist filters with context-aware sanitizers that normalize nested payloads."
      ]
    },
    fixPrompt:
      "We host PentesterLab XSS 03-style non-recursive filter labs. Show how to gate labs behind auth and encode user output in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pentesterlab-xss-mysql-exercise-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "critical",
    title: "PentesterLab XSS and MySQL FILE exercise disclosed",
    description:
      "PentesterLab XSS and MySQL FILE hosted exercise documents an XSS-to-admin-access chain followed by SQL injection for server-side code execution.",
    impactOneline:
      "Public multi-step exercise instance reveals XSS-to-SQLi exploitation chains for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePentesterlabXssMysqlExerciseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate exercise VMs behind paid accounts; prevent XSS-to-SQLi chains in production.",
      steps: [
        "Require authentication before serving injectable exercise instances.",
        "HTML-encode reflected output and use parameterized SQL queries in production.",
        "Isolate exercise infrastructure from production databases."
      ]
    },
    fixPrompt:
      "We host PentesterLab XSS and MySQL FILE-style multi-step labs. Show how to gate labs behind auth and break XSS-to-SQLi chains in production.",
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
    slug: "client-side-defhawk-practice-lab-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "DefHawk PracticeLab cybersecurity training disclosed",
    description:
      "DefHawk vulnAI / PracticeLab publishes real-world vulnerability exploitation drills and Hack Arena gamified challenge simulations.",
    impactOneline:
      "Public DefHawk practice hubs document hands-on exploitation training used to calibrate scanners against lab targets.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideDefhawkPracticeLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "DefHawk labs are intentional training — isolate practice environments from production networks.",
      steps: [
        "Run vulnerability exploitation drills only on dedicated training tenants.",
        "Require authenticated accounts before launching Hack Arena challenge instances.",
        "Use DefHawk lab findings to patch similar gaps in production applications."
      ]
    },
    fixPrompt:
      "We host DefHawk-style real-world exploitation practice labs. Show how to isolate training instances from production.",
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
    slug: "client-side-redtiger-hackit-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "RedTiger PHP/SQL hackit disclosed",
    description:
      "RedTiger's Hackit on redtiger.labs.overthewire.org teaches PHP/MySQL SQL injection, blind injection, and login-bypass challenges across level1.php–level10.php.",
    impactOneline:
      "Public RedTiger hackit pages document SQL injection and authentication bypass training surfaces with real-world vulnerability patterns.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideRedtigerHackitEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "RedTiger Hackit is intentional training — isolate hackit VMs from production networks.",
      steps: [
        "Run RedTiger challenges only on dedicated training VMs.",
        "Use parameterized queries instead of string-concatenated SQL in production.",
        "Rate-limit unauthenticated hackit enumeration."
      ]
    },
    fixPrompt:
      "We host RedTiger-style PHP/SQL injection hackits. Show how to isolate training labs from production and fix SQLi patterns.",
    version: 1,
    enabled: true
  },
  {
    slug: "redtiger-blind-login-form-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "RedTiger blind login-bypass form disclosed",
    description:
      "RedTiger Hackit levels 2–10 expose password-only POST login forms (levelNlogin) for blind SQL injection and authentication bypass drills.",
    impactOneline:
      "Public RedTiger level pages document blind SQLi login-bypass training surfaces beyond the hub catalog.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "redtigerBlindLoginFormEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "RedTiger blind-login levels are intentional training — isolate hackit VMs from production.",
      steps: [
        "Run RedTiger challenges only on dedicated training VMs.",
        "Use parameterized queries for authentication in production.",
        "Rate-limit blind login enumeration on public endpoints."
      ]
    },
    fixPrompt:
      "We host RedTiger blind SQLi login-bypass levels. Show how to isolate training labs and fix authentication SQLi.",
    version: 1,
    enabled: true
  },
  {
    slug: "redtiger-classic-login-sql-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "RedTiger classic SQLi login form disclosed",
    description:
      "RedTiger Hackit level1–2 expose username+password POST login forms with disclosed users table names for classic SQL injection drills.",
    impactOneline:
      "Public RedTiger level pages document classic SQLi login training surfaces with Tablename: levelN_users hints.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "redtigerClassicLoginSqlEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "RedTiger classic-login levels are intentional training — isolate hackit VMs from production.",
      steps: [
        "Run RedTiger challenges only on dedicated training VMs.",
        "Use parameterized queries for authentication in production.",
        "Disable verbose table-name hints on public login pages."
      ]
    },
    fixPrompt:
      "We host RedTiger classic SQLi login levels. Show how to isolate training labs and fix authentication SQLi.",
    version: 1,
    enabled: true
  },
  {
    slug: "redtiger-special-challenge-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "RedTiger special SMS exfiltration challenge disclosed",
    description:
      "RedTiger Hackit special1.php documents a non-SQL SMS exfiltration challenge with solution POST form — a web hacking drill beyond SQL injection levels.",
    impactOneline:
      "Public RedTiger special challenge pages document alternate web exploitation training surfaces outside the SQLi level catalog.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "redtigerSpecialChallengeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "RedTiger special challenges are intentional training — isolate hackit VMs from production.",
      steps: [
        "Run RedTiger challenges only on dedicated training VMs.",
        "Do not expose SMS gateway or phone-number lookup endpoints without auth in production.",
        "Rate-limit unauthenticated hackit enumeration."
      ]
    },
    fixPrompt:
      "We host RedTiger-style special web hacking challenges. Show how to isolate training labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vuln-expose-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "VulnSite pentest training platform disclosed",
    description:
      "VulnSite (vuln-expose.vercel.app) is a Next.js pentest platform with dual-mode corporate apps and explicit SQLi, XSS, IDOR, and command-injection laboratories.",
    impactOneline:
      "Public VulnSite pages document deliberately vulnerable corporate facades plus hands-on security lab routes for pentest training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnExposeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "VulnSite is intentional training — never deploy its vulnerability patterns to production.",
      steps: [
        "Run VulnSite labs only on isolated infrastructure.",
        "Gate lab routes behind authenticated training accounts.",
        "Do not copy VulnSite SQLi/XSS/CMDi patterns into production code."
      ]
    },
    fixPrompt:
      "We host VulnSite-style dual-mode pentest labs. Show how to isolate training deployments from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vuln-expose-lab-module-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "VulnSite hands-on lab module with inline exploit payloads",
    description:
      "VulnSite module pages (/sqli/login, /sqli/blind, /xss/profile, /cmdi, /idor/dashboard, /network-tools) publish SQL auth-bypass, blind SQLi, XSS, command injection, IDOR, and ping/SSRF lab banners with inline payloads.",
    impactOneline:
      "Public VulnSite lab modules document live exploit techniques and test credentials that accelerate attacker training on real vulnerability classes.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnExposeLabModuleEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "VulnSite lab modules are intentional training — never copy inline exploit patterns to production.",
      steps: [
        "Run VulnSite SQLi/XSS modules only on isolated training infrastructure.",
        "Remove displayed test credentials from any non-training deployment.",
        "Use parameterized queries and output encoding in production auth and comment flows."
      ]
    },
    fixPrompt:
      "We host VulnSite SQL auth-bypass and XSS playground modules. Show how to isolate lab payloads from production login and comment rendering.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-cyberpunker-insecureship-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "TheCyberpunker InsecureShip API security lab disclosed",
    description:
      "TheCyberpunker InsecureShip is a deliberately vulnerable Node.js shipping REST API documenting OWASP API Security Top 10 (2023) training coverage.",
    impactOneline:
      "Public InsecureShip lab writeups expose BOLA/BFLA/API misconfiguration training routes attackers use to tune API security scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCyberpunkerInsecureshipEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "InsecureShip is intentional API security training — never deploy its vulnerability patterns to production.",
      steps: [
        "Run InsecureShip only on isolated lab infrastructure.",
        "Gate API training instances behind authenticated lab accounts.",
        "Do not copy InsecureShip authorization bypass patterns into production APIs."
      ]
    },
    fixPrompt:
      "We host TheCyberpunker InsecureShip API security training. Show how to isolate deliberately vulnerable API labs from production services.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-wizer-ctf-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "Wizer developer security CTF disclosed",
    description:
      "Wizer hosts public chal*.vercel.app CTF challenges with SQL injection login labs, XSS sinks, and developer security training scenarios.",
    impactOneline:
      "Public Wizer CTF pages document deliberately vulnerable login and XSS training surfaces for developer security education.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWizerCtfEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Wizer CTF labs are intentional training — never deploy challenge vulnerability patterns to production.",
      steps: [
        "Run Wizer CTF challenges only on isolated training infrastructure.",
        "Use parameterized queries and output encoding in production login flows.",
        "Do not copy Wizer challenge SQLi/XSS patterns into production apps."
      ]
    },
    fixPrompt:
      "We host Wizer-style developer security CTF labs. Show how to isolate training deployments from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ringzer0-ctf-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "RingZer0 Team online CTF disclosed",
    description:
      "RingZer0 Team hosts ringzer0ctf.com — an online CTF platform where players solve web, crypto, and exploitation challenges to earn points.",
    impactOneline:
      "Public RingZer0 CTF pages document challenge infrastructure attackers use to calibrate scanners against training targets.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideRingzer0CtfEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "RingZer0 CTF is intentional training — gate challenge instances behind authenticated accounts.",
      steps: [
        "Require login before spawning injectable CTF challenge VMs.",
        "Isolate CTF infrastructure from production networks.",
        "Rate-limit unauthenticated challenge enumeration."
      ]
    },
    fixPrompt:
      "We host RingZer0-style online CTF challenges. Show how to gate lab instances behind auth and isolate them from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-webhacking-kr-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Webhacking.kr challenge platform disclosed",
    description:
      "Webhacking.kr hosts 80+ Korean web application security challenges where competitors exploit or defend vulnerabilities in web apps.",
    impactOneline:
      "Public Webhacking.kr pages document web injection and access-control training challenge catalogs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWebhackingKrEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Webhacking.kr is intentional training — require accounts before serving challenge instances.",
      steps: [
        "Gate /chall.php challenge routes behind authenticated sessions.",
        "Isolate challenge VMs from production networks.",
        "Rate-limit unauthenticated challenge enumeration."
      ]
    },
    fixPrompt:
      "We host Webhacking.kr-style web security challenges. Show how to gate challenge routes behind auth and isolate labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-net-force-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Net-Force.nl hacking challenge platform disclosed",
    description:
      "Net-Force.nl is an online community with web, JavaScript, and cryptography hacking challenges at /challenge/levelNN/.",
    impactOneline:
      "Public Net-Force pages document injectable challenge instances used for web security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideNetForceEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Net-Force is intentional training — require login before serving challenge instances.",
      steps: [
        "Gate /challenge/ routes behind authenticated accounts.",
        "Isolate challenge VMs from production networks.",
        "Rate-limit unauthenticated challenge enumeration."
      ]
    },
    fixPrompt:
      "We host Net-Force-style hacking challenges. Show how to gate challenge routes behind auth and isolate labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-net-force-challenge-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "medium",
    title: "Net-Force.nl JavaScript auth-bypass challenge disclosed",
    description:
      "Net-Force.nl /challenge/levelNN/ instances expose client-side validate(), document.write(unescape()), JScript.Encode tester() gates, eval(unescape()) koh() decoders, HTML PROTECT SHA1 hash gates, or substring password-generation drills for authentication bypass training.",
    impactOneline:
      "Public Net-Force challenge pages document trivial client-side credential checks attackers bypass without server validation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideNetForceChallengeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Net-Force challenges are intentional training — never implement client-side-only authentication in production.",
      steps: [
        "Validate credentials server-side on every protected route.",
        "Do not embed passwords in JavaScript or obfuscated document.write blocks.",
        "Gate challenge instances behind authenticated lab accounts."
      ]
    },
    fixPrompt:
      "We host Net-Force-style JS auth-bypass challenges. Show how to move credential checks server-side and isolate training labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnlab-verbose-404-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "high",
    title: "VulnLab verbose 404 credential leak disclosed",
    description:
      "VulnLab Academy ships verbose 404 error pages that echo stack traces with DB_PASS and NODE_ENV secrets for sensitive-data-in-errors training.",
    impactOneline:
      "Public VulnLab verbose 404 labs leak database credentials and stack traces in HTML error responses.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnlabVerbose404Evidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never return stack traces or secrets in production error pages.",
      steps: [
        "Return generic 404 pages without internal paths or environment variables.",
        "Log detailed errors server-side only.",
        "Redact DB_PASS and other secrets from all client-visible diagnostics."
      ]
    },
    fixPrompt:
      "Our VulnLab verbose 404 lab leaks DB_PASS in HTML. Show how to return generic errors and redact secrets in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctfd-platform-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "CTFd open-source CTF platform disclosed",
    description:
      "CTFd deployments (hackerfire.com and ctfd.io instances) expose challenge catalogs, registration, and admin setup prompts without production isolation.",
    impactOneline:
      "Public CTFd instances document challenge infrastructure attackers use to enumerate training targets.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtfdPlatformEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Isolate CTFd challenge platforms from production networks and harden admin setup.",
      steps: [
        "Run CTFd on dedicated training infrastructure with network isolation.",
        "Require strong admin passwords and disable public registration when not needed.",
        "Do not reuse CTF challenge credentials in production systems."
      ]
    },
    fixPrompt:
      "We host a CTFd challenge platform. Show how to isolate it from production and harden admin registration.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-brutelogic-xss-gym-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "Brute Logic XSS Gym disclosed",
    description:
      "Brute Logic XSS Gym at x55.is/brutelogic/gym.php exposes 30+ DOM XSS cases with innerHTML and eval sinks for PoC training.",
    impactOneline:
      "Public XSS Gym pages document DOM XSS sinks attackers use to calibrate reflected and DOM-based XSS scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBrutelogicXssGymEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "XSS Gym is intentional training — do not deploy eval/innerHTML patterns to production.",
      steps: [
        "Run XSS Gym only on isolated training hosts.",
        "Replace innerHTML with textContent for user-controlled data in production.",
        "Never use eval() on URL parameters or form input."
      ]
    },
    fixPrompt:
      "We host Brute Logic-style XSS gyms for training. Show how to isolate DOM XSS labs and fix innerHTML/eval sinks in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-brutelogic-xss-test-page-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "Brute Logic XSS Test Page disclosed",
    description:
      "Brute Logic XSS Test Page at x55.is/brutelogic/xss.php reflects 11 URL/form parameters (a, b1–b6, c1–c6) for HTML and JS injection calibration.",
    impactOneline:
      "Public XSS test pages document reflected injection surfaces attackers use to tune XSS scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBrutelogicXssTestPageEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "XSS test pages are intentional training — encode all reflected output in production.",
      steps: [
        "Run Brute Logic labs only on isolated training hosts.",
        "HTML-encode reflected user input before rendering.",
        "Never reflect URL parameters into inline script blocks."
      ]
    },
    fixPrompt:
      "We host Brute Logic-style XSS test pages for training. Show how to isolate labs and fix reflected XSS in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-knoxss-test-page-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "KNOXSS add-on XSS test hub disclosed",
    description:
      "KNOXSS add-on test hub at x55.is/brutelogic/knoxss.html catalogs 29+ reflected, DOM, and blind XSS cases across xss.php, multi/, dom/, and blind/ paths.",
    impactOneline:
      "Public KNOXSS hubs enumerate XSS challenge routes used to calibrate browser-based XSS scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideKnoxssTestPageEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "KNOXSS test hubs are intentional training — do not expose blind-XSS collectors in production.",
      steps: [
        "Host KNOXSS labs on isolated training domains.",
        "Disable blind-XSS email collectors outside authorized ranges.",
        "Rate-limit unauthenticated XSS probe traffic on lab hosts."
      ]
    },
    fixPrompt:
      "We host KNOXSS-style XSS test hubs for training. Show how to isolate blind-XSS labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctflearn-webfour-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "CTFlearn Web4 SQLi challenge disclosed",
    description:
      "CTFlearn Web4 at web.ctflearn.com/web4/ discloses string-concatenated SQL against webfour.webfour — a beginner SQL injection training challenge.",
    impactOneline:
      "Public Web4 pages echo injectable SQL queries — SQLi likely if the pattern is wired to a live database.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtflearnWebfourEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CTFlearn Web4 is intentional training — use parameterized queries in production.",
      steps: [
        "Run Web4 challenges only on dedicated training databases.",
        "Replace string-concatenated SQL with prepared statements.",
        "Rate-limit unauthenticated SQLi probe traffic on lab hosts."
      ]
    },
    fixPrompt:
      "We host CTFlearn Web4-style SQLi labs. Show how to isolate training databases and fix string-concatenated SQL in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctflearn-webeight-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "CTFlearn Web8 Dog Viewer SQLi challenge disclosed",
    description:
      "CTFlearn Web8 at web.ctflearn.com/web8/ exposes a Dog Viewer with numeric id GET parameter against dog records — UNION/blind SQLi training lab.",
    impactOneline:
      "Public Web8 pages accept injectable id parameters against a live dog database — SQLi likely.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtflearnWebeightEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CTFlearn Web8 is intentional training — use parameterized queries in production.",
      steps: [
        "Run Web8 challenges only on dedicated training databases.",
        "Replace string-concatenated SQL with prepared statements.",
        "Rate-limit unauthenticated SQLi probe traffic on lab hosts."
      ]
    },
    fixPrompt:
      "We host CTFlearn Web8-style dog-id SQLi labs. Show how to isolate training databases and fix numeric id SQL injection in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctflearn-webone-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "high",
    title: "CTFlearn Web1 HTML comment credential disclosed",
    description:
      "CTFlearn Web1 at web.ctflearn.com/web1/ hides the login password in an HTML comment beside a POST password form — Simple credential disclosure training challenge.",
    impactOneline:
      "Public Web1 pages leak the password in view-source comments — authentication bypass likely.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtflearnWeboneEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CTFlearn Web1 is intentional training — never embed credentials in HTML comments in production.",
      steps: [
        "Run Web1 challenges only on dedicated training hosts.",
        "Remove secrets from HTML comments and client-visible markup.",
        "Store credentials server-side with proper hashing."
      ]
    },
    fixPrompt:
      "We host CTFlearn Web1-style credential disclosure labs. Show how to remove HTML comment secrets and secure password checks in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctflearn-webthree-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "CTFlearn Web3 admin gate challenge disclosed",
    description:
      "CTFlearn Web3 at web.ctflearn.com/web3/ presents an unauthenticated admin gate with a denial message — broken access control training challenge.",
    impactOneline:
      "Public Web3 pages expose an admin-only surface without authentication — auth bypass training surface.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtflearnWebthreeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CTFlearn Web3 is intentional training — enforce server-side authorization in production.",
      steps: [
        "Run Web3 challenges only on dedicated training hosts.",
        "Require authenticated sessions before serving admin routes.",
        "Never rely on client-visible gate messages for access control."
      ]
    },
    fixPrompt:
      "We host CTFlearn Web3-style admin gate labs. Show how to enforce server-side authorization on admin routes in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctflearn-webtwo-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "high",
    title: "CTFlearn Web2 base64 HTML comment credential disclosed",
    description:
      "CTFlearn Web2 at web.ctflearn.com/web2/ hides the login password in a base64-encoded HTML comment beside a POST password form.",
    impactOneline:
      "Public Web2 pages leak base64-encoded credentials in view-source comments — authentication bypass likely.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtflearnWebtwoEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CTFlearn Web2 is intentional training — never embed credentials in HTML comments in production.",
      steps: [
        "Run Web2 challenges only on dedicated training hosts.",
        "Remove secrets from HTML comments and client-visible markup.",
        "Store credentials server-side with proper hashing."
      ]
    },
    fixPrompt:
      "We host CTFlearn Web2-style base64 comment credential labs. Show how to remove HTML comment secrets in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctflearn-webseven-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "CTFlearn Web7 calculator eval challenge disclosed",
    description:
      "CTFlearn Web7 at web.ctflearn.com/web7/ uses eval() on calculator expression input in calc.js — DOM code injection training challenge.",
    impactOneline:
      "Public Web7 calculator passes user input to eval() — arbitrary JavaScript execution likely.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtflearnWebsevenEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CTFlearn Web7 is intentional training — never pass user input to eval() in production.",
      steps: [
        "Run Web7 challenges only on dedicated training hosts.",
        "Replace eval() with safe expression parsers.",
        "Sanitize and validate all calculator input server-side when applicable."
      ]
    },
    fixPrompt:
      "We host CTFlearn Web7-style calculator eval labs. Show how to replace eval() with safe parsers in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ctflearn-websix-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "high",
    title: "CTFlearn Web6 PHP strcmp challenge disclosed",
    description:
      "CTFlearn Web6 at web.ctflearn.com/web6/ points to source.txt with a GET password strcmp check — PHP type-juggling training challenge.",
    impactOneline:
      "Public Web6 pages expose strcmp source and accept array password[] bypass — authentication bypass likely.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCtflearnWebsixEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CTFlearn Web6 is intentional training — use strict comparison and type checks in production.",
      steps: [
        "Run Web6 challenges only on dedicated training hosts.",
        "Replace strcmp with hash_equals for secrets.",
        "Reject array parameters on password inputs."
      ]
    },
    fixPrompt:
      "We host CTFlearn Web6-style strcmp labs. Show how to fix PHP strcmp type juggling and array parameter bypass in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "php-strcmp-array-bypass",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "critical",
    title: "PHP strcmp bypass via array password parameter",
    description:
      "Live probe confirms PHP strcmp password check bypassed when password[] array is supplied — type juggling returns flag or success marker.",
    impactOneline:
      "GET password[]=1 bypasses strcmp auth and returns a CTF flag — critical authentication bypass.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "phpStrcmpArrayBypass" },
    tierRequired: "deep",
    remediation: {
      summary: "Reject non-string password input and use hash_equals for secret comparison.",
      steps: [
        "Validate password is a string before strcmp or hash_equals.",
        "Use hash_equals instead of strcmp for credential checks.",
        "Return generic errors without leaking flags on failure."
      ]
    },
    fixPrompt:
      "Our PHP login uses strcmp on $_GET password. Show how to block array type juggling and use hash_equals.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-wechall-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "WeChall global CTF challenge scoreboard disclosed",
    description:
      "WeChall at wechall.net aggregates 180+ non-simulated hacking challenges across MySQL, PHP, exploit, and HTTP categories.",
    impactOneline:
      "Public WeChall pages catalogue injectable challenge taxonomy reusable for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWechallEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "WeChall challenges are intentional training — isolate lab VMs from production.",
      steps: [
        "Run WeChall-hosted challenges only on dedicated lab infrastructure.",
        "Require authentication before serving injectable challenge instances.",
        "Never copy WeChall challenge vulnerability patterns into production code."
      ]
    },
    fixPrompt:
      "We link to WeChall-style CTF scoreboards for team training. Show how to isolate challenge VMs from production networks.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-appsec-master-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "AppSecMaster web hacking lab platform disclosed",
    description:
      "AppSecMaster advertises Docker-based web application hacking labs with hands-on code review challenges, CTF labs, and OSWE certification prep.",
    impactOneline:
      "Public AppSecMaster marketing pages document lab infrastructure and vulnerability taxonomy for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAppsecMasterEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "AppSecMaster labs are intentional training — gate lab instances behind paid accounts.",
      steps: [
        "Require AppSecMaster authentication before spawning injectable lab containers.",
        "Isolate Docker lab instances from corporate production networks.",
        "Use lab findings to close skill gaps without copying vulnerable patterns to production."
      ]
    },
    fixPrompt:
      "We use AppSecMaster-style Docker web hacking labs for team training. Show how to isolate lab containers from production and gate spawns behind SSO.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-appsec-master-lab-hub-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "AppSecMaster XSS/SQLi category lab hub disclosed",
    description:
      "AppSecMaster /labs/cross-site-scripting-xss and /labs/sql-injection hubs publish Course schema, FAQ copy, and Start Labs CTAs for deployed injection challenges.",
    impactOneline:
      "Public AppSecMaster lab category pages document injectable challenge infrastructure for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAppsecMasterLabHubEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "AppSecMaster lab hubs are intentional training — gate challenge instances behind paid accounts.",
      steps: [
        "Require authentication before spawning injectable lab containers.",
        "Isolate Docker lab instances from production networks.",
        "Use lab hub findings to tune DAST coverage without copying vulnerable patterns."
      ]
    },
    fixPrompt:
      "We link to AppSecMaster XSS/SQLi lab hubs for team training. Show how to isolate lab containers and gate challenge spawns behind SSO.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ist-edu-vuln-portal-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "IST Edu intentionally vulnerable university portal disclosed",
    description:
      "ist-edu-bd.vercel.app documents SQLi login bypass on /api/portal, LFI on /api/notices?file=, CRLF newsletter injection, and XSS search labs.",
    impactOneline:
      "Public IST Edu portal exposes multi-vector vulnerability training routes reachable without local setup.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideIstEduVulnPortalEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "IST Edu is an intentional training portal — gate lab routes behind authentication.",
      steps: [
        "Require login before exposing /portal and /search lab modules.",
        "Never deploy similar SQLi/LFI/CRLF patterns to production university portals.",
        "Isolate training instances from student production data."
      ]
    },
    fixPrompt:
      "We host an IST Edu-style vulnerable university portal for security workshops. Show how to isolate lab routes and block unauthenticated access to injectable APIs.",
    version: 1,
    enabled: true
  },
  {
    slug: "notices-file-lfi-probe",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "critical",
    title: "Local file inclusion via file query parameter",
    description:
      "A notices or file-reader API accepts a file= parameter with path traversal sequences and returns /etc/passwd or similar system file contents.",
    impactOneline:
      "LFI via unsanitized file parameters enables reading sensitive server files and often leads to RCE.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "noticesFileLfiProbe" },
    tierRequired: "deep",
    remediation: {
      summary: "Never pass user input directly to filesystem reads; use allowlisted filenames.",
      steps: [
        "Reject path traversal sequences (../, ..\\) in file parameters.",
        "Use an allowlist of permitted notice filenames instead of arbitrary paths.",
        "Run file-serving APIs with minimal filesystem permissions."
      ]
    },
    fixPrompt:
      "Our /api/notices?file= endpoint returns /etc/passwd when given ../../../etc/passwd. Block path traversal and allowlist permitted filenames.",
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
    slug: "client-side-vulnex-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "VULNEX web hacking playbook disclosed",
    description:
      "VULNEX publishes ready-to-use payloads, exploitation techniques, and checklists for security researchers and bug hunters.",
    impactOneline:
      "Public payload playbooks document OWASP-aligned injection and exploitation patterns attackers reuse against real targets.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnexEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Payload libraries are reference material — never deploy copy-pasted exploit strings to production apps.",
      steps: [
        "Use payload playbooks only in authorized lab environments.",
        "Patch vulnerabilities matching playbook categories in production code.",
        "Monitor for exploitation signatures documented in public payload libraries."
      ]
    },
    fixPrompt:
      "We host a VULNEX-style payload playbook. Show how to keep exploit references out of production deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-secureflag-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "SecureFlag OWASP secure coding labs disclosed",
    description:
      "SecureFlag partners with OWASP to offer browser-based hands-on secure coding training labs and vulnerability exercises.",
    impactOneline:
      "Public SecureFlag hubs document OWASP Top 10 lab instances used to calibrate scanners against training environments.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSecureflagEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "SecureFlag labs are intentional training — gate lab VMs behind OWASP member authentication.",
      steps: [
        "Require OWASP email verification before launching lab instances.",
        "Isolate SecureFlag-style training environments from production networks.",
        "Never reuse lab-vulnerable code patterns in production applications."
      ]
    },
    fixPrompt:
      "We host SecureFlag-style OWASP training labs. Show how to gate lab access behind member auth and isolate VMs.",
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
    slug: "client-side-wrongsecrets-challenge-evidence",
    platform: "generic",
    category: "Exposed secret",
    severityDefault: "high",
    title: "OWASP WrongSecrets challenge walkthrough page disclosed",
    description:
      "WrongSecrets /challenge/challenge-N pages document hardcoded-secret hunting in Git, Docker layers, or cloud config with answer submission UI.",
    impactOneline:
      "Public WrongSecrets challenge walkthroughs teach attackers where production apps commonly hide secrets in code and containers.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideWrongSecretsChallengeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "WrongSecrets challenges are intentional training — remove hardcoded secrets from production code and images.",
      steps: [
        "Scan repositories and container layers for secrets before deploy.",
        "Use secret managers instead of application.properties or env files in images.",
        "Never ship answer-submission CTF walkthroughs on production domains."
      ]
    },
    fixPrompt:
      "Our WrongSecrets-style challenge pages document hardcoded secrets in Git/Docker. Show how to detect and remove secrets from code, containers, and cloud config.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-mass-assignment-lesson-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Hacksplaining mass assignment lesson disclosed",
    description:
      "Hacksplaining /lessons/mass-assignment publishes an interactive exploit-then-fix walkthrough covering HTTP request unpacking that lets attackers bind privileged fields.",
    impactOneline:
      "Public mass assignment lesson pages document privilege-escalation exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingMassAssignmentLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining mass assignment lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable mass assignment lesson instances on private deployments.",
        "Use explicit allowlists for bindable request fields in production — never copy Hacksplaining vulnerable unpackers.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style mass assignment exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-broken-access-control-lesson-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Hacksplaining broken access control lesson disclosed",
    description:
      "Hacksplaining /lessons/broken-access-control publishes an interactive exploit-then-fix walkthrough covering obscured resources, predictable paths, and authorization bypass chains.",
    impactOneline:
      "Public broken access control lesson pages document IDOR and authz-bypass exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingBrokenAccessControlLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining broken access control lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable broken access control lesson instances on private deployments.",
        "Enforce authorization on every resource path in production — never rely on security through obscurity.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style broken access control exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-dns-poisoning-lesson-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "Hacksplaining DNS poisoning lesson disclosed",
    description:
      "Hacksplaining /lessons/dns-poisoning publishes an interactive exploit-then-fix walkthrough covering upstream DNS cache poisoning and traffic interception chains.",
    impactOneline:
      "Public DNS poisoning lesson pages document cache-poisoning exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingDnsPoisoningLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining DNS poisoning lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable DNS poisoning lesson instances on private deployments.",
        "Validate DNS responses and enforce DNSSEC in production — never copy Hacksplaining vulnerable resolver trust models.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style DNS poisoning exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-downgrade-attacks-lesson-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "Hacksplaining downgrade attacks lesson disclosed",
    description:
      "Hacksplaining /lessons/downgrade-attacks publishes an interactive exploit-then-fix walkthrough covering TLS version downgrade, SSL stripping, and HTTPS interception chains.",
    impactOneline:
      "Public downgrade attacks lesson pages document TLS downgrade exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingDowngradeAttacksLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining downgrade attack lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable downgrade attack lesson instances on private deployments.",
        "Enforce modern TLS versions and HSTS in production — never copy Hacksplaining weak cipher negotiation handlers.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style downgrade attack exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-email-spoofing-lesson-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "Hacksplaining email spoofing lesson disclosed",
    description:
      "Hacksplaining /lessons/email-spoofing publishes an interactive exploit-then-fix walkthrough covering forged From headers and weak SPF/DKIM validation chains.",
    impactOneline:
      "Public email spoofing lesson pages document forged-sender exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingEmailSpoofingLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining email spoofing lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable email spoofing lesson instances on private deployments.",
        "Enforce SPF, DKIM, and DMARC in production — never copy Hacksplaining weak mail validation handlers.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style email spoofing exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-ssl-stripping-lesson-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "Hacksplaining SSL stripping lesson disclosed",
    description:
      "Hacksplaining /lessons/ssl-stripping publishes an interactive exploit-then-fix walkthrough covering partial HTTPS coverage and credential theft via protocol downgrade.",
    impactOneline:
      "Public SSL stripping lesson pages document partial-HTTPS downgrade exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingSslStrippingLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining SSL stripping lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable SSL stripping lesson instances on private deployments.",
        "Enforce sitewide HTTPS and HSTS in production — never copy Hacksplaining partial-HTTPS login handlers.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style SSL stripping exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-malvertising-lesson-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "Hacksplaining malvertising lesson disclosed",
    description:
      "Hacksplaining /lessons/malvertising publishes an interactive exploit-then-fix walkthrough covering compromised ad-tech supply chains and malware delivery via embedded adverts.",
    impactOneline:
      "Public malvertising lesson pages document ad-supply-chain exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingMalvertisingLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining malvertising lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable malvertising lesson instances on private deployments.",
        "Vet third-party ad scripts and enforce CSP in production — never copy Hacksplaining weak ad-tech handlers.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style malvertising exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-open-redirects-lesson-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Hacksplaining open redirects lesson disclosed",
    description:
      "Hacksplaining /lessons/open-redirects publishes an interactive exploit-then-fix walkthrough covering unvalidated redirect parameters that enable phishing attacks.",
    impactOneline:
      "Public open-redirect lesson pages document query-string redirect bypass patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingOpenRedirectsLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining open redirect lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable open-redirect lesson instances on private deployments.",
        "Validate redirect targets against an allowlist in production — never copy Hacksplaining unvalidated redirect handlers.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style open redirect exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-xss-dom-lesson-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "Hacksplaining DOM XSS lesson disclosed",
    description:
      "Hacksplaining /lessons/xss-dom publishes an interactive exploit-then-fix walkthrough covering URI fragment sinks that inject malicious JavaScript.",
    impactOneline:
      "Public DOM XSS lesson pages document fragment-based client-side XSS patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingXssDomLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining DOM XSS lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable DOM XSS lesson instances on private deployments.",
        "Sanitize or avoid writing URI fragments to dangerous sinks in production — never copy Hacksplaining vulnerable fragment handlers.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style DOM XSS exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-session-fixation-lesson-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "high",
    title: "Hacksplaining session fixation lesson disclosed",
    description:
      "Hacksplaining /lessons/session-fixation publishes an interactive exploit-then-fix walkthrough covering attacker-controlled session IDs that enable session hijacking after login.",
    impactOneline:
      "Public session fixation lesson pages document pre-auth session ID injection patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingSessionFixationLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining session fixation lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable session fixation lesson instances on private deployments.",
        "Regenerate session IDs after authentication in production — never copy Hacksplaining weak session handlers.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style session fixation exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-file-upload-lesson-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Hacksplaining file upload lesson disclosed",
    description:
      "Hacksplaining /lessons/file-upload publishes an interactive exploit-then-fix walkthrough covering unvalidated file uploads that let attackers inject malicious code.",
    impactOneline:
      "Public file upload lesson pages document unsafe upload handling patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingFileUploadLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining file upload lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable file upload lesson instances on private deployments.",
        "Validate file types, extensions, and content in production — never copy Hacksplaining weak upload handlers.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style file upload exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-oopssec-store-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "OopsSec Store CTF walkthrough roadmap disclosed",
    description:
      "OopsSec Store is an intentionally vulnerable Next.js e-commerce SPA with a 35-flag, 11-chapter CTF roadmap from recon through remote code execution.",
    impactOneline:
      "Public OopsSec Store walkthroughs document OWASP Top 10 and API security flaw progression for unauthenticated training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOopssecStoreEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "OopsSec Store is intentional training — isolate lab deployments from production.",
      steps: [
        "Run OopsSec Store only in isolated lab environments.",
        "Gate walkthrough roadmaps behind authentication on private mirrors.",
        "Do not copy OopsSec vulnerability patterns into production e-commerce code."
      ]
    },
    fixPrompt:
      "We host an OopsSec Store-style vulnerable e-commerce CTF. Show how to isolate lab instances and gate walkthrough content from production.",
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
    slug: "client-side-maestro-rag-sqli-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "MAESTRO demo documents SQL injection via agent memory queries",
    description:
      "MAESTRO Framework agentic AI demos document unsanitized user input in RAG/vector memory search queries enabling SQL injection against agent storage.",
    impactOneline:
      "Agent memory search SQLi can poison or exfiltrate data from vector databases backing LLM agents.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideMaestroRagSqliEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Parameterize all memory/vector search queries; never concatenate user input into SQL.",
      steps: [
        "Use parameterized queries or ORM bindings for memory search APIs.",
        "Validate and sanitize user input before vector/relational memory lookups.",
        "Isolate agent memory stores from production databases."
      ]
    },
    fixPrompt:
      "Our MAESTRO agent demo documents SQL injection via memory queries. Show parameterized memory search and input validation.",
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
    slug: "client-side-hacksec-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "HackSec password-protected ethical hacking portal disclosed",
    description:
      "hacksec.in gates content behind a WordPress password-protected login — a common pattern for private security training lab hubs.",
    impactOneline:
      "Password-protected training portals still disclose lab infrastructure metadata and may leak challenge routes once credentials circulate.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksecEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Use authenticated user accounts instead of shared site passwords; keep lab VMs off public indexes.",
      steps: [
        "Replace site-wide password gates with per-user authentication.",
        "Block crawlers from indexing lab paths via robots.txt and auth.",
        "Run vulnerable labs on isolated infrastructure."
      ]
    },
    fixPrompt:
      "We host hacksec.in behind a WordPress password-protected gate for ethical hacking labs. Show how to replace shared passwords with per-user auth and isolate lab VMs.",
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
    slug: "client-side-vulnforge-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "VulnForge attack-surface scanner SPA disclosed",
    description:
      "VulnForge is an AI-guided web attack-surface explorer SPA that wires a public backend API, client-side auth tokens, and a hardcoded x-vulnforge-api-key header in its JavaScript bundle.",
    impactOneline:
      "Public VulnForge scanner bundles expose backend hosts, API key placeholders, and client-side session storage patterns.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnforgeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "VulnForge scanner instances are training/demo software — rotate API keys and isolate backends from production.",
      steps: [
        "Move x-vulnforge-api-key to server-side proxy routes only.",
        "Rotate change_me_for_prod and any leaked backend credentials.",
        "Do not ship scanner auth tokens in localStorage on production domains."
      ]
    },
    fixPrompt:
      "We deploy a VulnForge-style attack-surface scanner SPA. Show how to proxy backend API calls server-side and remove hardcoded API keys from the client bundle.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnshop-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "VulnShop pentest practice lab disclosed",
    description:
      "VulnShop is an intentionally vulnerable e-commerce SPA that documents unauthenticated /api/debug/config and /api/debug/users routes on a public Railway backend, exposing secret keys and plaintext passwords.",
    impactOneline:
      "Public VulnShop bundles wire a production Railway API with zero-auth debug endpoints documented in the client UI.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnshopEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "VulnShop is intentional training software — isolate lab backends and remove debug routes from any production deploy.",
      steps: [
        "Remove or gate /api/debug/* routes behind admin authentication.",
        "Rotate secret_key and demo passwords if the Railway backend was publicly reachable.",
        "Do not copy VulnShop debug-route patterns into production APIs."
      ]
    },
    fixPrompt:
      "We host a VulnShop-style pentest practice SPA. Show how to remove unauthenticated /api/debug routes and proxy sensitive config server-side.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-jwtlens-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "medium",
    title: "JWTLens JWT security scanner disclosed",
    description:
      "JWTLens is an open-source Burp Suite extension with 62 automated JWT checks covering algorithm confusion, KID injection, weak secrets, and JWT Forge exploitation.",
    impactOneline:
      "Public JWT scanner landing pages document attack techniques attackers reuse against production JSON Web Token implementations.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideJwtlensEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "JWT scanner docs are educational — enforce strict JWT validation in production APIs.",
      steps: [
        "Reject alg:none and unexpected signing algorithms server-side.",
        "Validate JWT kid headers against an allow-list; never fetch JWKS from attacker-controlled URLs.",
        "Rotate JWT secrets if weak secrets were ever used in production."
      ]
    },
    fixPrompt:
      "We reference JWTLens-style JWT testing in our security docs. Show how to harden JWT validation against algorithm confusion and KID injection.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-cybersheild-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "CyberShield Lab OWASP Top 10 training platform disclosed",
    description:
      "CyberShield Lab is an interactive cybersecurity education platform with live SQL injection, XSS, and password-analysis modules covering OWASP Top 10 attack-and-fix demos.",
    impactOneline:
      "Public CyberShield Lab instances expose intentionally vulnerable SQLi and XSS training modules for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCybersheildLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CyberShield Lab is intentional training — isolate demo instances from production networks.",
      steps: [
        "Run CyberShield Lab only on dedicated training infrastructure.",
        "Do not copy SQLi/XSS demo patterns into production authentication or comment systems.",
        "Rate-limit unauthenticated access to vulnerable demo modules."
      ]
    },
    fixPrompt:
      "We host a CyberShield Lab-style OWASP Top 10 education platform. Show how to isolate SQLi and XSS demo modules from production apps.",
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
    slug: "client-side-xvwa-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "XVWA deliberately vulnerable web application disclosed",
    description:
      "XVWA (Xtreme Vulnerable Web Application) is an intentionally insecure PHP training app with 15+ attack modules covering SQLi, XSS, SSRF, IDOR, SSTI, and CSRF.",
    impactOneline:
      "Public XVWA instances expose live SQL injection, XSS, SSRF, and access-control flaws for unauthenticated exploitation practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideXvwaEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "XVWA is intentional training software — never deploy to production or expose publicly.",
      steps: [
        "Run XVWA only in isolated Docker/VM lab environments.",
        "Do not expose XVWA vulnerability modules to the public internet.",
        "Use XVWA to validate scanner detection rules, not as a production pattern."
      ]
    },
    fixPrompt:
      "We host XVWA for application security training. Show how to keep it isolated in a lab Docker network.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-open-redirect-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Client-side open redirect validation documented in bundle",
    description:
      "Login or OAuth flows validate ?next= redirects client-side via /api/auth/validate-redirect while URLSearchParams reads only the first duplicate parameter — HTTP-parameter pollution can bypass allow-lists.",
    impactOneline:
      "Post-auth redirects can send users to attacker-controlled URLs when validation inspects a different next= value than the one used for navigation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOpenRedirectEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Validate redirect targets server-side with a single canonical next parameter and an allow-list of same-origin paths.",
      steps: [
        "Reject protocol-relative URLs (//evil.com) and off-origin hosts in redirect handlers.",
        "Parse only the last (or only) next= parameter server-side — never trust client-side validation alone.",
        "Use signed redirect tokens instead of raw URL parameters after login."
      ]
    },
    fixPrompt:
      "Our SPA uses /api/auth/validate-redirect with ?next= after login. Show how to enforce same-origin allow-lists server-side and prevent HPP bypasses.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hackmyvm-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "HackMyVM boot2root CTF platform disclosed",
    description:
      "HackMyVM is a public CTF platform publishing boot2root virtual machines and browser-based vulnerability labs for red-team practice.",
    impactOneline:
      "Public HackMyVM instances expose intentionally vulnerable challenge VMs and online labs for unauthenticated exploitation practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHackmyvmEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "HackMyVM is intentional training infrastructure — isolate challenge VMs from production networks.",
      steps: [
        "Run HackMyVM challenge instances only on dedicated lab VLANs.",
        "Do not expose boot2root VMs to the public internet without access controls.",
        "Rate-limit unauthenticated challenge downloads and lab enumeration."
      ]
    },
    fixPrompt:
      "We host HackMyVM-style boot2root CTF challenges. Show how to isolate vulnerable VMs from production networks.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-xss-victim-bank-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "XSS victim bank session-theft demo disclosed",
    description:
      "Swarnadip-Kar xss-victim bank lab sets a session cookie at login and documents attacker-crafted URLs that steal it via victim.html innerHTML sinks.",
    impactOneline:
      "Public XSS victim bank demos expose session-cookie theft patterns paired with cross-origin C2 collector labs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideXssVictimBankEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Educational XSS labs must not set real session cookies on shared demo origins.",
      steps: [
        "Use HttpOnly and SameSite=Strict on session cookies even in demos.",
        "Sanitize all URL parameters before assigning to innerHTML on victim pages.",
        "Host attacker/victim pairs on isolated subdomains with no shared cookie scope."
      ]
    },
    fixPrompt:
      "We host an XSS victim bank demo with session cookies and victim.html search sinks. Show how to prevent cross-origin cookie theft.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-nimbus-vault-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Nimbus Vault bug-bounty playbook platform disclosed",
    description:
      "Nimbus Vault operationalizes CAVET (Component Analysis & Vulnerability Enumeration Technique) with a Nexus Engine that surfaces attack paths for ethical hackers and bug bounty hunters.",
    impactOneline:
      "Public Nimbus Vault docs expose bug bounty methodology, playbooks, and attack-path reasoning for unauthenticated study.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideNimbusVaultEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Bug bounty platforms are intentional training infrastructure — gate workspace data behind auth.",
      steps: [
        "Require login before exposing target inventories or encoded playbooks.",
        "Do not publish live practice target URLs without access controls.",
        "Rate-limit unauthenticated playbook and component enumeration."
      ]
    },
    fixPrompt:
      "We run a Nimbus Vault-style bug bounty knowledge platform. Show how to auth-gate target inventories and isolate practice apps like Todoer.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-securebank-blog-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "SecureBank attack/secure mode educational lab disclosed",
    description:
      "FAST-NUCES SecureBank semester project blog documents live Attack Mode SQL injection, XSS, and CSRF demos with side-by-side secure vs insecure code.",
    impactOneline:
      "Public SecureBank blog walkthroughs expose intentionally vulnerable banking attack patterns for educational replay.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSecurebankBlogEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Educational attack/secure mode toggles must never ship to production deployments.",
      steps: [
        "Remove Attack Mode from any publicly reachable deployment.",
        "Use parameterized queries and output encoding in all demo code paths.",
        "Host vulnerable demos on isolated lab subdomains with no production data."
      ]
    },
    fixPrompt:
      "Our SecureBank blog documents Attack Mode SQLi/XSS/CSRF. Show how to remove attack toggles from production and isolate lab deploys.",
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
    slug: "client-side-bugbountyhunter-challenge-scenario-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "BugBountyHunter numbered challenge scenario disclosed",
    description:
      "BugBountyHunter challenge?id=N pages publish zseano-style bug bounty scenario titles for XSS filter bypass, open redirect, SSO token theft, and CORS whitelist flaws.",
    impactOneline:
      "Public BugBountyHunter challenge URLs document real-world bug bounty hunting scenarios attackers study.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBugBountyHunterChallengeScenarioEvidence" },
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
      "We host BugBountyHunter-style numbered challenge scenarios. Show how to gate live challenges behind auth.",
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
    slug: "client-side-clawguard-ai-audit-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "ClawGuard EU AI Act compliance audit platform disclosed",
    description:
      "prompttools.co ClawGuard advertises deterministic EU AI Act compliance audits for KI agents and MCP servers against hundreds of threat patterns.",
    impactOneline:
      "Public AI compliance audit landing pages document MCP and agent security assessment surfaces.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideClawguardAiAuditEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Compliance audit tools should not expose live agent/MCP probe endpoints without authentication.",
      steps: [
        "Gate AI compliance scans behind authenticated customer portals.",
        "Do not expose MCP server probe APIs on public marketing pages.",
        "Isolate audit sandboxes from production agent infrastructure."
      ]
    },
    fixPrompt:
      "We publish a ClawGuard-style EU AI Act audit landing page for KI agents and MCP servers. Show how to gate audit APIs behind auth.",
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
    slug: "client-side-code-breaking-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Code-Breaking source-code audit CTF disclosed",
    description:
      "Code-Breaking on code-breaking.fly.dev publishes open source-code audit puzzles where players review shipped source to reach RCE, SQL injection, and other flags.",
    impactOneline:
      "Public code-audit CTF instances document real vulnerability patterns from source review drills.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCodeBreakingEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Code-Breaking is intentional training — isolate puzzle instances from production codebases.",
      steps: [
        "Run source-audit CTF puzzles only on dedicated lab infrastructure.",
        "Require authentication before serving downloadable challenge source archives.",
        "Use puzzle findings to train reviewers without copying vulnerable patterns into production."
      ]
    },
    fixPrompt:
      "We host Code-Breaking-style source audit CTF puzzles. Show how to isolate challenge instances from production repositories.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-sanitize-xss-demo-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "Sanitize HTML filter bypass demo disclosed",
    description:
      "The Sanitize Online Demo on sanitize-web.fly.dev invites users to post HTML and test bypasses against Ruby Sanitize configs (default, restricted, basic, relaxed).",
    impactOneline:
      "Public sanitizer bypass demos document HTML filter evasion techniques applicable to production XSS defenses.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSanitizeXssDemoEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Sanitizer demos are intentional — use strict allowlists and context-aware encoding in production.",
      steps: [
        "Never rely on a single HTML sanitizer config for all user content contexts.",
        "Test sanitizer bypass cases in CI with a curated payload corpus.",
        "Prefer text-only rendering for untrusted content instead of filter-and-render HTML."
      ]
    },
    fixPrompt:
      "We expose a Sanitize HTML filter demo. Show production-safe alternatives to filter-and-render user HTML.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pokemorty-ctf-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Morty's Pokedex CTF disclosed",
    description:
      "Morty's Pokedex CTF on pokemorty.fly.dev stages Rick and Morty themed browser challenges with nickname cookies, captcha forms, and /pokedex validation puzzles.",
    impactOneline:
      "Public Pokemorty CTF instances document client-side and form-based challenge surfaces for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePokemortyCtfEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Pokemorty CTF is intentional training — isolate challenge apps from production networks.",
      steps: [
        "Run CTF challenge apps only on dedicated lab infrastructure.",
        "Require authentication before serving multi-stage challenge routes.",
        "Do not copy challenge cookie or captcha bypass patterns into production apps."
      ]
    },
    fixPrompt:
      "We host Morty's Pokedex-style browser CTF challenges. Show how to isolate challenge instances from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-cvebench-benchmark-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "CVE-Bench AI agent vulnerability benchmark disclosed",
    description:
      "CVE-Bench on cvebench.com evaluates AI agents on autonomously exploiting critical CVEs spanning remote code execution, SQL injection, and privilege escalation in zero-day and one-day modes.",
    impactOneline:
      "Public CVE-Bench leaderboards document high-stakes web exploit oracles attackers use to benchmark autonomous exploitation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCvebenchBenchmarkEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CVE-Bench is intentional research infrastructure — isolate benchmark targets from production networks.",
      steps: [
        "Run CVE-Bench challenge instances only on dedicated lab infrastructure.",
        "Do not expose production apps as CVE-Bench evaluation targets.",
        "Track benchmark CVE categories to prioritize patching in production systems."
      ]
    },
    fixPrompt:
      "We host CVE-Bench-style AI agent exploitation benchmarks. Show how to isolate evaluation targets from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-sploitify-exploit-database-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "Sploitify public exploit cheat sheet disclosed",
    description:
      "Sploitify on splotify.haxx.it is an interactive cheat sheet of curated public server-side exploits with RCE, SQLi, SSRF, and XSS filters inspired by GTFOBins and LOLBAS.",
    impactOneline:
      "Public exploit databases accelerate attacker reconnaissance when vulnerable products are found in scope.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSploitifyExploitDatabaseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Sploitify is a public reference — reduce attack surface by patching known CVEs and minimizing exposed services.",
      steps: [
        "Inventory internet-facing services and map them to known exploit entries.",
        "Patch or isolate software versions referenced in public exploit databases.",
        "Monitor perimeter services for exploit attempts matching published PoCs."
      ]
    },
    fixPrompt:
      "Our perimeter exposes software versions cataloged on Sploitify. Show how to prioritize patching and service hardening.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pwn-guide-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "pwn.guide hands-on cybersecurity tutorial hub disclosed",
    description:
      "pwn.guide hosts 200+ hands-on cybersecurity tutorials covering web hacking, wireless security, and forensics practice paths.",
    impactOneline:
      "Public offensive-security tutorial hubs document attack techniques attackers study before targeting production apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePwnGuideEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Tutorial hubs are public references — harden production apps against techniques documented in training material.",
      steps: [
        "Map tutorial attack patterns to your application threat model.",
        "Patch and monitor for vulnerabilities commonly taught in public hacking guides.",
        "Run internal purple-team drills using public tutorial scenarios on staging only."
      ]
    },
    fixPrompt:
      "We reference pwn.guide-style offensive security tutorials internally. Show how to translate tutorial attack paths into production hardening checks.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-bountybench-benchmark-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Stanford BountyBench AI agent bug bounty benchmark disclosed",
    description:
      "BountyBench on bountybench.github.io benchmarks AI agents on Detect, Exploit, and Patch tasks across 40 real-world bug bounties covering 9 OWASP Top 10 risk categories.",
    impactOneline:
      "Public BountyBench leaderboards document high-value bug bounty oracles used to evaluate autonomous offensive and defensive cyber agents.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBountybenchBenchmarkEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "BountyBench is intentional research infrastructure — isolate benchmark targets from production networks.",
      steps: [
        "Run BountyBench challenge systems only on dedicated lab infrastructure.",
        "Do not expose production apps as BountyBench evaluation targets.",
        "Track benchmark bug bounty categories to prioritize patching in production systems."
      ]
    },
    fixPrompt:
      "We host BountyBench-style AI agent bug bounty benchmarks. Show how to isolate evaluation targets from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-oauth-fetch-playground-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "medium",
    title: "oauth-fetch OAuth2/DPoP API security playground disclosed",
    description:
      "oauth-fetch.oauthlabs.com publishes an interactive playground for OAuth2 protected-resource fetching with Bearer and DPoP token types.",
    impactOneline:
      "Public oauth-fetch demos expose token-provider and DPoP key-pair contracts attackers use to calibrate OAuth API security scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOauthFetchPlaygroundEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "oauth-fetch playground is intentional training — do not expose production tokens in demos.",
      steps: [
        "Use mock token providers in public oauth-fetch demos.",
        "Require authentication before DPoP key-pair generation endpoints.",
        "Never embed live OAuth client secrets in playground bundles."
      ]
    },
    fixPrompt:
      "We host an oauth-fetch OAuth2/DPoP playground. Show how to gate token providers and isolate demo credentials.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-judgement-day-arena-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Judgement Day AI red team arena disclosed",
    description:
      "Judgement Day publishes an AI red-teaming competition with multi-modal jailbreak bounty scenarios for adversarial model evaluation.",
    impactOneline:
      "Public Judgement Day arenas document jailbreak and red-team attack surfaces used to benchmark AI safety defenses.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideJudgementDayArenaEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Judgement Day is intentional red-team research — isolate arena instances from production AI systems.",
      steps: [
        "Run red-team arenas only on dedicated evaluation infrastructure.",
        "Rate-limit jailbreak submission endpoints.",
        "Do not connect production LLM APIs to public arena instances without guardrails."
      ]
    },
    fixPrompt:
      "We host a Judgement Day-style AI red team arena. Show how to isolate jailbreak evaluation from production models.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-metasploitable-lab-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "critical",
    title: "Metasploitable2 intentionally vulnerable VM hub disclosed",
    description:
      "Metasploitable2 hub pages link DVWA, Mutillidae, phpMyAdmin, TWiki, and WebDAV training surfaces with msfadmin default credentials on one host.",
    impactOneline:
      "Public Metasploitable2 hubs aggregate multiple exploitable training apps attackers use to calibrate scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideMetasploitableLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Metasploitable2 is intentional training — never expose lab VMs to untrusted networks.",
      steps: [
        "Run Metasploitable2 only on isolated lab VLANs with no production data.",
        "Block public internet access to phpMyAdmin and DVWA paths on shared lab hosts.",
        "Rotate msfadmin and DVWA default credentials on any forked lab images."
      ]
    },
    fixPrompt:
      "We host a Metasploitable2-style training VM. Show how to isolate it from production networks and remove default credentials.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-blueteamlabs-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Blue Team Labs Online cyber range disclosed",
    description:
      "Blue Team Labs Online advertises scenario-based defender investigations covering incident response, digital forensics, security operations, and threat hunting.",
    impactOneline:
      "Public BTLO marketing pages document blue-team cyber range infrastructure attackers use to study defender training surfaces.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBlueTeamLabsEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "BTLO is intentional training — require authentication before serving investigation lab instances.",
      steps: [
        "Gate cyber range investigations behind registered accounts.",
        "Isolate BTLO-style lab VMs from corporate production networks.",
        "Use investigation findings to improve detection playbooks without copying lab misconfigs to production."
      ]
    },
    fixPrompt:
      "We use Blue Team Labs Online-style cyber range training. Show how to gate investigation labs behind auth and isolate them from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-juice-shop-project-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "OWASP Juice Shop project challenge oracle disclosed",
    description:
      "juice-shop.github.io documents OWASP Juice Shop challenge categories spanning XSS, SQLi, IDOR, auth bypass, and sensitive-data oracles for CTF training.",
    impactOneline:
      "Public Juice Shop project pages expose challenge taxonomy attackers use as benchmark oracles for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideJuiceShopProjectEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Juice Shop is intentional training — run demo instances in isolated lab networks only.",
      steps: [
        "Host Juice Shop demo instances on dedicated lab infrastructure.",
        "Do not deploy Juice Shop challenge patterns or default credentials in production.",
        "Use challenge taxonomy for scanner tuning, not as production security requirements."
      ]
    },
    fixPrompt:
      "We publish OWASP Juice Shop challenge documentation. Show how to keep demo instances isolated from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-juicesec-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "JuiceSec OWASP vulnerability lab disclosed",
    description:
      "JuiceSec is a Cloudflare Workers OWASP lab with inline checkSQLi, checkJWT, and checkSSRF challenge modules plus DOM XSS sinks in the challenge catalog UI.",
    impactOneline:
      "Public JuiceSec deployments document deliberately vulnerable SQLi, JWT, SSRF, and XSS training surfaces for scanner calibration.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideJuicesecLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "JuiceSec is intentional training software — isolate Workers lab deployments from production.",
      steps: [
        "Run JuiceSec only on dedicated lab Workers subdomains.",
        "Do not copy checkSQLi/checkJWT/checkSSRF lab patterns into production auth flows.",
        "Treat JuiceSec challenge modules as scanner oracles, not production design patterns."
      ]
    },
    fixPrompt:
      "We host JuiceSec-style OWASP vulnerability labs on Cloudflare Workers. Show how to isolate lab deployments from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pwnedlabs-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "Pwned Labs cloud security training platform disclosed",
    description:
      "Pwned Labs advertises hands-on cloud, hybrid, and AI security labs covering AWS, Azure, and GCP attacker tradecraft scenarios.",
    impactOneline:
      "Public Pwned Labs catalog documents cloud exploitation lab infrastructure for red-team skill development.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePwnedlabsEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Pwned Labs is intentional training — require authentication before provisioning lab environments.",
      steps: [
        "Gate cloud lab instances behind registered student accounts.",
        "Isolate lab AWS/Azure/GCP sandboxes from production cloud accounts.",
        "Rotate lab credentials and tear down environments after sessions."
      ]
    },
    fixPrompt:
      "We use Pwned Labs-style cloud security training. Show how to gate lab sandboxes behind auth and isolate them from production cloud.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pwnedlabs-git-secrets-evidence",
    platform: "generic",
    category: "Sensitive data exposure",
    severityDefault: "high",
    title: "Pwned Labs git-secrets hunting lab disclosed",
    description:
      "labs.pwnedlabs.io Hunt for Secrets in Git Repos lab documents Trufflehog and git-secrets workflows for finding leaked credentials in company repositories.",
    impactOneline:
      "Public git-secrets lab pages teach credential hunting patterns applicable to real GitHub/GitLab exposure incidents.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePwnedlabsGitSecretsEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Git-secrets labs are intentional training — never commit real credentials to repositories.",
      steps: [
        "Enable secret scanning and pre-commit hooks in all production repos.",
        "Rotate any credentials exposed during git history audits.",
        "Run git-secrets labs only against synthetic repositories with fake credentials."
      ]
    },
    fixPrompt:
      "We host Pwned Labs-style git-secrets hunting exercises. Show how to prevent credential leaks with pre-commit hooks and secret scanning.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-cahyod-vulnerable-lab-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Cahyod Vulnerable Lab pentest training hub disclosed",
    description:
      "lab.cahyo.web.id catalogs 13 intentionally vulnerable subdomain applications spanning SQLi, XSS, IDOR, JWT, and RCE practice targets.",
    impactOneline:
      "Public Cahyod lab hubs document multi-app pentest training surfaces with linked vulnerable subdomains for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCahyodVulnerableLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Cahyod labs are intentional training — isolate vulnerable subdomains from production networks.",
      steps: [
        "Run Cahyod-style training apps only on dedicated lab infrastructure.",
        "Require VPN or auth before serving vulnerable subdomain instances.",
        "Do not copy lab SQLi/XSS patterns into production applications."
      ]
    },
    fixPrompt:
      "We host Cahyod-style multi-app pentest training labs. Show how to isolate vulnerable subdomains from production.",
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
    slug: "client-side-vulnlab-cms-platform-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "VulnLab CMS and platform pentest lab hub disclosed",
    description:
      "VulnLab Academy publishes CMS testing targets (WordPress generator, wp-json, xmlrpc) and platform-specific lab cards (ASP.NET, PHP, Node, Java, Ruby) for hands-on reconnaissance practice.",
    impactOneline:
      "Public CMS/platform lab hubs expose version fingerprints and probe targets that aid attacker recon on misconfigured stacks.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnlabCmsPlatformEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CMS/platform lab hubs are training surfaces — isolate from production and remove version leaks.",
      steps: [
        "Deploy CMS and platform labs on dedicated training infrastructure only.",
        "Remove generator meta tags and version banners from lab pages when not needed.",
        "Gate lab hubs behind authentication even for training environments."
      ]
    },
    fixPrompt:
      "We host VulnLab-style CMS and platform pentest lab hubs. Show how to isolate WordPress/Drupal/Joomla and stack-specific labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnlab-a06-components-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "VulnLab A06 vulnerable components lab disclosed",
    description:
      "VulnLab Academy A06 module ships outdated jQuery 1.12.4 and Angular 1.6.9 vendor scripts for component-detection training.",
    impactOneline:
      "Public A06 labs advertise end-of-life JavaScript libraries attackers fingerprint for known CVE chains.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnlabA06ComponentsEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Track dependency versions and patch outdated client libraries.",
      steps: [
        "Remove unused jQuery/Angular 1.x vendor bundles from production pages.",
        "Enable Dependabot or SCA to alert on EOL component versions.",
        "Host component-detection labs on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "Our A06 lab loads jQuery 1.12.4 and Angular 1.6.9. Show how to inventory and upgrade outdated components.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnlab-a07-auth-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "high",
    title: "VulnLab A07 authentication failures lab disclosed",
    description:
      "VulnLab Academy A07 module documents brute-force login testing and password-reset flows with predictable tokens.",
    impactOneline:
      "Public A07 auth labs advertise weak credential and session-management patterns for scanner validation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnlabA07AuthEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Enforce rate limits, MFA, and cryptographically random password-reset tokens.",
      steps: [
        "Throttle login attempts and lock accounts after repeated failures.",
        "Generate single-use reset tokens with sufficient entropy and short TTL.",
        "Require step-up authentication before sensitive account recovery actions."
      ]
    },
    fixPrompt:
      "Our A07 auth lab exposes brute-force and predictable reset-token flows. Show secure alternatives.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnlab-auth-session-lab-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "high",
    title: "VulnLab auth & session labs disclosed",
    description:
      "VulnLab Academy /auth/* modules document JWT weak secrets, alg=none confusion, login enumeration, and default credentials.",
    impactOneline:
      "Public auth/session labs advertise JWT bypass and credential-guessing patterns for scanner validation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnlabAuthSessionLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Reject alg=none JWTs, use strong signing secrets, and normalize login error messages.",
      steps: [
        "Allowlist JWT algorithms and reject alg=none or key-confusion payloads.",
        "Store signing secrets server-side only; rotate weak or demo secrets.",
        "Return identical login errors for invalid username and password."
      ]
    },
    fixPrompt:
      "Our /auth/jwt.html lab exposes weaksecret and alg=none. Show secure JWT verification patterns.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnlab-a08-integrity-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "VulnLab A08 software integrity lab disclosed",
    description:
      "VulnLab Academy A08 module stores serialized pickle payloads in localStorage and exposes unsigned /api/update manifests.",
    impactOneline:
      "Public A08 integrity labs document unsafe deserialization and unsigned update channels.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnlabA08IntegrityEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never deserialize untrusted blobs; sign and verify all update manifests.",
      steps: [
        "Reject client-side deserialization of attacker-controlled pickle/JSON blobs.",
        "Sign software updates with Ed25519 or RSA and verify before applying.",
        "Use Subresource Integrity hashes on all third-party script tags."
      ]
    },
    fixPrompt:
      "Our A08 integrity lab stores pickle blobs in localStorage and serves unsigned updates. Show safe patterns.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnlab-a01-access-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "VulnLab A01 broken access control lab disclosed",
    description:
      "VulnLab Academy A01 module documents IDOR order probing, unauthenticated admin endpoints, and /api/files path traversal.",
    impactOneline:
      "Public A01 access-control labs advertise IDOR, privilege escalation, and path traversal training targets.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnlabA01AccessEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Enforce authorization on every object reference and validate file paths server-side.",
      steps: [
        "Bind object IDs to the authenticated user session before returning data.",
        "Require admin roles on /admin/* routes and deny by default.",
        "Reject path traversal sequences in file-serving endpoints."
      ]
    },
    fixPrompt:
      "Our A01 access-control lab exposes IDOR and unauthenticated admin routes. Show secure authorization patterns.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnlab-a02-crypto-evidence",
    platform: "generic",
    category: "Sensitive data exposure",
    severityDefault: "high",
    title: "VulnLab A02 cryptographic failures lab disclosed",
    description:
      "VulnLab Academy A02 module documents client-side secret leakage via window.__SECRET_KEY__ and weak MD5/base64 crypto samples.",
    impactOneline:
      "Public A02 crypto labs advertise hardcoded secrets and deprecated hash algorithms for scanner validation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnlabA02CryptoEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never embed secrets in client bundles; use modern password hashing.",
      steps: [
        "Store API keys server-side and proxy requests through authenticated backends.",
        "Replace MD5/SHA1 with Argon2id or bcrypt for password storage.",
        "Remove sample hashes and base64-encoded credentials from public HTML."
      ]
    },
    fixPrompt:
      "Our A02 crypto lab exposes window.__SECRET_KEY__ and MD5 samples. Show secure secret management.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnlab-a03-injection-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "VulnLab A03 injection lab disclosed",
    description:
      "VulnLab Academy A03 module documents reflected XSS, SQL error injection, and /api/ping command injection labs.",
    impactOneline:
      "Public A03 injection labs advertise XSS, SQLi, and OS command injection training endpoints.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnlabA03InjectionEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Use parameterized queries, output encoding, and shell argument allowlists.",
      steps: [
        "Escape user input before rendering into HTML DOM sinks.",
        "Use prepared statements instead of string-concatenated SQL.",
        "Never pass unsanitized input to shell commands or ping utilities."
      ]
    },
    fixPrompt:
      "Our A03 injection lab has reflected XSS and /api/ping command injection. Show input validation fixes.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnlab-a09-logging-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "high",
    title: "VulnLab A09 logging failures lab disclosed",
    description:
      "VulnLab Academy A09 module documents sensitive credentials in verbose error messages and newline log injection via an unauthenticated /api/log endpoint.",
    impactOneline:
      "Public A09 logging labs expose password leakage in errors and forgeable audit log lines for scanner validation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnlabA09LoggingEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never return stack traces or secrets in production errors; sanitize log input.",
      steps: [
        "Return generic error messages to clients and log details server-side only.",
        "Strip newlines and control characters from values written to audit logs.",
        "Require authentication before exposing verbose diagnostic endpoints."
      ]
    },
    fixPrompt:
      "Our A09 logging lab leaks DB passwords in errors. Show how to redact secrets and prevent log injection.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnlab-a10-ssrf-evidence",
    platform: "generic",
    category: "Server-side request forgery",
    severityDefault: "high",
    title: "VulnLab A10 SSRF scanner lab disclosed",
    description:
      "VulnLab Academy A10 module ships a URL fetcher at /api/fetch?url= with default cloud metadata probe targets for SSRF training.",
    impactOneline:
      "Public A10 SSRF labs advertise unvalidated server-side fetch endpoints reachable without authentication.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnlabA10SsrfEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Block server-side fetches to internal IPs, metadata endpoints, and private networks.",
      steps: [
        "Allowlist outbound fetch destinations instead of accepting arbitrary URLs.",
        "Deny RFC1918, link-local, and cloud metadata IP ranges at the egress layer.",
        "Require authentication before exposing URL preview or fetch utilities."
      ]
    },
    fixPrompt:
      "Our A10 SSRF lab accepts arbitrary URLs at /api/fetch. Show how to block metadata and internal targets.",
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
    slug: "client-side-overthewire-krypton-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "medium",
    title: "OverTheWire Krypton cryptography wargame disclosed",
    description:
      "OverTheWire Krypton teaches cryptography challenges on krypton.labs.overthewire.org with staged level progression.",
    impactOneline:
      "Public Krypton wargame pages document crypto exploit training surfaces for classical cipher and encoding challenges.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOverthewireKryptonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Krypton is intentional training — isolate wargame VMs from production networks.",
      steps: [
        "Run Krypton challenges only on dedicated training VMs.",
        "Do not reuse Krypton crypto weakness patterns in production systems.",
        "Rate-limit unauthenticated wargame enumeration."
      ]
    },
    fixPrompt:
      "We host OverTheWire Krypton-style crypto wargames. Show how to isolate challenge VMs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-overthewire-narnia-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "OverTheWire Narnia privilege-escalation wargame disclosed",
    description:
      "OverTheWire Narnia teaches SSH privilege-escalation challenges on narnia.labs.overthewire.org:2226 with narnia0 default credentials.",
    impactOneline:
      "Public Narnia wargame pages expose challenge structure and default credentials used to bootstrap the training chain.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOverthewireNarniaEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Narnia is intentional training — isolate wargame VMs from production networks.",
      steps: [
        "Run Narnia challenges only on dedicated training VMs with no production access.",
        "Rotate default wargame credentials if mirroring challenges internally.",
        "Do not copy privilege-escalation patterns into production systems."
      ]
    },
    fixPrompt:
      "We host OverTheWire Narnia-style privilege escalation labs. Show how to isolate wargame instances from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-overthewire-behemoth-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "OverTheWire Behemoth/Vortex/Manpage binary wargames disclosed",
    description:
      "OverTheWire Behemoth, Vortex, and Manpage wargames teach binary exploitation and code-audit challenges via SSH on behemoth.labs, vortex.labs, and manpage.labs hosts.",
    impactOneline:
      "Public Behemoth/Vortex/Manpage pages document binary exploit training surfaces with default level-0 credentials.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOverthewireBehemothEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Behemoth/Vortex/Manpage are intentional training — isolate wargame VMs from production.",
      steps: [
        "Run binary wargames only on dedicated training VMs.",
        "Do not expose default wargame credentials on public marketing pages.",
        "Rate-limit unauthenticated wargame enumeration."
      ]
    },
    fixPrompt:
      "We host OverTheWire Behemoth/Vortex/Manpage binary labs. Show how to isolate wargame VMs from production networks.",
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
    slug: "client-side-sec-code-educational-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Developer security & privacy lesson platform disclosed",
    description:
      "sec_code publishes interactive SQL injection and privacy training lessons with live query manipulation demos for developer education.",
    impactOneline:
      "Public sec_code lessons expose SQL injection walkthroughs and privacy principles attackers use to calibrate injection scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSecCodeEducationalEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Educational SQL injection demos belong in isolated training — never on production login forms.",
      steps: [
        "Use parameterized queries in all production authentication endpoints.",
        "Host developer security lessons on dedicated training domains.",
        "Remove interactive SQL concat demos from production-facing pages."
      ]
    },
    fixPrompt:
      "We publish developer security lessons with SQL injection demos. Show how to isolate training from production auth flows.",
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
    slug: "client-side-secured-ai-lab-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "SecuredAI Lab OWASP agentic security playground disclosed",
    description:
      "SecuredAI Lab publishes interactive OWASP ASI modules covering agent goal hijacking, tool misuse, and privilege abuse with vulnerable/secure agent toggles.",
    impactOneline:
      "Public agentic AI security labs document ASI attack chains attackers use to probe LLM agent guardrails.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideSecuredAiLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Agentic security labs are intentional — isolate ASI demos from production agent deployments.",
      steps: [
        "Never expose production agent system prompts in client-visible playgrounds.",
        "Gate agent tool access with least-privilege policies and human-in-the-loop approval.",
        "Log and rate-limit goal-hijack and prompt-injection probes on public agent endpoints."
      ]
    },
    fixPrompt:
      "We host a SecuredAI Lab-style OWASP ASI agent security playground. Show how to isolate agent demos and block goal-hijack attacks.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-gitagent-securebot-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "GitAgent SecureBot autonomous repo scanner disclosed",
    description:
      "GitAgent SecureBot advertises an OWASP Top 10 repo scanner with CWE-tagged findings, custom scan_file/find_secrets tools, and a bundled vulnerable Node.js demo target.",
    impactOneline:
      "Public AI security scanners document autonomous agent pipelines and demo vulnerable codebases attackers can probe.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideGitagentSecurebotEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "SecureBot demo scanners are intentional — isolate bundled vulnerable repos from production networks.",
      steps: [
        "Never expose demo vulnerable Node.js targets on public URLs without auth.",
        "Gate autonomous scanner agents behind authenticated workspaces.",
        "Rotate any API keys used by scanner/fix agent pipelines."
      ]
    },
    fixPrompt:
      "We host a GitAgent SecureBot-style autonomous repo scanner with bundled vulnerable demo code. Show how to isolate demo targets and gate agent tool access.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-airt-academy-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "AIRT AI Red Team Academy course disclosed",
    description:
      "AIRT (AI Red Team Academy) publishes a free open-source offensive AI security curriculum covering prompt injection, RAG pipelines, multi-agent systems, and supply-chain attacks with Docker-based labs.",
    impactOneline:
      "Public AI red-team course pages document prompt-injection and LLM attack lab modules attackers can use to tune scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAirtAcademyEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "AIRT Docker labs are intentional training — isolate lab environments from production AI systems.",
      steps: [
        "Run AIRT vulnerable chatbot labs on private networks only.",
        "Gate module lab downloads behind authenticated training portals on private deployments.",
        "Never expose Ollama or vector-database lab targets to the public internet without access controls."
      ]
    },
    fixPrompt:
      "We host an AIRT-style AI red-team training academy with Docker labs. Show how to isolate vulnerable LLM lab targets from production agent deployments.",
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
    slug: "client-side-bug-collection-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "BUG Collection OWASP Top 10 training app disclosed",
    description:
      "BUG Collection (valentin-panov/bug-collection) is an intentionally vulnerable React/Next/MongoDB app with markup injection, NoSQL/SQLi, broken access control, and prototype-pollution test modules.",
    impactOneline:
      "Public BUG Collection instances document OWASP Top 10 flaw patterns attackers can replay against production React/Next APIs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBugCollectionEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "BUG Collection is intentional training — never deploy similar injection or access-control flaws to production.",
      steps: [
        "Run BUG Collection only on isolated lab infrastructure with no production data.",
        "Remove testLib injection modules and hardcoded secrets from production bundles.",
        "Enforce authorization on every /api route before exposing dashboard data."
      ]
    },
    fixPrompt:
      "We host a BUG Collection-style vulnerable Next.js training app. Show how to isolate testLib labs and fix MongoDB injection on production APIs.",
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
    slug: "client-side-hacksplaining-sql-injection-lesson-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "Hacksplaining SQL injection lesson disclosed",
    description:
      "Hacksplaining /lessons/sql-injection publishes an interactive exploit-then-fix walkthrough covering database query manipulation, injection-vulnerability steps, and server-error oracles.",
    impactOneline:
      "Public SQL injection lesson pages document query-concatenation exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingSqlInjectionLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining SQLi lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable SQL injection lesson instances on private deployments.",
        "Use parameterized queries in production — never copy Hacksplaining vulnerable query builders.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style SQL injection exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-host-header-poisoning-lesson-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "high",
    title: "Hacksplaining host header poisoning lesson disclosed",
    description:
      "Hacksplaining /lessons/host-header-poisoning publishes an interactive exploit-then-fix walkthrough covering untrusted Host header values and cache-poisoning attack chains.",
    impactOneline:
      "Public host header poisoning lesson pages document cache-poisoning exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingHostHeaderPoisoningLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining host header lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable host header poisoning lesson instances on private deployments.",
        "Validate Host headers against an allowlist in production — never trust client-supplied Host values.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style host header poisoning exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-csrf-lesson-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Hacksplaining CSRF lesson disclosed",
    description:
      "Hacksplaining /lessons/csrf publishes an interactive exploit-then-fix walkthrough covering forged cross-site requests, cross-domain request abuse, and authenticated action hijacking.",
    impactOneline:
      "Public CSRF lesson pages document session-riding exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingCsrfLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining CSRF lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable CSRF lesson instances on private deployments.",
        "Use synchronizer tokens or SameSite cookies in production — never copy Hacksplaining vulnerable forms.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style CSRF exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-ssrf-lesson-evidence",
    platform: "generic",
    category: "Server-side request forgery",
    severityDefault: "high",
    title: "Hacksplaining SSRF lesson disclosed",
    description:
      "Hacksplaining /lessons/ssrf publishes an interactive exploit-then-fix walkthrough covering arbitrary-domain fetches, internal-network probing, and cloud metadata abuse.",
    impactOneline:
      "Public SSRF lesson pages document server-side fetch exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingSsrfLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining SSRF lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable SSRF lesson instances on private deployments.",
        "Blocklist internal IP ranges and metadata URLs in production fetchers — never copy Hacksplaining vulnerable proxies.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style SSRF exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-xss-reflected-lesson-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "Hacksplaining reflected XSS lesson disclosed",
    description:
      "Hacksplaining /lessons/xss-reflected publishes an interactive exploit-then-fix walkthrough covering URL-reflected script injection, crafting malicious links, and session hijacking.",
    impactOneline:
      "Public reflected XSS lesson pages document URL-bounce exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingXssReflectedLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining XSS lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable reflected XSS lesson instances on private deployments.",
        "Encode all user-supplied output in production — never copy Hacksplaining vulnerable echo handlers.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style reflected XSS exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-xss-stored-lesson-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "Hacksplaining stored XSS lesson disclosed",
    description:
      "Hacksplaining /lessons/xss-stored publishes an interactive exploit-then-fix walkthrough covering persistent user-content script injection and stored payload delivery.",
    impactOneline:
      "Public stored XSS lesson pages document persistent user-content exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingXssStoredLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining stored XSS lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable stored XSS lesson instances on private deployments.",
        "Sanitize and encode all user-generated content in production — never copy Hacksplaining vulnerable storage handlers.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style stored XSS exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hacksplaining-clickjacking-lesson-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Hacksplaining clickjacking lesson disclosed",
    description:
      "Hacksplaining /lessons/click-jacking publishes an interactive exploit-then-fix walkthrough covering iframe UI redress, transparent overlays, and stolen-click attacks.",
    impactOneline:
      "Public clickjacking lesson pages document UI-redress exploit patterns for unauthenticated security training.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHacksplainingClickjackingLessonEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Hacksplaining clickjacking lessons are intentional training — gate live lesson instances behind authentication.",
      steps: [
        "Require login before serving runnable clickjacking lesson instances on private deployments.",
        "Set X-Frame-Options or CSP frame-ancestors in production — never copy Hacksplaining vulnerable framing handlers.",
        "Rate-limit unauthenticated probing of lesson step endpoints on self-hosted mirrors."
      ]
    },
    fixPrompt:
      "We mirror Hacksplaining-style clickjacking exploit-then-fix lessons. Show how to auth-gate live lesson instances on private deployments.",
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
    slug: "client-side-flask-vulnapp-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "VulnApp intentionally vulnerable Flask practice app disclosed",
    description:
      "VulnApp (web-security-practice-app) is a deliberately vulnerable Flask application with SQL injection on login/register forms and stored XSS in an unescaped comment system.",
    impactOneline:
      "Public VulnApp instances expose Flask SQLi and XSS training surfaces attackers use to calibrate scanners.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideFlaskVulnappEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "VulnApp is intentional training — never deploy similar vulnerable Flask routes to production.",
      steps: [
        "Run VulnApp only on isolated lab infrastructure.",
        "Use parameterized queries and Jinja2 autoescape in production Flask apps.",
        "HTML-encode all user-controlled output in comment and search templates."
      ]
    },
    fixPrompt:
      "We host VulnApp-style Flask training apps. Show how to fix SQLi on login forms and stored XSS in comment systems.",
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
  },
  {
    slug: "client-side-aikido-zen-demo-evidence",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "Aikido Zen live security demo disclosed",
    description:
      "Zen by Aikido fly.dev demo exercises rate limiting, bot blocking, user blocking, LLM proxy endpoints, and attack-wave .env probing for WAF evaluation.",
    impactOneline:
      "Public Zen security demos document attack-simulation endpoints attackers study for bypassing rate limits and bot defenses.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAikidoZenDemoEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Zen demos are intentional — never expose attack-wave or LLM test endpoints on production hosts.",
      steps: [
        "Run Zen evaluation demos only on isolated fly.dev or lab infrastructure.",
        "Block unauthenticated /.env enumeration probes at the edge.",
        "Rate-limit and bot-filter LLM proxy test routes in staging environments."
      ]
    },
    fixPrompt:
      "We host an Aikido Zen-style security evaluation demo. Show how to isolate rate-limit and bot-blocking test endpoints from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-attp-agent-trust-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "ATTP Agent Trust Transport Protocol demo disclosed",
    description:
      "ATTP live demo documents the IETF Agent Trust Transport Protocol — a cryptographically signed synchronous transport layer for AI agent security.",
    impactOneline:
      "Public ATTP demos expose agent-trust protocol surfaces relevant to LLM agent authentication and transport security research.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideAttpAgentTrustEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "ATTP demos are research infrastructure — gate agent transport endpoints behind authentication.",
      steps: [
        "Require mutual authentication on all agent transport channels in production.",
        "Do not expose unsigned agent message relays on public fly.dev hosts.",
        "Monitor agent transport endpoints for unauthorized protocol probing."
      ]
    },
    fixPrompt:
      "We host an ATTP-style agent trust transport demo. Show how to authenticate agent wire-protocol endpoints in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-bugzap-prompt-defense-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "BugZap prompt-injection defense demo disclosed",
    description:
      "BugZap vercel.app publishes an interactive Next.js demo for basic prompt-injection prevention and LLM application hardening.",
    impactOneline:
      "Public BugZap demos document LLM input-sanitization patterns attackers study to bypass prompt-injection defenses.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBugzapPromptDefenseEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "BugZap is a training demo — never ship unauthenticated LLM chat endpoints without server-side guardrails.",
      steps: [
        "Validate and sanitize all user prompts server-side before forwarding to LLM providers.",
        "Isolate prompt-injection defense demos on lab-only Vercel deployments.",
        "Rate-limit and authenticate LLM proxy routes exposed by Next.js API handlers."
      ]
    },
    fixPrompt:
      "We host a BugZap-style Next.js prompt-injection defense demo. Show how to gate LLM proxy routes and sanitize user prompts server-side.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-redlockx-prompt-firewall-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "RedLockX prompt-injection firewall demo disclosed",
    description:
      "RedLockX vercel.app documents a hybrid + DeBERTa-v3 ML pipeline for real-time prompt-injection and jailbreak detection.",
    impactOneline:
      "Public RedLockX demos expose adversarial prompt-classification surfaces attackers probe to evade LLM guardrails.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideRedlockxPromptFirewallEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "RedLockX is a guardrail research demo — do not expose unauthenticated prompt-classification APIs in production.",
      steps: [
        "Authenticate all prompt-scoring endpoints before accepting user text.",
        "Run ML guardrail demos on isolated infrastructure, not production LLM apps.",
        "Monitor for jailbreak probe patterns against public classifier endpoints."
      ]
    },
    fixPrompt:
      "We host a RedLockX-style prompt-injection firewall demo. Show how to authenticate ML guardrail endpoints and isolate them from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-rogue-studio-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "high",
    title: "Rogue Studio uncensored security-research IDE disclosed",
    description:
      "Rogue Studio vercel.app advertises an autonomous AI IDE with zero safety filters, exploit modes, payload forging, and Tor/IPFS tooling for penetration testers.",
    impactOneline:
      "Public Rogue Studio demos document unrestricted agentic exploit workflows relevant to autonomous offensive-security tooling.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideRogueStudioEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Rogue Studio is intentional research infrastructure — never deploy uncensored agent loops on internet-facing hosts.",
      steps: [
        "Air-gap autonomous security-research IDEs from production networks.",
        "Require authentication before exposing agentic exploit or payload-forge modes.",
        "Audit Tor/Ollama bootstrap scripts for outbound network access on shared hosts."
      ]
    },
    fixPrompt:
      "We host a Rogue Studio-style autonomous security-research IDE. Show how to air-gap uncensored agent modes from production infrastructure.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-haozi-xss-challenge-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "haozi XSS challenge playground documents client-side XSS levels",
    description:
      "xss.haozi.me (xss-demo) is a Vue SPA where each level requires user-supplied code to pop alert(1) via innerHTML and other DOM sinks.",
    impactOneline:
      "Public haozi XSS challenges teach reusable DOM XSS gadget patterns attackers replay against production SPAs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHaoziXssChallengeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "haozi XSS is intentional training — never copy its eval/innerHTML challenge patterns into production.",
      steps: [
        "Keep XSS challenge SPAs on isolated lab domains, not production apps.",
        "Replace innerHTML assignments with textContent or DOMPurify-sanitized HTML.",
        "Disable unsafe-eval CSP exceptions outside classroom environments."
      ]
    },
    fixPrompt:
      "We host haozi-style XSS challenge levels that require alert(1). Show safe textContent alternatives and CSP hardening for Vue SPAs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-insaits-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "InsAIts multi-agent runtime security monitor disclosed",
    description:
      "InsAIts-public documents 30 anomaly detectors with OWASP MCP Top 10 coverage for tool poisoning, hallucination, and multi-agent AI sessions.",
    impactOneline:
      "Public InsAIts demos expose MCP runtime-security surfaces attackers probe for tool-poisoning and agent hijack chains.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideInsAItsEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "InsAIts is a security monitor demo — authenticate MCP tool calls and validate agent session boundaries in production.",
      steps: [
        "Require authentication before exposing MCP tool registries or anomaly dashboards.",
        "Validate tool-call arguments server-side to block poisoning payloads.",
        "Run multi-agent security demos on isolated infrastructure, not production LLM apps."
      ]
    },
    fixPrompt:
      "We document InsAIts-style multi-agent runtime monitoring with OWASP MCP Top 10 coverage. Show how to authenticate MCP endpoints and block tool-poisoning.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-genai-security-crosswalk-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "OWASP GenAI Security Crosswalk framework mapper disclosed",
    description:
      "GenAI Security Crosswalk maps NIST AI RMF and OWASP LLM controls with incident recipes and tool guidance for GenAI risk management.",
    impactOneline:
      "Public GenAI crosswalk explorers document LLM security control gaps attackers use to prioritize prompt-injection and data-leak targets.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideGenaiSecurityCrosswalkEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "GenAI crosswalk is educational — do not expose unauthenticated incident-recipe APIs on production domains.",
      steps: [
        "Gate GenAI security tooling behind authentication when self-hosting.",
        "Apply OWASP LLM Top 10 controls before publishing framework-mapping UIs.",
        "Remove sample API keys or incident payloads from public crosswalk demos."
      ]
    },
    fixPrompt:
      "We host a GenAI Security Crosswalk mapping NIST and OWASP LLM controls. Show how to authenticate incident-recipe endpoints and scrub demo secrets.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-pwning-juice-shop-companion-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Pwning OWASP Juice Shop companion guide disclosed",
    description:
      "pwning.owasp-juice.shop documents official Juice Shop challenge-hunting walkthroughs spanning XSS, SQLi, IDOR, auth bypass, and insecure deserialization oracles.",
    impactOneline:
      "Public Pwning Juice Shop companion chapters expose step-by-step exploit oracles attackers use to calibrate scanners against Juice Shop benchmarks.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePwningJuiceShopCompanionEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Pwning Juice Shop is intentional training — host companion docs separately from production apps.",
      steps: [
        "Run Juice Shop demo instances only on isolated lab infrastructure.",
        "Do not mirror companion-guide exploit payloads in production codebases.",
        "Use challenge solutions for scanner tuning, not as production security baselines."
      ]
    },
    fixPrompt:
      "We publish Pwning OWASP Juice Shop companion walkthroughs. Show how to keep demo instances isolated from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-ziran-agent-security-evidence",
    platform: "generic",
    category: "AI security",
    severityDefault: "medium",
    title: "ZIRAN AI agent security testing framework disclosed",
    description:
      "ZIRAN docs describe knowledge-graph tool-chain analysis, multi-phase campaigns, and autonomous pentesting for AI agent security evaluation.",
    impactOneline:
      "Public ZIRAN documentation exposes agentic attack-surface analysis patterns applicable to MCP and multi-tool AI deployments.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideZiranAgentSecurityEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "ZIRAN is a security-testing framework — authenticate agent endpoints and validate tool chains in production.",
      steps: [
        "Gate MCP and agent tool endpoints behind authentication.",
        "Audit tool-chain compositions for privilege-escalation paths.",
        "Run ZIRAN-style red-team exercises only in isolated agent sandboxes."
      ]
    },
    fixPrompt:
      "We document ZIRAN-style AI agent security testing with tool-chain analysis. Show how to authenticate MCP endpoints and audit dangerous tool compositions.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-dotnet-serialization-lab-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: ".NET serialization training lab with Juice Shop exercises disclosed",
    description:
      "johniwasz rce-serialization-dotnet documents Juice Shop CSP bypass, SQL injection, password cracking, and mass-assignment pentest walkthroughs.",
    impactOneline:
      "Public .NET serialization lab pages teach Juice Shop exploit chains including CSP weaknesses and API mass-assignment oracles.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideDotnetSerializationLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Serialization labs are intentional training — never expose unsafe deserialization endpoints in production.",
      steps: [
        "Disable unsafe .NET deserialization gadgets in production APIs.",
        "Validate JSON mass-assignment with explicit allowlists.",
        "Run Juice Shop exercises only against isolated demo instances."
      ]
    },
    fixPrompt:
      "We host .NET serialization training with Juice Shop CSP/SQLi/mass-assignment exercises. Show how to block unsafe deserialization and mass assignment in production APIs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-povzayd-xss-labs-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "povzayd XSS LABS interactive training platform disclosed",
    description:
      "povzayd XSS LABS publishes browser-side reflected, stored, and DOM XSS exercises with payload simulation for pentester and learner practice.",
    impactOneline:
      "Public povzayd XSS LABS document client-side XSS simulation modules attackers use to practice filter bypasses.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSidePovzaydXssLabsEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "povzayd XSS LABS are intentional training — isolate lab pages from production applications.",
      steps: [
        "Run XSS training labs only on dedicated lab infrastructure.",
        "Encode and sanitize all user-controlled output in HTML contexts.",
        "Use Content-Security-Policy to mitigate XSS in production apps."
      ]
    },
    fixPrompt:
      "We host povzayd-style XSS training labs. Show how to isolate reflected and DOM XSS exercises from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-juice-shop-vapt-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Juice Shop VAPT exploitation write-up hub disclosed",
    description:
      "lucky-cyber3008 juice-shop-vapt documents Juice Shop SQLi, XSS, IDOR, and sensitive-data exploitation walkthroughs with Burp Suite PoC screenshots.",
    impactOneline:
      "Public Juice Shop VAPT reports expose step-by-step exploit oracles attackers use to calibrate scanners against Juice Shop benchmarks.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideJuiceShopVaptEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Juice Shop VAPT write-ups are intentional training — host demo instances in isolated lab networks only.",
      steps: [
        "Run Juice Shop demo instances only on dedicated lab infrastructure.",
        "Do not mirror VAPT exploit payloads in production codebases.",
        "Use write-up taxonomy for scanner tuning, not as production security baselines."
      ]
    },
    fixPrompt:
      "We publish Juice Shop VAPT exploitation write-ups. Show how to keep demo instances isolated from production apps.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-openvault-learn-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "OpenVault Bank OWASP API Top 10 learn lab disclosed",
    description:
      "OpenVault Bank /learn documents BOLA, mass assignment, and excessive data exposure modules with OWASP API1/API6 endpoint oracles for hands-on API security training.",
    impactOneline:
      "Public OpenVault Bank learn pages expose deliberate API vulnerability walkthroughs attackers use to tune scanners against banking API benchmarks.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOpenvaultLearnEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "OpenVault Bank learn labs are intentional training — host demo instances in isolated lab networks only.",
      steps: [
        "Run OpenVault Bank demo instances only on dedicated lab infrastructure.",
        "Do not mirror learn-page API exploit oracles in production banking APIs.",
        "Use learn modules for scanner tuning, not as production security baselines."
      ]
    },
    fixPrompt:
      "We host OpenVault Bank API security training labs. Show how to isolate /learn demo instances from production APIs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-openvault-cheatsheet-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "OpenVault Bank API security tooling cheatsheet disclosed",
    description:
      "OpenVault Bank /cheatsheet lists APIsec Bolt, Burp Suite, Postman, and OWASP ZAP workflows for practicing BOLA and mass-assignment attacks against the vulnerable banking API.",
    impactOneline:
      "Public cheatsheet pages document API pen-test tooling and attack workflows attackers reuse against production banking APIs.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideOpenvaultCheatsheetEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "OpenVault Bank cheatsheet is intentional training — host demo instances in isolated lab networks only.",
      steps: [
        "Run OpenVault Bank demo instances only on dedicated lab infrastructure.",
        "Do not mirror cheatsheet API attack workflows in production banking APIs.",
        "Use cheatsheet tooling guidance for scanner tuning, not as production security baselines."
      ]
    },
    fixPrompt:
      "We host OpenVault Bank API security cheatsheet pages. Show how to isolate /cheatsheet demo instances from production APIs.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-cookiejar-lab-evidence",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "medium",
    title: "CookieJar session-security training lab disclosed",
    description:
      "CookieJar lab homepage documents hands-on session hijack training — stolen cookies bypass passwords, 2FA, and OAuth — with an interactive /demo replay walkthrough.",
    impactOneline:
      "Public CookieJar lab pages teach session token theft and replay patterns reusable against production session management.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideCookiejarLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "CookieJar is an intentional training lab — gate demos behind auth and isolate from production.",
      steps: [
        "Require authentication before serving session hijack demo pages.",
        "Set HttpOnly, Secure, and SameSite on all session cookies in production.",
        "Run CookieJar demos only on isolated lab infrastructure."
      ]
    },
    fixPrompt:
      "We host CookieJar session-security training labs. Show how to gate /demo behind auth and harden session cookies in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-benstafford-xss-demo-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "Ben Stafford XSS Demo documents query-parameter DOM XSS",
    description:
      "xss.benstafford.dev publishes attack1.html labs where URLSearchParams username flows into innerHTML, plus document.cookie session exfiltration walkthroughs.",
    impactOneline:
      "Public XSS Demo pages teach query-parameter DOM XSS and session theft patterns reusable against production apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideBenstaffordXssDemoEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never assign URL parameters to innerHTML; use textContent and HttpOnly session cookies.",
      steps: [
        "Replace innerHTML with textContent when rendering user-controlled strings.",
        "Set HttpOnly and Secure flags on all session cookies.",
        "Host XSS training demos on isolated lab subdomains, not production apps."
      ]
    },
    fixPrompt:
      "Our attack1.html demo assigns query username to innerHTML. Show safe textContent rendering and HttpOnly cookie hardening.",
    version: 1,
    enabled: true
  },
  {
    slug: "domgo-referrer-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DomGoat referrer-driven DOM XSS exercise disclosed",
    description:
      "DomGoat /cxss/example pages assign document.referrer query parameters to msgboard.innerHTML — a deliberate referrer-based DOM XSS lab.",
    impactOneline:
      "Referrer-to-innerHTML flows enable DOM XSS when attackers control the Referer header on victim navigation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "domgoReferrerDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never render document.referrer into innerHTML; sanitize or ignore referrer data in DOM sinks.",
      steps: [
        "Use textContent instead of innerHTML for referrer-derived strings.",
        "Validate referrer URLs against an allowlist before display.",
        "Host DomGoat-style labs on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "Our DomGoat exercise writes document.referrer into msgboard.innerHTML. Show safe alternatives and referrer validation.",
    version: 1,
    enabled: true
  },
  {
    slug: "domgo-hash-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DomGoat hash-fragment DOM XSS exercise disclosed",
    description:
      "DomGoat /cxss/example pages assign location.hash fragments to msgboard.innerHTML — deliberate hash-based DOM XSS labs.",
    impactOneline:
      "Hash-to-innerHTML flows enable DOM XSS when attackers craft malicious URL fragments victims open.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "domgoHashDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never render location.hash into innerHTML; use textContent or strict sanitization.",
      steps: [
        "Use textContent instead of innerHTML for hash-derived strings.",
        "Validate and encode hash fragments before DOM insertion.",
        "Host DomGoat-style labs on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "Our DomGoat exercise writes location.hash into msgboard.innerHTML. Show safe textContent alternatives.",
    version: 1,
    enabled: true
  },
  {
    slug: "domgo-postmessage-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DomGoat postMessage DOM XSS exercise disclosed",
    description:
      "DomGoat /cxss/example pages assign postMessage event data to msgboard.innerHTML — deliberate cross-window DOM XSS labs.",
    impactOneline:
      "postMessage-to-innerHTML flows enable DOM XSS when pages accept untrusted message payloads.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "domgoPostMessageDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Validate postMessage origin and never render evt.data into innerHTML without sanitization.",
      steps: [
        "Check event.origin against an allowlist before processing postMessage data.",
        "Use textContent instead of innerHTML for message payloads.",
        "Host DomGoat-style labs on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "Our DomGoat exercise writes postMessage evt.data into msgboard.innerHTML. Show origin validation and safe rendering.",
    version: 1,
    enabled: true
  },
  {
    slug: "domgo-localstorage-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DomGoat localStorage DOM XSS exercise disclosed",
    description:
      "DomGoat /cxss/example pages read localStorage payloads into msgboard.innerHTML — deliberate client-storage DOM XSS labs.",
    impactOneline:
      "localStorage-to-innerHTML flows enable stored DOM XSS when poisoned values are rendered unsafely.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "domgoLocalStorageDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never render localStorage values into innerHTML; treat stored client data as untrusted input.",
      steps: [
        "Use textContent instead of innerHTML for localStorage-derived strings.",
        "Sanitize stored payloads before DOM insertion.",
        "Host DomGoat-style labs on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "Our DomGoat exercise reads localStorage into msgboard.innerHTML. Show safe rendering and input validation.",
    version: 1,
    enabled: true
  },
  {
    slug: "domgo-ajax-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DomGoat AJAX response DOM XSS exercise disclosed",
    description:
      "DomGoat /cxss/example pages fetch JSON via XHR and assign response payloads to msgboard.innerHTML — deliberate AJAX-driven DOM XSS labs.",
    impactOneline:
      "AJAX-to-innerHTML flows enable DOM XSS when server responses include attacker-controlled strings rendered unsafely.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "domgoAjaxDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never render AJAX/JSON response fields into innerHTML; use textContent or strict sanitization.",
      steps: [
        "Use textContent instead of innerHTML for XHR/fetch response data.",
        "Validate and encode JSON fields before DOM insertion.",
        "Host DomGoat-style labs on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "Our DomGoat exercise writes XHR JSON response payloads into msgboard.innerHTML. Show safe textContent alternatives.",
    version: 1,
    enabled: true
  },
  {
    slug: "domgo-websocket-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DomGoat WebSocket message DOM XSS exercise disclosed",
    description:
      "DomGoat /cxss/example pages assign WebSocket onmessage payloads to msgboard.innerHTML — deliberate real-time DOM XSS labs.",
    impactOneline:
      "WebSocket-to-innerHTML flows enable DOM XSS when message payloads are rendered without validation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "domgoWebsocketDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Validate WebSocket message payloads and never render them into innerHTML without sanitization.",
      steps: [
        "Authenticate and validate WebSocket message schema before processing.",
        "Use textContent instead of innerHTML for WebSocket payloads.",
        "Host DomGoat-style labs on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "Our DomGoat exercise writes WebSocket message payloads into msgboard.innerHTML. Show safe rendering and message validation.",
    version: 1,
    enabled: true
  },
  {
    slug: "domgo-query-param-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DomGoat URL query-parameter DOM XSS exercise disclosed",
    description:
      "DomGoat /cxss/example pages parse location.href query strings and window.name into msgboard.innerHTML — deliberate URL-parameter DOM XSS labs.",
    impactOneline:
      "Query-parameter-to-innerHTML flows enable DOM XSS when URL parameters are rendered without encoding.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "domgoQueryParamDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never render location.href query parameters into innerHTML; use textContent or strict encoding.",
      steps: [
        "Use textContent instead of innerHTML for URL-derived strings.",
        "Validate query parameter names and values against an allowlist.",
        "Host DomGoat-style labs on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "Our DomGoat exercise parses location.href query parameters into msgboard.innerHTML. Show safe encoding alternatives.",
    version: 1,
    enabled: true
  },
  {
    slug: "domgo-hash-sanitization-bypass-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DomGoat hash sanitization-bypass DOM XSS exercise disclosed",
    description:
      "DomGoat /cxss/example pages unescape location.hash then apply weak replace() filters before msgboard.innerHTML — deliberate sanitization-bypass DOM XSS labs.",
    impactOneline:
      "Weak hash sanitization before innerHTML still enables DOM XSS when filters miss attack vectors.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "domgoHashSanitizationBypassDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never rely on partial replace() sanitization before innerHTML; use textContent or a strict HTML sanitizer.",
      steps: [
        "Use textContent instead of innerHTML for hash-derived strings.",
        "Apply allowlist encoding rather than blacklist replace() filters.",
        "Host DomGoat-style labs on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "Our DomGoat exercise unescapes location.hash with weak replace() then writes to msgboard.innerHTML. Show safe encoding alternatives.",
    version: 1,
    enabled: true
  },
  {
    slug: "domgo-window-name-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DomGoat window.name + hash DOM XSS exercise disclosed",
    description:
      "DomGoat /cxss/example pages concatenate location.hash and window.name into msgboard.innerHTML — deliberate multi-source DOM XSS labs.",
    impactOneline:
      "Combining window.name and hash fragments into innerHTML enables DOM XSS via cross-page name poisoning.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "domgoWindowNameDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never render window.name or hash fragments into innerHTML; treat both as untrusted attacker input.",
      steps: [
        "Use textContent instead of innerHTML for window.name and hash-derived strings.",
        "Clear window.name on navigation and avoid reading it for DOM rendering.",
        "Host DomGoat-style labs on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "Our DomGoat exercise concatenates location.hash and window.name into msgboard.innerHTML. Show safe rendering alternatives.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-xss-page-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "medium",
    title: "XSS.page interactive payload playground disclosed",
    description:
      "XSS.page playground exposes filter/context XSS payload tester, cheat sheet, and ethical-use guidelines for authorized security training.",
    impactOneline:
      "Public XSS playgrounds document filter-bypass techniques attackers reuse against production apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideXssPageEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Host XSS training playgrounds on isolated domains, not production infrastructure.",
      steps: [
        "Restrict playground access to authenticated lab users.",
        "Do not mirror production filter logic on public training pages.",
        "Add robots noindex and separate from customer-facing apps."
      ]
    },
    fixPrompt:
      "Our site hosts an XSS.page-style payload playground. Show how to isolate it from production and restrict access.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hackthissite-realistic-mission-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "HackThisSite Realistic mission hub login-gated",
    description:
      "HackThisSite /missions/realistic/ hub documents advanced wargame challenges behind authenticated access with Login Required gate.",
    impactOneline:
      "Realistic mission category signals advanced SQLi, XSS, and auth bypass labs requiring HTS account access.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHackThisSiteRealisticMissionEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Wargame realistic missions are intentional — isolate challenge VMs from production networks.",
      steps: [
        "Require authentication before serving realistic mission challenge instances.",
        "Never copy realistic mission vulnerability patterns into production code.",
        "Rate-limit unauthenticated probing of mission hub endpoints."
      ]
    },
    fixPrompt:
      "We mirror HackThisSite Realistic mission hubs. Show how to auth-gate advanced wargame challenges on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "domgo-sinks-catalog-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DomGoat XSS sinks catalog with eval/innerHTML/document.write demos",
    description:
      "DomGoat /cxss/sinks page catalogs interactive eval(), innerHTML, document.write, and document.writeln XSS sink demonstrations.",
    impactOneline:
      "Public sink catalogs teach attackers which DOM APIs to target for code execution in client-side apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "domgoSinksCatalogDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never expose interactive XSS sink playgrounds on production domains.",
      steps: [
        "Use textContent instead of innerHTML for untrusted strings.",
        "Avoid eval(), document.write, and document.writeln with user-controlled input.",
        "Host DomGoat-style labs on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "Our DomGoat /cxss/sinks page demos eval() and innerHTML sinks. Show safe alternatives and lab isolation.",
    version: 1,
    enabled: true
  },
  {
    slug: "domgo-sources-catalog-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "DomGoat XSS sources catalog with location/postMessage/WebSocket demos",
    description:
      "DomGoat /cxss/sources page catalogs URL-based DOM property sources (location.*, document.referrer) plus postMessage, WebSocket, and AJAX live source demos.",
    impactOneline:
      "Public source catalogs teach attackers which client-side inputs can feed DOM XSS sinks.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "domgoSourcesCatalogDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Never expose interactive XSS source playgrounds on production domains.",
      steps: [
        "Validate and encode all URL fragments, query params, and referrer values before DOM insertion.",
        "Verify postMessage origin before handling untrusted payloads.",
        "Host DomGoat-style labs on isolated training infrastructure."
      ]
    },
    fixPrompt:
      "Our DomGoat /cxss/sources page demos location.hash and postMessage sources. Show safe handling and lab isolation.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vwad-wackopicko-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "OWASP VWAD WackoPicko scanner benchmark lab disclosed",
    description:
      "WackoPicko VWAD listing documents XSS, SQLi, directory traversal, and command injection labs from the Why Johnny Can't Pentest scanner benchmark.",
    impactOneline:
      "Public WackoPicko registry advertises multi-class vulnerability training surfaces for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVwadWackopickoEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Keep WackoPicko instances isolated; VWAD listing is intentional but live deployments need monitoring.",
      steps: [
        "Deploy WackoPicko only on isolated lab networks.",
        "Require authentication when exposing scanner benchmark apps publicly.",
        "Monitor VWAD-linked instances for abuse."
      ]
    },
    fixPrompt:
      "Our WackoPicko instance is listed in OWASP VWAD. Show how to isolate scanner benchmark labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vwad-bodgeit-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "OWASP VWAD BodgeIt Store beginner pen-test lab disclosed",
    description:
      "BodgeIt Store VWAD listing documents XSS, SQL injection, CSRF, hidden content, and logic-flaw challenges for beginner penetration testing.",
    impactOneline:
      "Public BodgeIt registry advertises multi-vulnerability Java/JSP training app for unauthenticated practice.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVwadBodgeitEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Keep BodgeIt instances isolated; VWAD listing is intentional but live deployments need monitoring.",
      steps: [
        "Deploy BodgeIt only on isolated lab Tomcat instances.",
        "Require authentication when exposing beginner pen-test apps publicly.",
        "Monitor VWAD-linked instances for abuse."
      ]
    },
    fixPrompt:
      "Our BodgeIt Store instance is listed in OWASP VWAD. Show how to isolate beginner pen-test labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hts-realistic-mission-lab-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "high",
    title: "HackThisSite Realistic mission instance lab disclosed",
    description:
      "HTS Realistic mission pages expose Uncle Arnold vote.php SQLi, defacement challenges, Fischer products.php SQLi labs, XECryption ciphertext oracles, political blog comment injection, U.B.O.A login bypass, Holy Word student.php grades, BudgetSERV page.pl CGI hosting, Heartland internet.pl SSRF, Elbonia ENRP members.php roster, Yuppers! search.cgi portal, secuLas Ltd. products.php defense catalog, Simple Mail index.php?module= auth labs, or Compu-global-Hyper-Mega-Net frameset challenges.",
    impactOneline:
      "Public realistic mission instances expose SQLi and legacy web challenge surfaces without authentication.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHtsRealisticMissionLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Auth-gate realistic mission instances; never copy HTS challenge patterns into production.",
      steps: [
        "Require HTS login before serving realistic mission challenge VMs.",
        "Parameterize SQL queries in any products.php-style catalog endpoints.",
        "Isolate wargame mission infrastructure from production networks."
      ]
    },
    fixPrompt:
      "We host HTS-style realistic mission labs with products.php SQLi. Show parameterized queries and auth gating.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hts-login-gated-mission-hub-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "HackThisSite login-gated mission category hub disclosed",
    description:
      "HTS Basic, Application, Forensic, Javascript, Programming, Extended Basic, or Steganography mission hubs return Login Required or require_auth — documenting challenge categories behind authenticated wargame access. Indexed mission instance URLs that return 404 still disclose forensic/javascript/programming/stego challenge slots.",
    impactOneline:
      "Public mission hub gates confirm HTS hosts HTML-comment, application exploit, forensic disk-image, JS exploit, programming, extbasic, and stego challenges requiring accounts.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHtsLoginGatedMissionHubEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Auth-gate wargame mission instances; hub listing alone is low risk but signals training attack surface.",
      steps: [
        "Require HTS login before serving mission challenge content.",
        "Never copy mission vulnerability patterns into production code.",
        "Rate-limit unauthenticated probing of mission hub endpoints."
      ]
    },
    fixPrompt:
      "We mirror HackThisSite login-gated mission hubs. Show how to auth-gate challenge content on private wargame deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hts-playlevel-hub-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "HackThisSite playlevel arcade wargame hub disclosed",
    description:
      "HTS playlevel arcade hubs return Login Required — documenting browser-based wargame challenge levels behind authenticated access.",
    impactOneline:
      "Public playlevel hub gates confirm HTS hosts arcade-style wargame challenges requiring accounts.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHtsPlaylevelHubEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Auth-gate arcade wargame instances; hub listing alone is low risk but signals training attack surface.",
      steps: [
        "Require HTS login before serving playlevel challenge content.",
        "Never copy arcade wargame vulnerability patterns into production code.",
        "Rate-limit unauthenticated probing of playlevel hub endpoints."
      ]
    },
    fixPrompt:
      "We mirror HackThisSite playlevel arcade hubs. Show how to auth-gate wargame challenge content on private deployments.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vwad-app-not-found-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "low",
    title: "OWASP VWAD app listing returns 404",
    description:
      "OWASP VWAD /app/{slug}/ detail URLs that return the site-wide 404 shell indicate a stale directory entry — the vulnerable training instance was removed or never deployed.",
    impactOneline:
      "Stale VWAD app URLs mislead scanners into false positives from crawled sibling listings on the 404 page.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVwadAppNotFoundEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Remove or update stale VWAD listings when training apps go offline.",
      steps: [
        "Open a VWAD GitHub issue to delist removed training instances.",
        "Do not link production security tools to VWAD URLs without verifying the app still loads.",
        "Gate scanner benchmarks on live oracle checks, not directory metadata alone."
      ]
    },
    fixPrompt:
      "Our VWAD app listing returns 404. Show how to delist stale entries and avoid false-positive scans from sibling app crawls.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-net-force-offline-challenge-evidence",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "low",
    title: "Net-Force.nl challenge instance offline (redirects to homepage)",
    description:
      "Net-Force /challenge/levelNN/ URLs that 301 to the homepage indicate decommissioned training challenges (e.g. level110–111).",
    impactOneline:
      "Offline Net-Force challenge URLs pollute discovery queues and can trigger false positives from homepage crawl siblings.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideNetForceOfflineChallengeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Net-Force challenges are retired over time — remove dead level URLs from scanner queues.",
      steps: [
        "Verify /challenge/levelNN/ returns a challenge title before enqueueing.",
        "Treat homepage redirects as offline oracles, not auth-bypass labs.",
        "Prefer active Net-Force levels 101–109 and 405 from the challenges catalog."
      ]
    },
    fixPrompt:
      "We link to Net-Force challenges that redirect to the homepage. Show how to detect offline instances and prune scanner queues.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vwad-security-shepherd-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "OWASP Security Shepherd VWAD lab listing disclosed",
    description:
      "OWASP VWAD Security Shepherd listing documents staged web and mobile application security lessons followed by challenge modules.",
    impactOneline:
      "Public VWAD Security Shepherd catalog exposes XSS, injection, and access-control training lab metadata.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVwadSecurityShepherdEvidence" },
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
      "Our Security Shepherd instance is listed in OWASP VWAD. Show how to isolate training labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vwad-mutillidae-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "OWASP Mutillidae VWAD lab listing disclosed",
    description:
      "OWASP VWAD Mutillidae listing documents deliberately vulnerable web hacking environment for SQLi, XSS, and command-injection training.",
    impactOneline:
      "Public VWAD Mutillidae catalog exposes OWASP Top 10 web-security training lab metadata.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVwadMutillidaeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Mutillidae is intentional training — isolate lab instances from production networks.",
      steps: [
        "Deploy Mutillidae only on isolated lab VMs.",
        "Require authentication when exposing training apps publicly.",
        "Monitor VWAD-linked instances for abuse."
      ]
    },
    fixPrompt:
      "Our Mutillidae instance is listed in OWASP VWAD. Show how to isolate web hacking labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vwad-nodegoat-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "OWASP NodeGoat VWAD lab listing disclosed",
    description:
      "OWASP VWAD NodeGoat listing documents Node.js OWASP Top 10 training environment with tutorial pages for injection and access-control labs.",
    impactOneline:
      "Public VWAD NodeGoat catalog exposes insecure Node.js application training lab metadata.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVwadNodegoatEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "NodeGoat is intentional training — isolate lab instances from production networks.",
      steps: [
        "Deploy NodeGoat only on isolated lab infrastructure.",
        "Require authentication when exposing Node.js training apps publicly.",
        "Monitor VWAD-linked instances for abuse."
      ]
    },
    fixPrompt:
      "Our NodeGoat instance is listed in OWASP VWAD. Show how to isolate Node.js training labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vwad-vulnerableapp-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "OWASP VulnerableApp VWAD scanner-evaluation oracle disclosed",
    description:
      "OWASP VWAD VulnerableApp listing documents JWT, SQLi, XSS, XXE, SSRF, and path-traversal labs built for vulnerability scanner benchmarking.",
    impactOneline:
      "Public VWAD VulnerableApp catalog exposes multi-class deliberately vulnerable Spring/React training surfaces for scanner evaluation.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVwadVulnerableappEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "VulnerableApp is intentional scanner training — isolate lab instances from production networks.",
      steps: [
        "Deploy VulnerableApp only via Docker on isolated lab infrastructure.",
        "Require authentication when exposing scanner benchmark apps publicly.",
        "Monitor VWAD-linked instances for abuse."
      ]
    },
    fixPrompt:
      "Our VulnerableApp instance is listed in OWASP VWAD. Show how to isolate scanner evaluation labs from production.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-hts-basic-mission-lab-evidence",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "medium",
    title: "HackThisSite Basic mission instance lab disclosed",
    description:
      "HTS Basic mission instances like level 11 serve bare challenge content with HTML-comment directory oracle hints without login wrapper.",
    impactOneline:
      "Public HTS Basic mission instances expose introductory web challenge surfaces and hidden-path hints without authentication.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideHtsBasicMissionLabEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Auth-gate HTS mission instances; never copy bare-mission oracle patterns into production.",
      steps: [
        "Require HTS login before serving mission challenge VMs.",
        "Do not expose hidden directory hints via HTML comments on public pages.",
        "Isolate wargame mission infrastructure from production networks."
      ]
    },
    fixPrompt:
      "Our app exposes HTS-style bare mission content with HTML comment oracles. Show how to remove hidden-path hints and require authentication.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnerableapp-dom-xss-evidence",
    platform: "generic",
    category: "Cross-site scripting",
    severityDefault: "high",
    title: "SasanLabs vulnerableapp.com DOM XSS demo disclosed",
    description:
      "vulnerableapp.com publishes DOM-based XSS training pages with document.write cookie-theft payloads in malicious URL href examples.",
    impactOneline:
      "Public DOM XSS demo advertises cookie-exfiltration attack patterns attackers replicate against production apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnerableappDomXssEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "DOM XSS demos are intentional training — isolate from production and never copy sink patterns.",
      steps: [
        "Deploy DOM XSS labs only on isolated training hosts.",
        "Never use document.write with URL-derived input in production code.",
        "Sanitize or encode all DOM sinks fed by query parameters."
      ]
    },
    fixPrompt:
      "Our site has DOM XSS patterns like vulnerableapp.com document.write cookie theft. Show safe DOM manipulation alternatives.",
    version: 1,
    enabled: true
  },
  {
    slug: "client-side-vulnscope-evidence",
    platform: "generic",
    category: "Injection",
    severityDefault: "medium",
    title: "VulnScope Pro vulnerability scanner demo disclosed",
    description:
      "VulnScope Pro publishes an AI-powered web vulnerability scanner UI that crawls targets and tests for SQL injection and XSS with preset vulnweb benchmark URLs.",
    impactOneline:
      "Public scanner demos expose automated injection testing workflows attackers reuse against production apps.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientSideVulnscopeEvidence" },
    tierRequired: "deep",
    remediation: {
      summary: "Gate scanner demos behind auth; never point automated injection tools at production without authorization.",
      steps: [
        "Require login before launching automated vulnerability scans.",
        "Run scanner demos on isolated infrastructure with synthetic targets only.",
        "Rate-limit scan API endpoints to prevent abuse as a free attack proxy."
      ]
    },
    fixPrompt:
      "Our VulnScope-style scanner demo tests live URLs for SQLi and XSS. Show how to gate the scan API and restrict targets to authorized lab hosts.",
    version: 1,
    enabled: true
  }
];
