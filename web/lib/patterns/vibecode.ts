import type { Pattern } from "./types";

// Research-backed patterns for AI-generated ("vibe-coded") apps.
// Sources: vibe-eval (2025), securityscanner.dev, vibeappscanner, aithinkerlab audits of
// Lovable/Bolt/v0/Replit/Cursor deploys — RLS gaps, public storage, demo auth bypasses,
// exposed API docs, and service_role keys in client bundles are the top recurring failures.

export const vibecodePatterns: Pattern[] = [
  {
    slug: "vibe-openapi-docs-exposed",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "OpenAPI / Swagger docs publicly reachable",
    description:
      "AI scaffolds often ship with /openapi.json or /swagger enabled in production. Attackers get a full map of every route, parameter, and mutation without guessing.",
    impactOneline: "Public API docs reveal every endpoint and schema to attackers.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "openApiDocs" },
    tierRequired: "free",
    remediation: {
      summary: "Disable or gate API documentation in production.",
      steps: [
        "Remove or protect /openapi.json, /swagger, and /docs routes behind auth.",
        "Use environment checks so docs only load in development.",
        "Confirm production returns 404 for doc endpoints."
      ]
    },
    fixPrompt:
      "My production app exposes OpenAPI/Swagger docs at paths like /openapi.json or /swagger. Disable or protect them behind auth in production and show the config changes.",
    version: 1,
    enabled: true
  },
  {
    slug: "vibe-demo-auth-bypass-flag",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "Demo / skip-auth flag enabled in shipped bundle",
    description:
      "Vibe-coded apps frequently ship SKIP_AUTH, DEMO_MODE, or BYPASS_AUTH toggles left on from scaffolding. Anyone can flip the same flag in DevTools or read it from the bundle.",
    impactOneline: "A hard-coded auth bypass flag is live in your production JavaScript.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "demoModeFlags" },
    tierRequired: "free",
    remediation: {
      summary: "Remove demo auth bypass flags from production builds.",
      steps: [
        "Delete SKIP_AUTH / DEMO_MODE / BYPASS_AUTH constants from client code.",
        "Gate any dev-only bypass behind NODE_ENV === 'development' on the server only.",
        "Rotate sessions if the bypass was ever deployed publicly."
      ]
    },
    fixPrompt:
      "My app ships with SKIP_AUTH, DEMO_MODE, or BYPASS_AUTH enabled in the client bundle. Remove every auth bypass flag from production code and enforce auth server-side only.",
    version: 1,
    enabled: true
  },
  {
    slug: "vibe-supabase-storage-public",
    platform: "supabase",
    category: "Broken access control",
    severityDefault: "high",
    title: "Supabase Storage bucket marked public",
    description:
      "Lovable and Bolt scaffolds often create a 'public' storage bucket with public:true. The anon key can list it and download any object unless you add RLS policies on storage.objects.",
    impactOneline: "A public Supabase bucket may expose uploads to anyone with the anon key.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "supabaseStoragePublic" },
    tierRequired: "free",
    remediation: {
      summary: "Make buckets private and add storage RLS policies.",
      steps: [
        "Set public:false on buckets that hold user data.",
        "Add storage.objects policies restricting SELECT to authenticated users.",
        "Audit existing objects for sensitive uploads."
      ]
    },
    fixPrompt:
      "My Supabase project has a public storage bucket. Make buckets private, add storage RLS so only authenticated owners can read/write, and show the SQL policies.",
    version: 1,
    enabled: true
  },
  {
    slug: "vibe-supabase-service-role-client",
    platform: "supabase",
    category: "Exposed secret",
    severityDefault: "critical",
    title: "Supabase service_role key wired into browser client",
    description:
      "AI builders pass the service_role JWT to createClient() in frontend code to 'make admin features work'. That key bypasses every RLS policy and grants full database access.",
    impactOneline: "The service_role key in your browser bundle bypasses all database security.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "supabaseServiceRoleClient" },
    tierRequired: "free",
    remediation: {
      summary: "Never use service_role in client code; rotate the key immediately.",
      steps: [
        "Remove createClient(url, service_role_key) from all frontend files.",
        "Move privileged operations to Edge Functions or server routes using service_role server-side only.",
        "Rotate the service_role key in Supabase dashboard → Settings → API."
      ]
    },
    fixPrompt:
      "My frontend calls createClient with the Supabase service_role key. Remove it from all client code, move admin operations to a server route or Edge Function, and tell me to rotate the service_role key.",
    version: 1,
    enabled: true
  },
  {
    slug: "lovable-supabase-storage-public",
    platform: "lovable",
    category: "Broken access control",
    severityDefault: "high",
    title: "Lovable scaffold left a public Supabase Storage bucket",
    description:
      "Lovable templates default to a public avatars/uploads bucket. Without storage RLS, anyone with the anon key from your bundle can list and fetch objects.",
    impactOneline: "Public storage is a common Lovable default — user files may be world-readable.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "supabaseStoragePublic" },
    tierRequired: "free",
    remediation: {
      summary: "Lock down storage buckets and add RLS.",
      steps: ["Set buckets to private.", "Add storage.objects RLS.", "Re-test with the anon key."]
    },
    fixPrompt:
      "My Lovable app has a public Supabase storage bucket. Make buckets private and add storage RLS policies so only the owning user can access their files.",
    version: 1,
    enabled: true
  },
  {
    slug: "bolt-demo-mode-shipped",
    platform: "bolt",
    category: "Broken access control",
    severityDefault: "high",
    title: "Bolt demo / skip-auth flag left enabled",
    description:
      "Bolt prototypes often include VITE_DEMO_MODE or skipAuth for local testing. When deployed unchanged, the bypass ships to every visitor.",
    impactOneline: "Demo auth bypass from Bolt scaffolding is live in production.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "demoModeFlags" },
    tierRequired: "free",
    remediation: {
      summary: "Strip demo flags before deploy.",
      steps: ["Remove VITE_DEMO / skipAuth from client.", "Enforce auth on the API layer."]
    },
    fixPrompt:
      "My Bolt/Vite app still has demo or skip-auth flags enabled in production. Remove them and enforce authentication on every API call server-side.",
    version: 1,
    enabled: true
  },
  {
    slug: "v0-openapi-routes-exposed",
    platform: "v0",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "v0 Next.js app exposes API schema docs",
    description:
      "v0-generated Next.js APIs often leave OpenAPI/Swagger routes from the template enabled, documenting every Server Action and route handler.",
    impactOneline: "Generated API docs reveal all v0 routes to attackers.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "openApiDocs" },
    tierRequired: "free",
    remediation: {
      summary: "Remove or protect API doc routes in production.",
      steps: ["Delete or auth-gate /openapi.json and /docs.", "Verify 404 in production."]
    },
    fixPrompt:
      "My v0 Next.js app exposes OpenAPI docs in production. Remove or protect those routes and confirm they 404 on the live deploy.",
    version: 1,
    enabled: true
  },
  {
    slug: "vibe-streamlit-secrets-exposed",
    platform: "generic",
    category: "Source exposure",
    severityDefault: "critical",
    title: "Streamlit secrets.toml reachable over HTTP",
    description:
      "Streamlit vibe apps deployed without proper static routing sometimes serve .streamlit/secrets.toml, leaking API keys and database passwords.",
    impactOneline: "Streamlit secrets file is downloadable from your public URL.",
    detectorKind: "http_probe",
    detectorConfig: {
      paths: ["/.streamlit/secrets.toml", "/secrets.toml"],
      expect: { kind: "status_2xx_non_html" },
      maxBytes: 4096
    },
    tierRequired: "free",
    remediation: {
      summary: "Block secrets.toml from the web root and rotate every leaked secret.",
      steps: [
        "Configure the host to never serve .streamlit/ paths.",
        "Rotate all keys that were in secrets.toml."
      ]
    },
    fixPrompt:
      "My Streamlit deploy serves .streamlit/secrets.toml publicly. Block that path at the edge and tell me which secrets to rotate.",
    version: 1,
    enabled: true
  },
  {
    slug: "vibe-sitemap-sensitive-paths",
    platform: "generic",
    category: "Information disclosure",
    severityDefault: "medium",
    title: "sitemap.xml lists sensitive routes",
    description:
      "AI SEO scaffolds auto-generate sitemaps that include /admin, /api/internal, or /staging URLs — a crawlable map of your attack surface.",
    impactOneline: "Your sitemap advertises internal routes to search engines and attackers.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "sitemapSensitivePaths" },
    tierRequired: "free",
    remediation: {
      summary: "Remove sensitive URLs from sitemap.xml.",
      steps: ["Exclude admin/internal paths from sitemap generation.", "Protect those routes with auth."]
    },
    fixPrompt:
      "My sitemap.xml includes sensitive paths like /admin or /staging. Exclude them from sitemap generation and protect those routes with auth.",
    version: 1,
    enabled: true
  },
  {
    slug: "vibe-weak-csp",
    platform: "generic",
    category: "Security misconfiguration",
    severityDefault: "medium",
    title: "Content-Security-Policy allows unsafe-inline or unsafe-eval",
    description:
      "A CSP is present but includes unsafe-inline or unsafe-eval — the default AI template CSP that does not actually stop XSS.",
    impactOneline: "Your CSP still allows inline scripts, so XSS can bypass it.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "weakCsp" },
    tierRequired: "free",
    remediation: {
      summary: "Remove unsafe-inline and unsafe-eval from production CSP.",
      steps: ["Use nonces or hashes for required inline scripts.", "Drop unsafe-eval unless absolutely required."]
    },
    fixPrompt:
      "My CSP includes unsafe-inline or unsafe-eval. Tighten the Content-Security-Policy for production using nonces/hashes and remove unsafe directives.",
    version: 1,
    enabled: true
  },
  {
    slug: "vibe-hardcoded-demo-credentials",
    platform: "generic",
    category: "Broken authentication",
    severityDefault: "high",
    title: "Hardcoded demo credentials in client bundle",
    description:
      "The shipped JavaScript contains literal admin/password or demo@test.com credentials from AI scaffolding — readable in DevTools.",
    impactOneline: "Default demo login credentials are embedded in your production JavaScript.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "hardcodedCredentials" },
    tierRequired: "free",
    remediation: {
      summary: "Remove all hardcoded credentials from client code.",
      steps: ["Delete demo login constants.", "Use server-side auth only.", "Rotate any accounts that used demo passwords."]
    },
    fixPrompt:
      "My client bundle contains hardcoded demo credentials (admin/password or demo@test.com). Remove them from all client code and enforce auth server-side.",
    version: 1,
    enabled: true
  },
  {
    slug: "vibe-clerk-secret-in-client",
    platform: "generic",
    category: "Exposed secret",
    severityDefault: "critical",
    title: "Clerk secret key referenced in client bundle",
    description:
      "Clerk's sk_live_ / sk_test_ secret is assigned in client-side code. Only the publishable key (pk_) belongs in the browser.",
    impactOneline: "Your Clerk secret key in JS grants full auth admin on your app.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clerkSecretInClient" },
    tierRequired: "free",
    remediation: {
      summary: "Move Clerk secret operations server-side and rotate the key.",
      steps: ["Use pk_ keys client-side only.", "Use sk_ keys in API routes / Edge Functions only.", "Rotate in Clerk dashboard."]
    },
    fixPrompt:
      "My frontend references a Clerk secret key (sk_live/sk_test). Move all Clerk secret usage to server-side API routes and tell me to rotate the key.",
    version: 1,
    enabled: true
  },
  {
    slug: "vibe-auth0-secret-in-client",
    platform: "generic",
    category: "Exposed secret",
    severityDefault: "critical",
    title: "Auth0 client secret referenced in client bundle",
    description:
      "Auth0 quickstarts and NextAuth Auth0Provider configs often assign AUTH0_CLIENT_SECRET or clientSecret in modules that ship to the browser. Only the client ID belongs client-side; the secret enables token exchange and session forgery.",
    impactOneline: "Your Auth0 client secret in JS enables OAuth token theft and account takeover.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "auth0SecretInClient" },
    tierRequired: "free",
    remediation: {
      summary: "Move Auth0 secret usage server-side and rotate the client secret.",
      steps: [
        "Remove AUTH0_CLIENT_SECRET from all client code and client-exposed env vars (NEXT_PUBLIC_*, VITE_*).",
        "Handle Auth0 token exchange only in server routes or Edge Functions.",
        "Rotate the client secret in Auth0 Dashboard → Applications → Settings."
      ]
    },
    fixPrompt:
      "My frontend references an Auth0 client secret (AUTH0_CLIENT_SECRET or clientSecret). Move all Auth0 secret usage to server-side API routes, remove it from client-exposed env vars, and tell me to rotate the client secret in Auth0.",
    version: 1,
    enabled: true
  },
  {
    slug: "vibe-firebase-firestore-open",
    platform: "firebase",
    category: "Broken access control",
    severityDefault: "high",
    title: "Firestore collection readable without authentication",
    description:
      "Firebase web config + open security rules let anyone with the API key list documents from common collections (users, profiles, posts).",
    impactOneline: "Firestore returns documents to unauthenticated callers.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "firebaseFirestoreOpen" },
    tierRequired: "free",
    remediation: {
      summary: "Tighten Firestore security rules to require auth.",
      steps: ["Add request.auth != null checks.", "Scope reads/writes to the owning user.", "Audit exposed collections."]
    },
    fixPrompt:
      "My Firestore returns documents without authentication. Tighten security rules so reads require auth and users can only access their own data.",
    version: 1,
    enabled: true
  },
  {
    slug: "vibe-unauthenticated-api-routes",
    platform: "generic",
    category: "Broken access control",
    severityDefault: "high",
    title: "JSON API routes return data without authentication",
    description:
      "Routes referenced in your client bundle respond with JSON to unauthenticated GET requests — a classic vibe-coded API with no session check on the server.",
    impactOneline: "API endpoints leak data to anyone who guesses or reads the path from your JS.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "unauthenticatedApiRoutes" },
    tierRequired: "deep",
    remediation: {
      summary: "Require authentication on every API route that returns user or business data.",
      steps: ["Add session verification at the top of each handler.", "Return 401 for missing/invalid auth.", "Never rely on hiding routes in the UI."]
    },
    fixPrompt:
      "My API routes return JSON without checking authentication. Add session/auth verification to every sensitive route handler and return 401 when unauthenticated.",
    version: 1,
    enabled: true
  },
  {
    slug: "vibe-next-data-sensitive-keys",
    platform: "v0",
    category: "Exposed secret",
    severityDefault: "critical",
    title: "Sensitive env key names in Next.js __NEXT_DATA__",
    description:
      "Server secret key names (DATABASE_URL, SERVICE_ROLE, etc.) with values are serialized into __NEXT_DATA__ — visible in View Source on every page load.",
    impactOneline: "Secret configuration is embedded in the HTML payload shipped to every visitor.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "nextDataSensitiveKeys" },
    tierRequired: "free",
    remediation: {
      summary: "Never pass secrets through getServerSideProps/page props into __NEXT_DATA__.",
      steps: ["Remove secret values from all page props.", "Read secrets only in server route handlers.", "Rotate anything that was exposed."]
    },
    fixPrompt:
      "My Next.js __NEXT_DATA__ contains sensitive env key names with values. Remove them from page props so they never reach the client, and list what I must rotate.",
    version: 1,
    enabled: true
  }
];
