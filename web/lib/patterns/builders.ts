import type { Pattern } from "./types";

// Builder-specific patterns. These encode defaults that a particular AI tool tends to ship.
// Many are "deep" tier because confirming them needs multi-page or authenticated probing;
// on a free scan they surface as locked cards proving there is more to find.

export const lovablePatterns: Pattern[] = [
  {
    slug: "lovable-client-only-auth",
    platform: "lovable",
    category: "Broken access control",
    severityDefault: "high",
    title: "Client-side-only route guarding (auth not enforced on data)",
    description:
      "Lovable scaffolds frequently gate UI routes in React but leave the Supabase/data layer open, so the API/DB can be hit directly without the UI ever loading.",
    impactOneline:
      "Hiding a page in the UI does not protect the data behind it; the data is still reachable.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "clientOnlyAuth" },
    tierRequired: "deep",
    remediation: {
      summary: "Enforce authorization at the data layer, not just the UI.",
      steps: [
        "Add Row Level Security / server-side checks for every table and endpoint.",
        "Treat client route guards as UX only, never as security."
      ]
    },
    fixPrompt:
      "My app guards routes in the React UI but the underlying Supabase data is reachable without auth. Add server-side / RLS authorization on every table and endpoint so data is protected independently of the UI.",
    version: 1,
    enabled: true
  },
];

export const boltPatterns: Pattern[] = [
  {
    slug: "bolt-public-env-prefix-leak",
    platform: "bolt",
    category: "Exposed secret",
    severityDefault: "high",
    title: "Server secret behind a public env prefix",
    description:
      "Bolt-generated Vite apps expose any VITE_-prefixed env var to the browser. Secrets accidentally given that prefix are shipped to every visitor.",
    impactOneline: "A secret was exposed because it used a browser-public env prefix.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "publicEnvPrefixLeak" },
    tierRequired: "free",
    remediation: {
      summary: "Rename server secrets off the public prefix and rotate them.",
      steps: [
        "Only VITE_/NEXT_PUBLIC_ values should be browser-safe.",
        "Move secrets to non-public env vars used only server-side, then rotate."
      ]
    },
    fixPrompt:
      "A server secret in my Vite/Bolt app is exposed because it uses a VITE_ public prefix. Move it to a non-public server-side variable, update the code to read it server-side only, and tell me to rotate it.",
    version: 1,
    enabled: true
  }
];

export const v0Patterns: Pattern[] = [
  {
    slug: "v0-server-action-no-authz",
    platform: "v0",
    category: "Broken access control",
    severityDefault: "high",
    title: "Next.js Server Action without authorization check",
    description:
      "v0-generated Next.js apps often expose Server Actions that mutate data without re-checking the caller's identity/permissions, trusting the UI to gate access.",
    impactOneline:
      "A generated Server Action may let any caller perform privileged mutations.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "serverActionAuthz" },
    tierRequired: "deep",
    remediation: {
      summary: "Authorize inside every Server Action.",
      steps: [
        "Re-validate the session and permissions at the top of each Server Action.",
        "Never rely on the calling component being hidden."
      ]
    },
    fixPrompt:
      "My Next.js Server Actions mutate data without checking who is calling them. Add session + permission checks at the start of each Server Action and reject unauthorized callers. Show the updated actions.",
    version: 1,
    enabled: true
  }
];

export const replitPatterns: Pattern[] = [
  {
    slug: "replit-secrets-in-client",
    platform: "replit",
    category: "Exposed secret",
    severityDefault: "critical",
    title: "Replit secret referenced in client-side code",
    description:
      "Replit Secrets are meant for server-side use. AI-generated frontends often read process.env / import.meta.env in the browser, shipping those secrets to visitors.",
    impactOneline: "Secrets from Replit may be readable in the browser bundle.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "publicEnvPrefixLeak" },
    tierRequired: "free",
    remediation: {
      summary: "Use Replit Secrets only in backend/server code.",
      steps: [
        "Move secret reads into Express/FastAPI/server routes.",
        "Rotate any secret that appeared in client JS."
      ]
    },
    fixPrompt:
      "My Replit app may be exposing Secrets in client-side code. Find every client reference to secrets/env vars, move them server-side, and list what I must rotate.",
    version: 1,
    enabled: true
  },
  {
    slug: "replit-exposed-dot-replit",
    platform: "replit",
    category: "Source exposure",
    severityDefault: "medium",
    title: "Replit project config reachable over HTTP",
    description:
      "A deployed Replit app sometimes serves .replit or replit.nix, revealing run commands and internal layout.",
    impactOneline: "Project config files are downloadable from production.",
    detectorKind: "http_probe",
    detectorConfig: {
      paths: ["/.replit", "/replit.nix", "/.config/replit"],
      expect: { kind: "status_2xx_non_html" },
      maxBytes: 4096
    },
    tierRequired: "free",
    remediation: {
      summary: "Stop serving Replit config files from the public web root.",
      steps: ["Exclude .replit and nix configs from the static deploy.", "Confirm they 404."]
    },
    fixPrompt:
      "My Replit deploy serves .replit or similar config files. Exclude them from the public web root and confirm they return 404.",
    version: 1,
    enabled: true
  }
];

export const cursorPatterns: Pattern[] = [
  {
    slug: "cursor-next-public-secret",
    platform: "cursor",
    category: "Exposed secret",
    severityDefault: "critical",
    title: "NEXT_PUBLIC_ variable holds a server secret",
    description:
      "Cursor/Claude-generated Next.js apps often put API keys in NEXT_PUBLIC_* because the model copies .env examples. Anything with that prefix is embedded in the browser bundle.",
    impactOneline: "A server secret was published under a NEXT_PUBLIC_ name.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "publicEnvPrefixLeak" },
    tierRequired: "free",
    remediation: {
      summary: "Rename secrets off NEXT_PUBLIC_ and rotate them.",
      steps: [
        "Only publish truly public values with NEXT_PUBLIC_.",
        "Read secrets in route handlers / server components only."
      ]
    },
    fixPrompt:
      "My Next.js app exposes a server secret via a NEXT_PUBLIC_ env var. Move it to a server-only env var, update all reads to server-side code, and tell me to rotate the key.",
    version: 1,
    enabled: true
  }
];

export const windsurfPatterns: Pattern[] = [
  {
    slug: "windsurf-public-env-leak",
    platform: "windsurf",
    category: "Exposed secret",
    severityDefault: "high",
    title: "Public env prefix used for a privileged credential",
    description:
      "Windsurf-generated Vite/Next apps share the same public-prefix trap as Bolt and Cursor scaffolds.",
    impactOneline: "A privileged credential may be embedded in client JS.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "publicEnvPrefixLeak" },
    tierRequired: "free",
    remediation: {
      summary: "Keep privileged credentials server-side only.",
      steps: ["Audit VITE_/NEXT_PUBLIC_ usage.", "Rotate any leaked credential."]
    },
    fixPrompt:
      "My Windsurf-built app may expose secrets via public env prefixes. Find them, move them server-side, and list rotations needed.",
    version: 1,
    enabled: true
  }
];

/** Stack patterns common across vibe-coded SaaS (Clerk, Neon, Prisma, Vercel). */
export const stackPatterns: Pattern[] = [
  {
    slug: "stack-database-url-in-bundle",
    platform: "generic",
    category: "Exposed secret",
    severityDefault: "critical",
    title: "Database connection string in client bundle",
    description:
      "Postgres/Neon/Prisma DATABASE_URL (or similar) appears in JavaScript served to the browser. AI scaffolds often import server config into shared modules.",
    impactOneline: "Anyone can connect to your database with the credentials in the page source.",
    detectorKind: "secret_regex",
    detectorConfig: {
      regex: "(?:postgres(?:ql)?|mysql):\\/\\/[^\\s\"']{12,}",
      secretName: "Database connection URL",
      serverOnly: true
    },
    tierRequired: "free",
    remediation: {
      summary: "Remove the connection string from all client code and rotate DB credentials.",
      steps: [
        "Keep DATABASE_URL only in server env.",
        "Rotate the database password.",
        "Use a server-only data access layer."
      ]
    },
    fixPrompt:
      "A database connection string is in my client bundle. Remove every client reference, keep DATABASE_URL server-only, and tell me to rotate the database password.",
    version: 1,
    enabled: true
  },
  {
    slug: "stack-neon-url-in-bundle",
    platform: "generic",
    category: "Exposed secret",
    severityDefault: "critical",
    title: "Neon / serverless Postgres URL in client",
    description:
      "Neon connection strings in client JS give full database access. Common when AI copies .env into a shared config module.",
    impactOneline: "Your Neon database credentials are public.",
    detectorKind: "secret_regex",
    detectorConfig: {
      regex: "ep-[a-z0-9-]+\\.[a-z0-9.-]+\\.neon\\.tech",
      secretName: "Neon host",
      serverOnly: true
    },
    tierRequired: "free",
    remediation: {
      summary: "Keep Neon credentials server-side and rotate.",
      steps: ["Remove Neon URLs from client bundles.", "Rotate the role password in Neon."]
    },
    fixPrompt:
      "A Neon database host/credential appears in my client bundle. Move all DB access server-side and rotate the Neon role password.",
    version: 1,
    enabled: true
  },
  {
    slug: "stack-vercel-env-exposure",
    platform: "generic",
    category: "Source exposure",
    severityDefault: "medium",
    title: "Vercel / Next build manifest or env debug endpoint",
    description:
      "Debug or build artifacts sometimes remain reachable on Vercel deploys from AI templates.",
    impactOneline: "Build or env debug surfaces may leak configuration.",
    detectorKind: "http_probe",
    detectorConfig: {
      paths: ["/_next/static/chunks/env.js", "/api/debug", "/api/env", "/.vercel/project.json"],
      expect: { kind: "status_2xx_non_html" },
      maxBytes: 4096
    },
    tierRequired: "deep",
    remediation: {
      summary: "Remove debug routes and never deploy env dumps.",
      steps: ["Delete debug API routes.", "Confirm they 404 in production."]
    },
    fixPrompt:
      "My Vercel/Next deploy may expose debug or env endpoints. Remove them and confirm they return 404 in production.",
    version: 1,
    enabled: true
  },
  {
    slug: "stack-cors-wildcard-api",
    platform: "generic",
    category: "Misconfiguration",
    severityDefault: "high",
    title: "API reflects Access-Control-Allow-Origin: * with credentials path",
    description:
      "AI-generated APIs often set CORS to * so demos work, which enables any site to call your API from a victim's browser.",
    impactOneline: "Any website can call your API from users' browsers.",
    detectorKind: "rule_ref",
    detectorConfig: { rule: "permissiveCors" },
    tierRequired: "deep",
    remediation: {
      summary: "Restrict CORS to your real front-end origins.",
      steps: [
        "Set Access-Control-Allow-Origin to explicit origins.",
        "Avoid * when cookies or auth headers are used."
      ]
    },
    fixPrompt:
      "My API uses Access-Control-Allow-Origin: *. Restrict CORS to my real front-end origins and show the updated server config.",
    version: 1,
    enabled: true
  }
];
