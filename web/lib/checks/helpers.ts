// Shared helpers for rule_ref checks. Kept separate so unit tests can import without HTTP.

export function jwtPayload(jwt: string): string | null {
  try {
    const part = jwt.split(".")[1];
    if (!part) return null;
    return atob(part.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    return null;
  }
}

/** Convex deployment URLs embedded in client bundles (e.g. https://happy-fox-123.convex.cloud). */
export function extractConvexFromText(combined: string): { deploymentUrl: string } | null {
  const direct = combined.match(/https:\/\/([a-z][a-z0-9-]{2,50})\.convex\.cloud\b/);
  if (direct) return { deploymentUrl: `https://${direct[1]}.convex.cloud` };
  const env = combined.match(
    /(?:CONVEX_URL|NEXT_PUBLIC_CONVEX_URL|VITE_CONVEX_URL)\s*[=:]\s*["']?(https:\/\/[^"'\s;]+\.convex\.cloud)\/?["']?/i
  );
  if (env) return { deploymentUrl: env[1].replace(/\/$/, "") };
  return null;
}

/** Convex function paths as module:fn (from api.users.list or "users:list" strings in bundles). */
export function extractConvexFunctionPaths(combined: string, limit = 8): string[] {
  const paths = new Set<string>();
  const colonRe = /["']([a-z][a-zA-Z0-9_]*):([a-z][a-zA-Z0-9_]+)["']/g;
  let m: RegExpExecArray | null;
  while ((m = colonRe.exec(combined)) && paths.size < limit) {
    paths.add(`${m[1]}:${m[2]}`);
  }
  const apiRe = /api\.([a-z][a-zA-Z0-9_]*)\.([a-z][a-zA-Z0-9_]+)/g;
  while ((m = apiRe.exec(combined)) && paths.size < limit) {
    paths.add(`${m[1]}:${m[2]}`);
  }
  return [...paths];
}

/** True when a Convex /api/query response returned real data without an auth error. */
export function isConvexOpenQueryResponse(body: string): { open: boolean; rowHint?: string } {
  if (/unauthorized|not authenticated|unauthenticated|must be signed in|permission denied/i.test(body)) {
    return { open: false };
  }
  try {
    const parsed = JSON.parse(body) as {
      status?: string;
      errorMessage?: string;
      value?: unknown;
    };
    if (parsed.status === "error" || parsed.errorMessage) return { open: false };
    if (parsed.status !== "success") return { open: false };
    const val = parsed.value;
    if (Array.isArray(val) && val.length > 0) {
      return { open: true, rowHint: `rows:${val.length}` };
    }
    if (val && typeof val === "object" && !Array.isArray(val) && Object.keys(val as object).length > 0) {
      return { open: true, rowHint: "object" };
    }
    return { open: false };
  } catch {
    return { open: false };
  }
}

export function isLikelyConvexQueryPath(path: string): boolean {
  const fn = path.split(":")[1] || "";
  if (/^(create|update|delete|insert|remove|set|add|mutate|send|patch|put|destroy)$/i.test(fn)) {
    return false;
  }
  return /^(list|get|fetch|read|all|search|find|load|current|me|by|for)/i.test(fn);
}

export function extractSupabaseFromText(
  combined: string
): { projectUrl: string; anonKey: string } | null {
  const urlMatch = combined.match(/https:\/\/([a-z0-9]{20})\.supabase\.co/);
  if (!urlMatch) return null;
  const projectUrl = `https://${urlMatch[1]}.supabase.co`;
  const jwts =
    combined.match(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g) || [];
  for (const k of jwts) {
    const payload = jwtPayload(k);
    if (payload && /"role"\s*:\s*"anon"/.test(payload)) return { projectUrl, anonKey: k };
  }
  const fallback = jwts[0];
  if (!fallback) return null;
  return { projectUrl, anonKey: fallback };
}

/** Paths commonly advertised in robots.txt / sitemap.xml on vibe-coded deploys. */
export const SENSITIVE_PATH_NEEDLES = [
  "/admin",
  "/.env",
  "/.git",
  "/backup",
  "/config",
  "/api/internal",
  "/dashboard",
  "/phpmyadmin",
  "/wp-admin",
  "/debug",
  "/.well-known/acme",
  "/api/debug",
  "/staging",
  "/internal"
];

export const DEMO_FLAG_RES = [
  /["']?(?:SKIP_AUTH|BYPASS_AUTH|DISABLE_AUTH|MOCK_AUTH|DEMO_MODE|VITE_SKIP_AUTH|NEXT_PUBLIC_SKIP_AUTH|VITE_DEMO_MODE|NEXT_PUBLIC_DEMO_MODE)["']?\s*[:=]\s*(?:true|"true"|'true'|"1"|'1'|1)(?=["'\s;,}]|$)/i,
  /\bskipAuth\s*:\s*true\b/i,
  /\bdemoMode\s*:\s*true\b/i,
  /\bauthBypass\s*:\s*true\b/i
];

export function matchDemoFlags(text: string): string[] {
  const hits: string[] = [];
  for (const re of DEMO_FLAG_RES) {
    const m = text.match(re);
    if (m) hits.push(m[0].slice(0, 80));
  }
  return [...new Set(hits)];
}

export function looksOpenApiBody(body: string): boolean {
  const trimmed = body.trim();
  return (
    /"paths"\s*:\s*\{/.test(trimmed) && /"(get|post|put|delete|patch)"\s*:/.test(trimmed)
  );
}

export const HARDCODED_CRED_RES = [
  { label: "default admin password", re: /["']password["']\s*:\s*["'](?:admin|password|123456|12345678|test|secret)['"]/i },
  { label: "hardcoded admin username", re: /["']username["']\s*:\s*["']admin['"]/i },
  { label: "demo account email", re: /["'][a-z]*(?:email|user(?:name)?)["']\s*:\s*["'](?:demo|test|admin)@[^"']+["']/i }
];
