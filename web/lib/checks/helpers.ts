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

/** Common admin-panel paths on vibe-coded deploys (read-only GET probes). */
export const ADMIN_PANEL_PATHS = [
  "/admin",
  "/dashboard",
  "/admin/dashboard",
  "/manage",
  "/backend",
  "/console",
  "/superadmin",
  "/administrator",
  "/staff"
];

/** Positive markers in HTML that indicate an admin UI (not a marketing page). */
export const ADMIN_PANEL_MARKERS = [
  /admin\s+dashboard/i,
  /admin\s+panel/i,
  /user\s+management/i,
  /manage\s+users/i,
  /role\s+management/i,
  /total\s+(?:users|orders|revenue|customers)/i,
  /data-admin/i,
  /react-admin/i,
  /ra-resource/i,
  /moderator\s+dashboard/i,
  /staff\s+portal/i
];

function normalizeHtmlSnippet(s: string): string {
  return s.replace(/\s+/g, " ").trim().slice(0, 800);
}

/** True when the response is a login gate, not an exposed admin surface. */
export function looksLikeLoginOnlyPage(body: string): boolean {
  const hasPassword = /<input[^>]*type=["']password["']/i.test(body);
  const hasLoginCta = /\b(?:sign\s*in|log\s*in)\b/i.test(body);
  const hasAdminMarker = ADMIN_PANEL_MARKERS.some((re) => re.test(body));
  if (hasPassword && hasLoginCta && !hasAdminMarker) return true;
  if (/<title[^>]*>[^<]*(?:login|sign\s*in)[^<]*<\/title>/i.test(body) && !hasAdminMarker) return true;
  return false;
}

/** True when HTML contains admin-dashboard signals (tables, nav, management copy). */
export function looksLikeAdminPanel(body: string): boolean {
  if (ADMIN_PANEL_MARKERS.some((re) => re.test(body))) return true;
  if (body.length < 200) return false;
  if (/(?:sidebar|side-nav|sidenav)/i.test(body) && /<table/i.test(body)) return true;
  return false;
}

/** SPA catch-all: same shell as homepage with no admin-specific content. */
export function isSameSpaShell(homeBody: string, body: string): boolean {
  return normalizeHtmlSnippet(homeBody) === normalizeHtmlSnippet(body);
}

export function redirectedToLogin(requestedPath: string, finalUrl: string, body: string): boolean {
  try {
    const finalPath = new URL(finalUrl).pathname.toLowerCase();
    const req = requestedPath.toLowerCase();
    if (finalPath !== req && /(?:^|\/)(?:login|signin|sign-in|auth)(?:\/|$)/.test(finalPath)) return true;
  } catch {
    /* ignore */
  }
  return looksLikeLoginOnlyPage(body);
}
