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

/** Harmless marker with HTML metacharacters — reflected unescaped in HTML is XSS proof. */
export const XSS_CANARY = '"><thugir-xss-canary>';

const HTML_CT_RE = /text\/html|application\/xhtml/i;

/** True when the canary appears literally in an HTML response (not JSON/plain). */
export function isReflectedXssInHtml(
  body: string,
  canary: string,
  contentType = ""
): boolean {
  if (!body.includes(canary)) return false;
  if (/application\/json/i.test(contentType)) return false;
  const isHtml = HTML_CT_RE.test(contentType) || /^\s*<(?:!doctype|html)/i.test(body);
  if (!isHtml) return false;
  // URL-encoded echoes in links (e.g. ?q=%22%3E...) are not unescaped reflection.
  const urlEncoded = encodeURIComponent(canary);
  if (body.includes(urlEncoded) && !body.includes(canary)) return false;
  return true;
}
