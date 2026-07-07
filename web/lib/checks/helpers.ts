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

export function redactSecretSample(sample: string): string {
  return sample.length > 12 ? `${sample.slice(0, 6)}…${sample.slice(-4)}` : "***";
}

const STRIPE_PLACEHOLDER_RE =
  /example|placeholder|your_|changeme|sample|fake|testkey|dummy|not[_-]?real|insert|replace|sk_live_test/i;

/** Reject tutorial/placeholder Stripe live secret keys before hitting the API. */
export function isLikelyStripeLiveKey(key: string): boolean {
  if (!/^sk_live_[A-Za-z0-9]{20,}$/.test(key)) return false;
  if (STRIPE_PLACEHOLDER_RE.test(key)) return false;
  if (/^sk_live_0{8,}/.test(key)) return false;
  const body = key.slice(8);
  if (new Set(body).size < 8) return false;
  return true;
}

const STRIPE_LIVE_KEY_RE = /sk_live_[A-Za-z0-9]{20,}/g;

/** Pull the first plausible Stripe live secret key from bundle text. */
export function extractStripeLiveKey(combined: string): string | null {
  const envPatterns = [
    /(?:NEXT_PUBLIC_|VITE_)?STRIPE_(?:SECRET_)?KEY\s*[=:]\s*["'](sk_live_[A-Za-z0-9]{20,})["']/gi,
    /(?:stripeSecretKey|STRIPE_SECRET)\s*[=:]\s*["'](sk_live_[A-Za-z0-9]{20,})["']/gi
  ];
  for (const re of envPatterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(combined))) {
      if (isLikelyStripeLiveKey(m[1])) return m[1];
    }
  }

  if (/stripe/i.test(combined)) {
    for (const m of combined.matchAll(STRIPE_LIVE_KEY_RE)) {
      if (isLikelyStripeLiveKey(m[0])) return m[0];
    }
  }

  for (const m of combined.matchAll(STRIPE_LIVE_KEY_RE)) {
    if (isLikelyStripeLiveKey(m[0])) return m[0];
  }
  return null;
}
