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

/** Twilio auth tokens are 32 hex chars; reject obvious non-secrets and SID duplicates. */
export function isLikelyTwilioAuthToken(token: string, accountSid?: string): boolean {
  if (!/^[a-f0-9]{32}$/i.test(token)) return false;
  if (accountSid && token.toLowerCase() === accountSid.slice(2).toLowerCase()) return false;
  if (/^0{12,}/.test(token)) return false;
  return true;
}

const TWILIO_SID_RE = /AC[a-f0-9]{32}/gi;

/** Pull the first plausible Twilio accountSid + authToken pair from bundle text. */
export function extractTwilioCredentials(
  combined: string
): { accountSid: string; authToken: string } | null {
  const publicAuthEnv =
    /(?:NEXT_PUBLIC_|VITE_)?TWILIO_AUTH_TOKEN\s*[=:]\s*["']([a-f0-9]{32})["']/gi;
  let m: RegExpExecArray | null;
  while ((m = publicAuthEnv.exec(combined))) {
    if (!isLikelyTwilioAuthToken(m[1])) continue;
    const start = Math.max(0, (m.index ?? 0) - 400);
    const nearby = combined.slice(start, (m.index ?? 0) + m[0].length + 400);
    const sid =
      nearby.match(/(?:TWILIO_ACCOUNT_SID|accountSid)\s*[=:]\s*["'](AC[a-f0-9]{32})["']/i)?.[1] ||
      nearby.match(/AC[a-f0-9]{32}/i)?.[0];
    if (sid && isLikelyTwilioAuthToken(m[1], sid)) {
      return { accountSid: sid, authToken: m[1] };
    }
  }

  for (const sidMatch of combined.matchAll(TWILIO_SID_RE)) {
    const accountSid = sidMatch[0];
    const idx = sidMatch.index ?? 0;
    const window = combined.slice(Math.max(0, idx - 220), idx + accountSid.length + 420);

    const authNear = window.match(
      /(?:authToken|auth_token|TWILIO_AUTH_TOKEN)\s*[=:]\s*["']([a-f0-9]{32})["']/i
    );
    if (authNear && isLikelyTwilioAuthToken(authNear[1], accountSid)) {
      return { accountSid, authToken: authNear[1] };
    }

    const callPat = new RegExp(
      `twilio\\s*\\(\\s*["']${accountSid}["']\\s*,\\s*["']([a-f0-9]{32})["']`,
      "i"
    );
    const callM = window.match(callPat);
    if (callM && isLikelyTwilioAuthToken(callM[1], accountSid)) {
      return { accountSid, authToken: callM[1] };
    }
  }

  if (!/twilio/i.test(combined)) return null;
  const genericAuth = /(?:authToken|auth_token)\s*[=:]\s*["']([a-f0-9]{32})["']/gi;
  while ((m = genericAuth.exec(combined))) {
    const start = Math.max(0, (m.index ?? 0) - 320);
    const end = (m.index ?? 0) + m[0].length + 320;
    const nearby = combined.slice(start, end);
    const sid = nearby.match(/AC[a-f0-9]{32}/i)?.[0];
    if (sid && isLikelyTwilioAuthToken(m[1], sid)) {
      return { accountSid: sid, authToken: m[1] };
    }
  }
  return null;
}
