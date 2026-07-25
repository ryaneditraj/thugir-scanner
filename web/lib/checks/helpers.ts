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
  "/internal",
  "/back-office",
  "the-back-office"
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
  { label: "demo account email", re: /["'][a-z]*(?:email|user(?:name)?)["']\s*:\s*["'](?:demo|test|admin)@[^"']+["']/i },
  {
    label: "inline admin/password login check",
    re: /["']admin["']\s*===\s*\w+\s*&&\s*["']password["']\s*===\s*\w+/i
  },
  {
    label: "inline password literal comparison",
    re: /["']password["']\s*===\s*["'](?:admin|password|123456|12345678|test|secret)['"]/i
  },
  {
    label: "inline email/password ternary login check",
    re: /["'][\w.+-]+@[^"']+["']\s*===\s*\w+\s*&&\s*["'][^"']+["']\s*===\s*\w+/
  },
  {
    label: "admin password in API query string",
    re: /(?:\?|&)username=admin&password=(?:123456|password|admin|passw0rd)/i
  },
  {
    label: "DVWA default credential hint",
    re: /default username is ['"]admin['"] with password ['"]password['"]/i
  },
  {
    label: "HTML lab displayed admin credentials",
    re: /font-mono[^>]*>admin\s*\/\s*admin(?:123)?|Admin:[\s\S]{0,40}font-mono[^>]*>admin\s*\/\s*admin/i
  },
  {
    label: "VulnForge hardcoded API key placeholder",
    re: /x-vulnforge-api-key[\s\S]{0,220}change_me_for_prod|change_me_for_prod[\s\S]{0,220}x-vulnforge-api-key|bh=["']change_me_for_prod["']/i
  }
];

/** Disallow paths under /api/ advertised in robots.txt (often probed for data leaks). */
export function parseRobotsDisallowApiPaths(robotsBody: string): string[] {
  const paths = new Set<string>();
  for (const line of robotsBody.split(/\r?\n/)) {
    const m = line.match(/^\s*Disallow:\s*(\/\S+)/i);
    if (!m) continue;
    const p = m[1].trim();
    if (/\/api\//i.test(p)) paths.add(p);
  }
  return [...paths];
}

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

const OPENAI_PLACEHOLDER_RE =
  /example|placeholder|your_|changeme|sample|fake|dummy|not[_-]?real|insert|replace|sk-test|xxxxxxxx/i;

const OPENAI_KEY_BODY_RE = /^(?:proj-)?[A-Za-z0-9_-]{20,}$/;

/** Reject tutorial/placeholder OpenAI keys and non-OpenAI sk- prefixes before hitting the API. */
export function isLikelyOpenAiKey(key: string): boolean {
  if (!/^sk-(?:proj-)?[A-Za-z0-9_-]{20,}$/.test(key)) return false;
  if (/^sk-ant-/i.test(key)) return false;
  if (/^sk_(?:live|test)_/i.test(key)) return false;
  if (OPENAI_PLACEHOLDER_RE.test(key)) return false;
  const body = key.slice(3);
  if (!OPENAI_KEY_BODY_RE.test(body)) return false;
  const entropy = new Set(body.replace(/-/g, "")).size;
  if (entropy < 8) return false;
  return true;
}

const OPENAI_KEY_RE = /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g;

/** Pull the first plausible OpenAI API key from bundle text. */
export function extractOpenAiKey(combined: string): string | null {
  const envPatterns = [
    /(?:NEXT_PUBLIC_|VITE_)?OPENAI_(?:API_)?KEY\s*[=:]\s*["'](sk-(?:proj-)?[A-Za-z0-9_-]{20,})["']/gi,
    /(?:openaiApiKey|OPENAI_API_KEY)\s*[=:]\s*["'](sk-(?:proj-)?[A-Za-z0-9_-]{20,})["']/gi
  ];
  for (const re of envPatterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(combined))) {
      if (isLikelyOpenAiKey(m[1])) return m[1];
    }
  }

  if (/openai/i.test(combined)) {
    for (const m of combined.matchAll(OPENAI_KEY_RE)) {
      if (isLikelyOpenAiKey(m[0])) return m[0];
    }
  }

  for (const m of combined.matchAll(OPENAI_KEY_RE)) {
    if (isLikelyOpenAiKey(m[0])) return m[0];
  }
  return null;
}

const ANTHROPIC_PLACEHOLDER_RE =
  /example|placeholder|your_|changeme|sample|fake|dummy|not[_-]?real|insert|replace|xxxxxxxx/i;

const ANTHROPIC_KEY_BODY_RE = /^[A-Za-z0-9_-]{20,}$/;

/** Reject tutorial/placeholder Anthropic keys before hitting the API. */
export function isLikelyAnthropicKey(key: string): boolean {
  if (!/^sk-ant-[A-Za-z0-9_-]{20,}$/.test(key)) return false;
  if (ANTHROPIC_PLACEHOLDER_RE.test(key)) return false;
  const body = key.slice(7);
  if (!ANTHROPIC_KEY_BODY_RE.test(body)) return false;
  const entropy = new Set(body.replace(/-/g, "")).size;
  if (entropy < 8) return false;
  return true;
}

const ANTHROPIC_KEY_RE = /sk-ant-[A-Za-z0-9_-]{20,}/g;

/** Pull the first plausible Anthropic API key from bundle text. */
export function extractAnthropicKey(combined: string): string | null {
  const envPatterns = [
    /(?:NEXT_PUBLIC_|VITE_)?ANTHROPIC_(?:API_)?KEY\s*[=:]\s*["'](sk-ant-[A-Za-z0-9_-]{20,})["']/gi,
    /(?:anthropicApiKey|ANTHROPIC_API_KEY)\s*[=:]\s*["'](sk-ant-[A-Za-z0-9_-]{20,})["']/gi
  ];
  for (const re of envPatterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(combined))) {
      if (isLikelyAnthropicKey(m[1])) return m[1];
    }
  }

  if (/anthropic/i.test(combined)) {
    for (const m of combined.matchAll(ANTHROPIC_KEY_RE)) {
      if (isLikelyAnthropicKey(m[0])) return m[0];
    }
  }

  for (const m of combined.matchAll(ANTHROPIC_KEY_RE)) {
    if (isLikelyAnthropicKey(m[0])) return m[0];
  }
  return null;
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

export type CloudStorageProvider = "s3" | "gcs" | "r2";

export interface CloudStorageBucket {
  provider: CloudStorageProvider;
  bucket: string;
  /** Read-only list/probe URL used to confirm public listing. */
  listUrl: string;
  /** Where in the bundle the reference was found (redacted host path). */
  sourceHint: string;
}

const CLOUD_BUCKET_SKIP = new Set([
  "example",
  "examples",
  "test",
  "demo",
  "samples",
  "public",
  "assets",
  "static",
  "cdn",
  "www",
  "elasticbeanstalk"
]);

function addCloudBucket(
  out: Map<string, CloudStorageBucket>,
  provider: CloudStorageProvider,
  bucket: string,
  listUrl: string,
  sourceHint: string
) {
  const name = bucket.toLowerCase();
  if (name.length < 3 || CLOUD_BUCKET_SKIP.has(name)) return;
  const key = `${provider}:${name}`;
  if (!out.has(key)) out.set(key, { provider, bucket: name, listUrl, sourceHint });
}

/** Extract S3/GCS/R2 bucket references from fetched JS/HTML. Only buckets named in the bundle are probed. */
export function extractCloudStorageBuckets(combined: string): CloudStorageBucket[] {
  const out = new Map<string, CloudStorageBucket>();

  const s3Virtual =
    /https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/gi;
  let m: RegExpExecArray | null;
  while ((m = s3Virtual.exec(combined))) {
    const bucket = m[1];
    addCloudBucket(
      out,
      "s3",
      bucket,
      `https://${bucket}.s3.amazonaws.com/?max-keys=5`,
      m[0].slice(0, 80)
    );
  }

  const s3Path = /https?:\/\/s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/gi;
  while ((m = s3Path.exec(combined))) {
    const bucket = m[1];
    addCloudBucket(
      out,
      "s3",
      bucket,
      `https://${bucket}.s3.amazonaws.com/?max-keys=5`,
      m[0].slice(0, 80)
    );
  }

  const gcsPath = /https?:\/\/storage\.googleapis\.com\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])/gi;
  while ((m = gcsPath.exec(combined))) {
    const bucket = m[1];
    addCloudBucket(
      out,
      "gcs",
      bucket,
      `https://storage.googleapis.com/storage/v1/b/${bucket}/o?maxResults=5`,
      m[0].slice(0, 80)
    );
  }

  const gcsVirtual = /https?:\/\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])\.storage\.googleapis\.com/gi;
  while ((m = gcsVirtual.exec(combined))) {
    const bucket = m[1];
    addCloudBucket(
      out,
      "gcs",
      bucket,
      `https://storage.googleapis.com/storage/v1/b/${bucket}/o?maxResults=5`,
      m[0].slice(0, 80)
    );
  }

  const r2Public = /https?:\/\/(pub-[a-f0-9]{16,}\.r2\.dev)\/?/gi;
  while ((m = r2Public.exec(combined))) {
    const host = m[1];
    addCloudBucket(out, "r2", host, `https://${host}/`, m[0].slice(0, 80));
  }

  const r2Account = /https?:\/\/[a-f0-9]{32}\.r2\.cloudflarestorage\.com\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])/gi;
  while ((m = r2Account.exec(combined))) {
    const bucket = m[1];
    addCloudBucket(
      out,
      "r2",
      bucket,
      m[0].split("?")[0].replace(/\/$/, "") + "/?max-keys=5",
      m[0].slice(0, 80)
    );
  }

  return [...out.values()].slice(0, 4);
}

/** Positive proof that a list request returned object names (not AccessDenied / empty error). */
export function looksPublicBucketListing(body: string, provider: CloudStorageProvider): boolean {
  const trimmed = body.trim();
  if (!trimmed || trimmed.length < 20) return false;
  if (/AccessDenied|AccessDeniedMessage|AllAccessDisabled|InvalidAccessKeyId|SignatureDoesNotMatch/i.test(trimmed)) {
    return false;
  }
  if (provider === "s3" || provider === "r2") {
    if (!/<ListBucketResult[\s>]/i.test(trimmed)) return false;
    return /<(?:Contents|CommonPrefixes)\b/i.test(trimmed);
  }
  if (/\"kind\"\s*:\s*\"storage#objects\"/.test(trimmed) && /\"items\"\s*:\s*\[/.test(trimmed)) {
    return true;
  }
  if (/<ListBucketResult[\s>]/i.test(trimmed) && /<(?:Contents|CommonPrefixes)\b/i.test(trimmed)) {
    return true;
  }
  return false;
}

function b64urlJson(obj: Record<string, unknown>): string {
  const json = JSON.stringify(obj);
  const b64 =
    typeof Buffer !== "undefined"
      ? Buffer.from(json, "utf8").toString("base64")
      : btoa(json);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Build an unsigned JWT with alg:none for safe auth-bypass probes. */
export function buildAlgNoneJwt(payload: Record<string, unknown>): string {
  const header = b64urlJson({ alg: "none", typ: "JWT" });
  const body = b64urlJson(payload);
  return `${header}.${body}.`;
}

export function looksAuthChallenge(doc: { status: number; body: string }): boolean {
  if (doc.status === 401 || doc.status === 403) return true;
  return /unauthorized|invalid token|authentication required|not authenticated|access denied/i.test(
    doc.body.slice(0, 400)
  );
}

export function looksAuthGatedJson(doc: {
  status: number;
  headers: Record<string, string>;
  body: string;
}): boolean {
  if (doc.status < 200 || doc.status >= 300) return false;
  const ct = doc.headers["content-type"] || "";
  if (!/json/i.test(ct) && !/^\s*[\[{]/.test(doc.body.trim())) return false;
  return !/unauthorized|invalid token|forbidden|not authenticated/i.test(doc.body.slice(0, 400));
}

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
  if (body.length < 200) return false;
  if (ADMIN_PANEL_MARKERS.some((re) => re.test(body))) return true;
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
