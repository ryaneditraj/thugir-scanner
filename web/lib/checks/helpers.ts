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
  // GCS JSON list
  if (/\"kind\"\s*:\s*\"storage#objects\"/.test(trimmed) && /\"items\"\s*:\s*\[/.test(trimmed)) {
    return true;
  }
  // GCS XML fallback (some buckets answer with XML)
  if (/<ListBucketResult[\s>]/i.test(trimmed) && /<(?:Contents|CommonPrefixes)\b/i.test(trimmed)) {
    return true;
  }
  return false;
}
