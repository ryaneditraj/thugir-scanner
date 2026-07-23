// Minimal, defensive HTTP helper for free-tier checks.
// Free checks are single-request and cheap; this enforces timeouts, byte caps, and an
// SSRF/abuse guard that refuses to fetch private / loopback / metadata hosts.

export interface FetchedDoc {
  url: string;
  finalUrl: string;
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  // Raw Set-Cookie values (the forEach header view collapses these into one string, so we keep
  // the array separately for cookie-flag analysis).
  setCookies: string[];
  body: string;
  truncated: boolean;
  // When status===0 (fetch threw), a short human reason so callers can tell the user WHY the
  // target didn't respond (dns / timeout / tls / refused) instead of a blank failure.
  error?: string;
}

const DEFAULT_TIMEOUT_MS = 15000; // real sites (cold hosts, TLS + full body) routinely exceed 8s
const DEFAULT_MAX_BYTES = 1_500_000; // ~1.5MB cap on any single body
// Present as a mainstream browser. Many hosts (Cloudflare, WAFs, some CDNs) reject or hang on
// unknown bot user-agents, which previously surfaced as a false "target did not respond".
const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
const UA = `${BROWSER_UA} ThugirScanner/1.0 (+https://thugirlabs.com/scanner)`;

/** Vercel Security Checkpoint blocks the ThugirScanner UA suffix — retry with a plain browser UA. */
function isVercelSecurityCheckpoint(doc: FetchedDoc): boolean {
  return (
    doc.headers["x-vercel-mitigated"] === "challenge" ||
    (doc.status === 403 && Boolean(doc.headers["x-vercel-challenge-token"]))
  );
}

// Map a thrown fetch error to a short, user-facing reason.
function describeFetchError(e: unknown): string {
  const err = e as { name?: string; code?: string; cause?: { code?: string; message?: string } };
  const code = err?.code || err?.cause?.code || "";
  const name = err?.name || "";
  if (name === "AbortError") return "timed out";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return "domain not found (DNS)";
  if (code === "ECONNREFUSED") return "connection refused";
  if (code === "ECONNRESET") return "connection reset";
  if (code === "ETIMEDOUT" || code === "UND_ERR_CONNECT_TIMEOUT") return "connection timed out";
  if (code === "CERT_HAS_EXPIRED" || code === "DEPTH_ZERO_SELF_SIGNED_CERT" || /CERT|SSL|TLS/i.test(code))
    return "TLS/certificate error";
  const msg = err?.cause?.message || (e instanceof Error ? e.message : "");
  if (/certificate|self-signed|SSL|TLS/i.test(msg)) return "TLS/certificate error";
  return "no response";
}

const PRIVATE_HOST_RE =
  /^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|::1|fc00:|fe80:)/i;
const PRIVATE_172_RE = /^172\.(1[6-9]|2\d|3[0-1])\./;
const METADATA_HOSTS = new Set(["metadata.google.internal", "169.254.169.254"]);

// Well-known third-party platforms a user almost certainly does not own. The free flow
// refuses these so the tool can't be pointed at major infrastructure by an anonymous-ish
// account. (Authorized testing of your own property still goes through Deep Scan, which
// requires verified domain ownership.)
const THIRD_PARTY_APEX = new Set([
  "google.com", "gmail.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
  "amazon.com", "aws.amazon.com", "microsoft.com", "azure.com", "apple.com", "icloud.com",
  "github.com", "gitlab.com", "openai.com", "anthropic.com", "cloudflare.com", "vercel.com",
  "netlify.com", "x.com", "twitter.com", "linkedin.com", "stripe.com", "paypal.com",
  "supabase.com", "firebase.google.com"
]);

export class BlockedTargetError extends Error {}

function apexOf(host: string): string {
  const parts = host.split(".");
  return parts.length <= 2 ? host : parts.slice(-2).join(".");
}

export function normalizeTarget(input: string): URL {
  let raw = input.trim();
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new BlockedTargetError("Invalid URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new BlockedTargetError("Only http/https targets are allowed");
  }
  const host = u.hostname.toLowerCase();
  if (
    PRIVATE_HOST_RE.test(host) ||
    PRIVATE_172_RE.test(host) ||
    METADATA_HOSTS.has(host) ||
    !host.includes(".")
  ) {
    throw new BlockedTargetError("Refusing to scan private/internal hosts");
  }
  if (THIRD_PARTY_APEX.has(host) || THIRD_PARTY_APEX.has(apexOf(host))) {
    throw new BlockedTargetError(
      "That's a third-party platform we don't allow on the free scan. Scan an app you own."
    );
  }
  return u;
}

async function fetchDocOnce(
  url: string,
  userAgent: string,
  opts: {
    timeoutMs?: number;
    maxBytes?: number;
    method?: string;
    body?: string;
    headers?: Record<string, string>;
    redirect?: RequestRedirect;
  }
): Promise<FetchedDoc> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: opts.method ?? "GET",
      redirect: opts.redirect ?? "follow",
      signal: controller.signal,
      body: opts.body,
      headers: { "User-Agent": userAgent, Accept: "*/*", ...(opts.headers ?? {}) }
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
    const getSetCookie = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
    const setCookies = typeof getSetCookie === "function" ? getSetCookie.call(res.headers) : [];

    let body = "";
    let truncated = false;
    const reader = res.body?.getReader();
    if (reader) {
      const decoder = new TextDecoder();
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
          body += decoder.decode(value.slice(0, Math.max(0, maxBytes - (total - value.byteLength))));
          truncated = true;
          await reader.cancel();
          break;
        }
        body += decoder.decode(value, { stream: true });
      }
    }
    return {
      url,
      finalUrl: res.url || url,
      status: res.status,
      ok: res.ok,
      headers,
      setCookies,
      body,
      truncated
    };
  } catch (e) {
    if (e instanceof BlockedTargetError) throw e;
    return {
      url,
      finalUrl: url,
      status: 0,
      ok: false,
      headers: {},
      setCookies: [],
      body: "",
      truncated: false,
      error: describeFetchError(e)
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchDoc(
  url: string,
  opts: {
    timeoutMs?: number;
    maxBytes?: number;
    method?: string;
    body?: string;
    headers?: Record<string, string>;
    /** When "manual", redirect responses are returned without following Location. */
    redirect?: RequestRedirect;
  } = {}
): Promise<FetchedDoc> {
  const first = await fetchDocOnce(url, UA, opts);
  if (!isVercelSecurityCheckpoint(first)) return first;
  const retry = await fetchDocOnce(url, BROWSER_UA, opts);
  if (retry.status > 0 && !isVercelSecurityCheckpoint(retry)) return retry;
  return first;
}

/** raw.githack.com deploy base: https://raw.githack.com/{owner}/{repo}/{branch}/ */
export function githackDeployBase(pageUrl: string): string | null {
  try {
    const u = new URL(pageUrl);
    if (!u.hostname.endsWith("githack.com")) return null;
    const parts = u.pathname.split("/").filter(Boolean);
    if (parts.length < 3) return null;
    return `https://${u.hostname}/${parts[0]}/${parts[1]}/${parts[2]}/`;
  } catch {
    return null;
  }
}

/** Map raw.githack.com asset URL to raw.githubusercontent.com sibling (Cloudflare blocks .jsx on githack). */
export function toRawGithubusercontentUrl(url: string): string | null {
  const m = url.match(/^https:\/\/raw\.githack\.com\/(.+)$/);
  return m ? `https://raw.githubusercontent.com/${m[1]}` : null;
}

/** Resolve script/asset paths — githack absolute /src/ paths must stay under owner/repo/branch. */
export function resolvePageAssetUrl(raw: string, pageUrl: string): string | null {
  const githackBase = githackDeployBase(pageUrl);
  if (githackBase) {
    try {
      const rel = raw.startsWith("/") ? raw.slice(1) : raw;
      return new URL(rel, githackBase).toString();
    } catch {
      /* fall through */
    }
  }
  try {
    return new URL(raw, pageUrl).toString();
  } catch {
    return null;
  }
}

// Extract same-origin script URLs referenced by an HTML document.
// Resolve relative src against the page URL (not bare origin) so subpath deploys work.
export function extractScriptUrls(html: string, pageUrl: string, limit = 12): string[] {
  const urls = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  const add = (raw: string) => {
    const abs = resolvePageAssetUrl(raw, pageUrl);
    if (!abs) return;
    try {
      if (new URL(abs).origin === pageOrigin) urls.add(abs);
    } catch {
      /* ignore malformed */
    }
  };
  const scriptRe = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = scriptRe.exec(html))) add(m[1]);
  // Vite/React SPAs often lazy-load lab content via modulepreload only (e.g. SecTrainer lesson-content chunk).
  const preloadRe = /<link[^>]+rel=["']modulepreload["'][^>]+href=["']([^"']+)["']/gi;
  while ((m = preloadRe.exec(html))) add(m[1]);
  const preloadReAlt = /<link[^>]+href=["']([^"']+)["'][^>]+rel=["']modulepreload["']/gi;
  while ((m = preloadReAlt.exec(html))) add(m[1]);
  const prioritized = [...urls].sort((a, b) => {
    const score = (u: string) => {
      const path = u.toLowerCase();
      if (/lesson-content|lab-content|challenge-content/.test(path)) return 0;
      if (/\/assets\/index-/.test(path)) return 1;
      return 2;
    };
    return score(a) - score(b);
  });
  return prioritized.slice(0, Math.max(1, limit)); // free tier: cap scripts examined
}

// Apex helper reused by the runner's per-operator denylist.
export function hostApex(host: string): string {
  const parts = host.toLowerCase().split(".");
  return parts.length <= 2 ? host.toLowerCase() : parts.slice(-2).join(".");
}

const HTML_RE = /text\/html|application\/xhtml/i;
export function looksHtml(headers: Record<string, string>, body: string): boolean {
  const ct = headers["content-type"] || "";
  if (HTML_RE.test(ct)) return true;
  return /^\s*<(?:!doctype|html)/i.test(body);
}
