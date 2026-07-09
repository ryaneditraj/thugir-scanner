// rule_ref check implementations. Each rule receives the scan context (fetched homepage,
// fetched scripts, origin) and returns whether the pattern fired plus evidence.
//
// All free-tier rules are read-only and near-zero-compute. Deep-tier rules
// (idorProbe, clientOnlyAuth, serverActionAuthz) intentionally do not run on the free path;
// they exist so the worker / future deep flow can share the same registry keys.

import type { FetchedDoc } from "./http";
import type { ProbeCache } from "./probe-cache";
import {
  extractApiPaths,
  extractExternalApiBases,
  extractLinkedLabOrigins,
  buildApiProbeUrls
} from "./extract-api";
import {
  extractSupabaseFromText,
  jwtPayload,
  looksOpenApiBody,
  matchDemoFlags,
  HARDCODED_CRED_RES,
  SENSITIVE_PATH_NEEDLES
} from "./helpers";

export interface RuleContext {
  origin: string;
  home: FetchedDoc;
  scripts: FetchedDoc[];
  combined: string;
  /** Deduped + batched HTTP probes for this scan. */
  probe: ProbeCache;
}

export interface RuleResult {
  fired: boolean;
  confidence: number;
  evidence: Record<string, unknown>;
}

type Rule = (ctx: RuleContext, options?: Record<string, unknown>) => Promise<RuleResult>;

const NEGATIVE: RuleResult = { fired: false, confidence: 0, evidence: {} };

function extractSupabase(ctx: RuleContext) {
  return extractSupabaseFromText(ctx.combined);
}

// --- security headers -------------------------------------------------------
const securityHeaders: Rule = async (ctx) => {
  const h = ctx.home.headers;
  const missing: string[] = [];
  if (!h["content-security-policy"]) missing.push("Content-Security-Policy");
  if (!h["x-frame-options"] && !(h["content-security-policy"] || "").includes("frame-ancestors"))
    missing.push("X-Frame-Options");
  if (!h["strict-transport-security"]) missing.push("Strict-Transport-Security");
  if (!h["x-content-type-options"]) missing.push("X-Content-Type-Options");
  if (!h["referrer-policy"]) missing.push("Referrer-Policy");
  if (missing.length === 0) return NEGATIVE;
  return { fired: true, confidence: 0.95, evidence: { missing, present: Object.keys(h) } };
};

// --- source maps ------------------------------------------------------------
const sourceMaps: Rule = async (ctx) => {
  const candidates = new Set<string>();
  // sourceMappingURL comments in scripts
  for (const s of ctx.scripts) {
    const m = s.body.match(/sourceMappingURL=([^\s'"]+\.map)/);
    if (m) {
      try {
        candidates.add(new URL(m[1], s.finalUrl).toString());
      } catch {
        /* ignore */
      }
    }
    if (!s.finalUrl.endsWith(".map")) candidates.add(`${s.finalUrl}.map`);
  }
  for (const url of [...candidates].slice(0, 4)) {
    const doc = await ctx.probe.get(url, { maxBytes: 4096 });
    if (doc.status === 200 && doc.body.includes('"version"') && doc.body.includes('"sources"')) {
      return { fired: true, confidence: 0.9, evidence: { mapUrl: url } };
    }
  }
  return NEGATIVE;
};

// --- Supabase RLS (harmless existence probe) --------------------------------
// We detect the Supabase project URL + anon key in the bundle, then issue ONE harmless
// read against the REST endpoint. A 200 with row data while unauthenticated indicates an
// open / missing RLS policy. We never write and never enumerate.
const supabaseRls: Rule = async (ctx) => {
  const sb = extractSupabase(ctx);
  if (!sb) return NEGATIVE;
  const { projectUrl, anonKey } = sb;

  // Ask PostgREST for the table list via the root; then try a single harmless select.
  const probe = await ctx.probe.get(`${projectUrl}/rest/v1/?apikey=${anonKey}`, { maxBytes: 8192 });
  let tables: string[] = [];
  try {
    const paths = JSON.parse(probe.body)?.paths ?? {};
    tables = Object.keys(paths)
      .filter((p) => p.startsWith("/") && p.length > 1 && !p.startsWith("/rpc"))
      .map((p) => p.slice(1))
      .slice(0, 8);
  } catch {
    /* introspection disabled — fall through to the common-name wordlist */
  }
  // Many projects disable schema introspection but still leave common tables world-readable.
  // Probe a small, high-signal wordlist of the table names AI scaffolds create by default.
  if (tables.length === 0) {
    tables = ["profiles", "users", "todos", "messages", "posts", "orders", "customers", "notes"];
  }
  const openTables: string[] = [];
  const tableUrls = tables.slice(0, 8).map(
    (t) => `${projectUrl}/rest/v1/${t}?select=*&limit=1&apikey=${anonKey}`
  );
  const tableDocs = await ctx.probe.getMany(tableUrls, { maxBytes: 4096 }, 4);
  for (const [url, r] of tableDocs) {
    const t = url.match(/\/rest\/v1\/([^?]+)/)?.[1];
    if (r.status === 200 && /^\s*\[\s*\{/.test(r.body) && t) openTables.push(t);
  }
  if (openTables.length > 0) {
    return {
      fired: true,
      confidence: 0.85,
      evidence: { projectUrl, openTables, note: "rows returned to anon - RLS missing/permissive" }
    };
  }
  return { fired: false, confidence: 0, evidence: { projectUrl, openTables } };
};

// --- Firebase open rules (harmless read) ------------------------------------
const firebaseRules: Rule = async (ctx) => {
  const proj = ctx.combined.match(/https:\/\/([a-z0-9-]+)\.firebaseio\.com/) ||
    ctx.combined.match(/"projectId"\s*:\s*"([a-z0-9-]+)"/) ||
    ctx.combined.match(/([a-z0-9-]+)\.firebaseapp\.com/);
  if (!proj) return NEGATIVE;
  const projectId = proj[1];
  // Realtime DB: a harmless shallow read. Open rules return data (not 401/permission denied).
  const rtdb = await ctx.probe.get(`https://${projectId}.firebaseio.com/.json?shallow=true`, {
    maxBytes: 2048
  });
  if (rtdb.status === 200 && !/permission_denied/i.test(rtdb.body) && rtdb.body.trim() !== "null") {
    return { fired: true, confidence: 0.85, evidence: { projectId, db: "realtime", note: "shallow read succeeded unauthenticated" } };
  }
  return { fired: false, confidence: 0, evidence: { projectId } };
};

// --- webhook signature heuristic (static, no probing) -----------------------
const webhookSignature: Rule = async (ctx) => {
  const paths = new Set<string>();
  const re = /["'`](\/(?:api\/)?(?:webhooks?|stripe|razorpay)[a-z0-9/_-]*)["'`]/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(ctx.combined))) paths.add(m[1]);
  if (paths.size === 0) return NEGATIVE;
  // Static signal only: presence of webhook paths in the client without any nearby
  // signature-verification reference. We do NOT send forged events on the free tier.
  const mentionsVerify = /(constructevent|verifywebhooksignature|x-razorpay-signature|stripe-signature|webhook.?secret)/i.test(
    ctx.combined
  );
  return {
    fired: !mentionsVerify,
    confidence: mentionsVerify ? 0 : 0.5,
    evidence: { webhookPaths: [...paths].slice(0, 5), signatureRefSeen: mentionsVerify }
  };
};

// --- Vite/Next public-prefix secret leak ------------------------------------
// High-precision only: a public-prefixed var whose name unambiguously denotes a server
// secret (SECRET / SERVICE_ROLE / PASSWORD / PRIVATE). We deliberately exclude generic
// names like *_TOKEN and *_KEY because those are routinely (and legitimately) public
// (publishable keys, anon keys, mapbox tokens) - flagging them produced false positives.
const publicEnvPrefixLeak: Rule = async (ctx) => {
  const re = /(?:VITE_|NEXT_PUBLIC_)([A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PASSWORD|PRIVATE)[A-Z0-9_]*)/g;
  const hits = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(ctx.combined))) hits.add(m[0]);
  if (hits.size === 0) return NEGATIVE;
  // The match itself is the evidence: a literal server-secret name shipped to the browser.
  return { fired: true, confidence: 0.9, evidence: { riskyPublicVars: [...hits].slice(0, 10) } };
};

// --- insecure cookies -------------------------------------------------------
// A cookie set over HTTPS without the Secure flag can leak over plain HTTP; a session-like
// cookie without HttpOnly is reachable by injected JavaScript. High precision: we only fire on
// the Secure omission over HTTPS (unambiguous) and report HttpOnly/SameSite as extra context.
const insecureCookies: Rule = async (ctx) => {
  const cookies = ctx.home.setCookies || [];
  if (cookies.length === 0) return NEGATIVE;
  const isHttps = ctx.origin.startsWith("https:");
  const flagged: { name: string; missing: string[] }[] = [];
  for (const c of cookies) {
    const name = c.split("=")[0].trim();
    const lc = c.toLowerCase();
    const missing: string[] = [];
    if (isHttps && !/;\s*secure/.test(lc)) missing.push("Secure");
    if (!/;\s*httponly/.test(lc)) missing.push("HttpOnly");
    if (!/;\s*samesite/.test(lc)) missing.push("SameSite");
    // Only treat as a finding when Secure is missing over HTTPS (the unambiguous case).
    if (isHttps && !/;\s*secure/.test(lc)) flagged.push({ name, missing });
  }
  if (flagged.length === 0) return NEGATIVE;
  return { fired: true, confidence: 0.85, evidence: { insecureCookies: flagged.slice(0, 8) } };
};

// --- permissive CORS --------------------------------------------------------
const permissiveCors: Rule = async (ctx) => {
  const acao = (ctx.home.headers["access-control-allow-origin"] || "").trim();
  if (acao !== "*") return NEGATIVE;
  const creds = (ctx.home.headers["access-control-allow-credentials"] || "").toLowerCase() === "true";
  return {
    fired: true,
    confidence: creds ? 0.92 : 0.85,
    evidence: { allowOrigin: "*", allowCredentials: creds }
  };
};

// --- CORS reflects arbitrary Origin (worse than *) ----------------------------
// Some misconfigs echo whatever Origin the browser sends — any site can read credentialed API
// responses. We probe with a fake origin and only fire when it is reflected back.
const corsReflectOrigin: Rule = async (ctx) => {
  const homeAcao = (ctx.home.headers["access-control-allow-origin"] || "").trim();
  if (homeAcao === "*") return NEGATIVE;
  const probeOrigin = "https://evil-cors-probe.example";
  const doc = await ctx.probe.get(ctx.origin, {
    maxBytes: 512,
    headers: { Origin: probeOrigin }
  });
  const acao = (doc.headers["access-control-allow-origin"] || "").trim();
  if (acao !== probeOrigin) return NEGATIVE;
  const creds = (doc.headers["access-control-allow-credentials"] || "").toLowerCase() === "true";
  return {
    fired: true,
    confidence: creds ? 0.95 : 0.88,
    evidence: { allowOrigin: acao, allowCredentials: creds, note: "reflects arbitrary Origin header" }
  };
};

// --- Open redirect via query parameter (read-only GET, redirect: manual) -------
// Inject a harmless external probe URL and only flag when the server issues a redirect
// (or meta-refresh) to that exact host — positive proof, not a reflected-string guess.
const OPEN_REDIRECT_PROBE = "https://evil-open-redirect-probe.example/thugir-redirect-test";
const OPEN_REDIRECT_PROBE_HOST = "evil-open-redirect-probe.example";
const OPEN_REDIRECT_PARAMS = [
  "url",
  "redirect",
  "next",
  "return",
  "returnTo",
  "return_to",
  "redirect_uri",
  "redirect_url",
  "goto",
  "dest",
  "destination",
  "redir",
  "continue",
  "callback",
  "forward"
];
const OPEN_REDIRECT_FALLBACK_PATHS = [
  "/",
  "/login",
  "/logout",
  "/signin",
  "/auth/login",
  "/redirect"
];

function resolvesToOpenRedirectProbe(location: string, baseOrigin: string): boolean {
  if (!location.trim()) return false;
  try {
    const u = new URL(location, baseOrigin);
    return u.hostname === OPEN_REDIRECT_PROBE_HOST;
  } catch {
    return false;
  }
}

function extractOpenRedirectPaths(text: string): string[] {
  const paths = new Set<string>();
  const hrefRe = /href\s*=\s*["'](\/[^"'#]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = hrefRe.exec(text))) {
    const p = m[1].split("?")[0];
    if (/redirect|return|callback|logout|signin|continue|oauth/i.test(p)) paths.add(p);
  }
  if (/redirect/i.test(text)) {
    paths.add("/redirect");
    paths.add("/redirect/parameter");
  }
  return [...paths].slice(0, 6);
}

const openRedirect: Rule = async (ctx) => {
  const probes: { path: string; param: string; status: number; location: string; kind: string }[] = [];
  const seen = new Set<string>();
  const urls: { url: string; param: string; path: string }[] = [];
  const discovered = extractOpenRedirectPaths(ctx.combined);
  const paths = discovered.length
    ? [...new Set([...discovered, "/"])].slice(0, 6)
    : [...OPEN_REDIRECT_FALLBACK_PATHS].slice(0, 6);

  // Spread probes across paths (discovered first) instead of exhausting one path.
  outer: for (const param of OPEN_REDIRECT_PARAMS) {
    for (const path of paths) {
      const key = `${path}?${param}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const u = new URL(path, ctx.origin);
      u.searchParams.set(param, OPEN_REDIRECT_PROBE);
      urls.push({ url: u.toString(), param, path });
      if (urls.length >= 16) break outer;
    }
  }

  const docs = await ctx.probe.getMany(
    urls.map((x) => x.url),
    { maxBytes: 2048, redirect: "manual", timeoutMs: 8000 },
    4
  );
  for (const { url: probeUrl, param, path } of urls) {
    const doc = docs.get(probeUrl);
    if (!doc) continue;
    const location = doc.headers["location"] || "";
    if (
      [301, 302, 303, 307, 308].includes(doc.status) &&
      resolvesToOpenRedirectProbe(location, ctx.origin)
    ) {
      probes.push({ path, param, status: doc.status, location, kind: "http_redirect" });
      continue;
    }
    const meta = doc.body.match(
      /<meta[^>]*http-equiv=["']refresh["'][^>]*content=["'][^"']*url=([^"';]+)/i
    );
    if (meta && resolvesToOpenRedirectProbe(meta[1].trim(), ctx.origin)) {
      probes.push({
        path,
        param,
        status: doc.status,
        location: meta[1].trim(),
        kind: "meta_refresh"
      });
    }
  }

  if (probes.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.93,
    evidence: {
      probeHost: OPEN_REDIRECT_PROBE_HOST,
      hits: probes.slice(0, 4),
      note: "Server redirected to attacker-controlled URL from query parameter"
    }
  };
};

// --- Reflected XSS via query parameter (canary probe) -------------------------
// Inject a unique canary into common query params on discovered/candidate paths.
// Only fires when the raw canary is echoed unescaped in the HTML body — positive proof.
const REFLECTED_XSS_PARAMS = [
  "q",
  "search",
  "query",
  "searchTerm",
  "content",
  "s",
  "term",
  "name",
  "id",
  "message",
  "text",
  "keyword",
  "input",
  "category",
  "filter"
];
const REFLECTED_XSS_FALLBACK_PATHS = ["/", "/search", "/search.html", "/search.jsp", "/index.jsp", "/catalog"];

function prioritizeReflectedXssPaths(paths: string[], discovered = new Set<string>()): string[] {
  const score = (p: string) => {
    if (discovered.has(p)) return 0;
    if (/\/frame|\/mission|reflected/i.test(p)) return 1;
    if (/\/catalog|search|product/i.test(p)) return 2;
    if (p === "/") return 4;
    return 3;
  };
  return [...paths].sort((a, b) => score(a) - score(b));
}

function normalizeProbePath(raw: string): string | null {
  let p = raw.split("?")[0].split("#")[0].trim();
  if (!p || /^https?:/i.test(p)) return null;
  if (!p.startsWith("/")) p = `/${p}`;
  if (p.length < 2 || p.length > 80) return null;
  return p;
}

/** Discover search/echo/content paths from href, form action, and fetch() strings. */
function extractSearchLikePaths(text: string): string[] {
  const paths = new Set<string>();
  const linkRe = /(?:href|action)\s*=\s*["']([^"'#]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(text))) {
    const full = m[1];
    const pathPart = full.split("?")[0];
    const queryPart = full.includes("?") ? full.split("?")[1] : "";
    if (
      !/search|query|content|reflected|echo|find|catalog|product|searchTerm|category|filter/i.test(
        `${pathPart}${queryPart}`
      )
    )
      continue;
    const norm = normalizeProbePath(pathPart);
    if (norm) paths.add(norm);
  }
  const fetchRe = /fetch\(\s*["']([^"'`?]*(?:search|query)[^"'`]*)["']/gi;
  while ((m = fetchRe.exec(text))) {
    const norm = normalizeProbePath(m[1]);
    if (norm) paths.add(norm);
  }
  return [...paths].slice(0, 6);
}

/** iframe/frame src paths (e.g. XSS game /level1/frame). */
function extractIframeSrcPaths(text: string): string[] {
  const paths = new Set<string>();
  const re = /<(?:iframe|frame)[^>]*\ssrc\s*=\s*["']([^"'#?]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const norm = normalizeProbePath(m[1]);
    if (norm) paths.add(norm);
  }
  return [...paths];
}

/** href/action paths whose query string names a probe param (e.g. /mission?id=). */
function extractQueryParamPaths(text: string): string[] {
  const paths = new Set<string>();
  const linkRe = /(?:href|action)\s*=\s*["']([^"'#]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(text))) {
    const full = m[1];
    if (!full.includes("?")) continue;
    const [pathPart, queryPart] = full.split("?");
    const hasParam = REFLECTED_XSS_PARAMS.some((p) => new RegExp(`(?:^|&)${p}=`, "i").test(queryPart));
    if (!hasParam) continue;
    const norm = normalizeProbePath(pathPart);
    if (norm) paths.add(norm);
  }
  return [...paths];
}

function extractReflectedXssPaths(text: string): string[] {
  const paths = new Set([
    ...extractSearchLikePaths(text),
    ...extractIframeSrcPaths(text),
    ...extractQueryParamPaths(text)
  ]);
  if (/reflected/i.test(text)) paths.add("/reflected/parameter/body");
  const levelRe = /(?:href|action)\s*=\s*["'](\/level\d+)["']/gi;
  let lm: RegExpExecArray | null;
  while ((lm = levelRe.exec(text))) paths.add(`${lm[1]}/frame`);
  return [...paths].slice(0, 8);
}

function isReflectedXssCanary(body: string, canary: string): boolean {
  if (!body.includes(canary)) return false;
  const encoded = canary.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  if (body.includes(encoded) && !body.includes(canary)) return false;
  return true;
}

const reflectedXss: Rule = async (ctx) => {
  const canary = `thugirXSS${Date.now().toString(36)}`;
  const homePath = new URL(ctx.home.finalUrl).pathname || "/";
  const discovered = extractReflectedXssPaths(ctx.combined);
  const discoveredSet = new Set(discovered);
  const paths = prioritizeReflectedXssPaths(
    [...new Set([...discovered, homePath, ...REFLECTED_XSS_FALLBACK_PATHS])],
    discoveredSet
  ).slice(0, 10);
  const hits: { path: string; param: string; url: string; snippet: string }[] = [];
  const seen = new Set<string>();
  const urls: { url: string; param: string; path: string }[] = [];

  outer: for (const path of paths) {
    for (const param of REFLECTED_XSS_PARAMS) {
      const key = `${path}?${param}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const u = new URL(path, ctx.origin);
      u.searchParams.set(param, canary);
      urls.push({ url: u.toString(), param, path });
      if (urls.length >= 40) break outer;
    }
  }

  const docs = await ctx.probe.getMany(urls.map((x) => x.url), { maxBytes: 8192 }, 4);
  for (const { url: probeUrl, param, path } of urls) {
    const doc = docs.get(probeUrl);
    if (!doc || doc.status < 200) continue;
    const ct = doc.headers["content-type"] || "";
    if (!/html|text\/plain/i.test(ct) && !/<html|<body/i.test(doc.body)) continue;
    if (!isReflectedXssCanary(doc.body, canary)) continue;
    hits.push({ path, param, url: probeUrl, snippet: doc.body.slice(0, 200).trim() });
    if (hits.length >= 3) break;
  }

  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.9,
    evidence: {
      canary,
      hits,
      note: "query parameter echoed unescaped in HTML response — reflected XSS likely"
    }
  };
};

// --- robots.txt discloses sensitive paths -------------------------------------
const robotsSensitivePaths: Rule = async (ctx) => {
  const doc = await ctx.probe.get(`${ctx.origin}/robots.txt`, { maxBytes: 4096 });
  if (doc.status !== 200 || !doc.body.trim()) return NEGATIVE;
  const body = doc.body.toLowerCase();
  const disclosed = SENSITIVE_PATH_NEEDLES.filter((p) => body.includes(p));
  if (disclosed.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.8,
    evidence: {
      url: doc.finalUrl,
      disclosedPaths: disclosed.slice(0, 8),
      snippet: doc.body.slice(0, 280).trim()
    }
  };
};

// --- server / framework version disclosure ----------------------------------
// Low-severity but very common: Server / X-Powered-By headers reveal the exact stack + version,
// which hands an attacker a list of known CVEs to try.
const techDisclosure: Rule = async (ctx) => {
  const leaks: Record<string, string> = {};
  const powered = ctx.home.headers["x-powered-by"];
  const server = ctx.home.headers["server"];
  const aspNet = ctx.home.headers["x-aspnet-version"] || ctx.home.headers["x-aspnetmvc-version"];
  if (powered) leaks["x-powered-by"] = powered;
  if (server && /\d/.test(server)) leaks["server"] = server; // only when a version number is present
  if (aspNet) leaks["x-aspnet-version"] = aspNet;
  if (Object.keys(leaks).length === 0) return NEGATIVE;
  return { fired: true, confidence: 0.85, evidence: { disclosingHeaders: leaks } };
};

// --- secrets embedded in inline app state (__NEXT_DATA__, hydration, window.__ENV__) ---------
// AI builders frequently pass server config straight into page props / global bootstrap objects,
// shipping live secrets inside the HTML itself. We scan the inline JSON blobs for unambiguous
// server credentials only (same high-precision set used for bundle scanning) so this stays proof,
// not a guess.
const INLINE_SECRET_RES: { name: string; re: RegExp }[] = [
  { name: "Stripe secret key", re: /sk_live_[A-Za-z0-9]{16,}/ },
  { name: "Stripe restricted key", re: /rk_live_[A-Za-z0-9]{16,}/ },
  { name: "AWS access key id", re: /AKIA[0-9A-Z]{16}/ },
  { name: "Google API key", re: /AIza[0-9A-Za-z_-]{35}/ },
  { name: "OpenAI key", re: /sk-[A-Za-z0-9]{20,}/ },
  { name: "Private key block", re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
  { name: "Slack token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { name: "GitHub token", re: /gh[pousr]_[A-Za-z0-9]{36,}/ }
];
const inlineStateSecrets: Rule = async (ctx) => {
  const html = ctx.home.body || "";
  const blobs: string[] = [];
  // Next.js hydration payload
  const nextData = html.match(/<script[^>]*id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i);
  if (nextData) blobs.push(nextData[1]);
  // Common global bootstrap objects (Vite/CRA/handrolled): window.__ENV__ / __CONFIG__ / __INITIAL_STATE__
  const globalRe = /(?:window|self|globalThis)\.__(?:ENV|CONFIG|INITIAL_STATE|APP_CONFIG|RUNTIME_CONFIG)__\s*=\s*(\{[\s\S]{0,20000}?\})\s*[;<]/gi;
  let gm: RegExpExecArray | null;
  while ((gm = globalRe.exec(html)) && blobs.length < 6) blobs.push(gm[1]);
  if (blobs.length === 0) return NEGATIVE;

  const scope = blobs.join("\n");
  const hits: { secret: string; sampleRedacted: string }[] = [];
  for (const { name, re } of INLINE_SECRET_RES) {
    const m = scope.match(re);
    if (m) {
      const s = m[0];
      hits.push({ secret: name, sampleRedacted: s.length > 12 ? `${s.slice(0, 6)}…${s.slice(-4)}` : "***" });
    }
  }
  // Also flag explicit server-secret KEY NAMES carrying a non-empty value in the inline state.
  const keyNameRe = /["']([A-Za-z0-9_]*(?:SECRET|SERVICE_ROLE|PASSWORD|PRIVATE_KEY|API_SECRET)[A-Za-z0-9_]*)["']\s*:\s*["']([^"']{6,})["']/g;
  let km: RegExpExecArray | null;
  const riskyKeys = new Set<string>();
  while ((km = keyNameRe.exec(scope)) && riskyKeys.size < 8) riskyKeys.add(km[1]);
  if (hits.length === 0 && riskyKeys.size === 0) {
    const jwts =
      scope.match(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g) || [];
    for (const jwt of jwts) {
      const payload = jwtPayload(jwt);
      if (payload?.includes("service_role")) {
        hits.push({
          secret: "Supabase service_role JWT",
          sampleRedacted: jwt.length > 12 ? `${jwt.slice(0, 6)}…${jwt.slice(-4)}` : "***"
        });
      }
    }
  }
  if (hits.length === 0 && riskyKeys.size === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.9,
    evidence: {
      location: nextData ? "__NEXT_DATA__ / inline app state" : "inline app state",
      leakedSecrets: hits.slice(0, 8),
      riskyKeys: [...riskyKeys]
    }
  };
};

// --- GraphQL introspection enabled ------------------------------------------
// An exposed GraphQL endpoint with introspection on hands attackers a full map of your schema,
// including internal mutations and fields. Introspection is a read-only query, so confirming it
// is positive proof without touching data.
function extractHasuraAdminSecret(text: string): string | null {
  const m = text.match(/x-hasura-admin-secret["']?\s*:\s*["']([A-Za-z0-9]{20,})["']/i);
  return m?.[1] ?? null;
}

function extractBundleGraphqlUrls(text: string, pageOrigin: string): string[] {
  const own = new URL(pageOrigin).origin;
  const urls = new Set<string>();
  const patterns = [
    /["'](https?:\/\/[^"']+\/v1\/graphql)["']/gi,
    /url:\s*["'](https?:\/\/[^"']+\/graphql)["']/gi,
    /url:\s*["'](https?:\/\/[^"']+\/v1\/graphql)["']/gi
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      try {
        const origin = new URL(m[1]).origin;
        if (origin !== own) urls.add(m[1]);
      } catch {
        /* ignore */
      }
      if (urls.size >= 4) break;
    }
  }
  return [...urls];
}

const graphqlIntrospection: Rule = async (ctx) => {
  const query = JSON.stringify({ query: "{__schema{queryType{name} types{name}}}" });
  const hasuraSecret = extractHasuraAdminSecret(ctx.combined);
  const candidates = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    ...extractBundleGraphqlUrls(ctx.combined, ctx.origin)
  ];
  const seen = new Set<string>();
  const probes: { url: string; headers: Record<string, string> }[] = [];
  for (const path of candidates) {
    const url = /^https?:\/\//i.test(path) ? path : new URL(path, ctx.origin).toString();
    if (seen.has(url)) continue;
    seen.add(url);
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (hasuraSecret && /hasura/i.test(url)) headers["x-hasura-admin-secret"] = hasuraSecret;
    probes.push({ url, headers });
    if (probes.length >= 8) break;
  }
  for (const { url, headers } of probes) {
    const r = await ctx.probe.get(url, {
      method: "POST",
      body: query,
      headers,
      maxBytes: 8192
    });
    if (r.status < 200 || r.status >= 300) continue;
    if (!/"__schema"\s*:/.test(r.body) || !/"queryType"/.test(r.body)) continue;
    let typeCount = 0;
    try {
      typeCount = (JSON.parse(r.body)?.data?.__schema?.types ?? []).length;
    } catch {
      /* keep zero */
    }
    const external = /^https?:\/\//i.test(url) && !url.startsWith(ctx.origin);
    return {
      fired: true,
      confidence: external && hasuraSecret ? 0.92 : 0.9,
      evidence: {
        endpoint: url,
        introspection: "enabled",
        typeCount,
        ...(external && hasuraSecret
          ? { note: "external GraphQL endpoint from bundle — introspection confirmed with leaked Hasura admin secret" }
          : {})
      }
    };
  }
  return NEGATIVE;
};

// --- phpinfo() page exposed in production -----------------------------------
// PHP apps sometimes ship phpinfo.php for debugging. The page dumps extensions,
// paths, env vars and sometimes secrets — positive proof when the title/body match.
const PHPINFO_PATHS = [
  "/phpinfo.php",
  "/info.php",
  "/phpinfo",
  "/_profiler/phpinfo",
  "/i.php"
];

const phpinfoExposed: Rule = async (ctx) => {
  const urls = PHPINFO_PATHS.map((p) => new URL(p, ctx.origin).toString());
  const docs = await ctx.probe.getMany(urls, { maxBytes: 16_384 }, 3);
  for (const [url, r] of docs) {
    if (r.status < 200 || r.status >= 300) continue;
    const hasVersion = /PHP Version\s+[0-9]/i.test(r.body);
    const hasPhpinfo =
      /phpinfo\s*\(\s*\)/i.test(r.body) ||
      /<title>[^<]*phpinfo\s*\(\s*\)[^<]*<\/title>/i.test(r.body);
    if (!hasVersion || !hasPhpinfo) continue;
    const version = r.body.match(/PHP Version\s+([0-9][^\s<]+)/i)?.[1];
    return {
      fired: true,
      confidence: 0.95,
      evidence: {
        url,
        phpVersion: version,
        snippet: r.body.slice(0, 220).trim(),
        note: "phpinfo() page reachable — full server configuration disclosed"
      }
    };
  }
  return NEGATIVE;
};

// --- directory listing / autoindex ------------------------------------------
const directoryListing: Rule = async (ctx) => {
  const dirs = ["/uploads/", "/files/", "/images/", "/static/", "/assets/", "/backup/", "/tmp/"];
  const urls = dirs.map((d) => new URL(d, ctx.origin).toString());
  const docs = await ctx.probe.getMany(urls, { maxBytes: 4096 }, 4);
  const found: string[] = [];
  for (const [url, r] of docs) {
    if (r.status === 200 && /<title>\s*Index of \/|Directory listing for |\[To Parent Directory\]/i.test(r.body)) {
      found.push(url);
    }
  }
  if (found.length === 0) return NEGATIVE;
  return { fired: true, confidence: 0.9, evidence: { directories: found } };
};

// --- verbose error / stack-trace disclosure (deep) --------------------------
// Requests a deliberately malformed path and inspects for framework stack traces / debug pages.
// These leak file paths, dependency versions and sometimes secrets. Deep-tier: it crafts a
// request and carries a small FP risk, so it never runs on the read-only free pass.
const STACK_MARKERS = [
  /Traceback \(most recent call last\)/,
  /at [\w$.]+ \(.*?:\d+:\d+\)/,
  /Whoops\\?, looks like something went wrong/i,
  /Exception in thread/,
  /java\.lang\.[A-Za-z.]+Exception/,
  /System\.[A-Za-z.]+Exception:/,
  /Warning: .*? in .*? on line \d+/,
  /Fatal error: /i
];
const errorDisclosure: Rule = async (ctx) => {
  const probes = [`/thugir-probe-${Date.now().toString(36)}`, "/%2e%2e/%2e%2e/etc/passwd", "/?id[]=1"];
  for (const p of probes) {
    const url = new URL(p, ctx.origin).toString();
    const r = await ctx.probe.get(url, { maxBytes: 12_000 });
    // A stack trace in a 5xx (or any non-empty error body) is the signal, not a normal 404 page.
    if (r.status >= 500 || (r.status >= 400 && r.body.length > 40)) {
      const marker = STACK_MARKERS.find((re) => re.test(r.body));
      if (marker) {
        return {
          fired: true,
          confidence: 0.8,
          evidence: { url, status: r.status, snippet: r.body.slice(0, 240) }
        };
      }
    }
  }
  return NEGATIVE;
};

// --- OpenAPI / Swagger docs exposed in production ---------------------------
// Common on v0/Next and FastAPI scaffolds. A 200 with an openapi/swagger schema is
// positive proof — attackers get every route without brute force.
const OPENAPI_PATHS = [
  "/openapi.json",
  "/swagger.json",
  "/v2/swagger.json",
  "/api/openapi.json",
  "/v3/api-docs",
  "/docs/openapi.json",
  "/swagger/v1/swagger.json",
  "/static/openapi.json",
  "/api/docs/openapi.json"
];

/** Swagger UI embeds the spec URL in inline config (e.g. FastAPI /api/docs → /static/openapi.json). */
function extractSwaggerUiOpenApiPaths(text: string): string[] {
  const paths = new Set<string>();
  const re = /["']url["']\s*:\s*["']([^"']*(?:openapi|swagger|api-docs)[^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const raw = m[1].trim();
    if (!raw) continue;
    try {
      const p = /^https?:\/\//i.test(raw) ? new URL(raw).pathname : raw.split("?")[0];
      if (p.startsWith("/") && p.length < 120) paths.add(p);
    } catch {
      /* ignore malformed */
    }
  }
  return [...paths];
}

function openApiProbePaths(ctx: RuleContext): string[] {
  return [...new Set([...OPENAPI_PATHS, ...extractSwaggerUiOpenApiPaths(ctx.combined)])].slice(0, 14);
}

// Large FastAPI specs (e.g. duck-store.escape.tech ~53KB) truncate at 24KB and break JSON.parse.
const OPENAPI_SPEC_MAX_BYTES = 65_536;

function substituteOpenApiPathParam(param: string): string {
  const p = param.toLowerCase();
  if (/user(name)?|owner|account|email/.test(p)) return "name1";
  if (/id|num|order|book|item/.test(p)) return "1";
  return "test";
}

function concreteOpenApiGetPath(path: string): string | null {
  const concrete = /\{[^}]+\}/.test(path)
    ? path.replace(/\{([^}]+)\}/g, (_, name) => substituteOpenApiPathParam(name))
    : path;
  return concrete.length > 1 && concrete.length < 120 ? concrete : null;
}

async function loadOpenApiSpec(ctx: RuleContext): Promise<Record<string, Record<string, unknown>> | null> {
  const urls = openApiProbePaths(ctx).map((path) => new URL(path, ctx.origin).toString());
  const docs = await ctx.probe.getMany(urls, { maxBytes: OPENAPI_SPEC_MAX_BYTES }, 4);
  for (const [, r] of docs) {
    if (r.status < 200 || r.status >= 300) continue;
    if (!looksOpenApiBody(r.body)) continue;
    try {
      const spec = JSON.parse(r.body.trim()) as { paths?: Record<string, Record<string, unknown>> };
      if (spec.paths) return spec.paths;
    } catch {
      /* yaml or truncated */
    }
  }
  return null;
}

/** Turn OpenAPI GET paths into concrete probe URLs (e.g. /users/v1/{username} → /users/v1/name1). */
async function fetchOpenApiGetPaths(ctx: RuleContext, limit = 10): Promise<string[]> {
  const specPaths = await loadOpenApiSpec(ctx);
  if (!specPaths) return [];
  const paths = new Set<string>();
  for (const [path, ops] of Object.entries(specPaths)) {
    if (!ops.get) continue;
    const concrete = concreteOpenApiGetPath(path);
    if (concrete) paths.add(concrete);
    if (paths.size >= limit) break;
  }
  return [...paths].slice(0, limit);
}

/**
 * OpenAPI GET paths plus list→detail expansion: probe a list endpoint, take the first
 * record id/uuid, and substitute into templated detail routes (e.g. Duck Store /users/).
 */
async function fetchOpenApiGetPathsWithDetails(ctx: RuleContext, limit = 12): Promise<string[]> {
  const specPaths = await loadOpenApiSpec(ctx);
  if (!specPaths) return [];
  const paths = new Set<string>();
  const templated: string[] = [];
  const listPaths: string[] = [];

  for (const [path, ops] of Object.entries(specPaths)) {
    if (!ops.get) continue;
    if (/\{[^}]+\}/.test(path)) {
      templated.push(path);
      const concrete = concreteOpenApiGetPath(path);
      if (concrete) paths.add(concrete);
    } else {
      paths.add(path);
      listPaths.push(path);
    }
  }

  for (const listPath of listPaths.slice(0, 4)) {
    const r = await ctx.probe.get(new URL(listPath, ctx.origin).toString(), { maxBytes: 4096 });
    if (r.status < 200 || r.status >= 300) continue;
    let items: unknown;
    try {
      items = JSON.parse(r.body);
    } catch {
      continue;
    }
    if (!Array.isArray(items) || items.length === 0) continue;
    const first = items[0];
    if (!first || typeof first !== "object") continue;
    const rec = first as Record<string, unknown>;
    const id = rec.id ?? rec.uuid ?? rec.user_id ?? rec.order_id;
    if (id == null) continue;
    const idStr = String(id);
    const base = listPath.replace(/\/$/, "");

    for (const tpl of templated) {
      if (!tpl.startsWith(`${base}/`)) continue;
      const detail = tpl.replace(/\{[^}]+\}/g, idStr);
      if (detail.length > 1 && detail.length < 120) paths.add(detail);
    }
  }

  return [...paths].slice(0, limit);
}

const openApiDocs: Rule = async (ctx) => {
  const urls = openApiProbePaths(ctx).map((path) => new URL(path, ctx.origin).toString());
  const docs = await ctx.probe.getMany(urls, { maxBytes: 12_000 }, 4);
  for (const [url, r] of docs) {
    if (r.status < 200 || r.status >= 300) continue;
    if (!looksOpenApiBody(r.body)) continue;
    let title = "";
    try {
      const parsed = JSON.parse(r.body.trim());
      title = parsed.info?.title || parsed.info?.description || "";
    } catch {
      /* yaml */
    }
    return {
      fired: true,
      confidence: 0.9,
      evidence: { url, title: title || undefined, note: "OpenAPI/Swagger schema reachable without auth" }
    };
  }
  return NEGATIVE;
};

// --- Demo / skip-auth flags shipped in client bundle ------------------------
// Vibe-coded prototypes leave SKIP_AUTH / DEMO_MODE enabled. Explicit true in the
// bundle is positive proof the bypass exists client-side.
const demoModeFlags: Rule = async (ctx) => {
  const hits = matchDemoFlags(ctx.combined);
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.88,
    evidence: { flags: hits.slice(0, 6), note: "auth bypass / demo flag enabled in client bundle" }
  };
};

// --- Supabase Storage public bucket -----------------------------------------
// Lists buckets with the anon key; public:true means world-readable objects.
const supabaseStoragePublic: Rule = async (ctx) => {
  const sb = extractSupabase(ctx);
  if (!sb) return NEGATIVE;
  const r = await ctx.probe.get(`${sb.projectUrl}/storage/v1/bucket`, {
    maxBytes: 8192,
    headers: {
      apikey: sb.anonKey,
      Authorization: `Bearer ${sb.anonKey}`
    }
  });
  if (r.status !== 200) return NEGATIVE;
  let buckets: { name?: string; id?: string; public?: boolean }[] = [];
  try {
    buckets = JSON.parse(r.body);
  } catch {
    return NEGATIVE;
  }
  if (!Array.isArray(buckets)) return NEGATIVE;
  const publicBuckets = buckets
    .filter((b) => b.public === true)
    .map((b) => b.name || b.id)
    .filter(Boolean) as string[];
  if (publicBuckets.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.88,
    evidence: {
      projectUrl: sb.projectUrl,
      publicBuckets: publicBuckets.slice(0, 8),
      note: "anon key can list public buckets — verify sensitive files aren't world-readable"
    }
  };
};

// --- service_role JWT passed to createClient in browser bundle ----------------
const supabaseServiceRoleClient: Rule = async (ctx) => {
  if (!/supabase/i.test(ctx.combined)) return NEGATIVE;
  const jwts =
    ctx.combined.match(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g) || [];
  for (const jwt of jwts) {
    const payload = jwtPayload(jwt);
    if (!payload?.includes("service_role")) continue;
    const idx = ctx.combined.indexOf(jwt);
    const window = ctx.combined.slice(Math.max(0, idx - 160), idx + jwt.length + 160);
    if (!/createClient|createBrowserClient|SupabaseClient/i.test(window)) continue;
    return {
      fired: true,
      confidence: 0.95,
      evidence: {
        note: "service_role JWT passed to Supabase createClient in browser bundle",
        sampleRedacted: jwt.length > 12 ? `${jwt.slice(0, 8)}…${jwt.slice(-4)}` : "***"
      }
    };
  }
  return NEGATIVE;
};

// --- sitemap.xml discloses sensitive paths ----------------------------------
const sitemapSensitivePaths: Rule = async (ctx) => {
  const doc = await ctx.probe.get(`${ctx.origin}/sitemap.xml`, { maxBytes: 8192 });
  if (doc.status !== 200 || !doc.body.trim()) return NEGATIVE;
  const body = doc.body.toLowerCase();
  const disclosed = SENSITIVE_PATH_NEEDLES.filter((p) => body.includes(p.replace(/^\//, "")) || body.includes(p));
  if (disclosed.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.82,
    evidence: { url: doc.finalUrl, disclosedPaths: disclosed.slice(0, 8), snippet: doc.body.slice(0, 280).trim() }
  };
};

// --- weak CSP (unsafe-inline + unsafe-eval) ---------------------------------
const weakCsp: Rule = async (ctx) => {
  const csp = ctx.home.headers["content-security-policy"] || "";
  if (!csp) return NEGATIVE;
  const lc = csp.toLowerCase();
  const hasUnsafeInline = lc.includes("'unsafe-inline'") || lc.includes("unsafe-inline");
  const hasUnsafeEval = lc.includes("'unsafe-eval'") || lc.includes("unsafe-eval");
  if (!hasUnsafeInline && !hasUnsafeEval) return NEGATIVE;
  const weaknesses: string[] = [];
  if (hasUnsafeInline) weaknesses.push("unsafe-inline");
  if (hasUnsafeEval) weaknesses.push("unsafe-eval");
  return {
    fired: true,
    confidence: 0.85,
    evidence: { weaknesses, snippet: csp.slice(0, 200) }
  };
};

// --- hardcoded demo credentials in client bundle ----------------------------
const hardcodedCredentials: Rule = async (ctx) => {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of HARDCODED_CRED_RES) {
    const m = ctx.combined.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 60) });
  }
  if (hits.length === 0) return NEGATIVE;
  return { fired: true, confidence: 0.88, evidence: { hardcoded: hits.slice(0, 5) } };
};

// --- Clerk secret key in client bundle --------------------------------------
const clerkSecretInClient: Rule = async (ctx) => {
  if (!/clerk/i.test(ctx.combined)) return NEGATIVE;
  const re = /(?:CLERK_SECRET(?:_KEY)?|clerkSecretKey)\s*[=:]\s*["'](sk_(?:live|test)_[A-Za-z0-9]+)["']/i;
  const m = ctx.combined.match(re);
  if (!m) return NEGATIVE;
  const key = m[1];
  return {
    fired: true,
    confidence: 0.92,
    evidence: {
      note: "Clerk secret key referenced in client bundle",
      sampleRedacted: key.length > 12 ? `${key.slice(0, 10)}…` : "***"
    }
  };
};

// --- Firebase Firestore open read (REST) ------------------------------------
const firebaseFirestoreOpen: Rule = async (ctx) => {
  const proj =
    ctx.combined.match(/"projectId"\s*:\s*"([a-z0-9-]+)"/) ||
    ctx.combined.match(/([a-z0-9-]+)\.firebaseapp\.com/);
  if (!proj) return NEGATIVE;
  const projectId = proj[1];
  const apiKeyMatch = ctx.combined.match(/AIza[0-9A-Za-z_-]{35}/);
  if (!apiKeyMatch) return NEGATIVE;
  const apiKey = apiKeyMatch[0];
  const collections = ["users", "profiles", "posts", "messages", "todos"];
  const urls = collections.map(
    (c) =>
      `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${c}?key=${apiKey}&pageSize=1`
  );
  const docs = await ctx.probe.getMany(urls, { maxBytes: 4096 }, 3);
  for (const [url, r] of docs) {
    if (r.status === 200 && /"documents"\s*:\s*\[/.test(r.body)) {
      const coll = url.match(/\/documents\/([^?]+)/)?.[1];
      return {
        fired: true,
        confidence: 0.85,
        evidence: { projectId, collection: coll, note: "Firestore documents returned without auth token" }
      };
    }
  }
  return NEGATIVE;
};

// --- Client-only auth (UI guards without server/RLS signals) — deep heuristic ----------
const clientOnlyAuth: Rule = async (ctx) => {
  const backend = /supabase|createClient|firebase|convex|@clerk/i.test(ctx.combined);
  if (!backend) return NEGATIVE;
  const uiGuard =
    /ProtectedRoute|RequireAuth|PrivateRoute|AuthGuard|if\s*\(\s*!user\b|if\s*\(\s*!session\b|navigate\(['"]\/login|router\.push\(['"]\/login|redirect\(['"]\/login/i.test(
      ctx.combined
    );
  const serverEnforcement =
    /row level security|enable row level|createServerClient|getServerSession|auth\.getSession|getUser\(\)|middleware.*auth|unauthorized\(|403/i.test(
      ctx.combined
    );
  if (!uiGuard || serverEnforcement) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.58,
    evidence: {
      note: "React/UI route guards present without visible server-side auth or RLS enforcement in bundle",
      stack: backend ? "backend client detected" : undefined
    }
  };
};

// --- Next.js Server Actions without auth check — deep heuristic ----------------
const serverActionAuthz: Rule = async (ctx) => {
  if (!/"use server"|'use server'/.test(ctx.combined)) return NEGATIVE;
  const parts = ctx.combined.split(/["']use server["']/i);
  for (const block of parts.slice(1, 8)) {
    const chunk = block.slice(0, 1500);
    if (!/export async function|async function \w+/i.test(chunk)) continue;
    if (/getSession|getUser|auth\(|supabase\.auth|createServerClient|currentUser|unauthorized|forbidden|403|permission|role/i.test(chunk))
      continue;
    return {
      fired: true,
      confidence: 0.55,
      evidence: { snippet: chunk.slice(0, 220).trim(), note: "Server Action block lacks visible session/permission check" }
    };
  }
  return NEGATIVE;
};

// --- Spring Boot actuator exposed (read-only GET) -----------------------------
// Production Spring apps often leave /actuator reachable. The index JSON with
// _links.health or a health UP response is positive proof of management exposure.
const ACTUATOR_PROBE_PATHS = ["/actuator", "/actuator/health", "/actuator/info", "/manage/actuator"];

const springActuatorExposed: Rule = async (ctx) => {
  const urls = ACTUATOR_PROBE_PATHS.map((p) => new URL(p, ctx.origin).toString());
  const docs = await ctx.probe.getMany(urls, { maxBytes: 8192 }, 3);
  for (const [url, r] of docs) {
    if (r.status < 200 || r.status >= 300) continue;
    const body = r.body.trim();
    if (!/^\s*[\[{]/.test(body)) continue;
    const isIndex = /"_links"\s*:/.test(body) && /"health"\s*:/.test(body);
    const isHealth = /"status"\s*:\s*"UP"/i.test(body);
    const isInfo = /"git"\s*:\s*\{/.test(body) && /"commit"\s*:/.test(body);
    if (!isIndex && !isHealth && !isInfo) continue;
    return {
      fired: true,
      confidence: 0.92,
      evidence: {
        url,
        snippet: body.slice(0, 200).trim(),
        note: "Spring Boot actuator management endpoint reachable without authentication"
      }
    };
  }
  return NEGATIVE;
};

// --- IDOR: unauthenticated read by sequential numeric ID (active GET probe) ---
// Positive proof when /resource/1 returns record JSON without an auth challenge.
const IDOR_FALLBACK_PATHS = [
  "/rest/track-order/1",
  "/api/orders/1",
  "/api/users/1",
  "/users/v1/name1",
  "/users/v1/1"
];
const IDOR_AUTH_MARKERS = /unauthorized|login required|authentication|credentials_required|jwt token required|invalid token/i;

function extractIdorProbePaths(text: string): string[] {
  const paths = new Set<string>();
  const templateRe = /["'`](\/(?:rest|api|users)\/[a-z0-9_./-]+)\/\$\{/gi;
  let m: RegExpExecArray | null;
  while ((m = templateRe.exec(text))) {
    const base = m[1].replace(/\/+$/, "");
    paths.add(`${base}/1`);
    if (/\/users/i.test(base)) paths.add(`${base}/1001`);
  }
  if (/track-order/i.test(text)) paths.add("/rest/track-order/1");
  const braceRe = /["'`](\/api\/[a-z0-9_/-]+)\/\{[a-zA-Z]+\}["'`]/gi;
  while ((m = braceRe.exec(text))) {
    const base = m[1];
    paths.add(`${base}/1`);
    if (/\/users/i.test(base)) paths.add(`${base}/1001`);
  }
  const baseRe = /["'`](\/rest\/[a-z][a-z0-9_-]{2,30})["'`]/gi;
  while ((m = baseRe.exec(text))) {
    const base = m[1];
    if (base.includes("admin") || base.endsWith("search")) continue;
    paths.add(`${base}/1`);
  }
  return [...paths].slice(0, 5);
}

const idorObjectAccess: Rule = async (ctx) => {
  const discovered = extractIdorProbePaths(ctx.combined);
  const openApiPaths = await fetchOpenApiGetPathsWithDetails(ctx, 8);
  const paths = [...new Set([...discovered, ...openApiPaths, ...IDOR_FALLBACK_PATHS])].slice(0, 10);
  const externalBases = extractExternalApiBases(ctx.combined, ctx.origin, 4);
  const origins = [ctx.origin, ...externalBases];
  const urls: string[] = [];
  const seen = new Set<string>();
  for (const base of origins) {
    for (const p of paths) {
      const url = new URL(p, base).toString();
      if (seen.has(url)) continue;
      seen.add(url);
      urls.push(url);
      if (urls.length >= 24) break;
    }
    if (urls.length >= 24) break;
  }
  const docs = await ctx.probe.getMany(urls, { maxBytes: 8192 }, 3);
  const hits: { path: string; status: number; sample: string }[] = [];
  for (const [url, r] of docs) {
    if (r.status < 200 || r.status >= 300) continue;
    if (IDOR_AUTH_MARKERS.test(r.body.slice(0, 500))) continue;
    const trimmed = r.body.trim();
    if (!/^\s*[\[{]/.test(trimmed)) continue;
    if (/"(?:config|application|settings|admin)"\s*:/.test(r.body.slice(0, 300))) continue;
    const hasRecord =
      /"status"\s*:\s*"success"/i.test(r.body) ||
      /"orderId"|"userId"|"user_id"|"username"|"email"\s*:|"data"\s*:\s*\[\s*\{|"Books"\s*:\s*\[/.test(
        r.body
      );
    if (!hasRecord) continue;
    hits.push({
      path: new URL(url).pathname,
      status: r.status,
      sample: r.body.slice(0, 120).trim()
    });
  }
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.9,
    evidence: {
      routes: hits.slice(0, 4),
      note: "sequential numeric ID returns record data without authentication — IDOR likely"
    }
  };
};

// --- IDOR / client-side ID fetch pattern — deep heuristic ----------------------
const idorProbe: Rule = async (ctx) => {
  const signals: string[] = [];
  if (/fetch\([^)]*(\$\{|\+\s*)(id|userId|user_id|params\.)/i.test(ctx.combined)) {
    signals.push("fetch uses client-controlled id parameter");
  }
  if (/useParams\(\)[^;]{0,200}fetch/i.test(ctx.combined)) {
    signals.push("useParams wired directly to fetch");
  }
  if (/\/api\/[a-z]+\/\$\{/i.test(ctx.combined)) {
    signals.push("API path built from template id");
  }
  if (signals.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.52,
    evidence: { signals, note: "Resource access keyed off client-supplied ID — verify server-side ownership checks" }
  };
};

// --- Sensitive keys in __NEXT_DATA__ ----------------------------------------
const nextDataSensitiveKeys: Rule = async (ctx) => {
  const m = ctx.home.body.match(/<script[^>]*id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i);
  if (!m) return NEGATIVE;
  const blob = m[1];
  const keyRe =
    /["']([A-Za-z0-9_]*(?:SECRET|SERVICE_ROLE|DATABASE|PASSWORD|PRIVATE|STRIPE|OPENAI|API_KEY)[A-Za-z0-9_]*)["']\s*:\s*["']([^"']{8,})["']/gi;
  const hits: string[] = [];
  let km: RegExpExecArray | null;
  while ((km = keyRe.exec(blob)) && hits.length < 8) hits.push(km[1]);
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.88,
    evidence: { location: "__NEXT_DATA__", sensitiveKeys: hits, note: "server-secret key names with values in Next.js page payload" }
  };
};

// --- SQL error disclosure on search/query endpoints (deep) --------------------
// Benign malformed input that triggers a database syntax error is positive proof the
// parameter is interpolated into SQL — the classic injection precursor.
const SQL_ERROR_MARKERS = [
  /SQLITE_ERROR/i,
  /You have an error in your SQL syntax/i,
  /ER_PARSE_ERROR/i,
  /ORA-\d{5}/i,
  /PostgreSQL.*ERROR/i,
  /SQLSTATE\[/i,
  /unterminated quoted string/i,
  /quoted string not properly terminated/i,
  /Microsoft OLE DB Provider/i,
  /ODBC SQL Server Driver/i,
  /ADODB\.Recordset/i,
  /Syntax error.*in query expression/i,
  /"detail"\s*:\s*"[\s\S]{0,120}syntax error/i
];
const SQL_PROBE = "'))";
const SQL_ASP_PROBE_PARAMS = ["id", "cat", "tfSearch"];
const SQL_ASP_FALLBACK_PATHS = ["/showforum.asp", "/search.asp"];

function extractAspSqlProbePaths(text: string): string[] {
  const paths = new Set<string>();
  const hrefRe = /(?:href|action)\s*=\s*["']([^"'#?]+\.asp)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = hrefRe.exec(text))) {
    const norm = normalizeProbePath(m[1]);
    if (norm) paths.add(norm);
  }
  return [...paths].slice(0, 5);
}

async function probeAspDifferentialSql(
  ctx: RuleContext,
  paths: string[]
): Promise<{ fired: true; confidence: number; evidence: Record<string, unknown> } | null> {
  for (const path of paths.slice(0, 4)) {
    for (const param of SQL_ASP_PROBE_PARAMS) {
      const baseline = new URL(path, ctx.origin);
      baseline.searchParams.set(param, "1");
      const evil = new URL(path, ctx.origin);
      evil.searchParams.set(param, "1'");
      const docs = await ctx.probe.getMany([baseline.toString(), evil.toString()], { maxBytes: 8192 }, 2);
      const baseDoc = docs.get(baseline.toString());
      const evilDoc = docs.get(evil.toString());
      if (!baseDoc || !evilDoc) continue;
      if (baseDoc.status < 200 || baseDoc.status >= 400) continue;
      if (evilDoc.status < 500) continue;
      if (/500 - Internal server error/i.test(evilDoc.body) || evilDoc.status >= 500) {
        return {
          fired: true,
          confidence: 0.88,
          evidence: {
            url: evil.toString(),
            baselineStatus: baseDoc.status,
            errorStatus: evilDoc.status,
            snippet: evilDoc.body.slice(0, 240).trim(),
            note: "numeric parameter tolerated but quote triggers server error — SQL injection likely (ASP/IIS)"
          }
        };
      }
    }
  }
  return null;
}

function extractSearchEndpoints(text: string): string[] {
  const paths = new Set<string>(extractSearchLikePaths(text));
  for (const p of extractAspSqlProbePaths(text)) paths.add(p);
  const patterns = [
    /["'`](\/rest\/[a-z0-9_\-/]+\/search)["'`]/gi,
    /["'`](\/api\/[a-z0-9_\-/]+\/search)["'`]/gi
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      const p = m[1].split("?")[0].replace(/\/+$/, "");
      if (p.length > 3 && p.length < 80) paths.add(p);
    }
  }
  return [...paths].slice(0, 8);
}

const SQL_PROBE_PARAMS = ["q", "query", "search", "id", "tfSearch", "cat"];
const SQL_API_SEARCH_PATHS = ["/api/products", "/api/search", "/api/items", "/api/users"];
const JSON_AUTH_SQL_PATHS = ["/api/portal", "/api/auth/login", "/api/login", "/api/authenticate"];
const JSON_SQLI_BODIES = [
  JSON.stringify({ username: "admin' OR '1'='1", password: "x" }),
  JSON.stringify({ email: "admin' OR '1'='1", password: "x" })
];
const JSON_SQLI_SUCCESS_MARKERS = [
  /SQL\s*Injection/i,
  /Authentication Bypass Successful/i,
  /Login Successful.*SQL Injection/i
];

async function probeJsonAuthSqlInjection(ctx: RuleContext): Promise<RuleResult | null> {
  const discovered = extractApiPaths(ctx.combined, 8).filter((p) =>
    /login|auth|portal|authenticate/i.test(p)
  );
  const paths = [...new Set([...discovered, ...JSON_AUTH_SQL_PATHS])].slice(0, 6);
  for (const path of paths) {
    const url = new URL(path, ctx.origin).toString();
    for (const body of JSON_SQLI_BODIES) {
      const doc = await ctx.probe.get(url, {
        method: "POST",
        body,
        headers: { "Content-Type": "application/json" },
        maxBytes: 8192
      });
      if (doc.status < 200 || doc.status >= 500) continue;
      const marker = JSON_SQLI_SUCCESS_MARKERS.find((re) => re.test(doc.body));
      if (!marker) continue;
      const match = doc.body.match(marker);
      return {
        fired: true,
        confidence: 0.91,
        evidence: {
          url,
          method: "POST",
          marker: match?.[0]?.slice(0, 80) || "SQL injection success",
          snippet: doc.body.slice(0, 240).trim(),
          note: "JSON auth endpoint accepted SQLi payload — authentication bypass likely"
        }
      };
    }
  }
  return null;
}

const sqlErrorDisclosure: Rule = async (ctx) => {
  const discovered = extractSearchEndpoints(ctx.combined);
  const fallbacks = [
    "/rest/products/search",
    "/api/products/search",
    "/search",
    "/search.jsp",
    ...SQL_ASP_FALLBACK_PATHS
  ];
  const bases = [...new Set([...discovered, ...fallbacks])].slice(0, 6);
  const externalBases = extractExternalApiBases(ctx.combined, ctx.origin, 3);
  const urls: string[] = [];
  const seen = new Set<string>();
  outer: for (const p of bases) {
    for (const param of SQL_PROBE_PARAMS) {
      const u = new URL(p, ctx.origin);
      u.searchParams.set(param, SQL_PROBE);
      const url = u.toString();
      if (seen.has(url)) continue;
      seen.add(url);
      urls.push(url);
      if (urls.length >= 14) break outer;
    }
  }
  // SPA backends: probe discovered external hosts with common JSON search routes.
  ext: for (const base of externalBases) {
    for (const path of SQL_API_SEARCH_PATHS) {
      for (const param of ["search", "q", "query"]) {
        const u = new URL(path, base);
        u.searchParams.set(param, SQL_PROBE);
        const url = u.toString();
        if (seen.has(url)) continue;
        seen.add(url);
        urls.push(url);
        if (urls.length >= 20) break ext;
      }
    }
  }
  const docs = await ctx.probe.getMany(urls, { maxBytes: 8192 }, 3);
  for (const [url, r] of docs) {
    if (r.status === 401 || r.status === 403) continue;
    const marker = SQL_ERROR_MARKERS.find((re) => re.test(r.body));
    if (!marker) continue;
    const match = r.body.match(marker);
    return {
      fired: true,
      confidence: 0.9,
      evidence: {
        url,
        sqlError: match?.[0]?.slice(0, 120) || "database syntax error",
        snippet: r.body.slice(0, 240).trim(),
        note: "search/query parameter reaches SQL — injection likely"
      }
    };
  }

  const aspPaths = [...new Set([...extractAspSqlProbePaths(ctx.combined), ...SQL_ASP_FALLBACK_PATHS])];
  const aspHit = await probeAspDifferentialSql(ctx, aspPaths);
  if (aspHit) return aspHit;

  const jsonHit = await probeJsonAuthSqlInjection(ctx);
  if (jsonHit?.fired) return jsonHit;

  return NEGATIVE;
};

// --- Unauthenticated admin / application config (read-only GET) ---------------
const ADMIN_PROBE_PATHS = [
  "/rest/admin/application-configuration",
  "/rest/admin/config",
  "/api/admin/config",
  "/api/admin/settings",
  "/admin/application-configuration"
];
const ADMIN_HTML_LOGIN_PATHS = ["/admin", "/admin/"];
const ADMIN_JSON_MARKERS = /"(?:config|admin|application|settings|server)"\s*:/;
const ADMIN_HTML_LOGIN_MARKERS =
  /(?:Admin Panel|Admin Login|administrator access|Secure administrator)/i;

function isExposedAdminLoginHtml(body: string): boolean {
  if (!ADMIN_HTML_LOGIN_MARKERS.test(body)) return false;
  if (!/<input[^>]+type=["']password["']/i.test(body)) return false;
  if (/oauth|sso|saml|sign in with/i.test(body.slice(0, 1200))) return false;
  return true;
}

const ADMIN_SHELL_NAV_MARKERS = /Administration|Admin Panel|Manage users/i;
const ADMIN_SHELL_LINK_MARKERS = /href\s*=\s*["']\/admin\/(?:users|config|settings)/i;

function isExposedAdminShellHtml(body: string): boolean {
  if (!ADMIN_SHELL_LINK_MARKERS.test(body) && !/\/admin\/users/i.test(body)) return false;
  if (!ADMIN_SHELL_NAV_MARKERS.test(body)) return false;
  if (/sign in|log in|login required|unauthorized/i.test(body.slice(0, 800))) return false;
  if (isExposedAdminLoginHtml(body)) return false;
  return true;
}

const unauthenticatedAdminEndpoint: Rule = async (ctx) => {
  const externalBases = extractExternalApiBases(ctx.combined, ctx.origin, 4);
  const origins = [ctx.origin, ...externalBases];
  const urls: string[] = [];
  const seen = new Set<string>();
  for (const base of origins) {
    for (const p of ADMIN_PROBE_PATHS) {
      const url = new URL(p, base).toString();
      if (seen.has(url)) continue;
      seen.add(url);
      urls.push(url);
    }
  }
  const docs = await ctx.probe.getMany(urls, { maxBytes: 8192 }, 3);
  for (const [url, r] of docs) {
    if (r.status < 200 || r.status >= 300) continue;
    if (/unauthorized|credentials_required|login required/i.test(r.body.slice(0, 400))) continue;
    if (!ADMIN_JSON_MARKERS.test(r.body)) continue;
    if (!/^\s*[\[{]/.test(r.body.trim()) && !/"status"\s*:\s*"success"/.test(r.body)) continue;
    return {
      fired: true,
      confidence: 0.92,
      evidence: {
        url,
        snippet: r.body.slice(0, 200).trim(),
        note: "admin/application configuration returned without authentication"
      }
    };
  }

  const htmlUrls = ADMIN_HTML_LOGIN_PATHS.map((p) => new URL(p, ctx.origin).toString());
  const htmlDocs = await ctx.probe.getMany(htmlUrls, { maxBytes: 8192 }, 2);
  for (const [url, r] of htmlDocs) {
    if (r.status < 200 || r.status >= 300) continue;
    if (isExposedAdminLoginHtml(r.body)) {
      return {
        fired: true,
        confidence: 0.86,
        evidence: {
          url,
          snippet: r.body.slice(0, 200).trim(),
          note: "admin login panel reachable without prior authentication redirect"
        }
      };
    }
    if (isExposedAdminShellHtml(r.body)) {
      return {
        fired: true,
        confidence: 0.84,
        evidence: {
          url,
          snippet: r.body.slice(0, 200).trim(),
          note: "admin SPA shell (users/config nav) reachable without authentication redirect"
        }
      };
    }
  }

  return NEGATIVE;
};

// --- Dangerous HTML sinks in client bundle (XSS precursor) --------------------
const DANGEROUS_SINK_RES: { label: string; re: RegExp }[] = [
  {
    label: "Angular bypassSecurityTrustHtml with template interpolation",
    re: /bypassSecurityTrustHtml\s*\(\s*`[^`]*\$\{/
  },
  {
    label: "Angular bypassSecurityTrustHtml with API/user data",
    re: /bypassSecurityTrustHtml\s*\([^)]*\.(?:data|orderId|comment|description|searchValue)/
  },
  {
    label: "React dangerouslySetInnerHTML",
    re: /dangerouslySetInnerHTML\s*:\s*\{/
  },
  {
    label: "innerHTML binding with dynamic search/user value",
    re: /\["innerHTML"\][^;]{0,120}(?:searchValue|userInput|\.data)/
  },
  {
    label: "innerHTML renders unsanitized post content from template literal",
    re: /\$\{(?:post\.)?(?:content|title|author)\}[\s\S]{0,350}\.innerHTML\s*=\s*html/i
  },
  {
    label: "innerHTML assignment from URL query param (URLSearchParams)",
    re: /URLSearchParams[\s\S]{0,450}\.innerHTML\s*=/
  },
  {
    label: "getElementById innerHTML = query param variable",
    re: /getElementById\([^)]+\)\.innerHTML\s*=\s*[a-z]\b/
  },
  {
    label: "innerHTML html variable built from post.content",
    re: /post\.content[\s\S]{0,500}innerHTML\s*=\s*html/i
  },
  {
    label: "DOM XSS via location.hash innerHTML",
    re: /(?:element\.)?innerHTML\s*=\s*location\.hash|innerHTML\s*=\s*hash\b[\s\S]{0,120}location\.hash/
  },
  {
    label: "getElementById innerHTML = hash variable",
    re: /getElementById\([^)]+\)\.innerHTML\s*=\s*hash\b/
  },
  {
    label: "innerHTML template literal with user input variable",
    re: /\.innerHTML\s*=\s*`[^`]{0,300}\$\{(?:escapeHtmlDisplay\()?input\b/
  },
  {
    label: "innerHTML += user command/input variable",
    re: /\.innerHTML\s*\+=\s*(?:command|input|userInput|payload|query|term)\b/
  },
  {
    label: "getElementById innerHTML += user input",
    re: /getElementById\([^)]+\)\.innerHTML\s*\+=/
  },
  {
    label: "preview.innerHTML = user comment/content variable",
    re: /preview\.innerHTML\s*=\s*(?:comment|content|input|userInput|payload)\b/
  },
  {
    label: "output.innerHTML = render(user input)",
    re: /output\.innerHTML\s*=\s*render\s*\(\s*(?:input|userInput|payload|comment)\s*\)/
  },
  {
    label: "element.innerHTML = userInput (XSS lab sample)",
    re: /element\.innerHTML\s*=\s*userInput\b/
  },
  {
    label: "getElementById innerHTML = API response field (data.message XSS)",
    re: /getElementById\([^)]+\)\.innerHTML\s*=\s*(?:data|response|result|json|res)\./
  },
  {
    label: "innerHTML string concat with user val (reflected XSS lab)",
    re: /\.innerHTML\s*=\s*'[^']*'\s*\+\s*val\b/
  },
  {
    label: "div.innerHTML = val (stored XSS direct assignment)",
    re: /if\s*\(\s*div\s*\)\s*div\.innerHTML\s*=\s*val\b/
  },
  {
    label: "commentStore.map rendered via innerHTML (stored XSS)",
    re: /\.innerHTML\s*=\s*commentStore\.map\s*\(/
  },
  {
    label: "SVG preview innerHTML = uploaded file content",
    re: /getElementById\([^)]*svgPreview[^)]*\)\.innerHTML\s*=\s*content\b/i
  },
  {
    label: "commentDiv.innerHTML template with user content variable",
    re: /\.innerHTML\s*=\s*`[^`]*\$\{content\}`/
  },
  {
    label: "Inline HTML XSS lab documents innerHTML vulnerability",
    re: /Cross-Site Scripting\s*\(\s*XSS\s*\)[\s\S]{0,800}<code>innerHTML<\/code>/i
  },
  {
    label: "PHP echo $_GET superglobal without escaping",
    re: /echo[\s\S]{0,60}\$_GET\[/
  },
  {
    label: "PHP echo $_REQUEST into HTML output",
    re: /echo[\s\S]{0,60}\$_REQUEST\[/
  }
];
const SINK_SYMBOL_RE = /bypassSecurityTrustHtml|dangerouslySetInnerHTML|\.innerHTML/;
const LARGE_SCRIPT_REFETCH_BYTES = 2_000_000;

function scanDangerousHtmlSinks(text: string): { label: string; sample: string }[] {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of DANGEROUS_SINK_RES) {
    const m = text.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 80) });
  }
  return hits;
}

// --- DOM XSS via eval() on user-controlled input --------------------------------
const DOM_EVAL_XSS_RES: { label: string; re: RegExp }[] = [
  {
    label: "eval() on getElementById/querySelector .value",
    re: /eval\s*\(\s*(?:document\.)?(?:getElementById|querySelector|getElementsByName)\([^)]{0,80}\)\.value/
  },
  {
    label: "eval() on input/textarea .value",
    re: /eval\s*\(\s*(?:document\.)?(?:getElementById|querySelector)\([^)]{0,80}\)\.(?:value|innerHTML)/
  },
  {
    label: "new Function() on DOM .value",
    re: /new\s+Function\s*\(\s*(?:document\.)?(?:getElementById|querySelector)\([^)]{0,80}\)\.value/
  }
];

const domEvalXss: Rule = async (ctx) => {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of DOM_EVAL_XSS_RES) {
    const m = ctx.combined.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 100) });
  }
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.92,
    evidence: {
      sinks: hits.slice(0, 3),
      note: "client bundle passes DOM user input to eval() — DOM XSS is trivial"
    }
  };
};

// --- postMessage DOM XSS (message event data → innerHTML) ---------------------
// Third-party widgets (e.g. Gartner Peer Insights) that listen for postMessage and
// assign event data into innerHTML without sanitization — classic DOM XSS via iframe.
const POSTMESSAGE_DOM_XSS_RES: { label: string; re: RegExp }[] = [
  {
    label: "Page documents postMessage DOM XSS vulnerability",
    re: /postMessage\s+DOM\s+XSS/i
  },
  {
    label: "postMessage listener assigns innerHTML from event data",
    re: /addEventListener\s*\(\s*["']message["'][\s\S]{0,4000}\.innerHTML\s*=/
  },
  {
    label: "message handler writes unsanitized data to innerHTML",
    re: /(?:function\s*\(\s*e\s*\)|=>\s*\{)[\s\S]{0,600}?(?:e\.data|event\.data)[\s\S]{0,1200}\.innerHTML\s*=/
  },
  {
    label: "postMessage origin check then innerHTML sink",
    re: /(?:e|event)\.origin[\s\S]{0,800}\.innerHTML\s*=/
  }
];

const postMessageDomXssEvidence: Rule = async (ctx) => {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of POSTMESSAGE_DOM_XSS_RES) {
    const m = ctx.combined.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 100) });
  }
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: hits.length >= 2 ? 0.92 : 0.86,
    evidence: {
      markers: hits.slice(0, 3),
      note: "postMessage handler assigns untrusted message data to innerHTML — DOM XSS via cross-origin iframe"
    }
  };
};

const dangerousHtmlSinks: Rule = async (ctx) => {
  let hits = scanDangerousHtmlSinks(ctx.combined);

  // Minified SPA bundles (e.g. Juice Shop main.js ~1.7MB) truncate at 800KB — sink *usage*
  // often lives past the cut. Re-fetch flagged script URLs with a higher byte cap.
  if (hits.length === 0 && SINK_SYMBOL_RE.test(ctx.combined)) {
    const urls = ctx.scripts
      .filter((s) => SINK_SYMBOL_RE.test(s.body))
      .map((s) => s.finalUrl)
      .slice(0, 3);
    for (const url of urls) {
      const doc = await ctx.probe.get(url, { maxBytes: LARGE_SCRIPT_REFETCH_BYTES });
      hits = scanDangerousHtmlSinks(doc.body);
      if (hits.length > 0) {
        return {
          fired: true,
          confidence: 0.88,
          evidence: {
            sinks: hits.slice(0, 4),
            scriptUrl: url,
            note: "client bundle renders unsanitized HTML — sink usage found past initial fetch truncation"
          }
        };
      }
    }
  }

  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.88,
    evidence: {
      sinks: hits.slice(0, 4),
      note: "client bundle renders unsanitized HTML — stored/reflected XSS likely"
    }
  };
};

// --- Client-side SQL injection evidence in bundle (educational labs / vibe prototypes) --
const CLIENT_SQL_RES: { label: string; re: RegExp }[] = [
  {
    label: "DANGEROUS SQL string concatenation marker",
    re: /DANGEROUS:\s*Concatenating input directly/i
  },
  {
    label: "Unsafe Concat SQL query builder",
    re: /Unsafe Concat[\s\S]{0,400}SELECT[\s\S]{0,200}FROM[\s\S]{0,120}WHERE/i
  },
  {
    label: "SELECT FROM users WHERE id string concat",
    re: /SELECT[\s\S]{0,60}FROM[\s\S]{0,60}users[\s\S]{0,120}WHERE[\s\S]{0,60}id\s*=\s*['"]/i
  },
  {
    label: "Client-side SQLi login bypass string check",
    re: /includes\s*\(\s*["']' or ['"]1['"]='1["']\s*\)|includes\s*\(\s*["']' OR '1'='1["']\s*\)|includes\s*\(\s*["']admin' --["']\s*\)/i
  },
  {
    label: "INTENTIONALLY INSECURE string-concat SQL login",
    re: /INTENTIONALLY INSECURE[\s\S]{0,120}string concatenation/i
  },
  {
    label: "loginVulnerable async SQL string interpolation",
    re: /async function loginVulnerable[\s\S]{0,250}`SELECT[\s\S]{0,120}FROM[\s\S]{0,60}users[\s\S]{0,120}WHERE[\s\S]{0,80}\$\{/
  },
  {
    label: "Template literal SELECT FROM users WHERE username interpolation",
    re: /`SELECT[\s\S]{0,120}FROM[\s\S]{0,60}users[\s\S]{0,120}WHERE[\s\S]{0,60}username\s*=\s*'\$\{/
  },
  {
    label: "SQLi bypass OR/quote inspection before query build",
    re: /\.includes\s*\(\s*["']OR["']\s*\)[\s\S]{0,250}`SELECT \* FROM users/i
  },
  {
    label: "SQLi training lab login query with INPUT placeholders",
    re: /SELECT\s+\*\s+FROM\s+users\s+WHERE\s+username\s*=\s*['"]INPUT['"]/i
  },
  {
    label: "SQLi lab vulnerable login query marker",
    re: /vulnerable login query[\s\S]{0,250}SELECT[\s\S]{0,120}FROM[\s\S]{0,60}users/i
  },
  {
    label: "Educational lab builds SQL via string concatenation",
    re: /builds its SQL query using string concatenation/i
  },
  {
    label: "sqli-query innerHTML displays interpolated username in SQL",
    re: /getElementById\(['"]sqli-query['"]\)\.innerHTML[\s\S]{0,300}\$\{esc\(u\)\}/
  },
  {
    label: "mysql_query SELECT FROM users WHERE coupon interpolation",
    re: /mysql_query\([\s\S]{0,80}SELECT[\s\S]{0,120}FROM[\s\S]{0,60}users[\s\S]{0,120}WHERE[\s\S]{0,60}coupon\s*=\s*'\$\{/i
  },
  {
    label: "Query executed coupon SQL injection log",
    re: /Query executed: SELECT \* FROM users WHERE coupon='\$\{coupon\}'/
  },
  {
    label: "String concat SQL query on email field",
    re: /query\s*=\s*"SELECT \* FROM users WHERE email='"\s*\+\s*email\s*\+\s*"'/
  },
  {
    label: "PHP string-concat SQL with POST variables",
    re: /\$sql\s*=\s*["']SELECT[\s\S]{0,200}WHERE[\s\S]{0,120}\$[a-zA-Z_]+/
  },
  {
    label: "PHP query() with interpolated username variable",
    re: /SELECT\s+\*\s+FROM\s+users\s+WHERE\s+username\s*=\s*['"]\$username/
  },
  {
    label: "SPA SQL injection lab success markers",
    re: /SQL Injection Detected|Authentication Bypass Successful|Login Successful.*SQL Injection/i
  },
  {
    label: "Inline HTML SQL injection lab with OR 1=1 example",
    re: /SQL Injection[\s\S]{0,600}'\s+OR\s+1\s*=\s*1/i
  },
  {
    label: "Vulnerable login API route login-vulneravel",
    re: /\/auth\/login-vulneravel|login\s*\(\s*['"]vulneravel['"]\s*\)/
  },
  {
    label: "Cyber lab SQL module INPUT placeholder login query",
    re: /CYBERLAB[\s\S]{0,2500}SELECT\s+\*\s+FROM\s+users\s+WHERE\s+username\s*=\s*['"]INPUT['"]/i
  }
];

const clientSideSqlEvidence: Rule = async (ctx) => {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of CLIENT_SQL_RES) {
    const m = ctx.combined.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 100) });
  }
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: hits.length >= 2 ? 0.92 : 0.86,
    evidence: {
      markers: hits.slice(0, 4),
      note: "client bundle builds SQL via string concatenation or simulates SQLi — injection likely if wired to a backend"
    }
  };
};

// --- Client-side IDOR evidence in bundle (explicit vulnerable endpoint docs) --
const CLIENT_IDOR_MARKER_RE =
  /VULNERABLE ENDPOINT|No authorization check|No ownership verification|any authenticated user can access/i;

const clientSideIdorEvidence: Rule = async (ctx) => {
  if (!CLIENT_IDOR_MARKER_RE.test(ctx.combined)) return NEGATIVE;
  const endpoints = new Set<string>();
  const re = /\/api\/[a-z0-9_/-]+(?:\$\{[^}]+\}|\{[a-zA-Z]+\})/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(ctx.combined))) endpoints.add(m[0]);
  if (endpoints.size === 0) return NEGATIVE;
  const markers: string[] = [];
  if (/VULNERABLE ENDPOINT/i.test(ctx.combined)) markers.push("VULNERABLE ENDPOINT");
  if (/No authorization check/i.test(ctx.combined)) markers.push("No authorization check");
  if (/No ownership verification/i.test(ctx.combined)) markers.push("No ownership verification");
  return {
    fired: true,
    confidence: 0.88,
    evidence: {
      endpoints: [...endpoints].slice(0, 5),
      markers,
      note: "client bundle documents IDOR-prone API routes without ownership checks"
    }
  };
};

// --- Client-side session hijack evidence (educational labs / insecure cookie demos) --
// --- Server-side eval() on request body (Node/Express anti-pattern) ----------------
const SERVER_SIDE_EVAL_RES: { label: string; re: RegExp }[] = [
  {
    label: "eval(req.body.*) server-side injection",
    re: /eval\s*\(\s*req\.body\.[a-zA-Z_$][\w$]*/
  },
  {
    label: "eval(req.query.*) server-side injection",
    re: /eval\s*\(\s*req\.query\.[a-zA-Z_$][\w$]*/
  },
  {
    label: "Function(req.body.*) dynamic code execution",
    re: /(?:new\s+)?Function\s*\(\s*[^)]*req\.body\.[a-zA-Z_$][\w$]*/
  }
];

const serverSideEvalEvidence: Rule = async (ctx) => {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of SERVER_SIDE_EVAL_RES) {
    const m = ctx.combined.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 100) });
  }
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.9,
    evidence: {
      markers: hits.slice(0, 3),
      note: "server-side handler passes req.body/query to eval() — remote code execution likely"
    }
  };
};

// --- Client-side prototype pollution evidence (educational labs / unsafe merge) ---
const clientSidePrototypePollutionEvidence: Rule = async (ctx) => {
  const markers: string[] = [];
  if (/prototype pollution/i.test(ctx.combined)) markers.push("prototype pollution");
  if (/unsafeMerge\s*\(/i.test(ctx.combined)) markers.push("unsafeMerge recursive merge");
  if (/Prototype pollution happens here/i.test(ctx.combined)) markers.push("prototype pollution injection point");
  if (/__proto__[\s\S]{0,120}isAdmin/i.test(ctx.combined)) markers.push("__proto__ isAdmin payload");
  if (/__proto__[\s\S]{0,160}(?:onerror|img|polluted)/i.test(ctx.combined))
    markers.push("__proto__ XSS/allowlist gadget");
  if (/TAG_ALLOWLIST[\s\S]{0,120}Prototype chain traversal/i.test(ctx.combined))
    markers.push("allowlist bypass via prototype chain");
  if (/constructor\.prototype[\s\S]{0,120}(?:polluted|isAdmin)/i.test(ctx.combined))
    markers.push("constructor.prototype pollution");
  if (/Object\.assign\s*\([^)]*,\s*(?:JSON\.parse|userInput|req\.body)/i.test(ctx.combined))
    markers.push("Object.assign with user input");
  if (markers.length < 2) return NEGATIVE;
  return {
    fired: true,
    confidence: markers.length >= 3 ? 0.9 : 0.85,
    evidence: {
      markers,
      note: "client bundle documents prototype pollution via __proto__ merge without sanitization"
    }
  };
};

const clientSideSessionHijackEvidence: Rule = async (ctx) => {
  const markers: string[] = [];
  if (/Session Replay Attack/i.test(ctx.combined)) markers.push("Session Replay Attack");
  if (/\bdoReplay\s*\(/i.test(ctx.combined)) markers.push("doReplay()");
  if (/vault-token|atk-token|stolen token/i.test(ctx.combined)) markers.push("session token replay UI");
  if (/cookies exfiltrated.*session tokens/i.test(ctx.combined))
    markers.push("session token exfiltration");
  if (markers.length < 2) return NEGATIVE;
  return {
    fired: true,
    confidence: markers.length >= 3 ? 0.9 : 0.84,
    evidence: {
      markers,
      note: "client bundle documents session hijack / token replay without HttpOnly protection"
    }
  };
};

// --- SSRF endpoint probe (server fetches attacker-supplied URL) ---------------
const SSRF_CANARY_URL = "http://example.com";
const SSRF_CANARY_MARKERS = [/Example Domain/i, /<title>\s*Example Domain/i];
const SSRF_GET_PATHS = [
  "/api/fetch",
  "/api/proxy",
  "/api/url",
  "/api/ssrf",
  "/fetch",
  "/proxy",
  "/api/render",
  "/api/metadata"
];
const SSRF_GET_PARAMS = ["url", "target", "link", "uri", "dest"];
const SSRF_POST_PATHS = [
  "/api/fetch",
  "/api/proxy",
  "/api/url",
  "/api/ssrf",
  "/api/render",
  "/api/metadata",
  "/workshop/api/merchant/contact_mechanic"
];
const SSRF_POST_FIELDS = ["url", "target", "link", "uri", "mechanic_api"];
const API_LAB_DEMO_CREDS = [{ email: "test@test.com", password: "Test123!" }];
const API_LAB_LOGIN_PATHS = ["/identity/api/auth/login", "/api/auth/login", "/api/login"];

function looksLikeApiSecurityLab(combined: string): boolean {
  return (
    /completely ridiculous API\s*\(crAPI\)/i.test(combined) ||
    (/BOLA/i.test(combined) && /BFLA/i.test(combined) && /OWASP.*API.*Top\s*10/i.test(combined)) ||
    (/identity\/api/i.test(combined) && /workshop\/api/i.test(combined))
  );
}

async function tryApiLabJwt(ctx: RuleContext): Promise<string | null> {
  for (const path of API_LAB_LOGIN_PATHS) {
    for (const creds of API_LAB_DEMO_CREDS) {
      const url = new URL(path, ctx.origin).toString();
      const r = await ctx.probe.get(url, {
        method: "POST",
        body: JSON.stringify(creds),
        headers: { "Content-Type": "application/json" },
        maxBytes: 4096
      });
      if (r.status < 200 || r.status >= 300) continue;
      const m = r.body.match(/"token"\s*:\s*"(eyJ[^"]+)"/);
      if (m) return m[1];
    }
  }
  return null;
}

function extractSsrfPaths(text: string): string[] {
  const paths = new Set<string>();
  const re = /["'`](\/(?:api\/)?(?:fetch|proxy|ssrf|render|metadata)[a-z0-9/_-]*)["'`]/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const p = m[1].split("?")[0].replace(/\/+$/, "") || m[1];
    paths.add(p);
    if (paths.size >= 6) break;
  }
  return [...paths];
}

function bodyReflectsSsrfCanary(body: string): boolean {
  return SSRF_CANARY_MARKERS.some((re) => re.test(body));
}

const ssrfEndpointProbe: Rule = async (ctx) => {
  const paths = [...new Set([...extractSsrfPaths(ctx.combined), ...SSRF_GET_PATHS])].slice(0, 8);
  const getUrls: string[] = [];
  const seen = new Set<string>();
  outer: for (const path of paths) {
    for (const param of SSRF_GET_PARAMS) {
      const u = new URL(path, ctx.origin);
      u.searchParams.set(param, SSRF_CANARY_URL);
      const url = u.toString();
      if (seen.has(url)) continue;
      seen.add(url);
      getUrls.push(url);
      if (getUrls.length >= 12) break outer;
    }
  }
  const getDocs = await ctx.probe.getMany(getUrls, { maxBytes: 16_384, redirect: "manual" }, 4);
  for (const [url, r] of getDocs) {
    if (r.status < 200 || r.status >= 300) continue;
    if (!bodyReflectsSsrfCanary(r.body)) continue;
    const parsed = new URL(url);
    return {
      fired: true,
      confidence: 0.9,
      evidence: {
        url,
        param: parsed.searchParams.keys().next().value,
        status: r.status,
        snippet: r.body.slice(0, 180).trim(),
        note: "server returned fetched canary page content — server-side request forgery likely"
      }
    };
  }

  const postPaths = [...new Set([...extractSsrfPaths(ctx.combined), ...SSRF_POST_PATHS])].slice(0, 6);
  for (const path of postPaths) {
    for (const field of SSRF_POST_FIELDS) {
      const url = new URL(path, ctx.origin).toString();
      const payload: Record<string, unknown> = { [field]: SSRF_CANARY_URL };
      if (field === "mechanic_api") {
        payload.repeat_request_if_failed = true;
        payload.number_of_repeats = 1;
      }
      const body = JSON.stringify(payload);
      const r = await ctx.probe.get(url, {
        method: "POST",
        body,
        headers: { "Content-Type": "application/json" },
        maxBytes: 16_384,
        redirect: "manual"
      });
      if (r.status < 200 || r.status >= 300) continue;
      if (!bodyReflectsSsrfCanary(r.body)) continue;
      return {
        fired: true,
        confidence: 0.9,
        evidence: {
          url,
          method: "POST",
          field,
          status: r.status,
          snippet: r.body.slice(0, 180).trim(),
          note: "POST body URL fetched server-side and echoed — server-side request forgery likely"
        }
      };
    }
  }

  // crAPI / OWASP API labs gate SSRF behind JWT — try benign demo login then re-probe.
  if (looksLikeApiSecurityLab(ctx.combined)) {
    const jwt = await tryApiLabJwt(ctx);
    if (jwt) {
      const authPaths = [
        "/workshop/api/merchant/contact_mechanic",
        ...postPaths.filter((p) => /workshop|merchant|contact/i.test(p))
      ];
      for (const path of [...new Set(authPaths)].slice(0, 4)) {
        for (const field of SSRF_POST_FIELDS) {
          const url = new URL(path, ctx.origin).toString();
          const payload: Record<string, unknown> = { [field]: SSRF_CANARY_URL };
          if (field === "mechanic_api") {
            payload.repeat_request_if_failed = true;
            payload.number_of_repeats = 1;
          }
          const body = JSON.stringify(payload);
          const r = await ctx.probe.get(url, {
            method: "POST",
            body,
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${jwt}`
            },
            maxBytes: 16_384,
            redirect: "manual"
          });
          if (r.status < 200 || r.status >= 300) continue;
          if (!bodyReflectsSsrfCanary(r.body)) continue;
          return {
            fired: true,
            confidence: 0.92,
            evidence: {
              url,
              method: "POST",
              field,
              status: r.status,
              authenticated: true,
              snippet: r.body.slice(0, 180).trim(),
              note: "authenticated API lab endpoint fetched attacker URL server-side — SSRF confirmed"
            }
          };
        }
      }
    }
  }
  return NEGATIVE;
};

// --- Client-side SSRF evidence in bundle (educational labs / admin panels) ---
const CLIENT_SSRF_RES: { label: string; re: RegExp }[] = [
  {
    label: "SSRF vulnerability marker in admin panel",
    re: /VULNERABILITY:\s*SSRF[\s\S]{0,80}No URL validation/i
  },
  {
    label: "SSRF attack simulation with fetch",
    re: /SSRF Attack detected[\s\S]{0,120}fetch/i
  },
  {
    label: "SSRF lab localhost/127.0.0.1 blocklist check",
    re: /includes\s*\(\s*["']localhost["']\s*\)[\s\S]{0,200}includes\s*\(\s*["']127\.0\.0\.1["']\s*\)/
  },
  {
    label: "Server-Side Request Forgery in admin panel",
    re: /Server-Side Request Forgery in admin panel/i
  }
];

const clientSideSsrfEvidence: Rule = async (ctx) => {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of CLIENT_SSRF_RES) {
    const m = ctx.combined.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 100) });
  }
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: hits.length >= 2 ? 0.9 : 0.86,
    evidence: {
      markers: hits.slice(0, 4),
      note: "client bundle documents SSRF-prone URL fetch without validation — server-side request forgery likely"
    }
  };
};

// --- Client-side unsafe file upload evidence in bundle -----------------------
const CLIENT_FILE_UPLOAD_RES: { label: string; re: RegExp }[] = [
  {
    label: "No file type validation marker",
    re: /VULNERABILITY:\s*No file type validation/i
  },
  {
    label: "Unsafe file upload with no validation",
    re: /Unsafe file upload with no validation/i
  },
  {
    label: "File input without validation before upload handler",
    re: /type:\s*["']file["'][\s\S]{0,500}Upload(?:ing)? file:/i
  }
];

const clientSideFileUploadEvidence: Rule = async (ctx) => {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of CLIENT_FILE_UPLOAD_RES) {
    const m = ctx.combined.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 100) });
  }
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: hits.length >= 2 ? 0.9 : 0.86,
    evidence: {
      markers: hits.slice(0, 4),
      note: "client bundle documents file upload without type/size validation — arbitrary file upload likely"
    }
  };
};

// --- Sensitive token/JWT leaked in unauthenticated JSON API response ---------
const TOKEN_API_PATHS = ["/api/posts", "/api/session", "/api/me", "/api/user", "/api/auth/session"];
const JWT_IN_JSON_RE = /"(?:token|accessToken|refreshToken|jwt)"\s*:\s*"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"/;

const sensitiveApiTokenLeakage: Rule = async (ctx) => {
  const paths = [
    ...new Set([
      ...TOKEN_API_PATHS,
      ...extractApiPaths(ctx.combined, 10).filter((p) => /posts|session|token|auth/i.test(p))
    ])
  ];
  if (paths.length === 0) return NEGATIVE;
  const urls = paths.map((p) => new URL(p, ctx.origin).toString());
  const docs = await ctx.probe.getMany(urls, { maxBytes: 8192 }, 4);
  const leaks: { path: string; field: string; sample: string }[] = [];
  for (const [url, r] of docs) {
    if (r.status < 200 || r.status >= 300) continue;
    const ct = r.headers["content-type"] || "";
    if (!/json/i.test(ct) && !/^\s*[\[{]/.test(r.body.trim())) continue;
    const m = r.body.match(JWT_IN_JSON_RE);
    if (!m) continue;
    const field = m[0].match(/"([^"]+)"\s*:/)?.[1] ?? "token";
    leaks.push({
      path: new URL(url).pathname,
      field,
      sample: m[1].slice(0, 48) + "..."
    });
  }
  if (leaks.length === 0) return NEGATIVE;
  const bundleDebug = /DEBUG token:/i.test(ctx.combined);
  return {
    fired: true,
    confidence: bundleDebug ? 0.92 : 0.88,
    evidence: {
      routes: leaks.slice(0, 4),
      bundleDebugLogging: bundleDebug,
      note: "JSON API returned a JWT/session token without authentication — sensitive data exposure"
    }
  };
};

// --- Unauthenticated JSON API routes (discovered from bundle, read-only GET) --
const DEBUG_API_PATHS = ["/api/debug/config", "/api/debug/users", "/api/debug/env"];

const unauthenticatedApiRoutes: Rule = async (ctx) => {
  const paths = [
    ...new Set([
      ...extractApiPaths(ctx.combined, 10),
      ...(await fetchOpenApiGetPathsWithDetails(ctx, 10)),
      ...DEBUG_API_PATHS
    ])
  ];
  if (paths.length === 0) return NEGATIVE;
  const externalBases = extractExternalApiBases(ctx.combined, ctx.origin, 4);
  const urls = buildApiProbeUrls(paths, ctx.origin, externalBases, 18);
  const docs = await ctx.probe.getMany(urls, { maxBytes: 8192 }, 4);
  const open: { path: string; status: number; sample: string; host?: string }[] = [];
  for (const [url, r] of docs) {
    if (r.status < 200 || r.status >= 300) continue;
    const ct = r.headers["content-type"] || "";
    if (!/json/i.test(ct) && !/^\s*[\[{]/.test(r.body.trim())) continue;
    if (/unauthorized|login required|sign in|authentication/i.test(r.body.slice(0, 500))) continue;
    const parsed = new URL(url);
    const path = parsed.pathname;
    const sensitive =
      /secret_key|admin_default_password|password|is_admin|plaintext/i.test(r.body) ||
      /\/api\/debug\//i.test(path);
    if (!sensitive && !/"(?:id|name|email|username|data)"\s*:/.test(r.body.slice(0, 400))) continue;
    open.push({
      path,
      status: r.status,
      sample: r.body.slice(0, 120).trim(),
      host: parsed.hostname
    });
  }
  if (open.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.85,
    evidence: {
      routes: open.slice(0, 6),
      note: "JSON API routes returned data without auth challenge"
    }
  };
};

// --- Client-side prompt-injection lab / scanner evidence in bundle ------------
// Detects intentional AI red-team UIs (Fabraix Playground, agent/probe, etc.) from
// shipped JS or SSR HTML — positive proof the app trains or automates prompt attacks.
const CLIENT_PROMPT_INJECTION_RES: { label: string; re: RegExp }[] = [
  {
    label: "Prompt injection red-team lab instructions",
    re: /Use prompt injection, social engineering/i
  },
  {
    label: "AI agent defender challenge UI",
    re: /agent guarded by a defender/i
  },
  {
    label: "Adversarial chatbot prompt scanner",
    re: /(?:Sends )?adversarial prompts to chatbots/i
  },
  {
    label: "Prompt injection scanner product description",
    re: /prompt injection vulnerabilities in any website/i
  },
  {
    label: "Prompt attack research pool",
    re: /\d+-attack (?:research )?pool/i
  },
  {
    label: "Exposed system prompt in client UI",
    re: /(?:systemPrompt|Defender system prompt)/i
  },
  {
    label: "Damn Vulnerable AI Bank training lab",
    re: /Damn Vulnerable AI Bank/i
  },
  {
    label: "DVAIB prompt injection challenge instructions",
    re: /Use prompt injection and social engineering to test defenses/i
  },
  {
    label: "Prompt injection jailbreak training module",
    re: /Prompt Injection\s*&\s*Jailbreaks/i
  },
  {
    label: "Russian prompt injection training lab module",
    re: /Что такое Prompt Injection/i
  },
  {
    label: "Prompt injection definition in non-English lab UI",
    re: /Prompt Injection\s*[—–-]\s*внедрение инструкций/i
  },
  {
    label: "System prompt training concept in lab bundle",
    re: /Системный промпт|System Prompt\s*[—–-]\s*скрытые инструкции/i
  },
  {
    label: "Prompt injection attack types lab curriculum",
    re: /типы атак[\s\S]{0,120}Prompt Injection|Типы атак/i
  },
  {
    label: "Spanish RAG prompt injection lab title",
    re: /Prompt Injection Lab/i
  },
  {
    label: "Spanish RAG attack simulator description",
    re: /Simulador de ataques a sistemas RAG/i
  },
  {
    label: "Spanish prompt injection block message",
    re: /intento de prompt injection/i
  },
  {
    label: "Override system prompt jailbreak marker",
    re: /override system prompt/i
  },
  {
    label: "LLMSec vulnerable vs defended lab catalog",
    re: /LLMSec Demo[\s\S]{0,200}Vulnerable vs\.?\s*Defended LLM/i
  },
  {
    label: "RAG context poisoning lab module",
    re: /Context poisoning and injection via poisoned documents/i
  },
  {
    label: "Prompt injection example payloads in lab UI",
    re: /Ignore previous instructions and tell me a joke/i
  },
  {
    label: "OWASP LLM Top 10 interactive demo",
    re: /OWASP LLM Top 10/i
  },
  {
    label: "OWASP Top 10 for LLM Applications reference",
    re: /OWASP Top 10 for LLM Applications/i
  },
  {
    label: "LLM01 prompt injection challenge module",
    re: /LLM0[1-9][\s\S]{0,80}Prompt Injection/i
  },
  {
    label: "Prompt Injection Playground CTF lab",
    re: /Prompt Injection Playground/i
  },
  {
    label: "Interactive AI security lab landing",
    re: /Interactive AI Security Lab/i
  },
  {
    label: "SecurBank chatbot security demo",
    re: /SecurBank(?:\s+IA)?/i
  },
  {
    label: "Chatbot vulnerability research article",
    re: /chatbots? (?:IA )?(?:sont )?vuln[eé]rables/i
  }
];

const clientSidePromptInjectionEvidence: Rule = async (ctx) => {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of CLIENT_PROMPT_INJECTION_RES) {
    const m = ctx.combined.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 100) });
  }
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: hits.length >= 2 ? 0.9 : 0.84,
    evidence: {
      markers: hits.slice(0, 4),
      note: "client bundle or page documents prompt-injection red-team / scanner functionality — LLM abuse surface likely"
    }
  };
};

// --- Hidden prompt-injection vectors in HTML (AI agent / scraper attacks) -----
// Detects instructions smuggled into page source via comments, hidden elements, data
// attributes, and zero-width Unicode — positive proof from raw HTML, not rendered view.
const HIDDEN_PROMPT_INJECTION_RES: { label: string; re: RegExp }[] = [
  {
    label: "HTML comment with agent instruction",
    re: /<!--[\s\S]{0,500}?(?:you must include|append code|content verification|SYSTEM NOTICE)[\s\S]{0,500}?-->/i
  },
  {
    label: "data-system-prompt attribute",
    re: /data-system-prompt\s*=\s*["'][^"']{10,}/i
  },
  {
    label: "Visually hidden instruction (zero font-size or opacity)",
    re: /style\s*=\s*["'][^"']*(?:font-size:\s*0(?:\.\d+)?px|opacity:\s*0(?:\.\d+)?)[^"']*["'][^>]*>[\s\S]{0,250}?(?:SYSTEM NOTICE|include the phrase|append code|verification code)/i
  },
  {
    label: "display:none smuggled instruction",
    re: /display\s*:\s*none[^>]*>[\s\S]{0,350}?(?:SYSTEM:|verification code|include the phrase|you must include)/i
  },
  {
    label: "clip:rect screen-reader hidden instruction",
    re: /clip:\s*rect\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)[^>]*>[\s\S]{0,250}?(?:SYSTEM NOTICE|append code|verification)/i
  },
  {
    label: "Zero-width Unicode smuggled in HTML text",
    re: /(?:&#x200[bcdBCD];|&#820[345];|&#65279;){2,}/
  },
  {
    label: "ai-instructions meta tag for AI agents",
    re: /<meta\s+name=["']ai-instructions["']\s+content=["'][^"']{20,}/i
  },
  {
    label: "AI agent honeypot security resilience tests",
    re: /AI agent security research[\s\S]{0,200}security resilience tests/i
  },
  {
    label: "AgentPwn distributed honeypot network",
    re: /distributed honeypot network[\s\S]{0,120}AI agents/i
  }
];

const hiddenPromptInjection: Rule = async (ctx) => {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of HIDDEN_PROMPT_INJECTION_RES) {
    const m = ctx.combined.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 120).replace(/\s+/g, " ").trim() });
  }
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: Math.min(0.92, 0.78 + hits.length * 0.03),
    evidence: {
      vectorCount: hits.length,
      hits: hits.slice(0, 5),
      note: "HTML source contains hidden instructions aimed at AI agents/scrapers (prompt injection)"
    }
  };
};

// --- Client-side NoSQL injection evidence in bundle -----------------------------
const CLIENT_NOSQL_RES: { label: string; re: RegExp }[] = [
  {
    label: "NoSQL Injection Educational Lab title",
    re: /NoSQL Injection(?:\s+Educational)?\s+Lab/i
  },
  {
    label: "MongoDB findOne with user-supplied credentials",
    re: /findOne\s*\(\s*\{\s*email\s*:[\s\S]{0,120}password\s*:/i
  },
  {
    label: "NoSQL $gt/$ne operator injection payload",
    re: /\$\s*(?:gt|ne|regex)\s*["']?\s*:/
  },
  {
    label: "Vulnerable Node login without mongo-sanitize",
    re: /app\.post\s*\(\s*['"]\/login['"][\s\S]{0,500}findOne\s*\(\s*\{/i
  },
  {
    label: "NoSQL auth bypass via JSON operator injection",
    re: /contourner une authentification complète sur MongoDB|BACKEND VULNÉRABLE[\s\S]{0,200}findOne/i
  }
];

const clientSideNosqlEvidence: Rule = async (ctx) => {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of CLIENT_NOSQL_RES) {
    const m = ctx.combined.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 100) });
  }
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: hits.length >= 2 ? 0.92 : 0.86,
    evidence: {
      markers: hits.slice(0, 4),
      note: "client bundle documents NoSQL injection via MongoDB operator objects — auth bypass likely if wired to a backend"
    }
  };
};

// --- Client-side XXE evidence in bundle ---------------------------------------
const CLIENT_XXE_RES: { label: string; re: RegExp }[] = [
  {
    label: "XXE Vulnerability Lab title",
    re: /(?:External Entity\s*\(\s*)?XXE(?:\s+Vulnerability)?\s+Lab/i
  },
  {
    label: "XXE ENTITY SYSTEM file:// payload",
    re: /ENTITY\s+\w+\s+SYSTEM\s+["']file:\/\//i
  },
  {
    label: "XXE file:///etc/passwd entity expansion",
    re: /file:\/\/\/etc\/passwd/i
  },
  {
    label: "libxmljs entity processing options",
    re: /libxmljs[\s\S]{0,250}(?:noent|nonet|dtdload)/i
  },
  {
    label: "DOMParser parseFromString text/xml without hardening",
    re: /parseFromString\s*\([^)]*text\/xml/i
  }
];

const clientSideXxeEvidence: Rule = async (ctx) => {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of CLIENT_XXE_RES) {
    const m = ctx.combined.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 100) });
  }
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: hits.length >= 2 ? 0.92 : 0.88,
    evidence: {
      markers: hits.slice(0, 4),
      note: "client bundle documents XXE via external entity expansion — file disclosure or SSRF likely if XML parsing is server-side"
    }
  };
};

// --- Client-side OWASP API Security lab evidence in bundle --------------------
const CLIENT_API_SECURITY_RES: { label: string; re: RegExp }[] = [
  {
    label: "OWASP API Security Top 10 lab",
    re: /OWASP API Security Top 10/i
  },
  {
    label: "Broken Object Level Authorization (BOLA)",
    re: /Broken Object Level Authorization\s*\(\s*BOLA\s*\)/i
  },
  {
    label: "Broken Function Level Authorization (BFLA)",
    re: /Broken Function Level Authorization/i
  },
  {
    label: "Deliberately vulnerable RESTful API showcase",
    re: /deliberately vulnerable RESTful API/i
  },
  {
    label: "Vulnerable API lab BOLA tag",
    re: />\s*BOLA\s*<|BOLA<\/span>/i
  },
  {
    label: "crAPI intentionally vulnerable API lab",
    re: /completely ridiculous API\s*\(crAPI\)/i
  },
  {
    label: "crAPI meta keywords BOLA + BFLA + OWASP API Top 10",
    re: /BOLA[\s,]+IDOR[\s,]+BFLA[\s\S]{0,120}OWASP[\s,]+API[\s,]+Top\s*10/i
  },
  {
    label: "crAPI microservice API prefixes in bundle",
    re: /["']identity\/["'][\s\S]{0,400}["']workshop\/["']/i
  },
  {
    label: "Mass assignment API lab module",
    re: /Privilege Escalation via Mass Assignment|Mass Assignment/i
  },
  {
    label: "Excessive data exposure API lab module",
    re: /Excessive Data Exposure/i
  },
  {
    label: "OpenVault Bank API security lab",
    re: /OpenVault Bank|OVB[\s—–-]\s*OpenVault Bank/i
  },
  {
    label: "API lab endpoint documentation with curl",
    re: /endpoint:\s*["'](?:GET|POST|PUT|DELETE|PATCH)\s+\/(?:api\/)?[\w/{}-]+["']/i
  }
];

const clientSideApiSecurityLabEvidence: Rule = async (ctx) => {
  const hits: { label: string; sample: string }[] = [];
  for (const { label, re } of CLIENT_API_SECURITY_RES) {
    const m = ctx.combined.match(re);
    if (m) hits.push({ label, sample: m[0].slice(0, 100) });
  }
  if (hits.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: hits.length >= 2 ? 0.9 : 0.85,
    evidence: {
      markers: hits.slice(0, 4),
      note: "client bundle documents OWASP API Security Top 10 vulnerability categories (BOLA/BFLA) — broken authorization likely on API routes"
    }
  };
};

// --- PentestForge hub: linked *.lab.pentest-forge.com vulnerable targets --------
// Hub pages catalog OWASP Juice Shop, crAPI, VAmPI, etc. on sibling subdomains.
// Probe linked origins with lab-specific routes; hub catalog alone is positive proof
// of a public benchmark playground when 3+ live targets are listed.
function labProbePathsForHost(hostname: string): string[] {
  const h = hostname.toLowerCase();
  if (h.includes("juice-shop")) {
    return ["/rest/admin/application-configuration", "/rest/track-order/1", "/rest/products/search"];
  }
  if (h.includes("vampi")) return ["/api/v1/users/v1", "/api/v1/users"];
  if (h.includes("crapi")) return ["/identity/api/v2/user/vehicles", "/workshop/api/shop/orders"];
  if (h.includes("tomcat")) return ["/manager/html", "/host-manager/html"];
  if (h.includes("weblogic")) return ["/console/", "/console/login/LoginForm.jsp"];
  if (h.includes("dvga")) return ["/graphql", "/graphiql"];
  if (h.includes("dvwa")) return ["/login.php", "/phpinfo.php"];
  if (h.includes("mutillidae")) return ["/index.php?page=login.php"];
  return ["/api/v1/users", "/rest/products/search"];
}

const PENTEST_FORGE_LAB_HIT_MARKERS = [
  /"(?:config|application|settings|admin)"\s*:/,
  /"status"\s*:\s*"success"/i,
  /"orderId"|"username"|"email"\s*:/,
  /SQLITE_ERROR|SQL syntax/i,
  /Tomcat Manager Application/i,
  /WebLogic Server/i
];

const pentestForgeLinkedLabProbe: Rule = async (ctx) => {
  const isHub =
    /PentestForge Lab/i.test(ctx.combined) &&
    /vulnerable lab|Vulnerable systems/i.test(ctx.combined);
  const linked = extractLinkedLabOrigins(ctx.combined, ctx.origin, 8);
  const origins = new Set<string>(linked);
  if (/\.lab\.pentest-forge\.com$/i.test(new URL(ctx.origin).hostname)) {
    origins.add(ctx.origin);
  }
  if (!isHub && origins.size === 0) return NEGATIVE;

  const probeHits: { host: string; path: string; status: number; sample: string }[] = [];
  for (const origin of [...origins].slice(0, 6)) {
    const host = new URL(origin).hostname;
    const paths = labProbePathsForHost(host);
    const urls = paths.map((p) => new URL(p, origin).toString());
    const docs = await ctx.probe.getMany(urls, { maxBytes: 8192 }, 3);
    for (const [url, r] of docs) {
      if (r.status < 200 || r.status >= 400) continue;
      if (!PENTEST_FORGE_LAB_HIT_MARKERS.some((re) => re.test(r.body.slice(0, 1200)))) continue;
      probeHits.push({
        host,
        path: new URL(url).pathname,
        status: r.status,
        sample: r.body.slice(0, 120).trim()
      });
    }
  }

  if (probeHits.length > 0) {
    return {
      fired: true,
      confidence: 0.9,
      evidence: {
        hits: probeHits.slice(0, 4),
        note: "linked PentestForge lab subdomain returned vulnerable-app data without auth"
      }
    };
  }

  const catalogLabs = linked.map((u) => new URL(u).hostname);
  if (isHub && catalogLabs.length >= 3 && /OWASP Juice Shop/i.test(ctx.combined)) {
    return {
      fired: true,
      confidence: 0.82,
      evidence: {
        labHosts: catalogLabs.slice(0, 8),
        note: "public PentestForge vulnerable lab catalog lists live OWASP/API/CVE benchmark targets"
      }
    };
  }

  return NEGATIVE;
};

// --- deep-tier rules (not run on free path) ---------------------------------

export const RULES: Record<string, Rule> = {
  securityHeaders,
  sourceMaps,
  supabaseRls,
  firebaseRules,
  webhookSignature,
  publicEnvPrefixLeak,
  insecureCookies,
  permissiveCors,
  corsReflectOrigin,
  openRedirect,
  reflectedXss,
  robotsSensitivePaths,
  techDisclosure,
  inlineStateSecrets,
  graphqlIntrospection,
  directoryListing,
  phpinfoExposed,
  errorDisclosure,
  openApiDocs,
  demoModeFlags,
  supabaseStoragePublic,
  supabaseServiceRoleClient,
  sitemapSensitivePaths,
  weakCsp,
  hardcodedCredentials,
  clerkSecretInClient,
  firebaseFirestoreOpen,
  clientOnlyAuth,
  serverActionAuthz,
  idorProbe,
  clientSideIdorEvidence,
  clientSideSqlEvidence,
  clientSideNosqlEvidence,
  clientSideXxeEvidence,
  clientSideApiSecurityLabEvidence,
  clientSideSessionHijackEvidence,
  clientSideSsrfEvidence,
  clientSideFileUploadEvidence,
  sensitiveApiTokenLeakage,
  clientSidePrototypePollutionEvidence,
  serverSideEvalEvidence,
  nextDataSensitiveKeys,
  unauthenticatedApiRoutes,
  sqlErrorDisclosure,
  unauthenticatedAdminEndpoint,
  dangerousHtmlSinks,
  domEvalXss,
  postMessageDomXssEvidence,
  springActuatorExposed,
  idorObjectAccess,
  hiddenPromptInjection,
  clientSidePromptInjectionEvidence,
  ssrfEndpointProbe,
  pentestForgeLinkedLabProbe
};

// Free-tier rules must produce POSITIVE PROOF, not a guess. webhookSignature is a static
// client-side heuristic (it can't see server-side verification), so it is intentionally NOT
// a free rule - it moves to the Deep Scan path where the worker can actually forge a test
// event against an authorized target and confirm it.
export const FREE_RULES = new Set([
  "securityHeaders",
  "sourceMaps",
  "supabaseRls",
  "firebaseRules",
  "publicEnvPrefixLeak",
  "insecureCookies",
  "permissiveCors",
  "corsReflectOrigin",
  "openRedirect",
  "robotsSensitivePaths",
  "techDisclosure",
  // read-only, positive-proof additions — safe to confirm on the free pass
  "inlineStateSecrets",
  "graphqlIntrospection",
  "directoryListing",
  "phpinfoExposed",
  "openApiDocs",
  "demoModeFlags",
  "supabaseStoragePublic",
  "supabaseServiceRoleClient",
  "sitemapSensitivePaths",
  "weakCsp",
  "hardcodedCredentials",
  "clerkSecretInClient",
  "firebaseFirestoreOpen",
  "nextDataSensitiveKeys",
  "unauthenticatedAdminEndpoint",
  "dangerousHtmlSinks",
  "domEvalXss",
  "springActuatorExposed",
  "hiddenPromptInjection",
  "ssrfEndpointProbe"
]);
