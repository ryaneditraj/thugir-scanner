// rule_ref check implementations. Each rule receives the scan context (fetched homepage,
// fetched scripts, origin) and returns whether the pattern fired plus evidence.
//
// All free-tier rules are read-only and near-zero-compute. Deep-tier rules
// (idorProbe, clientOnlyAuth, serverActionAuthz) intentionally do not run on the free path;
// they exist so the worker / future deep flow can share the same registry keys.

import type { FetchedDoc } from "./http";
import type { ProbeCache } from "./probe-cache";
import { extractApiPaths } from "./extract-api";
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
  "redirect",
  "redirect_uri",
  "redirect_url",
  "return",
  "returnTo",
  "return_to",
  "next",
  "url",
  "goto",
  "dest",
  "destination",
  "redir",
  "continue",
  "callback",
  "forward"
];
const OPEN_REDIRECT_FALLBACK_PATHS = ["/", "/login", "/logout", "/signin", "/auth/login"];

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
  return [...paths].slice(0, 6);
}

const openRedirect: Rule = async (ctx) => {
  const probes: { path: string; param: string; status: number; location: string; kind: string }[] = [];
  const seen = new Set<string>();
  const urls: { url: string; param: string; path: string }[] = [];
  const paths = [
    ...new Set([...OPEN_REDIRECT_FALLBACK_PATHS, ...extractOpenRedirectPaths(ctx.combined)])
  ].slice(0, 8);

  for (const path of paths) {
    for (const param of OPEN_REDIRECT_PARAMS) {
      const key = `${path}?${param}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const u = new URL(path, ctx.origin);
      u.searchParams.set(param, OPEN_REDIRECT_PROBE);
      urls.push({ url: u.toString(), param, path });
      if (urls.length >= 12) break;
    }
    if (urls.length >= 12) break;
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
  "s",
  "term",
  "name",
  "id",
  "message",
  "text",
  "keyword",
  "input"
];
const REFLECTED_XSS_FALLBACK_PATHS = ["/", "/search"];

function extractReflectedXssPaths(text: string): string[] {
  const paths = new Set<string>();
  const hrefRe = /href\s*=\s*["'](\/[^"'#?]+)\?[^"']+["']/gi;
  let m: RegExpExecArray | null;
  while ((m = hrefRe.exec(text))) {
    const p = m[1];
    if (/reflected|search|query|echo|error/i.test(p)) paths.add(p);
  }
  if (/reflected/i.test(text)) paths.add("/reflected/parameter/body");
  return [...paths].slice(0, 6);
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
  const paths = [
    ...new Set([homePath, ...extractReflectedXssPaths(ctx.combined), ...REFLECTED_XSS_FALLBACK_PATHS])
  ].slice(0, 6);
  const hits: { path: string; param: string; url: string; snippet: string }[] = [];
  const seen = new Set<string>();
  const urls: { url: string; param: string; path: string }[] = [];

  for (const path of paths) {
    for (const param of REFLECTED_XSS_PARAMS) {
      const key = `${path}?${param}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const u = new URL(path, ctx.origin);
      u.searchParams.set(param, canary);
      urls.push({ url: u.toString(), param, path });
      if (urls.length >= 12) break;
    }
    if (urls.length >= 12) break;
  }

  const docs = await ctx.probe.getMany(urls.map((x) => x.url), { maxBytes: 8192 }, 4);
  for (const { url: probeUrl, param, path } of urls) {
    const doc = docs.get(probeUrl);
    if (!doc || doc.status < 200 || doc.status >= 400) continue;
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
const graphqlIntrospection: Rule = async (ctx) => {
  const query = JSON.stringify({ query: "{__schema{queryType{name} types{name}}}" });
  const candidates = ["/graphql", "/api/graphql", "/v1/graphql", "/query"];
  const urls = candidates.map((path) => new URL(path, ctx.origin).toString());
  const docs = await ctx.probe.getMany(
    urls,
    {
      method: "POST",
      body: query,
      headers: { "Content-Type": "application/json" },
      maxBytes: 8192
    },
    4
  );
  for (const [url, r] of docs) {
    if (r.status >= 200 && r.status < 300 && /"__schema"\s*:/.test(r.body) && /"queryType"/.test(r.body)) {
      let typeCount = 0;
      try {
        typeCount = (JSON.parse(r.body)?.data?.__schema?.types ?? []).length;
      } catch {
        /* keep zero */
      }
      return { fired: true, confidence: 0.9, evidence: { endpoint: url, introspection: "enabled", typeCount } };
    }
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
  "/swagger/v1/swagger.json"
];
const openApiDocs: Rule = async (ctx) => {
  const urls = OPENAPI_PATHS.map((path) => new URL(path, ctx.origin).toString());
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
const IDOR_FALLBACK_PATHS = ["/rest/track-order/1", "/api/orders/1", "/api/users/1"];
const IDOR_AUTH_MARKERS = /unauthorized|login required|authentication|credentials_required|jwt token required|invalid token/i;

function extractIdorProbePaths(text: string): string[] {
  const paths = new Set<string>();
  const templateRe = /["'`](\/(?:rest|api)\/[a-z0-9_-]+)\/\$\{/gi;
  let m: RegExpExecArray | null;
  while ((m = templateRe.exec(text))) paths.add(`${m[1]}/1`);
  if (/track-order/i.test(text)) paths.add("/rest/track-order/1");
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
  const paths = [...new Set([...discovered, ...IDOR_FALLBACK_PATHS])].slice(0, 6);
  const urls = paths.map((p) => new URL(p, ctx.origin).toString());
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
      /"orderId"|"userId"|"user_id"|"email"\s*:|"data"\s*:\s*\[\s*\{/.test(r.body);
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
  /quoted string not properly terminated/i
];
const SQL_PROBE = "'))";

function extractSearchEndpoints(text: string): string[] {
  const paths = new Set<string>();
  const patterns = [
    /["'`](\/rest\/[a-z0-9_\-/]+\/search)["'`]/gi,
    /["'`](\/api\/[a-z0-9_\-/]+\/search)["'`]/gi,
    /fetch\(\s*["']([^"'`]*\/search[^"'`?]*)["']/gi
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      const p = m[1].split("?")[0].replace(/\/+$/, "");
      if (p.length > 3 && p.length < 80) paths.add(p);
    }
  }
  return [...paths].slice(0, 4);
}

const sqlErrorDisclosure: Rule = async (ctx) => {
  const discovered = extractSearchEndpoints(ctx.combined);
  const fallbacks = ["/rest/products/search", "/api/products/search", "/search"];
  const bases = [...new Set([...discovered, ...fallbacks])].slice(0, 5);
  const urls = bases.map((p) => {
    const u = new URL(p, ctx.origin);
    u.searchParams.set("q", SQL_PROBE);
    return u.toString();
  });
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
const ADMIN_JSON_MARKERS = /"(?:config|admin|application|settings|server)"\s*:/;

const unauthenticatedAdminEndpoint: Rule = async (ctx) => {
  const urls = ADMIN_PROBE_PATHS.map((p) => new URL(p, ctx.origin).toString());
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

// --- Unauthenticated JSON API routes (discovered from bundle, read-only GET) --
const unauthenticatedApiRoutes: Rule = async (ctx) => {
  const paths = extractApiPaths(ctx.combined, 10);
  if (paths.length === 0) return NEGATIVE;
  const urls = paths.map((p) => new URL(p, ctx.origin).toString());
  const docs = await ctx.probe.getMany(urls, { maxBytes: 8192 }, 4);
  const open: { path: string; status: number; sample: string }[] = [];
  for (const [url, r] of docs) {
    if (r.status < 200 || r.status >= 300) continue;
    const ct = r.headers["content-type"] || "";
    if (!/json/i.test(ct) && !/^\s*[\[{]/.test(r.body.trim())) continue;
    if (/unauthorized|login required|sign in|authentication/i.test(r.body.slice(0, 500))) continue;
    const path = new URL(url).pathname;
    open.push({ path, status: r.status, sample: r.body.slice(0, 120).trim() });
  }
  if (open.length === 0) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.82,
    evidence: { routes: open.slice(0, 6), note: "JSON API routes returned data without auth challenge" }
  };
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
  nextDataSensitiveKeys,
  unauthenticatedApiRoutes,
  sqlErrorDisclosure,
  unauthenticatedAdminEndpoint,
  dangerousHtmlSinks,
  springActuatorExposed,
  idorObjectAccess
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
  "springActuatorExposed"
]);
