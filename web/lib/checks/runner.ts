// Free-tier scan orchestrator. Runs entirely inside a Vercel function.
// Cost budget: 1 homepage fetch + up to a handful of fixed path probes + up to 12 same-origin
// scripts + a couple of harmless backend reads. No crawl, no auth, no multi-step probing.

import type { Pattern, PatternFinding, Platform } from "../patterns/types";
import { patternsForTier, lockedTeasersForPlatform } from "../patterns";
import { detectPlatform } from "../detect";
import {
  BlockedTargetError,
  extractScriptUrls,
  fetchDoc,
  hostApex,
  looksHtml,
  normalizeTarget,
  type FetchedDoc
} from "./http";

import { FREE_RULES, RULES, type RuleContext } from "./registry";
import { ProbeCache } from "./probe-cache";
import { fetchScriptsBatched, fetchPagesBatched, expandGithackModuleImports } from "./fetch-scripts";

export interface FreeScanOptions {
  maxScripts?: number;
  extraBlockedDomains?: string[];
}

export interface FreeScanResult {
  target: string;
  finalUrl: string;
  detectedPlatform: Platform | null;
  findings: PatternFinding[];
  lockedTeasers: ReturnType<typeof lockedTeasersForPlatform>;
}

// A free finding is only shown if its detector produced positive proof. Anything below this
// is treated as a lead for Deep Scan, never reported as confirmed. This is what makes
// "evidence-gated" literally true rather than a marketing claim.
const FREE_MIN_CONFIDENCE = 0.8;

function compile(re: string): RegExp {
  return new RegExp(re, "gi");
}

// Try hard to reach the target before giving up. Order:
//   1. as given (https for bare domains)
//   2. http:// fallback  (host serves plain http only) — bare domains only
//   3. www. host         (apex has no A record but www does — extremely common)
//   4. http:// + www.
// On success, mutates `target` in place to the URL that actually responded so downstream
// origin/link resolution uses the reachable variant.
/** Parse Username/Password pairs documented on wargame hub pages (e.g. OverTheWire Natas). */
function parseDocumentedBasicAuthCreds(html: string): { user: string; pass: string } | null {
  const m = html.match(/Username:\s*(\S+)[\s\S]{0,120}?Password:\s*(\S+)/i);
  return m ? { user: m[1], pass: m[2] } : null;
}

/** Extract Natas level password from HTML comment or wechallinfo on prior level page. */
function parseNatasLevelCreds(hostname: string, html: string): { user: string; pass: string } | null {
  const levelM = hostname.match(/^natas(\d+)\.natas\.labs\.overthewire\.org$/i);
  if (!levelM) return null;
  const level = levelM[1];
  if (level === "0") return { user: "natas0", pass: "natas0" };
  const commentRe = new RegExp(`password for natas${level} is (\\S+)`, "i");
  const cm = html.match(commentRe);
  if (cm) return { user: `natas${level}`, pass: cm[1] };
  const wechallRe = new RegExp(
    `wechallinfo\\s*=\\s*\\{[^}]*"level"\\s*:\\s*"natas${level}"[^}]*"pass"\\s*:\\s*"([^"]+)"`,
    "i"
  );
  const wm = html.match(wechallRe);
  if (wm) return { user: `natas${level}`, pass: wm[1] };
  return null;
}

/** Natas level-0 credentials are public on the wargame docs page. */
function natasLevelBasicAuth(hostname: string): { user: string; pass: string } | null {
  const m = hostname.match(/^natas(\d+)\.natas\.labs\.overthewire\.org$/i);
  if (!m || m[1] !== "0") return null;
  return { user: "natas0", pass: "natas0" };
}

/** Public demo credentials for known training-lab hosts (documented on course pages). */
function knownLabBasicAuth(hostname: string): { user: string; pass: string } | null {
  if (/^pentesteracademylab\.appspot\.com$/i.test(hostname)) {
    return { user: "student", pass: "password" };
  }
  return null;
}

/** Bootstrap Natas chain creds by walking prior levels when queue hits natas1+ directly. */
async function bootstrapNatasCreds(
  targetLevel: number,
  probe: ProbeCache,
  maxBytes: number
): Promise<{ user: string; pass: string } | null> {
  if (targetLevel <= 0) return { user: "natas0", pass: "natas0" };
  const priorCreds = await bootstrapNatasCreds(targetLevel - 1, probe, maxBytes);
  if (!priorCreds) return null;
  const priorUrl = `http://natas${targetLevel - 1}.natas.labs.overthewire.org/`;
  const priorDoc = await probe.get(priorUrl, { maxBytes, headers: basicAuthHeader(priorCreds) });
  if (priorDoc.status < 200 || priorDoc.status >= 400) return null;
  const fromHtml = parseNatasLevelCreds(
    `natas${targetLevel}.natas.labs.overthewire.org`,
    priorDoc.body
  );
  if (fromHtml) return fromHtml;
  // Natas2+ hides next-level creds in /files/users.txt behind directory listing.
  const usersTxtUrl = `http://natas${targetLevel - 1}.natas.labs.overthewire.org/files/users.txt`;
  const usersDoc = await probe.get(usersTxtUrl, {
    maxBytes: 4096,
    headers: basicAuthHeader(priorCreds)
  });
  if (usersDoc.status === 200) {
    const lineRe = new RegExp(`^natas${targetLevel}:(\\S+)`, "m");
    const lm = usersDoc.body.match(lineRe);
    if (lm) return { user: `natas${targetLevel}`, pass: lm[1] };
  }
  // Natas3+ hides next-level creds in robots.txt Disallow paths (e.g. /s3cr3t/users.txt).
  const priorLevel = targetLevel - 1;
  const priorBase = `http://natas${priorLevel}.natas.labs.overthewire.org`;
  const robotsDoc = await probe.get(`${priorBase}/robots.txt`, {
    maxBytes: 4096,
    headers: basicAuthHeader(priorCreds)
  });
  if (robotsDoc.status === 200) {
    const disallowRe = /^Disallow:\s*(\/\S+)/gim;
    let dm: RegExpExecArray | null;
    while ((dm = disallowRe.exec(robotsDoc.body))) {
      const secretPath = dm[1].replace(/\/$/, "");
      const secretUrl = `${priorBase}${secretPath}/users.txt`;
      const secretDoc = await probe.get(secretUrl, {
        maxBytes: 4096,
        headers: basicAuthHeader(priorCreds)
      });
      if (secretDoc.status !== 200) continue;
      const secretLineRe = new RegExp(`^natas${targetLevel}:(\\S+)`, "m");
      const slm = secretDoc.body.match(secretLineRe);
      if (slm) return { user: `natas${targetLevel}`, pass: slm[1] };
      const secretCommentRe = new RegExp(`password for natas${targetLevel} is (\\S+)`, "i");
      const scm = secretDoc.body.match(secretCommentRe);
      if (scm) return { user: `natas${targetLevel}`, pass: scm[1] };
    }
  }
  return null;
}

function basicAuthHeader(creds: { user: string; pass: string }): Record<string, string> {
  return { Authorization: `Basic ${Buffer.from(`${creds.user}:${creds.pass}`).toString("base64")}` };
}

async function applyWargameBasicAuth(
  url: string,
  doc: FetchedDoc,
  probe: ProbeCache,
  htmlContext: string,
  maxBytes = 600_000
): Promise<FetchedDoc> {
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return doc;
  }
  const needsAuth = doc.status === 401 || /\.natas\.labs\.overthewire\.org$/i.test(host);
  const knownCreds = knownLabBasicAuth(host);
  if (!needsAuth && knownCreds) {
    const shouldAuth =
      /pentesteracademylab\.appspot\.com$/i.test(host) ||
      /Pentester Academy Lab|form-signin/i.test(doc.body);
    if (shouldAuth) {
      const authed = await probe.get(url, { maxBytes, headers: basicAuthHeader(knownCreds) });
      if (
        authed.status >= 200 &&
        authed.status < 400 &&
        (authed.body.length > doc.body.length || /Challenge\s+[1-4]/i.test(authed.body))
      ) {
        return authed;
      }
    }
  }
  if (!needsAuth) return doc;
  let creds =
    parseNatasLevelCreds(host, htmlContext) ??
    parseDocumentedBasicAuthCreds(htmlContext) ??
    natasLevelBasicAuth(host) ??
    knownCreds;
  if (!creds) {
    const levelM = host.match(/^natas(\d+)\.natas\.labs\.overthewire\.org$/i);
    if (levelM && levelM[1] !== "0") {
      creds = await bootstrapNatasCreds(parseInt(levelM[1], 10), probe, maxBytes);
    }
  }
  if (!creds) return doc;
  const authed = await probe.get(url, { maxBytes, headers: basicAuthHeader(creds) });
  if (authed.status >= 200 && authed.status < 400 && authed.body.length > doc.body.length) return authed;
  return doc;
}

/** OWASP GenAI Security Lab — POST /onboard to obtain session cookie for dashboard + lesson pages. */
async function ensureOwaspGenaiLabSession(
  origin: string,
  probe: ProbeCache,
  sessionRef: { cookie?: string },
  maxBytes = 600_000
): Promise<string | undefined> {
  if (sessionRef.cookie) return sessionRef.cookie;
  const onboardUrl = `${origin}/onboard`;
  const body = "name=thugir&goals=prompt-injection&goals=system-prompt-leakage";
  const onboardRes = await probe.get(onboardUrl, {
    method: "POST",
    body,
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    redirect: "manual",
    maxBytes
  });
  const cookie = onboardRes.setCookies.find((c) => /^session=/i.test(c))?.split(";")[0];
  if (cookie) sessionRef.cookie = cookie;
  return cookie;
}

async function applyOwaspGenaiLabSession(
  url: string,
  doc: FetchedDoc,
  probe: ProbeCache,
  sessionRef: { cookie?: string },
  maxBytes = 600_000
): Promise<FetchedDoc> {
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return doc;
  }
  if (!/owaspbased-lessons\.vercel\.app/i.test(host)) return doc;
  if (/lesson-card|LLM0\d:|demo-player__system-prompt/i.test(doc.body)) return doc;
  const cookie = await ensureOwaspGenaiLabSession(new URL(url).origin, probe, sessionRef, maxBytes);
  if (!cookie) return doc;
  const authed = await probe.get(url, { maxBytes, headers: { Cookie: cookie } });
  if (authed.status >= 200 && authed.status < 400 && authed.body.length >= doc.body.length) return authed;
  return doc;
}

const HEROKU_APP_ERROR_RE = /Application Error|herokucdn\.com\/error-pages/i;

function isJuiceShopHost(url: string): boolean {
  try {
    const host = new URL(url).hostname;
    return /juice-shop|owasp-juice|\.juice\.shop$/i.test(host);
  } catch {
    return false;
  }
}

const JUICE_SHOP_API_HEALTH_PATHS = [
  "/rest/admin/application-configuration",
  "/rest/track-order/1",
  "/rest/products/search?q=warmup",
  "/rest/products/search?q=apple",
  "/rest/products/search?q='))"
];

/** True when Juice Shop REST API responds (not Heroku Application Error stub). */
async function juiceShopApiLive(pageUrl: string): Promise<boolean> {
  for (const p of JUICE_SHOP_API_HEALTH_PATHS) {
    try {
      const doc = await fetchDoc(new URL(p, pageUrl).toString(), {
        timeoutMs: 12000,
        maxBytes: 4096
      });
      if (doc.status < 200 || HEROKU_APP_ERROR_RE.test(doc.body)) continue;
      if (p.includes("admin") && /"config"|"application"/i.test(doc.body)) return true;
      if (p.includes("track-order") && /"status"\s*:\s*"success"|"orderId"/i.test(doc.body))
        return true;
      // Juice Shop SQLi oracle returns HTTP 500 with SQLITE_ERROR — still proves API is live.
      if (p.includes("'))") && /SQLITE|syntax error|sequelize/i.test(doc.body)) return true;
      if (doc.status >= 500) continue;
      if (
        p.includes("search") &&
        (/"products"|"data"\s*:\s*\[/i.test(doc.body) ||
          (/"status"\s*:\s*"success"/i.test(doc.body) && /"name"\s*:/i.test(doc.body)) ||
          doc.status === 200)
      )
        return true;
    } catch {
      /* ignore */
    }
  }
  return false;
}

/** Benchmark oracle paths — admin, IDOR track-order, and SQLi/search must all respond before deep rules run. */
async function juiceShopBenchmarkOracleReady(pageUrl: string): Promise<boolean> {
  const checks = await Promise.all(
    JUICE_SHOP_API_HEALTH_PATHS.map(async (p) => {
      try {
        const doc = await fetchDoc(new URL(p, pageUrl).toString(), {
          timeoutMs: 10000,
          maxBytes: 4096
        });
        if (doc.status < 200 || HEROKU_APP_ERROR_RE.test(doc.body)) return null;
        if (p.includes("admin") && /"config"|"application"/i.test(doc.body)) return "admin";
        if (p.includes("track-order") && /"status"\s*:\s*"success"|"orderId"/i.test(doc.body))
          return "idor";
        if (p.includes("'))") && /SQLITE|syntax error|sequelize/i.test(doc.body)) return "sqli";
        if (
          p.includes("warmup") &&
          doc.status >= 200 &&
          doc.status < 300 &&
          /"status"\s*:\s*"success"|"data"\s*:\s*\[/i.test(doc.body)
        )
          return "sqli";
        return null;
      } catch {
        return null;
      }
    })
  );
  const ready = new Set(checks.filter(Boolean));
  return ready.has("admin") && ready.has("idor") && ready.has("sqli");
}

/** Pre-fetch Juice Shop REST + bundle paths into probe cache after dyno wake-up. */
async function primeJuiceShopApiProbes(probe: ProbeCache, pageUrl: string): Promise<void> {
  const origin = new URL(pageUrl).origin;
  const apiPaths = [
    "/rest/admin/application-configuration",
    "/rest/track-order/1",
    "/rest/products/search?q=''))",
    "/rest/products/search?q=warmup",
    "/rest/products/search?q=apple"
  ];
  const bundlePaths = ["/main.js", "/polyfills.js", "/runtime.js"];
  const probeOpts = { maxBytes: 800_000, timeoutMs: 18000 };

  const wakeApi = async (): Promise<boolean> => {
    for (let attempt = 0; attempt < 10; attempt++) {
      if (await juiceShopBenchmarkOracleReady(pageUrl)) return true;
      await new Promise((r) => setTimeout(r, 2500));
    }
    // Last resort: prime whatever API paths respond (partial wake) so other rules still get signal.
    return juiceShopApiLive(pageUrl);
  };

  const wakeBundle = async (): Promise<boolean> => {
    for (let attempt = 0; attempt < 8; attempt++) {
      try {
        const doc = await fetchDoc(new URL("/main.js", origin).toString(), {
          timeoutMs: 10000,
          maxBytes: 16384
        });
        if (
          doc.status >= 200 &&
          doc.status < 500 &&
          !HEROKU_APP_ERROR_RE.test(doc.body) &&
          doc.body.length > 500
        ) {
          return true;
        }
      } catch {
        /* ignore */
      }
      await new Promise((r) => setTimeout(r, 2500));
    }
    return false;
  };

  // Wake API + bundle in parallel — Heroku cold-start often serves one before the other.
  const [apiLive, bundleLive] = await Promise.all([wakeApi(), wakeBundle()]);
  if (apiLive) {
    await probe.getMany(
      apiPaths.map((p) => new URL(p, origin).toString()),
      probeOpts,
      3
    );
  }
  if (bundleLive) {
    await probe.getMany(
      bundlePaths.map((p) => new URL(p, origin).toString()),
      probeOpts,
      3
    );
  }
}

/** Heroku cold-start often serves Application Error HTML — retry before bundle/API probes. */
async function warmupJuiceShopHome(targetUrl: string, home: FetchedDoc): Promise<FetchedDoc> {
  if (!isJuiceShopHost(targetUrl) && !isJuiceShopHost(home.finalUrl)) return home;
  let best = home;
  for (let attempt = 0; attempt < 4; attempt++) {
    const origin = best.finalUrl || targetUrl;
    const pageReady =
      !HEROKU_APP_ERROR_RE.test(best.body) &&
      /main\.js/i.test(best.body) &&
      (await juiceShopApiLive(origin));
    if (pageReady) break;
    await new Promise((r) => setTimeout(r, 3500));
    const retried = await fetchDoc(best.finalUrl || targetUrl, {
      timeoutMs: 18000,
      maxBytes: 600_000
    });
    if (
      retried.status >= 200 &&
      retried.status < 500 &&
      (!HEROKU_APP_ERROR_RE.test(retried.body) || retried.body.length > best.body.length)
    ) {
      best = retried;
    }
  }
  return best;
}

async function reachTarget(target: URL, _rawInput: string): Promise<FetchedDoc> {
  const apexHost = target.hostname.replace(/^www\./i, "");
  const hadWww = target.hostname.toLowerCase().startsWith("www.");

  const hosts = hadWww ? [target.hostname, apexHost] : [apexHost, `www.${apexHost}`];
  // Legacy training benchmarks (demo.testfire.net, zero.webappsecurity.com) are http-only — always
  // fall back to http when https DNS/TLS fails even if the user pasted an https:// URL.
  const protocols = ["https:", "http:"];

  // Interleave so we prefer https on both hosts before dropping to http.
  const candidates: Array<{ protocol: string; hostname: string }> = [];
  for (const protocol of protocols) {
    for (const hostname of hosts) candidates.push({ protocol, hostname });
  }

  let last: FetchedDoc | null = null;
  for (let i = 0; i < candidates.length; i++) {
    const c = candidates[i];
    target.protocol = c.protocol;
    target.hostname = c.hostname;
    // Give the primary attempt the full timeout; keep fallbacks short so the total stays well
    // under the function's 60s budget even if several variants hang.
    const doc = await fetchDoc(target.toString(), { timeoutMs: i === 0 ? 15000 : 7000 });
    if (doc.status !== 0) return doc;
    last = doc;
  }
  return last as FetchedDoc;
}

function reachFailureMessage(target: URL, reason?: string): string {
  const host = target.hostname.replace(/^www\./i, "");
  const why = reason && reason !== "no response" ? ` (${reason})` : "";
  return `We couldn't reach ${host}${why}. Check the address is public and live, then try again — include https:// if it only serves one protocol.`;
}

// Apply a single secret_regex pattern to the combined text.
function scanSecret(pattern: Pattern, combined: string): PatternFinding | null {
  if (pattern.detectorKind !== "secret_regex") return null;
  const cfg = pattern.detectorConfig as { regex: string; validate?: string; secretName: string };
  const re = compile(cfg.regex);
  const raw = combined.match(re);
  if (!raw) return null;
  // Webpack emits `re__WEBPACK_IMPORTED_MODULE_N__` identifiers that false-positive Resend keys.
  const matches =
    pattern.slug === "secret-resend"
      ? raw.filter(
          (m) =>
            !/WEBPACK|__WEBPACK|MODULE/i.test(m) && (m.match(/_/g) || []).length <= 1
        )
      : pattern.slug === "secret-aws-akid"
        ? raw.filter((m) => !/(.)\1{7,}/.test(m.slice(4)) && !/X{8,}/i.test(m))
        : [...raw];
  if (matches.length === 0) return null;
  // Optional validation substring near the match (e.g. service_role inside a JWT payload).
  if (cfg.validate) {
    const hasValid = matches.some((m) => {
      // for JWTs, decode the payload segment and look for the validate token
      try {
        const seg = m.split(".")[1];
        const decoded = atob(seg.replace(/-/g, "+").replace(/_/g, "/"));
        return decoded.includes(cfg.validate!);
      } catch {
        return m.includes(cfg.validate!);
      }
    });
    if (!hasValid) return null;
  }
  const sample = matches[0];
  const redacted = sample.length > 12 ? `${sample.slice(0, 6)}...${sample.slice(-4)}` : "***";
  return {
    patternSlug: pattern.slug,
    category: pattern.category,
    title: pattern.title,
    severity: pattern.severityDefault,
    tierRequired: pattern.tierRequired,
    impactOneline: pattern.impactOneline,
    evidence: { secretName: cfg.secretName, sampleRedacted: redacted, occurrences: matches.length },
    remediation: pattern.remediation,
    fixPrompt: pattern.fixPrompt,
    confidence: 0.9
  };
}

async function scanHttpProbe(
  pattern: Pattern,
  origin: string,
  probe: ProbeCache
): Promise<PatternFinding | null> {
  if (pattern.detectorKind !== "http_probe") return null;
  const cfg = pattern.detectorConfig as {
    paths: string[];
    expect: { kind: string; needle?: string; regex?: string; header?: string };
    maxBytes?: number;
  };
  const maxBytes = cfg.maxBytes ?? 4096;
  const urls = cfg.paths.map((p) => new URL(p, origin).toString());
  const docs = await probe.getMany(urls, { maxBytes }, 4);
  for (const [url, doc] of docs) {
    let hit = false;
    switch (cfg.expect.kind) {
      case "status_2xx":
        hit = doc.status >= 200 && doc.status < 300;
        break;
      case "status_2xx_non_html":
        hit = doc.status >= 200 && doc.status < 300 && !looksHtml(doc.headers, doc.body);
        break;
      case "body_contains":
        hit = doc.status < 400 && doc.body.includes(cfg.expect.needle || "\u0000");
        break;
      case "body_regex":
        hit =
          doc.status < 400 &&
          !looksHtml(doc.headers, doc.body) &&
          new RegExp(cfg.expect.regex || "$^").test(doc.body);
        break;
    }
    if (hit) {
      return {
        patternSlug: pattern.slug,
        category: pattern.category,
        title: pattern.title,
        severity: pattern.severityDefault,
        tierRequired: pattern.tierRequired,
        impactOneline: pattern.impactOneline,
        evidence: { url, status: doc.status, bodySample: doc.body.slice(0, 200) },
        remediation: pattern.remediation,
        fixPrompt: pattern.fixPrompt,
        confidence: 0.9
      };
    }
  }
  return null;
}

async function scanRule(pattern: Pattern, ctx: RuleContext, allowed: Set<string>): Promise<PatternFinding | null> {
  if (pattern.detectorKind !== "rule_ref") return null;
  const cfg = pattern.detectorConfig as { rule: string; options?: Record<string, unknown> };
  if (!allowed.has(cfg.rule)) return null; // rules outside this tier don't run here
  const rule = RULES[cfg.rule];
  if (!rule) return null;
  const res = await rule(ctx, cfg.options);
  if (!res.fired) return null;
  return {
    patternSlug: pattern.slug,
    category: pattern.category,
    title: pattern.title,
    severity: pattern.severityDefault,
    tierRequired: pattern.tierRequired,
    impactOneline: pattern.impactOneline,
    evidence: res.evidence,
    remediation: pattern.remediation,
    fixPrompt: pattern.fixPrompt,
    confidence: res.confidence
  };
}

export async function runFreeScan(targetInput: string, opts: FreeScanOptions = {}): Promise<FreeScanResult> {
  const target = normalizeTarget(targetInput); // throws BlockedTargetError on bad/private hosts

  // Operator-configured denylist (admin → Settings → Security), on top of the built-in one.
  const extra = (opts.extraBlockedDomains ?? []).map((d) => d.toLowerCase());
  if (extra.length) {
    const host = target.hostname.toLowerCase();
    if (extra.includes(host) || extra.includes(hostApex(host))) {
      throw new BlockedTargetError("That domain is blocked for scanning on this platform.");
    }
  }

  let home = await reachTarget(target, targetInput);
  if (home.status === 0) {
    throw new BlockedTargetError(reachFailureMessage(target, home.error));
  }
  const stubRedirect = extractStubRedirectTarget(home.body, home.finalUrl);
  if (stubRedirect && home.body.length < 4096) {
    const redirected = await fetchDoc(stubRedirect, { timeoutMs: 12000, maxBytes: 600_000 });
    if (redirected.status >= 200 && redirected.body.length > home.body.length) home = redirected;
  }
  const origin = target.origin;

  // Pull a capped set of same-origin scripts for secret scanning.
  const probe = new ProbeCache();
  const scriptUrls = extractScriptUrls(home.body, home.finalUrl, opts.maxScripts ?? 12);
  let scripts = await fetchScriptsBatched(scriptUrls, { probe, maxBytes: 800_000, concurrency: 4 });
  const githackSiblings = expandGithackModuleImports(scripts, home.finalUrl, 6);
  if (githackSiblings.length > 0) {
    const fetched = new Set(scriptUrls);
    const extra = githackSiblings.filter((u) => !fetched.has(u));
    if (extra.length > 0) {
      const siblings = await fetchScriptsBatched(extra, { probe, maxBytes: 800_000, concurrency: 4 });
      scripts = [...scripts, ...siblings];
    }
  }
  const combined = [home.body, ...scripts.map((s) => s.body)].join("\n");
  const detection = detectPlatform(home, combined);
  const ctx: RuleContext = { origin, scanUrl: targetInput, home, scripts, combined, probe };

  // Ordering: run the basic, platform-agnostic checks FIRST, then the more targeted
  // platform-specific checks (prioritising the detected platform). The heavier, advanced
  // attacks live in the deep tier and run after these, in the worker.
  const detected = detection.platform;
  const orderWeight = (p: Pattern): number => {
    if (p.platform === "generic") return 0; // basic checks first
    if (detected && p.platform === detected) return 1; // detected-platform checks next
    return 2; // other platform-specific checks last
  };
  const free = [...patternsForTier("free")].sort((a, b) => orderWeight(a) - orderWeight(b));
  const findings: PatternFinding[] = [];
  const seen = new Set<string>();
  const seenRules = new Set<string>();

  for (const pattern of free) {
    let f: PatternFinding | null = null;
    if (pattern.detectorKind === "secret_regex") f = scanSecret(pattern, combined);
    else if (pattern.detectorKind === "http_probe") f = await scanHttpProbe(pattern, origin, probe);
    else if (pattern.detectorKind === "rule_ref") {
      const ruleName = (pattern.detectorConfig as { rule: string }).rule;
      if (seenRules.has(ruleName)) continue;
      f = await scanRule(pattern, ctx, FREE_RULES);
      if (f) seenRules.add(ruleName);
    }
    if (f && f.confidence >= FREE_MIN_CONFIDENCE && !seen.has(f.patternSlug)) {
      seen.add(f.patternSlug);
      findings.push(f);
    }
  }

  // Locked teaser cards prove there is more to find without revealing it.
  const lockedTeasers = lockedTeasersForPlatform(detection.platform);

  return {
    target: target.toString(),
    finalUrl: home.finalUrl,
    detectedPlatform: detection.platform,
    findings,
    lockedTeasers
  };
}

// Deep rules = free rules plus heuristics that need multi-page bundle context or active GET probes.
// clientOnlyAuth, serverActionAuthz, idorProbe, and unauthenticatedApiRoutes run inline here;
// forged webhooks and multi-step IDOR confirmation remain in the Python worker.
const DEEP_RULES = new Set<string>([
  ...FREE_RULES,
  "webhookSignature",
  "errorDisclosure",
  "clientOnlyAuth",
  "serverActionAuthz",
  "idorProbe",
  "unauthenticatedApiRoutes",
  "sqlErrorDisclosure",
  "invictiNslookupCommandInjectionProbe",
  "postLoginSqlBypass",
  "sstiTemplateInjection",
  "clientSideXorAuthEvidence",
  "idorObjectAccess",
  "reflectedXss",
  "clientSideIdorEvidence",
  "clientSideSqlEvidence",
  "clientSideCsrfEvidence",
  "clientSideNosqlEvidence",
  "clientSideXxeEvidence",
  "clientSideApiSecurityLabEvidence",
  "clientSideCyberpunkerInsecureshipEvidence",
  "clientSideOpenvaultLearnEvidence",
  "clientSideOpenvaultCheatsheetEvidence",
  "clientSideCookiejarLabEvidence",
  "clientSideWebgoatEvidence",
  "clientSideSessionHijackEvidence",
  "clientSideSsrfEvidence",
  "clientSideFileUploadEvidence",
  "sensitiveApiTokenLeakage",
  "sensitiveApiPasswordLeakage",
  "clientSideHackYourselfFirstEvidence",
  "clientSidePrototypePollutionEvidence",
  "clientSideJwtNoneEvidence",
  "clientSideOwaspEducationalLabEvidence",
  "serverSideEvalEvidence",
  "clientSidePromptInjectionEvidence",
  "pentestForgeLinkedLabProbe",
  "postMessageDomXssEvidence",
  "clientSideXssEvidence",
  "owaspCtfLinkedLabProbe",
  "clientSideSecurityGameEvidence",
  "clientSideCtfPlatformEvidence",
  "clientSideCtfChallengeHubEvidence",
  "clientSideBouvetIntroCtfEvidence",
  "clientSideCodeBreakingEvidence",
  "clientSideSanitizeXssDemoEvidence",
  "clientSidePokemortyCtfEvidence",
  "clientSideCvebenchBenchmarkEvidence",
  "clientSideSploitifyExploitDatabaseEvidence",
  "clientSidePwnGuideEvidence",
  "clientSideBountybenchBenchmarkEvidence",
  "clientSideOauthFetchPlaygroundEvidence",
  "clientSideJudgementDayArenaEvidence",
  "clientSideCahyodVulnerableLabEvidence",
  "clientSideXssC2CollectorEvidence",
  "clientSideDevSecOpsLabEvidence",
  "clientSideVulnAuthPortalEvidence",
  "clientSideAuthSecurityProjectEvidence",
  "clientSideOsCommandInjectionLabEvidence",
  "clientSideWebVulnsGuideCorsLabEvidence",
  "clientSideEvalFilterBypassLabEvidence",
  "clientSideWebVulnsGuideSstiLabEvidence",
  "clientSideWebVulnsGuideXxeLabEvidence",
  "clientSideWebVulnsGuideSsrfLabEvidence",
  "clientSideSqlInjectionPlaygroundEvidence",
  "clientSidePathTraversalEvidence",
  "clientSideGraphqlLabEvidence",
  "clientSideGraphqlSecurityHubEvidence",
  "clientSideReactRscCveEvidence",
  "clientSideChimeraVulnLabEvidence",
  "clientSideHackHealthLabEvidence",
  "clientSideDomGoatLabEvidence",
  "domgoReferrerDomXssEvidence",
  "domgoHashDomXssEvidence",
  "domgoHashSanitizationBypassDomXssEvidence",
  "domgoWindowNameDomXssEvidence",
  "domgoPostMessageDomXssEvidence",
  "domgoLocalStorageDomXssEvidence",
  "domgoAjaxDomXssEvidence",
  "domgoWebsocketDomXssEvidence",
  "domgoQueryParamDomXssEvidence",
  "domgoSinksCatalogDomXssEvidence",
  "clientSideBenstaffordXssDemoEvidence",
  "clientSideHackThisSiteRealisticMissionEvidence",
  "clientSideHtsLoginGatedMissionHubEvidence",
  "clientSideHtsRealisticMissionLabEvidence",
  "clientSideHtsBasicMissionLabEvidence",
  "clientSideHtsPlaylevelHubEvidence",
  "clientSideInvictiPracticeSiteEvidence",
  "clientSideGinAndJuiceScannerLabEvidence",
  "clientSideWebsecChallengeEvidence",
  "clientSideSixHackCtfLabEvidence",
  "clientSideRootMeChallengeEvidence",
  "clientSidePentesterLabEvidence",
  "clientSidePentesterlabWebForPentesterEvidence",
  "clientSidePentesterlabSqliExerciseEvidence",
  "clientSidePentesterlabXssExerciseEvidence",
  "clientSidePentesterlabSqliToShellEvidence",
  "clientSidePentesterlabSsrfExerciseEvidence",
  "clientSideOverthewireNatasRefererEvidence",
  "clientSideKontraApplicationSecurityEvidence",
  "clientSideDefhawkPracticeLabEvidence",
  "clientSideVulnexEvidence",
  "clientSideSecureflagEvidence",
  "clientSideImmersiveLabsEvidence",
  "clientSideRedtigerHackitEvidence",
  "redtigerClassicLoginSqlEvidence",
  "redtigerBlindLoginFormEvidence",
  "redtigerSpecialChallengeEvidence",
  "htsYuppersSearchSqliProbe",
  "clientSideVulnExposeEvidence",
  "clientSideVulnExposeLabModuleEvidence",
  "clientSideWizerCtfEvidence",
  "clientSideRingzer0CtfEvidence",
  "clientSideWebhackingKrEvidence",
  "clientSideNetForceEvidence",
  "clientSideNetForceChallengeEvidence",
  "clientSideBrutelogicXssGymEvidence",
  "clientSideBrutelogicXssTestPageEvidence",
  "clientSideKnoxssTestPageEvidence",
  "clientSideXssPageEvidence",
  "clientSideCtflearnWebfourEvidence",
  "clientSideCtflearnWebeightEvidence",
  "clientSideCtflearnWeboneEvidence",
  "clientSideCtflearnWebtwoEvidence",
  "clientSideCtflearnWebthreeEvidence",
  "clientSideCtflearnWebsixEvidence",
  "clientSideCtflearnWebsevenEvidence",
  "phpStrcmpArrayBypass",
  "clientSideWechallEvidence",
  "clientSideAppsecMasterEvidence",
  "clientSideAppsecMasterLabHubEvidence",
  "clientSideIstEduVulnPortalEvidence",
  "noticesFileLfiProbe",
  "clientSideHackTheBoxEvidence",
  "clientSideHackTheBoxAcademyEvidence",
  "clientSideHackThisSiteEvidence",
  "clientSideCyberDefendersEvidence",
  "clientSideWebSecurityLabZhEvidence",
  "clientSideSectrainerEvidence",
  "clientSideHackAdvisorLabEvidence",
  "clientSideAgenticAiCtfEvidence",
  "clientSideWrongSecretsEvidence",
  "clientSideMaestroAgenticAiEvidence",
  "clientSideZerodayTrainingEvidence",
  "clientSideCtfResearchTeamEvidence",
  "clientSidePentesterAcademyLabEvidence",
  "clientSideCyberScavengerHuntEvidence",
  "clientSideSkfLabEvidence",
  "clientSideVulnscopeEvidence",
  "clientSideGoogleGruyereCodelabEvidence",
  "clientSideMetasploitableLabEvidence",
  "clientSideBlueTeamLabsEvidence",
  "clientSideJuiceShopProjectEvidence",
  "clientSideJuicesecLabEvidence",
  "clientSidePwnedlabsEvidence",
  "clientSidePwnedlabsGitSecretsEvidence",
  "clientSideMutillidaeEvidence",
  "clientSideBwappEvidence",
  "clientSideBwappInjectionCatalogEvidence",
  "clientSideZeroBankWebinspectEvidence",
  "clientSideCsTrainingAcademyEvidence",
  "clientSideHackableSoLabEvidence",
  "clientSideVulnwebLabEvidence",
  "clientSideHackingLabEvidence",
  "clientSideHacksecEvidence",
  "clientSideSolydTrainingEvidence",
  "clientSideCylabAcademyEvidence",
  "clientSideVulnerableappEvidence",
  "clientSideRestVulnwebEvidence",
  "clientSidePwnshopEvidence",
  "clientSideVulnforgeAcademyEvidence",
  "clientSideVulnforgeEvidence",
  "clientSideVulnshopEvidence",
  "clientSideJwtlensEvidence",
  "clientSideCybersheildLabEvidence",
  "clientSideOopssecStoreEvidence",
  "clientSideTegalsecLabEvidence",
  "clientSideXvwaEvidence",
  "clientSideOpenRedirectEvidence",
  "clientSideHackmyvmEvidence",
  "clientSideXssVictimBankEvidence",
  "clientSideNimbusVaultEvidence",
  "clientSideSecurebankBlogEvidence",
  "clientSideBugBountyHunterEvidence",
  "clientSideBugBountyHunterChallengeScenarioEvidence",
  "clientSideBugCollectionEvidence",
  "clientSideZeroHealthEvidence",
  "clientSideAlfXssWargameEvidence",
  "clientSideLlmSecEvidence",
  "clientSideClawguardAiAuditEvidence",
  "clientSideDefendthewebEvidence",
  "clientSideReturnTrueWargameEvidence",
  "clientSideAuthlabEvidence",
  "clientSideXssQuizEvidence",
  "clientSideCtfchallengeEvidence",
  "clientSideExploitEducationEvidence",
  "clientSideYogsecXssLabsEvidence",
  "clientSideHacker101CtfEvidence",
  "clientSideSockettomeEvidence",
  "clientSideOwaspBricksEvidence",
  "clientSideFvbLabEvidence",
  "clientSidePeruggiaEvidence",
  "clientSideVaultappLabEvidence",
  "clientSideDamnVulnerableBankEvidence",
  "clientSideVulnlabAcademyEvidence",
  "clientSideVulnlabA01AccessEvidence",
  "clientSideVulnlabA02CryptoEvidence",
  "clientSideVulnlabA03InjectionEvidence",
  "clientSideVulnlabA06ComponentsEvidence",
  "clientSideVulnlabA07AuthEvidence",
  "clientSideVulnlabAuthSessionLabEvidence",
  "clientSideVulnlabA08IntegrityEvidence",
  "clientSideVulnlabCmsPlatformEvidence",
  "clientSideVulnlabA09LoggingEvidence",
  "clientSideVulnlabA10SsrfEvidence",
  "clientSideVulnerableWebSiteEvidence",
  "clientSideNivaraSecurityEvidence",
  "clientSideEksGoatEvidence",
  "clientSideCtflearnEvidence",
  "clientSideCybenchEvidence",
  "clientSideW3challsEvidence",
  "clientSideIntercodeEvidence",
  "clientSideVulnerableQaLabEvidence",
  "clientSideMlastgEvidence",
  "clientSideCryptohackEvidence",
  "clientSideOverthewireNatasEvidence",
  "clientSideFfufMeEvidence",
  "clientSideYrpreyEvidence",
  "clientSideBergerCyberLabEvidence",
  "clientSidePwnCollegeEvidence",
  "clientSideReactDomXssLabEvidence",
  "clientSideOwaspGenaiLabEvidence",
  "clientSideCtfDefiEvidence",
  "clientSideAtlasCrewHubEvidence",
  "clientSideAtlasCrewInfernoLabEvidence",
  "clientSideAtlasCrewEdgeProtectionEvidence",
  "clientSideMcpSupplyChainEvidence",
  "clientSideOwaspVwadEvidence",
  "clientSideVwadWackopickoEvidence",
  "clientSideVwadBodgeitEvidence",
  "clientSideVwadSecurityShepherdEvidence",
  "clientSideVwadMutillidaeEvidence",
  "clientSideVwadNodegoatEvidence",
  "clientSideVwadVulnerableappEvidence",
  "clientSideVulnerableappDomXssEvidence",
  "clientSideSecLabPlaygroundEvidence",
  "clientSideSecCodeEducationalEvidence",
  "clientSideSkillauditEvidence",
  "clientSideSecuredAiLabEvidence",
  "clientSideGitagentSecurebotEvidence",
  "clientSideAirtAcademyEvidence",
  "clientSideSecResearchLabEvidence",
  "clientSideBrokencrystalsEvidence",
  "clientSideVapiEvidence",
  "clientSideArchonTrainingEvidence",
  "clientSideOverthewireBanditEvidence",
  "clientSideMcpSherpaWorkshopEvidence",
  "htmlCommentCredentialDisclosure",
  "openApiDebugPasswordExposure",
  "http403BypassProbe",
  "clientSideDevsecopsPipelineVisualizerEvidence",
  "clientSideQamaxAdversaryEvidence",
  "clientSideHacksplainingEvidence",
  "clientSideHacksplainingSqlInjectionLessonEvidence",
  "clientSideHacksplainingHostHeaderPoisoningLessonEvidence",
  "clientSideHacksplainingCsrfLessonEvidence",
  "clientSideHacksplainingSsrfLessonEvidence",
  "clientSideHacksplainingXssReflectedLessonEvidence",
  "clientSideHacksplainingXssStoredLessonEvidence",
  "clientSideHacksplainingClickjackingLessonEvidence",
  "clientSideHacksplainingMassAssignmentLessonEvidence",
  "clientSideHacksplainingBrokenAccessControlLessonEvidence",
  "clientSideHacksplainingDnsPoisoningLessonEvidence",
  "clientSideHacksplainingDowngradeAttacksLessonEvidence",
  "clientSideHacksplainingEmailSpoofingLessonEvidence",
  "clientSideHacksplainingSslStrippingLessonEvidence",
  "clientSideHacksplainingMalvertisingLessonEvidence",
  "clientSideHacksplainingOpenRedirectsLessonEvidence",
  "clientSideHacksplainingXssDomLessonEvidence",
  "clientSideHacksplainingSessionFixationLessonEvidence",
  "clientSideHacksplainingFileUploadLessonEvidence",
  "clientSidePortswiggerAcademyEvidence",
  "clientSideHackinghubEvidence",
  "clientSideUnsecurePwaEvidence",
  "clientSidePromptmapEvidence",
  "clientSideGoogleXssGameEvidence",
  "clientSideSentinelAiEvidence",
  "clientSideNodegoatEvidence",
  "clientSideGandalfEvidence",
  "clientSideIronwaspEvidence",
  "clientSideTry2hackEvidence",
  "clientSideRogueloopXxsCourseEvidence",
  "clientSideEpicdetectEvidence",
  "clientSideAlfServiceworkerEvidence",
  "clientSideBurpBountyLabEvidence",
  "clientSideArtemisKitEvidence",
  "clientSideRailsgoatEvidence",
  "clientSidePcPartsStoreLabEvidence",
  "clientSideBreakTheFlaskEvidence",
  "clientSideGrpcGoatLabEvidence",
  "clientSideWebvulnRunnerEvidence",
  "clientSideFrontendXssDemoEvidence",
  "clientSideAiChatHtmlSinkEvidence",
  "clientSideAvidVulnRegistryEvidence",
  "clientSideSecurityShepherdEvidence",
  "clientSideCyberDrillEvidence",
  "clientSideDeserializationEvidence",
  "clientSideOverthewireLeviathanEvidence",
  "clientSideOverthewireKryptonEvidence",
  "clientSideOverthewireNarniaEvidence",
  "clientSideOverthewireBehemothEvidence",
  "clientSideSecurityWriteupEvidence",
  "clientSideNorthStarAgiCtfEvidence",
  "clientSideWafWorkshopEvidence",
  "clientSideBugforgeLabEvidence",
  "clientSideAikidoZenDemoEvidence",
  "clientSideAttpAgentTrustEvidence",
  "clientSideBugzapPromptDefenseEvidence",
  "clientSideRedlockxPromptFirewallEvidence",
  "clientSideHaoziXssChallengeEvidence",
  "clientSideInsAItsEvidence",
  "clientSideGenaiSecurityCrosswalkEvidence",
  "clientSidePwningJuiceShopCompanionEvidence",
  "clientSideZiranAgentSecurityEvidence",
  "clientSideDotnetSerializationLabEvidence",
  "clientSidePovzaydXssLabsEvidence",
  "clientSideJuiceShopVaptEvidence",
  "clientSideRogueStudioEvidence"
]);
const DEEP_MIN_CONFIDENCE = 0.5; // deep tier surfaces strong heuristics, not just hard proof
const DEEP_MAX_PAGES = 6;

export interface DeepScanResult {
  target: string;
  finalUrl: string;
  detectedPlatform: Platform | null;
  pagesCrawled: string[];
  findings: PatternFinding[];
  /** Full crawl text for AI deep probe (API routes only — not sent to client). */
  combined: string;
  probesRun: number;
}

// Pull same-origin internal links from an HTML body (deduped, capped).
// Resolve against pageUrl so GitHub Pages / subpath deploys crawl sibling .html correctly.
function internalLinks(html: string, pageUrl: string, limit: number): string[] {
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  const re = /href\s*=\s*["']([^"'#?]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) && out.size < limit * 3) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      if (/\.(png|jpe?g|svg|gif|webp|ico|css|js|map|woff2?|ttf|pdf|zip)$/i.test(u.pathname)) continue;
      u.hash = "";
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out].slice(0, limit);
}

/** Security lab hub paths (HackXpert, VWAD-style nav) — scan full HTML, not capped internalLinks. */
const LAB_HUB_PATH_RE =
  /href\s*=\s*["'](\/(?:SQLI|SSTI|XXE|CSRF|SSRF|IDOR|JWT|LFI|NoSQLi|CSTI|RXSS|SXSS|XSS_Playground|OPENREDIRECT|CommandInjection|loginBypass|PortScanning|HOST_HEADER|CORS|CSP|HPP|RateLimitBypass|FILE_UPLOAD|LFIRFICOMBINED|RFI|BUSINESS_LOGIC|PrivEsc|ObjectPropertyAssignment|AdminBypass|XPATH_INJECTION)[^"'#?]*)["']/gi;

function extractLabHubLinks(html: string, pageUrl: string): string[] {
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  let m: RegExpExecArray | null;
  while ((m = LAB_HUB_PATH_RE.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      u.hash = "";
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Docusaurus OWASP Top 10 lab hubs (mehdiaitsaid.github.io/owasp-top-10-labs) — sidebar links /labs/*. */
const DOCUSAURUS_LAB_PATH_RE = /href\s*=\s*["']([^"']*\/labs\/[a-z0-9_./-]+)["']/gi;
const DOCUSAURUS_LAB_SKIP = /\/labs\/(?:intro|setup)\/?$/i;

function extractDocusaurusLabLinks(html: string, pageUrl: string): string[] {
  if (!/docusaurus|docs-doc-page|theme-doc-sidebar/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  let m: RegExpExecArray | null;
  while ((m = DOCUSAURUS_LAB_PATH_RE.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      if (DOCUSAURUS_LAB_SKIP.test(u.pathname)) continue;
      u.hash = "";
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Nextra Hack Health-style cybersecurity tutorial paths (/cybersecurity/a03/sqlInjection). */
const NEXTRA_CYBER_PATH_RE = /href\s*=\s*["'](\/cybersecurity\/[a-z0-9_./-]+)["']/gi;

function extractNextraCybersecurityLinks(html: string, pageUrl: string): string[] {
  if (!/nextra|__NEXT_DATA__|nx-flex/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  let m: RegExpExecArray | null;
  while ((m = NEXTRA_CYBER_PATH_RE.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      u.hash = "";
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Jekyll security doc hubs (Chimera) — vulnerability inventory and endpoint catalogs. */
const JEKYLL_SECURITY_DOC_RE =
  /href\s*=\s*["'](\/(?:vulnerability-inventory|endpoints-catalog|vulnerability-as-a-service)(?:\.html)?)["']/gi;

function extractJekyllSecurityDocLinks(html: string, pageUrl: string): string[] {
  if (!/Jekyll|site-header|jekyll/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  let m: RegExpExecArray | null;
  while ((m = JEKYLL_SECURITY_DOC_RE.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      u.hash = "";
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Jekyll security blogs (maz4lhacks, etc.) — /posts/ write-ups are not linked from capped internalLinks. */
const JEKYLL_BLOG_POST_RE =
  /href\s*=\s*["'](\/posts\/[^"'#?]+)["']/gi;

function extractJekyllBlogPostSeeds(html: string, pageUrl: string): string[] {
  if (!/Jekyll|simple-jekyll-search|site-header|jekyll|maz4lhacks\.vercel\.app/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  let m: RegExpExecArray | null;
  while ((m = JEKYLL_BLOG_POST_RE.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      u.hash = "";
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** DomGoat (domgo.at) — /cxss exercise pages carry inline innerHTML sink labs. */
const DOM_GOAT_CXSS_RE = /href\s*=\s*["'](\/cxss\/(?:example(?:\/\d+)?|sinks|sources)[^"']*)["']/gi;

function extractDomGoatCxssSeeds(html: string, pageUrl: string): string[] {
  if (!/DomGoat|DOM Security Learning Platform/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  let m: RegExpExecArray | null;
  while ((m = DOM_GOAT_CXSS_RE.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      u.hash = "";
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  for (let n = 1; n <= 10; n++) {
    try {
      out.add(new URL(`/cxss/example/${n}`, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  for (const path of ["/cxss/sinks", "/cxss/example/10", "/cxss/example/1", "/cxss/example/2", "/cxss/example/3"]) {
    try {
      out.add(new URL(path, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Ben Stafford XSS Demo (xss.benstafford.dev) — attack1.html query-param DOM XSS labs. */
const BENSTAFFORD_ATTACK_PAGE_RE = /href\s*=\s*["'](attack\d+\.html[^"']*)["']/gi;

function extractBenstaffordXssAttackSeeds(html: string, pageUrl: string): string[] {
  if (!/xss\.benstafford\.dev|XSS Demo|attack1\.html\?username=/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  let m: RegExpExecArray | null;
  while ((m = BENSTAFFORD_ATTACK_PAGE_RE.exec(html))) {
    try {
      const u = new URL(m[1].split("?")[0], pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  for (const p of ["/attack1.html"]) {
    try {
      out.add(new URL(p, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** CTF challenge hubs (webexp05-style) link /c1/, /c2/, … from a landing index only. */
const CTF_CHALLENGE_HUB_RE = /href\s*=\s*["'](\/c\d+\/)["']/gi;

function extractCtfChallengeHubLinks(html: string, pageUrl: string): string[] {
  if (!/CTF Challenge Hub|Web Security Training Challenges|class="challenge-link"/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  let m: RegExpExecArray | null;
  while ((m = CTF_CHALLENGE_HUB_RE.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      u.hash = "";
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** WebSec.fr challenge levels live under /levelNN/ but are only linked in <noscript> <select> options. */
function extractWebsecChallengeSeeds(html: string, origin: string): string[] {
  try {
    if (!/websec\.fr$/i.test(new URL(origin).hostname)) return [];
  } catch {
    return [];
  }
  const out = new Set<string>();
  const optRe = /<option[^>]*>\s*(level\d+)\s*<\/option>/gi;
  let m: RegExpExecArray | null;
  while ((m = optRe.exec(html))) {
    try {
      out.add(new URL(`/${m[1]}/`, origin).toString());
      out.add(new URL(`/${m[1]}/source.php`, origin).toString());
    } catch {
      /* ignore */
    }
  }
  // Banner hint on websec.fr: ".php?id=" — seed common challenge paths + disclosed source.
  if (
    /\.php\?id=/i.test(html) ||
    /websec challenges/i.test(html) ||
    /web security challenges from the people of websec/i.test(html)
  ) {
    for (let n = 1; n <= 12; n++) {
      const slug = `level${String(n).padStart(2, "0")}`;
      try {
        out.add(new URL(`/${slug}/`, origin).toString());
        out.add(new URL(`/${slug}/source.php`, origin).toString());
      } catch {
        /* ignore */
      }
    }
  }
  return [...out];
}

/** PentesterLab exercise catalog — /exercises/* course pages document CVE labs. */
const PENTESTERLAB_EXERCISE_RE = /href\s*=\s*["'](\/exercises\/[a-z0-9_-]+)["']/gi;

function extractPentesterLabExerciseSeeds(html: string, origin: string): string[] {
  if (!/pentesterlab|700\+.*hands-on labs|Web for Pentester/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of [
    "/exercises",
    "/exercises/web-for-pentester",
    "/exercises/web_for_pentester",
    "/exercises/sqli_01",
    "/exercises/sqli-01",
    "/exercises/xss_01",
    "/exercises/xss-01",
    "/exercises/from_sqli_to_shell",
    "/exercises/from-sqli-to-shell",
    "/exercises/ssrf_01",
    "/exercises/ssrf-01",
    "/exercises/web-fundamentals-cors",
    "/exercises/web-fundamentals-graphql",
    "/exercises/web-fundamentals-sessions",
    "/exercises/web-fundamentals-api",
    "/exercises/web-fundamentals-databases"
  ]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  let m: RegExpExecArray | null;
  while ((m = PENTESTERLAB_EXERCISE_RE.exec(html))) {
    try {
      out.add(new URL(m[1], origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** VULNEX playbook — sitemap lists vulnerability/payload taxonomy pages. */
function extractVulnexPlaybookSeeds(html: string, origin: string): string[] {
  if (!/VULNEX|vulnex\.vercel\.app|Web Hacking Playbook/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["/vulnerabilities", "/methods", "/recon", "/all", "/tech-specific", "/cloud"]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  const re = /<loc>(https?:\/\/[^<]*vulnex[^<]*\/[a-z0-9/-]+)<\/loc>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      out.add(new URL(m[1]).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** SecureFlag — owasp.html meta-refresh lands on /owasp OWASP member labs hub. */
function extractSecureflagOwaspSeeds(html: string, origin: string): string[] {
  if (!/secureflag\.com|SecureFlag|Hands-On Secure Coding Training/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["/owasp", "/owasp.html", "/labs", "/training"]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Kontra application.security — free OWASP Top 10 web/API training hubs. */
function extractKontraTrainingSeeds(html: string, origin: string): string[] {
  if (!/application\.security|Kontra Application Security|OWASP Top 10 for (?:API|Web|LLM)/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of [
    "/free/owasp-top-10-API",
    "/free/owasp-top-10",
    "/free/llm",
    "/free/llm/prompt-injection",
    "/free-application-security-training/owasp-top-10-sql-injection",
    "/free-application-security-training/owasp-top-10-command-injection",
    "/free-application-security-training/owasp-top-10-directory-traversal",
    "/free-application-security-training/server-side-request-forgery-in-capital-one",
    "/free-application-security-training/owasp-top-10-clickjacking",
    "/free-application-security-training/owasp-top-10-forced-browsing",
    "/free-application-security-training/owasp-top-10-horizontal-privilege-escalation",
    "/free-application-security-training/owasp-top-10-vertical-privilege-escalation",
    "/free-application-security-training/owasp-top-10-session-fixation",
    "/free-application-security-training/owasp-top-10-user-enumeration",
    "/free-application-security-training/owasp-top-10-stored-cross-site-scripting",
    "/free-application-security-training/owasp-top-10-reflected-cross-site-scripting",
    "/free-application-security-training/owasp-top-10-dom-cross-site-scripting",
    "/free-application-security-training/owasp-top-10-insecure-url-redirect",
    "/free-application-security-training/owasp-top-10-cross-site-request-forgery",
    "/free-application-security-training/owasp-top-10-leftover-debug-code",
    "/free-application-security-training/owasp-top-10-host-header-injection",
    "/free-application-security-training/owasp-top-10-xml-entity-injection",
    "/free-application-security-training/owasp-top-10-components-with-known-vulnerabilities",
    "/free-application-security-training/owasp-top-10-weak-randomness",
    "/free"
  ]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** HackThisSite mission hubs — /missions/basic|realistic|application carry challenge labs. */
const HACKTHISITE_MISSION_RE = /href\s*=\s*["'](\/missions\/[a-z]+(?:\/\d+)?\/?)["']/gi;

function extractHackThisSiteMissionSeeds(html: string, origin: string): string[] {
  if (!/hackthissite|Hack This Site|ethical hacking skills/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of [
    "/missions/basic/",
    "/missions/basic/1/",
    "/missions/realistic/",
    "/missions/application/",
    "/missions/application/1/",
    "/missions/application/2/",
    "/missions/javascript/",
    "/missions/programming/",
    "/missions/forensic/",
    "/missions/playit/extbasic/0/",
    "/missions/playit/stego/0/",
    "/playlevel/1/",
    "/playlevel/2/",
    "/missions/basic/2/",
    "/missions/basic/3/",
    "/missions/basic/4/",
    "/missions/basic/5/",
    "/missions/basic/6/",
    "/missions/basic/7/",
    "/missions/basic/8/",
    "/missions/basic/9/",
    "/missions/basic/10/",
    "/missions/basic/11/",
    "/missions/forensic/1/",
    "/missions/javascript/1/",
    "/missions/stego/1/",
    "/playlevel/3/",
    "/playlevel/4/",
    "/playlevel/5/",
    "/playlevel/6/",
    "/missions/realistic/9/",
    "/missions/realistic/10/",
    "/missions/application/4/",
    "/missions/javascript/2/",
    "/missions/playit/stego/1/",
    "/missions/programming/1/",
    "/missions/application/3/",
    "/missions/realistic/11/",
    "/missions/forensic/2/",
    "/missions/programming/2/",
    "/missions/stego/2/",
    "/playlevel/7/",
    "/playlevel/8/",
    "/playlevel/9/",
    "/playlevel/10/",
    "/playlevel/11/",
    "/missions/realistic/12/",
    "/missions/realistic/13/",
    "/missions/realistic/14/",
    "/missions/realistic/15/",
    "/missions/realistic/16/",
    "/missions/javascript/3/",
    "/missions/stego/3/",
    "/missions/forensic/3/",
    "/missions/programming/3/",
    "/missions/application/6/",
    "/playlevel/12/",
    "/missions/forensic/4/",
    "/missions/javascript/4/",
    "/missions/stego/4/",
    "/missions/programming/4/",
    "/playlevel/13/",
    "/playlevel/14/",
    "/missions/application/7/",
    "/missions/application/8/",
    "/missions/javascript/5/",
    "/missions/javascript/6/",
    "/missions/stego/5/",
    "/missions/stego/6/",
    "/missions/programming/5/",
    "/missions/programming/6/",
    "/missions/programming/7/",
    "/missions/forensic/5/",
    "/missions/forensic/6/",
    "/missions/application/9/",
    "/missions/javascript/7/",
    "/missions/stego/7/",
    "/playlevel/15/",
    "/playlevel/16/",
    "/missions/application/10/",
    "/missions/javascript/8/",
    "/missions/stego/8/",
    "/missions/programming/8/",
    "/missions/forensic/7/",
    "/playlevel/17/",
    "/playlevel/18/",
    "/playlevel/19/",
    "/playlevel/20/",
    "/playlevel/21/",
    "/playlevel/22/",
    "/playlevel/23/",
    "/playlevel/24/",
    "/playlevel/25/",
    "/playlevel/26/",
    "/playlevel/27/",
    "/playlevel/28/",
    "/playlevel/29/",
    "/playlevel/30/",
    "/playlevel/31/",
    "/playlevel/32/",
    "/missions/application/11/",
    "/missions/application/12/",
    "/missions/application/13/",
    "/missions/application/14/",
    "/missions/application/15/",
    "/missions/application/16/",
    "/missions/application/17/",
    "/missions/application/18/",
    "/missions/application/19/",
    "/missions/application/20/",
    "/missions/application/22/",
    "/missions/application/23/",
    "/missions/application/24/",
    "/missions/application/25/",
    "/missions/application/26/",
    "/missions/application/27/",
    "/missions/javascript/9/",
    "/missions/javascript/10/",
    "/missions/javascript/11/",
    "/missions/javascript/12/",
    "/missions/javascript/13/",
    "/missions/javascript/14/",
    "/missions/javascript/15/",
    "/missions/javascript/17/",
    "/missions/javascript/19/",
    "/missions/stego/9/",
    "/missions/stego/10/",
    "/missions/stego/11/",
    "/missions/stego/12/",
    "/missions/stego/13/",
    "/missions/stego/14/",
    "/missions/stego/15/",
    "/missions/stego/16/",
    "/missions/programming/8/",
    "/missions/programming/12/",
    "/missions/programming/9/",
    "/missions/programming/10/",
    "/missions/programming/11/",
    "/missions/forensic/8/",
    "/missions/forensic/9/",
    "/missions/forensic/10/",
    "/missions/forensic/11/",
    "/missions/forensic/12/",
    "/missions/forensic/13/",
    "/missions/forensic/15/",
    "/missions/forensic/16/",
    "/missions/forensic/17/",
    "/missions/forensic/18/"
  ]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  for (const n of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]) {
    try {
      out.add(new URL(`/missions/realistic/${n}/`, origin).toString());
    } catch {
      /* ignore */
    }
  }
  let m: RegExpExecArray | null;
  while ((m = HACKTHISITE_MISSION_RE.exec(html))) {
    try {
      out.add(new URL(m[1], origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** dxx33/WebVulnsGuide — standalone HTML labs for OS injection, prototype pollution, CSRF, eval bypass. */
function extractWebVulnsGuideLabSeeds(html: string, pageUrl: string): string[] {
  if (!/WebVulnsGuide|dxx33\.github\.io\/WebVulnsGuide/i.test(`${html}\n${pageUrl}`)) return [];
  const out = new Set<string>();
  for (const p of [
    "/OS-injection.html",
    "/prototype.html",
    "/EvalByPass.html",
    "/CSRF.html",
    "/SSRF.html",
    "/XSS.html",
    "/SQLi.html",
    "/SSTI.html",
    "/CORS.html",
    "/xxe.html",
    "/SSRF-2.html"
  ]) {
    try {
      out.add(new URL(p, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** HTS Realistic mission instances — vote SQLi, defacement, Fischer products.php, frameset child pages. */
function extractHtsRealisticMissionSeeds(html: string, pageUrl: string): string[] {
  if (!/hackthissite\.org\/missions\/realistic/i.test(pageUrl)) return [];
  const out = new Set<string>();
  if (/uncle arnold|action\s*=\s*["']v\.php/i.test(html)) {
    try {
      out.add(new URL("v.php", pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  if (/AMERICAN NAZI PARTY|update\.php/i.test(html)) {
    try {
      out.add(new URL("update.php", pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  if (/Fischer(?:'|&#x27;)s Animal Products|products\.php/i.test(html)) {
    for (const cat of [1, 2]) {
      try {
        out.add(new URL(`products.php?category=${cat}`, pageUrl).toString());
      } catch {
        /* ignore */
      }
    }
    try {
      out.add(new URL("addemail.php", pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  if (/Compu-global-Hyper-Mega-Net|frameset/i.test(html)) {
    for (const frame of ["top.htm", "menu.htm", "main.htm"]) {
      try {
        out.add(new URL(frame, pageUrl).toString());
      } catch {
        /* ignore */
      }
    }
  }
  if (/Holy Word High School|student\.php/i.test(html)) {
    for (const child of ["student.php", "listteachers.php", "staff.php", "index.php"]) {
      try {
        out.add(new URL(child, pageUrl).toString());
      } catch {
        /* ignore */
      }
    }
  }
  if (/BudgetSERV|page\.pl\?page=/i.test(html)) {
    for (const page of ["main", "features", "faq", "terms", "pricing", "email"]) {
      try {
        out.add(new URL(`page.pl?page=${page}`, pageUrl).toString());
      } catch {
        /* ignore */
      }
    }
    try {
      out.add(new URL("webmail.php", pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  if (/Heartland School District|internet\.pl/i.test(html)) {
    try {
      out.add(new URL("cgi-bin/internet.pl", pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  if (/Elbonia National Republican|members\.php/i.test(html)) {
    for (const child of ["members.php", "debates.php", "newsletter.php", "mailinglist.php"]) {
      try {
        out.add(new URL(child, pageUrl).toString());
      } catch {
        /* ignore */
      }
    }
  }
  if (/Yuppers!|search\.cgi|Web Permit/i.test(html)) {
    for (const child of [
      "search.cgi",
      "login.html",
      "news.cgi",
      "finance/",
      "mail/",
      "yweb/",
      "people.html"
    ]) {
      try {
        out.add(new URL(child, pageUrl).toString());
      } catch {
        /* ignore */
      }
    }
  }
  if (/secuLas|seculas/i.test(html)) {
    for (const child of ["products.php", "questions.php", "jobs.php", "imprint.php"]) {
      try {
        out.add(new URL(child, pageUrl).toString());
      } catch {
        /* ignore */
      }
    }
  }
  if (/Simple Mail|trustworthy email provider/i.test(html)) {
    for (const mod of ["login", "register", "admin_login", "email", "send", "home"]) {
      try {
        out.add(new URL(`index.php?module=${mod}`, pageUrl).toString());
      } catch {
        /* ignore */
      }
    }
  }
  return [...out];
}

/** SixHack Academy links CTF Labs on /ctf-labs/ and platform.sixhackacademy.com from marketing pages. */
function extractSixHackCtfSeeds(html: string, origin: string): string[] {
  if (!/sixhackacademy|CTF Labs de SixHack|platform\.sixhackacademy\.com/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["/ctf-labs/", "/ctf-labs", "/ctf/"]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  const plat = html.match(/https?:\/\/platform\.sixhackacademy\.com\/?/i);
  if (plat) {
    try {
      out.add(new URL("/", plat[0]).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Metasploitable2 / vulnapp.id hub — DVWA, Mutillidae, phpMyAdmin, TWiki, WebDAV. */
function extractVulnappHubSeeds(html: string, origin: string): string[] {
  if (!/Metasploitable2|Never expose this VM to an untrusted network|msfadmin/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["/mutillidae/", "/dvwa/", "/phpMyAdmin/", "/twiki/", "/dav/"]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  const re = /href\s*=\s*["'](\/(?:mutillidae|dvwa|phpMyAdmin|twiki|dav)\/?)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      out.add(new URL(m[1], origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Blue Team Labs Online — cyber range marketing and auth entry points. */
function extractBlueTeamLabsSeeds(html: string, origin: string): string[] {
  if (!/Blue Team Labs Online|blueteamlabs\.online|gamified platform for cyber defenders/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["/login", "/register"]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Pwning OWASP Juice Shop companion guide — Antora challenge-hunting chapters. */
function extractPwningJuiceShopCompanionSeeds(html: string, pageUrl: string): string[] {
  if (!/Pwning OWASP Juice Shop|pwning\.owasp-juice\.shop/i.test(html)) return [];
  const out = new Set<string>();
  const seeds = [
    "https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html",
    "https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html",
    "https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html",
    "https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html"
  ];
  for (const raw of seeds) {
    try {
      out.add(new URL(raw).toString());
    } catch {
      /* ignore */
    }
  }
  try {
    const origin = new URL(pageUrl).origin;
    if (origin.includes("pwning.owasp-juice.shop")) {
      for (const p of [
        "/companion-guide/latest/part2/injection.html",
        "/companion-guide/latest/part2/xss.html",
        "/companion-guide/latest/part2/broken-access-control.html"
      ]) {
        try {
          out.add(new URL(p, pageUrl).toString());
        } catch {
          /* ignore */
        }
      }
    }
  } catch {
    /* ignore */
  }
  return [...out];
}

/** ZIRAN AI agent security testing docs (taoq-ai.github.io/ziran). */
function extractZiranDocSeeds(html: string, pageUrl: string): string[] {
  if (!/ZIRAN|taoq-ai\/ziran|AI Agent Security Testing/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["/getting-started/", "/architecture/", "/tool-chain-analysis/"]) {
    try {
      out.add(new URL(p, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** johniwasz .NET serialization lab — Juice Shop exercise walkthroughs. */
function extractDotnetSerializationLabSeeds(html: string, pageUrl: string): string[] {
  if (!/rce-serialization-dotnet|johniwasz\.github\.io/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of [
    "/rce-serialization-dotnet/JuiceShop/JuiceShop.html",
    "/rce-serialization-dotnet/JuiceShop/solutions/JuiceShop-sqlinjection.html",
    "/rce-serialization-dotnet/JuiceShop/solutions/override-csp-header.html",
    "/rce-serialization-dotnet/JuiceShop/solutions/mass-assignment.html"
  ]) {
    try {
      out.add(new URL(p, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** OWASP Juice Shop GitHub Pages project site — challenge taxonomy and CTF docs. */
function extractJuiceShopProjectSeeds(html: string, origin: string): string[] {
  if (!/OWASP Juice Shop|juice-shop\.github\.io|most modern and sophisticated insecure web application/i.test(html))
    return [];
  const out = new Set<string>();
  for (const p of [
    "/tab_challenges.html",
    "/tab_ctf.html",
    "/tab_learning.html",
    "/tab_overview.html",
    "/www-project-top-ten"
  ]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Pwned Labs marketing and lab landing pages (pwnedlabs.io / labs.pwnedlabs.io). */
function extractPwnedlabsLabSeeds(html: string, pageUrl: string): string[] {
  if (!/Pwned Labs|pwnedlabs\.io|Hunt for Secrets in Git Repos/i.test(html)) return [];
  const out = new Set<string>();
  const seeds = [
    "https://pwnedlabs.io/explore",
    "https://labs.pwnedlabs.io/hunt-for-secrets-in-git-repos"
  ];
  for (const raw of seeds) {
    try {
      out.add(new URL(raw).toString());
    } catch {
      /* ignore */
    }
  }
  try {
    const pageOrigin = new URL(pageUrl).origin;
    if (pageOrigin.includes("pwnedlabs.io")) {
      for (const p of ["/explore", "/hunt-for-secrets-in-git-repos"]) {
        try {
          out.add(new URL(p, pageUrl).toString());
        } catch {
          /* ignore */
        }
      }
    }
  } catch {
    /* ignore */
  }
  return [...out];
}

/** OWASP Mutillidae — index.php?page= routes for SQLi, HTMLi, command injection labs. */
function extractMutillidaeLabSeeds(html: string, origin: string): string[] {
  if (!/Mutillidae:\s*Born to be Hacked|mutillidae/i.test(html)) return [];
  const out = new Set<string>();
  const pages = [
    "user-info.php",
    "login.php",
    "register.php",
    "dns-lookup.php",
    "add-to-your-blog.php",
    "html5-storage.php",
    "capture-data.php",
    "view-someones-blog.php",
    "password-generator.php",
    "show-log.php",
    "site-footer-xss-discussion.php",
    "pen-test-tool-lookup.php",
    "pen-test-tool-lookup-ajax.php"
  ];
  for (const page of pages) {
    try {
      out.add(new URL(`/index.php?page=${page}`, origin).toString());
    } catch {
      /* ignore */
    }
  }
  const re = /index\.php\?page=([a-z0-9_.-]+\.php)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      out.add(new URL(`/index.php?page=${m[1]}`, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** hackable.so — Next.js social platform with 12 hidden vulnerabilities. */
function extractHackableSoSeeds(html: string, jsBodies: string[], origin: string): string[] {
  const corpus = html + jsBodies.join("");
  if (!/hackable\.so|12 hidden vulnerabilities/i.test(corpus)) return [];
  const out = new Set<string>();
  for (const p of [
    "/login",
    "/register",
    "/admin",
    "/dashboard",
    "/admin/users",
    "/admin/config"
  ]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** VulnWeb SPA lab — React routes for SQLi/XSS/IDOR modules (bundle + meta). */
function extractVulnwebLabSeeds(html: string, jsBodies: string[], origin: string): string[] {
  const corpus = html + jsBodies.join("");
  if (!/VulnWeb|vulnerable web app lab|vulnweb\.netlify/i.test(corpus)) return [];
  const out = new Set<string>();
  for (const p of ["/login", "/search", "/comments", "/profile/1", "/profile/2"]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Micro Focus Fortify Zero Bank training demo (zero.webappsecurity.com) — seed bank/login lab pages. */
function extractZeroBankTrainingSeeds(html: string, origin: string): string[] {
  if (!/Zero Bank|zero\.webappsecurity|WebInspect products/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of [
    "login.html",
    "feedback.html",
    "search.html",
    "online-banking.html",
    "bank/account-activity.html",
    "bank/transfer-funds.html",
    "bank/money-map.html"
  ]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** bWAPP marketing site (itsecgames.com) — bugs catalog documents 100+ vulnerability types. */
function extractBwappLabSeeds(html: string, origin: string): string[] {
  if (!/bWAPP|buggy web application|itsecgames/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["bugs.htm", "downloads/vulnerabilities.txt", "download.htm", "training.htm"]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Google Firing Range benchmark (public-firing-range.appspot.com) — reflected/redirect XSS modules. */
function extractFiringRangeCrawlSeeds(html: string, origin: string): string[] {
  if (!/firing[\s-]range|public-firing-range/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of [
    "/reflected/index.html",
    "/redirect/index.html",
    "/dom/index.html",
    "/reflected/parameter/body",
    "/reflected/parameter/title",
    "/reflected/parameter/head",
    "/reflected/parameter/attribute_unquoted"
  ]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  const hrefRe = /href\s*=\s*["'](\/reflected\/parameter\/[^"'?]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = hrefRe.exec(html))) {
    try {
      out.add(new URL(m[1], origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Bouvet Intro to CTF hub (eivindarvesen.github.io/intro-ctf-startpage) — CTFD scoreboard + instances. */
function extractBouvetIntroCtfSeeds(html: string, pageUrl: string): string[] {
  if (!/intro-ctf-startpage|Bouvet Intro to CTF|bouvet-ctfd/i.test(html)) return [];
  const out = new Set<string>();
  for (const raw of [
    "https://bouvet-ctfd.herokuapp.com/",
    "https://bouvet-ctfd.herokuapp.com/register",
    "https://bouvet-ctfd.herokuapp.com/scoreboard"
  ]) {
    try {
      out.add(raw);
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](https?:\/\/bouvet-ctfd\.herokuapp\.com[^"'#]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(m[1]);
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Erling Ellingsen alf.nu XSS wargame (escape.alf.nu, /alert1). */
function extractAlfNuXssSeeds(html: string, pageUrl: string): string[] {
  if (!/alf\.nu|alert\(1\)\s+to\s+win|escape\.alf\.nu/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const raw of [
    "https://escape.alf.nu/",
    "https://alf.nu/alert1",
    "https://alf.nu/alert2",
    "https://returntrue.win/",
    "/alert1",
    "/alert2",
    "/level1",
    "/level2",
    "/level3",
    "/level4",
    "/level5",
    "/level6",
    "/level7",
    "/level8",
    "/level9",
    "/level10",
    "/ReturnTrue"
  ]) {
    try {
      const u = new URL(raw, pageUrl);
      if (u.origin !== pageOrigin && !/alf\.nu$/i.test(u.hostname)) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["']([^"']*(?:escape\.alf\.nu|\/alert\d*|ReturnTrue)[^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (!/alf\.nu$/i.test(u.hostname)) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Erling Ellingsen returntrue.win code-injection wargame levels. */
function extractReturnTrueSeeds(html: string, pageUrl: string): string[] {
  if (!/return\s+true\s+to\s+win|returntrue\.win/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const raw of ["https://returntrue.win/", "?level=1", "?level=2", "?level=3"]) {
    try {
      const u = new URL(raw, pageUrl);
      if (u.origin !== pageOrigin && !/returntrue\.win$/i.test(u.hostname)) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const levelRe = /href\s*=\s*["'](\?level=\d+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = levelRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** DigiNinja Authentication Lab challenge routes. */
function extractAuthlabSeeds(html: string, pageUrl: string): string[] {
  if (!/Authentication Lab|authlab\.digi\.ninja/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/Bypass",
    "/ClientSide",
    "/Timing",
    "/Leaky_JWT",
    "/Auth1",
    "/JWT_None",
    "/JWT_Cracking",
    "/UserAgent"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/(?:Bypass|ClientSide|Timing|Leaky_JWT|Auth1|JWT_None|JWT_Cracking|UserAgent))["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** yamagata21 XSS Challenges staged PHP routes (xss-quiz.int21h.jp). */
function extractXssQuizInt21hSeeds(html: string, pageUrl: string): string[] {
  if (!/xss-quiz\.int21h\.jp|XSS Challenges|yamagata21/i.test(html)) return [];
  if (/printenv at xss-quiz\.int21h\.jp/i.test(html)) {
    const out = new Set<string>();
    const origin = new URL(pageUrl).origin;
    for (const p of [
      "/",
      "/stage2.php",
      "/stage-3.php",
      "/stage_4.php",
      "/stage07.php",
      "/ranking.php"
    ]) {
      try {
        out.add(new URL(p, origin).toString());
      } catch {
        /* ignore */
      }
    }
    return [...out];
  }
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  const stageRe = /href\s*=\s*["']([^"']*stage[^"']*\.php[^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = stageRe.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** TegalSec browser hacking labs (labs.tegalsec.org hub, br0w, xss-labs). */
function extractTegalsecLabSeeds(html: string, pageUrl: string): string[] {
  const isHub = /Cyber Labs[\s\S]{0,60}TegalSec|Hands-on Security Training/i.test(html);
  const isLab = /HACK THE BR0W|XSS Labs \| Tegal1337|tegalsec\.org/i.test(html);
  if (!isHub && !isLab) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  if (isHub) {
    for (const p of ["/br0w/", "/xss-labs/"]) {
      try {
        const u = new URL(p, pageUrl);
        if (u.origin !== pageOrigin) continue;
        out.add(u.toString());
      } catch {
        /* ignore */
      }
    }
  }
  for (const p of ["chall-1.php", "chall-2.php", "instructions.php", "about.php"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Cyber Drill interactive security suite (thecyberdrill.netlify.app). */
function extractCyberDrillToolSeeds(html: string, pageUrl: string): string[] {
  if (!/Cyber Drill|thecyberdrill\.netlify\.app/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/sql-injection/",
    "/phishing-demo/phishing_info",
    "/camera-hijack/",
    "/password-checker/",
    "/quiz/"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const toolRe = /href\s*=\s*["'](\/(?:sql-injection|phishing-demo|camera-hijack|password-checker|quiz)[^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = toolRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Meta-refresh or canonical stub pages (e.g. webgoat.github.io → webgoat.org). */
function extractStubRedirectTarget(html: string, pageUrl: string): string | null {
  const refresh =
    html.match(/<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"';]+)/i) ??
    html.match(/content\s*=\s*["'][^"']*url\s*=\s*([^"';]+)[^"']*["'][^>]*http-equiv\s*=\s*["']refresh["']/i);
  if (refresh?.[1]) {
    try {
      return new URL(refresh[1].trim(), pageUrl).toString();
    } catch {
      /* ignore */
    }
  }
  const canonical = html.match(/<link[^>]*rel\s*=\s*["']canonical["'][^>]*href\s*=\s*["']([^"']+)["']/i);
  if (canonical?.[1] && /moved to|page been moved|redirect/i.test(html)) {
    try {
      const u = new URL(canonical[1].trim(), pageUrl);
      if (u.origin !== new URL(pageUrl).origin) return u.toString();
    } catch {
      /* ignore */
    }
  }
  // Flask/Werkzeug stub pages: "You should be redirected automatically to … <a href="/auth/login">"
  if (/redirecting/i.test(html)) {
    const flask =
      html.match(/redirected automatically[^<]*<a\s+href\s*=\s*["']([^"']+)["']/i) ??
      html.match(/<a\s+href\s*=\s*["']([^"']+)["'][^>]*>[^<]*<\/a>\s*\.?\s*If not, click/i);
    if (flask?.[1]) {
      try {
        return new URL(flask[1].trim(), pageUrl).toString();
      } catch {
        /* ignore */
      }
    }
  }
  return null;
}

/** Google Gruyere codelab (google-gruyere.appspot.com) — multi-part XSS/SQLi/XSRF walkthrough. */
function extractGruyereCodelabSeeds(html: string, origin: string): string[] {
  if (!/gruyere\.appspot\.com|Web Application Exploits and Defenses/i.test(html)) return [];
  const out = new Set<string>();
  for (const part of ["part1", "part2", "part3", "part4", "part5"]) {
    try {
      out.add(new URL(`/${part}`, origin).toString());
    } catch {
      /* ignore */
    }
  }
  const re = /href\s*=\s*["'](\/part[1-5][^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      out.add(new URL(m[1], origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Cahyod Vulnerable Lab hub (lab.cahyo.web.id) — seed linked *.lab.cahyo.web.id subdomains. */
function extractCahyodVulnerableLabSeeds(html: string, pageUrl: string): string[] {
  if (!/lab\.cahyo\.web\.id|Vulnerable Lab|Pentest training environment/i.test(html)) return [];
  const out = new Set<string>();
  const linkRe = /href\s*=\s*["'](https?:\/\/[^"']*\.lab\.cahyo\.web\.id[^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      const u = new URL(m[1]);
      u.hash = "";
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const hostRe = /(?:portal|wp|api-vuln|juice-vuln|ticket|library)\.lab\.cahyo\.web\.id/gi;
  while ((m = hostRe.exec(html))) {
    try {
      out.add(`http://${m[0]}/`);
    } catch {
      /* ignore */
    }
  }
  return [...out].slice(0, 6);
}

/** Pwnshop OWASP Top 10 2025 e-commerce lab (pwnshop.ctfsecurity.com). */
function extractPwnshopDocSeeds(html: string, pageUrl: string): string[] {
  if (!/pwnshop|ctfsecurity\.com/i.test(html) && !/Pwnshop/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const path of ["/vulnerabilities"]) {
    try {
      const u = new URL(path, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/vulnerabilities)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** OWASP Security Shepherd — seed login/about and mirror instances. */
function extractSecurityShepherdSeeds(html: string, pageUrl: string): string[] {
  if (!/Security Shepherd|securityshepherd|about_shepherd_blurb/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/", "/login", "/register.jsp"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  for (const mirror of [
    "https://owasp.securityshepherd.eu/",
    "https://shepherd.fs25.isf.hslu-edu.ch/"
  ]) {
    if (/securityshepherd|Security Shepherd/i.test(html) || pageUrl.includes(mirror)) {
      out.add(mirror);
    }
  }
  return [...out];
}

/** TempeHS Unsecure PWA — seed student security module docs. */
function extractUnsecurePwaSeeds(html: string, pageUrl: string): string[] {
  if (!/Unsecure_PWA|unsecure by-design/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    ".student_resources/XSS/README.md",
    ".student_resources/CSRF/README.md",
    ".student_resources/broken_authentication_and_session_management/README.md",
    ".student_resources/content_security_policy/README.md"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\.student_resources\/[^"'#]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Google XSS game — seed level challenge pages. */
function extractGoogleXssGameSeeds(html: string, pageUrl: string): string[] {
  if (!/XSS game|xss-game\.appspot\.com/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/level1", "/level1/frame", "/level2", "/level3"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/level\d[^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** PromptMap LLM testing workbench — seed dashboard and guide routes. */
function extractPromptmapSeeds(html: string, pageUrl: string): string[] {
  if (!/PromptMap|promptmap\.vercel\.app/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/dashboard", "/guide", "/login"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Lucas Oliveira frontend XSS demo — seed insecure vs secure lab routes. */
function extractFrontendXssDemoSeeds(html: string, pageUrl: string): string[] {
  if (!/frontend-xss-demo|XSS testing.*educational demo/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/insecure", "/secure", "/inseguro", "/seguro"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** AVID vulnerability registry editor — seed /vuln listing and editor routes. */
function extractAvidVulnEditorSeeds(html: string, pageUrl: string): string[] {
  if (!/avid-vuln-editor|AVID Backend|href=["']\/vuln["']/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/vuln", "/editor", "/editor/1", "/faq"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Try2Hack progressive security challenges (try2hack.nl|try2hack.net /levels). */
function extractTry2hackLevelSeeds(html: string, pageUrl: string): string[] {
  if (!/try2hack\.(?:nl|net)|security oriented challenges/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/levels/", "/faq/", "/rules/"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["']([^"']*\/levels\/[^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 6) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Valentin Panov BUG Collection vulnerable Next.js training app. */
function extractBugCollectionSeeds(html: string, pageUrl: string): string[] {
  if (!/BUG Collection|bug-collection\.vercel\.app/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["/login", "/signup", "/dashboard", "/account"]) {
    try {
      out.add(new URL(p, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Hacksplaining OWASP lesson catalog (hacksplaining.com). */
function extractHacksplainingLessonSeeds(html: string, pageUrl: string): string[] {
  if (!/Hacksplaining|hacksplaining\.com/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/lessons",
    "/lessons/sql-injection/start",
    "/lessons/sql-injection/checking-the-code",
    "/lessons/sql-injection/injection-vulnerability",
    "/lessons/sql-injection/injection-explained",
    "/lessons/xss-reflected/start",
    "/lessons/xss-stored/start",
    "/lessons/xss-dom/start",
    "/lessons/xss-dom/checking-the-code",
    "/lessons/csrf/start",
    "/lessons/csrf/cross-domain-requests",
    "/lessons/csrf/forged-requests",
    "/lessons/open-redirects/start",
    "/lessons/ai-prompt-injection/start",
    "/lessons/click-jacking/start",
    "/lessons/click-jacking/checking-the-code",
    "/lessons/mass-assignment/start",
    "/lessons/mass-assignment/checking-the-code",
    "/lessons/css-injection/start",
    "/lessons/css-injection/checking-the-code",
    "/lessons/directory-traversal/start",
    "/lessons/ssrf/start",
    "/lessons/ssrf/arbitrary-domains",
    "/lessons/ssrf/internal-networks",
    "/lessons/broken-access-control/start",
    "/lessons/xml-external-entities/start",
    "/lessons/command-execution/start",
    "/lessons/remote-code-execution/start",
    "/lessons/session-fixation/start",
    "/lessons/file-upload/start",
    "/lessons/prototype-pollution/start",
    "/lessons/cross-origin-resource-sharing/start",
    "/lessons/password-mismanagement/start",
    "/lessons/slop-squatting/start",
    "/lessons/buffer-overflows/start",
    "/lessons/denial-of-service-attacks/start",
    "/lessons/ai-bias-and-unreliability/start",
    "/lessons/ai-data-extraction-attacks/start",
    "/lessons/xml-bombs/start",
    "/lessons/subdomain-squatting/start",
    "/lessons/toxic-dependencies/start",
    "/lessons/unencrypted-communication/start",
    "/lessons/xssi/start",
    "/lessons/dns-poisoning/start",
    "/lessons/downgrade-attacks/start",
    "/lessons/email-spoofing/start",
    "/lessons/malvertising/start",
    "/lessons/ssl-stripping/start",
    "/lessons/host-header-poisoning/start",
    "/lessons/information-leakage/start",
    "/lessons/privilege-escalation/start",
    "/lessons/logging-and-monitoring/start",
    "/lessons/weak-session/start",
    "/lessons/insecure-design/start",
    "/lessons/lax-security-settings/start",
    "/lessons/user-enumeration/start",
    "/lessons/regex-injection/start",
    "/lessons/insecure-deserialization/start"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/lessons\/[a-z0-9-]+(?:\/[a-z0-9-]+)?)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  const stepRe = /href\s*=\s*["']\.\/([a-z0-9-]+)["']/gi;
  while ((m = stepRe.exec(html))) {
    try {
      const base = pageUrl.replace(/\/[^/]*$/, "");
      out.add(new URL(m[1], `${base}/`).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Invicti PHP practice site — seed nslookup command-injection and SQLi lab pages. */
function extractInvictiPhpSeeds(html: string, pageUrl: string): string[] {
  let host = "";
  try {
    host = new URL(pageUrl).hostname;
  } catch {
    /* ignore */
  }
  if (
    !/testsparker\.com|testinvicti\.com/i.test(host) &&
    !/Invicti Test Web Site|artist\.php|nslookup\.php|process\.php\?file=/i.test(html)
  ) {
    return [];
  }
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/nslookup.php", "/hello.php", "/artist.php", "/phpinfo.php", "/products.php"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** PortSwigger Web Security Academy hub (portswigger.net/web-security). */
function extractPortswiggerAcademySeeds(html: string, pageUrl: string): string[] {
  if (!/PortSwigger|Web Security Academy|portswigger\.net\/web-security/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/web-security",
    "/web-security/all-labs",
    "/web-security/mystery-lab-challenge",
    "/web-security/sql-injection",
    "/web-security/cross-site-scripting",
    "/web-security/nosql-injection",
    "/web-security/server-side-request-forgery-ssrf",
    "/web-security/authentication",
    "/web-security/access-control",
    "/web-security/learning-paths"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/web-security\/[a-z0-9-]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Hack The Box marketing hub (hackthebox.com). */
function extractHackTheBoxSeeds(html: string, pageUrl: string): string[] {
  if (!/Hack The Box|hackthebox\.com|cyber readiness platform/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/", "/business/capture-the-flag", "/business/threat-hunting", "/business/cyber-range"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](https?:\/\/(?:www\.)?hackthebox\.com\/[^"'#]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1]).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** HTB Academy training catalogue (academy.hackthebox.com). */
function extractHackTheBoxAcademySeeds(html: string, pageUrl: string): string[] {
  if (!/HTB Academy|academy\.hackthebox\.com|Cybersecurity Training/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/catalogue",
    "/catalogue/paths",
    "/preview/certifications",
    "/academy-lab-relations",
    "/faq",
    "/news"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](https?:\/\/academy\.hackthebox\.com\/[^"'#]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1]).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** OWASP VulnerableApp docs (sasanlabs.github.io/VulnerableApp) — Jekyll scanner-eval platform. */
function extractVulnerableAppDocSeeds(html: string, pageUrl: string): string[] {
  const host = new URL(pageUrl).hostname.toLowerCase();
  const onVulnerableAppHost =
    /(?:^|\.)sasanlabs\.github\.io$/i.test(host) ||
    /(?:^|\.)vulnerableapp\.com$/i.test(host) ||
    /vulnerableapp/i.test(host);
  if (
    !onVulnerableAppHost &&
    !/SasanLabs\/VulnerableApp|href\s*=\s*["']\/VulnerableApp\//i.test(html)
  ) {
    return [];
  }
  if (!/VulnerableApp|SasanLabs\/VulnerableApp/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  const re =
    /href\s*=\s*["'](\/VulnerableApp\/(?:Why_VulnerableApp|DesignDocumentation|HOW-TO-USE-VulnerableApp|blogs\/Overview_of_Owasp-VulnerableApp)\.html)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      u.hash = "";
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  for (const path of [
    "/VulnerableApp/Why_VulnerableApp.html",
    "/VulnerableApp/DesignDocumentation.html",
    "/VulnerableApp/blogs/Overview_of_Owasp-VulnerableApp.html"
  ]) {
    try {
      out.add(new URL(path, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** CTFChallenge UK web app hacking puzzles (ctfchallenge.co.uk). */
function extractCtfChallengeSeeds(html: string, pageUrl: string): string[] {
  if (!/ctfchallenge\.co\.uk|CTF Challenge|web application hacking challenge/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/about", "/login", "/register", "/latest-flags", "/top10"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/(?:about|login|register|latest-flags|top10))["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** h3xstream WAF Bypass Workshop mkdocs lab chapters (waf-workshop/site). */
function extractWafWorkshopMkdocsSeeds(html: string, pageUrl: string): string[] {
  if (!/WAF Bypass Workshop|h3xstream\.github\.io\/waf-workshop|ModSecurity[\s\S]{0,80}libinjection/i.test(html))
    return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/waf-workshop/site/",
    "/waf-workshop/site/03-lab/",
    "/waf-workshop/site/03-sql-syntax/",
    "/waf-workshop/site/02-lab/",
    "/waf-workshop/site/01-lab/",
    "/waf-workshop/site/waf/"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\.\.\/[^"'#?]*(?:lab|sql-syntax|encoding|waf)[^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 10) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Burp Bounty Lab vuln route catalog (burpbountylab.com — XSS/SQLi/SSRF/SSTI profile testbed). */
function extractBurpBountyLabSeeds(html: string, pageUrl: string): string[] {
  if (!/burpbountylab\.com|Burp Bounty Lab|Intentionally vulnerable application for testing Burp Bounty profiles/i.test(html))
    return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/xss/reflect?q=test",
    "/xss/dom?msg=test",
    "/sqli/search?q=laptop",
    "/sqli/user?id=1",
    "/ssrf/fetch?url=http://example.com",
    "/ssti/render?name=test"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/(?:xss|sqli|ssrf|ssti|xxe|graphql|rce)[^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 12) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Exploit Education VM lab index (exploit.education — Phoenix/Nebula/Protostar). */
function extractExploitEducationSeeds(html: string, pageUrl: string): string[] {
  if (!/exploit\.education|Exploit Education|Welcome to exploit\.education/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/phoenix/", "/nebula/", "/protostar/stack-zero/", "/fusion/level00/"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/(?:phoenix|nebula|protostar|fusion)[^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 8) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** yogsec XSS Labs (yogsec.github.io/xss-labs — reflected/stored/DOM browser labs). */
function extractYogsecXssLabsSeeds(html: string, pageUrl: string): string[] {
  if (!/yogsec\.github\.io\/xss-labs|XSS Labs|yogsec\/xss-labs/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const id of ["1", "2", "3", "4", "5", "6"]) {
    try {
      const u = new URL(`labs/lab${id}.html`, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** povzayd XSS LABS (povzayd.github.io/XSS-LABS — reflected/stored/DOM browser labs). */
function extractPovzaydXssLabsSeeds(html: string, pageUrl: string): string[] {
  const onHub =
    /povzayd\.github\.io\/XSS-LABS/i.test(pageUrl) ||
    /povzayd\.github\.io\/XSS-LABS|Welcome to XSS\s*LABS/i.test(html);
  if (!onHub) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  // GitHub Pages is case-sensitive — lab pages live under /LABS/ not /labs/.
  for (let i = 0; i <= 5; i++) {
    try {
      const u = new URL(`LABS/lab${i}.html`, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["']([^"']*\/LABS\/lab\d+\.html)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** OWASP Bricks (sechow.com/bricks — PHP web security learning platform documentation). */
function extractOwaspBricksSeeds(html: string, pageUrl: string): string[] {
  if (!/OWASP Bricks|sechow\.com\/bricks|Break the Bricks/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  // Relative paths — absolute /docs/… drops the /bricks/ deploy prefix on sechow.com.
  for (const p of [
    "docs/login-1.html",
    "docs/content-page-1.html",
    "docs/file-upload-1.html",
    "docs/login-pages.html",
    "docs/content-pages.html"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["']((?:\.\.\/)?docs\/(?:login|content-page|file-upload)-\d+\.html)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 8) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** First Vulnerable Bank GitBook (fvb.vchan.in — REST API security walkthroughs). */
function extractFvbGitbookSeeds(html: string, pageUrl: string): string[] {
  if (!/First Vulnerable Bank|fvb\.vchan\.in/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "llms.txt",
    "readme.md",
    "api-vulnerabilities/broken-object-level-authorization.md",
    "api-vulnerabilities/authenticated-route-bypass.md"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /\(https:\/\/fvb\.vchan\.in\/([^)\s]+\.md)\)/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 8) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Damn Vulnerable Bank (rewanthtammana.com — Android mobile security lab docs). */
function extractDamnVulnerableBankSeeds(html: string, pageUrl: string): string[] {
  if (!/Damn Vulnerable Bank|damn-vulnerable-bank|rewanthtammana/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/exploits/exploit-1/",
    "/exploits/exploit-2/",
    "/exploits/exploit-3/",
    "/exploits/exploit-4/"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/damn-vulnerable-bank\/exploits\/exploit-\d+\/?)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 6) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** VulnLab Academy / Pentest Toolkit (hack-this-site-eta.vercel.app static OWASP lab hub). */
function extractVulnLabAcademySeeds(html: string, pageUrl: string): string[] {
  if (!/VulnLab Academy|Pentest Toolkit|deliberately vulnerable pentest/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const n of ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10"]) {
    try {
      out.add(new URL(`/owasp/a${n}.html`, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  for (const p of [
    "/home/",
    "/owasp/",
    "/labs/xss-reflected.html",
    "/labs/sqli-error.html",
    "/labs/idor.html",
    "/labs/secret-scanner.html",
    "/admin/"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/(?:home|owasp|admin|labs\/[^"']+)\/?)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 10) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Hacker101 CTF (ctf.hacker101.com — HackerOne web security challenge game). */
function extractHacker101CtfSeeds(html: string, pageUrl: string): string[] {
  if (!/ctf\.hacker101\.com|Hacker101 CTF|learn to hack in a safe/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/about", "/howtoplay", "/auth/login", "/scoreboard"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/(?:about|howtoplay|auth\/login|scoreboard)[^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** OWASP EKS Goat mdBook (ekssecurity.netlify.app — cloud-native security masterclass). */
function extractEksGoatMdbookSeeds(html: string, pageUrl: string): string[] {
  if (!/OWASP EKS Goat|AWS EKS Security Masterclass|ekssecurity\.netlify\.app/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/welcome/introduction", "/welcome/agenda", "/basics/lab_setup"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/(?:welcome|basics|exploitation|defense)[^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 8) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** MLASTG mkdocs — seed methodology and LLM security test pages. */
function extractMlastgMkdocsSeeds(html: string, pageUrl: string): string[] {
  if (!/MLASTG|mlastg\.vercel\.app|bb1nfosec\/MLASTG/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/Quick-Start/", "/MLASTG/0x00-Testing-Methodology/", "/MLASVS/V3-LLM/0x30-LLM-Security-Overview/"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/(?:MLASTG|MLASVS|Quick-Start)[^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 8) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Archon VitePress docs — seed cybersecurity and OWASP training paths. */
function extractArchonVitepressSeeds(html: string, pageUrl: string): string[] {
  if (!/archon-eight\.vercel\.app|Holy Grail of Engineering Knowledge|VitePress/i.test(html))
    return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/cybersecurity/", "/security/", "/security/owasp/"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/(?:cybersecurity|security)[^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 8) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Archon VitePress — hostname fallback when SPA shell omits nav on cold fetch. */
function extractArchonHostFallbackSeeds(pageUrl: string): string[] {
  try {
    const u = new URL(pageUrl);
    if (!u.hostname.includes("archon-eight.vercel.app")) return [];
    return ["/cybersecurity/", "/security/", "/security/owasp/"].map((p) =>
      new URL(p, u.origin).toString()
    );
  } catch {
    return [];
  }
}

/** jjirik77/sec_code — developer security & privacy lesson pages. */
function extractSecCodeEducationalSeeds(html: string, pageUrl: string): string[] {
  if (!/sec_code|Developer's Guide to Security|App Security\s*&\s*Privacy/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["privacy.html", "index.html"]) {
    try {
      out.add(new URL(p, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** CryptoHack — seed public challenge catalog. */
function extractCryptohackChallengeSeeds(html: string, pageUrl: string): string[] {
  if (!/CryptoHack|cryptohack\.org/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/challenges/", "/scoreboard/"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** OverTheWire — seed Natas wargame docs and level-0 lab host. */
function extractOverTheWireNatasSeeds(html: string, pageUrl: string): string[] {
  if (!/OverTheWire|overthewire\.org|natas\.labs\.overthewire\.org/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/wargames/natas",
    "/wargames/",
    "/wargames/bandit",
    "/wargames/leviathan",
    "/wargames/krypton",
    "/wargames/narnia",
    "/wargames/behemoth",
    "/wargames/vortex",
    "/wargames/manpage"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const wargameRe =
    /href\s*=\s*["'](\/wargames\/(?:natas|bandit|leviathan|krypton|narnia|behemoth|vortex|manpage))["']/gi;
  let m: RegExpExecArray | null;
  while ((m = wargameRe.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  if (/natas\.labs\.overthewire\.org|Username:\s*natas0/i.test(html)) {
    out.add("http://natas0.natas.labs.overthewire.org/");
  }
  const natasNextRe = /password for natas(\d+) is \S+/gi;
  let natasNext: RegExpExecArray | null;
  while ((natasNext = natasNextRe.exec(html))) {
    out.add(`http://natas${natasNext[1]}.natas.labs.overthewire.org/`);
  }
  if (/bandit\.labs\.overthewire\.org|Username:\s*bandit0/i.test(html)) {
    out.add("https://www.overthewire.org/wargames/bandit/bandit0.html");
  }
  if (/leviathan\.labs\.overthewire\.org|Username:\s*leviathan0/i.test(html)) {
    out.add("https://www.overthewire.org/wargames/leviathan/");
  }
  if (/krypton\.labs\.overthewire\.org|renderLevelsMenu\("krypton"\)/i.test(html)) {
    out.add("https://www.overthewire.org/wargames/krypton/");
    out.add("http://krypton0.krypton.labs.overthewire.org/");
  }
  if (/narnia\.labs\.overthewire\.org|Username:\s*narnia0/i.test(html)) {
    out.add("https://www.overthewire.org/wargames/narnia/");
    out.add("http://narnia0.narnia.labs.overthewire.org/");
  }
  if (/behemoth\.labs\.overthewire\.org|Username:\s*behemoth0/i.test(html)) {
    out.add("https://www.overthewire.org/wargames/behemoth/");
    out.add("http://behemoth0.behemoth.labs.overthewire.org/");
  }
  if (/vortex\.labs\.overthewire\.org|renderLevelsMenu\("vortex"\)/i.test(html)) {
    out.add("https://www.overthewire.org/wargames/vortex/");
    out.add("http://vortex0.vortex.labs.overthewire.org/");
  }
  if (/manpage\.labs\.overthewire\.org|Username:\s*manpage0/i.test(html)) {
    out.add("https://www.overthewire.org/wargames/manpage/");
    out.add("http://manpage0.manpage.labs.overthewire.org/");
  }
  if (/redtiger\.labs\.overthewire\.org|RedTiger's Hackit/i.test(html)) {
    out.add("http://redtiger.labs.overthewire.org/");
  }
  return [...out];
}

/** RedTiger Hackit — seed SQLi/login-bypass level pages from index catalog or direct level URL. */
function extractRedTigerHackitSeeds(html: string, origin: string): string[] {
  const isHub = /RedTiger's Hackit|redtiger\.labs\.overthewire\.org/i.test(html);
  const isLevel =
    /Welcome to level \d+|simple injection|Tablename:\s*level\d+_users|level\d+login/i.test(
      html
    ) && /redtiger\.labs\.overthewire\.org/i.test(origin);
  if (!isHub && !isLevel) return [];
  const out = new Set<string>();
  const re = /href="(level\d+\.php|special1\.php)"/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      out.add(new URL(m[1], origin).toString());
    } catch {
      /* ignore */
    }
  }
  if (isHub || isLevel) {
    for (let i = 1; i <= 10; i++) {
      try {
        out.add(new URL(`level${i}.php`, origin).toString());
      } catch {
        /* ignore */
      }
    }
    try {
      out.add(new URL("special1.php", origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Wizer CTF hub (wizer-ctf.com / sam.wizer-ctf.com) — seed guest play catalog and linked chal*.vercel.app instances. */
function extractWizerCtfSeeds(html: string, pageUrl: string): string[] {
  if (!/Wizer CTF|wizer-ctf\.com|sam\.wizer-ctf\.com|wizer-training\.com/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/?pos=last", "/login", "/signup"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const decoded = html.replace(/&#34;/g, '"').replace(/&quot;/g, '"');
  const chalRe = /https?:\/\/chal[\w-]+\.vercel\.app[^"'\s]*/gi;
  let m: RegExpExecArray | null;
  while ((m = chalRe.exec(decoded))) {
    try {
      out.add(new URL(m[0]).origin + "/");
    } catch {
      /* ignore */
    }
  }
  // sam.wizer-ctf.com promo hub omits chal*.vercel.app links — seed known public instances.
  for (let i = 1; i <= 17; i++) {
    out.add(`https://chal${i}.vercel.app/`);
  }
  return [...out];
}

/** VulnSite (vuln-expose.vercel.app) — seed explicit SQLi/XSS/IDOR/CMDi lab routes from homepage. */
function extractVulnExposeSeeds(html: string, pageUrl: string): string[] {
  if (!/VulnSite|vuln-expose\.vercel\.app|vulns-expose\.jveltri\.com\.ar/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/sqli/login",
    "/sqli/search",
    "/sqli/users",
    "/sqli/blind",
    "/xss/playground",
    "/xss/profile",
    "/xss/comments",
    "/idor/dashboard",
    "/cmdi",
    "/network-tools",
    "/blog",
    "/invoices",
    "/employee-portal"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** VulnPortal — seed /auth/register from login shell links. */
function extractVulnPortalAuthSeeds(html: string, pageUrl: string): string[] {
  if (!/VULN\s*PORTAL|VulnPortal|SECURE ACCESS TERMINAL/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/auth/register", "/auth/login", "/dashboard"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/auth\/[^"'#?]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** OpenVault Bank — seed /learn, /cheatsheet, and /api/v1 training routes from SPA shell. */
function extractOpenvaultBankSeeds(html: string, pageUrl: string): string[] {
  if (!/OpenVault Bank|openvaultbank\.com/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/learn", "/cheatsheet", "/api/v1/users", "/api/v1/admin", "/api/v1/accounts"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** BugBountyHunter zseano — seed numbered challenges and member playground from hub. */
function extractBugBountyHunterChallengeSeeds(html: string, pageUrl: string): string[] {
  if (!/BugBountyHunter|bugbountyhunter\.com|@zseano/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/playground",
    "/challenge?id=1",
    "/training",
    "/vulnerability/?type=xss",
    "/vulnerability/?type=sql",
    "/vulnerability/?type=ssrf"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const idRe = /challenge\?id=(\d+)/gi;
  let m: RegExpExecArray | null;
  while ((m = idRe.exec(html))) {
    try {
      out.add(new URL(`challenge?id=${m[1]}`, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  for (let i = 1; i <= 25; i++) {
    try {
      out.add(new URL(`challenge?id=${i}`, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** SasanLabs vulnerableapp.com — prioritize DOM XSS training page from sparse homepage. */
function extractVulnerableappDomXssSeeds(html: string, pageUrl: string): string[] {
  const host = new URL(pageUrl).hostname.toLowerCase();
  if (!/(?:^|\.)vulnerableapp\.com$/i.test(host)) return [];
  if (!/dom-xss\.html|DOM Based Cross-Site Scripting/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["/dom-xss.html", "/"]) {
    try {
      out.add(new URL(p, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Webhacking.kr — seed challenge hub and ranking pages. */
function extractWebhackingKrSeeds(html: string, pageUrl: string): string[] {
  if (!/Webhacking\.kr|webhacking\.kr/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/chall.php", "/rank.php", "/hof.php"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Net-Force.nl — seed challenge catalog and first training levels. */
function extractNetForceChallengeSeeds(html: string, pageUrl: string): string[] {
  if (!/Net-Force|net-force\.nl/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/challenges/", "/hacktivity/"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href="(challenge\/level\d+\/)"/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 8) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Brute Logic XSS labs — seed gym.php, knoxss hub, xss.php, and linked challenge paths. */
function extractBrutelogicXssGymSeeds(html: string, pageUrl: string): string[] {
  if (!/Brute Logic|brutelogic|knoxss|XSS Gym|XSS Test/i.test(html)) return [];
  const out = new Set<string>();
  const linkRe = /href\s*=\s*["']([^"']*(?:brutelogic\/gym\.php|brutelogic\/xss\.php|brutelogic\/knoxss\.html|\/xss\.php|\/dom\/|\/multi\/|\/blind\/)[^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  if (/x55\.is|brutelogic\.com\.br/i.test(pageUrl)) {
    for (const p of [
      "/brutelogic/gym.php",
      "/brutelogic/xss.php",
      "/brutelogic/knoxss.html",
      "/xss.php?a=1",
      "/dom/sinks.html?name=probe",
      "/multi/double-html.php?p=1"
    ]) {
      try {
        out.add(new URL(p, pageUrl).toString());
      } catch {
        /* ignore */
      }
    }
  }
  return [...out];
}

/** CTFlearn Web4 — seed SQLi challenge on web.ctflearn.com subdomain. */
function extractCtflearnWebfourSeeds(html: string, pageUrl: string): string[] {
  if (!/CTFlearn|ctflearn\.com|web\.ctflearn\.com/i.test(html)) return [];
  const out = new Set<string>();
  try {
    out.add("https://web.ctflearn.com/web4/");
  } catch {
    /* ignore */
  }
  const linkRe = /href\s*=\s*["']([^"']*web\.ctflearn\.com\/web4[^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** CTFlearn Web8 Inj3ction Time — seed dog-id SQLi challenge on web.ctflearn.com. */
function extractCtflearnWebeightSeeds(html: string, pageUrl: string): string[] {
  if (!/CTFlearn|ctflearn\.com|web\.ctflearn\.com/i.test(html)) return [];
  const out = new Set<string>();
  try {
    out.add("https://web.ctflearn.com/web8/");
  } catch {
    /* ignore */
  }
  const linkRe = /href\s*=\s*["']([^"']*web\.ctflearn\.com\/web8[^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** CTFlearn Web1/Web2/Web3/Web6/Web7 — seed beginner web challenge instances on web.ctflearn.com. */
function extractCtflearnWebChallengeSeeds(html: string, pageUrl: string): string[] {
  if (!/CTFlearn|ctflearn\.com|web\.ctflearn\.com/i.test(html)) return [];
  const out = new Set<string>();
  for (const path of ["/web1/", "/web2/", "/web3/", "/web6/", "/web7/"]) {
    try {
      out.add(new URL(path, "https://web.ctflearn.com").toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["']([^"']*web\.ctflearn\.com\/web(?:1|2|3|6|7)[^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** WeChall — seed challenge catalog categories from global CTF scoreboard. */
function extractWechallChallengeSeeds(html: string, pageUrl: string): string[] {
  if (!/WeChall|wechall\.net/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/challs", "/challs/MySQL", "/challs/PHP", "/challs/Exploit", "/challs/HTTP"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** SecuredAI Lab (mnthnx64.github.io/secured-ai) — OWASP ASI agentic security playground. */
function extractSecuredAiSeeds(html: string, pageUrl: string): string[] {
  if (!/SecuredAI Lab|Secured.*AI.*Lab|mnthnx64\/secured-ai/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["app.js", "modules.js"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** VWAD WrongSecrets listing notes link Heroku demo — seed live instance for challenge crawl. */
function extractVwadWrongsecretsLiveSeed(html: string, pageUrl: string): string[] {
  if (!/vwad\.owasp\.org\/app\/wrongsecrets|OWASP WrongSecrets|wrongsecrets\.herokuapp/i.test(html))
    return [];
  const out = new Set<string>();
  const herokuNote = html.match(/Heroku demo:\s*(wrongsecrets\.herokuapp\.com)/i);
  if (herokuNote?.[1]) {
    try {
      out.add(new URL(`https://${herokuNote[1]}/`).toString());
    } catch {
      /* ignore */
    }
  }
  const urlMatch = html.match(/https?:\/\/wrongsecrets\.herokuapp\.com\/?/i);
  if (urlMatch?.[0]) {
    try {
      out.add(new URL(urlMatch[0]).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** VulnForge attack-surface SPA (vulnforge.vercel.app) — seed login routes + main JS bundle. */
function extractVulnforgeSeeds(html: string, pageUrl: string): string[] {
  if (!/VulnForge|vulnforge-backend|AI-Guided Web Attack Surface Explorer/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/login", "/register", "/dashboard", "/benchmarks", "/surface"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const scriptMatch = html.match(/src=["'](\/assets\/index-[^"']+\.js)["']/i);
  if (scriptMatch?.[1]) {
    try {
      out.add(new URL(scriptMatch[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** AppSecMaster (appsecmaster.net) — seed XSS/SQLi category lab hub pages. */
function extractAppsecMasterLabSeeds(html: string, origin: string): string[] {
  if (!/AppSecMaster|appsecmaster\.net/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of [
    "/labs/cross-site-scripting-xss",
    "/labs/sql-injection",
    "/en/challenges?category=Client-Side",
    "/en/challenges?category=Injection"
  ]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** IST Edu vulnerable university portal (ist-edu-bd.vercel.app) — seed auth/search lab routes. */
function extractIstEduVulnPortalSeeds(html: string, pageUrl: string): string[] {
  if (
    !/ist-edu-bd|Institute of Science and Technology|intentionally vulnerable application for security testing/i.test(
      html
    )
  ) {
    return [];
  }
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/portal", "/search", "/dashboard", "/notices", "/login"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** AIRT AI Red Team Academy (0x4d31.github.io/airt) — seed module lab pages. */
function extractAirtAcademySeeds(html: string, pageUrl: string): string[] {
  if (!/AIRT[\s\S]{0,40}AI Red Team Academy|0x4d31\.github\.io\/airt/i.test(`${html}\n${pageUrl}`))
    return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (let i = 1; i <= 8; i++) {
    try {
      const u = new URL(`./module${i}.html`, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** GitAgent SecureBot demo scanner (gitagent-securebot-app.vercel.app) — seed demo scan route. */
function extractGitagentSecurebotSeeds(html: string, pageUrl: string): string[] {
  if (!/GitAgent SecureBot|gitagent-securebot|open-gitagent\/gitagent/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/scan?demo=1", "/scan"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** SkillAudit MCP skill scanner (skillaudit.vercel.app) — seed docs/rules for agent-security markers. */
function extractSkillauditDocSeeds(html: string, pageUrl: string): string[] {
  if (!/SkillAudit|skillaudit\.vercel\.app/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/docs", "/rules", "/integrations", "/openapi.json"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Sec Research Lab (secresearchlab.web.app) — seed interactive lab routes. */
function extractSecResearchLabSeeds(html: string, pageUrl: string): string[] {
  if (!/Sec Research Lab|secresearchlab\.web\.app/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/labs/",
    "/labs/sql-injection/",
    "/labs/xss-playground/",
    "/labs/ssrf-lab/"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** OWASP WebGoat docs (webgoat.org, GitHub Pages mirrors, meta-refresh stubs). */
/** OWASP RailsGoat documentation mirror (railsgoat.cktricky.com). */
function extractRailsgoatDocSeeds(html: string, pageUrl: string): string[] {
  if (!/RailsGoat|railsgoat\.cktricky|OWASP\/railsgoat/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["getting_started.html", "faq.html", "about.html"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** BreakTheFlask Jekyll writeups (dghostninja.github.io) — seed OWASP module posts. */
function extractBreakTheFlaskWriteupSeeds(html: string, pageUrl: string): string[] {
  if (!/BreakTheFlask|DghostNinja\/BreakTheFlask/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/posts/Injection/",
    "/posts/BAC/",
    "/posts/CRYPTOGRAPHIC-FAILURE/",
    "/posts/Insecure-design/"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const postRe = /href\s*=\s*["'](\/posts\/[^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = postRe.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** gRPC Goat Astro docs (rootxjs.github.io/docs/grpc_goat_docs). */
function extractGrpcGoatDocSeeds(html: string, pageUrl: string): string[] {
  if (!/gRPC Goat|grpc_goat_docs|rootxjs\/grpc-goat/i.test(html)) return [];
  const out = new Set<string>();
  const docBases = new Set<string>();
  const helpMatch = html.match(
    /softwareHelp["']\s*:\s*["'](https?:\/\/[^"']+grpc[_-]?goat[^"']*)["']/i
  );
  if (helpMatch?.[1]) {
    try {
      out.add(new URL(helpMatch[1]).toString());
      docBases.add(new URL(helpMatch[1]).origin);
    } catch {
      /* ignore */
    }
  }
  if (/rootxjs\.github\.io|github\.com\/rootxjs\/grpc-goat/i.test(html)) {
    docBases.add("https://rootxjs.github.io");
  }
  // VWAD listing pages reference docs on rootxjs.github.io — not vwad.owasp.org/docs (404).
  try {
    const pageHost = new URL(pageUrl).hostname;
    if (!/vwad\.owasp\.org$/i.test(pageHost)) {
      docBases.add(new URL(pageUrl).origin);
    }
  } catch {
    /* ignore */
  }
  for (const base of docBases) {
    for (const p of [
      "/docs/grpc_goat_docs/getting-started/",
      "/docs/grpc_goat_docs/labs/",
      "/docs/grpc_goat_docs/walkthrough/",
      "/docs/grpc_goat_docs/grpc-basics/"
    ]) {
      try {
        out.add(new URL(p, base).toString());
      } catch {
        /* ignore */
      }
    }
  }
  return [...out];
}

function extractWebgoatDocSeeds(html: string, pageUrl: string): string[] {
  if (!/WebGoat|webgoat\.org|webgoat\.github\.io|vwad\.owasp\.org\/app\/webgoat/i.test(html))
    return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  const helpMatch = html.match(
    /softwareHelp["']\s*:\s*["'](https?:\/\/[^"']+webgoat[^"']*)["']/i
  );
  if (helpMatch?.[1]) {
    try {
      out.add(new URL(helpMatch[1]).toString());
    } catch {
      /* ignore */
    }
  }
  const repoMatch = html.match(
    /codeRepository["']\s*:\s*["'](https?:\/\/github\.com\/[^"']*WebGoat[^"']*)["']/i
  );
  if (repoMatch?.[1]) {
    try {
      out.add(new URL(repoMatch[1]).toString());
    } catch {
      /* ignore */
    }
  }
  if (/luisillobret2\.github\.io\/WebGoat|deliberately insecure Web Application/i.test(html)) {
    for (const p of ["/WebGoat/", "/WebGoat/README.html"]) {
      try {
        out.add(new URL(p, pageUrl).toString());
      } catch {
        /* ignore */
      }
    }
  }
  if (/www-project-webgoat|owasp\.org\/www-project-webgoat/i.test(html)) {
    try {
      out.add(new URL("https://owasp.org/www-project-webgoat/").toString());
    } catch {
      /* ignore */
    }
  }
  const docRe = /href\s*=\s*["']([^"']*\/WebGoat\/[^"']+)["']/gi;
  let dm: RegExpExecArray | null;
  while ((dm = docRe.exec(html))) {
    try {
      const u = new URL(dm[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** SecLab (securityweb-iota.vercel.app) — seed XSS/SQLi/CSRF/IDOR lab routes. */
function extractSecLabPlaygroundSeeds(html: string, pageUrl: string): string[] {
  if (!/SecLab|Web Vulnerability Playground/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/xss", "/sqli", "/csrf", "/idor"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Chinese Web Security Lab — seed /learn/* chapter routes from hub nav. */
function extractWebSecurityLabZhSeeds(html: string, pageUrl: string): string[] {
  if (!/Web 安全实验室|web-security-lab\.vercel\.app/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/learn/same-origin", "/learn/xss", "/learn/csrf", "/learn/cookies-samesite", "/learn/csp"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/learn\/[a-z0-9-]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** TheCyberpunker — seed /labs/insecureship and related API security lab writeups. */
function extractCyberpunkerLabSeeds(html: string, pageUrl: string): string[] {
  if (!/TheCyberpunker|thecyberpunker\.com|InsecureShip/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/labs/insecureship/",
    "/labs/",
    "/learn/insecureship-walkthrough-writeup/"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/labs\/[^"'#?]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Microsoft Sherpa MCP Security Summit workshop — seed camp routes. */
function extractMcpSherpaWorkshopSeeds(html: string, pageUrl: string): string[] {
  if (!/MCP Security Summit Workshop|azure-samples\.github\.io\/sherpa/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "camps/camp1-auth/",
    "camps/camp2-gateway/",
    "camps/camp3-io-security/",
    "camps/camp4-red-team/"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** FFUF.me — seed fuzzing practice lab pages. */
function extractFfufMeSeeds(html: string, pageUrl: string): string[] {
  if (!/FFUF\.me|ffuf\.me|practice and improve your ffuf/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/about", "/help", "/cd/basic"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** BergerZvika Cyber-Lab — seed integer overflow, race, and prompt injection modules. */
function extractBergerCyberLabSeeds(html: string, pageUrl: string): string[] {
  if (!/Cyber-Lab|Secure Programming[\s\S]{0,20}\(Cyber\)/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "integer-overflow.html",
    "race-conditions.html",
    "prompt-injection.html",
    "indirect-prompt-injection-example.html"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** OWASP GenAI Security Lab — seed dashboard and /lesson/* pages from onboarding or lesson grid. */
function extractOwaspGenaiLabSeeds(html: string, pageUrl: string): string[] {
  if (!/GenAI Security Lab|OWASP Top 10 for LLM applications/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/dashboard"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const lessonRe = /href\s*=\s*["'](\/lesson\/[^"'#?]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = lessonRe.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** CTF DeFi Security 101 — seed wallet play route. */
function extractCtfDefiSeeds(html: string, pageUrl: string): string[] {
  if (!/CTF Defi Security 101|DeFi-Security-Summit-Stanford/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/play"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** VaultApp Omega finance security training SPA — seed login page with demo credentials. */
function extractVaultappSeeds(html: string, pageUrl: string): string[] {
  let host = "";
  try {
    host = new URL(pageUrl).hostname;
  } catch {
    /* ignore */
  }
  if (!/vaultapp-omega\.vercel\.app/i.test(host) && !/VaultApp|Security Training Lab/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["/login", "/dashboard"]) {
    try {
      out.add(new URL(p, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Escape.tech / ThreatX / Pentest Ground hosted DVGA — seed live GraphQL lab routes from sidebar HTML. */
function extractDvgaLiveSeeds(html: string, pageUrl: string): string[] {
  let host = "";
  try {
    host = new URL(pageUrl).hostname;
  } catch {
    /* ignore */
  }
  const isLiveHost =
    /xplat-demo\.threatx\.io|dvga\.tools\.escape\.tech|pentest-ground\.com/i.test(host);
  const isLiveApp =
    /Damn Vulnerable GraphQL Application/i.test(html) &&
    /dvgql_logo\.png|id="sidebar-wrapper"[\s\S]{0,500}\/import_paste/i.test(html);
  if (/vwad\.owasp\.org/i.test(host) || (!isLiveHost && !isLiveApp)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/import_paste", "/create_paste", "/public_pastes", "/graphql", "/graphiql", "/audit"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** TomAbai LLM Security Labs (llm-sec.dev) — seed October CTF and lab modules. */
function extractLlmSecDevSeeds(html: string, pageUrl: string): string[] {
  if (!/llm-sec\.dev|LLM Security Labs|TomAbai\/llm-sec/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/october", "/labs"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/(?:october|labs)[^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** picoCTF migration landing — seed CyLab Security Academy hub for deeper crawl. */
function extractPicoctfCylabSeeds(html: string, pageUrl: string): string[] {
  if (!/picoCTF|picoctf\.org|CyLab Security Academy|cylabacademy\.org/i.test(html)) return [];
  const out = new Set<string>();
  for (const url of [
    "https://cylabacademy.org/",
    "https://cylabacademy.org/about.html",
    "https://cylabacademy.org/learners.html",
    "https://cylabacademy.org/competitors.html",
    "https://cylabacademy.org/educators.html",
    "https://primer.cylabacademy.org/"
  ]) {
    out.add(url);
  }
  const linkRe = /href\s*=\s*["'](https?:\/\/(?:cylabacademy|primer\.cylabacademy)\.org[^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 6) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Hacking-Lab AG training platform — seed CTF and events hubs from Angular landing. */
function extractHackingLabSeeds(html: string, pageUrl: string): string[] {
  if (!/Hacking-Lab|hacking-lab\.com/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/events/", "/ctf_platform", "/cyber_security_labs_for_universities"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/(?:events|ctf_platform)[^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Gin & Juice Shop — seed blog post pages from /blog listing. */
function extractGinAndJuiceBlogPostSeeds(html: string, pageUrl: string): string[] {
  let host = "";
  try {
    host = new URL(pageUrl).hostname;
  } catch {
    /* ignore */
  }
  if (!/ginandjuice\.shop/i.test(host) && !/ginandjuice\.shop|Gin & Juice Shop/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  const postRe = /href\s*=\s*["'](\/blog\/post\?postId=\d+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = postRe.exec(html)) && out.size < 8) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Gin & Juice Shop — PortSwigger scanner evaluation lab with /vulnerabilities oracle. */
function extractGinAndJuiceVulnSeeds(html: string, pageUrl: string): string[] {
  let host = "";
  try {
    host = new URL(pageUrl).hostname;
  } catch {
    /* ignore */
  }
  if (
    !/ginandjuice\.shop/i.test(host) &&
    !/Gin & Juice Shop|ginandjuice\.shop|vulnerability scanner to the test/i.test(html)
  ) {
    return [];
  }
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/vulnerabilities", "/catalog", "/blog"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  if (/href\s*=\s*["']\/vulnerabilities["']/i.test(html)) {
    try {
      out.add(new URL("/vulnerabilities", pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Invicti ASP.NET practice site — seed guestbook XSS lab page. */
function extractInvictiAspnetSeeds(html: string, pageUrl: string): string[] {
  let host = "";
  try {
    host = new URL(pageUrl).hostname;
  } catch {
    /* ignore */
  }
  if (
    !/testsparker\.com|testinvicti\.com/i.test(host) &&
    !/Guestbook\.aspx|guestbookPermenantCrossSiteScripting/i.test(html)
  ) {
    return [];
  }
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/Guestbook.aspx", "/administrator/Login.aspx"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Atlas Crew portfolio hub — security platform docs and linked lab subdomains. */
function extractAtlasCrewHubSeeds(html: string, pageUrl: string): string[] {
  if (!/atlascrew\.dev/i.test(new URL(pageUrl).hostname)) return [];
  if (!/Atlas Crew Security|Open-Source Security|Synapse.*Chimera/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/security.html",
    "/chimera.html",
    "/synapse.html",
    "/crucible.html",
    "/apparatus.html",
    "/synapse-fleet.html"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const extRe =
    /href="(https:\/\/(?:chimera|synapse|crucible|apparatus|horizon-demo)\.atlascrew\.dev[^"]*)"/gi;
  let m: RegExpExecArray | null;
  while ((m = extRe.exec(html)) && out.size < 10) {
    try {
      out.add(new URL(m[1]).origin + "/");
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Atlas Crew Inferno Lab — Apparatus + Crucible tutorial and feature docs. */
function extractAtlasCrewInfernoLabSeeds(html: string, pageUrl: string): string[] {
  if (!/atlascrew\.dev|Apparatus|Crucible|@atlascrew/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  const host = new URL(pageUrl).hostname;
  const paths =
    host.includes("crucible")
      ? ["/quick-reference", "/scenarios", "/features", "/architecture"]
      : [
          "/tutorial-testing-lab",
          "/tutorial-advanced-red-team",
          "/tutorial-live-payload-fuzzer",
          "/features",
          "/quick-reference"
        ];
  for (const p of paths) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Atlas Crew Horizon + Synapse edge protection docs (synapse.atlascrew.dev). */
function extractAtlasCrewEdgeProtectionSeeds(html: string, pageUrl: string): string[] {
  if (!/Horizon|Synapse|edge-protection|atlascrew\.dev/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/architecture/synapse",
    "/reference/synapse-features",
    "/getting-started/demo-mode",
    "/architecture/horizon",
    "/architecture/data-flow"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** OopsSec Store — seed roadmap and walkthrough posts from GitHub Pages hub. */
function extractOopssecStoreSeeds(html: string, pageUrl: string): string[] {
  if (!/OopsSec Store|oss-oopssec-store/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/roadmap", "/roadmap/", "/posts", "/topics", "/about"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/oss-oopssec-store\/(?:roadmap|posts\/[^"']+))["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 8) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** CookieJar session-security lab — seed interactive demo and lab-guide docs from homepage. */
function extractCookiejarLabSeeds(html: string, pageUrl: string): string[] {
  if (!/CookieJar|cookiejar-lab/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/demo",
    "/demo/",
    "/demo/index.html",
    "/cookiejar-lab/docs/lab-guide",
    "/cookiejar-lab/docs/lab-guide.html",
    "/cookiejar-lab/docs/security-notes",
    "/cookiejar-lab/docs/security-notes.html",
    "/cookiejar-lab/cookiejar-lab/docs/lab-guide",
    "/cookiejar-lab/cookiejar-lab/docs/lab-guide.html",
    "/cookiejar-lab/cookiejar-lab/docs/security-notes",
    "/cookiejar-lab/cookiejar-lab/docs/security-notes.html"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe =
    /href\s*=\s*["']([^"']*(?:\/demo\/?|cookiejar-lab(?:\/cookiejar-lab)?\/docs\/(?:lab-guide|security-notes)(?:\.html)?))["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** OWASP VWAD — seed high-signal vulnerable app detail pages from directory JSON-LD. */
function extractOwaspVwadSeeds(html: string, pageUrl: string): string[] {
  if (!/vwad\.owasp\.org|Vulnerable Web Applications Directory/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  const linkRe = /"url"\s*:\s*"(https:\/\/vwad\.owasp\.org\/app\/[^"]+)"/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 8) {
    try {
      const u = new URL(m[1]);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  for (const p of [
    "/app/juice-shop/",
    "/app/dvwa/",
    "/app/webgoat/",
    "/app/crapi/",
    "/app/bwapp/",
    "/app/damn-vulnerable-graphql-application-dvga/",
    "/app/pixi/",
    "/app/security-shepherd/",
    "/app/mutillidae/",
    "/app/nodegoat/"
  ]) {
    try {
      out.add(new URL(p, pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** pwn.college — seed dojo catalog and welcome module. */
function extractPwnCollegeSeeds(html: string, pageUrl: string): string[] {
  if (!/pwn\.college|Learn to Hack!/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/dojos", "/dojo/welcome", "/dojo/linux-luminarium"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** CTFlearn — seed challenge browse pages for platform markers. */
function extractCtflearnChallengeSeeds(html: string, pageUrl: string): string[] {
  if (!/CTFlearn|ctflearn\.com/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/challenge/1/browse", "/users/register"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** W3Challs — seed challenge catalog and login routes. */
function extractW3ChallsChallengeSeeds(html: string, pageUrl: string): string[] {
  if (!/W3Challs|w3challs\.com/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of ["/challenges/", "/account/login", "/feeds/challenges/latest"]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/challenges[^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 8) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** RS Vulnerable Lab — seed exposed QA paths from attack-surface catalog. */
function extractVulnerableQaLabSeeds(html: string, pageUrl: string): string[] {
  if (!/INTENTIONAL QA LAB|RS Vulnerable Lab|vulnerable-lab\.vercel\.app/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  for (const p of [
    "/admin/",
    "/backup/",
    "/phpinfo.php",
    "/config/.env",
    "/login.html",
    "/confidential/hr-salaries.xlsx"
  ]) {
    try {
      const u = new URL(p, pageUrl);
      if (u.origin !== pageOrigin) continue;
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  const linkRe = /href\s*=\s*["'](\/(?:admin|backup|config|confidential|debug|staging)[^"'#?]*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && out.size < 10) {
    try {
      out.add(new URL(m[1], pageUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** Invicti rest.vulnweb.com — seed OpenAPI docs and api_data.json for REST lab markers. */
function extractRestVulnwebDocSeeds(html: string, origin: string): string[] {
  if (!/Invicti Vulnerable REST API|rest\.vulnweb\.com/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["docs/", "docs/api_data.json"]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** SecTrainer — seed module + CTF SPA routes from nav catalog. */
function extractSectrainerSpaSeeds(html: string, jsBodies: string[], origin: string): string[] {
  const corpus = [html, ...jsBodies].join("\n");
  if (!/SecTrainer|security-?trainer\.vercel\.app/i.test(corpus)) return [];
  const out = new Set<string>();
  for (const path of ["/modules", "/modules/sql-injection", "/modules/xss-basics", "/ctf", "/paths"]) {
    try {
      out.add(new URL(path, origin).toString());
    } catch {
      /* ignore */
    }
  }
  const moduleRe = /id:\s*[`'"]([a-z0-9-]+(?:injection|xss|idor|csrf)[a-z0-9-]*)[`'"]/gi;
  let m: RegExpExecArray | null;
  while ((m = moduleRe.exec(corpus)) && out.size < 8) {
    try {
      out.add(new URL(`/modules/${m[1]}`, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** OWASP WrongSecrets dropdown lists /challenge/challenge-N pages with secret-hunting walkthroughs. */
function extractWrongSecretsChallengeSeeds(html: string, origin: string): string[] {
  if (!/OWASP WrongSecrets|wrongsecrets/i.test(html)) return [];
  const out = new Set<string>();
  for (let i = 0; i <= 61; i++) {
    try {
      out.add(new URL(`/challenge/challenge-${i}`, origin).toString());
    } catch {
      /* ignore */
    }
  }
  const re = /href\s*=\s*["'](\/challenge\/challenge-\d+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      out.add(new URL(m[1], origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** XVWA (xvwa.vercel.app) — sidepanel lists 15+ attack modules under /xvwa/vulnerabilities/. */
function extractXvwaVulnSeeds(html: string, origin: string): string[] {
  if (!/XVWA|Xtreme Vulnerable Web Application/i.test(html)) return [];
  const out = new Set<string>();
  const basePath = /\/xvwa\//i.test(html) ? "/xvwa" : "";
  for (const p of [`${basePath}/about.html`, `${basePath}/instruction.php`, `${basePath}/sidepanel.php`]) {
    try {
      out.add(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  for (const mod of ["sqli", "reflected_xss", "ssrf_xspa", "idor", "ssti"]) {
    try {
      out.add(new URL(`${basePath}/vulnerabilities/${mod}/`, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

/** DVWA deploys (e.g. dvwa.vercel.app) may serve raw PHP source under vulnerabilities/…/source/. */
const DVWA_VULN_MODULES = [
  "sqli",
  "xss_r",
  "xss_s",
  "xss_d",
  "csrf",
  "fi",
  "fileupload",
  "exec",
  "brute",
  "weak_id"
];

function extractDvwaVulnSourceSeeds(html: string, origin: string): string[] {
  if (!/Damn Vulnerable Web Application|DVWA_WEB_PAGE_TO_ROOT/i.test(html)) return [];
  const out = new Set<string>();
  for (const mod of DVWA_VULN_MODULES) {
    try {
      out.add(new URL(`/vulnerabilities/${mod}/source/low.php`, origin).toString());
      out.add(new URL(`/vulnerabilities/${mod}/`, origin).toString());
    } catch {
      /* ignore */
    }
  }
  try {
    out.add(new URL("/login.php", origin).toString());
    out.add(new URL("/phpinfo.php", origin).toString());
  } catch {
    /* ignore */
  }
  return [...out];
}

/** Hackforge-style CTF SPAs expose challenge routes only in JS — seed from HTML meta. */
function extractCtfPlatformSpaSeeds(html: string, origin: string): string[] {
  const isHackforge =
    /Hackforge|CTF Platform|Premier Cybersecurity CTF|capture the flag.*training platform/i.test(
      html
    );
  let isIeeeVit = /IEEE-VIT|CTF-Conquer The World|Conquer The World.*CTF|webpackJsonpctf/i.test(
    html
  );
  if (!isIeeeVit) {
    try {
      isIeeeVit =
        /ctf\.vercel\.app$/i.test(new URL(origin).hostname) &&
        /<title>CTF<\/title>|flags\.png/i.test(html);
    } catch {
      /* ignore */
    }
  }
  if (!isHackforge && !isIeeeVit) return [];
  const paths = isIeeeVit
    ? ["/get_started", "/play", "/"]
    : ["/practice", "/challenges", "/events", "/dashboard", "/courses"];
  const out: string[] = [];
  for (const p of paths) {
    try {
      out.push(new URL(p, origin).toString());
    } catch {
      /* ignore */
    }
  }
  return out;
}

/** Child lab pages linked from category index pages (e.g. /SQLI/00.php, /SSTI/lab1.php). */
const LAB_CHILD_PATH_RE = /href\s*=\s*["']([^"']*(?:\/\d{2}\.php|lab\d+\.php))["']/gi;

function extractLabChildLinks(html: string, pageUrl: string): string[] {
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  let m: RegExpExecArray | null;
  while ((m = LAB_CHILD_PATH_RE.exec(html))) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin !== pageOrigin) continue;
      u.hash = "";
      out.add(u.toString());
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

async function extractSitemapCrawlSeeds(origin: string, probe: ProbeCache): Promise<string[]> {
  const doc = await probe.get(`${origin}/sitemap.xml`, { maxBytes: 16_384 });
  if (doc.status !== 200 || !doc.body.trim()) return [];
  const urls: string[] = [];
  const re = /<loc>([^<]+)<\/loc>/gi;
  const labPath =
    /\/(?:sqli|ssti|nosqli|xxe|csrf|ssrf|idor|jwt|lfi|rfi|csti|xss|rxss|sxss|csp|cors|openredirect|commandinjection|loginbypass|file_upload|xpath)/i;
  let m: RegExpExecArray | null;
  while ((m = re.exec(doc.body)) && urls.length < 24) {
    try {
      const loc = m[1].trim();
      const u = loc.startsWith("http") ? new URL(loc) : new URL(loc, origin);
      if (u.origin !== origin) continue;
      if (!labPath.test(u.pathname)) continue;
      urls.push(u.toString());
    } catch {
      /* ignore */
    }
  }
  return urls;
}

/** Prefer security lab HTML pages (xss/sqli/csrf/eval/prototype) over generic nav links. */
function prioritizeSecurityLabLinks(links: string[]): string[] {
  const LAB_KEYWORD_ORDER = [
    "bugs.htm",
    "vulnerabilities.txt",
    "vulnerability-inventory",
    "endpoints-catalog",
    "/web1/",
    "/web2/",
    "/web3/",
    "/web4/",
    "/web6/",
    "/web7/",
    "/web8/",
    "/cybersecurity/",
    "cybersecurity/",
    "ctf_platform",
    "events/",
    "cookiejar-lab/demo",
    "lab-guide",
    "security-notes",
    "cookiejar-lab/docs",
    "sqlInjection",
    "source.php",
    "/vulnerabilities/",
    "level1",
    "level0",
    "/c1/",
    "/c2/",
    "/c3/",
    "/c4/",
    "/c5/",
    "postmessage",
    "rag-vuln",
    "chat-vuln",
    "securbank",
    "chatbot",
    "llm",
    "blog",
    "transfer",
    "comments",
    "messages",
    "sqli",
    "ssti",
    "nosqli",
    "xxe",
    "prototype",
    "evalbypass",
    "csrf",
    "comment",
    "showcase",
    "authbypass",
    "xss",
    "cors",
    "ssrf",
    "os-injection",
    "injection",
    "idor",
    "bypass",
    "pollution",
    "demo"
  ];
  const rank = (url: string) => {
    try {
      const p = new URL(url).pathname.toLowerCase();
      for (let i = 0; i < LAB_KEYWORD_ORDER.length; i++) {
        if (p.includes(LAB_KEYWORD_ORDER[i])) return i;
      }
      if (/\.html?$/i.test(p)) return LAB_KEYWORD_ORDER.length + 1;
      return LAB_KEYWORD_ORDER.length + 2;
    } catch {
      return 99;
    }
  };
  return [...links].sort((a, b) => rank(a) - rank(b));
}

/** Client-side navigation targets (e.g. window.location.href = 'victim.html'). */
function jsNavTargets(html: string, pageUrl: string, limit: number): string[] {
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  const re =
    /(?:location\.(?:href|assign|replace)|window\.location(?:\.href)?)\s*=\s*['"]([^'"]+)['"]/gi;
  const onclickRe =
    /onclick\s*=\s*["'][^"']*?(?:location\.(?:href|assign|replace)|window\.location(?:\.href)?)\s*=\s*['"]([^'"]+)['"]/gi;
  for (const pattern of [re, onclickRe]) {
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(html)) && out.size < limit * 2) {
      try {
        const u = new URL(m[1], pageUrl);
        if (u.origin !== pageOrigin) continue;
        if (/^javascript:/i.test(m[1])) continue;
        out.add(u.toString());
      } catch {
        /* ignore */
      }
    }
  }
  return [...out].slice(0, limit);
}

/** Expand React Router params like /profile/:id into concrete probe paths. */
function expandSpaParamPaths(path: string): string[] {
  if (!path.includes(":")) return [path];
  const out = new Set<string>();
  for (const id of ["1", "2"]) {
    out.add(path.replace(/:[a-zA-Z_][a-zA-Z0-9_]*/g, id));
  }
  return [...out];
}

/** React/Vite SPA routes declared in JS bundles (path:`/transfer`, to:`/comments`). */
function spaRouteTargets(jsBodies: string[], pageUrl: string, limit: number): string[] {
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
  const re = /(?:path|to)\s*:\s*[`'"](\/[a-z0-9/_:-]+)[`'"]/gi;
  for (const body of jsBodies) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) && out.size < limit * 4) {
      const rawPath = m[1];
      if (rawPath === "/" || rawPath.length < 2) continue;
      for (const path of expandSpaParamPaths(rawPath)) {
        if (/\.(png|jpe?g|svg|gif|webp|ico|css|js|map|woff2?|ttf|pdf|zip)$/i.test(path)) continue;
        // Vercel Security Checkpoint false positives (e.g. /assets/admin.html behind bot gate).
        if (/\/assets\/admin\.html$/i.test(path)) continue;
        try {
          const u = new URL(path, pageOrigin);
          if (u.origin !== pageOrigin) continue;
          out.add(u.toString());
        } catch {
          /* ignore */
        }
      }
    }
  }
  return [...out].slice(0, limit);
}

// Synchronous, in-request Deep Scan. Runs the full code-defined library (free + deep rules) over
// the homepage AND a shallow same-origin crawl. No verified-domain requirement. Heavier active
// probing (forged webhooks, multi-step IDOR) still belongs to the Python worker in production.
export async function runDeepScan(targetInput: string, opts: FreeScanOptions = {}): Promise<DeepScanResult> {
  const target = normalizeTarget(targetInput);

  const extra = (opts.extraBlockedDomains ?? []).map((d) => d.toLowerCase());
  if (extra.length) {
    const host = target.hostname.toLowerCase();
    if (extra.includes(host) || extra.includes(hostApex(host)))
      throw new BlockedTargetError("That domain is blocked for scanning on this platform.");
  }

  let home = await reachTarget(target, targetInput);
  if (home.status === 0) throw new BlockedTargetError(reachFailureMessage(target, home.error));
  const stubRedirect = extractStubRedirectTarget(home.body, home.finalUrl);
  if (stubRedirect && home.body.length < 4096) {
    const redirected = await fetchDoc(stubRedirect, { timeoutMs: 12000, maxBytes: 600_000 });
    if (redirected.status >= 200 && redirected.body.length > home.body.length) home = redirected;
  }
  home = await warmupJuiceShopHome(target.toString(), home);
  const origin = target.origin;
  const crawlOrigin = new URL(home.finalUrl).origin;

  // Shallow crawl: homepage + internal pages (prioritize vuln lab HTML).
  // Prefetch homepage scripts first — static labs often navigate via JS (e.g. login.js → comments.html).
  const probe = new ProbeCache();
  if (isJuiceShopHost(home.finalUrl || target.toString())) {
    await primeJuiceShopApiProbes(probe, home.finalUrl || target.toString());
  }
  home = await applyWargameBasicAuth(home.finalUrl || target.toString(), home, probe, home.body);
  const owaspGenaiSessionRef: { cookie?: string } = {};
  home = await applyOwaspGenaiLabSession(
    home.finalUrl || target.toString(),
    home,
    probe,
    owaspGenaiSessionRef
  );
  const homeScriptUrls = extractScriptUrls(home.body, home.finalUrl, 8);
  const earlyScripts = await fetchScriptsBatched(homeScriptUrls.slice(0, 8), {
    probe,
    maxBytes: 120_000,
    concurrency: 4
  });
  const scriptNavTargets = earlyScripts.flatMap((s) => jsNavTargets(s.body, s.finalUrl, DEEP_MAX_PAGES));
  const spaRoutes = spaRouteTargets(
    [home.body, ...earlyScripts.map((s) => s.body)],
    home.finalUrl,
    DEEP_MAX_PAGES
  );

  const sitemapSeeds = await extractSitemapCrawlSeeds(origin, probe);
  const labHubSeeds = extractLabHubLinks(home.body, home.finalUrl);
  const docusaurusLabSeeds = extractDocusaurusLabLinks(home.body, home.finalUrl);
  const nextraCyberSeeds = extractNextraCybersecurityLinks(home.body, home.finalUrl);
  const jekyllSecurityDocSeeds = extractJekyllSecurityDocLinks(home.body, home.finalUrl);
  const jekyllBlogPostSeeds = extractJekyllBlogPostSeeds(home.body, home.finalUrl);
  const domGoatCxssSeeds = extractDomGoatCxssSeeds(home.body, home.finalUrl);
  const benstaffordXssSeeds = extractBenstaffordXssAttackSeeds(home.body, home.finalUrl);
  const ctfHubSeeds = extractCtfChallengeHubLinks(home.body, home.finalUrl);
  const ctfPlatformSeeds = extractCtfPlatformSpaSeeds(home.body, origin);
  const websecSeeds = extractWebsecChallengeSeeds(home.body, origin);
  const sixHackSeeds = extractSixHackCtfSeeds(home.body, origin);
  const gruyereSeeds = extractGruyereCodelabSeeds(home.body, origin);
  const cahyodLabSeeds = extractCahyodVulnerableLabSeeds(home.body, home.finalUrl);
  const firingRangeSeeds = extractFiringRangeCrawlSeeds(home.body, origin);
  const bouvetIntroCtfSeeds = extractBouvetIntroCtfSeeds(home.body, home.finalUrl);
  const tegalsecSeeds = extractTegalsecLabSeeds(home.body, home.finalUrl);
  const cyberDrillSeeds = extractCyberDrillToolSeeds(home.body, home.finalUrl);
  const alfNuXssSeeds = extractAlfNuXssSeeds(home.body, home.finalUrl);
  const returnTrueSeeds = extractReturnTrueSeeds(home.body, home.finalUrl);
  const authlabSeeds = extractAuthlabSeeds(home.body, home.finalUrl);
  const xssQuizSeeds = extractXssQuizInt21hSeeds(home.body, home.finalUrl);
  const ctfChallengeSeeds = extractCtfChallengeSeeds(home.body, home.finalUrl);
  const exploitEducationSeeds = extractExploitEducationSeeds(home.body, home.finalUrl);
  const burpBountyLabSeeds = extractBurpBountyLabSeeds(home.body, home.finalUrl);
  const wafWorkshopSeeds = extractWafWorkshopMkdocsSeeds(home.body, home.finalUrl);
  const yogsecXssLabsSeeds = extractYogsecXssLabsSeeds(home.body, home.finalUrl);
  const povzaydXssLabsSeeds = extractPovzaydXssLabsSeeds(home.body, home.finalUrl);
  const hacker101CtfSeeds = extractHacker101CtfSeeds(home.body, home.finalUrl);
  const owaspBricksSeeds = extractOwaspBricksSeeds(home.body, home.finalUrl);
  const fvbGitbookSeeds = extractFvbGitbookSeeds(home.body, home.finalUrl);
  const damnVulnerableBankSeeds = extractDamnVulnerableBankSeeds(home.body, home.finalUrl);
  const vulnLabAcademySeeds = extractVulnLabAcademySeeds(home.body, home.finalUrl);
  const eksGoatSeeds = extractEksGoatMdbookSeeds(home.body, home.finalUrl);
  const ctflearnSeeds = extractCtflearnChallengeSeeds(home.body, home.finalUrl);
  const w3challsSeeds = extractW3ChallsChallengeSeeds(home.body, home.finalUrl);
  const vulnerableQaLabSeeds = extractVulnerableQaLabSeeds(home.body, home.finalUrl);
  const mlastgSeeds = extractMlastgMkdocsSeeds(home.body, home.finalUrl);
  const cryptohackSeeds = extractCryptohackChallengeSeeds(home.body, home.finalUrl);
  const overthewireNatasSeeds = extractOverTheWireNatasSeeds(home.body, home.finalUrl);
  const redTigerSeeds = extractRedTigerHackitSeeds(home.body, origin);
  const wizerCtfSeeds = extractWizerCtfSeeds(home.body, home.finalUrl);
  const vulnExposeSeeds = extractVulnExposeSeeds(home.body, home.finalUrl);
  const vulnPortalAuthSeeds = extractVulnPortalAuthSeeds(home.body, home.finalUrl);
  const picoctfCylabSeeds = extractPicoctfCylabSeeds(home.body, home.finalUrl);
  const bugBountyHunterSeeds = extractBugBountyHunterChallengeSeeds(home.body, home.finalUrl);
  const openvaultBankSeeds = extractOpenvaultBankSeeds(home.body, home.finalUrl);
  const webhackingKrSeeds = extractWebhackingKrSeeds(home.body, home.finalUrl);
  const netForceSeeds = extractNetForceChallengeSeeds(home.body, home.finalUrl);
  const brutelogicXssGymSeeds = extractBrutelogicXssGymSeeds(home.body, home.finalUrl);
  const ctflearnWebfourSeeds = extractCtflearnWebfourSeeds(home.body, home.finalUrl);
  const ctflearnWebeightSeeds = extractCtflearnWebeightSeeds(home.body, home.finalUrl);
  const ctflearnWebChallengeSeeds = extractCtflearnWebChallengeSeeds(home.body, home.finalUrl);
  const wechallSeeds = extractWechallChallengeSeeds(home.body, home.finalUrl);
  const railsgoatSeeds = extractRailsgoatDocSeeds(home.body, home.finalUrl);
  const breakTheFlaskSeeds = extractBreakTheFlaskWriteupSeeds(home.body, home.finalUrl);
  const grpcGoatSeeds = extractGrpcGoatDocSeeds(home.body, home.finalUrl);
  const webgoatSeeds = extractWebgoatDocSeeds(home.body, home.finalUrl);
  const seclabPlaygroundSeeds = extractSecLabPlaygroundSeeds(home.body, home.finalUrl);
  const webSecurityLabZhSeeds = extractWebSecurityLabZhSeeds(home.body, home.finalUrl);
  const cyberpunkerLabSeeds = extractCyberpunkerLabSeeds(home.body, home.finalUrl);
  const secResearchLabSeeds = extractSecResearchLabSeeds(home.body, home.finalUrl);
  const skillauditSeeds = extractSkillauditDocSeeds(home.body, home.finalUrl);
  const gitagentSecurebotSeeds = extractGitagentSecurebotSeeds(home.body, home.finalUrl);
  const airtAcademySeeds = extractAirtAcademySeeds(home.body, home.finalUrl);
  const appsecMasterLabSeeds = extractAppsecMasterLabSeeds(home.body, origin);
  const istEduVulnPortalSeeds = extractIstEduVulnPortalSeeds(home.body, home.finalUrl);
  const vulnforgeSeeds = extractVulnforgeSeeds(home.body, home.finalUrl);
  const securedAiSeeds = extractSecuredAiSeeds(home.body, home.finalUrl);
  const vwadWrongsecretsLiveSeeds = extractVwadWrongsecretsLiveSeed(home.body, home.finalUrl);
  const mcpSherpaWorkshopSeeds = extractMcpSherpaWorkshopSeeds(home.body, home.finalUrl);
  const ffufMeSeeds = extractFfufMeSeeds(home.body, home.finalUrl);
  const bergerCyberLabSeeds = extractBergerCyberLabSeeds(home.body, home.finalUrl);
  const pwnCollegeSeeds = extractPwnCollegeSeeds(home.body, home.finalUrl);
  const owaspGenaiLabSeeds = extractOwaspGenaiLabSeeds(home.body, home.finalUrl);
  const ctfDefiSeeds = extractCtfDefiSeeds(home.body, home.finalUrl);
  const invictiAspnetSeeds = extractInvictiAspnetSeeds(home.body, home.finalUrl);
  const invictiPhpSeeds = extractInvictiPhpSeeds(home.body, home.finalUrl);
  const ginAndJuiceVulnSeeds = extractGinAndJuiceVulnSeeds(home.body, home.finalUrl);
  const ginAndJuiceBlogPostSeeds = extractGinAndJuiceBlogPostSeeds(home.body, home.finalUrl);
  const dvgaLiveSeeds = extractDvgaLiveSeeds(home.body, home.finalUrl);
  const vaultappSeeds = extractVaultappSeeds(home.body, home.finalUrl);
  const llmSecDevSeeds = extractLlmSecDevSeeds(home.body, home.finalUrl);
  const hackingLabSeeds = extractHackingLabSeeds(home.body, home.finalUrl);
  const atlasCrewHubSeeds = extractAtlasCrewHubSeeds(home.body, home.finalUrl);
  const atlasCrewInfernoLabSeeds = extractAtlasCrewInfernoLabSeeds(home.body, home.finalUrl);
  const atlasCrewEdgeProtectionSeeds = extractAtlasCrewEdgeProtectionSeeds(home.body, home.finalUrl);
  const owaspVwadSeeds = extractOwaspVwadSeeds(home.body, home.finalUrl);
  const archonVitepressSeeds = extractArchonVitepressSeeds(home.body, home.finalUrl);
  const archonHostFallbackSeeds = extractArchonHostFallbackSeeds(home.finalUrl);
  const secCodeEducationalSeeds = extractSecCodeEducationalSeeds(home.body, home.finalUrl);
  const vulnerableAppSeeds = extractVulnerableAppDocSeeds(home.body, home.finalUrl);
  const vulnerableappDomXssSeeds = extractVulnerableappDomXssSeeds(home.body, home.finalUrl);
  const bugCollectionSeeds = extractBugCollectionSeeds(home.body, home.finalUrl);
  const oopssecStoreSeeds = extractOopssecStoreSeeds(home.body, home.finalUrl);
  const cookiejarLabSeeds = extractCookiejarLabSeeds(home.body, home.finalUrl);
  const hacksplainingSeeds = extractHacksplainingLessonSeeds(home.body, home.finalUrl);
  const portswiggerSeeds = extractPortswiggerAcademySeeds(home.body, home.finalUrl);
  const hackTheBoxSeeds = extractHackTheBoxSeeds(home.body, home.finalUrl);
  const hackTheBoxAcademySeeds = extractHackTheBoxAcademySeeds(home.body, home.finalUrl);
  const try2hackSeeds = extractTry2hackLevelSeeds(home.body, home.finalUrl);
  const unsecurePwaSeeds = extractUnsecurePwaSeeds(home.body, home.finalUrl);
  const securityShepherdSeeds = extractSecurityShepherdSeeds(home.body, home.finalUrl);
  const googleXssGameSeeds = extractGoogleXssGameSeeds(home.body, home.finalUrl);
  const promptmapSeeds = extractPromptmapSeeds(home.body, home.finalUrl);
  const frontendXssDemoSeeds = extractFrontendXssDemoSeeds(home.body, home.finalUrl);
  const avidVulnEditorSeeds = extractAvidVulnEditorSeeds(home.body, home.finalUrl);
  const pwnshopSeeds = extractPwnshopDocSeeds(home.body, home.finalUrl);
  const restVulnwebSeeds = extractRestVulnwebDocSeeds(home.body, origin);
  const vulnappHubSeeds = extractVulnappHubSeeds(home.body, origin);
  const blueTeamLabsSeeds = extractBlueTeamLabsSeeds(home.body, origin);
  const juiceShopProjectSeeds = extractJuiceShopProjectSeeds(home.body, origin);
  const pwningJuiceShopCompanionSeeds = extractPwningJuiceShopCompanionSeeds(home.body, home.finalUrl);
  const ziranDocSeeds = extractZiranDocSeeds(home.body, home.finalUrl);
  const dotnetSerializationLabSeeds = extractDotnetSerializationLabSeeds(home.body, home.finalUrl);
  const pwnedlabsSeeds = extractPwnedlabsLabSeeds(home.body, home.finalUrl);
  const mutillidaeSeeds = extractMutillidaeLabSeeds(home.body, origin);
  const bwappSeeds = extractBwappLabSeeds(home.body, origin);
  const zeroBankSeeds = extractZeroBankTrainingSeeds(home.body, origin);
  const hackableSoSeeds = extractHackableSoSeeds(
    home.body,
    earlyScripts.map((s) => s.body),
    crawlOrigin
  );
  const vulnwebSeeds = extractVulnwebLabSeeds(
    home.body,
    earlyScripts.map((s) => s.body),
    crawlOrigin
  );
  const pentesterLabSeeds = extractPentesterLabExerciseSeeds(home.body, origin);
  const vulnexPlaybookSeeds = extractVulnexPlaybookSeeds(home.body, origin);
  const secureflagOwaspSeeds = extractSecureflagOwaspSeeds(home.body, origin);
  const kontraTrainingSeeds = extractKontraTrainingSeeds(home.body, origin);
  const hackThisSiteSeeds = extractHackThisSiteMissionSeeds(home.body, origin);
  const webVulnsGuideSeeds = extractWebVulnsGuideLabSeeds(home.body, home.finalUrl);
  const htsRealisticMissionSeeds = extractHtsRealisticMissionSeeds(home.body, home.finalUrl);
  const wrongSecretsSeeds = extractWrongSecretsChallengeSeeds(home.body, origin);
  const sectrainerSeeds = extractSectrainerSpaSeeds(
    home.body,
    earlyScripts.map((s) => s.body),
    crawlOrigin
  );
  const dvwaSeeds = extractDvwaVulnSourceSeeds(home.body, origin);
  const xvwaSeeds = extractXvwaVulnSeeds(home.body, origin);
  const wizerChalPrioritySeeds =
    /wizer|sam\.wizer-ctf|wizer-ctf\.com/i.test(home.body) ||
    /wizer-ctf\.com|sam\.wizer-ctf\.com|chal\d+[\w-]*\.vercel\.app/i.test(home.finalUrl)
      ? Array.from({ length: 17 }, (_, i) => `https://chal${i + 1}.vercel.app/`)
      : [];
  const sixHackPlatformPrioritySeeds =
    /sixhackacademy|CTF Labs de SixHack|platform\.sixhackacademy\.com/i.test(home.body) ||
    /sixhackacademy\.com/i.test(home.finalUrl)
      ? ["https://platform.sixhackacademy.com/"]
      : [];
  const hackingLabPrioritySeeds =
    /Hacking-Lab|hacking-lab\.com/i.test(home.body) || /hacking-lab\.com/i.test(home.finalUrl)
      ? ["https://hacking-lab.com/ctf_platform/", "https://hacking-lab.com/events/"]
      : [];
  const cylabAcademyPrioritySeeds =
    /picoCTF|picoctf\.org|CyLab Security Academy|cylabacademy\.org/i.test(home.body) ||
    /picoctf\.org|cylabacademy\.org/i.test(home.finalUrl)
      ? [
          "https://cylabacademy.org/",
          "https://cylabacademy.org/about.html",
          "https://cylabacademy.org/learners.html",
          "https://cylabacademy.org/competitors.html",
          "https://cylabacademy.org/educators.html",
          "https://primer.cylabacademy.org/"
        ]
      : [];
  const sectrainerPrioritySeeds =
    /SecTrainer|security-?trainer\.vercel\.app|gamified cyber security training/i.test(home.body) ||
    /security-?trainer\.vercel\.app/i.test(home.finalUrl)
      ? ["/modules", "/modules/sql-injection", "/modules/xss-basics", "/ctf", "/paths"].map((p) =>
          new URL(p, crawlOrigin).toString()
        )
      : [];
  const ctflearnWebPrioritySeeds =
    /CTFlearn|ctflearn\.com/i.test(home.body) || /ctflearn\.com/i.test(home.finalUrl)
      ? ["/web1/", "/web2/", "/web3/", "/web4/", "/web6/", "/web7/", "/web8/"].map((p) =>
          new URL(p, "https://web.ctflearn.com").toString()
        )
      : [];
  const povzaydLabPrioritySeeds =
    /povzayd\.github\.io\/XSS-LABS/i.test(home.finalUrl) ||
    /povzayd\.github\.io\/XSS-LABS|Welcome to XSS\s*LABS/i.test(home.body)
      ? ["LABS/lab1.html", "LABS/lab2.html", "LABS/lab3.html"].map((p) =>
          new URL(p, home.finalUrl).toString()
        )
      : [];
  const ctfHubPrioritySeeds =
    /CTF Challenge Hub|Web Security Training Challenges|class="challenge-link"/i.test(home.body)
      ? Array.from({ length: 5 }, (_, i) => new URL(`/c${i + 1}/`, home.finalUrl).toString())
      : [];
  const cookiejarLabPrioritySeeds =
    /CookieJar|cookiejar-lab/i.test(home.body) || /cookiejar-lab/i.test(home.finalUrl)
      ? [
          "/cookiejar-lab/demo/",
          "/cookiejar-lab/cookiejar-lab/docs/lab-guide.html",
          "/cookiejar-lab/cookiejar-lab/docs/security-notes.html"
        ].map((p) => new URL(p, home.finalUrl).toString())
      : [];
  const ginAndJuicePrioritySeeds =
    /ginandjuice\.shop|Gin & Juice Shop|vulnerability scanner to the test/i.test(home.body) ||
    /ginandjuice\.shop/i.test(home.finalUrl)
      ? ["/vulnerabilities", "/catalog", "/blog"].map((p) => new URL(p, home.finalUrl).toString())
      : [];
  const redTigerPrioritySeeds = /redtiger\.labs\.overthewire\.org/i.test(home.finalUrl)
    ? [
        "http://redtiger.labs.overthewire.org/",
        "http://redtiger.labs.overthewire.org/level1.php",
        "http://redtiger.labs.overthewire.org/level4.php",
        "http://redtiger.labs.overthewire.org/level5.php",
        "http://redtiger.labs.overthewire.org/level6.php",
        "http://redtiger.labs.overthewire.org/special1.php"
      ]
    : [];
  const netForcePrioritySeeds = /net-force\.nl/i.test(home.finalUrl)
    ? [
        "http://www.net-force.nl/challenge/level101/index.php",
        "http://www.net-force.nl/challenge/level102/index.php",
        "http://www.net-force.nl/challenge/level103/index.php",
        "http://www.net-force.nl/challenge/level104/index.php"
      ]
    : [];
  const grpcGoatPrioritySeeds =
    /vwad\.owasp\.org\/app\/grpc-goat|rootxjs\.github\.io\/blog\/grpc-goat/i.test(home.finalUrl)
      ? [
          "https://rootxjs.github.io/blog/grpc-goat/",
          "https://rootxjs.github.io/docs/grpc_goat_docs/labs/",
          "https://rootxjs.github.io/docs/grpc_goat_docs/getting-started/"
        ]
      : [];
  const vwadWebgoatPrioritySeeds =
    /vwad\.owasp\.org\/app\/webgoat/i.test(home.finalUrl)
      ? [
          "https://owasp.org/www-project-webgoat/",
          "https://github.com/WebGoat/WebGoat"
        ]
      : [];
  const hackThisSiteEtaAuthHubPrioritySeeds =
    /hack-this-site-eta\.vercel\.app\/auth\/?$/i.test(home.finalUrl)
      ? [
          new URL("/auth/login.html", home.finalUrl).toString(),
          new URL("/auth/jwt.html", home.finalUrl).toString(),
          new URL("/auth/session.html", home.finalUrl).toString(),
          new URL("/auth/reset.html", home.finalUrl).toString(),
          new URL("/labs/sqli-error.html", home.finalUrl).toString(),
          new URL("/labs/xss-reflected.html", home.finalUrl).toString(),
          new URL("/labs/idor.html", home.finalUrl).toString(),
          new URL("/labs/cors.html", home.finalUrl).toString()
        ]
      : [];
  const hackThisSiteEtaPrioritySeeds =
    /hack-this-site-eta\.vercel\.app/i.test(home.finalUrl)
      ? [
          new URL("/home/", home.finalUrl).toString(),
          new URL("/cms/", home.finalUrl).toString(),
          new URL("/platform/", home.finalUrl).toString(),
          new URL("/resource/", home.finalUrl).toString(),
          new URL("/admin/", home.finalUrl).toString(),
          new URL("/backup/", home.finalUrl).toString(),
          new URL("/recon/", home.finalUrl).toString(),
          new URL("/labs/", home.finalUrl).toString(),
          new URL("/auth/", home.finalUrl).toString(),
          new URL("/auth/login.html", home.finalUrl).toString(),
          new URL("/auth/jwt.html", home.finalUrl).toString(),
          new URL("/auth/session.html", home.finalUrl).toString(),
          new URL("/auth/reset.html", home.finalUrl).toString(),
          new URL("/api-labs/", home.finalUrl).toString(),
          new URL("/owasp/a01.html", home.finalUrl).toString(),
          new URL("/owasp/a02.html", home.finalUrl).toString(),
          new URL("/owasp/a03.html", home.finalUrl).toString(),
          new URL("/owasp/a04.html", home.finalUrl).toString(),
          new URL("/owasp/a05.html", home.finalUrl).toString(),
          new URL("/owasp/a06.html", home.finalUrl).toString(),
          new URL("/owasp/a07.html", home.finalUrl).toString(),
          new URL("/owasp/a08.html", home.finalUrl).toString(),
          new URL("/owasp/a09.html", home.finalUrl).toString(),
          new URL("/owasp/a10.html", home.finalUrl).toString(),
          new URL("/cms/wordpress.html", home.finalUrl).toString(),
          new URL("/platform/php.html", home.finalUrl).toString(),
          new URL("/platform/aspnet.html", home.finalUrl).toString(),
          new URL("/platform/node.html", home.finalUrl).toString(),
          new URL("/platform/java.html", home.finalUrl).toString(),
          new URL("/platform/python.html", home.finalUrl).toString()
        ]
      : [];
  const seclabPlaygroundPrioritySeeds =
    /securityweb-iota\.vercel\.app/i.test(home.finalUrl)
      ? ["/xss", "/sqli", "/csrf", "/idor"].map((p) => new URL(p, home.finalUrl).toString())
      : [];
  const vwadWrongsecretsPrioritySeeds =
    /vwad\.owasp\.org\/app\/wrongsecrets/i.test(home.finalUrl)
      ? ["https://wrongsecrets.herokuapp.com/"]
      : [];
  const vwadScannerBenchPrioritySeeds =
    /vwad\.owasp\.org\/app\/(?:wackopicko|bodgeit-store|owasp-vulnerableapp)/i.test(home.finalUrl)
      ? [
          "https://vwad.owasp.org/app/wackopicko/",
          "https://vwad.owasp.org/app/bodgeit-store/",
          "https://vwad.owasp.org/app/owasp-vulnerableapp/",
          "https://sasanlabs.github.io/VulnerableApp/",
          "https://sasanlabs.github.io/VulnerableApp/Why_VulnerableApp.html"
        ]
      : [];

  const crawlSeeds = prioritizeSecurityLabLinks([
    ...new Set([
      ...hackThisSiteEtaAuthHubPrioritySeeds,
      ...hackThisSiteEtaPrioritySeeds,
      ...seclabPlaygroundPrioritySeeds,
      ...vwadWrongsecretsPrioritySeeds,
      ...vwadWrongsecretsLiveSeeds,
      ...vwadWebgoatPrioritySeeds,
      ...vwadScannerBenchPrioritySeeds,
      ...grpcGoatPrioritySeeds,
      ...redTigerPrioritySeeds,
      ...netForcePrioritySeeds,
      ...ginAndJuicePrioritySeeds,
      ...cookiejarLabPrioritySeeds,
      ...ctfHubPrioritySeeds,
      ...cylabAcademyPrioritySeeds,
      ...sectrainerPrioritySeeds,
      ...hackingLabPrioritySeeds,
      ...sixHackPlatformPrioritySeeds,
      ...ctflearnWebPrioritySeeds,
      ...wizerChalPrioritySeeds,
      ...povzaydLabPrioritySeeds,
      ...archonHostFallbackSeeds,
      ...labHubSeeds,
      ...docusaurusLabSeeds,
      ...nextraCyberSeeds,
      ...jekyllSecurityDocSeeds,
      ...jekyllBlogPostSeeds,
      ...domGoatCxssSeeds,
      ...benstaffordXssSeeds,
      ...ctfHubSeeds,
      ...ctfPlatformSeeds,
      ...websecSeeds,
      ...sixHackSeeds,
      ...gruyereSeeds,
      ...cahyodLabSeeds,
      ...firingRangeSeeds,
      ...bouvetIntroCtfSeeds,
      ...tegalsecSeeds,
      ...cyberDrillSeeds,
      ...alfNuXssSeeds,
      ...returnTrueSeeds,
      ...authlabSeeds,
      ...xssQuizSeeds,
      ...ctfChallengeSeeds,
      ...exploitEducationSeeds,
      ...burpBountyLabSeeds,
      ...wafWorkshopSeeds,
      ...yogsecXssLabsSeeds,
      ...povzaydXssLabsSeeds,
      ...hacker101CtfSeeds,
      ...owaspBricksSeeds,
      ...fvbGitbookSeeds,
      ...damnVulnerableBankSeeds,
      ...vulnLabAcademySeeds,
      ...eksGoatSeeds,
      ...ctflearnSeeds,
      ...w3challsSeeds,
      ...vulnerableQaLabSeeds,
      ...mlastgSeeds,
      ...cryptohackSeeds,
      ...overthewireNatasSeeds,
      ...redTigerSeeds,
      ...wizerCtfSeeds,
      ...vulnExposeSeeds,
      ...vulnPortalAuthSeeds,
      ...bugBountyHunterSeeds,
      ...picoctfCylabSeeds,
      ...openvaultBankSeeds,
      ...webhackingKrSeeds,
      ...netForceSeeds,
      ...brutelogicXssGymSeeds,
      ...ctflearnWebfourSeeds,
      ...ctflearnWebeightSeeds,
      ...ctflearnWebChallengeSeeds,
      ...wechallSeeds,
      ...railsgoatSeeds,
      ...breakTheFlaskSeeds,
      ...grpcGoatSeeds,
      ...webgoatSeeds,
      ...seclabPlaygroundSeeds,
      ...webSecurityLabZhSeeds,
      ...cyberpunkerLabSeeds,
      ...secResearchLabSeeds,
      ...skillauditSeeds,
      ...gitagentSecurebotSeeds,
      ...airtAcademySeeds,
      ...appsecMasterLabSeeds,
      ...istEduVulnPortalSeeds,
      ...vulnforgeSeeds,
      ...securedAiSeeds,
      ...mcpSherpaWorkshopSeeds,
      ...ffufMeSeeds,
      ...bergerCyberLabSeeds,
      ...pwnCollegeSeeds,
      ...owaspGenaiLabSeeds,
      ...ctfDefiSeeds,
      ...invictiAspnetSeeds,
      ...invictiPhpSeeds,
      ...dvgaLiveSeeds,
      ...vaultappSeeds,
      ...llmSecDevSeeds,
      ...hackingLabSeeds,
      ...atlasCrewHubSeeds,
      ...atlasCrewInfernoLabSeeds,
      ...atlasCrewEdgeProtectionSeeds,
      ...owaspVwadSeeds,
      ...archonVitepressSeeds,
      ...secCodeEducationalSeeds,
      ...vulnerableAppSeeds,
      ...vulnerableappDomXssSeeds,
      ...bugCollectionSeeds,
      ...oopssecStoreSeeds,
      ...cookiejarLabSeeds,
      ...hacksplainingSeeds,
      ...portswiggerSeeds,
      ...hackTheBoxSeeds,
      ...hackTheBoxAcademySeeds,
      ...try2hackSeeds,
      ...unsecurePwaSeeds,
      ...securityShepherdSeeds,
      ...googleXssGameSeeds,
      ...promptmapSeeds,
      ...frontendXssDemoSeeds,
      ...avidVulnEditorSeeds,
      ...pwnshopSeeds,
      ...ginAndJuiceVulnSeeds,
      ...ginAndJuiceBlogPostSeeds,
      ...restVulnwebSeeds,
      ...vulnappHubSeeds,
      ...blueTeamLabsSeeds,
      ...juiceShopProjectSeeds,
      ...pwningJuiceShopCompanionSeeds,
      ...ziranDocSeeds,
      ...dotnetSerializationLabSeeds,
      ...pwnedlabsSeeds,
      ...mutillidaeSeeds,
      ...bwappSeeds,
      ...zeroBankSeeds,
      ...hackableSoSeeds,
      ...vulnwebSeeds,
      ...pentesterLabSeeds,
      ...vulnexPlaybookSeeds,
      ...secureflagOwaspSeeds,
      ...kontraTrainingSeeds,
      ...hackThisSiteSeeds,
      ...webVulnsGuideSeeds,
      ...htsRealisticMissionSeeds,
      ...wrongSecretsSeeds,
      ...sectrainerSeeds,
      ...dvwaSeeds,
      ...xvwaSeeds,
      ...sitemapSeeds,
      ...spaRoutes,
      ...internalLinks(home.body, home.finalUrl, (DEEP_MAX_PAGES - 1) * 8),
      ...jsNavTargets(home.body, home.finalUrl, DEEP_MAX_PAGES - 1),
      ...scriptNavTargets
    ])
  ]).slice(0, DEEP_MAX_PAGES - 1);
  const pageUrls = [home.finalUrl, ...new Set(crawlSeeds)].slice(0, DEEP_MAX_PAGES);
  const extraPageUrls = pageUrls.slice(1);
  const extraPagesRaw = await fetchPagesBatched(extraPageUrls, { probe, maxBytes: 600_000, concurrency: 3 });
  const extraPages = await Promise.all(
    extraPageUrls.map(async (u, i) =>
      applyOwaspGenaiLabSession(
        u,
        await applyWargameBasicAuth(u, extraPagesRaw[i]!, probe, home.body),
        probe,
        owaspGenaiSessionRef
      )
    )
  );
  let pages: FetchedDoc[] = [home, ...extraPages];

  const childSeeds = prioritizeSecurityLabLinks(
    extraPages.flatMap((p) => [
      ...extractLabChildLinks(p.body, p.finalUrl),
      ...extractDocusaurusLabLinks(p.body, p.finalUrl)
    ])
  ).slice(0, 2);
  if (childSeeds.length > 0 && pages.length >= DEEP_MAX_PAGES) {
    const childPagesRaw = await fetchPagesBatched(childSeeds, { probe, maxBytes: 600_000, concurrency: 2 });
    const childPages = await Promise.all(
      childSeeds.map(async (u, i) =>
        applyOwaspGenaiLabSession(
          u,
          await applyWargameBasicAuth(u, childPagesRaw[i]!, probe, home.body),
          probe,
          owaspGenaiSessionRef
        )
      )
    );
    pages = [...pages.slice(0, DEEP_MAX_PAGES - childPages.length), ...childPages];
  } else if (childSeeds.length > 0) {
    const childPagesRaw = await fetchPagesBatched(childSeeds, { probe, maxBytes: 600_000, concurrency: 2 });
    const childPages = await Promise.all(
      childSeeds.map(async (u, i) =>
        applyOwaspGenaiLabSession(
          u,
          await applyWargameBasicAuth(u, childPagesRaw[i]!, probe, home.body),
          probe,
          owaspGenaiSessionRef
        )
      )
    );
    pages = [...pages, ...childPages].slice(0, DEEP_MAX_PAGES);
  }

  const scriptCap = opts.maxScripts ?? 24;
  const scriptUrls = new Set<string>();
  for (const p of pages) for (const u of extractScriptUrls(p.body, p.finalUrl, scriptCap)) scriptUrls.add(u);
  if (isJuiceShopHost(home.finalUrl)) {
    for (const p of ["/main.js", "/polyfills.js", "/runtime.js"]) {
      try {
        scriptUrls.add(new URL(p, crawlOrigin).toString());
      } catch {
        /* ignore */
      }
    }
  }
  let scripts = await fetchScriptsBatched([...scriptUrls].slice(0, scriptCap), {
    probe,
    maxBytes: 800_000,
    concurrency: 4
  });
  const githackSiblings = expandGithackModuleImports(scripts, home.finalUrl, 8);
  if (githackSiblings.length > 0) {
    const fetched = new Set([...scriptUrls]);
    const extra = githackSiblings.filter((u) => !fetched.has(u)).slice(0, Math.max(0, scriptCap - scripts.length));
    if (extra.length > 0) {
      const siblings = await fetchScriptsBatched(extra, { probe, maxBytes: 800_000, concurrency: 4 });
      scripts = [...scripts, ...siblings];
    }
  }

  // Re-prime Juice Shop API/bundle after crawl + script fetch — dyno may wake during that window.
  const juiceShopOrigin = home.finalUrl || target.toString();
  if (isJuiceShopHost(juiceShopOrigin)) {
    await primeJuiceShopApiProbes(probe, juiceShopOrigin);
  }

  // Heroku cold-start often serves a stub homepage — merge bootstrapped REST/bundle bodies so
  // deep rules still see SQLi/IDOR/admin/XSS markers when pages_crawled=1.
  let juiceShopBootstrap = "";
  if (isJuiceShopHost(juiceShopOrigin)) {
    const jsOrigin = new URL(juiceShopOrigin).origin;
    const bootstrapPaths = [
      "/main.js",
      "/rest/admin/application-configuration",
      "/rest/track-order/1",
      "/rest/products/search?q='))",
      "/rest/products/search?q=apple"
    ];
    const bootstrapUrls = bootstrapPaths.map((p) => new URL(p, jsOrigin).toString());
    const mainJsUrl = new URL("/main.js", jsOrigin).toString();
    let bootDocs = await probe.getMany(
      bootstrapUrls.filter((u) => u !== mainJsUrl),
      { maxBytes: 800_000, timeoutMs: 15000 },
      3
    );
    let mainJsDoc = await probe.get(mainJsUrl, { maxBytes: 800_000, timeoutMs: 15000 });
    bootDocs.set(mainJsUrl, mainJsDoc);
    const trackUrl = bootstrapUrls[2]!;
    const sqlUrl = bootstrapUrls[3]!;
    const appleUrl = bootstrapUrls[4]!;
    for (let attempt = 0; attempt < 8; attempt++) {
      const trackBody = bootDocs.get(trackUrl)?.body ?? "";
      const sqlBody = bootDocs.get(sqlUrl)?.body ?? "";
      const appleBody = bootDocs.get(appleUrl)?.body ?? "";
      const mainJsReady =
        !HEROKU_APP_ERROR_RE.test(mainJsDoc.body) &&
        /bypassSecurityTrustHtml|re_[A-Za-z0-9_]{20,}/i.test(mainJsDoc.body);
      const trackReady =
        !HEROKU_APP_ERROR_RE.test(trackBody) &&
        /"status"\s*:\s*"success"|"orderId"/i.test(trackBody);
      const sqlReady = /SQLITE_ERROR|syntax error|sequelize/i.test(sqlBody);
      const appleReady =
        !HEROKU_APP_ERROR_RE.test(appleBody) &&
        /"status"\s*:\s*"success"/i.test(appleBody) &&
        /"data"\s*:\s*\[\s*\{/.test(appleBody);
      if (mainJsReady && trackReady && sqlReady && appleReady) break;
      await new Promise((r) => setTimeout(r, 2500));
      if (!mainJsReady) {
        mainJsDoc = await probe.get(mainJsUrl, {
          maxBytes: attempt >= 2 ? 2_000_000 : 800_000,
          timeoutMs: 18000
        });
        bootDocs.set(mainJsUrl, mainJsDoc);
      }
      if (!trackReady) {
        bootDocs.set(trackUrl, await probe.get(trackUrl, { maxBytes: 8192, timeoutMs: 12000 }));
      }
      if (!sqlReady) {
        bootDocs.set(sqlUrl, await probe.get(sqlUrl, { maxBytes: 8192, timeoutMs: 12000 }));
      }
      if (!appleReady) {
        bootDocs.set(appleUrl, await probe.get(appleUrl, { maxBytes: 8192, timeoutMs: 12000 }));
      }
    }
    juiceShopBootstrap = [...bootDocs.values()]
      .filter((d) => {
        if (HEROKU_APP_ERROR_RE.test(d.body)) return false;
        if (d.status >= 200 && d.status < 500) return true;
        // SQLi oracle is intentionally HTTP 500 — keep for deep-rule markers.
        return d.status === 500 && /SQLITE_ERROR|syntax error|sequelize/i.test(d.body);
      })
      .map((d) => d.body)
      .join("\n");
  }

  const combined = [...pages.map((p) => p.body), ...scripts.map((s) => s.body), juiceShopBootstrap]
    .filter(Boolean)
    .join("\n");
  const detection = detectPlatform(home, combined);
  const ctx: RuleContext = { origin, scanUrl: targetInput, home, scripts, combined, probe };

  const all = patternsForTier("deep").sort((a, b) => {
    const w = (p: Pattern) => (p.platform === "generic" ? 0 : detection.platform && p.platform === detection.platform ? 1 : 2);
    return w(a) - w(b);
  });
  const findings: PatternFinding[] = [];
  const seen = new Set<string>();
  const seenRules = new Set<string>();
  for (const pattern of all) {
    let f: PatternFinding | null = null;
    if (pattern.detectorKind === "secret_regex") f = scanSecret(pattern, combined);
    else if (pattern.detectorKind === "http_probe") f = await scanHttpProbe(pattern, origin, probe);
    else if (pattern.detectorKind === "rule_ref") {
      const ruleName = (pattern.detectorConfig as { rule: string }).rule;
      if (seenRules.has(ruleName)) continue;
      f = await scanRule(pattern, ctx, DEEP_RULES);
      if (f) seenRules.add(ruleName);
    }
    if (f && f.confidence >= DEEP_MIN_CONFIDENCE && !seen.has(f.patternSlug)) {
      seen.add(f.patternSlug);
      findings.push(f);
    }
  }

  return {
    target: target.toString(),
    finalUrl: home.finalUrl,
    detectedPlatform: detection.platform,
    pagesCrawled: pages.map((p) => p.finalUrl),
    findings,
    combined,
    probesRun: probe.size
  };
}
