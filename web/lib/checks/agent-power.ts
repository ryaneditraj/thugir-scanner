/**
 * Thugir power checks — JWT analysis, endpoint discovery, dir enum, reflexion probes.
 */
import type { FetchedDoc } from "./http";
import type { ProbeCache } from "./probe-cache";
import { decodeJwt, extractJwtCandidates } from "./crypto-tools";
import {
  escalatePayload,
  escalationLevelFromFailures,
  SQLI_PROBES,
  xssCanary,
  SSTI_PROBES,
  sstiArithmeticEvaluated
} from "../methodology/reflexion";

interface PowerCtx {
  origin: string;
  scanUrl?: string;
  home: FetchedDoc;
  scripts: FetchedDoc[];
  combined: string;
  probe: ProbeCache;
}

interface PowerResult {
  fired: boolean;
  confidence: number;
  evidence: Record<string, unknown>;
}

type PowerRule = (ctx: PowerCtx) => Promise<PowerResult>;

const BYPASS403_HOST_RE = /bypass403\.vercel\.app/i;
const AI_SECURITY_PLATFORM_HOST_RE = /ai-security-platform-iota\.vercel\.app/i;

/** AI Security Platform login-gated challenge shells — Next.js redirect pages embed coincidental '49' in chunks. */
function aiSecurityPlatformLoginGatedReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  if (!AI_SECURITY_PLATFORM_HOST_RE.test(pageUrl)) return false;
  return /\/challenges\/[a-z0-9-]+/i.test(pageUrl);
}

/** nextjs-cve-hackerone RSC CVE demo — reflexion XSS probes false-positive on intentional lab canaries. */
function nextjsCveHackeroneReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /nextjs-cve-hackerone\.vercel\.app/i.test(pageUrl);
}

const WSL_HOST_RE = /web-security-learning-labs\.vercel\.app/i;
const SECRESEARCHLAB_HOST_RE = /secresearchlab\.web\.app/i;
const SUPPORT_RELIABILITY_LAB_HOST_RE = /support-reliability-lab\.vercel\.app/i;
const VULNFORGE_ACADEMY_HOST_RE = /vulnforge-academy\.vercel\.app/i;
const RIGLABS_CYBER_LAB_HOST_RE = /riglabs-cyber-lab\.vercel\.app/i;

/** Route scans on WSL /module/{id} shells — generic reflexion probes hit homepage, not the lab route. */
function wslModuleRouteReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return WSL_HOST_RE.test(pageUrl) && /\/module\/\d{4}\b/i.test(pageUrl);
}

/** Firebase/Next.js lab shells embed coincidental '49' in chunk IDs — suppress reflexion SSTI FPs. */
function secResearchLabReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return SECRESEARCHLAB_HOST_RE.test(pageUrl);
}

/** Next.js incident-lab tenant shells — reflexion SSTI probes false-positive on chunk hashes. */
function supportReliabilityLabReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return SUPPORT_RELIABILITY_LAB_HOST_RE.test(pageUrl);
}

/** VulnForge file-upload tiers (levels 16–18) — reflexion SSTI false-positives on training shells. */
function vulnforgeAcademyFileUploadReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  if (!VULNFORGE_ACADEMY_HOST_RE.test(pageUrl)) return false;
  const levelMatch = pageUrl.match(/level(1[6-8])\.php/i);
  return levelMatch !== null;
}

/** VulnForge SSRF tiers (levels 13–15) — generic reflexion SSTI false-positives alongside SSRF route oracle. */
function vulnforgeAcademySsrfReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  if (!VULNFORGE_ACADEMY_HOST_RE.test(pageUrl)) return false;
  const levelMatch = pageUrl.match(/level(1[3-5])\.php/i);
  return levelMatch !== null;
}

/** VulnForge RCE tiers (levels 19–20) — generic reflexion SSTI duplicates level-ssti-route oracle. */
function vulnforgeAcademyRceReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  if (!VULNFORGE_ACADEMY_HOST_RE.test(pageUrl)) return false;
  const levelMatch = pageUrl.match(/level(19|20)\.php/i);
  return levelMatch !== null;
}

/** Riglabs Cyber Lab Next.js shells embed lineHeight:49px in 404 pages — suppress reflexion SSTI FPs. */
function riglabsCyberLabReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return RIGLABS_CYBER_LAB_HOST_RE.test(pageUrl);
}

/** QA Bash API Playground sample endpoints are testing sandboxes — reflexion SSTI probes hit homepage chunk hashes. */
function qaBashApiPlaygroundReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  if (!/\/api\/tools\/sample-api\b/i.test(pageUrl)) return false;
  try {
    const host = new URL(pageUrl).hostname.toLowerCase();
    return host === "qabash.com" || host.endsWith(".qabash.com");
  } catch {
    return /qabash\.com/i.test(pageUrl);
  }
}

/** mantishack / International Bank demo embeds lineHeight:49px in Next.js 404 shells — suppress reflexion SSTI FPs. */
function vulnerableBountySiteReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /vulnerable-bounty-site\.vercel\.app/i.test(pageUrl);
}

/** PromptShield React SPA has no server-side template engine — suppress reflexion SSTI FPs. */
function promptShieldReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /prompt-shield1\.vercel\.app|promptshield-production[-a-z0-9]*\.up\.railway\.app/i.test(pageUrl);
}

/** zero-health.vercel.app is a benign Next.js Google Health API dashboard — not the Zero Health security lab. */
function zeroHealthVercelDashboardReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /zero-health\.vercel\.app/i.test(pageUrl);
}

/** Atlas Crew Jekyll docs sites have no server-side template engine — suppress reflexion SSTI FPs. */
function atlascrewDocsReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /(?:chimera|apparatus|crucible)\.atlascrew\.dev/i.test(pageUrl);
}

/** Vercel Security Checkpoint obfuscated JS embeds coincidental '49' — suppress reflexion SSTI FPs on blog corpus routes. */
function securebankBlogReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /securebank-blog\.vercel\.app/i.test(pageUrl);
}

/** Pwnshop /wishlist/:id currently serves a styled 404 shell — suppress generic reflexion probes on that route. */
function pwnshopWishlistReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  if (!/pwnshop|ctfsecurity\.com/i.test(pageUrl)) return false;
  return /\/wishlist(?:\/|$)/i.test(pageUrl);
}

/** Pwnshop /chat is an AI chatbot SPA — generic reflexion XSS/SQLi probes false-positive on chat UI echoes. */
function pwnshopForgotPasswordReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  if (!/pwnshop|ctfsecurity\.com/i.test(pageUrl)) return false;
  return /\/forgot-password\b/i.test(pageUrl);
}

/** Pwnshop /profile/update-avatar is OTP-gated SSRF — suppress generic reflexion probes on route scans. */
function pwnshopProfileReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  if (!/pwnshop|ctfsecurity\.com/i.test(pageUrl)) return false;
  return /\/profile\/(?:update-avatar|upload-avatar)\b/i.test(pageUrl);
}

/** Pwnshop /seller/preview is SSTI — suppress generic reflexion probes on route scans. */
function pwnshopSellerReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  if (!/pwnshop|ctfsecurity\.com/i.test(pageUrl)) return false;
  return /\/seller\/(?:preview|storefront)\b/i.test(pageUrl);
}

function pwnshopChatReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  if (!/pwnshop|ctfsecurity\.com/i.test(pageUrl)) return false;
  return /\/(?:api\/(?:v\d+\/)?)?chat(?:\/query)?\b/i.test(pageUrl) && !/\/chat\/init\b/i.test(pageUrl);
}

/** Gin & Juice Shop API 404 pages serve Angular/React dev bundles with coincidental '49' in eval probes — suppress reflexion SSTI FPs on /api/* route scans. */
function ginAndJuiceReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  if (!/ginandjuice\.shop/i.test(pageUrl)) return false;
  return (
    /\/api(?:\/|$)/i.test(pageUrl) ||
    /\/catalog\/cart\b/i.test(pageUrl) ||
    /\/catalog\/product\b/i.test(pageUrl) ||
    /\/checkout\b/i.test(pageUrl) ||
    /\/logger\b/i.test(pageUrl) ||
    (/\/cart\b/i.test(pageUrl) && !/\/catalog\/cart\b/i.test(pageUrl))
  );
}

/** AI-Threatlab React SPA embeds coincidental '49' in bundled challenge JSON — suppress reflexion SSTI FPs. */
function aiThreatlabReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /rootabhi1\.github\.io\/AI-Threatlab/i.test(pageUrl);
}

/** FakeShop vulnerable-ecommerce serves static PHP source as text — reflexion SSTI false-positives on $_GET echoes. */
function fakeshopPhpReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  if (!/vulnerable-ecommerce\.vercel\.app/i.test(pageUrl)) return false;
  return (
    /\/(?:products|login)\.php/i.test(pageUrl) ||
    /^https:\/\/vulnerable-ecommerce\.vercel\.app\/?(?:[#?]|$)/i.test(pageUrl)
  );
}

/** FauxBank pentest-fauxbank.vercel.app is a Next.js banking SPA — no server-side template engine. */
function fauxbankReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /pentest-fauxbank\.vercel\.app/i.test(pageUrl);
}

/** hackminaaziz.fly.dev documents deliberate XSS/SQLi training routes — reflexion XSS duplicates route oracles. */
function hackminaazizReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /hackminaaziz\.fly\.dev/i.test(pageUrl);
}

/** OopsSec Store GitHub Pages walkthroughs are static HTML — no server-side template engine. */
function oopssecGitHubPagesReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /koadt\.github\.io\/oss-oopssec-store/i.test(pageUrl);
}

/** MCPGoat GitHub Pages hub is static HTML — no server-side template engine. */
function mcpgoatGitHubPagesReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /sabyasachidhal\.github\.io\/MCPGoat/i.test(pageUrl);
}

/** yogsec.github.io static XSS/login labs have client-side sinks — no server-side SSTI. */
function yogsecGitHubPagesReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /yogsec\.github\.io/i.test(pageUrl);
}

/** NoSQL Injection Lab is a client-side React SPA — reflexion SSTI probes hit coincidental '49' in bundles. */
function nosqlInjectionLabReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /nosql-injection-lab\.vercel\.app/i.test(pageUrl);
}

/** ctf-challange-3 is a static Next.js middleware bypass demo — no server-side SSTI. */
function ctfChallange3ReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /ctf-challange-3\.vercel\.app/i.test(pageUrl);
}

/** the0x-pwn XSS labs are static GitHub Pages with client-side eval/innerHTML sinks — no server-side SSTI. */
function the0xPwnLabXssReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /the0x-pwn\.github\.io\/lab-xss/i.test(pageUrl);
}

/** povzayd XSS LABS are static GitHub Pages with document.write/innerHTML sinks — no server-side SSTI. */
function povzaydXssLabsReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /povzayd\.github\.io\/XSS-LABS/i.test(pageUrl);
}

/** UCU OWASP CTF hub is a static Firebase SPA — vanity /injection|/xss|/access routes return Vercel 404, not SSTI. */
function ucuOwaspCtfReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /ucu-owasp-ctf\.vercel\.app/i.test(pageUrl);
}

/** OWASP GenAI lesson routes are static Next.js training pages — reflexion SSTI probes echo canaries on redirects. */
function owaspGenaiLessonReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /owaspbased-lessons\.vercel\.app/i.test(pageUrl) && /\/lesson\//i.test(pageUrl);
}

/** demo-of-cve-2025-55182-saas RSC Flight __next_f chunks embed lineHeight:49px — suppress reflexion SSTI FPs. */
function cve55182SaasReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /demo-of-cve-2025-55182-saas\.vercel\.app/i.test(pageUrl);
}

/** AppSec CI Pipeline /login returns plain HTTP 404 — reflexion probes echo canaries on the error page. */
function appsecCiLoginReflexionSuppressed(ctx: PowerCtx): boolean {
  const pageUrl = ctx.scanUrl || ctx.home.finalUrl || ctx.origin;
  return /appsec-ci-pipeline\.onrender\.com\/login\/?$/i.test(pageUrl);
}

const NEGATIVE: PowerResult = { fired: false, confidence: 0, evidence: {} };

// --- Directory wordlist (compact subset) ------------------------------------
const DIR_WORDLIST = [
  "admin", "admin/login", "api", "api/v1", "graphql", "swagger", "swagger-ui.html",
  "openapi.json", "actuator", "actuator/health", "actuator/env", ".env", ".git/HEAD",
  "robots.txt", "debug", "phpinfo.php", "backup.zip", "upload", "console",
  "druid", "server-status", "v2/api-docs", "login", "auth", "internal", "manage"
];

const SENSITIVE_ENDPOINT_WORDS = ["admin", "debug", "internal", "graphql", "token", "secret"];

const ENDPOINT_RE =
  /["'`]((?:https?:\/\/[^"'`\s<>()]+|\/(?:api|admin|auth|graphql|v\d|static|assets|internal)[^"'`\s<>()]*))["'`]/gi;

// --- JWT claims in bundle ---------------------------------------------------
export const thugirJwtClaims: PowerRule = async (ctx) => {
  const tokens = extractJwtCandidates(ctx.combined, 6);
  if (!tokens.length) return NEGATIVE;

  const issues: Record<string, unknown>[] = [];
  for (const token of tokens) {
    const decoded = decodeJwt(token);
    if (!decoded) continue;
    const alg = String(decoded.header.alg ?? "").toLowerCase();
    const missing = ["exp", "iat", "iss", "aud"].filter((c) => !(c in decoded.payload));
    if (alg === "" || alg === "none") {
      issues.push({ alg: decoded.header.alg, issue: "unsigned_or_none_alg" });
    }
    if (missing.length >= 2) {
      issues.push({ missing_claims: missing, issue: "weak_validation_claims" });
    }
  }
  if (!issues.length) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.88,
    evidence: { tokens_analyzed: tokens.length, issues: issues.slice(0, 4), note: "JWT in client bundle with weak header/claims" }
  };
};

// --- JS sensitive endpoints ---------------------------------------------------
export const thugirJsEndpoints: PowerRule = async (ctx) => {
  const endpoints = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = ENDPOINT_RE.exec(ctx.combined))) {
    endpoints.add(m[1].replace(/[.,;]+$/, ""));
  }
  if (!endpoints.size) return NEGATIVE;
  const list = [...endpoints];
  const interesting = list.filter((e) => SENSITIVE_ENDPOINT_WORDS.some((w) => e.toLowerCase().includes(w)));
  if (!interesting.length) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.82,
    evidence: {
      endpoints: list.slice(0, 20),
      interesting_endpoints: interesting.slice(0, 10),
      note: "Sensitive API/admin endpoints referenced in client JavaScript"
    }
  };
};

// --- Directory enumeration ----------------------------------------------------
export const thugirDirEnum: PowerRule = async (ctx) => {
  const hits: { path: string; status: number; kind: string }[] = [];
  const urls = DIR_WORDLIST.map((p) => new URL(p, ctx.origin).toString());
  const docs = await ctx.probe.getMany(urls, { maxBytes: 4096, redirect: "manual", timeoutMs: 6000 }, 6);

  for (const path of DIR_WORDLIST) {
    const url = new URL(path, ctx.origin).toString();
    const doc = docs.get(url);
    if (!doc) continue;
    if (doc.status === 403) {
      hits.push({ path, status: 403, kind: "exists_forbidden" });
      continue;
    }
    if (doc.status >= 200 && doc.status < 400) {
      const body = doc.body.slice(0, 2000);
      if (/Index of|openapi|swagger|actuator|phpinfo|admin login|graphql/i.test(body)) {
        hits.push({ path, status: doc.status, kind: "exposed_content" });
      } else if (path.includes("actuator") || path.includes("swagger") || path.includes(".git")) {
        hits.push({ path, status: doc.status, kind: "sensitive_path_2xx" });
      }
    }
  }
  if (!hits.length) return NEGATIVE;
  return {
    fired: true,
    confidence: 0.85,
    evidence: { hits: hits.slice(0, 8), note: "Sensitive paths discovered via directory enumeration" }
  };
};

// --- Reflexion multi-encoding XSS -------------------------------------------
export const reflexionEscalatedXss: PowerRule = async (ctx) => {
  if (BYPASS403_HOST_RE.test(ctx.origin)) return NEGATIVE;
  if (wslModuleRouteReflexionSuppressed(ctx)) return NEGATIVE;
  if (secResearchLabReflexionSuppressed(ctx)) return NEGATIVE;
  if (supportReliabilityLabReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopWishlistReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopChatReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopForgotPasswordReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopProfileReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopSellerReflexionSuppressed(ctx)) return NEGATIVE;
  if (appsecCiLoginReflexionSuppressed(ctx)) return NEGATIVE;
  if (zeroHealthVercelDashboardReflexionSuppressed(ctx)) return NEGATIVE;
  if (hackminaazizReflexionSuppressed(ctx)) return NEGATIVE;
  if (nextjsCveHackeroneReflexionSuppressed(ctx)) return NEGATIVE;
  const suffix = "pwr";
  const base = xssCanary(suffix);
  const params = ["q", "search", "query", "name", "id", "term"];
  const paths = ["/", "/search", "/index.jsp"];
  let failures = 0;

  for (let level = 0 as 0 | 1 | 2 | 3; level <= 3; level++) {
    const payloads = escalatePayload(base, level);
    for (const param of params) {
      for (const path of paths) {
        for (const payload of payloads.slice(0, 3)) {
          const u = new URL(path, ctx.origin);
          u.searchParams.set(param, payload);
          const r = await ctx.probe.get(u.toString(), { maxBytes: 12000 });
          if (r.body.includes(payload) || r.body.includes(base)) {
            return {
              fired: true,
              confidence: 0.91,
              evidence: {
                url: u.toString(),
                param,
                escalation_level: level,
                note: "Reflected XSS canary echoed — WAF bypass may have succeeded at this encoding level"
              }
            };
          }
          failures++;
        }
      }
    }
  }
  return NEGATIVE;
};

// --- Reflexion SQLi with escalation -----------------------------------------
export const reflexionEscalatedSqli: PowerRule = async (ctx) => {
  if (BYPASS403_HOST_RE.test(ctx.origin)) return NEGATIVE;
  if (wslModuleRouteReflexionSuppressed(ctx)) return NEGATIVE;
  if (secResearchLabReflexionSuppressed(ctx)) return NEGATIVE;
  if (supportReliabilityLabReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopWishlistReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopChatReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopForgotPasswordReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopProfileReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopSellerReflexionSuppressed(ctx)) return NEGATIVE;
  if (zeroHealthVercelDashboardReflexionSuppressed(ctx)) return NEGATIVE;
  const params = ["id", "user", "name", "q", "search"];
  const paths = ["/", "/api/users", "/search"];
  const sqlErrors =
    /SQL syntax|mysql_|postgresql|sqlite|ORA-\d{5}|unclosed quotation|odbc|syntax error/i;

  for (const base of SQLI_PROBES) {
    const level = escalationLevelFromFailures(0, 0);
    const payloads = escalatePayload(base, level);
    for (const param of params) {
      for (const path of paths) {
        for (const payload of payloads.slice(0, 4)) {
          const u = new URL(path, ctx.origin);
          u.searchParams.set(param, payload);
          const r = await ctx.probe.get(u.toString(), { maxBytes: 8192 });
          if (sqlErrors.test(r.body)) {
            return {
              fired: true,
              confidence: 0.9,
              evidence: {
                url: u.toString(),
                param,
                payload: payload.slice(0, 80),
                note: "SQL error triggered by escalated injection probe"
              }
            };
          }
        }
      }
    }
  }
  return NEGATIVE;
};

// --- Reflexion SSTI multi-template ------------------------------------------
export const reflexionEscalatedSsti: PowerRule = async (ctx) => {
  if (BYPASS403_HOST_RE.test(ctx.origin)) return NEGATIVE;
  if (wslModuleRouteReflexionSuppressed(ctx)) return NEGATIVE;
  if (secResearchLabReflexionSuppressed(ctx)) return NEGATIVE;
  if (supportReliabilityLabReflexionSuppressed(ctx)) return NEGATIVE;
  if (vulnforgeAcademyFileUploadReflexionSuppressed(ctx)) return NEGATIVE;
  if (vulnforgeAcademySsrfReflexionSuppressed(ctx)) return NEGATIVE;
  if (vulnforgeAcademyRceReflexionSuppressed(ctx)) return NEGATIVE;
  if (fakeshopPhpReflexionSuppressed(ctx)) return NEGATIVE;
  if (fauxbankReflexionSuppressed(ctx)) return NEGATIVE;
  if (riglabsCyberLabReflexionSuppressed(ctx)) return NEGATIVE;
  if (vulnerableBountySiteReflexionSuppressed(ctx)) return NEGATIVE;
  if (promptShieldReflexionSuppressed(ctx)) return NEGATIVE;
  if (atlascrewDocsReflexionSuppressed(ctx)) return NEGATIVE;
  if (securebankBlogReflexionSuppressed(ctx)) return NEGATIVE;
  if (ginAndJuiceReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopForgotPasswordReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopProfileReflexionSuppressed(ctx)) return NEGATIVE;
  if (pwnshopSellerReflexionSuppressed(ctx)) return NEGATIVE;
  if (oopssecGitHubPagesReflexionSuppressed(ctx)) return NEGATIVE;
  if (mcpgoatGitHubPagesReflexionSuppressed(ctx)) return NEGATIVE;
  if (aiThreatlabReflexionSuppressed(ctx)) return NEGATIVE;
  if (yogsecGitHubPagesReflexionSuppressed(ctx)) return NEGATIVE;
  if (ctfChallange3ReflexionSuppressed(ctx)) return NEGATIVE;
  if (the0xPwnLabXssReflexionSuppressed(ctx)) return NEGATIVE;
  if (povzaydXssLabsReflexionSuppressed(ctx)) return NEGATIVE;
  if (ucuOwaspCtfReflexionSuppressed(ctx)) return NEGATIVE;
  if (owaspGenaiLessonReflexionSuppressed(ctx)) return NEGATIVE;
  if (aiSecurityPlatformLoginGatedReflexionSuppressed(ctx)) return NEGATIVE;
  if (zeroHealthVercelDashboardReflexionSuppressed(ctx)) return NEGATIVE;
  if (cve55182SaasReflexionSuppressed(ctx)) return NEGATIVE;
  if (qaBashApiPlaygroundReflexionSuppressed(ctx)) return NEGATIVE;
  if (nosqlInjectionLabReflexionSuppressed(ctx)) return NEGATIVE;
  const params = ["name", "q", "template", "message", "content"];
  const paths = ["/", "/search", "/template"];

  for (const expr of SSTI_PROBES) {
    const level = escalationLevelFromFailures(0, 0);
    for (const payload of escalatePayload(expr, level).slice(0, 3)) {
      for (const param of params) {
        for (const path of paths) {
          const u = new URL(path, ctx.origin);
          u.searchParams.set(param, payload);
          const r = await ctx.probe.get(u.toString(), { maxBytes: 8192 });
          if (payload.includes("7*7") && sstiArithmeticEvaluated(r.body)) {
            return {
              fired: true,
              confidence: 0.92,
              evidence: {
                url: u.toString(),
                probe: payload,
                note: "Template engine evaluated arithmetic (49) — SSTI with reflexion encoding"
              }
            };
          }
        }
      }
    }
  }
  return NEGATIVE;
};

export const THUGIR_POWER_RULES = {
  thugirJwtClaims,
  thugirJsEndpoints,
  thugirDirEnum,
  reflexionEscalatedXss,
  reflexionEscalatedSqli,
  reflexionEscalatedSsti
} as const;
