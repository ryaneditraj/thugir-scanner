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
import { fetchScriptsBatched, fetchPagesBatched } from "./fetch-scripts";

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
  const matches = combined.match(re);
  if (!matches) return null;
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
  const scripts = await fetchScriptsBatched(scriptUrls, { probe, maxBytes: 800_000, concurrency: 4 });
  const combined = [home.body, ...scripts.map((s) => s.body)].join("\n");
  const detection = detectPlatform(home, combined);
  const ctx: RuleContext = { origin, home, scripts, combined, probe };

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
  "clientSideXssC2CollectorEvidence",
  "clientSideDevSecOpsLabEvidence",
  "clientSideVulnAuthPortalEvidence",
  "clientSidePathTraversalEvidence",
  "clientSideGraphqlLabEvidence",
  "clientSideReactRscCveEvidence",
  "clientSideChimeraVulnLabEvidence",
  "clientSideHackHealthLabEvidence",
  "clientSideDomGoatLabEvidence",
  "clientSideInvictiPracticeSiteEvidence",
  "clientSideWebsecChallengeEvidence",
  "clientSideSixHackCtfLabEvidence",
  "clientSideRootMeChallengeEvidence",
  "clientSidePentesterLabEvidence",
  "clientSideHackThisSiteEvidence",
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
  "clientSideGoogleGruyereCodelabEvidence",
  "clientSideMutillidaeEvidence",
  "clientSideBwappEvidence",
  "clientSideHackableSoLabEvidence",
  "clientSideVulnwebLabEvidence",
  "clientSideHackingLabEvidence",
  "clientSideSolydTrainingEvidence",
  "clientSideCylabAcademyEvidence",
  "clientSideVulnerableappEvidence",
  "clientSideRestVulnwebEvidence",
  "clientSideVulnforgeAcademyEvidence",
  "clientSideTegalsecLabEvidence",
  "clientSideBugBountyHunterEvidence",
  "clientSideZeroHealthEvidence",
  "clientSideAlfXssWargameEvidence",
  "clientSideLlmSecEvidence",
  "clientSideDefendthewebEvidence",
  "clientSideReturnTrueWargameEvidence",
  "clientSideAuthlabEvidence",
  "clientSideXssQuizEvidence",
  "htmlCommentCredentialDisclosure",
  "openApiDebugPasswordExposure"
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
  for (const path of ["/cxss/sinks", "/cxss/example/1", "/cxss/example/2"]) {
    try {
      out.add(new URL(path, pageUrl).toString());
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
  for (const p of ["/exercises", "/exercises/web-for-pentester", "/exercises/web_for_pentester"]) {
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

/** HackThisSite mission hubs — /missions/basic|realistic|application carry challenge labs. */
const HACKTHISITE_MISSION_RE = /href\s*=\s*["'](\/missions\/[a-z]+(?:\/\d+)?\/?)["']/gi;

function extractHackThisSiteMissionSeeds(html: string, origin: string): string[] {
  if (!/hackthissite|Hack This Site|ethical hacking skills/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of [
    "/missions/basic/",
    "/missions/realistic/",
    "/missions/application/",
    "/missions/javascript/"
  ]) {
    try {
      out.add(new URL(p, origin).toString());
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

/** SixHack Academy links CTF Labs on /ctf-labs/ and platform.sixhackacademy.com from marketing pages. */
function extractSixHackCtfSeeds(html: string, origin: string): string[] {
  if (!/sixhackacademy|CTF Labs de SixHack|platform\.sixhackacademy\.com/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["/ctf-labs/", "/ctf-labs"]) {
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
    "site-footer-xss-discussion.php"
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

/** bWAPP marketing site (itsecgames.com) — bugs catalog documents 100+ vulnerability types. */
function extractBwappLabSeeds(html: string, origin: string): string[] {
  if (!/bWAPP|buggy web application|itsecgames/i.test(html)) return [];
  const out = new Set<string>();
  for (const p of ["bugs.htm", "download.htm", "training.htm", "downloads/vulnerabilities.txt"]) {
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
  for (const p of ["/reflected/index.html", "/redirect/index.html", "/dom/index.html"]) {
    try {
      out.add(new URL(p, origin).toString());
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
    "https://returntrue.win/",
    "/alert1",
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

/** TegalSec browser hacking labs (labs.tegalsec.org/br0w, xss-labs). */
function extractTegalsecLabSeeds(html: string, pageUrl: string): string[] {
  if (!/HACK THE BR0W|XSS Labs \| Tegal1337|tegalsec\.org/i.test(html)) return [];
  const out = new Set<string>();
  const pageOrigin = new URL(pageUrl).origin;
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

/** OWASP VulnerableApp docs (sasanlabs.github.io/VulnerableApp) — Jekyll scanner-eval platform. */
function extractVulnerableAppDocSeeds(html: string, pageUrl: string): string[] {
  if (!/VulnerableApp|SasanLabs\/VulnerableApp|Vulnerable App/i.test(html)) return [];
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
  if (!/SecTrainer|securitytrainer\.vercel\.app/i.test(corpus)) return [];
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
  for (let i = 0; i <= 12; i++) {
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
  if (
    !/Hackforge|CTF Platform|Premier Cybersecurity CTF|capture the flag.*training platform/i.test(
      html
    )
  )
    return [];
  const paths = ["/practice", "/challenges", "/events", "/dashboard", "/courses"];
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
    "vulnerability-inventory",
    "endpoints-catalog",
    "sqlInjection",
    "source.php",
    "/vulnerabilities/",
    "level1",
    "level0",
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
  const origin = target.origin;
  const crawlOrigin = new URL(home.finalUrl).origin;

  // Shallow crawl: homepage + internal pages (prioritize vuln lab HTML).
  // Prefetch homepage scripts first — static labs often navigate via JS (e.g. login.js → comments.html).
  const probe = new ProbeCache();
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
  const domGoatCxssSeeds = extractDomGoatCxssSeeds(home.body, home.finalUrl);
  const ctfHubSeeds = extractCtfChallengeHubLinks(home.body, home.finalUrl);
  const ctfPlatformSeeds = extractCtfPlatformSpaSeeds(home.body, origin);
  const websecSeeds = extractWebsecChallengeSeeds(home.body, origin);
  const sixHackSeeds = extractSixHackCtfSeeds(home.body, origin);
  const gruyereSeeds = extractGruyereCodelabSeeds(home.body, origin);
  const firingRangeSeeds = extractFiringRangeCrawlSeeds(home.body, origin);
  const tegalsecSeeds = extractTegalsecLabSeeds(home.body, home.finalUrl);
  const alfNuXssSeeds = extractAlfNuXssSeeds(home.body, home.finalUrl);
  const returnTrueSeeds = extractReturnTrueSeeds(home.body, home.finalUrl);
  const authlabSeeds = extractAuthlabSeeds(home.body, home.finalUrl);
  const xssQuizSeeds = extractXssQuizInt21hSeeds(home.body, home.finalUrl);
  const vulnerableAppSeeds = extractVulnerableAppDocSeeds(home.body, home.finalUrl);
  const restVulnwebSeeds = extractRestVulnwebDocSeeds(home.body, origin);
  const mutillidaeSeeds = extractMutillidaeLabSeeds(home.body, origin);
  const bwappSeeds = extractBwappLabSeeds(home.body, origin);
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
  const hackThisSiteSeeds = extractHackThisSiteMissionSeeds(home.body, origin);
  const wrongSecretsSeeds = extractWrongSecretsChallengeSeeds(home.body, origin);
  const sectrainerSeeds = extractSectrainerSpaSeeds(
    home.body,
    earlyScripts.map((s) => s.body),
    crawlOrigin
  );
  const dvwaSeeds = extractDvwaVulnSourceSeeds(home.body, origin);

  const crawlSeeds = prioritizeSecurityLabLinks([
    ...new Set([
      ...labHubSeeds,
      ...docusaurusLabSeeds,
      ...nextraCyberSeeds,
      ...jekyllSecurityDocSeeds,
      ...domGoatCxssSeeds,
      ...ctfHubSeeds,
      ...ctfPlatformSeeds,
      ...websecSeeds,
      ...sixHackSeeds,
      ...gruyereSeeds,
      ...firingRangeSeeds,
      ...tegalsecSeeds,
      ...alfNuXssSeeds,
      ...returnTrueSeeds,
      ...authlabSeeds,
      ...xssQuizSeeds,
      ...vulnerableAppSeeds,
      ...restVulnwebSeeds,
      ...mutillidaeSeeds,
      ...bwappSeeds,
      ...hackableSoSeeds,
      ...vulnwebSeeds,
      ...pentesterLabSeeds,
      ...hackThisSiteSeeds,
      ...wrongSecretsSeeds,
      ...sectrainerSeeds,
      ...dvwaSeeds,
      ...sitemapSeeds,
      ...spaRoutes,
      ...internalLinks(home.body, home.finalUrl, (DEEP_MAX_PAGES - 1) * 8),
      ...jsNavTargets(home.body, home.finalUrl, DEEP_MAX_PAGES - 1),
      ...scriptNavTargets
    ])
  ]).slice(0, DEEP_MAX_PAGES - 1);
  const pageUrls = [home.finalUrl, ...new Set(crawlSeeds)].slice(0, DEEP_MAX_PAGES);
  const extraPages = await fetchPagesBatched(pageUrls.slice(1), { probe, maxBytes: 600_000, concurrency: 3 });
  let pages: FetchedDoc[] = [home, ...extraPages];

  const childSeeds = prioritizeSecurityLabLinks(
    extraPages.flatMap((p) => [
      ...extractLabChildLinks(p.body, p.finalUrl),
      ...extractDocusaurusLabLinks(p.body, p.finalUrl)
    ])
  ).slice(0, 2);
  if (childSeeds.length > 0 && pages.length >= DEEP_MAX_PAGES) {
    const childPages = await fetchPagesBatched(childSeeds, { probe, maxBytes: 600_000, concurrency: 2 });
    pages = [...pages.slice(0, DEEP_MAX_PAGES - childPages.length), ...childPages];
  } else if (childSeeds.length > 0) {
    const childPages = await fetchPagesBatched(childSeeds, { probe, maxBytes: 600_000, concurrency: 2 });
    pages = [...pages, ...childPages].slice(0, DEEP_MAX_PAGES);
  }

  const scriptCap = opts.maxScripts ?? 24;
  const scriptUrls = new Set<string>();
  for (const p of pages) for (const u of extractScriptUrls(p.body, p.finalUrl, scriptCap)) scriptUrls.add(u);
  const scripts = await fetchScriptsBatched([...scriptUrls].slice(0, scriptCap), {
    probe,
    maxBytes: 800_000,
    concurrency: 4
  });

  const combined = [...pages.map((p) => p.body), ...scripts.map((s) => s.body)].join("\n");
  const detection = detectPlatform(home, combined);
  const ctx: RuleContext = { origin, home, scripts, combined, probe };

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
