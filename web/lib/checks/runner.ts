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
async function reachTarget(target: URL, rawInput: string): Promise<FetchedDoc> {
  const userForcedHttps = /^https:\/\//i.test(rawInput.trim());
  const apexHost = target.hostname.replace(/^www\./i, "");
  const hadWww = target.hostname.toLowerCase().startsWith("www.");

  const hosts = hadWww ? [target.hostname, apexHost] : [apexHost, `www.${apexHost}`];
  const protocols = userForcedHttps ? ["https:"] : ["https:", "http:"];

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
  const origin = target.origin;

  // Pull a capped set of same-origin scripts for secret scanning.
  const probe = new ProbeCache();
  const scriptUrls = extractScriptUrls(home.body, origin, opts.maxScripts ?? 12);
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
  "idorObjectAccess",
  "reflectedXss",
  "clientSideIdorEvidence"
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
function internalLinks(html: string, origin: string, limit: number): string[] {
  const out = new Set<string>();
  const re = /href\s*=\s*["']([^"'#?]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) && out.size < limit * 3) {
    try {
      const u = new URL(m[1], origin);
      if (u.origin !== origin) continue;
      if (/\.(png|jpe?g|svg|gif|webp|ico|css|js|map|woff2?|ttf|pdf|zip)$/i.test(u.pathname)) continue;
      u.hash = "";
      out.add(u.toString());
    } catch {
      /* ignore */
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
  const origin = target.origin;

  // Shallow crawl: homepage + a handful of internal pages.
  const pageUrls = [home.finalUrl, ...internalLinks(home.body, origin, DEEP_MAX_PAGES - 1)];
  const probe = new ProbeCache();
  const extraPages = await fetchPagesBatched(pageUrls.slice(1), { probe, maxBytes: 600_000, concurrency: 3 });
  const pages: FetchedDoc[] = [home, ...extraPages];

  const scriptCap = opts.maxScripts ?? 24;
  const scriptUrls = new Set<string>();
  for (const p of pages) for (const u of extractScriptUrls(p.body, origin, scriptCap)) scriptUrls.add(u);
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
