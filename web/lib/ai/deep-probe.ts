// AI-driven Deep Scan layer. The LLM reads crawled HTML/JS and proposes vulnerabilities
// that MUST quote verbatim evidence from the source. Unverified proposals are discarded —
// this is AI-assisted detection, not AI hallucination as findings.

import type { PatternFinding, Severity } from "../patterns/types";
import { loadSettings } from "../settings/store";
import type { TierName } from "../settings/schema";
import { callAiProvider, envKeyFor, parseAiJson, tierAiConfig } from "./client";

export interface DeepProbeContext {
  target: string;
  origin: string;
  detectedPlatform: string | null;
  combined: string;
  pagesCrawled: string[];
}

interface AiDeepHit {
  title?: string;
  severity?: string;
  category?: string;
  impactOneline?: string;
  maxDamageOneline?: string;
  evidenceQuote?: string;
  reasoning?: string;
  suggestedFix?: string;
}

const SYSTEM = `You are an elite offensive security researcher auditing AI-generated ("vibe-coded") web apps.
You receive HTML and JavaScript excerpts from a shallow crawl of ONE target.

Find REAL security issues visible in the source. You must quote EXACT substrings from the provided source as evidenceQuote (max 200 chars each).

Focus on what vibe-coded apps ship wrong:
- Client-only auth (UI guards without server/RLS enforcement)
- Server Actions / fetch calls to /api/* without auth headers
- Hardcoded credentials, demo bypass flags, admin routes in client routers
- Dangerous sinks (dangerouslySetInnerHTML, eval, innerHTML with user data)
- Exposed internal URLs, staging keys, debug flags
- IDOR patterns (fetch by user id from URL without session check in same function)
- Missing CSRF on state-changing client calls

Do NOT report generic missing CSP/headers (other tools cover those).
Do NOT invent issues — if evidenceQuote is not literally in the source, it will be rejected.

Return ONLY a JSON array (max 8 items), no markdown:
[{"title":"short title","severity":"critical|high|medium|low","category":"Broken access control|Exposed secret|Broken authentication|Information disclosure","impactOneline":"one line","maxDamageOneline":"worst realistic outcome for the COMPANY (fines, breach, fraud, shutdown — 1-2 sentences)","evidenceQuote":"exact substring from source","reasoning":"one sentence","suggestedFix":"imperative fix"}]`;

const SEV: Severity[] = ["critical", "high", "medium", "low"];

function norm(s: string): string {
  return s.replace(/\s+/g, " ").trim().toLowerCase();
}

function evidenceInSource(quote: string, combined: string): boolean {
  if (!quote || quote.length < 8) return false;
  if (combined.includes(quote)) return true;
  const nq = norm(quote);
  const nc = norm(combined);
  return nc.includes(nq);
}

function slugify(title: string): string {
  return `ai-deep-${title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .slice(0, 48)
    .replace(/-$/, "")}`;
}

export async function aiDeepProbe(ctx: DeepProbeContext): Promise<PatternFinding[]> {
  const settings = await loadSettings();
  if (!settings.ai.analystEnabled || !settings.ai.deepScanAiEnabled) return [];

  const tier: TierName = "deep";
  const cfg = settings.ai.tiers[tier];
  if (!cfg?.enabled) return [];

  const apiKey = cfg.apiKey || envKeyFor(cfg.provider);
  if (!apiKey) return [];

  const { provider, model, url } = tierAiConfig(cfg.provider, cfg);
  const excerpt = ctx.combined.slice(0, 90_000);

  const userMsg = `Target: ${ctx.target}
Origin: ${ctx.origin}
Stack hint: ${ctx.detectedPlatform ?? "unknown"}
Pages crawled: ${ctx.pagesCrawled.slice(0, 8).join(", ")}

--- SOURCE EXCERPT (HTML + JS) ---
${excerpt}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 45_000);
  try {
    const content = await callAiProvider(provider, {
      url,
      apiKey,
      model,
      temperature: Math.min(cfg.temperature + 0.1, 0.4),
      maxTokens: Math.max(cfg.maxTokens, 2500),
      system: SYSTEM,
      user: userMsg,
      signal: controller.signal
    });
    if (!content) return [];

    const parsed = parseAiJson<AiDeepHit[]>(content);
    if (!Array.isArray(parsed)) return [];

    const findings: PatternFinding[] = [];
    const seenTitles = new Set<string>();

    for (const hit of parsed.slice(0, 8)) {
      const title = (hit.title || "").trim();
      const quote = (hit.evidenceQuote || "").trim();
      if (!title || !quote || !evidenceInSource(quote, ctx.combined)) continue;
      if (seenTitles.has(title.toLowerCase())) continue;
      seenTitles.add(title.toLowerCase());

      const severity = SEV.includes((hit.severity || "").toLowerCase() as Severity)
        ? ((hit.severity || "medium").toLowerCase() as Severity)
        : "medium";

      findings.push({
        patternSlug: slugify(title),
        category: hit.category || "AI deep analysis",
        title: `[AI] ${title}`,
        severity,
        tierRequired: "deep",
        impactOneline: hit.impactOneline || hit.reasoning || title,
        maxDamageOneline: hit.maxDamageOneline,
        evidence: {
          source: "ai_deep_probe",
          evidenceQuote: quote.slice(0, 300),
          reasoning: hit.reasoning,
          model
        },
        remediation: hit.suggestedFix
          ? { summary: hit.suggestedFix, steps: [] }
          : undefined,
        fixPrompt: hit.suggestedFix
          ? `Security issue on ${ctx.target}: ${title}. Evidence: "${quote.slice(0, 120)}". ${hit.suggestedFix}`
          : undefined,
        confidence: 0.62
      });
    }
    return findings;
  } catch {
    return [];
  } finally {
    clearTimeout(timeout);
  }
}
