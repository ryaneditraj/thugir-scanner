// AI-driven Deep Scan layer. The LLM reads crawled HTML/JS and proposes vulnerabilities
// that MUST quote verbatim evidence from the source. Unverified proposals are discarded —
// this is AI-assisted detection, not AI hallucination as findings.

import type { PatternFinding, Severity } from "../patterns/types";
import { loadSettings } from "../settings/store";
import type { TierName } from "../settings/schema";
import { callAiProvider, envKeyFor, parseAiJson, tierAiConfig } from "./client";
import {
  triageSeverity,
  WEB_SCANNER_SYSTEM_PREFIX,
  REFLEXION_PROMPT,
  loadCoreOracleSummaries,
  loadAgentOracleSummaries
} from "../methodology";

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

const ORACLE_CONTEXT = `${loadCoreOracleSummaries(2200)}

${loadAgentOracleSummaries(1800)}

${REFLEXION_PROMPT}`;

const SYSTEM = `${WEB_SCANNER_SYSTEM_PREFIX}

${ORACLE_CONTEXT}

You receive HTML and JavaScript excerpts from a crawl of ONE target.

Find REAL security issues visible in the source. Quote EXACT substrings as evidenceQuote (max 200 chars).

Priority classes: injection, XSS, IDOR/BOLA, auth bypass, exposed secrets/API keys, SSRF sinks,
dangerous sinks (eval, innerHTML, dangerouslySetInnerHTML), missing auth on state-changing fetches.
When a class looks blocked by WAF/filter, note which reflexion encoding level might bypass it.

AI-built app misconfigs are secondary — report if visible in source.

Return ONLY a JSON array (max 8 items), no markdown:
[{"title":"short title","severity":"critical|high|medium|low","category":"...","impactOneline":"one line","maxDamageOneline":"...","evidenceQuote":"exact substring","reasoning":"one sentence","suggestedFix":"imperative fix"}]`;

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

      let severity = SEV.includes((hit.severity || "").toLowerCase() as Severity)
        ? ((hit.severity || "medium").toLowerCase() as Severity)
        : "medium";

      severity = triageSeverity({
        severity,
        category: hit.category || "",
        title,
        hardeningOnly: /header|cors|csp|hsts/i.test((hit.category || "") + title)
      });

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
