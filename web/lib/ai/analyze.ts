// AI security-analyst layer. Sits ON TOP of the deterministic scan engine: the checks decide
// what is true (evidence-gated), the LLM explains impact, max company damage, and tailors fixes.
// It never invents findings.

import type { PatternFinding } from "../patterns/types";
import { loadSettings } from "../settings/store";
import { PROVIDER_ENDPOINTS, type AiProvider, type TierName } from "../settings/schema";
import { callAiProvider, envKeyFor, parseAiJson } from "./client";

export interface AiAnalysis {
  summary: string;
  riskLevel: "critical" | "high" | "medium" | "low" | "clean";
  maxCompanyDamage: string;
  /** How an attacker chains these findings into one breach narrative. */
  attackChain: string;
  fixes: Record<string, string>;
  maxDamage: Record<string, string>;
  model: string;
}

function findingsDigest(findings: PatternFinding[]): string {
  return findings
    .map(
      (f, i) =>
        `${i + 1}. [${f.severity}] ${f.title} (slug=${f.patternSlug})\n   impact: ${f.impactOneline}\n   maxDamage: ${f.maxDamageOneline ?? "unknown"}\n   evidence: ${JSON.stringify(f.evidence).slice(0, 400)}`
    )
    .join("\n");
}

const SYSTEM = `You are a senior application security analyst for Thugir Scanner advising founders and CTOs.
You are given CONFIRMED findings from a deterministic scan engine. The engine already proved these are real — do not question them or invent new ones.

Your job:
1. summary — 2-3 sentences, attacker's-eye view of the worst realistic outcome if left unfixed.
2. maxCompanyDamage — ONE paragraph (3-5 sentences) describing the MAXIMUM damage to the COMPANY: regulatory fines, customer churn, fraud losses, lawsuits, payment processor termination, layoffs, shutdown. Be specific and sober, not alarmist fiction.
3. riskLevel — one of: critical, high, medium, low, clean (clean only if zero findings).
4. attackChain — 2-4 sentences describing the most likely COMBINED attack path (step 1 → step 2 → outcome) using ONLY the confirmed findings. Founder-readable.
5. fixes — per slug, concrete remediation (2-4 sentences, imperative voice).
6. maxDamage — per slug, ONE sentence worst-case business outcome for THAT specific issue (fines, breach scope, fraud $, reputational harm).

Respond with ONLY valid minified JSON, no code fences:
{"summary": string, "maxCompanyDamage": string, "attackChain": string, "riskLevel": string, "fixes": {"<slug>": string}, "maxDamage": {"<slug>": string}}`;

export async function analyzeScan(args: {
  target: string;
  detectedPlatform: string | null;
  findings: PatternFinding[];
  tier?: TierName;
}): Promise<AiAnalysis | null> {
  const tier = args.tier ?? "free";
  const settings = await loadSettings();
  if (!settings.ai.analystEnabled) return null;

  const cfg = settings.ai.tiers[tier];
  if (!cfg || !cfg.enabled) return null;

  const apiKey = cfg.apiKey || envKeyFor(cfg.provider);
  if (!apiKey) return null;

  const model = cfg.model || PROVIDER_ENDPOINTS[cfg.provider].defaultModel;
  const url = cfg.baseUrl?.trim() || PROVIDER_ENDPOINTS[cfg.provider].url;
  const { target, detectedPlatform, findings } = args;
  const userMsg =
    findings.length === 0
      ? `Target: ${target}\nStack: ${detectedPlatform ?? "unknown"}\nNo issues were confirmed. Give a brief honest summary, maxCompanyDamage explaining what a clean scan does NOT guarantee, and set riskLevel to "clean".`
      : `Target: ${target}\nStack: ${detectedPlatform ?? "unknown"}\nConfirmed findings:\n${findingsDigest(findings)}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 25_000);
  try {
    const content = await callAiProvider(cfg.provider, {
      url,
      apiKey,
      model,
      temperature: cfg.temperature,
      maxTokens: Math.max(cfg.maxTokens, tier === "deep" ? 2000 : 1200),
      system: SYSTEM,
      user: userMsg,
      signal: controller.signal
    });
    if (!content) return null;

    const parsed = parseAiJson<{
      summary?: unknown;
      maxCompanyDamage?: unknown;
      attackChain?: unknown;
      riskLevel?: string;
      fixes?: unknown;
      maxDamage?: unknown;
    }>(content);
    if (!parsed) return null;

    const fixes: Record<string, string> = {};
    if (parsed.fixes && typeof parsed.fixes === "object") {
      for (const [k, v] of Object.entries(parsed.fixes)) if (typeof v === "string") fixes[k] = v;
    }
    const maxDamage: Record<string, string> = {};
    if (parsed.maxDamage && typeof parsed.maxDamage === "object") {
      for (const [k, v] of Object.entries(parsed.maxDamage)) if (typeof v === "string") maxDamage[k] = v;
    }
    const levels = ["critical", "high", "medium", "low", "clean"];
    const riskLevel = parsed.riskLevel && levels.includes(parsed.riskLevel) ? parsed.riskLevel : "medium";

    return {
      summary: typeof parsed.summary === "string" ? parsed.summary : "",
      maxCompanyDamage:
        typeof parsed.maxCompanyDamage === "string"
          ? parsed.maxCompanyDamage
          : typeof parsed.summary === "string"
            ? parsed.summary
            : "",
      attackChain: typeof parsed.attackChain === "string" ? parsed.attackChain : "",
      riskLevel: riskLevel as AiAnalysis["riskLevel"],
      fixes,
      maxDamage,
      model
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

export interface AiTestResult {
  ok: boolean;
  detail: string;
  provider: AiProvider;
  model: string;
  reply?: string;
}

export async function testTierAi(
  tier: TierName,
  override?: { provider?: AiProvider; model?: string; baseUrl?: string; apiKey?: string }
): Promise<AiTestResult> {
  const settings = await loadSettings();
  const saved = settings.ai.tiers[tier];
  const provider = (override?.provider ?? saved?.provider ?? "openrouter") as AiProvider;
  const model = override?.model?.trim() || saved?.model || PROVIDER_ENDPOINTS[provider].defaultModel;
  const url = override?.baseUrl?.trim() || saved?.baseUrl?.trim() || PROVIDER_ENDPOINTS[provider].url;
  const apiKey = override?.apiKey?.trim() || saved?.apiKey || envKeyFor(provider);

  if (!apiKey)
    return { ok: false, detail: "No API key set for this tier (and no environment fallback).", provider, model };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20_000);
  try {
    const ping = await rawProviderPing(provider, { url, apiKey, model, signal: controller.signal });
    if (ping.ok)
      return { ok: true, detail: `Connected — ${provider} answered using ${model}.`, provider, model, reply: ping.body.slice(0, 160) };
    return { ok: false, detail: `Provider returned HTTP ${ping.status}. ${ping.body.slice(0, 220)}`, provider, model };
  } catch (e) {
    const err = e as Error;
    const msg = err?.name === "AbortError" ? "Timed out after 20s." : err?.message || String(e);
    return { ok: false, detail: `Request failed: ${msg}`, provider, model };
  } finally {
    clearTimeout(timeout);
  }
}

async function rawProviderPing(
  provider: AiProvider,
  a: { url: string; apiKey: string; model: string; signal: AbortSignal }
): Promise<{ ok: boolean; status: number; body: string }> {
  const userMsg = "Reply with the single word: OK";
  if (provider === "anthropic") {
    const res = await fetch(a.url, {
      method: "POST",
      signal: a.signal,
      headers: { "x-api-key": a.apiKey, "anthropic-version": "2023-06-01", "Content-Type": "application/json" },
      body: JSON.stringify({ model: a.model, max_tokens: 16, temperature: 0, messages: [{ role: "user", content: userMsg }] })
    });
    const text = await res.text();
    if (!res.ok) return { ok: false, status: res.status, body: text };
    try {
      return { ok: true, status: res.status, body: JSON.parse(text)?.content?.[0]?.text ?? "OK" };
    } catch {
      return { ok: true, status: res.status, body: "OK" };
    }
  }

  const headers: Record<string, string> = { Authorization: `Bearer ${a.apiKey}`, "Content-Type": "application/json" };
  if (provider === "openrouter") {
    headers["HTTP-Referer"] = process.env.NEXT_PUBLIC_SITE_URL || "https://scanner.thugirlabs.com";
    headers["X-Title"] = "Thugir Scanner";
  }
  const res = await fetch(a.url, {
    method: "POST",
    signal: a.signal,
    headers,
    body: JSON.stringify({ model: a.model, max_tokens: 16, temperature: 0, messages: [{ role: "user", content: userMsg }] })
  });
  const text = await res.text();
  if (!res.ok) return { ok: false, status: res.status, body: text };
  try {
    return { ok: true, status: res.status, body: JSON.parse(text)?.choices?.[0]?.message?.content ?? "OK" };
  } catch {
    return { ok: true, status: res.status, body: "OK" };
  }
}
