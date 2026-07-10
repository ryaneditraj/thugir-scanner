import type { PatternFinding } from "../patterns/types";
import type { TierName } from "../settings/schema";
import { analyzeScan, type AiAnalysis } from "../ai/analyze";
import { aiDeepProbe } from "../ai/deep-probe";
import { applyStaticMaxDamage, overlayAiMaxDamage } from "../findings/max-damage";
import { runVulnClawScan, vulnClawAvailability, mapVulnClawFindings } from "../vulnclaw";

export interface EnrichScanArgs {
  findings: PatternFinding[];
  target: string;
  detectedPlatform: string | null;
  tier: TierName;
  isDeep: boolean;
  combined?: string;
  origin?: string;
  pagesCrawled?: string[];
}

export interface EnrichedScan {
  findings: PatternFinding[];
  ai: AiAnalysis | null;
  stats: {
    aiFindingsAdded: number;
    vulnclawFindingsAdded: number;
    totalFindings: number;
  };
}

/** Apply static max-damage, optional AI deep probe, then AI analyst (fixes + damage overlay). */
export async function enrichScanResults(args: EnrichScanArgs): Promise<EnrichedScan> {
  let findings = [...args.findings];
  const baseCount = findings.length;
  let vulnclawAdded = 0;

  if (args.isDeep && args.combined && args.origin) {
    const aiHits = await aiDeepProbe({
      target: args.target,
      origin: args.origin,
      detectedPlatform: args.detectedPlatform,
      combined: args.combined,
      pagesCrawled: args.pagesCrawled ?? []
    });
    const seen = new Set(findings.map((f) => f.title.toLowerCase()));
    for (const hit of aiHits) {
      if (!seen.has(hit.title.toLowerCase())) {
        seen.add(hit.title.toLowerCase());
        findings.push(hit);
      }
    }
  }

  // VulnClaw full agent when enabled (local worker / THUGIR_AGENT_SCAN_ENABLED)
  const agentEnabled =
    process.env.THUGIR_AGENT_SCAN_ENABLED === "1" ||
    process.env.NODE_ENV === "development";
  if (args.isDeep && agentEnabled && vulnClawAvailability().available) {
    try {
      const agent = runVulnClawScan({
        url: args.target,
        scan_mode: process.env.THUGIR_AGENT_SCAN_MODE === "deep" ? "deep" : "quick"
      });
      if (agent.ok && agent.findings?.length) {
        const mapped = mapVulnClawFindings(agent.findings, args.target);
        const seen = new Set(findings.map((f) => f.patternSlug));
        for (const hit of mapped) {
          if (!seen.has(hit.patternSlug)) {
            seen.add(hit.patternSlug);
            findings.push(hit);
            vulnclawAdded++;
          }
        }
      }
    } catch {
      /* agent layer optional */
    }
  }

  applyStaticMaxDamage(findings);

  const ai = await analyzeScan({
    target: args.target,
    detectedPlatform: args.detectedPlatform,
    findings,
    tier: args.tier
  });

  if (ai) {
    overlayAiMaxDamage(findings, ai.maxDamage);
    for (const f of findings) {
      const tailored = ai.fixes[f.patternSlug];
      if (tailored) {
        f.remediation = { summary: tailored, steps: f.remediation?.steps ?? [] };
      }
    }
  }

  return {
    findings,
    ai,
    stats: {
      aiFindingsAdded: findings.length - baseCount - vulnclawAdded,
      vulnclawFindingsAdded: vulnclawAdded,
      totalFindings: findings.length
    }
  };
}
