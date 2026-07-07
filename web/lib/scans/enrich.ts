import type { PatternFinding } from "../patterns/types";
import type { TierName } from "../settings/schema";
import { analyzeScan, type AiAnalysis } from "../ai/analyze";
import { aiDeepProbe } from "../ai/deep-probe";
import { applyStaticMaxDamage, overlayAiMaxDamage } from "../findings/max-damage";

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
    totalFindings: number;
  };
}

/** Apply static max-damage, optional AI deep probe, then AI analyst (fixes + damage overlay). */
export async function enrichScanResults(args: EnrichScanArgs): Promise<EnrichedScan> {
  let findings = [...args.findings];
  const baseCount = findings.length;

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
      aiFindingsAdded: findings.length - baseCount,
      totalFindings: findings.length
    }
  };
}
