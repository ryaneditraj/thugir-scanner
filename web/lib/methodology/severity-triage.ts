/**
 * Severity triage adapted from CyberStrike report_vulnerability.txt
 * @see docs/reference/cyberstrike/vendor/prompts/report_vulnerability.txt
 */
import type { Severity } from "../patterns/types";

export interface TriageInput {
  severity: Severity;
  category: string;
  title: string;
  description?: string;
  /** Exploit returned 403/401 on attack attempt */
  exploitBlocked?: boolean;
  /** Both baseline and exploit returned same status/body */
  noMeasurableDiff?: boolean;
  /** Only affects attacker's own account */
  selfOnly?: boolean;
  /** Missing header / CORS / info disclosure without demonstrated chain */
  hardeningOnly?: boolean;
  requiresAdmin?: boolean;
}

const RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
};

const SEV: Severity[] = ["info", "low", "medium", "high", "critical"];

function downgrade(sev: Severity, levels = 1): Severity {
  const i = Math.max(0, RANK[sev] - levels);
  return SEV[i] ?? "info";
}

/** Apply triager downgrade rules — prefer under-rating over scanner inflation. */
export function triageSeverity(input: TriageInput): Severity {
  let sev = input.severity;
  const cat = input.category.toLowerCase();
  const title = input.title.toLowerCase();

  if (input.exploitBlocked || input.noMeasurableDiff) return "info";

  if (input.selfOnly) sev = downgrade(sev, 2);

  if (input.requiresAdmin) sev = downgrade(sev, 2);

  if (input.hardeningOnly) sev = downgrade(sev, 1);

  // CORS / missing headers rarely above low
  if (/cors|header|csp|hsts|x-frame/i.test(cat + title)) {
    if (RANK[sev] > RANK.low) sev = "low";
  }

  if (/missing.*header|weak csp|x-frame-options/i.test(title)) {
    sev = "info";
  }

  return sev;
}

/** Condensed triage rules for LLM system prompts (not full vendor text). */
export const SEVERITY_TRIAGE_PROMPT = `Severity like a bug bounty triager — real attacker impact only.
- 403/401 on exploit = NOT a vuln (access control working)
- No measurable baseline vs exploit diff = NOT a vuln
- Self-XSS / self-only impact = low or info
- Missing headers / CORS without demonstrated data theft = low or info
- When in doubt, rate LOWER not higher
- CORS is almost never high/critical without demonstrated cross-origin data theft`;
